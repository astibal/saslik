from __future__ import annotations

import argparse
import ipaddress
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .settings import component_environment, component_restart_on_failure, setting_value


NAMESPACE = "sxp-test"
PROBE_NAMESPACE = "saslik-probe"
NS_ADDR = "10.254.77.2"
HOST_ADDR = "10.254.77.1"


def _run(command: list[str], *, tolerate: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.DEVNULL if quiet else None,
        stderr=subprocess.DEVNULL if quiet else None,
    )
    if result.returncode and not tolerate:
        raise RuntimeError(f"Příkaz selhal ({result.returncode}): {' '.join(command)}")
    return result


def _capture(command: list[str]) -> str:
    result = subprocess.run(command, check=False, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return result.stdout.strip()


def _state_env(lab: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in (lab / "state/state.env").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def _unit_instance(instance: str) -> str:
    # Instance names have already passed Instance.validate_instance_name.
    # Keep unit names readable while avoiding '.' being interpreted as a
    # suffix separator by humans and tools.
    return "".join(character if character.isalnum() else "-" for character in instance)


def unit_name(instance: str, component: str) -> str:
    return f"saslik-{_unit_instance(instance)}-{component}.service"


@dataclass(frozen=True)
class Component:
    name: str
    command: tuple[str, ...]
    log: Path
    environment: tuple[str, ...] = ()
    network_namespace: str | None = None
    restart_on_failure: bool = False


class SystemdComponents:
    """Own all long-running lab processes as transient systemd services.

    systemd is the lifecycle authority. PID files left by the old integration
    harness are read only during one-way migration and are never written here.
    """

    LEGACY_PID_FILES = (
        "smithproxy.pid", "cli-forward.pid", "spider.pid", "sift.pid",
        "frontend.pid", "expose-api.pid", "expose-proxy.pid", "expose-cli.pid",
        "pcap-viewer.pid",
    )

    def __init__(self, lab: Path, instance: str, expose_address: str = "127.0.0.1") -> None:
        self.lab = lab
        self.instance = instance
        self.state = lab / "state"
        try:
            address = ipaddress.ip_address(expose_address)
        except ValueError as exc:
            raise RuntimeError("Adresa pro vystavení služeb není platná IP.") from exc
        if address.version != 4:
            raise RuntimeError("Vystavení služeb zatím podporuje IPv4 adresu.")
        # A concrete non-loopback web bind still needs loopback access from the
        # same machine. 0.0.0.0 provides both; remote mode is always explicit.
        self.expose_address = "127.0.0.1" if address.is_loopback else "0.0.0.0"

    @property
    def slice_name(self) -> str:
        return f"saslik-{_unit_instance(self.instance)}.slice"

    def build_auxiliaries(self) -> None:
        spider_source = self.lab / "src/smithproxy-spider"
        if not (self.lab / "build/spider/smithproxy-spider").is_file():
            raise RuntimeError("Spider ještě není sestavený.")
        if not (self.lab / "build/sift/siftd").is_file():
            raise RuntimeError("Sift ještě není sestavený.")
        frontend = self.state / "frontend"
        frontend.mkdir(parents=True, exist_ok=True)
        shutil.copytree(spider_source / "frontend", frontend, dirs_exist_ok=True)
        shutil.copy2(self.state / "certs/default/ca-cert.pem", frontend / "test-ca.pem")
        viewer_workspace = self.state / "pcap-viewer"
        viewer_workspace.mkdir(parents=True, exist_ok=True)
        token = viewer_workspace / "storage.token"
        if not token.exists():
            token.write_text(secrets.token_urlsafe(32), encoding="ascii")
            token.chmod(0o600)

    def components(self) -> list[Component]:
        values = _state_env(self.lab)
        smithproxy = self.lab / "build/smithproxy/smithproxy"
        spider = self.lab / "build/spider/smithproxy-spider"
        sift = self.lab / "build/sift/siftd"
        pcap_viewer = self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer"
        pcap_storage = self.lab / "runtime/pcap-viewer-venv/bin/capture-storage"
        config = self.state / "smithproxy.cfg"
        socat = shutil.which("socat") or "socat"
        python = sys.executable
        result = [
            Component(
                "smithproxy",
                (str(smithproxy), "--config-file", str(config), "--diagnose", "--no-pidfile"),
                self.state / "smithproxy.log",
                network_namespace=NAMESPACE,
                restart_on_failure=component_restart_on_failure(self.lab, "smithproxy"),
            ),
            Component(
                "cli-forward",
                (socat, f"TCP4-LISTEN:55000,bind={NS_ADDR},reuseaddr,fork",
                 "TCP4:127.0.0.1:55000"),
                self.state / "cli-forward.log",
                network_namespace=NAMESPACE,
                restart_on_failure=True,
            ),
        ]
        result.append(Component(
            "sift", (str(sift), "--bind", "0.0.0.0", "--port", "18081"),
            self.state / "sift.log",
            restart_on_failure=component_restart_on_failure(self.lab, "sift"),
        ))
        if pcap_viewer.is_file() and pcap_storage.is_file():
            viewer_workspace = self.state / "pcap-viewer"
            result.append(Component(
                "pcap-storage",
                (str(pcap_storage), "--workspace", str(viewer_workspace),
                 "--watch-root", str(self.state), "--port", "15175"),
                self.state / "pcap-storage.log",
                restart_on_failure=component_restart_on_failure(self.lab, "pcap-storage"),
            ))
            result.append(Component(
                "pcap-viewer",
                (str(pcap_viewer), "--storage-url", "http://127.0.0.1:15175",
                 "--storage-token-file", str(viewer_workspace / "storage.token"),
                 "--capacity-profile", "desktop", "--theme-fixed", "saslik",
                 "--port", "15174", "--no-browser"),
                self.state / "pcap-viewer.log",
                component_environment(self.lab, "pcap-viewer"),
                restart_on_failure=component_restart_on_failure(self.lab, "pcap-viewer"),
            ))
        result.extend([
                Component(
                    "spider",
                    (str(spider), "--bind", "0.0.0.0", "--port", "18080",
                     "--smithproxy-url", values["SMITHPROXY_API_URL"],
                     "--callback-url", values["SMITHPROXY_CALLBACK_URL"],
                     "--smithproxy-insecure"),
                    self.state / "spider.log",
                    (f"SPIDER_SMITHPROXY_KEY={values['SMITHPROXY_API_KEY']}",
                     f"SPIDER_TOKEN={values['SPIDER_TOKEN']}"),
                    restart_on_failure=component_restart_on_failure(self.lab, "spider"),
                ),
                Component(
                    "frontend",
                    (python, "-m", "http.server", "15173", "--bind", "0.0.0.0",
                     "--directory", str(self.state / "frontend")),
                    self.state / "frontend.log",
                ),
        ])
        for name, port in (("api", 55580), ("proxy", 33128), ("cli", 55000)):
            result.append(Component(
                f"expose-{name}",
                (socat, f"TCP4-LISTEN:{port},bind={self.expose_address},reuseaddr,fork",
                 f"TCP4:{NS_ADDR}:{port}"),
                self.state / f"expose-{name}.log",
                restart_on_failure=True,
            ))
        result.append(Component(
            "e2e-probe",
            (python, "-m", "saslik.probe", "--output", str(self.state / "e2e-health.json"),
             "--ca", str(self.state / "certs/default/ca-cert.pem")),
            self.state / "e2e-probe.log",
            network_namespace=PROBE_NAMESPACE,
        ))
        return result

    def _check_assets(self) -> None:
        required = [
            self.lab / "build/smithproxy/smithproxy",
            self.state / "smithproxy.cfg",
            self.state / "state.env",
            Path(f"/run/netns/{NAMESPACE}"),
            Path(f"/run/netns/{PROBE_NAMESPACE}"),
        ]
        for path in required:
            if not path.exists():
                raise RuntimeError(f"Lab není připravený, chybí {path}.")

    def _stop_legacy_processes(self) -> None:
        stopped: list[int] = []
        for filename in self.LEGACY_PID_FILES:
            path = self.state / filename
            if not path.is_file():
                continue
            try:
                pid = int(path.read_text(encoding="ascii").strip())
                if self._legacy_pid_matches(filename, pid):
                    os.kill(pid, signal.SIGTERM)
                    stopped.append(pid)
            except (ValueError, ProcessLookupError, PermissionError):
                pass
            path.unlink(missing_ok=True)
        deadline = time.monotonic() + 4
        while stopped and time.monotonic() < deadline:
            stopped = [pid for pid in stopped if Path(f"/proc/{pid}").exists()]
            if stopped:
                time.sleep(0.05)
        # This path exists only for migration from the old PID-file runner.
        # Re-check ownership before escalating so a recycled PID can never be
        # killed. Future starts are owned by systemd and never reach this path.
        for filename in self.LEGACY_PID_FILES:
            for pid in stopped:
                if self._legacy_pid_matches(filename, pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
        (self.state / "service.pid").unlink(missing_ok=True)

    def _legacy_pid_matches(self, filename: str, pid: int) -> bool:
        try:
            command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
        except (OSError, UnicodeDecodeError):
            return False
        expected = {
            "smithproxy.pid": str(self.lab / "build/smithproxy/smithproxy"),
            "spider.pid": str(self.lab / "build/spider/smithproxy-spider"),
            "sift.pid": str(self.lab / "build/sift/siftd"),
            "frontend.pid": str(self.state / "frontend"),
            "pcap-viewer.pid": "capture-viewer",
            "cli-forward.pid": "TCP4-LISTEN:55000",
            "expose-api.pid": "TCP4-LISTEN:55580",
            "expose-proxy.pid": "TCP4-LISTEN:33128",
            "expose-cli.pid": "TCP4-LISTEN:55000",
        }
        return expected.get(filename, "\0") in command

    def _start_component(self, component: Component) -> None:
        unit = unit_name(self.instance, component.name)
        _run(["systemctl", "stop", unit], tolerate=True, quiet=True)
        command = [
            "systemd-run", "--quiet", "--collect", "--service-type=exec",
            f"--unit={unit}", f"--slice={self.slice_name}",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=8s",
            f"--property=Restart={'on-failure' if component.restart_on_failure else 'no'}",
            f"--property=StandardOutput=append:{component.log}",
            f"--property=StandardError=append:{component.log}",
        ]
        if component.restart_on_failure:
            command.append("--property=RestartSec=500ms")
        crash_components = {"smithproxy", "spider", "sift", "pcap-viewer", "pcap-storage"}
        if component.name in crash_components:
            collect_core = setting_value(self.lab, "collect_coredumps") is True
            command.append(f"--property=LimitCORE={'infinity' if collect_core else '0'}")
            hook = (f"{sys.executable} -m saslik.crash collect --lab {self.lab} "
                    f"--component {component.name} --unit {unit}")
            command.append(f"--property=ExecStopPost={hook}")
        if component.network_namespace:
            command.append(f"--property=NetworkNamespacePath=/run/netns/{component.network_namespace}")
        for value in component.environment:
            command.append(f"--setenv={value}")
        command.extend(component.command)
        _run(command)

    def up(self) -> None:
        self._check_assets()
        self.state.mkdir(parents=True, exist_ok=True)
        self.down()
        self._stop_legacy_processes()
        try:
            for component in self.components():
                self._start_component(component)
                if component.name == "pcap-storage":
                    self._wait_storage_ready()
            self._wait_ready()
            self.print_endpoints()
        except Exception:
            self.down()
            raise

    def down(self) -> None:
        # Stop the slice first. KillMode=control-group guarantees that socat
        # fork children and any component descendants disappear as well.
        _run(["systemctl", "stop", self.slice_name], tolerate=True, quiet=True)
        for component in self.components_if_configured():
            unit = unit_name(self.instance, component.name)
            _run(["systemctl", "stop", unit], tolerate=True, quiet=True)
            _run(["systemctl", "reset-failed", unit], tolerate=True, quiet=True)
        self._stop_legacy_processes()

    def components_if_configured(self) -> list[Component]:
        try:
            return self.components()
        except (OSError, KeyError):
            names = ("smithproxy", "cli-forward", "sift", "spider", "frontend",
                     "pcap-storage", "pcap-viewer", "expose-api", "expose-proxy", "expose-cli", "e2e-probe")
            return [Component(name, (), self.state / f"{name}.log") for name in names]

    def status(self) -> dict[str, dict[str, str | int | None]]:
        names = ("smithproxy", "cli-forward", "sift", "spider", "frontend",
                 "pcap-storage", "pcap-viewer", "expose-api", "expose-proxy", "expose-cli", "e2e-probe")
        units = {unit_name(self.instance, name): name for name in names}
        output = _capture([
            "systemctl", "show", *units,
            "--property=Id,ActiveState,SubState,MainPID,ExecMainStatus",
        ])
        by_unit: dict[str, dict[str, str]] = {}
        for block in output.split("\n\n"):
            values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            if values.get("Id"):
                by_unit[values["Id"]] = values
        result: dict[str, dict[str, str | int | None]] = {}
        for unit, name in units.items():
            values = by_unit.get(unit, {})
            active = values.get("ActiveState", "inactive")
            state = {"active": "running", "activating": "starting",
                     "failed": "failed"}.get(active, "stopped")
            pid = int(values.get("MainPID", "0") or 0)
            result[name] = {
                "state": state,
                "substate": values.get("SubState", "dead"),
                "pid": pid or None,
                "exit_status": int(values.get("ExecMainStatus", "0") or 0),
                "unit": unit,
            }
        return result

    def _wait_ready(self) -> None:
        values = _state_env(self.lab)
        checks = [(values["SMITHPROXY_API_URL"] + "/api/status/ping",
                   {"X-API-Key": values["SMITHPROXY_API_KEY"]}, True)]
        checks.append(("http://127.0.0.1:18080/api/health", {}, False))
        checks.append(("http://127.0.0.1:18081/api/health", {}, False))
        if (self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer").is_file():
            checks.append(("http://127.0.0.1:15174/readyz", {}, False))
        pending = list(checks)
        deadline = time.monotonic() + 30
        while pending and time.monotonic() < deadline:
            remaining = []
            for url, headers, insecure in pending:
                request = urllib.request.Request(url, headers=headers)
                context = None
                if insecure:
                    import ssl
                    context = ssl._create_unverified_context()
                try:
                    with urllib.request.urlopen(request, timeout=1, context=context):
                        pass
                except (OSError, urllib.error.URLError):
                    remaining.append((url, headers, insecure))
            pending = remaining
            if pending:
                time.sleep(0.2)
        if pending:
            failed = ", ".join(url for url, _, _ in pending)
            self.down()
            raise RuntimeError(f"Komponenty nenaběhly: {failed}")
        # The HTTP services above can be healthy even if a short-lived port
        # collision killed one of the socat exposure units during startup.
        # The forwarders restart on failure; require the user-facing CLI port
        # to become reachable before declaring the complete lab ready.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                import socket
                with socket.create_connection(("127.0.0.1", 55000), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.15)
        self.down()
        raise RuntimeError("Komponenty nenaběhly: Smithproxy CLI 127.0.0.1:55000")

    def _wait_storage_ready(self) -> None:
        token = (self.state / "pcap-viewer/storage.token").read_text(encoding="ascii").strip()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            request = urllib.request.Request(
                "http://127.0.0.1:15175/readyz",
                headers={"Authorization": f"Bearer {token}"},
            )
            try:
                with urllib.request.urlopen(request, timeout=1):
                    return
            except (OSError, urllib.error.URLError):
                time.sleep(0.15)
        raise RuntimeError("Capture.Zone storage API nenaběhlo.")

    def print_endpoints(self) -> None:
        values = _state_env(self.lab)
        print("Smithproxy:")
        print("  API:          https://127.0.0.1:55580")
        print("  HTTP CONNECT: http://127.0.0.1:33128")
        print("  CLI:          127.0.0.1:55000")
        print(f"  CA:           {values['SMITHPROXY_CA_CERT']}")
        print("Spider:")
        print("  UI:      http://127.0.0.1:15173/")
        print("  Backend: http://127.0.0.1:18080")
        print("  Sift:    http://127.0.0.1:18081/api/status")
        if (self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer").is_file():
            print("PCAP Viewer: http://127.0.0.1:15174/")
        print(f"Logs:    journalctl -u 'saslik-{_unit_instance(self.instance)}-*'")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-components")
    parser.add_argument("action", choices=("build", "up", "down", "status"))
    parser.add_argument("lab", type=Path)
    parser.add_argument("--instance", default="default")
    parser.add_argument("--expose-address", default="127.0.0.1")
    args = parser.parse_args(argv)
    manager = SystemdComponents(args.lab, args.instance, args.expose_address)
    try:
        if args.action == "build":
            manager.build_auxiliaries()
        elif args.action == "up":
            manager.up()
        elif args.action == "down":
            manager.down()
        else:
            for name, status in manager.status().items():
                print(f"{name}: {status['state']} pid={status['pid'] or '-'} unit={status['unit']}")
    except (OSError, RuntimeError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"saslik-components: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
