from __future__ import annotations

import argparse
import grp
import ipaddress
import os
import pwd
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

from .licensing import (EntitlementMissing, LicensingError, bootstrap_issuer,
                        install_issuer, license_grant)
from .settings import component_environment, component_restart_on_failure, setting_value


NAMESPACE = "sxp-test"
PROBE_NAMESPACE = "saslik-probe"
NS_ADDR = "10.254.77.2"
HOST_ADDR = "10.254.77.1"
SPIDER_FRONTEND_PORT = 25173
PCAP_VIEWER_PORT = 25174


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
    bind_paths: tuple[tuple[Path, Path], ...] = ()
    restart_on_failure: bool = False
    required_feature: str | None = None
    licensed_arguments: tuple[tuple[str, str], ...] = ()
    environment_files: tuple[Path, ...] = ()


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

    def __init__(self, lab: Path, instance: str, expose_address: str = "127.0.0.1",
                 *, devel: bool = False) -> None:
        self.lab = lab
        self.instance = instance
        self.devel = devel
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

    @property
    def tuntom_binary(self) -> Path:
        # Like the other source components, this is a locally managed runtime;
        # remote tunnel requests cannot supply an executable path.
        return self.lab / "runtime/tuntom/tuntom"

    def prepare_tuntom(self) -> None:
        """Prepare the non-login account used after Tuntom drops privileges."""
        if not self.tuntom_binary.is_file() or not os.access(self.tuntom_binary, os.X_OK):
            raise RuntimeError("Tuntom ještě není sestavený. Aktualizuj komponentu Tuntom.")
        try:
            group = grp.getgrnam("tuntom")
        except KeyError:
            _run(["groupadd", "--system", "tuntom"])
            group = grp.getgrnam("tuntom")
        try:
            user = pwd.getpwnam("tuntom")
        except KeyError:
            _run(["useradd", "--system", "--gid", "tuntom", "--no-create-home",
                  "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "tuntom"])
            user = pwd.getpwnam("tuntom")
        if user.pw_uid == 0 or user.pw_gid == 0 or group.gr_gid == 0:
            raise RuntimeError("Tuntom runtime účet nesmí mít root UID/GID.")

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
        if self.devel:
            lored_workspace = self.state / "lored"
            lored_workspace.mkdir(parents=True, exist_ok=True)
            pack = lored_workspace / "lore-pack.json"
            if not pack.exists():
                pack.write_text(
                    '{"format":"lore-pack/2","sources":[],"claims":[],"indexes":{}}\n',
                    encoding="utf-8",
                )

    def components(self) -> list[Component]:
        values = _state_env(self.lab)
        smithproxy = self.lab / "build/smithproxy/smithproxy"
        spider = self.lab / "build/spider/smithproxy-spider"
        sift = self.lab / "build/sift/siftd"
        pcap_viewer = self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer"
        pcap_storage = self.lab / "runtime/pcap-viewer-venv/bin/capture-storage"
        lored = self.lab / "build/lore/lored/lored"
        config = self.state / "smithproxy.cfg"
        socat = shutil.which("socat") or "socat"
        python = sys.executable
        frontend_server = self.lab / "src/smithproxy-spider/tools/serve-frontend.py"
        frontend_command = ((python, str(frontend_server)) if frontend_server.is_file()
                            else (python, "-m", "http.server"))
        portal_tls = self.lab.parent.parent / "portal-tls"
        portal_certificate = portal_tls / "certificate.pem"
        portal_key = portal_tls / "private-key.pem"

        def tls_relay(name: str, public_port: int, upstream_port: int) -> Component:
            listen = (
                f"OPENSSL-LISTEN:{public_port},bind={self.expose_address},reuseaddr,fork,"
                f"cert={portal_certificate},key={portal_key},verify=0"
            )
            return Component(
                name,
                (socat, listen, f"TCP4:127.0.0.1:{upstream_port}"),
                self.state / f"{name}.log",
                restart_on_failure=True,
            )
        result = [
            Component(
                "smithproxy",
                (str(smithproxy), "--config-file", str(config), "--diagnose", "--no-pidfile"),
                self.state / "smithproxy.log",
                network_namespace=NAMESPACE,
                bind_paths=((self.state / "smithproxy-data", Path("/var/smithproxy/data")),),
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
        if self.devel and lored.is_file():
            result.append(Component(
                "lored", (str(lored), "--pack", str(self.state / "lored/lore-pack.json"),
                          "--port", "8091"),
                self.state / "lored.log",
                restart_on_failure=component_restart_on_failure(self.lab, "lored"),
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
                 "--port", str(PCAP_VIEWER_PORT), "--no-browser"),
                self.state / "pcap-viewer.log",
                component_environment(self.lab, "pcap-viewer"),
                restart_on_failure=component_restart_on_failure(self.lab, "pcap-viewer"),
            ))
            result.append(tls_relay("pcap-viewer-tls", 15174, PCAP_VIEWER_PORT))
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
                    (*frontend_command, str(SPIDER_FRONTEND_PORT), "--bind", "127.0.0.1",
                     "--directory", str(self.state / "frontend")),
                    self.state / "frontend.log",
                ),
                tls_relay("frontend-tls", 15173, SPIDER_FRONTEND_PORT),
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

    @staticmethod
    def _saslik_forwarder_command(command: str) -> bool:
        """Recognize only socat relays using Saslik's fixed port topology."""
        if "socat" not in command:
            return False
        pairs = (
            ("TCP4-LISTEN:55580", f"TCP4:{NS_ADDR}:55580"),
            ("TCP4-LISTEN:33128", f"TCP4:{NS_ADDR}:33128"),
            ("TCP4-LISTEN:55000", f"TCP4:{NS_ADDR}:55000"),
            (f"TCP4-LISTEN:55000,bind={NS_ADDR}", "TCP4:127.0.0.1:55000"),
            ("OPENSSL-LISTEN:15173", f"TCP4:127.0.0.1:{SPIDER_FRONTEND_PORT}"),
            ("OPENSSL-LISTEN:15174", f"TCP4:127.0.0.1:{PCAP_VIEWER_PORT}"),
        )
        return any(listener in command and target in command for listener, target in pairs)

    def _saslik_runtime_command(self, command: str) -> bool:
        executables = (
            self.lab / "build/smithproxy/smithproxy",
            self.lab / "build/spider/smithproxy-spider",
            self.lab / "build/sift/siftd",
            self.lab / "build/lore/lored/lored",
            self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer",
            self.lab / "runtime/pcap-viewer-venv/bin/capture-storage",
        )
        return self._saslik_forwarder_command(command) or any(
            str(executable) in command for executable in executables
        )

    def _stop_stale_forwarders(self) -> None:
        """Remove relay processes left behind by pre-control-group units.

        Current transient units have KillMode=control-group. This migration
        guard is deliberately command-specific so it cannot kill an unrelated
        service merely because it happens to use one of the same ports.
        """
        stopped: list[int] = []
        for process in Path("/proc").glob("[0-9]*"):
            try:
                pid = int(process.name)
                command = process.joinpath("cmdline").read_bytes().replace(
                    b"\0", b" ").decode("utf-8")
                if pid != os.getpid() and self._saslik_runtime_command(command):
                    print(f"Sanity cleanup: ukončuji osiřelý runtime PID {pid}: {command}")
                    os.kill(pid, signal.SIGTERM)
                    stopped.append(pid)
            except (OSError, UnicodeDecodeError, ValueError):
                continue
        deadline = time.monotonic() + 2
        while stopped and time.monotonic() < deadline:
            stopped = [pid for pid in stopped if Path(f"/proc/{pid}").exists()]
            if stopped:
                time.sleep(0.05)
        for pid in stopped:
            try:
                command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(
                    b"\0", b" ").decode("utf-8")
                if self._saslik_runtime_command(command):
                    print(f"Sanity cleanup: PID {pid} nereagoval, posílám SIGKILL.")
                    os.kill(pid, signal.SIGKILL)
            except (OSError, UnicodeDecodeError):
                pass

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

    @staticmethod
    def _licensed_command(component: Component) -> tuple[str, ...]:
        runtime_command = list(component.command)
        if component.required_feature:
            granted = license_grant(component.required_feature, component.name)
            # The license only supplies values. Saslik owns the key-to-option
            # allow-list and never appends arbitrary license text to argv.
            for key, option in component.licensed_arguments:
                if key in granted:
                    runtime_command.extend((option, granted[key]))
        return tuple(runtime_command)

    def _start_component(self, component: Component,
                         runtime_command: tuple[str, ...] | None = None) -> None:
        if runtime_command is None:
            runtime_command = self._licensed_command(component)
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
        crash_components = {"smithproxy", "spider", "sift", "lored", "pcap-viewer", "pcap-storage"}
        if component.name in crash_components:
            collect_core = setting_value(self.lab, "collect_coredumps") is True
            command.append(f"--property=LimitCORE={'infinity' if collect_core else '0'}")
            hook = (f"{sys.executable} -m saslik.crash collect --lab {self.lab} "
                    f"--component {component.name} --unit {unit}")
            command.append(f"--property=ExecStopPost={hook}")
        if component.network_namespace:
            command.append(f"--property=NetworkNamespacePath=/run/netns/{component.network_namespace}")
        for source, destination in component.bind_paths:
            source.mkdir(parents=True, exist_ok=True)
            command.append(f"--property=BindPaths={source}:{destination}")
        for value in component.environment:
            command.append(f"--setenv={value}")
        for path in component.environment_files:
            command.append(f"--property=EnvironmentFile={path}")
        command.extend(runtime_command)
        _run(command)

    def _preflight_licenses(
            self, components: list[Component], *, skip_unlicensed: bool = False,
    ) -> tuple[list[Component], dict[str, tuple[str, ...]]]:
        licensed = [component for component in components if component.required_feature]
        if licensed:
            public_key = setting_value(self.lab, "license_issuer_key")
            issuer_ready = False
            if isinstance(public_key, str) and public_key.strip():
                install_issuer("smithproxy", public_key)
                issuer_ready = True
            else:
                try:
                    issuer_ready = bootstrap_issuer(self.lab)
                except LicensingError:
                    if not skip_unlicensed:
                        raise
            if not issuer_ready:
                if skip_unlicensed:
                    components = [component for component in components
                                  if not component.required_feature]
                    return components, {
                        component.name: component.command for component in components
                    }
                raise EntitlementMissing(
                    "Komponenta vyžaduje licenci; důvěryhodný licenční klíč není dostupný."
                )

        runnable: list[Component] = []
        commands: dict[str, tuple[str, ...]] = {}
        for component in components:
            try:
                commands[component.name] = self._licensed_command(component)
                runnable.append(component)
            except EntitlementMissing:
                if not skip_unlicensed:
                    raise
        return runnable, commands

    def up(self) -> None:
        self._check_assets()
        self.state.mkdir(parents=True, exist_ok=True)
        components = self.components()
        components, runtime_commands = self._preflight_licenses(
            components, skip_unlicensed=True)
        self.down()
        self._stop_legacy_processes()
        try:
            for component in components:
                self._start_component(component, runtime_commands[component.name])
                if component.name == "pcap-storage":
                    self._wait_storage_ready()
            self._wait_ready({component.name for component in components})
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
        self._stop_stale_forwarders()
        self._stop_legacy_processes()

    @staticmethod
    def component_group(component: str) -> tuple[str, ...]:
        groups = {
            "smithproxy": ("smithproxy",),
            "spider": ("spider", "frontend", "frontend-tls"),
            "sift": ("sift",),
            "lored": ("lored",),
            "pcap-viewer": ("pcap-storage", "pcap-viewer", "pcap-viewer-tls"),
        }
        try:
            return groups[component]
        except KeyError as exc:
            raise ValueError(f"Neznámá komponenta: {component}") from exc

    def stop_component(self, component: str) -> None:
        """Stop only the services owned by one updatable component."""
        if component == "tuntom":
            # The guardian releases leases first. This also handles CLI use
            # and orphaned endpoints without touching other lab services.
            _run(["systemctl", "stop", unit_name(self.instance, "tuntom-*")])
            return
        for name in reversed(self.component_group(component)):
            unit = unit_name(self.instance, name)
            _run(["systemctl", "stop", unit], tolerate=True, quiet=True)
            _run(["systemctl", "reset-failed", unit], tolerate=True, quiet=True)

    def restart_component(self, component: str) -> None:
        """Recreate only the selected component's transient services."""
        if component == "tuntom":
            self.prepare_tuntom()
            self.stop_component(component)
            # Endpoints need per-client credentials and are started on demand.
            return
        if component == "spider":
            self.build_auxiliaries()
        selected = set(self.component_group(component))
        components = [item for item in self.components() if item.name in selected]
        if len(components) != len(selected):
            missing = sorted(selected.difference(item.name for item in components))
            raise RuntimeError("Chybí runtime komponenty: " + ", ".join(missing))
        components, runtime_commands = self._preflight_licenses(components)
        self.stop_component(component)
        for item in components:
            self._start_component(item, runtime_commands[item.name])
            if item.name == "pcap-storage":
                self._wait_storage_ready()

    def components_if_configured(self) -> list[Component]:
        try:
            return self.components()
        except (OSError, KeyError):
            names = ("smithproxy", "cli-forward", "sift", "spider", "frontend",
                     "frontend-tls", "pcap-storage", "pcap-viewer", "pcap-viewer-tls",
                     "expose-api", "expose-proxy", "expose-cli", "e2e-probe")
            if self.devel:
                names += ("lored",)
            return [Component(name, (), self.state / f"{name}.log") for name in names]

    def status(self) -> dict[str, dict[str, str | int | None]]:
        names = ("smithproxy", "cli-forward", "sift", "spider", "frontend",
                 "frontend-tls", "pcap-storage", "pcap-viewer", "pcap-viewer-tls",
                 "expose-api", "expose-proxy", "expose-cli", "e2e-probe")
        if self.devel:
            names += ("lored",)
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

    def _wait_ready(self, running_components: set[str] | None = None) -> None:
        if running_components is None:
            running_components = {component.name for component in self.components()}
        values = _state_env(self.lab)
        checks = [(values["SMITHPROXY_API_URL"] + "/api/status/ping",
                   {"X-API-Key": values["SMITHPROXY_API_KEY"]}, True)]
        checks.append(("http://127.0.0.1:18080/api/health", {}, False))
        checks.append(("http://127.0.0.1:18081/api/health", {}, False))
        checks.append(("https://127.0.0.1:15173/", {}, True))
        if "lored" in running_components:
            checks.append(("http://127.0.0.1:8091/readyz", {}, False))
        if (self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer").is_file():
            checks.append((f"http://127.0.0.1:{PCAP_VIEWER_PORT}/readyz", {}, False))
            checks.append(("https://127.0.0.1:15174/readyz", {}, True))
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
        print("  UI:      https://127.0.0.1:15173/")
        print("  Backend: http://127.0.0.1:18080")
        print("  Sift:    http://127.0.0.1:18081/api/status")
        if (self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer").is_file():
            print("PCAP Viewer: https://127.0.0.1:15174/")
        print(f"Logs:    journalctl -u 'saslik-{_unit_instance(self.instance)}-*'")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-components")
    parser.add_argument("action", choices=("build", "up", "down", "status",
                                           "stop-component", "restart-component"))
    parser.add_argument("lab", type=Path)
    parser.add_argument("--instance", default="default")
    parser.add_argument("--expose-address", default="127.0.0.1")
    parser.add_argument("--devel", action="store_true")
    parser.add_argument("--component", choices=("smithproxy", "spider", "sift", "lored", "pcap-viewer", "tuntom"))
    args = parser.parse_args(argv)
    manager = SystemdComponents(args.lab, args.instance, args.expose_address, devel=args.devel)
    try:
        if args.action == "build":
            manager.build_auxiliaries()
        elif args.action == "up":
            manager.up()
        elif args.action == "down":
            manager.down()
        elif args.action == "stop-component":
            if not args.component:
                raise RuntimeError("Chybí --component.")
            manager.stop_component(args.component)
        elif args.action == "restart-component":
            if not args.component:
                raise RuntimeError("Chybí --component.")
            manager.restart_component(args.component)
        else:
            for name, status in manager.status().items():
                print(f"{name}: {status['state']} pid={status['pid'] or '-'} unit={status['unit']}")
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"saslik-components: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
