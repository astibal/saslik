from __future__ import annotations

import argparse
import grp
import ipaddress
import os
import pwd
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .licensing import (DEFAULT_ISSUER, EntitlementMissing, LicensingError,
                        bootstrap_issuer, install_issuer, license_grant)
from .runtime import WorkspaceRuntime
from .settings import component_environment, component_restart_on_failure, setting_value


SPIDER_FRONTEND_PORT = 25173
PCAP_VIEWER_PORT = 25174
SMITHPROXY_GUI_PORT = 18082
SMITHPROXY_GUI_ENV_KEYS = (
    "SMITHPROXY_API_URL", "SMITHPROXY_API_KEY", "SMITHPROXY_CA_CERT",
)


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


def write_smithproxy_gui_environment(lab: Path) -> Path:
    """Atomically derive the GUI's narrow credential file from workspace state."""
    values = _state_env(lab)
    missing = [key for key in SMITHPROXY_GUI_ENV_KEYS if not values.get(key)]
    if missing:
        raise RuntimeError("state.env neobsahuje GUI hodnoty: " + ", ".join(missing))
    for key in SMITHPROXY_GUI_ENV_KEYS:
        if any(character in values[key] for character in "\r\n\0"):
            raise RuntimeError(f"state.env obsahuje neplatnou hodnotu {key}.")
    state = lab / "state"
    state.mkdir(parents=True, exist_ok=True)
    destination = state / "smithproxy-gui.env"
    descriptor, temporary = tempfile.mkstemp(prefix=".smithproxy-gui.env.", dir=state)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            for key in SMITHPROXY_GUI_ENV_KEYS:
                stream.write(f"{key}={values[key]}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return destination


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
    """Own all long-running workspace processes as transient systemd services.

    systemd is the lifecycle authority. PID files left by the old integration
    harness are read only during one-way migration and are never written here.
    """

    LEGACY_PID_FILES = (
        "smithproxy.pid", "cli-forward.pid", "spider.pid", "sift.pid",
        "frontend.pid", "expose-api.pid", "expose-proxy.pid", "expose-socks.pid",
        "expose-cli.pid",
        "pcap-viewer.pid",
    )
    BASE_COMPONENT_NAMES = (
        "smithproxy", "cli-forward", "sift", "spider", "spider-tls",
        "frontend", "frontend-tls", "pcap-storage", "pcap-viewer",
        "pcap-viewer-tls", "expose-api", "expose-proxy", "expose-socks", "expose-sift",
        "expose-spider", "expose-frontend", "expose-pcap-storage",
        "expose-pcap-viewer", "pcap-storage-bridge", "e2e-probe",
    )
    DEVEL_COMPONENT_NAMES = ("lored", "lored-bridge", "expose-lored")

    def __init__(self, lab: Path, instance: str, expose_address: str = "127.0.0.1",
                 *, devel: bool = False) -> None:
        self.lab = lab
        self.instance = instance
        self.runtime = WorkspaceRuntime.for_workspace(lab, instance)
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
        return self.runtime.slice_name

    def component_names(self) -> tuple[str, ...]:
        optional = (("smithproxy-gui",)
                    if os.access(self.lab / "build/smithproxy-gui/smithproxy-gui", os.X_OK)
                    else ())
        return self.BASE_COMPONENT_NAMES + optional + (
            self.DEVEL_COMPONENT_NAMES if self.devel else ())

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
        smithproxy_gui = self.lab / "build/smithproxy-gui/smithproxy-gui"
        config = self.state / "smithproxy.cfg"
        socat = shutil.which("socat") or "socat"
        python = sys.executable
        frontend_server = self.lab / "src/smithproxy-spider/tools/serve-frontend.py"
        frontend_command = ((python, str(frontend_server)) if frontend_server.is_file()
                            else (python, "-m", "http.server"))
        portal_tls = self.lab.parent.parent / "portal-tls"
        portal_certificate = portal_tls / "certificate.pem"
        portal_key = portal_tls / "private-key.pem"
        namespace = self.runtime.namespace
        probe_namespace = self.runtime.probe_namespace
        namespace_address = self.runtime.namespace_address

        def forwarder(name: str, service: str, target_port: int, *,
                      local_only: bool = False) -> Component:
            bind = "127.0.0.1" if local_only else self.expose_address
            listen_port = self.runtime.public_port(service)
            return Component(
                name,
                (socat,
                 f"TCP4-LISTEN:{listen_port},bind={bind},reuseaddr,fork",
                 f"TCP4:{namespace_address}:{target_port}"),
                self.state / f"{name}.log",
                restart_on_failure=True,
            )

        def publish_loopback(name: str, port: int) -> Component:
            """Publish a loopback-only workspace service on its namespace veth."""
            return Component(
                name,
                (socat, f"TCP4-LISTEN:{port},bind={namespace_address},reuseaddr,fork",
                 f"TCP4:127.0.0.1:{port}"),
                self.state / f"{name}.log",
                network_namespace=namespace,
                restart_on_failure=True,
            )

        def tls_relay(name: str, public_port: int, upstream_port: int) -> Component:
            listen = (
                f"OPENSSL-LISTEN:{public_port},bind={namespace_address},reuseaddr,fork,"
                f"cert={portal_certificate},key={portal_key},verify=0"
            )
            return Component(
                name,
                (socat, listen, f"TCP4:127.0.0.1:{upstream_port}"),
                self.state / f"{name}.log",
                network_namespace=namespace,
                restart_on_failure=True,
            )
        result = [
            Component(
                "smithproxy",
                (str(smithproxy), "--config-file", str(config), "--diagnose", "--no-pidfile"),
                self.state / "smithproxy.log",
                network_namespace=namespace,
                bind_paths=((self.state / "smithproxy-data", Path("/var/smithproxy/data")),),
                restart_on_failure=component_restart_on_failure(self.lab, "smithproxy"),
            ),
            Component(
                "cli-forward",
                (socat, f"TCP4-LISTEN:55000,bind={namespace_address},reuseaddr,fork",
                 "TCP4:127.0.0.1:55000"),
                self.state / "cli-forward.log",
                network_namespace=namespace,
                restart_on_failure=True,
            ),
        ]
        sift_command = [str(sift), "--bind", "0.0.0.0", "--port", "18081"]
        if self.devel and lored.is_file():
            sift_command.extend(("--lored-url", "http://127.0.0.1:8091/v1/query"))

        result.append(Component(
            "sift", tuple(sift_command),
            self.state / "sift.log",
            network_namespace=namespace,
            restart_on_failure=component_restart_on_failure(self.lab, "sift"),
        ))
        if self.devel and lored.is_file():
            result.append(Component(
                "lored", (str(lored), "--pack", str(self.state / "lored/lore-pack.json"),
                          "--port", "8091"),
                self.state / "lored.log",
                network_namespace=namespace,
                restart_on_failure=component_restart_on_failure(self.lab, "lored"),
            ))
            result.append(publish_loopback("lored-bridge", 8091))
        if pcap_viewer.is_file() and pcap_storage.is_file():
            viewer_workspace = self.state / "pcap-viewer"
            result.append(Component(
                "pcap-storage",
                (str(pcap_storage), "--workspace", str(viewer_workspace),
                 "--watch-root", str(self.state), "--port", "15175"),
                self.state / "pcap-storage.log",
                network_namespace=namespace,
                restart_on_failure=component_restart_on_failure(self.lab, "pcap-storage"),
            ))
            result.append(publish_loopback("pcap-storage-bridge", 15175))
            result.append(forwarder("expose-pcap-storage", "pcap-storage", 15175,
                                    local_only=True))
            result.append(Component(
                "pcap-viewer",
                (str(pcap_viewer), "--storage-url", "http://127.0.0.1:15175",
                 "--storage-token-file", str(viewer_workspace / "storage.token"),
                 "--capacity-profile", "desktop", "--theme-fixed", "saslik",
                 "--port", str(PCAP_VIEWER_PORT), "--no-browser",
                 "--base-path", f"{self.runtime.web_prefix}/viewer/"),
                self.state / "pcap-viewer.log",
                component_environment(self.lab, "pcap-viewer"),
                network_namespace=namespace,
                restart_on_failure=component_restart_on_failure(self.lab, "pcap-viewer"),
            ))
            result.append(tls_relay("pcap-viewer-tls", 15174, PCAP_VIEWER_PORT))
        if smithproxy_gui.is_file() and os.access(smithproxy_gui, os.X_OK):
            result.append(Component(
                "smithproxy-gui",
                (str(smithproxy_gui), "--bind", "0.0.0.0", "--port",
                 str(SMITHPROXY_GUI_PORT), "--base-path",
                 f"{self.runtime.web_prefix}/smithproxy-gui/"),
                self.state / "smithproxy-gui.log",
                network_namespace=namespace,
                restart_on_failure=component_restart_on_failure(self.lab, "smithproxy-gui"),
                environment_files=(self.state / "smithproxy-gui.env",),
            ))
        result.extend([
                Component(
                    "spider",
                    (str(spider), "--bind", "127.0.0.1", "--port", "18080",
                     "--smithproxy-url", values["SMITHPROXY_API_URL"],
                     "--callback-url", values["SMITHPROXY_CALLBACK_URL"],
                     "--smithproxy-insecure"),
                    self.state / "spider.log",
                    (f"SPIDER_SMITHPROXY_KEY={values['SMITHPROXY_API_KEY']}",
                     f"SPIDER_TOKEN={values['SPIDER_TOKEN']}"),
                    network_namespace=namespace,
                    restart_on_failure=component_restart_on_failure(self.lab, "spider"),
                ),
                # The frontend is served over HTTPS, so its browser-side API
                # endpoint must be HTTPS as well.  Keep Spider itself on the
                # workspace loopback for internal callbacks and terminate TLS
                # only at the namespace boundary.
                tls_relay("spider-tls", 18080, 18080),
                Component(
                    "frontend",
                    (*frontend_command, str(SPIDER_FRONTEND_PORT), "--bind", "127.0.0.1",
                     "--directory", str(self.state / "frontend"),
                     "--base-path", f"{self.runtime.web_prefix}/spider/",
                     "--backend-path", f"{self.runtime.web_prefix}/spider-api/"),
                    self.state / "frontend.log",
                    network_namespace=namespace,
                ),
                tls_relay("frontend-tls", 15173, SPIDER_FRONTEND_PORT),
        ])
        # HTTP applications remain on the workspace veth and are published by
        # the shared nginx gateway. Only the forward-proxy protocol needs its
        # own host listener.
        for name, port in (("proxy", 33128), ("socks", 1080)):
            result.append(Component(
                f"expose-{name}",
                (socat,
                 f"TCP4-LISTEN:{self.runtime.public_port(name)},bind={self.expose_address},reuseaddr,fork",
                 f"TCP4:{namespace_address}:{port}"),
                self.state / f"expose-{name}.log",
                restart_on_failure=True,
            ))
        result.append(Component(
            "e2e-probe",
            (python, "-m", "saslik.probe", "--output", str(self.state / "e2e-health.json"),
             "--ca", str(self.state / "certs/default/ca-cert.pem"),
             "--gateway", self.runtime.probe_gateway),
            self.state / "e2e-probe.log",
            network_namespace=probe_namespace,
        ))
        return result

    def _check_assets(self) -> None:
        required = [
            self.lab / "build/smithproxy/smithproxy",
            self.state / "smithproxy.cfg",
            self.state / "state.env",
            Path(f"/run/netns/{self.runtime.namespace}"),
            Path(f"/run/netns/{self.runtime.probe_namespace}"),
        ]
        for path in required:
            if not path.exists():
                raise RuntimeError(f"Workspace není připravený, chybí {path}.")

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

    def _saslik_forwarder_command(self, command: str) -> bool:
        """Recognize only socat relays using Saslik's fixed port topology."""
        if "socat" not in command:
            return False
        address = self.runtime.namespace_address
        pairs = (
            (f"TCP4-LISTEN:{self.runtime.public_port('api')}", f"TCP4:{address}:55580"),
            (f"TCP4-LISTEN:{self.runtime.public_port('proxy')}", f"TCP4:{address}:33128"),
            (f"TCP4-LISTEN:{self.runtime.public_port('socks')}", f"TCP4:{address}:1080"),
            (f"TCP4-LISTEN:{self.runtime.public_port('spider')}", f"TCP4:{address}:18080"),
            (f"TCP4-LISTEN:{self.runtime.public_port('sift')}", f"TCP4:{address}:18081"),
            (f"TCP4-LISTEN:{self.runtime.public_port('lored')}", f"TCP4:{address}:8091"),
            (f"TCP4-LISTEN:{self.runtime.public_port('pcap-storage')}", f"TCP4:{address}:15175"),
            (f"TCP4-LISTEN:{self.runtime.public_port('frontend')}", f"TCP4:{address}:15173"),
            (f"TCP4-LISTEN:{self.runtime.public_port('pcap-viewer')}", f"TCP4:{address}:15174"),
            (f"TCP4-LISTEN:55000,bind={address}", "TCP4:127.0.0.1:55000"),
            (f"TCP4-LISTEN:8091,bind={address}", "TCP4:127.0.0.1:8091"),
            (f"TCP4-LISTEN:15175,bind={address}", "TCP4:127.0.0.1:15175"),
            ("OPENSSL-LISTEN:15173", f"TCP4:127.0.0.1:{SPIDER_FRONTEND_PORT}"),
            ("OPENSSL-LISTEN:15174", f"TCP4:127.0.0.1:{PCAP_VIEWER_PORT}"),
        )
        return any(listener in command and target in command for listener, target in pairs)

    def _migrate_internal_endpoints(self) -> None:
        """Refresh generated endpoints from the stable workspace identity."""
        env = self.state / "state.env"
        try:
            lines = env.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        generated = {
            "SMITHPROXY_API_URL": f"https://{self.runtime.namespace_address}:55580",
            "SMITHPROXY_CONNECT_URL": f"http://{self.runtime.namespace_address}:33128",
            "SMITHPROXY_CALLBACK_URL": "http://127.0.0.1:18080/webhook",
            "SMITHPROXY_CLI": f"{self.runtime.namespace_address}:55000",
        }
        updated = []
        seen = set()
        for line in lines:
            key = line.partition("=")[0]
            if key in generated:
                updated.append(f"{key}={generated[key]}")
                seen.add(key)
            else:
                updated.append(line)
        updated.extend(f"{key}={value}" for key, value in generated.items() if key not in seen)
        if lines and updated != lines:
            env.write_text("\n".join(updated) + "\n", encoding="utf-8")
            print(f"Workspace runtime: aktualizuji endpointy v {env}.")

        config = self.state / "smithproxy.cfg"
        try:
            original = config.read_text(encoding="utf-8")
        except OSError:
            return
        migrated = re.sub(r'(\bsift_url\s*=\s*)"[^"]+"',
                          r'\1"http://127.0.0.1:18081/webhook"', original, count=1)
        if migrated != original:
            config.write_text(migrated, encoding="utf-8")
            print(f"Workspace runtime: aktualizuji interní callback v {config}.")

    def _saslik_runtime_command(self, command: str) -> bool:
        executables = (
            self.lab / "build/smithproxy/smithproxy",
            self.lab / "build/spider/smithproxy-spider",
            self.lab / "build/sift/siftd",
            self.lab / "build/lore/lored/lored",
            self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer",
            self.lab / "runtime/pcap-viewer-venv/bin/capture-storage",
            self.lab / "build/smithproxy-gui/smithproxy-gui",
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
            "expose-socks.pid": "TCP4-LISTEN:1080",
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
        if component.name == "smithproxy-gui":
            write_smithproxy_gui_environment(self.lab)
        if runtime_command is None:
            runtime_command = self._licensed_command(component)
        component.log.parent.mkdir(parents=True, exist_ok=True)
        component.log.touch(exist_ok=True)
        if os.geteuid() == 0:
            owner = self.lab.stat()
            os.chown(component.log, owner.st_uid, owner.st_gid)
        component.log.chmod(0o640)
        unit = self.runtime.unit_name(component.name)
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
        crash_components = {"smithproxy", "spider", "sift", "lored", "pcap-viewer",
                            "pcap-storage", "smithproxy-gui"}
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
                install_issuer(DEFAULT_ISSUER, public_key)
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
        self._migrate_internal_endpoints()
        components = self.components()
        components, runtime_commands = self._preflight_licenses(
            components, skip_unlicensed=True)
        self.down()
        self._stop_legacy_processes()
        try:
            for component in components:
                self._start_component(component, runtime_commands[component.name])
            if "pcap-storage" in {component.name for component in components}:
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
            unit = self.runtime.unit_name(component.name)
            _run(["systemctl", "stop", unit], tolerate=True, quiet=True)
            _run(["systemctl", "reset-failed", unit], tolerate=True, quiet=True)
        self._stop_stale_forwarders()
        self._stop_legacy_processes()

    @staticmethod
    def component_group(component: str) -> tuple[str, ...]:
        groups = {
            "smithproxy": ("smithproxy",),
            "spider": ("spider", "spider-tls", "frontend", "frontend-tls"),
            "sift": ("sift",),
            "lored": ("lored", "lored-bridge"),
            "pcap-viewer": ("pcap-storage", "pcap-storage-bridge", "expose-pcap-storage",
                            "pcap-viewer", "pcap-viewer-tls"),
            "smithproxy-gui": ("smithproxy-gui",),
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
            _run(["systemctl", "stop", self.runtime.unit_name("tuntom-*")])
            return
        for name in reversed(self.component_group(component)):
            unit = self.runtime.unit_name(name)
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
        if "pcap-storage" in selected:
            self._wait_storage_ready()

    def components_if_configured(self) -> list[Component]:
        try:
            return self.components()
        except (OSError, KeyError):
            return [Component(name, (), self.state / f"{name}.log")
                    for name in self.component_names()]

    def status(self) -> dict[str, dict[str, str | int | None]]:
        units = {self.runtime.unit_name(name): name
                 for name in self.component_names()}
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
        address = self.runtime.namespace_address
        checks.append((f"https://{address}:18080/api/health", {}, True))
        checks.append((f"http://{address}:18081/api/health", {}, False))
        checks.append((f"https://{address}:15173{self.runtime.web_prefix}/spider/",
                       {}, True))
        if "lored" in running_components:
            checks.append((f"http://{address}:8091/readyz", {}, False))
        if "smithproxy-gui" in running_components:
            checks.append((f"http://{address}:{SMITHPROXY_GUI_PORT}/healthz", {}, False))
        if (self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer").is_file():
            # Exercise the real path.  Viewer binds the workspace loopback;
            # the namespace TLS relay is the only intentional ingress.
            checks.append((f"https://{address}:15174{self.runtime.web_prefix}/viewer/readyz",
                           {"Host": "127.0.0.1"}, True))
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
                with socket.create_connection(
                        (self.runtime.namespace_address, 55000), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.15)
        self.down()
        raise RuntimeError(
            f"Komponenty nenaběhly: Smithproxy CLI {self.runtime.namespace_address}:55000")

    def _wait_storage_ready(self) -> None:
        token = (self.state / "pcap-viewer/storage.token").read_text(encoding="ascii").strip()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            request = urllib.request.Request(
                f"http://{self.runtime.namespace_address}:15175/readyz",
                headers={"Authorization": f"Bearer {token}",
                         "Host": "127.0.0.1"},
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
        print(f"  API:          {self.runtime.web_prefix}/smithproxy-api/")
        print(f"  HTTP CONNECT: http://127.0.0.1:{self.runtime.public_port('proxy')}")
        print(f"  SOCKS5:       socks5h://127.0.0.1:{self.runtime.public_port('socks')}")
        print(f"  CLI:          {self.runtime.namespace_address}:55000")
        print(f"  CA:           {values['SMITHPROXY_CA_CERT']}")
        print("Spider:")
        print(f"  UI:      {self.runtime.web_prefix}/spider/")
        print(f"  Backend: {self.runtime.web_prefix}/spider-api/")
        print(f"  Sift:    {self.runtime.web_prefix}/sift-api/api/status")
        if (self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer").is_file():
            print(f"PCAP Viewer: {self.runtime.web_prefix}/viewer/")
        print(f"Logs:    journalctl -u '{self.runtime.prefix}-*'")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-components")
    parser.add_argument("action", choices=("build", "up", "down", "status",
                                           "stop-component", "restart-component"))
    parser.add_argument("lab", type=Path)
    parser.add_argument("--instance", default="default")
    parser.add_argument("--expose-address", default="127.0.0.1")
    parser.add_argument("--devel", action="store_true")
    parser.add_argument("--component", choices=("smithproxy", "spider", "sift", "lored",
                                                 "pcap-viewer", "tuntom", "smithproxy-gui"))
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
