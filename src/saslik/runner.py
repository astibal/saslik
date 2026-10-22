from __future__ import annotations

import os
import json
import re
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .components import SystemdComponents
from .health import collect as collect_health
from .pasta import cleanup_needed as pasta_cleanup_needed


def runtime_state(services: dict[str, dict], *, viewer_enabled: bool = False,
                  lored_enabled: bool = False) -> tuple[str, list[str]]:
    required = ["smithproxy", "spider", "sift"]
    if viewer_enabled:
        required.extend(("pcap-storage", "pcap-viewer"))
    if lored_enabled:
        required.append("lored")
    states = {name: str(services.get(name, {}).get("state", "stopped")) for name in required}
    if all(state == "stopped" for state in states.values()):
        return "stopped", []
    issues = [name for name, state in states.items() if state != "running"]
    if not issues:
        return "running", []
    if any(states[name] == "starting" for name in issues):
        return "recovering", issues
    return "degraded", issues
from .identity import active_name, list_identities


REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
URL_RE = re.compile(r"https?://[^\s]+")


def data_root() -> Path:
    configured = os.environ.get("SASLIK_DATA_DIR")
    if configured:
        return Path(configured).expanduser()
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid and sudo_uid.isdigit():
        import pwd
        return Path(pwd.getpwuid(int(sudo_uid)).pw_dir) / ".local/share/saslik"
    return Path.home() / ".local/share/saslik"


def ensure_friendly_data_link(root: Path | None = None) -> Path | None:
    """Expose the XDG data directory as the user-facing ~/Saslik path."""
    target = (root or data_root()).expanduser().resolve()
    link = Path.home() / "Saslik"
    if link.exists() or link.is_symlink():
        return link if link.is_symlink() and link.resolve() == target else None
    target.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target, target_is_directory=True)
    return link


def validate_ref(value: str) -> str:
    value = value.strip()
    if not REF_RE.fullmatch(value) or ".." in value:
        raise ValueError("Branch/ref smí obsahovat jen písmena, čísla, tečky, lomítka, _ a -.")
    return value


@dataclass
class Job:
    id: int = 0
    action: str = "idle"
    state: str = "idle"
    returncode: int | None = None
    lines: deque[str] = field(default_factory=lambda: deque(maxlen=1500))
    revision: int = 0
    template: str = "spider-sift"
    component: str = ""
    endpoints: dict[str, str] = field(default_factory=dict)


class LabRunner:
    """Builds a lab and delegates component lifecycle to systemd."""

    def __init__(self, root: Path | None = None, *, instance: str = "default", egress: str = "nat",
                 expose_address: str = "127.0.0.1", devel: bool = False) -> None:
        self.root = root or data_root()
        self.root.mkdir(parents=True, exist_ok=True)
        self.lab = self.root / "lab"
        self.instance = instance
        self.egress = egress
        self.expose_address = expose_address
        self.devel = devel
        self._lock = threading.RLock()
        self._job = Job()
        self._next_id = 1
        self._health_cache: tuple[float, dict] = (0.0, {})
        self._health_lock = threading.Lock()
        # The web server supplies its long-lived privileged guardian here.
        # Console-only commands retain the explicit sudo command path.
        self.component_action: Callable[[str, str], bool] | None = None

    @property
    def spider(self) -> Path:
        return self.lab / "src/smithproxy-spider"

    def operation_running(self) -> bool:
        with self._lock:
            return self._job.state == "running"

    def select_instance(self, instance) -> None:
        if self.operation_running():
            raise RuntimeError("Workspace nelze přepnout během probíhající operace.")
        with self._lock:
            self.instance = instance.name
            self.egress = instance.egress
            self.root = instance.data_dir.parent
            self.lab = instance.data_dir
            self._job = Job()
        with self._health_lock:
            self._health_cache = (0.0, {})

    def snapshot(self) -> dict:
        with self._lock:
            lines = list(self._job.lines)
            previous_endpoints = dict(self._job.endpoints)
            result = {
                "id": self._job.id,
                "action": self._job.action,
                "state": self._job.state,
                "returncode": self._job.returncode,
                "lines": lines,
                "revision": self._job.revision,
                "initialized": self.spider.is_dir(),
                "config_initialized": (self.lab / "state/smithproxy.cfg").is_file(),
                "instance": self.instance,
                "egress": self.egress,
                "template": self._job.template,
                "identity": active_name(self.lab, self.instance),
                "identities": list_identities(self.lab, self.instance),
                "binary_bundle": self._binary_bundle(),
            }
        endpoints = parse_endpoints(lines) or previous_endpoints
        if (self.lab / "state/certs/default/ca-cert.pem").is_file():
            endpoints["ca_download"] = "/api/ca"
        result["endpoints"] = endpoints
        result["services"] = self._service_status()
        result["runtime_state"], result["runtime_issues"] = runtime_state(
            result["services"],
            viewer_enabled=(self.lab / "runtime/pcap-viewer-venv/bin/capture-viewer").is_file(),
            lored_enabled=self.devel and (self.lab / "build/lore/lored/lored").is_file(),
        )
        result["health"] = self._health_status()
        return result

    def _binary_bundle(self) -> dict | None:
        marker = self.lab / "state/binary-bundle.json"
        if not marker.is_file():
            return None
        try:
            return json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"source_ref": "unknown"}

    def _health_status(self) -> dict:
        with self._health_lock:
            sampled, value = self._health_cache
            now = time.monotonic()
            if now - sampled >= 1.0:
                value = collect_health(self.lab, include_lored=self.devel)
                self._health_cache = (now, value)
            return value

    def _service_status(self) -> dict[str, dict]:
        result = SystemdComponents(self.lab, self.instance, self.expose_address,
                                   devel=self.devel).status()
        for name in ("smithproxy", "spider", "sift") + (("lored",) if self.devel else ()):
            result.setdefault(name, {"state": "inactive", "pid": None})
        return result

    def start_job(self, action: str, branch: str = "master", template: str = "spider-sift",
                  ca_cert: str = "", ca_key: str = "", component: str = "") -> int:
        if action not in {"start", "stop", "reset", "fetch", "status", "update-component"}:
            raise ValueError("Neznámá akce.")
        if action == "update-component" and component not in {
                "smithproxy", "spider", "sift", "lored", "pcap-viewer"}:
            raise ValueError("Neznámá komponenta.")
        branch = validate_ref(branch)
        if template not in {"spider-sift", "spider", "proxy"}:
            raise ValueError("Neznámá počáteční šablona.")
        with self._lock:
            if self._job.state == "running":
                raise RuntimeError("Jedna operace už běží.")
            job_id = self._next_id
            self._next_id += 1
            endpoints = ((parse_endpoints(list(self._job.lines)) or dict(self._job.endpoints))
                         if action == "update-component" else {})
            self._job = Job(id=job_id, action=action, state="running", template=template,
                            component=component, endpoints=endpoints)
        threading.Thread(target=self._run_job,
                         args=(job_id, action, branch, template, ca_cert, ca_key, component),
                         daemon=True).start()
        return job_id

    def run_console(self, action: str, branch: str = "master", emit: Callable[[str], None] = print,
                    template: str = "spider-sift", ca_cert: str = "", ca_key: str = "",
                    component: str = "") -> int:
        branch = validate_ref(branch)
        return self._run_commands(
            self._commands(action, branch, template, ca_cert, ca_key, component), emit)

    def _run_commands(self, commands: list[list[str]], emit: Callable[[str], None]) -> int:
        for command in commands:
            guardian_action = self._component_guardian_action(command)
            if guardian_action is not None and self.component_action is not None:
                action, component = guardian_action
                emit(f"$ guardian {action} {component}")
                if not self.component_action(action, component):
                    emit(f"Saslik: guardian odmítl {action} komponenty {component}.")
                    return 1
                continue
            emit("$ " + " ".join(map(str, command)))
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, bufsize=1, env=self._env())
            assert process.stdout is not None
            for line in process.stdout:
                emit(line.rstrip())
            code = process.wait()
            if code:
                return code
        return 0

    @staticmethod
    def _component_guardian_action(command: list[str]) -> tuple[str, str] | None:
        """Recognize the two narrowly-scoped privileged component actions."""
        try:
            module = command.index("saslik.components")
            action = command[module + 1]
            component = command[command.index("--component") + 1]
        except (ValueError, IndexError):
            return None
        if action not in {"stop-component", "restart-component"}:
            return None
        return action, component

    def _run_job(self, job_id: int, action: str, branch: str, template: str,
                 ca_cert: str, ca_key: str, component: str = "") -> None:
        try:
            commands = self._commands(action, branch, template, ca_cert, ca_key, component)
            code = self._run_commands(commands, lambda line: self._append(job_id, line))
            self._finish(job_id, "done" if code == 0 else "failed", code)
        except Exception as exc:
            self._append(job_id, f"Saslik: {exc}")
            self._finish(job_id, "failed", 1)

    def _commands(self, action: str, branch: str, template: str = "spider-sift",
                  ca_cert: str = "", ca_key: str = "", component: str = "") -> list[list[str]]:
        sudo = ["sudo", "-n"]
        # Sources, builds and persistent workspace data belong to the desktop
        # user.  In particular Git must retain access to that user's SSH agent.
        workspace = [sys.executable, "-m", "saslik.workspace"]
        network = sudo + [sys.executable, "-m", "saslik.network"]
        components = sudo + [sys.executable, "-m", "saslik.components"]
        pasta = sudo + [sys.executable, "-m", "saslik.pasta"]
        routing = sudo + [sys.executable, "-m", "saslik.routing"]
        identity = sudo + [sys.executable, "-m", "saslik.identity"]
        netns_dns = sudo + [sys.executable, "-m", "saslik.netns_dns"]
        dns_server = "169.254.1.1" if self.egress == "pasta" else "1.1.1.1"
        component_args = [str(self.lab), "--instance", self.instance,
                          "--expose-address", self.expose_address]
        if self.devel:
            component_args.append("--devel")
        workspace_devel = ["--devel"] if self.devel else []
        clean_pasta = self.egress == "pasta" or pasta_cleanup_needed(
            self.lab, self.instance, inspect_unit=False)

        if action == "start":
            commands = [
                components + ["down", *component_args],
                routing + ["down", str(self.lab)],
            ]
            if clean_pasta:
                commands.append(pasta + ["down", str(self.lab), "--instance", self.instance])
            commands.append(network + ["down", str(self.lab)])
            if not (self.lab / "state/binary-bundle.json").is_file():
                commands.extend([
                    workspace + ["sync", str(self.lab), "--ref", branch, *workspace_devel],
                    workspace + ["build", str(self.lab), "--ref", branch, *workspace_devel],
                ])
            else:
                # Binary bundles cover the compiled dataplane. Independently
                # managed components are still fetched and built normally.
                commands.extend([
                    workspace + ["viewer-sync", str(self.lab)],
                    workspace + ["viewer-install", str(self.lab)],
                    *([workspace + ["component-sync", str(self.lab), "--ref", branch,
                                   "--component", "lored", "--devel"],
                       workspace + ["component-build", str(self.lab),
                                   "--component", "lored", "--devel"]]
                      if self.devel else []),
                ])
            commands.extend([
                workspace + ["init", str(self.lab), "--ref", branch, "--template", template,
                             *(["--ca-cert", ca_cert, "--ca-key", ca_key]
                               if ca_cert or ca_key else [])],
                network + ["up", str(self.lab)],
                netns_dns + ["up", str(self.lab), "--nameserver", dns_server],
            ])
            if self.egress == "pasta":
                commands.append(pasta + ["snapshot", str(self.lab)])
                commands.append(pasta + ["up", str(self.lab), "--instance", self.instance])
            commands.extend([
                routing + ["namespace-up", str(self.lab)],
                components + ["build", *component_args],
                components + ["up", *component_args],
            ])
            return commands
        if action == "reset":
            commands = [
                components + ["down", *component_args],
                routing + ["down", str(self.lab)],
            ]
            if clean_pasta:
                commands.append(pasta + ["down", str(self.lab), "--instance", self.instance])
            commands.extend([
                network + ["down", str(self.lab)],
                identity + ["rotate", str(self.lab), "--fallback", self.instance],
                network + ["up", str(self.lab)],
                netns_dns + ["up", str(self.lab), "--nameserver", dns_server],
            ])
            if self.egress == "pasta":
                commands.append(pasta + ["snapshot", str(self.lab)])
                commands.append(pasta + ["up", str(self.lab), "--instance", self.instance])
            commands.extend([
                routing + ["namespace-up", str(self.lab)],
                components + ["up", *component_args],
            ])
            return commands
        if action == "fetch":
            return [workspace + ["sync", str(self.lab), "--ref", branch, *workspace_devel]]
        if action == "update-component":
            commands = [workspace + ["component-sync", str(self.lab), "--ref", branch,
                                     "--component", component, *workspace_devel]]
            if component == "pcap-viewer":
                commands.append(components + ["stop-component", *component_args,
                                               "--component", component])
            commands.extend([
                workspace + ["component-build", str(self.lab), "--component", component,
                             *workspace_devel],
                components + ["restart-component", *component_args, "--component", component],
            ])
            return commands
        if action == "stop":
            commands = [
                components + ["down", *component_args],
                routing + ["down", str(self.lab)],
            ]
            if clean_pasta:
                commands.append(pasta + ["down", str(self.lab), "--instance", self.instance])
            commands.extend([
                network + ["down", str(self.lab)],
                netns_dns + ["down", str(self.lab)],
            ])
            return commands
        return [components + ["status", *component_args]]

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        return env

    def _append(self, job_id: int, line: str) -> None:
        with self._lock:
            if self._job.id == job_id:
                self._job.lines.append(line)
                self._job.revision += 1

    def _finish(self, job_id: int, state: str, code: int) -> None:
        with self._lock:
            if self._job.id == job_id:
                self._job.state = state
                self._job.returncode = code
                self._job.revision += 1


def parse_endpoints(lines) -> dict[str, str]:
    result: dict[str, str] = {}
    labels = {
        "UI": "spider_ui", "Backend": "spider_backend",
        "Sift": "sift", "API": "smithproxy_api", "HTTP CONNECT": "proxy",
        "CLI": "cli", "CA": "ca", "State": "state", "Logs": "logs",
        "PCAP Viewer": "pcap_viewer",
    }
    for raw in lines:
        line = raw.strip()
        for label, key in labels.items():
            if line.startswith(label + ":"):
                value = line.split(":", 1)[1].strip()
                if value:
                    result[key] = value
    if "spider_ui" in result:
        result["ca_download"] = result["spider_ui"].rstrip("/") + "/test-ca.pem"
    return result
