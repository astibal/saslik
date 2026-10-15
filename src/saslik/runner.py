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


class LabRunner:
    """Builds a lab and delegates component lifecycle to systemd."""

    def __init__(self, root: Path | None = None, *, instance: str = "default", egress: str = "nat",
                 expose_address: str = "127.0.0.1") -> None:
        self.root = root or data_root()
        self.root.mkdir(parents=True, exist_ok=True)
        self.lab = self.root / "lab"
        self.instance = instance
        self.egress = egress
        self.expose_address = expose_address
        self._lock = threading.RLock()
        self._job = Job()
        self._next_id = 1
        self._health_cache: tuple[float, dict] = (0.0, {})
        self._health_lock = threading.Lock()

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
        endpoints = parse_endpoints(lines)
        if (self.lab / "state/certs/default/ca-cert.pem").is_file():
            endpoints["ca_download"] = "/api/ca"
        result["endpoints"] = endpoints
        result["services"] = self._service_status()
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
                value = collect_health(self.lab)
                self._health_cache = (now, value)
            return value

    def _service_status(self) -> dict[str, dict]:
        result = SystemdComponents(self.lab, self.instance, self.expose_address).status()
        for name in ("smithproxy", "spider", "sift"):
            result.setdefault(name, {"state": "inactive", "pid": None})
        return result

    def start_job(self, action: str, branch: str = "master", template: str = "spider-sift",
                  ca_cert: str = "", ca_key: str = "") -> int:
        if action not in {"start", "stop", "reset", "fetch", "status"}:
            raise ValueError("Neznámá akce.")
        branch = validate_ref(branch)
        if template not in {"spider-sift", "spider", "proxy"}:
            raise ValueError("Neznámá počáteční šablona.")
        with self._lock:
            if self._job.state == "running":
                raise RuntimeError("Jedna operace už běží.")
            job_id = self._next_id
            self._next_id += 1
            self._job = Job(id=job_id, action=action, state="running", template=template)
        threading.Thread(target=self._run_job,
                         args=(job_id, action, branch, template, ca_cert, ca_key),
                         daemon=True).start()
        return job_id

    def run_console(self, action: str, branch: str = "master", emit: Callable[[str], None] = print,
                    template: str = "spider-sift", ca_cert: str = "", ca_key: str = "") -> int:
        branch = validate_ref(branch)
        for command in self._commands(action, branch, template, ca_cert, ca_key):
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

    def _run_job(self, job_id: int, action: str, branch: str, template: str,
                 ca_cert: str, ca_key: str) -> None:
        try:
            code = self.run_console(action, branch, lambda line: self._append(job_id, line),
                                    template, ca_cert, ca_key)
            self._finish(job_id, "done" if code == 0 else "failed", code)
        except Exception as exc:
            self._append(job_id, f"Saslik: {exc}")
            self._finish(job_id, "failed", 1)

    def _commands(self, action: str, branch: str, template: str = "spider-sift",
                  ca_cert: str = "", ca_key: str = "") -> list[list[str]]:
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

        if action == "start":
            commands = [
                components + ["down", *component_args],
                routing + ["down", str(self.lab)],
                pasta + ["down", str(self.lab)],
                network + ["down", str(self.lab)],
            ]
            if not (self.lab / "state/binary-bundle.json").is_file():
                commands.extend([
                    workspace + ["sync", str(self.lab), "--ref", branch],
                    workspace + ["build", str(self.lab), "--ref", branch],
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
                commands.append(pasta + ["up", str(self.lab)])
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
                pasta + ["down", str(self.lab)],
                network + ["down", str(self.lab)],
                identity + ["rotate", str(self.lab), "--fallback", self.instance],
                network + ["up", str(self.lab)],
                netns_dns + ["up", str(self.lab), "--nameserver", dns_server],
            ]
            if self.egress == "pasta":
                commands.append(pasta + ["snapshot", str(self.lab)])
                commands.append(pasta + ["up", str(self.lab)])
            commands.extend([
                routing + ["namespace-up", str(self.lab)],
                components + ["up", *component_args],
            ])
            return commands
        if action == "fetch":
            return [workspace + ["sync", str(self.lab), "--ref", branch]]
        if action == "stop":
            return [
                components + ["down", *component_args],
                routing + ["down", str(self.lab)],
                pasta + ["down", str(self.lab)],
                network + ["down", str(self.lab)],
                netns_dns + ["down", str(self.lab)],
            ]
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
        "UI": "spider_ui", "Backend": "spider_backend", "Token": "spider_token",
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
