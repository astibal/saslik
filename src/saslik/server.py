from __future__ import annotations

import json
import base64
import ipaddress
import io
import mimetypes
import os
import secrets
import select
import shutil
import socket
import subprocess
import sys
import threading
import tempfile
import time
import webbrowser
import zipfile
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, urlparse

from .runner import LabRunner, data_root
from .ca import install_store, store_status
from .instance import Instance, remember_instance
from .identity import active_name, identity_root, list_identities
from .components import SystemdComponents
from .settings import provision_settings, public_settings, setting_value
from .crash import clear_reports, reports as crash_reports, save_bundle as save_crash_bundle
from .workspace import source_changes


APP_BROWSERS = (
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
    "microsoft-edge", "microsoft-edge-stable", "brave-browser", "vivaldi-stable", "vivaldi",
)


@dataclass
class CliSession:
    stream: socket.socket
    created_at: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    telnet_state: str = "data"
    telnet_command: int = 0

    def decode(self, chunk: bytes) -> bytes:
        """Strip telnet negotiation emitted by the CLI broker.

        The Smithproxy comm broker uses the telnet framing for display, but it
        does not accept telnet option replies on this socket: those would be
        parsed as malformed CLI/API input.
        """
        output = bytearray()
        for byte in chunk:
            if self.telnet_state == "data":
                if byte == 255:
                    self.telnet_state = "iac"
                else:
                    output.append(byte)
            elif self.telnet_state == "iac":
                if byte == 255:
                    output.append(byte)
                    self.telnet_state = "data"
                elif byte in {251, 252, 253, 254}:  # WILL/WONT/DO/DONT
                    self.telnet_command = byte
                    self.telnet_state = "option"
                elif byte == 250:  # subnegotiation
                    self.telnet_state = "subneg"
                else:
                    self.telnet_state = "data"
            elif self.telnet_state == "option":
                self.telnet_state = "data"
            elif self.telnet_state == "subneg":
                if byte == 255:
                    self.telnet_state = "subneg-iac"
            elif self.telnet_state == "subneg-iac":
                self.telnet_state = "data" if byte == 240 else "subneg"
        return bytes(output)


@dataclass(frozen=True)
class SpiderBootstrapGrant:
    backend: str
    token: str
    origin: str
    expires_at: float


class SpiderBootstrapStore:
    """Short-lived, single-use credentials for opening the Spider UI."""

    def __init__(self, lifetime: float = 60.0) -> None:
        self.lifetime = lifetime
        self._grants: dict[str, SpiderBootstrapGrant] = {}
        self._lock = threading.Lock()

    def issue(self, backend: str, token: str, origin: str,
              now: float | None = None) -> str:
        current = time.monotonic() if now is None else now
        code = secrets.token_urlsafe(32)
        with self._lock:
            self._prune(current)
            self._grants[code] = SpiderBootstrapGrant(
                backend, token, origin, current + self.lifetime)
        return code

    def redeem(self, code: str, origin: str,
               now: float | None = None) -> SpiderBootstrapGrant | None:
        current = time.monotonic() if now is None else now
        with self._lock:
            self._prune(current)
            grant = self._grants.get(code)
            if grant is None or grant.origin != origin:
                return None
            return self._grants.pop(code)

    def _prune(self, now: float) -> None:
        expired = [code for code, grant in self._grants.items()
                   if grant.expires_at <= now]
        for code in expired:
            self._grants.pop(code, None)


def open_frontend(url: str, mode: str = "app") -> str:
    if mode == "none":
        return "none"
    if mode == "app":
        for name in APP_BROWSERS:
            executable = shutil.which(name)
            if executable:
                subprocess.Popen(
                    [executable, f"--app={url}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return name
    webbrowser.open(url)
    return "browser"


def app_launch_command(url: str) -> str:
    for name in APP_BROWSERS:
        executable = shutil.which(name)
        if executable:
            return f"{executable} --app={url}"
    return f"chromium --app={url}"


class SaslikServer(ThreadingHTTPServer):
    def __init__(self, address, runner: LabRunner):
        super().__init__(address, Handler)
        self.runner = runner
        self.csrf = secrets.token_urlsafe(24)
        self.cli_sessions: dict[str, CliSession] = {}
        self.cli_lock = threading.Lock()
        self.spider_bootstraps = SpiderBootstrapStore()
        owner_uid = int(os.environ.get("SUDO_UID", os.getuid()))
        runtime = Path(f"/run/user/{owner_uid}")
        if not runtime.is_dir():
            runtime = Path(tempfile.gettempdir())
        self.guardian_socket = runtime / f"saslik-guardian-{os.getpid()}.sock"
        self.guardian_unit = f"saslik-guardian-{os.getpid()}.service"

    def start_guardian(self) -> None:
        if self.guardian_socket.exists():
            return
        owner_uid = int(os.environ.get("SUDO_UID", os.getuid()))
        privilege = [] if os.geteuid() == 0 else ["sudo", "-n"]
        command = [*privilege, "systemd-run", "--quiet", "--collect",
                   f"--unit={self.guardian_unit}", "--slice=saslik-control.slice",
                   "--property=Restart=no", sys.executable, "-m", "saslik.guardian",
                   "--socket", str(self.guardian_socket), "--owner-uid", str(owner_uid),
                   "--parent-pid", str(os.getpid()), "--data-root", str(data_root()),
                   "--lab", str(self.runner.lab), "--instance", self.runner.instance,
                   "--expose-address", self.runner.expose_address]
        subprocess.run(command, check=True)
        deadline = time.monotonic() + 3
        while not self.guardian_socket.exists() and time.monotonic() < deadline:
            time.sleep(0.03)
        if not self.guardian_socket.exists():
            raise RuntimeError("Privilegovaný guardian nenaběhl.")

    def guardian_request(self, action: str, instance: Instance | None = None,
                         **options: object) -> bool:
        if not self.guardian_socket.exists():
            return False
        target_lab = instance.data_dir if instance else self.runner.lab
        target_name = instance.name if instance else self.runner.instance
        payload = json.dumps({
            "action": action,
            "lab": str(target_lab), "instance": target_name,
            "expose_address": self.runner.expose_address,
            **options,
        }).encode("utf-8")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(60)
                client.connect(str(self.guardian_socket))
                client.sendall(payload)
                return b'"ok":true' in client.recv(4096)
        except OSError:
            return False

    def guardian_stop(self) -> bool:
        return self.guardian_request("stop")

    def guardian_arm(self) -> bool:
        return self.guardian_request("arm")

    def server_close(self) -> None:
        with self.cli_lock:
            sessions = list(self.cli_sessions.values())
            self.cli_sessions.clear()
        for session in sessions:
            try:
                session.stream.close()
            except OSError:
                pass
        self.guardian_stop()
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server: SaslikServer

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/status":
            return self._json(self.server.runner.snapshot())
        if path == "/api/session":
            return self._json({"csrf": self.server.csrf})
        if path == "/api/identity":
            services = self.server.runner._service_status()
            running = self.server.runner.operation_running() or any(
                value.get("state") in {"running", "starting"} for value in services.values())
            return self._json({
                "active": active_name(self.server.runner.lab, self.server.runner.instance),
                "identities": list_identities(self.server.runner.lab, self.server.runner.instance),
                "running": running,
                "binary_bundle": self.server.runner._binary_bundle(),
            })
        if path == "/api/workspaces":
            return self._json(self._workspaces())
        if path == "/api/workspace/settings":
            workspace = parse_qs(parsed.query).get("workspace", [""])[0]
            lab, _ = self._workspace_target(workspace)
            return self._json({"settings": public_settings(lab),
                               "crash_reports": len(crash_reports(lab)),
                               "source_changes": source_changes(lab)})
        if path == "/api/crashes/files":
            return self._crash_files(parse_qs(parsed.query).get("workspace", [""])[0])
        if path == "/api/ca":
            query = parse_qs(parsed.query)
            return self._ca(query.get("identity", [""])[0], query.get("workspace", [""])[0])
        if path == "/api/identity/files":
            query = parse_qs(parsed.query)
            return self._identity_files(query.get("identity", [""])[0],
                                        query.get("workspace", [""])[0])
        if path == "/api/binary/files":
            return self._binary_files(parse_qs(parsed.query).get("workspace", [""])[0])
        if path == "/api/ca/status":
            instance = Instance(self.server.runner.instance, self.server.runner.egress)
            try:
                return self._json({"stores": store_status(instance)})
            except RuntimeError as exc:
                return self._json({"error": str(exc)}, HTTPStatus.SERVICE_UNAVAILABLE)
        if path == "/api/cli":
            return self._cli_read(parse_qs(urlparse(self.path).query).get("session", [""])[0])
        self._asset(path)

    def do_OPTIONS(self) -> None:
        if urlparse(self.path).path != "/api/spider/bootstrap/redeem":
            return self.send_error(HTTPStatus.NOT_FOUND)
        origin = self.headers.get("Origin", "")
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Max-Age", "60")
        self.send_header("Vary", "Origin")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _workspace_target(self, workspace: str) -> tuple[Path, str]:
        if not workspace:
            return self.server.runner.lab, self.server.runner.instance
        instance = Instance.load(workspace)
        if workspace not in {item.name for item in Instance.discover()}:
            raise RuntimeError(f"Workspace neexistuje: {workspace}")
        return instance.data_dir, instance.name

    def _ca(self, identity: str = "", workspace: str = "") -> None:
        lab, instance = self._workspace_target(workspace)
        root = identity_root(lab, identity or active_name(lab, instance), instance)
        path = root / ("certs/default/ca-cert.pem" if root.name == "state" else "certs-default/ca-cert.pem")
        if not path.is_file():
            return self.send_error(HTTPStatus.NOT_FOUND, "CA ještě není vygenerovaná")
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Disposition", 'attachment; filename="saslik-ca.pem"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _binary_files(self, workspace: str = "") -> None:
        lab, _ = self._workspace_target(workspace)
        handle = tempfile.NamedTemporaryFile(prefix="saslik-binary-", suffix=".tar.gz",
                                             delete=False)
        path = Path(handle.name)
        handle.close()
        path.unlink()
        command = ["sudo", "-n", sys.executable, "-m", "saslik.workspace", "bundle-save",
                   str(lab), "--bundle", str(path)]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                text=True)
        if result.returncode:
            path.unlink(missing_ok=True)
            return self._json({"error": result.stderr.strip() or
                               "Uložení binary bundle selhalo."}, HTTPStatus.BAD_REQUEST)
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Disposition", 'attachment; filename="saslik-binaries.tar.gz"')
            self.send_header("Content-Length", str(path.stat().st_size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with path.open("rb") as source:
                shutil.copyfileobj(source, self.wfile, length=1024 * 1024)
        finally:
            path.unlink(missing_ok=True)

    def _identity_files(self, identity: str, workspace: str = "") -> None:
        lab, instance = self._workspace_target(workspace)
        root = identity_root(lab, identity or active_name(lab, instance), instance)
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name in ("smithproxy.cfg", "state.env"):
                path = root / name
                if path.is_file():
                    bundle.write(path, name)
            certs = root / ("certs/default" if root.name == "state" else "certs-default")
            for path in sorted(certs.glob("*")):
                if path.is_file():
                    bundle.write(path, f"certs/{path.name}")
        data = payload.getvalue()
        safe_name = (identity or "identity").replace('"', "")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", f'attachment; filename="saslik-workspace-{safe_name}.zip"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/spider/bootstrap/redeem":
            return self._spider_bootstrap_redeem()
        if self.headers.get("X-Saslik-CSRF") != self.server.csrf:
            return self._json({"error": "Neplatný CSRF token."}, HTTPStatus.FORBIDDEN)
        if path == "/api/binary/load":
            return self._binary_load()
        if path == "/api/binary/clear":
            return self._binary_clear()
        if path not in {"/api/action", "/api/cli", "/api/ca/action", "/api/identity/action",
                        "/api/workspace/action", "/api/workspace/settings",
                        "/api/crashes/clear", "/api/crashes/diagnose",
                        "/api/spider/bootstrap"}:
            return self.send_error(HTTPStatus.NOT_FOUND)
        try:
            declared = int(self.headers.get("Content-Length", "0"))
            limit = 24 * 1024 * 1024 if path == "/api/identity/action" else 4096
            if declared > limit:
                return self._json({"error": "Požadavek je příliš velký."},
                                  HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            length = min(declared, limit)
            body = json.loads(self.rfile.read(length) or b"{}")
            if path == "/api/spider/bootstrap":
                return self._spider_bootstrap_issue(str(body.get("origin", "")))
            if path == "/api/cli":
                return self._cli_write(body)
            if path == "/api/ca/action":
                return self._ca_action(str(body.get("store", "")))
            if path == "/api/identity/action":
                return self._identity_action(str(body.get("operation", "activate")),
                                             str(body.get("identity", "")),
                                             str(body.get("bundle", "")),
                                             str(body.get("new_name", "")))
            if path == "/api/workspace/action":
                return self._workspace_action(str(body.get("operation", "select")),
                                              str(body.get("workspace", "")),
                                              str(body.get("new_name", "")))
            if path == "/api/workspace/settings":
                workspace = str(body.get("workspace", ""))
                lab, _ = self._workspace_target(workspace)
                settings = body.get("settings", {})
                if not isinstance(settings, dict):
                    raise ValueError("Settings musí být objekt.")
                provision_settings(lab, settings)
                return self._json({"ok": True, "settings": public_settings(lab)})
            if path == "/api/crashes/clear":
                lab, _ = self._workspace_target(str(body.get("workspace", "")))
                return self._json({"ok": True, "removed": clear_reports(lab)})
            if path == "/api/crashes/diagnose":
                workspace = str(body.get("workspace", ""))
                signal_number = int(body.get("signal", 11))
                lab, instance_name = self._workspace_target(workspace)
                instance = Instance.load(instance_name)
                if signal_number not in {9, 11}:
                    raise ValueError("Povolené signály jsou pouze 9 a 11.")
                if not self.server.guardian_request("diagnose-smithproxy", instance,
                                                    signal=signal_number):
                    raise RuntimeError("Diagnostické ukončení Smithproxy selhalo.")
                return self._json({"ok": True})
            if path == "/api/action" and str(body.get("action", "")) == "stop":
                if self.server.guardian_stop():
                    return self._json({"job_id": 0}, HTTPStatus.ACCEPTED)
            if path == "/api/action" and str(body.get("action", "")) in {"start", "reset"}:
                self.server.guardian_arm()
            job_id = self.server.runner.start_job(
                str(body.get("action", "")),
                str(setting_value(self.server.runner.lab, "ref_smithproxy")),
                str(body.get("template", "spider-sift")),
                str(body.get("ca_cert", "")), str(body.get("ca_key", "")),
            )
            self._json({"job_id": job_id}, HTTPStatus.ACCEPTED)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _spider_bootstrap_issue(self, origin: str) -> None:
        parsed_origin = urlparse(origin)
        if parsed_origin.scheme not in {"http", "https"} or not parsed_origin.netloc:
            raise ValueError("Spider origin není platný.")
        normalized_origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}"
        values = {}
        for line in (self.server.runner.lab / "state/state.env").read_text(
                encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        token = values.get("SPIDER_TOKEN", "")
        if not token:
            raise RuntimeError("Workspace nemá Spider token.")
        backend = self.server.runner.snapshot().get("endpoints", {}).get(
            "spider_backend", "http://127.0.0.1:18080")
        code = self.server.spider_bootstraps.issue(
            str(backend), token, normalized_origin)
        self._json({"code": code, "expires_in": int(self.server.spider_bootstraps.lifetime)})

    def _spider_bootstrap_redeem(self) -> None:
        origin = self.headers.get("Origin", "")
        try:
            declared = int(self.headers.get("Content-Length", "0"))
            if declared > 4096:
                return self._json({"error": "Požadavek je příliš velký."},
                                  HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                                  cors_origin=origin)
            body = json.loads(self.rfile.read(declared) or b"{}")
            grant = self.server.spider_bootstraps.redeem(
                str(body.get("code", "")), origin)
            if grant is None:
                return self._json({"error": "Bootstrap kód je neplatný nebo vypršel."},
                                  HTTPStatus.UNAUTHORIZED, cors_origin=origin)
            self._json({"backend": grant.backend, "token": grant.token},
                       cors_origin=grant.origin)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST,
                       cors_origin=origin)

    def _workspaces(self) -> dict:
        items = []
        for instance in Instance.discover():
            services = SystemdComponents(instance.data_dir, instance.name,
                                         self.server.runner.expose_address).status()
            running = any(value.get("state") in {"running", "starting"}
                          for value in services.values())
            items.append({
                "name": instance.name,
                "selected": instance.name == self.server.runner.instance,
                "egress": instance.egress,
                "initialized": (instance.data_dir / "state/smithproxy.cfg").is_file(),
                "binaries": all((instance.data_dir / path).is_file() for path in (
                    "build/smithproxy/smithproxy", "build/spider/smithproxy-spider",
                    "build/sift/siftd")),
                "running": running,
            })
        return {"workspaces": items, "selected": self.server.runner.instance}

    def _crash_files(self, workspace: str) -> None:
        try:
            lab, instance = self._workspace_target(workspace)
            handle = tempfile.NamedTemporaryFile(prefix="saslik-crashes-", suffix=".tar.gz",
                                                 delete=False)
            path = Path(handle.name)
            handle.close()
            count = save_crash_bundle(lab, path)
            if not count:
                path.unlink(missing_ok=True)
                return self._json({"error": "Workspace nemá žádné crash reporty."},
                                  HTTPStatus.NOT_FOUND)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Disposition",
                             f'attachment; filename="saslik-{instance}-crashes.tar.gz"')
            self.send_header("Content-Length", str(path.stat().st_size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with path.open("rb") as source:
                shutil.copyfileobj(source, self.wfile, length=1024 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            return
        except (OSError, RuntimeError, ValueError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        finally:
            if "path" in locals():
                path.unlink(missing_ok=True)

    def _workspace_action(self, operation: str, workspace: str, new_name: str) -> None:
        instance = Instance.load(workspace)
        if operation == "stop":
            if not self.server.guardian_request("stop", instance):
                raise RuntimeError("Guardian workspace nezastavil.")
            return self._json({"ok": True, "workspace": workspace})
        if operation == "discard-source-changes":
            services = SystemdComponents(instance.data_dir, instance.name,
                                         self.server.runner.expose_address).status()
            if self.server.runner.operation_running() or any(
                    value.get("state") in {"running", "starting"}
                    for value in services.values()):
                raise RuntimeError("Lokální změny lze zahodit jen při zastaveném labu.")
            changed = source_changes(instance.data_dir)
            command = ["sudo", "-n", sys.executable, "-m", "saslik.workspace",
                       "discard-changes", str(instance.data_dir)]
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    text=True)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or
                                   "Zahození lokálních změn selhalo.")
            return self._json({"ok": True, "workspace": workspace, "discarded": changed})
        any_running = self.server.runner.operation_running()
        for candidate in Instance.discover():
            statuses = SystemdComponents(candidate.data_dir, candidate.name,
                                         self.server.runner.expose_address).status()
            any_running = any_running or any(
                value.get("state") in {"running", "starting"} for value in statuses.values())
        if any_running:
            raise RuntimeError("Workspace nelze změnit, dokud běží kterýkoliv lab.")
        services = SystemdComponents(instance.data_dir, instance.name,
                                     self.server.runner.expose_address).status()
        if any(value.get("state") in {"running", "starting"} for value in services.values()):
            raise RuntimeError("Běžící workspace nelze přepnout ani přejmenovat.")
        if operation == "select":
            instance.ensure_config()
            self.server.runner.select_instance(instance)
            remember_instance(instance.name)
            self.server.guardian_arm()
            return self._json({"ok": True, "workspace": instance.name})
        if operation == "create":
            if workspace in {item.name for item in Instance.discover()}:
                raise RuntimeError(f"Workspace už existuje: {workspace}")
            instance.ensure_config()
            self.server.runner.select_instance(instance)
            remember_instance(instance.name)
            self.server.guardian_arm()
            return self._json({"ok": True, "workspace": instance.name})
        if operation != "rename":
            raise RuntimeError("Neznámá workspace operace.")
        command = ["sudo", "-n", sys.executable, "-m", "saslik.instance", "rename",
                   workspace, new_name]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                text=True)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "Přejmenování workspace selhalo.")
        if self.server.runner.instance == workspace:
            renamed = Instance.load(new_name)
            renamed.ensure_config()
            self.server.runner.select_instance(renamed)
            remember_instance(renamed.name)
            self.server.guardian_arm()
        self._json({"ok": True, "workspace": new_name})

    def _lab_must_be_stopped(self) -> None:
        services = self.server.runner._service_status()
        if self.server.runner.operation_running() or any(
                value.get("state") in {"running", "starting"} for value in services.values()):
            raise RuntimeError("Binary bundle lze měnit jen při zastaveném labu.")

    def _binary_load(self) -> None:
        try:
            self._lab_must_be_stopped()
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1024 * 1024 * 1024:
                raise RuntimeError("Binary bundle chybí nebo je příliš velký.")
            with tempfile.NamedTemporaryFile(prefix="saslik-binary-", suffix=".tar.gz",
                                             delete=False) as target:
                remaining = length
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise RuntimeError("Binary bundle byl přerušen.")
                    target.write(chunk)
                    remaining -= len(chunk)
                path = Path(target.name)
            os.chmod(path, 0o644)
            command = ["sudo", "-n", sys.executable, "-m", "saslik.workspace", "bundle-load",
                       str(self.server.runner.lab), "--bundle", str(path)]
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    text=True)
            path.unlink(missing_ok=True)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or "Načtení binary bundle selhalo.")
            self._json({"ok": True})
        except (OSError, RuntimeError, ValueError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _binary_clear(self) -> None:
        try:
            self._lab_must_be_stopped()
            command = ["sudo", "-n", sys.executable, "-m", "saslik.workspace", "bundle-clear",
                       str(self.server.runner.lab)]
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    text=True)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or "Přepnutí na Git build selhalo.")
            self._json({"ok": True})
        except (OSError, RuntimeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _identity_action(self, operation: str, identity: str, bundle: str = "",
                         new_name: str = "") -> None:
        services = self.server.runner._service_status()
        if self.server.runner.operation_running() or any(
                value.get("state") in {"running", "starting"} for value in services.values()):
            raise RuntimeError("Identitu lze přepnout jen při zastaveném labu.")
        if operation not in {"activate", "rotate", "import", "rename"}:
            raise RuntimeError("Neznámá operace s identitou.")
        command = ["sudo", "-n", sys.executable, "-m", "saslik.identity", operation,
                   str(self.server.runner.lab)]
        if operation in {"activate", "import", "rename"}:
            command.append(identity)
        if operation == "rename":
            command.append(new_name)
        command.extend(["--fallback", self.server.runner.instance])
        temporary = None
        environment = None
        if operation == "import":
            try:
                data = base64.b64decode(bundle, validate=True)
            except ValueError as exc:
                raise RuntimeError("Identity bundle není platně zakódovaný.") from exc
            if len(data) > 16 * 1024 * 1024:
                raise RuntimeError("Identity bundle je příliš velký.")
            temporary = tempfile.NamedTemporaryFile(prefix="saslik-identity-", suffix=".zip",
                                                     delete=False)
            temporary.write(data)
            temporary.close()
            os.chmod(temporary.name, 0o644)
            environment = os.environ.copy()
            environment["SASLIK_IDENTITY_BUNDLE"] = temporary.name
        try:
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    text=True, env=environment)
        finally:
            if temporary:
                Path(temporary.name).unlink(missing_ok=True)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "Přepnutí identity selhalo.")
        self._json({"ok": True, "identity": identity})

    def _ca_action(self, store: str) -> None:
        instance = Instance(self.server.runner.instance, self.server.runner.egress)
        if store == "system":
            pkexec = shutil.which("pkexec")
            source = self.server.runner.lab / "state/certs/default/ca-cert.pem"
            if pkexec:
                command = [pkexec, sys.executable, "-m", "saslik.ca", "-i", instance.name,
                           "system-install", "--certificate", str(source)]
            elif shutil.which("sudo") and os.environ.get("SUDO_ASKPASS"):
                command = ["sudo", "-A", sys.executable, "-m", "saslik.ca", "-i", instance.name,
                           "system-install", "--certificate", str(source)]
            else:
                raise RuntimeError("Chybí pkexec nebo nakonfigurovaný SUDO_ASKPASS.")
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            return self._json({"pending": True}, HTTPStatus.ACCEPTED)
        count = install_store(instance, store)
        self._json({"installed": count})

    def _cli_write(self, body: dict) -> None:
        action = str(body.get("action", ""))
        session = str(body.get("session", ""))
        if action == "open":
            stream = socket.create_connection(("127.0.0.1", 55000), timeout=3)
            stream.setblocking(False)
            session = secrets.token_urlsafe(18)
            with self.server.cli_lock:
                self.server.cli_sessions[session] = CliSession(stream)
            return self._json({"session": session})
        with self.server.cli_lock:
            cli = self.server.cli_sessions.get(session)
        if cli is None:
            return self._json({"error": "CLI relace neexistuje."}, HTTPStatus.NOT_FOUND)
        cli.last_seen = time.monotonic()
        if action == "write":
            data = str(body.get("data", "")).replace("\r\n", "\n").replace("\r", "\n")
            cli.stream.sendall(data.replace("\n", "\r\n").encode("utf-8"))
            return self._json({"ok": True})
        if action == "close":
            with self.server.cli_lock:
                self.server.cli_sessions.pop(session, None)
            cli.stream.close()
            return self._json({"ok": True})
        self._json({"error": "Neznámá CLI akce."}, HTTPStatus.BAD_REQUEST)

    def _cli_read(self, session: str) -> None:
        with self.server.cli_lock:
            cli = self.server.cli_sessions.get(session)
        if cli is None:
            return self._json({"error": "CLI relace neexistuje."}, HTTPStatus.NOT_FOUND)
        cli.last_seen = time.monotonic()
        stream = cli.stream
        chunks = []
        closed = False
        # Long-poll briefly instead of forcing the browser to wait for a fixed
        # polling interval. Data already waiting returns immediately.
        try:
            readable, _, _ = select.select([stream], [], [], 0.25)
        except (OSError, ValueError):
            readable = [stream]
        if not readable:
            return self._json({"data": "", "closed": False})
        while True:
            try:
                chunk = stream.recv(65536)
                if not chunk:
                    closed = True
                    break
                clean = cli.decode(chunk)
                if clean:
                    chunks.append(clean)
            except BlockingIOError:
                break
            except (ConnectionResetError, OSError):
                closed = True
                break
        if closed:
            with self.server.cli_lock:
                self.server.cli_sessions.pop(session, None)
            stream.close()
        self._json({"data": b"".join(chunks).decode("utf-8", "replace"), "closed": closed})

    def _asset(self, path: str) -> None:
        name = "index.html" if path == "/" else str(PurePosixPath(path.lstrip("/")))
        if ".." in PurePosixPath(name).parts:
            return self.send_error(HTTPStatus.NOT_FOUND)
        target = files("saslik.web").joinpath(name)
        if not target.is_file():
            return self.send_error(HTTPStatus.NOT_FOUND)
        data = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetypes.guess_type(name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, value: dict, status: HTTPStatus = HTTPStatus.OK,
              cors_origin: str = "") -> None:
        data = json.dumps(value).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            if cors_origin:
                self.send_header("Access-Control-Allow-Origin", cors_origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            # Closing or reloading the browser routinely cancels an active
            # CLI long-poll request. The response is already irrelevant and
            # must not turn a normal disconnect into a server traceback.
            return

    def log_message(self, fmt: str, *args) -> None:
        pass


def serve(host: str = "127.0.0.1", port: int = 8765, display_mode: str = "app",
          runner: LabRunner | None = None) -> None:
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback:
        print("VAROVÁNÍ: Saslik UI a laboratorní porty budou dostupné ze sítě.")
        print("Používej pouze důvěryhodnou laboratorní síť nebo host firewall.")
    active_runner = runner or LabRunner()
    server = SaslikServer((host, port), active_runner)
    server.start_guardian()
    url = f"http://{host}:{server.server_port}/"
    print(f"Saslik hoří na {url}")
    print(f"App okno spustíš ručně: {app_launch_command(url)}")
    print("Ctrl-C ukončí Saslik.")
    opened_with = open_frontend(url, display_mode)
    if display_mode == "app" and opened_with == "browser":
        print("App browser nenalezen, otevírám běžný výchozí browser.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSaslik zhasíná.")
    finally:
        server.server_close()
        if active_runner.spider.is_dir():
            print("Guardian uklízí routing a lab…")
