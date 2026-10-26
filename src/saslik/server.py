from __future__ import annotations

import json
import base64
import html
import ipaddress
import io
import mimetypes
import os
import pty
import re
import secrets
import select
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import tempfile
import time
import zipfile
from .licensing import LicensingError, licensing_report, tunnel_features
from .portal_auth import (ensure_portal_credentials, portal_account_info,
                          record_portal_login, set_portal_password,
                          verify_portal_password)
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, quote, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

import segno

from .runner import LabRunner, data_root
from .ca import install_store, remove_store, store_status
from .instance import Instance, remember_instance
from .identity import active_name, identity_root, list_identities
from .components import SystemdComponents
from .settings import provision_settings, public_settings, setting_value
from .crash import clear_reports, reports as crash_reports, save_bundle as save_crash_bundle
from .workspace import COMPONENT_SOURCES, component_source_status, source_changes
from .version import saslik_version_status
from .files import (delete_path, file_revision, list_directory, make_directory,
                    read_file, target_path, write_file)
from .dev import (MAX_PATCH_BYTES, apply_named_patch, clear_patch_history,
                  list_patches, reapply_patch, remember_applied_patch,
                  revert_all_patches, revert_patch)
from .debug import DEBUG_COMPONENTS, component_binary, debug_status, gdb_client_arguments
from .dev_queries import run_query as run_dev_query
from .runtime import WorkspaceRuntime
from .pairing import PairingStore, PskServer
from .portal_tls import details as portal_tls_details
from .portal_tls import ensure as ensure_portal_tls
from .portal_tls import generate as generate_portal_tls
from .maintenance import LOG_BACKUPS, PROCESS_LOG_LIMIT, RotatingLog, save_logpack


SASLIK_LOG_TAIL_BYTES = 256 * 1024
WEB_LOG_SOURCES = {
    "smithproxy": "smithproxy.log",
    "spider": "spider.log",
    "spider-frontend": "frontend.log",
    "sift": "sift.log",
    "pcap-storage": "pcap-storage.log",
    "pcap-viewer": "pcap-viewer.log",
    "lored": "lored.log",
    "e2e-probe": "e2e-probe.log",
}


def log_tail(path: Path, limit: int = SASLIK_LOG_TAIL_BYTES) -> dict:
    """Return a bounded UTF-8 tail suitable for the live web log viewer."""
    try:
        stat = path.stat()
        with path.open("rb") as source:
            if stat.st_size > limit:
                source.seek(stat.st_size - limit)
                source.readline()  # Drop the first, potentially partial line.
            data = source.read(limit)
    except FileNotFoundError:
        return {"data": "", "revision": "missing", "truncated": False}
    return {
        "data": data.decode("utf-8", "replace"),
        "revision": f"{stat.st_mtime_ns}:{stat.st_size}",
        "truncated": stat.st_size > limit,
    }


def web_log_tail(root: Path, lab: Path, source: str) -> dict:
    """Resolve only named Saslik log sources; never accept browser paths."""
    if source == "saslik":
        return log_tail(root / "saslik.log")
    if source == "skewer-api":
        return log_tail(root / "skewer-api.log")
    if source == "tuntom":
        paths = sorted((lab / "state").glob("tuntom-*.log"))
        if not paths:
            return {"data": "", "revision": "missing", "truncated": False}
        per_file = max(4096, SASLIK_LOG_TAIL_BYTES // len(paths))
        parts = []
        revisions = []
        truncated = False
        for path in paths:
            value = log_tail(path, per_file)
            parts.append(f"=== {path.name} ===\n{value['data']}")
            revisions.append(f"{path.name}:{value['revision']}")
            truncated = truncated or value["truncated"]
        return {"data": "\n".join(parts), "revision": "|".join(revisions),
                "truncated": truncated}
    filename = WEB_LOG_SOURCES.get(source)
    if filename is None:
        raise ValueError("Neznámý zdroj logu.")
    return log_tail(lab / "state" / filename)


SKEWER_DEB_URL = (
    "https://github.com/astibal/saslik-skewer/releases/latest/download/"
    "skewer-linux-amd64.deb"
)
TUNTOM_DEB_URLS = {
    "amd64": "https://github.com/astibal/tuntom/releases/latest/download/tuntom_amd64.deb",
    "arm64": "https://github.com/astibal/tuntom/releases/latest/download/tuntom_arm64.deb",
}
SKEWER_DEB_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}
SKEWER_DEB_MAX_BYTES = 256 * 1024 * 1024


def _fetch_github_deb(url: str, label: str):
    """Fetch one fixed release package without becoming an open proxy."""
    response = urlopen(url, timeout=30)
    final_url = urlparse(response.geturl())
    if final_url.scheme != "https" or final_url.hostname not in SKEWER_DEB_HOSTS:
        response.close()
        raise ValueError(f"{label} release redirected outside the trusted download hosts.")
    declared = int(response.headers.get("Content-Length", "0") or 0)
    if declared > SKEWER_DEB_MAX_BYTES:
        response.close()
        raise ValueError(f"{label} package is unexpectedly large.")
    package = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
    total = 0
    try:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > SKEWER_DEB_MAX_BYTES:
                raise ValueError(f"{label} package is unexpectedly large.")
            package.write(chunk)
    except Exception:
        package.close()
        raise
    finally:
        response.close()
    package.seek(0)
    return package, total


def fetch_skewer_deb():
    return _fetch_github_deb(SKEWER_DEB_URL, "Skewer")


def fetch_tuntom_deb(architecture: str):
    try:
        url = TUNTOM_DEB_URLS[architecture]
    except KeyError as exc:
        raise ValueError("Unsupported Tuntom package architecture.") from exc
    return _fetch_github_deb(url, "Tuntom")


def skewer_discovery(workspace: str, network_root: Path = Path("/sys/class/net")) -> dict:
    """Describe the directly-connected lab ingress without configuring the client."""
    runtime = WorkspaceRuntime.for_instance(workspace)
    ifindex = network_root / runtime.host_interface / "ifindex"
    try:
        generation = ifindex.read_text(encoding="ascii").strip()
        available = True
    except OSError:
        generation, available = "", False
    return {
        "version": 1,
        "available": available,
        "workspace": workspace,
        "gateway": runtime.namespace_address,
        "host_interface": runtime.host_interface,
        "generation": generation,
    }


def skewer_ca(lab: Path, instance: str) -> dict:
    """Publish only the active workspace's public CA, never its private key."""
    root = identity_root(lab, active_name(lab, instance), instance)
    path = root / ("certs/default/ca-cert.pem" if root.name == "state" else "certs-default/ca-cert.pem")
    try:
        with path.open("rb") as source:
            pem = source.read(32769)
        if len(pem) > 32768:
            return {"ca_error": "CA certificate is too large"}
        return {"ca_pem": pem.decode("ascii")}
    except (OSError, UnicodeError):
        return {"ca_error": "Workspace CA is not available yet"}


def _safe_report_icon(value: object) -> str:
    prefix = "data:image/png;base64,"
    icon = str(value or "")
    if not icon.startswith(prefix) or len(icon) > 32768:
        return ""
    try:
        data = base64.b64decode(icon[len(prefix):], validate=True)
    except (ValueError, TypeError):
        return ""
    if (len(data) < 24 or len(data) > 24576
            or data[:8] != b"\x89PNG\r\n\x1a\n"
            or data[12:16] != b"IHDR"):
        return ""
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    if not (1 <= width <= 64 and 1 <= height <= 64):
        return ""
    return prefix + base64.b64encode(data).decode("ascii")


def pairing_qr_data_url(link: str) -> str:
    """Render a pairing secret locally without disclosing it to a QR service."""
    qr = segno.make(link, error="m")
    output = io.BytesIO()
    qr.save(output, kind="svg", scale=5, border=2,
            dark="#101613", light="#f4f7f5")
    encoded = base64.b64encode(output.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def normalize_skewer_report(value: object) -> dict:
    """Validate the intentionally small, read-only client status document."""
    if not isinstance(value, dict) or value.get("version") != 1:
        raise ValueError("Nepodporovaná verze Skewer reportu.")
    hostname = str(value.get("hostname", "")).strip()
    if not hostname or len(hostname) > 253 or not re.fullmatch(r"[A-Za-z0-9_.-]+", hostname):
        raise ValueError("Neplatný hostname ve Skewer reportu.")
    ca = value.get("ca", {})
    if not isinstance(ca, dict) or not isinstance(ca.get("stores", []), list):
        raise ValueError("Neplatný CA stav ve Skewer reportu.")
    applications = []
    seen_applications = set()
    for raw in ca.get("applications", [])[:128]:
        if not isinstance(raw, dict):
            continue
        app_id = str(raw.get("id", ""))[:128]
        alias = str(raw.get("alias", ""))[:256]
        if (not app_id or app_id in seen_applications
                or not re.fullmatch(r"[A-Za-z0-9_.:-]+", app_id)):
            continue
        seen_applications.add(app_id)
        applications.append({"id": app_id, "alias": alias or app_id,
                             "recognized": bool(raw.get("recognized")),
                             "icon": _safe_report_icon(raw.get("icon"))})
    stores = []
    for raw in ca.get("stores", [])[:256]:
        if not isinstance(raw, dict):
            continue
        application_id = str(raw.get("application_id", ""))[:128]
        if application_id not in seen_applications:
            application_id = ""
        lifecycle = str(raw.get("snap_lifecycle", "unknown"))
        if lifecycle not in {"current", "common", "retained", "unknown"}:
            lifecycle = "unknown"
        try:
            matches = max(0, min(int(raw.get("matches", 0) or 0), 10000))
        except (ValueError, TypeError):
            matches = 0
        stores.append({
            "key": str(raw.get("key", ""))[:1024],
            "label": str(raw.get("label", ""))[:256],
            "path": str(raw.get("path", ""))[:1024],
            "system": bool(raw.get("system")),
            "available": bool(raw.get("available")),
            "installed": bool(raw.get("installed")),
            "detail": str(raw.get("detail", ""))[:512],
            "matches": matches,
            "application_id": application_id,
            "snap_name": str(raw.get("snap_name", ""))[:128],
            "snap_revision": str(raw.get("snap_revision", ""))[:64],
            "snap_state": str(raw.get("snap_state", ""))[:128],
            "snap_lifecycle": lifecycle,
        })
    return {
        "version": 1,
        "hostname": hostname,
        "skewer_version": str(value.get("skewer_version", ""))[:64],
        "ca": {"fingerprint": str(ca.get("fingerprint", ""))[:128],
               "applications": applications, "stores": stores},
    }


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


@dataclass
class GdbSession:
    process: subprocess.Popen
    fd: int
    created_at: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass
        if self.process.poll() is None:
            self.process.terminate()


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


class SaslikServer(ThreadingHTTPServer):
    def __init__(self, address, runner: LabRunner, *, devel: bool = False,
                 log_root: Path | None = None):
        super().__init__(address, Handler)
        self.runner = runner
        self.devel = devel
        self.csrf = secrets.token_urlsafe(24)
        self.portal_username, self.portal_configured, self.portal_credentials_path = \
            ensure_portal_credentials(log_root or runner.root)
        self.portal_auth_lock = threading.Lock()
        self.portal_sessions: dict[str, float] = {}
        self.portal_sessions_lock = threading.Lock()
        self.login_failures: dict[str, list[float]] = {}
        self.login_failures_lock = threading.Lock()
        self.cli_sessions: dict[str, CliSession] = {}
        self.gdb_sessions: dict[str, GdbSession] = {}
        self.cli_lock = threading.Lock()
        self.spider_bootstraps = SpiderBootstrapStore()
        self.skewer_last_seen = 0.0
        self.skewer_reports: dict[str, dict] = {}
        self.skewer_reports_lock = threading.Lock()
        self.tunnel_targets: dict[str, str] = {}
        self.tunnel_targets_lock = threading.Lock()
        self.skewer_audit_log = RotatingLog((log_root or runner.root) / "skewer-api.log",
                                            PROCESS_LOG_LIMIT, LOG_BACKUPS)
        self.psk_server = None
        self.tls_context: ssl.SSLContext | None = None
        self.tls_certificate: Path | None = None
        self.tls_lock = threading.Lock()
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
        if self.devel:
            command.append("--devel")
        subprocess.run(command, check=True)
        deadline = time.monotonic() + 3
        while not self.guardian_socket.exists() and time.monotonic() < deadline:
            time.sleep(0.03)
        if not self.guardian_socket.exists():
            raise RuntimeError("Privilegovaný guardian nenaběhl.")

    def guardian_request(self, action: str, instance: Instance | None = None,
                         **options: object) -> bool:
        return self.guardian_exchange(action, instance, **options).get("ok") is True

    def guardian_exchange(self, action: str, instance: Instance | None = None,
                          **options: object) -> dict:
        if not self.guardian_socket.exists():
            return {"ok": False, "error": "Guardian unavailable"}
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
                client.shutdown(socket.SHUT_WR)
                response = bytearray()
                while len(response) < 65536:
                    chunk = client.recv(min(4096, 65536 - len(response)))
                    if not chunk:
                        break
                    response.extend(chunk)
                    if b"\n" in chunk:
                        break
                result = json.loads(response)
                return result if isinstance(result, dict) else {"ok": False}
        except (OSError, ValueError):
            return {"ok": False, "error": "Guardian communication failed"}

    def guardian_stop(self) -> bool:
        return self.guardian_request("stop")

    def guardian_arm(self) -> bool:
        return self.guardian_request("arm")

    def server_close(self) -> None:
        if self.psk_server is not None:
            self.psk_server.shutdown()
            self.psk_server.server_close()
        with self.cli_lock:
            sessions = list(self.cli_sessions.values())
            self.cli_sessions.clear()
        for session in sessions:
            try:
                session.stream.close()
            except OSError:
                pass
        for session in list(self.gdb_sessions.values()):
            session.close()
        self.gdb_sessions.clear()
        self.guardian_stop()
        self.skewer_audit_log.close()
        super().server_close()

    def skewer_audit(self, message: str) -> None:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.skewer_audit_log.write(f"{timestamp} {message}\n")


class Handler(BaseHTTPRequestHandler):
    # The UI polls several APIs. Reusing one TLS connection avoids a complete
    # certificate verification (and noisy browser diagnostics for the local
    # self-signed certificate) for every individual request.
    protocol_version = "HTTP/1.1"
    server: SaslikServer

    def _portal_token(self) -> str:
        header = self.headers.get("Cookie", "")
        return next((part.strip().split("=", 1)[1] for part in header.split(";")
                     if part.strip().startswith("saslik_session=")), "")

    def _portal_session(self) -> bool:
        token = self._portal_token()
        now = time.monotonic()
        with self.server.portal_sessions_lock:
            expired = [key for key, deadline in self.server.portal_sessions.items()
                       if deadline <= now]
            for key in expired:
                del self.server.portal_sessions[key]
            return bool(token and self.server.portal_sessions.get(token, 0) > now)

    def _portal_session_remaining(self) -> int:
        token = self._portal_token()
        with self.server.portal_sessions_lock:
            return max(0, int(self.server.portal_sessions.get(token, 0) - time.monotonic()))

    def _login_page(self, *, error: str = "", status: HTTPStatus = HTTPStatus.OK) -> None:
        template = files("saslik.web").joinpath("login.html").read_text(encoding="utf-8")
        mottos = [line.strip() for line in files("saslik.web").joinpath("mottos.txt")
                  .read_text(encoding="utf-8").splitlines() if line.strip()]
        message = f'<p class="login-error">{html.escape(error)}</p>' if error else ""
        if self.server.portal_configured:
            title = "Welcome back."
            subtitle = "Sign in to manage this Saslik appliance."
            form = (
                '<form method="post" action="/login" autocomplete="on">'
                '<label>Username<input name="username" value="saslik" '
                'autocomplete="username" required autofocus></label>'
                '<label>Password<input name="password" type="password" '
                'autocomplete="current-password" required></label>'
                '<button type="submit">Enter the workspace <span>→</span></button></form>'
            )
        else:
            title = "Claim your Saslik."
            subtitle = "Create the administrator password for this new appliance."
            form = (
                '<form method="post" action="/setup" autocomplete="off">'
                '<p class="setup-note">First-access setup is open until this password is saved. '
                'Connect the appliance only to a trusted network.</p>'
                '<label>New password<input name="password" type="password" '
                'autocomplete="new-password" minlength="12" maxlength="128" required autofocus></label>'
                '<label>Repeat password<input name="confirm" type="password" '
                'autocomplete="new-password" minlength="12" maxlength="128" required></label>'
                '<button type="submit">Claim appliance <span>→</span></button></form>'
            )
        data = template.replace("{{MOTTO}}", html.escape(secrets.choice(mottos))) \
                       .replace("{{TITLE}}", title).replace("{{SUBTITLE}}", subtitle) \
                       .replace("{{FORM}}", form).replace("{{ERROR}}", message).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _require_portal_session(self, path: str) -> bool:
        if self._portal_session():
            return True
        if path.startswith("/api/"):
            self._json({"error": "Authentication required"}, HTTPStatus.UNAUTHORIZED)
        else:
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/login")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
        return False

    def _connect_info(self) -> None:
        """Return only connection data that is safe to show before login."""
        snapshot = self.server.runner.snapshot()
        endpoints = snapshot.get("endpoints", {})
        definitions = (
            ("proxy", "PROXY", "HTTP CONNECT", "Set this proxy in your browser or application.", False, "#60e69a"),
            ("spider_ui", "APPLICATION", "Smithproxy Spider", "Live traffic browser and scripting workbench.", True, "#ff6b35"),
            ("pcap_viewer", "APPLICATION", "CZ PCAP Viewer", "Open captures stored by this lab.", True, "#54b8ff"),
            ("smithproxy_api", "API", "Smithproxy API", "Machine-readable proxy control and telemetry endpoint.", True, "#b889ff"),
            ("sift", "API", "Sift API", "Payload analysis and enrichment endpoint.", True, "#e6bd60"),
        )
        items = [
            {"kind": kind, "title": title, "description": description,
             "url": endpoints[key], "open": opened, "color": color}
            for key, kind, title, description, opened, color in definitions
            if isinstance(endpoints.get(key), str) and endpoints[key]
        ]
        items.extend((
            {"kind": "TRUST", "title": "Certificate Authority",
             "description": "Install this CA to trust TLS intercepted by the lab.",
             "url": "/connect/ca.pem", "open": True, "color": "#60e69a"},
            {"kind": "CLIENT", "title": "Skewer",
             "description": "Connect a client and select applications routed through the lab.",
             "url": "/api/skewer", "open": False, "color": "#ff8055"},
        ))
        services = snapshot.get("services", {})
        self._json({"items": items, "running": any(
            isinstance(service, dict) and service.get("state") == "running"
            for service in services.values())})

    def _login(self) -> None:
        if not self.server.portal_configured:
            return self._login_page()
        peer = self.client_address[0] if self.client_address else "unknown"
        now = time.monotonic()
        with self.server.login_failures_lock:
            failures = [stamp for stamp in self.server.login_failures.get(peer, [])
                        if now - stamp < 60]
            self.server.login_failures[peer] = failures
        if len(failures) >= 5:
            return self._login_page(error="Too many attempts. Try again in a minute.",
                                    status=HTTPStatus.TOO_MANY_REQUESTS)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096:
                raise ValueError
            form = parse_qs(self.rfile.read(size).decode("utf-8"), keep_blank_values=True)
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
        except (ValueError, UnicodeDecodeError):
            return self._login_page(error="Invalid login request.", status=HTTPStatus.BAD_REQUEST)
        if not (secrets.compare_digest(username, self.server.portal_username)
                and verify_portal_password(self.server.portal_credentials_path, password)):
            with self.server.login_failures_lock:
                self.server.login_failures.setdefault(peer, failures).append(now)
            return self._login_page(error="The username or password is incorrect.",
                                    status=HTTPStatus.FORBIDDEN)
        with self.server.login_failures_lock:
            self.server.login_failures.pop(peer, None)
        with self.server.portal_auth_lock:
            record_portal_login(self.server.portal_credentials_path)
        return self._issue_session()

    def _setup(self) -> None:
        if self.server.portal_configured:
            return self._login_page(error="This appliance has already been claimed.",
                                    status=HTTPStatus.CONFLICT)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096:
                raise ValueError
            form = parse_qs(self.rfile.read(size).decode("utf-8"), keep_blank_values=True)
            password = form.get("password", [""])[0]
            confirm = form.get("confirm", [""])[0]
            if password != confirm:
                return self._login_page(error="The passwords do not match.",
                                        status=HTTPStatus.BAD_REQUEST)
            with self.server.portal_auth_lock:
                if self.server.portal_configured:
                    raise RuntimeError("This appliance has already been claimed.")
                set_portal_password(self.server.portal_credentials_path, password)
                self.server.portal_configured = True
        except ValueError as exc:
            return self._login_page(error=str(exc) or "Invalid setup request.",
                                    status=HTTPStatus.BAD_REQUEST)
        except (UnicodeDecodeError, RuntimeError) as exc:
            return self._login_page(error=str(exc), status=HTTPStatus.CONFLICT)
        return self._issue_session()

    def _issue_session(self) -> None:
        now = time.monotonic()
        token = secrets.token_urlsafe(32)
        with self.server.portal_sessions_lock:
            self.server.portal_sessions[token] = now + 12 * 60 * 60
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"saslik_session={token}; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Strict")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/login":
            if self._portal_session():
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self._login_page()
        if path == "/logout":
            token = self._portal_token()
            with self.server.portal_sessions_lock:
                self.server.portal_sessions.pop(token, None)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "saslik_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/connect":
            return self._asset("/connect.html")
        if path == "/api/connect":
            return self._connect_info()
        if path == "/connect/ca.pem":
            return self._ca()
        public_downloads = {
            "/downloads/skewer-linux-amd64.deb",
            "/downloads/tuntom-linux-amd64.deb",
            "/downloads/tuntom_amd64.deb",
            "/downloads/tuntom_arm64.deb",
        }
        public_assets = {"/login.css", "/login-connect.css", "/connect.css", "/connect.js",
                         "/saslik-mark.svg", "/card-scenes/cli.png"}
        if path in public_assets:
            return self._asset(path)
        if path not in public_downloads and path != "/api/skewer" \
                and not self._require_portal_session(path):
            return
        if path == "/api/status":
            snapshot = self.server.runner.snapshot()
            snapshot["skewer_connected"] = time.monotonic() - self.server.skewer_last_seen < 30.0
            return self._json(snapshot)
        if path == "/api/licensing":
            try:
                return self._json({"available": True, **licensing_report()})
            except LicensingError as exc:
                return self._json({"available": False, "error": str(exc)})
        if path == "/api/logs/tail":
            source = parse_qs(parsed.query).get("source", ["saslik"])[0]
            try:
                return self._json(web_log_tail(data_root(), self.server.runner.lab, source))
            except ValueError as exc:
                return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if path == "/api/portal-tls":
            if self.server.tls_certificate is None:
                return self._json({"error": "HTTPS certificate is unavailable"},
                                  HTTPStatus.SERVICE_UNAVAILABLE)
            return self._json(portal_tls_details(self.server.tls_certificate))
        if path == "/api/skewer":
            self.server.skewer_last_seen = time.monotonic()
            return self._json(skewer_discovery(self.server.runner.instance), cors_origin="*")
        if path == "/downloads/skewer-linux-amd64.deb":
            return self._skewer_download()
        if path in {"/downloads/tuntom-linux-amd64.deb", "/downloads/tuntom_amd64.deb"}:
            return self._tuntom_download("amd64")
        if path == "/downloads/tuntom_arm64.deb":
            return self._tuntom_download("arm64")
        if path == "/api/skewer/reports":
            with self.server.skewer_reports_lock:
                reports = [dict(report, online=time.monotonic() - report["seen_monotonic"] < 30)
                           for report in self.server.skewer_reports.values()]
            for report in reports:
                identity = report.get("client_id", "")
                if identity and self.server.psk_server is not None:
                    report.update(self.server.psk_server.client_runtime(identity))
                report.pop("seen_monotonic", None)
            reports.sort(key=lambda report: report["hostname"].casefold())
            return self._json({"reports": reports})
        if path == "/api/session":
            account = portal_account_info(self.server.portal_credentials_path)
            return self._json({"csrf": self.server.csrf, "devel": self.server.devel,
                               "username": self.server.portal_username,
                               "expires_in": self._portal_session_remaining(), **account})
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
        if path == "/api/files/list":
            return self._files_list(parsed.query)
        if path == "/api/files/read":
            return self._files_read(parsed.query)
        if path == "/api/files/download":
            return self._files_download(parsed.query)
        if path == "/api/dev/patches":
            if not self.server.devel:
                return self._json({"error": "Dev režim není povolený."},
                                  HTTPStatus.FORBIDDEN)
            workspace = parse_qs(parsed.query).get("workspace", [""])[0]
            lab, _ = self._workspace_target(workspace)
            return self._json({"patches": list_patches(lab)})
        if path == "/api/dev/query":
            if not self.server.devel:
                return self._json({"error": "Dev režim není povolený."},
                                  HTTPStatus.FORBIDDEN)
            name = parse_qs(parsed.query).get("name", [""])[0]
            try:
                result = run_dev_query(name)
                return self._json(result, HTTPStatus.OK if result["ok"]
                                  else HTTPStatus.BAD_GATEWAY)
            except ValueError as exc:
                return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except RuntimeError as exc:
                return self._json({"error": str(exc)}, HTTPStatus.BAD_GATEWAY)
        if path == "/api/dev/debug":
            if not self.server.devel:
                return self._json({"error": "Dev režim není povolený."},
                                  HTTPStatus.FORBIDDEN)
            workspace = parse_qs(parsed.query).get("workspace", [""])[0]
            lab, name = self._workspace_target(workspace)
            return self._json(self._debug_payload(lab, name))
        if path == "/api/dev/gdb/session":
            if not self.server.devel:
                return self._json({"error": "Dev režim není povolený."},
                                  HTTPStatus.FORBIDDEN)
            return self._gdb_read(parse_qs(parsed.query).get("session", [""])[0])
        if path == "/api/workspace/settings":
            workspace = parse_qs(parsed.query).get("workspace", [""])[0]
            lab, _ = self._workspace_target(workspace)
            return self._json({"settings": public_settings(lab),
                               "crash_reports": len(crash_reports(lab)),
                               "source_changes": source_changes(lab)})
        if path == "/api/workspace/source-status":
            query = parse_qs(parsed.query)
            workspace = query.get("workspace", [""])[0]
            component = query.get("component", [""])[0]
            lab, _ = self._workspace_target(workspace)
            try:
                return self._json(component_source_status(lab, component))
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                return self._json({"state": "error", "detail": str(exc)})
        if path == "/api/version/status":
            try:
                return self._json(saslik_version_status())
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                return self._json({"state": "error", "detail": str(exc)})
        if path == "/api/crashes/files":
            return self._crash_files(parse_qs(parsed.query).get("workspace", [""])[0])
        if path == "/api/logpack":
            return self._logpack(parse_qs(parsed.query).get("workspace", [""])[0])
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

    def _file_query(self, query: str) -> tuple[Path, str]:
        values = parse_qs(query)
        lab, _ = self._workspace_target(values.get("workspace", [""])[0])
        return lab, values.get("path", [""])[0]

    def _files_list(self, query: str) -> None:
        try:
            lab, value = self._file_query(query)
            self._json(list_directory(lab, value))
        except (OSError, ValueError, RuntimeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _files_read(self, query: str) -> None:
        try:
            lab, value = self._file_query(query)
            data = read_file(lab, value)
            if b"\0" in data:
                raise ValueError("Binární soubor nelze otevřít v textovém editoru.")
            self._json({"path": value, "content": data.decode("utf-8"),
                        "revision": file_revision(lab, value)})
        except UnicodeDecodeError:
            self._json({"error": "Soubor není platný UTF-8 text."}, HTTPStatus.BAD_REQUEST)
        except (OSError, ValueError, RuntimeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _files_download(self, query: str) -> None:
        try:
            lab, value = self._file_query(query)
            target, _ = target_path(lab, value)
            if not target.is_file():
                raise ValueError("Stáhnout lze pouze běžný soubor.")
            filename = target.name.replace('"', "")
            ascii_name = filename.encode("ascii", "ignore").decode() or "download"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition",
                             f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(filename)}')
            self.send_header("Content-Length", str(target.stat().st_size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with target.open("rb") as source:
                shutil.copyfileobj(source, self.wfile, length=1024 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            return
        except (OSError, ValueError, RuntimeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _tuntom_download(self, architecture: str) -> None:
        try:
            package, size = fetch_tuntom_deb(architecture)
        except (HTTPError, URLError, OSError, ValueError) as exc:
            return self._json({"error": f"Tuntom balíček se nepodařilo stáhnout: {exc}"},
                              HTTPStatus.BAD_GATEWAY)
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/vnd.debian.binary-package")
            self.send_header("Content-Disposition",
                             f'attachment; filename="tuntom_{architecture}.deb"')
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            shutil.copyfileobj(package, self.wfile, length=1024 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            package.close()

    def _skewer_download(self) -> None:
        try:
            package, size = fetch_skewer_deb()
        except (HTTPError, URLError, OSError, ValueError) as exc:
            return self._json({"error": f"Skewer balíček se nepodařilo stáhnout: {exc}"},
                              HTTPStatus.BAD_GATEWAY)
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/vnd.debian.binary-package")
            self.send_header("Content-Disposition",
                             'attachment; filename="skewer-linux-amd64.deb"')
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            shutil.copyfileobj(package, self.wfile, length=1024 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            package.close()

    def _files_upload(self, query: str) -> None:
        try:
            if self.headers.get("X-Saslik-CSRF") != self.server.csrf:
                return self._json({"error": "Neplatný CSRF token."}, HTTPStatus.FORBIDDEN)
            lab, value = self._file_query(query)
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 1024 * 1024 * 1024:
                raise ValueError("Soubor je příliš velký.")
            payload = self.rfile.read(length)
            if len(payload) != length:
                raise ValueError("Upload byl přerušen.")
            write_file(lab, value, payload)
            self._json({"ok": True, "path": value})
        except (OSError, ValueError, RuntimeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _files_action(self, body: dict) -> None:
        operation = str(body.get("operation", ""))
        lab, _ = self._workspace_target(str(body.get("workspace", "")))
        value = str(body.get("path", ""))
        if operation == "save":
            content = body.get("content", "")
            if not isinstance(content, str) or len(content.encode("utf-8")) > 2 * 1024 * 1024:
                raise ValueError("Text je pro editor příliš velký.")
            write_file(lab, value, content.encode("utf-8"))
        elif operation == "mkdir":
            make_directory(lab, value)
        elif operation == "delete":
            delete_path(lab, value, override_locked=body.get("override_locked") is True)
        else:
            raise ValueError("Neznámá souborová operace.")
        self._json({"ok": True})

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
        if path == "/login":
            return self._login()
        if path == "/setup":
            return self._setup()
        # The one-time, origin-bound bootstrap code is the authentication
        # capability. Spider cannot possess the portal's browser cookie.
        if path == "/api/spider/bootstrap/redeem":
            return self._spider_bootstrap_redeem()
        if not self._require_portal_session(path):
            return
        if path == "/api/skewer/report":
            try:
                declared = int(self.headers.get("Content-Length", "0"))
                if declared < 1 or declared > 256 * 1024:
                    return self._json({"error": "Skewer report má neplatnou velikost."},
                                      HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                report = normalize_skewer_report(json.loads(self.rfile.read(declared)))
                report["received_at"] = time.time()
                report["seen_monotonic"] = time.monotonic()
                with self.server.skewer_reports_lock:
                    self.server.skewer_reports[report["hostname"]] = report
                self.server.skewer_last_seen = time.monotonic()
                return self._json({"ok": True})
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if self.headers.get("X-Saslik-CSRF") != self.server.csrf:
            return self._json({"error": "Neplatný CSRF token."}, HTTPStatus.FORBIDDEN)
        if path == "/api/skewer/pairing":
            if self.server.psk_server is None:
                return self._json({"error": "PSK endpoint není dostupný."}, HTTPStatus.SERVICE_UNAVAILABLE)
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    raise ValueError()
                value = json.loads(self.rfile.read(size))
                if not isinstance(value, dict):
                    raise ValueError()
                store = self.server.psk_server.store
                action = value.get("action", "link")
                if action == "rotate":
                    store.rotate()
                elif action == "revoke":
                    identity = str(value.get("identity", ""))
                    # Serialize against authenticated tunnel-open: once the
                    # credential disappears no concurrent request can renew it.
                    with store.lock:
                        store.revoke(identity)
                        result = self.server.guardian_exchange("tunnel-revoke", peer=identity)
                    with self.server.tunnel_targets_lock:
                        self.server.tunnel_targets.pop(identity, None)
                    if not result.get("ok"):
                        return self._json({"error": "Credential revoked; tunnel cleanup pending lease expiry"}, status=503)
                elif action not in {"link", "list"}:
                    raise ValueError()
                if action == "list":
                    with store.lock:
                        return self._json({"clients": [{"identity": key, "instance": item["instance"], "state": item["state"], "permissions": item["permissions"]} for key, item in store.clients.items()]})
                target = str(value.get("host") or host)
                if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", target):
                    raise ValueError()
                link = store.link(target, self.server.psk_server.server_address[1])
                return self._json({"link": link,
                                   "qr": pairing_qr_data_url(link)})
            except (ValueError, TypeError, KeyError):
                return self._json({"error": "Neplatný požadavek párování."}, HTTPStatus.BAD_REQUEST)
        if path.startswith("/api/dev/") and not self.server.devel:
            return self._json({"error": "Dev režim není povolený. Spusť Saslik s --devel."},
                              HTTPStatus.FORBIDDEN)
        if path == "/api/binary/load":
            return self._binary_load()
        if path == "/api/binary/clear":
            return self._binary_clear()
        if path == "/api/files/upload":
            return self._files_upload(urlparse(self.path).query)
        if path not in {"/api/action", "/api/cli", "/api/ca/action", "/api/identity/action",
                        "/api/workspace/action", "/api/workspace/settings",
                        "/api/crashes/clear", "/api/crashes/diagnose",
                        "/api/spider/bootstrap", "/api/files/action", "/api/dev/patch",
                        "/api/dev/debug", "/api/dev/gdb/session", "/api/portal-tls/renew",
                        "/api/account/password"}:
            return self.send_error(HTTPStatus.NOT_FOUND)
        try:
            declared = int(self.headers.get("Content-Length", "0"))
            limit = (24 * 1024 * 1024 if path == "/api/identity/action" else
                     3 * 1024 * 1024 if path == "/api/files/action" else
                     2 * MAX_PATCH_BYTES + 65536 if path == "/api/dev/patch" else 4096)
            if declared > limit:
                return self._json({"error": "Požadavek je příliš velký."},
                                  HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            length = min(declared, limit)
            body = json.loads(self.rfile.read(length) or b"{}")
            if path == "/api/account/password":
                current = str(body.get("current", ""))
                password = str(body.get("password", ""))
                if not verify_portal_password(self.server.portal_credentials_path, current):
                    return self._json({"error": "Současné heslo není správné."},
                                      HTTPStatus.BAD_REQUEST)
                try:
                    set_portal_password(self.server.portal_credentials_path, password)
                except ValueError as exc:
                    return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                token = self._portal_token()
                with self.server.portal_sessions_lock:
                    deadline = self.server.portal_sessions.get(token, 0)
                    self.server.portal_sessions.clear()
                    if deadline > time.monotonic():
                        self.server.portal_sessions[token] = deadline
                return self._json({"ok": True})
            if path == "/api/portal-tls/renew":
                with self.server.tls_lock:
                    certificate, key = generate_portal_tls(data_root() / "portal-tls",
                                                           self.server.server_address[0])
                    self.server.tls_context.load_cert_chain(certificate, key)
                    self.server.tls_certificate = certificate
                return self._json(portal_tls_details(certificate))
            if path == "/api/spider/bootstrap":
                return self._spider_bootstrap_issue(str(body.get("origin", "")))
            if path == "/api/cli":
                return self._cli_write(body)
            if path == "/api/files/action":
                return self._files_action(body)
            if path == "/api/dev/patch":
                lab, _ = self._workspace_target(str(body.get("workspace", "")))
                operation = str(body.get("operation", "apply"))
                if operation == "apply":
                    result = apply_named_patch(
                        lab, str(body.get("project", "")), str(body.get("patch", "")),
                        str(body.get("name", "")))
                elif operation == "remember-applied":
                    result = remember_applied_patch(
                        lab, str(body.get("project", "")), str(body.get("patch", "")),
                        str(body.get("name", "")))
                elif operation == "revert":
                    result = revert_patch(lab, str(body.get("id", "")))
                elif operation == "reapply":
                    result = reapply_patch(lab, str(body.get("id", "")))
                elif operation == "revert-all":
                    result = {"reverted": revert_all_patches(lab)}
                elif operation == "clear":
                    result = {"cleared": clear_patch_history(lab)}
                else:
                    raise ValueError("Neznámá operace patch journalu.")
                return self._json({"ok": True, "result": result,
                                   "patches": list_patches(lab),
                                   "source_changes": source_changes(lab)})
            if path == "/api/dev/debug":
                lab, instance = self._workspace_target(str(body.get("workspace", "")))
                component = str(body.get("component", ""))
                operation = str(body.get("operation", "start"))
                if operation not in {"start", "stop"}:
                    raise ValueError("Neznámá GDB operace.")
                if not self.server.guardian_request(
                        f"gdb-{operation}", Instance(instance, self.server.runner.egress),
                        component=component):
                    raise RuntimeError("Privilegovaný GDB helper operaci odmítl.")
                return self._json({"ok": True, **self._debug_payload(lab, instance)})
            if path == "/api/dev/gdb/session":
                return self._gdb_session(body)
            if path == "/api/ca/action":
                return self._ca_action(str(body.get("store", "")),
                                       str(body.get("operation", "install")))
            if path == "/api/identity/action":
                return self._identity_action(str(body.get("operation", "activate")),
                                             str(body.get("identity", "")),
                                             str(body.get("bundle", "")),
                                             str(body.get("new_name", "")))
            if path == "/api/workspace/action":
                return self._workspace_action(str(body.get("operation", "select")),
                                              str(body.get("workspace", "")),
                                              str(body.get("new_name", "")),
                                              str(body.get("component", "")))
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
                str(body.get("component", "")),
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
            "spider_backend",
            f"https://127.0.0.1:{self.server.runner.runtime.public_port('spider')}")
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
                                         self.server.runner.expose_address,
                                         devel=self.server.devel).status()
            running = any(value.get("state") in {"running", "starting"}
                          for value in services.values())
            items.append({
                "name": instance.name,
                "runtime": WorkspaceRuntime.for_instance(instance.name).prefix,
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

    def _logpack(self, workspace: str) -> None:
        try:
            lab, instance = self._workspace_target(workspace)
            handle = tempfile.NamedTemporaryFile(prefix="saslik-logpack-", suffix=".tar.gz",
                                                 delete=False)
            path = Path(handle.name)
            handle.close()
            save_logpack(data_root(), lab, instance, path)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Disposition",
                             f'attachment; filename="saslik-{instance}-logpack.tar.gz"')
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

    def _workspace_action(self, operation: str, workspace: str, new_name: str,
                          component: str = "") -> None:
        instance = Instance.load(workspace)
        if operation == "stop":
            if not self.server.guardian_request("stop", instance):
                raise RuntimeError("Guardian workspace nezastavil.")
            return self._json({"ok": True, "workspace": workspace})
        if operation == "discard-source-changes":
            if self.server.runner.operation_running():
                raise RuntimeError("Počkej na dokončení právě probíhající operace.")
            if component and component not in COMPONENT_SOURCES:
                raise ValueError(f"Neznámá komponenta: {component}")
            changed = source_changes(instance.data_dir)
            if component:
                changed = [name for name in changed
                           if name == COMPONENT_SOURCES[component][0]]
            command = ["sudo", "-n", sys.executable, "-m", "saslik.workspace",
                       "discard-changes", str(instance.data_dir)]
            if component:
                command.extend(["--component", component])
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    text=True)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or
                                   "Zahození lokálních změn selhalo.")
            return self._json({"ok": True, "workspace": workspace, "discarded": changed})
        if self.server.runner.operation_running():
            raise RuntimeError("Workspace nelze přepnout během probíhající operace.")
        services = SystemdComponents(instance.data_dir, instance.name,
                                     self.server.runner.expose_address,
                                     devel=self.server.devel).status()
        if operation == "select":
            instance.ensure_config()
            self.server.runner.select_instance(instance)
            remember_instance(instance.name)
            self.server.guardian_arm()
            return self._json({"ok": True, "workspace": instance.name})
        if any(value.get("state") in {"running", "starting"}
               for value in services.values()):
            raise RuntimeError("Běžící workspace nelze přejmenovat ani klonovat.")
        if operation == "create":
            if workspace in {item.name for item in Instance.discover()}:
                raise RuntimeError(f"Workspace už existuje: {workspace}")
            instance.ensure_config()
            self.server.runner.select_instance(instance)
            remember_instance(instance.name)
            self.server.guardian_arm()
            return self._json({"ok": True, "workspace": instance.name})
        if operation == "clone":
            command = [sys.executable, "-m", "saslik.instance", "clone",
                       workspace, new_name]
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    text=True)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or "Klonování workspace selhalo.")
            return self._json({"ok": True, "workspace": new_name})
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
            raise RuntimeError("Binary bundle lze měnit jen při zastaveném workspace.")

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
            raise RuntimeError("Identitu lze přepnout jen při zastaveném workspace.")
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

    def _ca_action(self, store: str, operation: str = "install") -> None:
        if operation not in {"install", "remove"}:
            raise ValueError("Neznámá operace s CA store.")
        instance = Instance(self.server.runner.instance, self.server.runner.egress)
        if store == "system":
            pkexec = shutil.which("pkexec")
            source = self.server.runner.lab / "state/certs/default/ca-cert.pem"
            if pkexec:
                command = [pkexec, sys.executable, "-m", "saslik.ca", "-i", instance.name,
                           "system-install" if operation == "install" else "system-remove"]
                if operation == "install":
                    command += ["--certificate", str(source)]
            elif shutil.which("sudo") and os.environ.get("SUDO_ASKPASS"):
                command = ["sudo", "-A", sys.executable, "-m", "saslik.ca", "-i", instance.name,
                           "system-install" if operation == "install" else "system-remove"]
                if operation == "install":
                    command += ["--certificate", str(source)]
            else:
                raise RuntimeError("Chybí pkexec nebo nakonfigurovaný SUDO_ASKPASS.")
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            return self._json({"pending": True}, HTTPStatus.ACCEPTED)
        count = install_store(instance, store) if operation == "install" else remove_store(instance, store)
        self._json({"installed" if operation == "install" else "removed": count})

    def _cli_write(self, body: dict) -> None:
        action = str(body.get("action", ""))
        session = str(body.get("session", ""))
        if action == "open":
            runtime = WorkspaceRuntime.for_workspace(
                self.server.runner.lab, self.server.runner.instance)
            stream = socket.create_connection(
                (runtime.namespace_address, 55000), timeout=3)
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

    def _gdb_session(self, body: dict) -> None:
        action = str(body.get("action", ""))
        session_id = str(body.get("session", ""))
        if action == "open":
            workspace = str(body.get("workspace", ""))
            component = str(body.get("component", ""))
            lab, instance = self._workspace_target(workspace)
            states = {item["component"]: item for item in debug_status(lab, instance)}
            state = states.get(component)
            if not state or not state.get("active"):
                raise RuntimeError("Nejdřív spusť gdbserver pro tuto komponentu.")
            gdb = shutil.which("gdb")
            if not gdb:
                raise RuntimeError("Chybí GDB. Nainstaluj balíček gdb.")
            binary = component_binary(lab, component)
            port = DEBUG_COMPONENTS[component][1]
            master, slave = pty.openpty()
            try:
                process = subprocess.Popen(
                    gdb_client_arguments(gdb, binary, port),
                    stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                    start_new_session=True,
                )
            finally:
                os.close(slave)
            os.set_blocking(master, False)
            session_id = secrets.token_urlsafe(18)
            self.server.gdb_sessions[session_id] = GdbSession(process, master)
            return self._json({"session": session_id, "component": component})
        session = self.server.gdb_sessions.get(session_id)
        if session is None:
            return self._json({"error": "GDB relace neexistuje."}, HTTPStatus.NOT_FOUND)
        session.last_seen = time.monotonic()
        if action == "write":
            os.write(session.fd, str(body.get("data", "")).encode("utf-8"))
            return self._json({"ok": True})
        if action == "close":
            self.server.gdb_sessions.pop(session_id, None)
            session.close()
            return self._json({"ok": True})
        return self._json({"error": "Neznámá GDB akce."}, HTTPStatus.BAD_REQUEST)

    def _debug_payload(self, lab: Path, instance: str) -> dict[str, object]:
        address = ipaddress.ip_address(self.client_address[0])
        local_client = address.is_loopback or bool(
            address.version == 6 and address.ipv4_mapped and address.ipv4_mapped.is_loopback)
        components = debug_status(lab, instance)
        if not local_client:
            # A loopback command copied to a remote workstation is misleading.
            # The embedded console still runs GDB on the Saslik host.
            for component in components:
                component["command"] = ""
        return {"components": components, "local_client": local_client}

    def _gdb_read(self, session_id: str) -> None:
        session = self.server.gdb_sessions.get(session_id)
        if session is None:
            return self._json({"error": "GDB relace neexistuje."}, HTTPStatus.NOT_FOUND)
        session.last_seen = time.monotonic()
        chunks = []
        try:
            readable, _, _ = select.select([session.fd], [], [], 0.25)
            if readable:
                while True:
                    try:
                        chunk = os.read(session.fd, 65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    except BlockingIOError:
                        break
        except OSError:
            pass
        closed = session.process.poll() is not None
        if closed:
            self.server.gdb_sessions.pop(session_id, None)
            try:
                os.close(session.fd)
            except OSError:
                pass
        data = b"".join(chunks).decode("utf-8", errors="replace")
        return self._json({"data": data, "closed": closed})

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
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
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

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        """Audit only Skewer HTTP API calls; keep ordinary UI polling quiet."""
        path = urlparse(self.path).path
        if not path.startswith("/api/skewer"):
            return
        peer = self.client_address[0] if self.client_address else "unknown"
        self.server.skewer_audit(f"{peer} {self.command} {path} -> {code}")


def serve(host: str = "127.0.0.1", port: int = 8765,
          runner: LabRunner | None = None, *, devel: bool = False) -> None:
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback:
        print("VAROVÁNÍ: Saslik UI a laboratorní porty budou dostupné ze sítě.")
        print("Používej pouze důvěryhodnou laboratorní síť nebo host firewall.")
    active_runner = runner or LabRunner()
    active_runner.devel = devel
    certificate, key = ensure_portal_tls(data_root() / "portal-tls", host)
    server = SaslikServer((host, port), active_runner, devel=devel, log_root=data_root())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    server.tls_context = context
    server.tls_certificate = certificate
    server.socket = context.wrap_socket(server.socket, server_side=True)
    def paired_status():
        server.skewer_last_seen = time.monotonic()
        snapshot = active_runner.snapshot()
        detail = {key: snapshot.get(key) for key in ("identity", "instance", "runtime_state", "services", "endpoints")}
        detail["end_to_end"] = snapshot.get("health", {}).get("end_to_end", {})
        return {**skewer_discovery(active_runner.instance),
                **skewer_ca(active_runner.lab, active_runner.instance),
                "lab_status": detail, "ui_port": server.server_port,
                "features": tunnel_features()}
    def paired_report(client, payload):
        report = normalize_skewer_report(payload)
        report.update(received_at=time.time(), seen_monotonic=time.monotonic(), client_id=client)
        with server.skewer_reports_lock:
            # The authenticated identity owns this record; hostname is display
            # data only. Retire the old unauthenticated row during migration.
            previous = server.skewer_reports.get(report["hostname"])
            if previous and not previous.get("client_id"):
                del server.skewer_reports[report["hostname"]]
            server.skewer_reports[client] = report
        server.skewer_last_seen = time.monotonic()
        return {"ok": True}
    def paired_tunnel(client, payload, psk):
        # Only the TLS-PSK dispatcher calls this callback. Do not forward
        # arbitrary remote fields (paths, addresses or executable arguments).
        action = payload["action"]
        options = {"peer": client, "context": payload.get("context", "")}
        with server.tunnel_targets_lock:
            target_name = (active_runner.instance if action == "tunnel-open" else
                           server.tunnel_targets.get(client, active_runner.instance))
        target = Instance.load(target_name)
        if action == "tunnel-open":
            options["psk"] = psk.hex()
        result = server.guardian_exchange(action, target, **options)
        if not result.get("ok"):
            detail = str(result.get("error", "unknown guardian failure"))
            detail = " ".join(detail.split())[:500]
            server.skewer_audit(f"{client} PSK {action} guardian-error={detail}")
            # Privileged stderr may contain implementation details; expose a
            # stable error, never echo a credential-bearing request.
            return {"ok": False, "error": "Tunnel operation unavailable"}
        with server.tunnel_targets_lock:
            if action == "tunnel-open":
                server.tunnel_targets[client] = target.name
            elif action == "tunnel-close":
                server.tunnel_targets.pop(client, None)
        return result
    server.psk_server = PskServer((host, server.server_port + 1),
        PairingStore(data_root() / "skewer-clients.json"),
        paired_status, paired_report, paired_tunnel, audit=server.skewer_audit)
    threading.Thread(target=server.psk_server.serve_forever, daemon=True).start()
    server.start_guardian()
    maintenance_result = server.guardian_exchange("maintenance")
    if not maintenance_result.get("ok"):
        print("Saslik log maintenance: privileged ownership repair failed",
              file=sys.stderr)
    active_runner.component_action = lambda action, component: server.guardian_request(
        f"component-{action.removesuffix('-component')}", component=component)
    url = f"https://{host}:{server.server_port}/"
    print(f"Saslik hoří na {url}")
    if server.portal_configured:
        print("Portal login: účet saslik je nakonfigurovaný.")
    else:
        print(f"Portal login: první návštěva {url} nastaví heslo účtu saslik.")
    if devel:
        print("Dev režim je zapnutý; UI může měnit zdrojové checkouty workspace.")
    print("Ctrl-C ukončí Saslik.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSaslik zhasíná.")
    finally:
        server.server_close()
        if active_runner.spider.is_dir():
            print("Guardian uklízí routing a workspace…")
