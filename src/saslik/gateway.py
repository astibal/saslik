from __future__ import annotations

import argparse
import ctypes
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from .instance import Instance
from .runtime import WorkspaceRuntime


PR_SET_PDEATHSIG = 1


def _terminate_with_parent() -> None:
    """Ask Linux to terminate nginx if the foreground Saslik process dies."""
    libc = ctypes.CDLL(None)
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM) != 0:
        raise OSError("prctl(PR_SET_PDEATHSIG) failed")


class GatewayError(RuntimeError):
    """Raised when the external HTTP gateway cannot be configured safely."""


def _nginx_quote(value: str | Path) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def workspace_locations(instances: list[Instance]) -> str:
    locations: list[str] = []
    for instance in sorted(instances, key=lambda item: item.workspace_id):
        if not instance.workspace_id:
            continue
        runtime = WorkspaceRuntime(instance.workspace_id)
        prefix = f"/ws{instance.workspace_id:03d}"
        address = runtime.namespace_address
        for suffix, port, tls, authenticated, websocket, preserve_path, landing in (
            ("spider", 15173, True, True, False, True, None),
            ("spider-api", 18080, True, True, True, False, None),
            ("viewer", 15174, True, True, False, True, None),
            ("smithproxy-api", 55580, True, False, False, False,
             "api/status/ping"),
            ("sift-api", 18081, False, False, False, False, "api/status"),
            ("lored-api", 8091, False, False, False, False, "readyz"),
        ):
            if landing:
                locations.append(f"""
    location = {prefix}/{suffix}/ {{
        return 302 {prefix}/{suffix}/{landing};
    }}""")
            upgrade = (
                "\n        proxy_set_header Upgrade $http_upgrade;"
                "\n        proxy_set_header Connection $connection_upgrade;"
                if websocket else ""
            )
            auth = ("\n        auth_request /__saslik_auth;"
                    "\n        error_page 401 = @saslik_login;" if authenticated else "")
            scheme = "https" if tls else "http"
            tls_options = "\n        proxy_ssl_verify off;" if tls else ""
            # A trailing slash replaces the matched prefix. Prefix-aware UI
            # servers receive the original URI and strip SCRIPT_NAME themselves.
            upstream = f"{scheme}://{address}:{port}" + ("" if preserve_path else "/")
            locations.append(f"""
    location ^~ {prefix}/{suffix}/ {{
        {auth.lstrip()}
        proxy_http_version 1.1;
        proxy_set_header Host 127.0.0.1;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Prefix {prefix}/{suffix};{upgrade}
        proxy_pass {upstream};{tls_options}
        proxy_request_buffering off;
        proxy_buffering off;
    }}""")
    return "\n".join(locations)


def nginx_config(*, host: str, port: int, upstream_port: int, certificate: Path,
                 key: Path, runtime_dir: Path, auth_secret: str,
                 instances: list[Instance]) -> str:
    listen_host = "[::]" if host == "::" else host
    return f"""worker_processes auto;
pid {_nginx_quote(runtime_dir / 'nginx.pid')};
error_log {_nginx_quote(runtime_dir / 'error.log')} warn;

events {{ worker_connections 1024; }}

http {{
    access_log off;
    client_max_body_size 2g;
    client_body_temp_path {_nginx_quote(runtime_dir / 'client-body')};
    proxy_temp_path {_nginx_quote(runtime_dir / 'proxy')};
    map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}

    server {{
        listen {listen_host}:{port} ssl;
        ssl_certificate {_nginx_quote(certificate)};
        ssl_certificate_key {_nginx_quote(key)};
        ssl_protocols TLSv1.2 TLSv1.3;

        location = /__saslik_auth {{
            internal;
            proxy_pass http://127.0.0.1:{upstream_port}/api/gateway/auth;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header Cookie $http_cookie;
            proxy_set_header X-Saslik-Gateway {auth_secret};
        }}

        location @saslik_login {{
            return 302 /login;
        }}
{workspace_locations(instances)}

        location / {{
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_pass http://127.0.0.1:{upstream_port};
            proxy_request_buffering off;
            proxy_buffering off;
        }}
    }}
}}
"""


class NginxGateway:
    """Own one unprivileged nginx process in front of the Saslik control plane."""

    def __init__(self, *, host: str, port: int, upstream_port: int,
                 certificate: Path, key: Path, data_root: Path) -> None:
        executable = shutil.which("nginx")
        if executable is None:
            raise GatewayError(
                "Chybí nginx. Nainstaluj systémový balík nginx a spusť Saslik znovu."
            )
        self.executable = executable
        self.host = host
        self.port = port
        self.upstream_port = upstream_port
        self.certificate = certificate
        self.key = key
        self.runtime_dir = data_root / "gateway"
        self.config_path = self.runtime_dir / "nginx.conf"
        self.auth_secret = secrets.token_urlsafe(32)
        self.process: subprocess.Popen | None = None

    def _write_config(self) -> None:
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        for name in ("client-body", "proxy"):
            (self.runtime_dir / name).mkdir(exist_ok=True)
        content = nginx_config(
            host=self.host, port=self.port, upstream_port=self.upstream_port,
            certificate=self.certificate, key=self.key,
            runtime_dir=self.runtime_dir, auth_secret=self.auth_secret,
            instances=Instance.discover(),
        )
        temporary = self.config_path.with_suffix(".tmp")
        temporary.write_text(content, encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(self.config_path)

    def _command(self, *arguments: str) -> list[str]:
        return [self.executable, "-p", str(self.runtime_dir),
                "-c", str(self.config_path), *arguments]

    def start(self) -> None:
        self._write_config()
        checked = subprocess.run(self._command("-t"), capture_output=True, text=True)
        if checked.returncode:
            raise GatewayError(checked.stderr.strip() or "Kontrola nginx konfigurace selhala.")
        # Keep pre-exec work out of Saslik's multi-threaded process. The tiny
        # single-threaded wrapper installs PDEATHSIG and immediately becomes
        # nginx through exec(), preserving normal signal and exit semantics.
        self.process = subprocess.Popen([
            sys.executable, "-m", "saslik.gateway", "--supervise",
            *self._command("-g", "daemon off;"),
        ])
        time.sleep(0.08)
        if self.process.poll() is not None:
            raise GatewayError("Nginx gateway se ihned ukončila.")

    def reload(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise GatewayError("Nginx gateway neběží.")
        self._write_config()
        reloaded = subprocess.run(self._command("-s", "reload"), capture_output=True, text=True)
        if reloaded.returncode:
            raise GatewayError(reloaded.stderr.strip() or "Reload nginx gateway selhal.")

    def close(self) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--supervise", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    if not arguments.supervise or not arguments.command:
        parser.error("gateway is an internal Saslik process supervisor")
    _terminate_with_parent()
    os.execv(arguments.command[0], arguments.command)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
