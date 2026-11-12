"""Seal and first-boot identity reseeding for Saslik Takeaway images."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from .runtime import WorkspaceRuntime
from .settings import SETTINGS, load_settings, update_settings

MARKER_NAME = ".takeaway-first-boot.json"
PENDING_SECRET = "TAKEAWAY_SECRET_PENDING_FIRST_BOOT"
RUNTIME_FILES = {"e2e-health.json", "server.csr", "server.ext", "smithproxy-gui.env"}
RUNTIME_DIRECTORIES = {"crashes", "identities", "pcap-viewer", "gretom"}
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".har"}


def _openssl(*arguments: str) -> None:
    subprocess.run(["openssl", *arguments], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _atomic_text(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _environment(path: Path) -> tuple[list[str], dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    values = {}
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return lines, values


def _replace_environment(lines: list[str], replacements: dict[str, str]) -> str:
    remaining = dict(replacements)
    result = []
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in remaining:
            line = f"{key}={remaining.pop(key)}"
        result.append(line)
    result.extend(f"{key}={value}" for key, value in remaining.items())
    return "\n".join(result) + "\n"


def _generate_workspace_certificates(directory: Path, runtime: WorkspaceRuntime,
                                     sslca: Path | None) -> None:
    directory.mkdir(mode=0o700)
    if sslca and sslca.is_file():
        shutil.copy2(sslca, directory / "sslca.json")
    _openssl("req", "-x509", "-newkey", "rsa:3072", "-sha256", "-days", "365",
             "-nodes", "-keyout", str(directory / "ca-key.pem"), "-out",
             str(directory / "ca-cert.pem"), "-subj",
             "/CN=Smithproxy Saslik CA/O=Smithproxy Saslik/C=CZ",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    request = directory / "server.csr"
    extensions = directory / "server.ext"
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout",
             str(directory / "srv-key.pem"), "-out", str(request),
             "-subj", "/CN=smithproxy-test")
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:smithproxy-test,IP:{runtime.namespace_address},"
        f"IP:{runtime.host_address}\n", encoding="ascii")
    _openssl("x509", "-req", "-in", str(request), "-CA",
             str(directory / "ca-cert.pem"), "-CAkey", str(directory / "ca-key.pem"),
             "-CAcreateserial", "-out", str(directory / "srv-cert.pem"), "-days", "365",
             "-sha256", "-extfile", str(extensions))
    for prefix in ("portal", "cl"):
        shutil.copy2(directory / "srv-key.pem", directory / f"{prefix}-key.pem")
        shutil.copy2(directory / "srv-cert.pem", directory / f"{prefix}-cert.pem")
    request.unlink(missing_ok=True)
    extensions.unlink(missing_ok=True)
    for key in directory.glob("*-key.pem"):
        key.chmod(0o600)


def _workspaces(root: Path) -> list[tuple[str, Path]]:
    result = []
    if (root / "lab").is_dir():
        result.append(("default", root / "lab"))
    instances = root / "instances"
    if instances.is_dir():
        result.extend((path.name, path) for path in sorted(instances.iterdir())
                      if path.is_dir() and not path.is_symlink())
    return result


def _clean_workspace(lab: Path) -> None:
    state = lab / "state"
    for directory in RUNTIME_DIRECTORIES:
        shutil.rmtree(state / directory, ignore_errors=True)
    for path in list(state.rglob("*")) if state.is_dir() else []:
        if path.is_dir() and path.name in RUNTIME_DIRECTORIES:
            shutil.rmtree(path, ignore_errors=True)
        elif path.is_file() and (path.name in RUNTIME_FILES
                                 or path.suffix in CAPTURE_SUFFIXES
                                 or path.name.endswith((".log", ".log.gz", ".pid", ".sock"))):
            path.unlink(missing_ok=True)
    settings = load_settings(lab)
    secret_settings = {key: "" for key, definition in SETTINGS.items()
                       if definition.get("secret") and key in settings}
    if secret_settings:
        update_settings(lab, secret_settings)
    for git in list(lab.rglob(".git")):
        if git.is_dir() and not git.is_symlink():
            shutil.rmtree(git)


def _clear_installation_credentials(root: Path) -> None:
    for path in (root / "portal-credentials.json", root / "skewer-clients.json",
                 root / "skewer-clients.json.lock"):
        path.unlink(missing_ok=True)
    for directory in (root / "portal-tls", root / "gateway"):
        shutil.rmtree(directory, ignore_errors=True)
    for path in root.glob("*.log*"):
        if path.is_file():
            path.unlink(missing_ok=True)


def seal(root: Path, source_data_root: str,
         target_data_root: str = "/var/lib/saslik") -> list[str]:
    """Remove source identity before a staging tree enters an image."""
    root = root.resolve()
    source = Path(source_data_root).resolve()
    if not source.is_dir():
        raise RuntimeError(f"Zdrojový Saslik data root neexistuje: {source}")
    if source == root:
        raise RuntimeError("Takeaway seal odmítá měnit živý Saslik data root.")
    _clear_installation_credentials(root)
    sealed = []
    for name, lab in _workspaces(root):
        state = lab / "state"
        config = state / "smithproxy.cfg"
        environment = state / "state.env"
        if config.exists() or environment.exists():
            if not config.exists() or not environment.exists():
                raise RuntimeError(f"Neúplný Takeaway workspace: {lab}")
            lines, values = _environment(environment)
            old_api_key = values.get("SMITHPROXY_API_KEY", "")
            if not old_api_key:
                raise RuntimeError(f"{environment} neobsahuje SMITHPROXY_API_KEY")
            config_text = config.read_text(encoding="utf-8")
            quoted = f'"{old_api_key}"'
            if config_text.count(quoted) != 1:
                raise RuntimeError(f"API key nebyl právě jednou nalezen v {config}")
            config_text = config_text.replace(quoted, f'"{PENDING_SECRET}"', 1)
            config_text = config_text.replace(str(source), target_data_root)
            env_text = _replace_environment(lines, {
                "SMITHPROXY_API_KEY": PENDING_SECRET,
                "SPIDER_TOKEN": PENDING_SECRET,
            }).replace(str(source), target_data_root)
            _atomic_text(config, config_text)
            _atomic_text(environment, env_text)
            certs = state / "certs/default"
            sslca = certs / "sslca.json"
            sslca_value = sslca.read_bytes() if sslca.is_file() else None
            shutil.rmtree(state / "certs", ignore_errors=True)
            if sslca_value is not None:
                sslca.parent.mkdir(parents=True, mode=0o700)
                sslca.write_bytes(sslca_value)
                sslca.chmod(0o600)
        _clean_workspace(lab)
        sealed.append(name)
    marker = {"format": 1, "source_data_root": str(source),
              "sealed_workspaces": sealed}
    _atomic_text(root / MARKER_NAME, json.dumps(marker, indent=2) + "\n")
    return sealed


def reseed_workspace(lab: Path, instance: str, source_data_root: str = "") -> None:
    """Replace every Saslik-managed workspace secret without keeping an archive."""
    state = lab / "state"
    config = state / "smithproxy.cfg"
    environment = state / "state.env"
    if not config.exists() and not environment.exists():
        return
    if not config.exists() or not environment.exists():
        raise RuntimeError(f"Neúplný Takeaway workspace: {lab}")
    runtime = WorkspaceRuntime.for_workspace(lab, instance)
    lines, values = _environment(environment)
    old_api_key = values.get("SMITHPROXY_API_KEY", "")
    if not old_api_key:
        raise RuntimeError(f"{environment} neobsahuje SMITHPROXY_API_KEY")
    config_text = config.read_text(encoding="utf-8")
    quoted = f'"{old_api_key}"'
    if config_text.count(quoted) != 1:
        raise RuntimeError(f"API key nebyl právě jednou nalezen v {config}")
    new_api_key = secrets.token_hex(24)
    new_spider_token = secrets.token_hex(24)
    new_config = config_text.replace(quoted, f'"{new_api_key}"', 1)
    target_root = str(lab.parent.parent if lab.parent.name == "instances" else lab.parent)
    if source_data_root:
        new_config = new_config.replace(source_data_root, target_root)
    certs = state / "certs/default"
    new_environment = _replace_environment(lines, {
        "SMITHPROXY_API_KEY": new_api_key,
        "SPIDER_TOKEN": new_spider_token,
        "SMITHPROXY_API_URL": f"https://{runtime.namespace_address}:55580",
        "SMITHPROXY_CONNECT_URL": f"http://{runtime.namespace_address}:33128",
        "SMITHPROXY_CALLBACK_URL": "http://127.0.0.1:18080/webhook",
        "SMITHPROXY_CA_CERT": str(certs / "ca-cert.pem"),
        "SMITHPROXY_CLI": f"{runtime.namespace_address}:55000",
    })
    if source_data_root:
        new_environment = new_environment.replace(source_data_root, target_root)

    temporary = Path(tempfile.mkdtemp(prefix=".takeaway-identity-", dir=state))
    staged_certs = temporary / "certs"
    old_certs = state / ".takeaway-old-certs"
    sslca = certs / "sslca.json"
    try:
        _generate_workspace_certificates(staged_certs, runtime, sslca if sslca.is_file() else None)
        _atomic_text(temporary / "smithproxy.cfg", new_config)
        _atomic_text(temporary / "state.env", new_environment)
        shutil.rmtree(old_certs, ignore_errors=True)
        if certs.exists():
            certs.rename(old_certs)
        else:
            certs.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        staged_certs.rename(certs)
        os.replace(temporary / "smithproxy.cfg", config)
        os.replace(temporary / "state.env", environment)
        shutil.rmtree(old_certs, ignore_errors=True)
    except Exception:
        if old_certs.exists() and not certs.exists():
            old_certs.rename(certs)
        raise
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    _clean_workspace(lab)


def first_boot(root: Path, marker: Path | None = None,
               generate_ssh_keys: bool = True) -> list[str]:
    root = root.resolve()
    marker = marker or root / MARKER_NAME
    value = json.loads(marker.read_text(encoding="utf-8"))
    if value.get("format") != 1:
        raise RuntimeError("Neznámý formát Saslik Takeaway markeru.")
    _clear_installation_credentials(root)
    completed = []
    for name, lab in _workspaces(root):
        reseed_workspace(lab, name, str(value.get("source_data_root") or ""))
        completed.append(name)
    if generate_ssh_keys:
        subprocess.run(["ssh-keygen", "-A"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    marker.unlink()
    return completed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-takeaway")
    parser.add_argument("action", choices=("seal", "first-boot"))
    parser.add_argument("--data-root", type=Path, default=Path("/var/lib/saslik"))
    parser.add_argument("--source-data-root")
    parser.add_argument("--target-data-root", default="/var/lib/saslik")
    parser.add_argument("--marker", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "seal":
            if not args.source_data_root:
                parser.error("seal vyžaduje --source-data-root")
            workspaces = seal(args.data_root, args.source_data_root, args.target_data_root)
            verb = "sealed"
        else:
            workspaces = first_boot(args.data_root, args.marker)
            verb = "initialized"
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError,
            json.JSONDecodeError) as exc:
        print(f"saslik-takeaway: {exc}", file=os.sys.stderr)
        return 1
    print(f"Takeaway identity {verb}: " + (", ".join(workspaces) or "no workspaces"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
