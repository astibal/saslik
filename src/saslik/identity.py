from __future__ import annotations

import os
import io
import re
import secrets
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import zipfile


REQUIRED = ("smithproxy.cfg", "state.env", "certs-default")
IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def active_name(lab: Path, fallback: str = "default") -> str:
    marker = lab / "state/identity-name"
    if marker.is_file():
        value = marker.read_text(encoding="utf-8").strip()
        if value:
            return value
    return fallback


def list_identities(lab: Path, fallback: str = "default") -> list[dict[str, object]]:
    state = lab / "state"
    result: list[dict[str, object]] = []
    if (state / "smithproxy.cfg").is_file():
        result.append({"id": active_name(lab, fallback), "active": True})
    archive_root = state / "identities"
    if archive_root.is_dir():
        for path in sorted(archive_root.iterdir(), reverse=True):
            if path.is_dir() and all((path / name).exists() for name in REQUIRED):
                result.append({"id": path.name, "active": False})
    return result


def identity_root(lab: Path, identity: str, fallback: str = "default") -> Path:
    if identity == active_name(lab, fallback):
        return lab / "state"
    if not identity or Path(identity).name != identity:
        raise RuntimeError("Neplatné jméno identity.")
    path = lab / "state/identities" / identity
    if not path.is_dir() or not all((path / name).exists() for name in REQUIRED):
        raise RuntimeError(f"Identita neexistuje: {identity}")
    return path


def rename_workspace(lab: Path, old_name: str, new_name: str,
                     fallback: str = "default") -> None:
    if not IDENTITY_RE.fullmatch(new_name):
        raise RuntimeError("Jméno workspace smí obsahovat písmena, čísla, tečku, _ a -.")
    if old_name == new_name:
        return
    state = lab / "state"
    archive_root = state / "identities"
    if new_name == active_name(lab, fallback) or (archive_root / new_name).exists():
        raise RuntimeError(f"Workspace už existuje: {new_name}")
    if old_name == active_name(lab, fallback):
        (state / "identity-name").write_text(new_name + "\n", encoding="utf-8")
        return
    source = identity_root(lab, old_name, fallback)
    source.rename(archive_root / new_name)


def import_bundle(lab: Path, name: str, payload: bytes, fallback: str = "default") -> Path:
    if not IDENTITY_RE.fullmatch(name):
        raise RuntimeError("Jméno identity smí obsahovat písmena, čísla, tečku, _ a -.")
    archive_root = lab / "state/identities"
    target = archive_root / name
    if target.exists() or name == active_name(lab, fallback):
        raise RuntimeError(f"Identita už existuje: {name}")
    archive_root.mkdir(parents=True, exist_ok=True)
    work = archive_root / f".import-{os.getpid()}-{secrets.token_hex(4)}"
    work.mkdir(mode=0o700)
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as bundle:
            files = [item for item in bundle.infolist() if not item.is_dir()]
            if sum(item.file_size for item in files) > 16 * 1024 * 1024:
                raise RuntimeError("Rozbalená identita je příliš velká.")
            allowed = {"smithproxy.cfg", "state.env"}
            for item in files:
                if item.filename in allowed:
                    destination = work / item.filename
                elif item.filename.startswith("certs/") and Path(item.filename).name == item.filename[6:]:
                    destination = work / "certs-default" / Path(item.filename).name
                else:
                    raise RuntimeError(f"Neočekávaný soubor v identitě: {item.filename}")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(bundle.read(item))
        for required in (work / "smithproxy.cfg", work / "state.env",
                         work / "certs-default/ca-cert.pem", work / "certs-default/ca-key.pem"):
            if not required.is_file():
                raise RuntimeError(f"Bundle neobsahuje {required.name}.")
        cert_public = subprocess.run(
            ["openssl", "x509", "-in", str(work / "certs-default/ca-cert.pem"),
             "-pubkey", "-noout"], check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL).stdout
        key_public = subprocess.run(
            ["openssl", "pkey", "-in", str(work / "certs-default/ca-key.pem"),
             "-pubout"], check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL).stdout
        if cert_public != key_public:
            raise RuntimeError("CA certifikát a privátní klíč importované identity k sobě nepatří.")
        (work / "state.env").chmod(0o600)
        for key in (work / "certs-default").glob("*-key.pem"):
            key.chmod(0o600)
        work.rename(target)
        return target
    except (zipfile.BadZipFile, subprocess.CalledProcessError) as exc:
        raise RuntimeError("Soubor není platný Saslik identity bundle.") from exc
    finally:
        if work.exists():
            shutil.rmtree(work)


def activate(lab: Path, identity: str, fallback: str = "default") -> None:
    state = lab / "state"
    current_name = active_name(lab, fallback)
    if identity == current_name:
        return
    selected = identity_root(lab, identity, fallback)
    archive_root = state / "identities"
    archive_root.mkdir(parents=True, exist_ok=True)
    archived_current = archive_root / current_name
    suffix = 1
    while archived_current.exists():
        archived_current = archive_root / f"{current_name}-{suffix}"
        suffix += 1
    archived_current.mkdir()
    try:
        shutil.move(str(state / "smithproxy.cfg"), str(archived_current / "smithproxy.cfg"))
        shutil.move(str(state / "state.env"), str(archived_current / "state.env"))
        shutil.move(str(state / "certs/default"), str(archived_current / "certs-default"))
        shutil.move(str(selected / "smithproxy.cfg"), str(state / "smithproxy.cfg"))
        shutil.move(str(selected / "state.env"), str(state / "state.env"))
        shutil.move(str(selected / "certs-default"), str(state / "certs/default"))
        selected.rmdir()
        (state / "identity-name").write_text(identity + "\n", encoding="utf-8")
    except Exception:
        # Leave a recoverable archive instead of deleting either identity.
        raise RuntimeError("Přepnutí identity nebylo dokončeno; identity zůstaly v archivu.")


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def rotate(lab: Path, fallback: str = "default") -> Path:
    state = lab / "state"
    config = state / "smithproxy.cfg"
    state_env = state / "state.env"
    certs = state / "certs/default"
    for required in (config, state_env, certs / "ca-cert.pem", certs / "ca-key.pem"):
        if not required.exists():
            raise RuntimeError(f"Identitu nelze otočit, chybí {required}.")

    values: dict[str, str] = {}
    env_lines = state_env.read_text(encoding="utf-8").splitlines()
    for line in env_lines:
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    old_api_key = values.get("SMITHPROXY_API_KEY", "")
    if not old_api_key:
        raise RuntimeError("state.env neobsahuje Smithproxy API key.")
    new_api_key = secrets.token_hex(24)
    new_spider_token = secrets.token_hex(24)

    config_text = config.read_text(encoding="utf-8")
    quoted_old_key = f'"{old_api_key}"'
    if config_text.count(quoted_old_key) != 1:
        raise RuntimeError("Aktuální API key nebyl v konfiguraci nalezen právě jednou.")
    new_config = config_text.replace(quoted_old_key, f'"{new_api_key}"', 1)

    work = state / f".identity-{os.getpid()}"
    if work.exists():
        raise RuntimeError(f"Dočasný adresář už existuje: {work}")
    work.mkdir(mode=0o700)
    try:
        # "New identity" rotates credentials and the leaf certificate.  The
        # per-instance CA is deliberately stable: rotating it here would
        # silently invalidate every Firefox/Chromium/system trust store.
        shutil.copy2(certs / "ca-cert.pem", work / "ca-cert.pem")
        shutil.copy2(certs / "ca-key.pem", work / "ca-key.pem")
        _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(work / "srv-key.pem"),
                 "-out", str(work / "server.csr"), "-subj", "/CN=smithproxy-test")
        extensions = work / "server.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:smithproxy-test,IP:10.254.77.2,IP:10.254.77.1\n",
            encoding="ascii",
        )
        _openssl("x509", "-req", "-in", str(work / "server.csr"),
                 "-CA", str(work / "ca-cert.pem"), "-CAkey", str(work / "ca-key.pem"),
                 "-CAcreateserial", "-out", str(work / "srv-cert.pem"), "-days", "30",
                 "-sha256", "-extfile", str(extensions))
        shutil.copy2(work / "srv-key.pem", work / "portal-key.pem")
        shutil.copy2(work / "srv-cert.pem", work / "portal-cert.pem")
        shutil.copy2(work / "srv-key.pem", work / "cl-key.pem")
        shutil.copy2(work / "srv-cert.pem", work / "cl-cert.pem")
        shutil.copy2(certs / "sslca.json", work / "sslca.json")
        for key in work.glob("*-key.pem"):
            key.chmod(0o600)

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive = state / "identities" / active_name(lab, fallback)
        suffix = 1
        while archive.exists():
            archive = state / "identities" / f"{stamp}-{suffix}"
            suffix += 1
        archive.mkdir(parents=True)
        shutil.copy2(config, archive / "smithproxy.cfg")
        shutil.copy2(state_env, archive / "state.env")
        shutil.move(str(certs), str(archive / "certs-default"))
        work.rename(certs)

        updated_env = []
        for line in env_lines:
            if line.startswith("SMITHPROXY_API_KEY="):
                line = f"SMITHPROXY_API_KEY={new_api_key}"
            elif line.startswith("SPIDER_TOKEN="):
                line = f"SPIDER_TOKEN={new_spider_token}"
            updated_env.append(line)
        config.write_text(new_config, encoding="utf-8")
        state_env.write_text("\n".join(updated_env) + "\n", encoding="utf-8")
        state_env.chmod(0o600)
        (state / "identity-name").write_text(f"workspace-{stamp}\n", encoding="utf-8")
        print(f"Nová identita vytvořena. Předchozí je archivována v {archive}")
        return archive
    finally:
        if work.exists():
            shutil.rmtree(work)


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="saslik-identity")
    parser.add_argument("action", choices=("rotate", "activate", "import", "rename"))
    parser.add_argument("lab", type=Path)
    parser.add_argument("identity", nargs="?")
    parser.add_argument("new_name", nargs="?")
    parser.add_argument("--fallback", default="default")
    args = parser.parse_args(argv)
    try:
        if args.action == "rotate":
            rotate(args.lab, args.fallback)
        elif args.action == "rename":
            if not args.identity or not args.new_name:
                raise RuntimeError("Přejmenování vyžaduje staré a nové jméno workspace.")
            rename_workspace(args.lab, args.identity, args.new_name, args.fallback)
        elif args.action == "import":
            if not args.identity:
                raise RuntimeError("Import vyžaduje jméno identity.")
            source = Path(os.environ.get("SASLIK_IDENTITY_BUNDLE", ""))
            if not source.is_file():
                raise RuntimeError("Chybí soubor identity bundle.")
            import_bundle(args.lab, args.identity, source.read_bytes(), args.fallback)
        elif not args.identity:
            raise RuntimeError("Chybí identita k aktivaci.")
        else:
            activate(args.lab, args.identity, args.fallback)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"saslik-identity: {exc}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
