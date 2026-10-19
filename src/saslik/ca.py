from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

from .instance import Instance


def nickname(instance: str) -> str:
    return f"Saslik {instance} CA"


STORE_LABELS = {
    "firefox": "Firefox",
    "firefox-snap": "Firefox Snap",
    "firefox-flatpak": "Firefox Flatpak",
    "thunderbird": "Thunderbird",
    "thunderbird-snap": "Thunderbird Snap",
    "chromium": "Chromium / NSS",
    "chromium-snap": "Chromium Snap",
    "brave-snap": "Brave Snap",
    "system": "Systémový store",
}


def nss_databases() -> list[tuple[str, str, Path]]:
    databases: list[tuple[str, str, Path]] = []
    firefox_roots = (
        ("firefox", "Firefox", Path.home() / ".mozilla/firefox"),
        ("firefox-snap", "Firefox Snap", Path.home() / "snap/firefox/common/.mozilla/firefox"),
        ("firefox-flatpak", "Firefox Flatpak", Path.home() / ".var/app/org.mozilla.firefox/.mozilla/firefox"),
        ("thunderbird", "Thunderbird", Path.home() / ".thunderbird"),
        ("thunderbird-snap", "Thunderbird Snap", Path.home() / "snap/thunderbird/common/.thunderbird"),
    )
    seen: set[Path] = set()
    for key, browser, root in firefox_roots:
        if not root.is_dir():
            continue
        for cert_db in sorted(root.glob("*/cert9.db")):
            database = cert_db.parent.resolve()
            if database not in seen:
                databases.append((key, browser, database))
                seen.add(database)
    chromium = Path.home() / ".pki/nssdb"
    if chromium.is_dir():
        databases.append(("chromium", "Chromium / NSS", chromium))
    # Snap gives every Brave revision a private HOME.  After a snap refresh an
    # already running browser can keep using the previous numbered revision,
    # while `current` points at the new one.  Cover every retained NSS DB with
    # the single Brave Snap button so trust works before and after restart.
    for snap_name, key, label in (
        ("brave", "brave-snap", "Brave Snap"),
        ("chromium", "chromium-snap", "Chromium Snap"),
    ):
        snap_root = Path.home() / "snap" / snap_name
        snap_databases = sorted(snap_root.glob("*/.pki/nssdb")) if snap_root.is_dir() else []
        for snap_database in snap_databases:
            if not (snap_database / "cert9.db").is_file():
                continue
            database = snap_database.resolve()
            if database not in seen:
                databases.append((key, label, database))
                seen.add(database)
    return databases


def certificate(instance: Instance) -> Path:
    return instance.data_dir / "state/certs/default/ca-cert.pem"


def _fingerprint_pem(value: str | bytes) -> str:
    text = value.decode("ascii") if isinstance(value, bytes) else value
    der = ssl.PEM_cert_to_DER_cert(text)
    return hashlib.sha256(der).hexdigest()


def _has_explicit_ssl_trust(database: Path, name: str) -> bool:
    """Chrome/Brave require NSS's explicit `T` bit for a local root.

    A certificate imported only as `C,,` is cryptographically a CA, but the
    current Chromium certificate manager presents it as an intermediate and
    does not use it as a local trust anchor.
    """
    listing = _certutil(["-L", "-d", f"sql:{database}"], check=False)
    for line in listing.stdout.splitlines():
        if line.strip().startswith(name):
            attributes = line.split()[-1]
            return "T" in attributes.split(",", 1)[0]
    return False


def system_certificate_path(instance: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", instance)
    return Path("/usr/local/share/ca-certificates") / f"saslik-{safe}.crt"


def store_status(instance: Instance) -> list[dict]:
    source = certificate(instance)
    expected = _fingerprint_pem(source.read_bytes()) if source.is_file() else None
    grouped: dict[str, list[Path]] = {}
    for key, _label, database in nss_databases():
        grouped.setdefault(key, []).append(database)
    result = []
    for key in ("firefox", "firefox-snap", "firefox-flatpak", "thunderbird",
                "thunderbird-snap", "chromium",
                "chromium-snap", "brave-snap"):
        databases = grouped.get(key, [])
        installed = 0
        if expected:
            for database in databases:
                found = _certutil(["-L", "-a", "-d", f"sql:{database}", "-n", nickname(instance.name)], check=False)
                try:
                    installed += (found.returncode == 0 and _fingerprint_pem(found.stdout) == expected
                                  and _has_explicit_ssl_trust(database, nickname(instance.name)))
                except (ValueError, ssl.SSLError):
                    pass
        result.append({"key": key, "label": STORE_LABELS[key], "available": bool(databases),
                       "installed": bool(databases) and installed == len(databases),
                       "detail": f"{installed}/{len(databases)} profilů" if databases else "nenalezen"})
    target = system_certificate_path(instance.name)
    system_installed = False
    if expected and target.is_file():
        try:
            system_installed = _fingerprint_pem(target.read_bytes()) == expected
        except (ValueError, ssl.SSLError, PermissionError):
            pass
    result.append({"key": "system", "label": STORE_LABELS["system"],
                   "available": bool(shutil.which("update-ca-certificates")),
                   "installed": system_installed,
                   "detail": "pro celý systém"})
    return result


def install_store(instance: Instance, store: str) -> int:
    source = certificate(instance)
    if not source.is_file():
        raise RuntimeError("CA ještě není vygenerovaná; nejdřív rozpal lab.")
    databases = [database for key, _label, database in nss_databases() if key == store]
    if not databases:
        raise RuntimeError(f"Store {STORE_LABELS.get(store, store)} nebyl nalezen.")
    for database in databases:
        _certutil(["-D", "-d", f"sql:{database}", "-n", nickname(instance.name)], check=False)
        _certutil(["-A", "-d", f"sql:{database}", "-n", nickname(instance.name), "-t", "CT,,", "-i", str(source)])
    return len(databases)


def install_system(instance_name: str, source: Path) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Instalace do systémového store vyžaduje administrátorská práva.")
    if not source.is_file():
        raise RuntimeError("Zdrojový CA certifikát neexistuje.")
    target = system_certificate_path(instance_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o644)
    subprocess.run(["update-ca-certificates"], check=True)


def _certutil(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("certutil")
    if not binary:
        raise RuntimeError("Chybí certutil. Na Ubuntu/Debian nainstaluj: sudo apt install libnss3-tools")
    try:
        return subprocess.run(
            [binary, *arguments], check=check, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip().splitlines()
        suffix = f" ({detail[-1]})" if detail else ""
        raise RuntimeError(
            "Úprava NSS databáze selhala. Úplně ukonči browser a zkus to znovu" + suffix
        ) from exc


def install(instance: Instance) -> None:
    source = certificate(instance)
    if not source.is_file():
        raise RuntimeError("CA ještě není vygenerovaná; nejdřív rozpal lab.")
    name = nickname(instance.name)
    databases = nss_databases()
    if not databases:
        raise RuntimeError("Nebyla nalezena žádná Firefox/Chromium NSS databáze.")
    for _key, _browser, database in databases:
        _certutil(["-D", "-d", f"sql:{database}", "-n", name], check=False)
        _certutil(["-A", "-d", f"sql:{database}", "-n", name, "-t", "CT,,", "-i", str(source)])
    print(f"CA nainstalována do {len(databases)} profilů. Restartuj browser.")


def remove(instance: Instance) -> None:
    removed = 0
    for _key, _browser, database in nss_databases():
        result = _certutil(["-D", "-d", f"sql:{database}", "-n", nickname(instance.name)], check=False)
        removed += result.returncode == 0
    print(f"CA odstraněna z {removed} NSS databází." if removed else "CA nebyla nainstalovaná.")


def status(instance: Instance) -> int:
    found = 0
    databases = nss_databases()
    for _key, _browser, database in databases:
        result = _certutil(["-L", "-d", f"sql:{database}", "-n", nickname(instance.name)], check=False)
        trusted = result.returncode == 0
        found += trusted
    print(f"CA: trusted ({found}/{len(databases)} profilů)" if found else "CA: not installed")
    return 0 if databases and found == len(databases) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-ca")
    parser.add_argument("-i", "--instance", default="default")
    parser.add_argument("action", choices=("install", "status", "remove", "system-install"))
    parser.add_argument("--certificate", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    instance = Instance.load(args.instance)
    try:
        if args.action == "system-install":
            if args.certificate is None:
                raise RuntimeError("Chybí cesta k certifikátu.")
            install_system(args.instance, args.certificate)
            return 0
        if args.action == "install":
            install(instance)
            return 0
        if args.action == "remove":
            remove(instance)
            return 0
        return status(instance)
    except RuntimeError as exc:
        print(f"saslik-ca: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
