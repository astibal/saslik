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


STORE_DEFINITIONS = {
    "firefox": {"label": "Firefox", "family": "Firefox", "variant": "Native"},
    "firefox-snap": {"label": "Firefox Snap", "family": "Firefox", "variant": "Snap"},
    "firefox-flatpak": {"label": "Firefox Flatpak", "family": "Firefox", "variant": "Flatpak"},
    "librewolf": {"label": "LibreWolf", "family": "LibreWolf", "variant": "Native"},
    "librewolf-flatpak": {"label": "LibreWolf Flatpak", "family": "LibreWolf", "variant": "Flatpak"},
    "chromium": {"label": "Chromium family / NSS", "family": "Chromium family", "variant": "Shared NSS"},
    "chromium-snap": {"label": "Chromium Snap", "family": "Chromium", "variant": "Snap"},
    "brave-snap": {"label": "Brave Snap", "family": "Brave", "variant": "Snap"},
    "thunderbird": {"label": "Thunderbird", "family": "Thunderbird", "variant": "Native"},
    "thunderbird-snap": {"label": "Thunderbird Snap", "family": "Thunderbird", "variant": "Snap"},
    "system": {"label": "Systémový store", "family": "System", "variant": "Ubuntu"},
}
STORE_LABELS = {key: value["label"] for key, value in STORE_DEFINITIONS.items()}

FAMILY_DESCRIPTIONS = {
    "Firefox": "Přidá CA do všech nalezených profilů Firefoxu. HTTPS provoz přes Smithproxy pak otevřeš bez varování o nedůvěryhodném certifikátu.",
    "LibreWolf": "Přidá CA do izolovaných profilů LibreWolfu. Zachová jeho vlastní trust store a zpřístupní v něm TLS inspekci labu.",
    "Chromium family": "Nastaví sdílený linuxový NSS store pro Chromium, Chrome, Vivaldi a Edge. Jedna instalace tak obslouží více nativních browserů.",
    "Chromium": "Nastaví NSS důvěru pro Chromium a další browsery postavené na Chromiu.",
    "Brave": "Přidá CA do izolovaného Brave Snap store, včetně ponechaných revizí. TLS inspekce přežije aktualizaci Snapu.",
    "Thunderbird": "Přidá CA do profilů Thunderbirdu, aby přes Smithproxy důvěřoval kontrolovaným TLS spojením pošty.",
    "System": "Nainstaluje CA pro celý Ubuntu systém. Pomůže nástrojům jako curl, Git a aplikacím používajícím systémový trust store; vyžádá si administrátorské potvrzení.",
}


def nss_databases() -> list[tuple[str, str, Path]]:
    databases: list[tuple[str, str, Path]] = []
    firefox_roots = (
        ("firefox", "Firefox", Path.home() / ".mozilla/firefox"),
        ("firefox-snap", "Firefox Snap", Path.home() / "snap/firefox/common/.mozilla/firefox"),
        ("firefox-flatpak", "Firefox Flatpak", Path.home() / ".var/app/org.mozilla.firefox/.mozilla/firefox"),
        ("librewolf", "LibreWolf", Path.home() / ".librewolf"),
        ("librewolf-flatpak", "LibreWolf Flatpak", Path.home() / ".var/app/io.gitlab.librewolf-community/.librewolf"),
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
    if not chromium.is_dir():
        xdg_data = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
        chromium = xdg_data / "pki/nssdb"
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
    for key in ("firefox", "firefox-snap", "firefox-flatpak", "librewolf",
                "librewolf-flatpak", "chromium",
                "chromium-snap", "brave-snap", "thunderbird", "thunderbird-snap"):
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
        definition = STORE_DEFINITIONS[key]
        result.append({"key": key, **definition,
                       "description": FAMILY_DESCRIPTIONS[definition["family"]],
                       "available": bool(databases),
                       "installed": bool(databases) and installed == len(databases),
                       "present": installed > 0,
                       "detail": f"{installed}/{len(databases)} profilů" if databases else "nenalezen"})
    target = system_certificate_path(instance.name)
    system_installed = False
    if expected and target.is_file():
        try:
            system_installed = _fingerprint_pem(target.read_bytes()) == expected
        except (ValueError, ssl.SSLError, PermissionError):
            pass
    result.append({"key": "system", **STORE_DEFINITIONS["system"],
                   "description": FAMILY_DESCRIPTIONS["System"],
                   "available": bool(shutil.which("update-ca-certificates")),
                   "installed": system_installed,
                   "present": system_installed,
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


def remove_store(instance: Instance, store: str) -> int:
    databases = [database for key, _label, database in nss_databases() if key == store]
    if not databases:
        raise RuntimeError(f"Store {STORE_LABELS.get(store, store)} nebyl nalezen.")
    removed = 0
    for database in databases:
        result = _certutil(["-D", "-d", f"sql:{database}", "-n", nickname(instance.name)], check=False)
        removed += result.returncode == 0
    return removed


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


def remove_system(instance_name: str) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Odebrání ze systémového store vyžaduje administrátorská práva.")
    system_certificate_path(instance_name).unlink(missing_ok=True)
    subprocess.run(["update-ca-certificates", "--fresh"], check=True)


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
    parser.add_argument("action", choices=("install", "status", "remove", "system-install", "system-remove"))
    parser.add_argument("--certificate", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    instance = Instance.load(args.instance)
    try:
        if args.action == "system-install":
            if args.certificate is None:
                raise RuntimeError("Chybí cesta k certifikátu.")
            install_system(args.instance, args.certificate)
            return 0
        if args.action == "system-remove":
            remove_system(args.instance)
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
