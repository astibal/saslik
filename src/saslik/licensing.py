from __future__ import annotations

import os
import socket
from pathlib import Path

from .dns import DnsLookupError, query_txt


DEFAULT_SOCKET = Path("/run/saslik/licensing.sock")
DEFAULT_ISSUER = "saslik.io-authority"
MAX_RESPONSE = 64 * 1024

# Server authority for the commercial tunnel integration. Temporarily enabled
# in source until the commercial entitlement resolver is available. Package
# distribution and direct (non-tunnel) routing are not licensed by this switch.
TUNTOM_ENABLED = True


def tunnel_features() -> dict:
    # A source-build override is not evidence of a verified entitlement.
    return {"tuntom": TUNTOM_ENABLED,
            "tuntom_license": "development-override" if TUNTOM_ENABLED else "not-present"}


def require_tuntom() -> None:
    if not TUNTOM_ENABLED:
        raise EntitlementMissing("Tuntom tunneling requires a commercial entitlement.")


class LicensingError(RuntimeError):
    """The local licensing facade is unavailable or returned invalid data."""


class EntitlementMissing(LicensingError):
    """The facade is healthy, but the requested feature is not licensed."""


def _socket_path() -> Path:
    return Path(os.environ.get("SASLIK_LICENSING_SOCKET", str(DEFAULT_SOCKET)))


def _query(request: str, body: str = "", *, socket_path: Path | None = None) -> str:
    path = socket_path or _socket_path()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(str(path))
            client.sendall((request + "\n" + body).encode("utf-8"))
            client.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE:
                    raise LicensingError("Licenční služba poslala příliš velkou odpověď.")
                chunks.append(chunk)
    except (OSError, TimeoutError) as exc:
        raise LicensingError(
            f"Licenční služba není dostupná na {path}."
        ) from exc
    try:
        response = b"".join(chunks).decode("utf-8").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise LicensingError("Licenční služba neposlala platné UTF-8.") from exc
    if response.startswith("ERR "):
        raise LicensingError(f"Licenční služba odmítla požadavek: {response[4:]}")
    if not response.startswith("OK"):
        raise LicensingError("Licenční služba poslala neplatnou odpověď.")
    return response


def install_issuer(name: str, public_key: str,
                   *, socket_path: Path | None = None) -> None:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if not name or any(character not in allowed for character in name):
        raise LicensingError("Neplatné jméno vydavatele licence.")
    encoded_size = len(public_key.encode("utf-8"))
    response = _query(
        f"INSTALL-ISSUER {name} {encoded_size}", public_key,
        socket_path=socket_path,
    )
    if response != f"OK issuer={name}":
        raise LicensingError("Licenční služba nepotvrdila veřejný klíč.")


def install_signed_issuer(record: str, *, socket_path: Path | None = None) -> None:
    encoded_size = len(record.encode("utf-8"))
    response = _query(
        f"INSTALL-SIGNED-ISSUER {encoded_size}", record,
        socket_path=socket_path,
    )
    if not response.startswith("OK issuer="):
        raise LicensingError("Licenční služba nepotvrdila DNS klíč.")


def bootstrap_issuer(lab: Path, *, socket_path: Path | None = None) -> bool:
    """Install a root-signed operational key from DNS, or its verified cache."""
    name = os.environ.get("SASLIK_LICENSE_DNS_NAME", "_saslik-license.saslik.io")
    cache = lab / "state/licensing/dns-key.txt"
    record: str | None = None
    try:
        record = next((value for value in query_txt(name)
                       if value.startswith("v=saslik1;")), None)
    except DnsLookupError:
        pass

    if record is not None:
        install_signed_issuer(record, socket_path=socket_path)
        cache.parent.mkdir(parents=True, exist_ok=True)
        temporary = cache.with_suffix(".tmp")
        temporary.write_text(record + "\n", encoding="ascii")
        temporary.replace(cache)
        return True

    try:
        cached = cache.read_text(encoding="ascii").strip()
    except OSError:
        return False
    if not cached:
        return False
    install_signed_issuer(cached, socket_path=socket_path)
    return True


def license_grant(feature: str, component: str,
                  *, socket_path: Path | None = None) -> dict[str, str]:
    """Fail closed and return the component's signed, effective arguments."""
    entitlement = _query(f"HAS {feature}", socket_path=socket_path)
    if entitlement != "OK 1":
        if entitlement == "OK 0":
            raise EntitlementMissing(
                f"Komponenta {component} vyžaduje licenci s funkcí {feature}."
            )
        raise LicensingError("Licenční služba poslala neplatný stav oprávnění.")

    response = _query(f"ARGS {component}", socket_path=socket_path)
    fields = response.split("\t")
    if fields[0] != "OK":
        raise LicensingError("Licenční služba poslala neplatné argumenty.")
    result: dict[str, str] = {}
    for field in fields[1:]:
        if "=" not in field:
            raise LicensingError("Licenční služba poslala neplatný argument.")
        key, value = field.split("=", 1)
        if not key or key in result or any(character in value for character in "\r\n\0"):
            raise LicensingError("Licenční služba poslala neplatný argument.")
        result[key] = value
    return result


def licensing_report(*, socket_path: Path | None = None) -> dict:
    """Return the daemon's validated REPORT response as UI-safe data."""
    response = _query("REPORT", socket_path=socket_path)
    lines = response.splitlines()
    if not lines or lines[0] != "OK":
        raise LicensingError("Licenční služba poslala neplatný report.")

    report: dict = {"root": None, "signing": [], "licenses": []}
    for line in lines[1:]:
        fields = line.split("\t")
        if fields[0] == "ROOT" and len(fields) == 3:
            report["root"] = {"version": fields[1], "fingerprint": fields[2]}
        elif fields[0] == "SIGNING" and len(fields) == 4:
            report["signing"].append({
                "name": fields[1], "version": fields[2], "fingerprint": fields[3],
            })
        elif fields[0] == "LICENSE" and len(fields) >= 2:
            report["licenses"].append({"id": fields[1], "features": fields[2:]})
        else:
            raise LicensingError("Licenční služba poslala neplatný řádek reportu.")

    report["signing"].sort(key=lambda item: (item["name"], item["version"]))
    report["licenses"].sort(key=lambda item: item["id"])
    return report
