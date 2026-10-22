from __future__ import annotations

import os
import socket
from pathlib import Path


DEFAULT_SOCKET = Path("/run/saslik/licensing.sock")
MAX_RESPONSE = 64 * 1024


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
