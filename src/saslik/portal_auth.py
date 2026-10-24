"""Small local credential store for the TLS-protected Saslik portal."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import tempfile
import time
from pathlib import Path


PORTAL_USER = "saslik"
SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1


def _password_record(password: str) -> dict[str, str | int]:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N,
                            r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return {"algorithm": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "salt": base64.b64encode(salt).decode("ascii"),
            "digest": base64.b64encode(digest).decode("ascii")}


def _read(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Credential store is not an object.")
    return value


def _write(path: Path, password: dict | None, *, password_changed_at: float | None = None,
           last_login_at: float | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".portal-credentials-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"username": PORTAL_USER, "password": password,
                       "password_changed_at": password_changed_at,
                       "last_login_at": last_login_at}, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _valid_record(value: object) -> bool:
    return isinstance(value, dict) and value.get("algorithm") == "scrypt" \
        and all(key in value for key in ("n", "r", "p", "salt", "digest"))


def ensure_portal_credentials(root: Path) -> tuple[str, bool, Path]:
    """Return portal state; false means first-access setup is still open."""
    path = root / "portal-credentials.json"
    try:
        value = _read(path)
        if value.get("username") != PORTAL_USER:
            raise ValueError("Unexpected portal user.")
        password = value.get("password")
        if _valid_record(password):
            path.chmod(0o600)
            return PORTAL_USER, True, path
        if password is None or password == "":
            path.chmod(0o600)
            return PORTAL_USER, False, path
        # Migrate the short-lived plaintext format without changing the password.
        if isinstance(password, str) and len(password) >= 12:
            _write(path, _password_record(password),
                   password_changed_at=value.get("password_changed_at") or time.time(),
                   last_login_at=value.get("last_login_at"))
            return PORTAL_USER, True, path
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        pass

    _write(path, None)
    return PORTAL_USER, False, path


def verify_portal_password(path: Path, password: str) -> bool:
    try:
        record = _read(path).get("password")
        if not _valid_record(record):
            return False
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["digest"], validate=True)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                                n=int(record["n"]), r=int(record["r"]),
                                p=int(record["p"]), dklen=len(expected))
        return secrets.compare_digest(actual, expected)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def set_portal_password(path: Path, password: str) -> None:
    if not 12 <= len(password) <= 128:
        raise ValueError("Password must contain between 12 and 128 characters.")
    try:
        last_login_at = _read(path).get("last_login_at")
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        last_login_at = None
    _write(path, _password_record(password), password_changed_at=time.time(),
           last_login_at=last_login_at)


def record_portal_login(path: Path) -> float:
    """Persist a successful administrator login without changing its verifier."""
    value = _read(path)
    login_at = time.time()
    _write(path, value.get("password"),
           password_changed_at=value.get("password_changed_at"), last_login_at=login_at)
    return login_at


def portal_account_info(path: Path) -> dict[str, float | None]:
    try:
        value = _read(path)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {"last_login_at": None, "password_changed_at": None}
    return {key: value.get(key) if isinstance(value.get(key), (int, float)) else None
            for key in ("last_login_at", "password_changed_at")}
