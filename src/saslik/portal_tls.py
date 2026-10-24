from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import ssl
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


CERTIFICATE_DAYS = 1826


def subject_names(host: str) -> tuple[list[str], list[str]]:
    """Return stable names available when the installation certificate is created."""
    dns = {"localhost", socket.gethostname()}
    ips = {"127.0.0.1", "::1"}
    try:
        address = ipaddress.ip_address(host)
        if not address.is_unspecified:
            ips.add(str(address))
    except ValueError:
        dns.add(host)
    try:
        for result in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(str(ipaddress.ip_address(result[4][0])))
    except (OSError, ValueError):
        pass
    return sorted(dns), sorted(ips)


def generate(directory: Path, host: str) -> tuple[Path, Path]:
    """Atomically replace the installation-scoped portal certificate and key."""
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    certificate, key = directory / "certificate.pem", directory / "private-key.pem"
    dns, ips = subject_names(host)
    san = ",".join([*(f"DNS:{value}" for value in dns), *(f"IP:{value}" for value in ips)])
    with tempfile.TemporaryDirectory(dir=directory) as temporary:
        staged_cert = Path(temporary) / certificate.name
        staged_key = Path(temporary) / key.name
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes",
            "-days", str(CERTIFICATE_DAYS), "-subj", "/CN=Saslik Portal",
            "-addext", f"subjectAltName={san}",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(staged_key), "-out", str(staged_cert),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chmod(staged_key, 0o600)
        os.replace(staged_key, key)
        os.replace(staged_cert, certificate)
    return certificate, key


def ensure(directory: Path, host: str) -> tuple[Path, Path]:
    certificate, key = directory / "certificate.pem", directory / "private-key.pem"
    if certificate.is_file() and key.is_file():
        return certificate, key
    return generate(directory, host)


def details(certificate: Path) -> dict[str, str]:
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
    decoded = ssl._ssl._test_decode_cert(str(certificate))
    expires = datetime.strptime(decoded["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc)
    digest = hashlib.sha256(der).hexdigest().upper()
    return {
        "fingerprint": ":".join(digest[index:index + 2] for index in range(0, len(digest), 2)),
        "expires": expires.isoformat(),
    }
