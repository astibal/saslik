from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


CERTIFICATE_DAYS = 1826
IGNORED_INTERFACE_PREFIXES = ("lo", "ws", "sxp-", "saslik", "veth", "skt", "tt_")


def host_interface_addresses() -> set[str]:
    """Return usable host addresses without workspace-internal veth noise."""
    try:
        result = subprocess.run(
            ["ip", "-j", "address", "show", "up"], check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        )
        links = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return set()
    addresses: set[str] = set()
    for link in links if isinstance(links, list) else []:
        name = str(link.get("ifname", ""))
        if (name.startswith(IGNORED_INTERFACE_PREFIXES)
                or str(link.get("operstate", "")).upper() == "DOWN"):
            continue
        for value in link.get("addr_info", []):
            # Temporary IPv6 privacy addresses would rotate the pinned portal
            # certificate far too often.  An explicitly bound IPv6 address is
            # still included by subject_names(); automatic discovery is IPv4.
            if value.get("family") != "inet" or value.get("scope") != "global":
                continue
            try:
                address = ipaddress.ip_address(str(value["local"]))
            except (KeyError, ValueError):
                continue
            if not (address.is_unspecified or address.is_multicast or address.is_link_local):
                addresses.add(str(address))
    return addresses


def subject_names(host: str, extra_ips=()) -> tuple[list[str], list[str]]:
    """Return stable names available when the installation certificate is created."""
    hostname = socket.gethostname()
    dns = {"localhost", hostname, socket.getfqdn()}
    ips = {"127.0.0.1", "::1", *host_interface_addresses()}
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
    for value in extra_ips:
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError as exc:
            raise ValueError(f"Neplatná dodatečná portal IP: {value}") from exc
        if not address.is_unspecified:
            ips.add(str(address))
    return sorted(value for value in dns if value), sorted(ips)


def generate(directory: Path, host: str, extra_ips=()) -> tuple[Path, Path]:
    """Atomically replace the installation-scoped portal certificate and key."""
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    certificate, key = directory / "certificate.pem", directory / "private-key.pem"
    dns, ips = subject_names(host, extra_ips)
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


def _covers(certificate: Path, dns: list[str], ips: list[str]) -> bool:
    try:
        decoded = ssl._ssl._test_decode_cert(str(certificate))
        names = decoded.get("subjectAltName", ())
        present_dns = {value.lower() for kind, value in names if kind == "DNS"}
        present_ips = {str(ipaddress.ip_address(value)) for kind, value in names
                       if kind == "IP Address"}
    except (OSError, ValueError, ssl.SSLError):
        return False
    return ({value.lower() for value in dns} <= present_dns
            and {str(ipaddress.ip_address(value)) for value in ips} <= present_ips)


def ensure(directory: Path, host: str, extra_ips=()) -> tuple[Path, Path]:
    certificate, key = directory / "certificate.pem", directory / "private-key.pem"
    dns, ips = subject_names(host, extra_ips)
    if certificate.is_file() and key.is_file() and _covers(certificate, dns, ips):
        return certificate, key
    return generate(directory, host, extra_ips)


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
