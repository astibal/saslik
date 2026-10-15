from __future__ import annotations

import argparse
import json
import os
import random
import re
import socket
import struct
import subprocess
import time
from pathlib import Path


def _dns_name(name: str) -> bytes:
    return b"".join(bytes((len(part),)) + part.encode("ascii") for part in name.split(".")) + b"\0"


def _skip_name(packet: bytes, offset: int) -> int:
    while offset < len(packet):
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length
    raise ValueError("neúplné DNS jméno")


def parse_a_response(packet: bytes, query_id: int) -> list[str]:
    if len(packet) < 12:
        raise ValueError("krátká DNS odpověď")
    response_id, flags, questions, answers = struct.unpack("!HHHH", packet[:8])
    if response_id != query_id or flags & 0x8000 == 0:
        raise ValueError("DNS odpověď neodpovídá dotazu")
    if flags & 0x000F:
        raise ValueError(f"DNS vrátilo RCODE {flags & 0x000F}")
    offset = 12
    for _ in range(questions):
        offset = _skip_name(packet, offset) + 4
    result: list[str] = []
    for _ in range(answers):
        offset = _skip_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("neúplný DNS answer")
        record_type, record_class, _ttl, length = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        data = packet[offset:offset + length]
        offset += length
        if record_type == 1 and record_class == 1 and len(data) == 4:
            result.append(socket.inet_ntoa(data))
    if not result:
        raise ValueError("DNS odpověď neobsahuje IPv4 adresu")
    return result


def dns_probe(name: str, resolver: str) -> tuple[dict[str, object], list[str]]:
    query_id = random.SystemRandom().randrange(65536)
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", 1, 1)
    started = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(4)
            stream.sendto(packet, (resolver, 53))
            response, peer = stream.recvfrom(4096)
        if peer[0] != resolver:
            raise ValueError("DNS odpovědělo z jiné adresy")
        addresses = parse_a_response(response, query_id)
        return ({"state": "ok", "detail": f"{name} → {addresses[0]}",
                 "latency_ms": round((time.perf_counter() - started) * 1000)}, addresses)
    except (OSError, ValueError) as exc:
        return ({"state": "down", "detail": str(exc)[:100],
                 "latency_ms": round((time.perf_counter() - started) * 1000)}, [])


def curl_probe(url: str, name: str, address: str, *, insecure: bool = False) -> dict[str, object]:
    started = time.perf_counter()
    port = 443 if url.startswith("https:") else 80
    command = ["curl", "-4", "--interface", "eth0", "--silent", "--show-error",
               "--output", "/dev/null", "--max-time", "7", "--resolve",
               f"{name}:{port}:{address}", "--write-out", "%{http_code}"]
    if insecure:
        command.append("--insecure")
    command.append(url)
    result = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=9)
    elapsed = round((time.perf_counter() - started) * 1000)
    code = result.stdout.strip()
    if result.returncode == 0 and code.isdigit() and 200 <= int(code) < 400:
        return {"state": "ok", "detail": f"HTTP {code}", "latency_ms": elapsed}
    detail = result.stderr.strip() or f"curl={result.returncode}, HTTP {code or '—'}"
    return {"state": "down", "detail": detail[:100], "latency_ms": elapsed}


def _certificate_name(path: Path, field: str) -> str:
    result = subprocess.run(
        ["openssl", "x509", "-in", str(path), "-noout", f"-{field}", "-nameopt", "RFC2253"],
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ).stdout.strip()
    return result.split("=", 1)[-1]


def tls_issuer(name: str, address: str, ca_certificate: Path) -> dict[str, object]:
    started = time.perf_counter()
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{address}:443", "-servername", name,
             "-showcerts"], input="", check=False, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=8,
        )
        match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", result.stdout, re.S)
        if not match:
            raise RuntimeError("server neposlal certifikát")
        leaf = subprocess.run(
            ["openssl", "x509", "-noout", "-issuer", "-nameopt", "RFC2253"],
            input=match.group(0), check=True, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout.strip().split("=", 1)[-1]
        expected = _certificate_name(ca_certificate, "subject")
        intercepted = leaf == expected
        return {"state": "ok" if intercepted else "degraded", "detail": leaf,
                "issuer": leaf, "expected_issuer": expected, "intercepted": intercepted,
                "latency_ms": round((time.perf_counter() - started) * 1000)}
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        return {"state": "down", "detail": str(exc)[:100], "intercepted": False,
                "latency_ms": round((time.perf_counter() - started) * 1000)}


def run_once(name: str, resolver: str, ca_certificate: Path) -> dict[str, object]:
    dns, addresses = dns_probe(name, resolver)
    if addresses:
        address = addresses[0]
        http = curl_probe(f"http://{name}/", name, address)
        tls = curl_probe(f"https://{name}/", name, address, insecure=True)
        issuer = tls_issuer(name, address, ca_certificate) if tls["state"] == "ok" else {
            "state": "down", "detail": "TLS spojení neprošlo", "intercepted": False}
    else:
        dependency = {"state": "down", "detail": "čeká na funkční DNS"}
        http = dependency.copy()
        tls = dependency.copy()
        issuer = dependency.copy() | {"intercepted": False}
    return {"sampled_at": time.time(), "target": name, "resolver": resolver,
            "checks": {"dns": dns, "http": http, "tls": tls, "issuer": issuer}}


def write_atomic(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-probe")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ca", required=True, type=Path)
    parser.add_argument("--target", default="example.com")
    parser.add_argument("--resolver", default="1.1.1.1")
    parser.add_argument("--interval", type=float, default=15)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    while True:
        try:
            result = run_once(args.target, args.resolver, args.ca)
        except Exception as exc:  # Keep the monitor alive and make failure visible.
            result = {"sampled_at": time.time(), "target": args.target,
                      "checks": {}, "error": str(exc)[:200]}
        write_atomic(args.output, result)
        if args.once:
            return 0
        time.sleep(max(5, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
