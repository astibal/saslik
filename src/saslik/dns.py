from __future__ import annotations

import secrets
import socket
import struct
from pathlib import Path


class DnsLookupError(RuntimeError):
    pass


def _nameservers(path: Path = Path("/etc/resolv.conf")) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise DnsLookupError("DNS resolver configuration is unavailable") from exc
    result = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            result.append(fields[1].removesuffix("%0"))
    if not result:
        raise DnsLookupError("no DNS resolver is configured")
    return result


def _question(name: str, query_id: int) -> bytes:
    labels = name.rstrip(".").split(".")
    if not labels or any(not label or len(label.encode("ascii")) > 63
                         for label in labels):
        raise DnsLookupError("invalid DNS name")
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii")
                       for label in labels) + b"\0"
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", 16, 1)


def _skip_name(packet: bytes, offset: int) -> int:
    for _ in range(128):
        if offset >= len(packet):
            raise DnsLookupError("truncated DNS name")
        size = packet[offset]
        if size == 0:
            return offset + 1
        if size & 0xC0 == 0xC0:
            if offset + 2 > len(packet):
                raise DnsLookupError("truncated DNS pointer")
            return offset + 2
        if size & 0xC0 or offset + 1 + size > len(packet):
            raise DnsLookupError("invalid DNS name")
        offset += 1 + size
    raise DnsLookupError("DNS name is too deep")


def parse_txt_response(packet: bytes, query_id: int) -> list[str]:
    if len(packet) < 12:
        raise DnsLookupError("truncated DNS response")
    response_id, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if response_id != query_id or flags & 0x8000 == 0:
        raise DnsLookupError("mismatched DNS response")
    if flags & 0x000F:
        return []
    offset = 12
    for _ in range(questions):
        offset = _skip_name(packet, offset)
        offset += 4
        if offset > len(packet):
            raise DnsLookupError("truncated DNS question")
    records = []
    for _ in range(answers):
        offset = _skip_name(packet, offset)
        if offset + 10 > len(packet):
            raise DnsLookupError("truncated DNS answer")
        record_type, record_class, _, size = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        end = offset + size
        if end > len(packet):
            raise DnsLookupError("truncated DNS record")
        if record_type == 16 and record_class == 1:
            chunks = []
            cursor = offset
            while cursor < end:
                length = packet[cursor]
                cursor += 1
                if cursor + length > end:
                    raise DnsLookupError("invalid DNS TXT record")
                chunks.append(packet[cursor:cursor + length])
                cursor += length
            try:
                records.append(b"".join(chunks).decode("ascii"))
            except UnicodeDecodeError as exc:
                raise DnsLookupError("DNS TXT record is not ASCII") from exc
        offset = end
    return records


def query_txt(name: str, *, timeout: float = 1.5,
              resolv_conf: Path = Path("/etc/resolv.conf")) -> list[str]:
    query_id = secrets.randbits(16)
    request = _question(name, query_id)
    last_error: OSError | None = None
    for server in _nameservers(resolv_conf):
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as client:
                client.settimeout(timeout)
                client.sendto(request, (server, 53))
                packet, _ = client.recvfrom(4096)
            return parse_txt_response(packet, query_id)
        except OSError as exc:
            last_error = exc
    raise DnsLookupError("DNS query failed") from last_error
