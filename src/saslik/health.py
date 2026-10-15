from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def _state_env(lab: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = (lab / "state/state.env").read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def _http_check(url: str, headers: dict[str, str] | None = None,
                insecure: bool = False) -> dict[str, object]:
    started = time.perf_counter()
    request = urllib.request.Request(url, headers=headers or {})
    context = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(request, timeout=0.45, context=context) as response:
            body = response.read(4096)
            code = response.status
        detail = f"HTTP {code}"
        try:
            payload = json.loads(body)
            if isinstance(payload, dict):
                message = payload.get("status") or payload.get("state")
                if isinstance(message, (str, int, float, bool)):
                    detail += f" · {message}"
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        return {"state": "ok" if 200 <= code < 300 else "degraded",
                "detail": detail, "latency_ms": round((time.perf_counter() - started) * 1000)}
    except urllib.error.HTTPError as exc:
        return {"state": "degraded", "detail": f"HTTP {exc.code}",
                "latency_ms": round((time.perf_counter() - started) * 1000)}
    except (OSError, urllib.error.URLError) as exc:
        reason = getattr(exc, "reason", exc)
        return {"state": "down", "detail": str(reason)[:80],
                "latency_ms": round((time.perf_counter() - started) * 1000)}


def _tcp_check(host: str, port: int) -> dict[str, object]:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=0.35):
            pass
        return {"state": "ok", "detail": "TCP přijímá spojení",
                "latency_ms": round((time.perf_counter() - started) * 1000)}
    except OSError as exc:
        return {"state": "down", "detail": str(exc)[:80],
                "latency_ms": round((time.perf_counter() - started) * 1000)}


def interface_counters(interface: str = "sxp-test0", *, sysfs: Path = Path("/sys/class/net")) -> dict[str, object]:
    statistics = sysfs / interface / "statistics"
    names = ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
             "tx_bytes", "tx_packets", "tx_errors", "tx_dropped")
    try:
        values = {name: int((statistics / name).read_text(encoding="ascii").strip())
                  for name in names}
    except (OSError, ValueError):
        return {"available": False, "interface": interface}
    return {"available": True, "interface": interface, **values}


def end_to_end_status(lab: Path) -> dict[str, object]:
    path = lab / "state/e2e-health.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("výsledek není objekt")
    except (OSError, ValueError, json.JSONDecodeError):
        return {"available": False, "stale": False, "checks": {}}
    sampled_at = value.get("sampled_at")
    stale = not isinstance(sampled_at, (int, float)) or time.time() - sampled_at > 45
    return {"available": True, "stale": stale, **value}


def collect(lab: Path) -> dict[str, object]:
    values = _state_env(lab)
    api_key = values.get("SMITHPROXY_API_KEY", "")
    checks = {
        "smithproxy": lambda: _http_check(
            "https://127.0.0.1:55580/api/status/ping",
            {"X-API-Key": api_key} if api_key else {}, True),
        "http_proxy": lambda: _tcp_check("127.0.0.1", 33128),
        "cli": lambda: _tcp_check("127.0.0.1", 55000),
        "spider": lambda: _http_check("http://127.0.0.1:18080/api/health"),
        "sift": lambda: _http_check("http://127.0.0.1:18081/api/health"),
    }
    with ThreadPoolExecutor(max_workers=len(checks), thread_name_prefix="saslik-health") as pool:
        futures = {name: pool.submit(callback) for name, callback in checks.items()}
        results = {name: future.result() for name, future in futures.items()}
    return {"checks": results, "traffic": interface_counters(),
            "end_to_end": end_to_end_status(lab), "sampled_at": time.time()}
