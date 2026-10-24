from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class Query:
    label: str
    url: str


QUERIES = {
    "lored-stats": Query("Lored stats", "http://127.0.0.1:8091/v1/stats"),
    "lored-health": Query("Lored readiness", "http://127.0.0.1:8091/readyz"),
    "sift-stats": Query("Sift stats", "http://127.0.0.1:18081/api/stats"),
    "sift-diagnostics": Query("Sift diagnostics", "http://127.0.0.1:18081/api/diagnostics"),
    "sift-config": Query("Sift config", "http://127.0.0.1:18081/api/config"),
}


def run_query(name: str, *, timeout: float = 2.0) -> dict[str, object]:
    """Run one fixed, loopback-only development query."""
    try:
        query = QUERIES[name]
    except KeyError as exc:
        raise ValueError("Neznámý Dev API dotaz.") from exc

    started = time.perf_counter()
    request = urllib.request.Request(query.url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            status = response.status
            content_type = response.headers.get_content_type()
    except urllib.error.HTTPError as exc:
        body = exc.read(2 * 1024 * 1024 + 1)
        status = exc.code
        content_type = exc.headers.get_content_type()
    except (OSError, urllib.error.URLError) as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(f"{query.label}: {reason}") from exc

    if len(body) > 2 * 1024 * 1024:
        raise RuntimeError(f"{query.label}: odpověď je větší než 2 MiB")
    text = body.decode("utf-8", errors="replace")
    try:
        result: object = json.loads(text)
        kind = "json"
    except json.JSONDecodeError:
        result = text
        kind = "text"
    return {
        "name": name, "label": query.label, "url": query.url,
        "status": status, "ok": 200 <= status < 300,
        "content_type": content_type, "kind": kind,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "result": result,
    }
