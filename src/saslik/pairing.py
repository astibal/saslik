"""Certificate-free Skewer control transport. Never forwards to the public HTTP API."""
from __future__ import annotations

import base64
import fcntl
import json
import os
import secrets
import socketserver
import ssl
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode


def encode(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode().rstrip("=")


class PairingStore:
    """One boot-local invitation; durable per-client keys with two-phase enrollment."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.clients = json.loads(path.read_text()) if path.exists() else {}
        self.invitation = "invite-" + secrets.token_hex(16)
        self.secret = secrets.token_bytes(32)
        self.reservation = None

    def _save(self, clients):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".pairing-")
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(clients, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        self.clients = clients

    def rotate(self, cancel_pending=True):
        with self.lock:
            if cancel_pending:
                self._save({key: value for key, value in self.clients.items() if value["state"] != "pending"})
            self.invitation = "invite-" + secrets.token_hex(16)
            self.secret = secrets.token_bytes(32)
            self.reservation = None

    def link(self, host: str, port: int) -> str:
        with self.lock:
            authority = f"[{host}]" if ":" in host else host
            return f"skewer://{authority}:{port}/pair#" + urlencode(
                {"v": "1", "id": self.invitation, "psk": encode(self.secret)})

    def key(self, identity: str | None) -> bytes:
        with self.lock:
            if identity == self.invitation:
                return self.secret
            value = self.clients.get(identity)
            return bytes.fromhex(value["key"]) if value else b""

    def request(self, identity: str, request: dict, status, report=None, tunnel=None):
        with self.lock:
            action = request.get("action")
            if identity == self.invitation and action == "enroll":
                instance = str(uuid.UUID(request["instance"]))
                nonce = str(uuid.UUID(request["request"]))
                if self.reservation:
                    previous, previous_nonce = self.reservation
                    value = self.clients[previous]
                    if value["instance"] != instance or previous_nonce != nonce:
                        raise ValueError("Invitation already reserved; regenerate it to cancel")
                    return {"identity": previous, "psk": encode(bytes.fromhex(value["key"]))}
                if any(value["instance"] == instance for value in self.clients.values()):
                    raise ValueError("Instance already registered; revoke its old pairing first")
                client = "client-" + secrets.token_hex(16)
                key = secrets.token_bytes(32)
                value = {"instance": instance, "key": key.hex(), "state": "pending", "permissions": ["status", "tunnel"]}
                self._save({**self.clients, client: value})
                self.reservation = (client, nonce)
                return {"identity": client, "psk": encode(key)}
            value = self.clients.get(identity)
            if not value:
                raise ValueError("Not authorized")
            if action == "commit":
                if value["state"] == "pending":
                    self._save({**self.clients, identity: {**value, "state": "active"}})
                    if self.reservation and self.reservation[0] == identity:
                        self.rotate(cancel_pending=False)
                return {"paired": True}
            if value["state"] == "active" and action == "status" and "status" in value["permissions"]:
                return status()
            if value["state"] == "active" and action == "report" and "status" in value["permissions"] and report:
                return report(identity, request.get("report"))
            if (value["state"] == "active" and "tunnel" in value["permissions"] and tunnel
                    and action in {"tunnel-open", "tunnel-heartbeat", "tunnel-close"}):
                return tunnel(identity, request, bytes.fromhex(value["key"]))
            raise ValueError("Operation not permitted")

    def revoke(self, identity):
        with self.lock:
            if identity not in self.clients:
                raise ValueError("Unknown client")
            self._save({key: value for key, value in self.clients.items() if key != identity})
            if self.reservation and self.reservation[0] == identity:
                self.rotate()


class PskServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = False

    def __init__(self, address, store: PairingStore, status, report=None, tunnel=None):
        if not hasattr(ssl.SSLContext, "set_psk_server_callback"):
            raise RuntimeError("Skewer PSK requires Python 3.13+ with OpenSSL PSK support")
        self.store, self.status = store, status
        self.report = report
        self.tunnel = tunnel
        self.slots = threading.BoundedSemaphore(16)
        store.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store_lock = os.open(str(store.path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.store_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if store.path.exists():
                store.clients = json.loads(store.path.read_text())
            super().__init__(address, PskHandler)
        except BaseException:
            if self.store_lock is not None:
                os.close(self.store_lock)
            self.store_lock = None
            raise

    def server_close(self):
        super().server_close()
        if self.store_lock is not None:
            os.close(self.store_lock)
            self.store_lock = None

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class PskHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        # Per-connection callback state prevents identity mixups between worker threads.
        identity = None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.options &= ~getattr(ssl, "OP_ALLOW_NO_DHE_KEX", 0)

        def lookup(candidate):
            nonlocal identity
            identity = candidate
            return self.server.store.key(candidate)

        context.set_psk_server_callback(lookup)
        try:
            with context.wrap_socket(self.request, server_side=True) as connection:
                deadline = time.monotonic() + 5
                raw = b""
                while not raw.endswith(b"\n") and len(raw) <= 262144:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return
                    connection.settimeout(remaining)
                    chunk = connection.recv(min(4096, 262145 - len(raw)))
                    if not chunk:
                        return
                    raw += chunk
                if len(raw) > 262144 or not raw.endswith(b"\n"):
                    return
                try:
                    request = json.loads(raw)
                    if not isinstance(request, dict):
                        raise ValueError("Expected an object")
                    response = self.server.store.request(identity, request, self.server.status, self.server.report, self.server.tunnel)
                except (ValueError, KeyError, TypeError):
                    response = {"error": "Request rejected"}
                connection.sendall(json.dumps(response).encode() + b"\n")
        except (OSError, ssl.SSLError):
            pass  # Never log request payloads or PSK identities on handshake failures.
