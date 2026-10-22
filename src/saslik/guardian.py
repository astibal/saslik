from __future__ import annotations

import argparse
import json
import os
import select
import socket
import time
from pathlib import Path

from .components import SystemdComponents
from .netns_dns import down as dns_down
from .network import down as network_down
from .pasta import pasta_down
from .routing import routing_down
from .crash import diagnose_smithproxy
from .debug import start_gdbserver, stop_gdbserver


UPDATABLE_COMPONENTS = {"smithproxy", "spider", "sift", "lored", "pcap-viewer"}


def cleanup(lab: Path, instance: str, expose_address: str, *, devel: bool = False) -> None:
    SystemdComponents(lab, instance, expose_address, devel=devel).down()
    routing_down()
    pasta_down(lab, instance)
    network_down(lab)
    dns_down(lab)


def parent_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def serve(socket_path: Path, owner_uid: int, parent_pid: int, data_root: Path,
          lab: Path, instance: str, expose_address: str, *, devel: bool = False) -> None:
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    os.chown(socket_path, owner_uid, -1)
    os.chmod(socket_path, 0o600)
    listener.listen(4)
    listener.setblocking(False)
    root = data_root.resolve()
    last_target: tuple[Path, str, str] | None = (lab.resolve(), instance, expose_address)
    try:
        while parent_alive(parent_pid):
            readable, _, _ = select.select([listener], [], [], 0.5)
            if not readable:
                continue
            connection, _ = listener.accept()
            with connection:
                try:
                    payload = json.loads(connection.recv(65536).decode("utf-8"))
                    lab = Path(str(payload["lab"])).resolve()
                    if not lab.is_relative_to(root):
                        raise RuntimeError("Workspace je mimo Saslik data root.")
                    target = (lab, str(payload["instance"]), str(payload["expose_address"]))
                    last_target = target
                    if payload.get("action") == "stop":
                        cleanup(*target, devel=devel)
                    elif payload.get("action") == "diagnose-smithproxy":
                        diagnose_smithproxy(lab, str(payload["instance"]),
                                            int(payload.get("signal", 11)))
                    elif payload.get("action") == "gdb-start":
                        start_gdbserver(*target, str(payload.get("component", "")))
                    elif payload.get("action") == "gdb-stop":
                        stop_gdbserver(str(payload["instance"]),
                                       str(payload.get("component", "")))
                    elif payload.get("action") in {"component-stop", "component-restart"}:
                        component = str(payload.get("component", ""))
                        if component not in UPDATABLE_COMPONENTS:
                            raise RuntimeError("Komponenta není povolená.")
                        manager = SystemdComponents(*target, devel=devel)
                        if payload["action"] == "component-stop":
                            manager.stop_component(component)
                        else:
                            manager.restart_component(component)
                    else:
                        raise RuntimeError("Neznámá guardian operace.")
                    connection.sendall(b'{"ok":true}\n')
                except Exception as exc:
                    connection.sendall(json.dumps({"ok": False, "error": str(exc)}).encode() + b"\n")
    finally:
        if last_target is not None:
            try:
                cleanup(*last_target, devel=devel)
            except Exception:
                pass
        listener.close()
        socket_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-guardian")
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--owner-uid", type=int, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--lab", type=Path, required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--expose-address", required=True)
    parser.add_argument("--devel", action="store_true")
    args = parser.parse_args(argv)
    serve(args.socket, args.owner_uid, args.parent_pid, args.data_root,
          args.lab, args.instance, args.expose_address, devel=args.devel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
