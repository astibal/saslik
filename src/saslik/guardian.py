from __future__ import annotations

import argparse
import json
import os
import select
import socket
import logging
import time
from pathlib import Path

from .components import SystemdComponents
from .netns_dns import down as dns_down
from .network import down as network_down
from .pasta import pasta_down
from .routing import routing_down
from .crash import diagnose_smithproxy
from .debug import start_gdbserver, stop_gdbserver
from .tuntom_supervisor import TunnelSupervisor
from .maintenance import maintain_component_logs, repair_log_ownership
from .runtime import WorkspaceRuntime
from .takeaway_jobs import cancel_unit as cancel_takeaway_unit
from .takeaway_jobs import start_unit as start_takeaway_unit
from .instance import clone_instance, delete_instance, restore_instance_ownership


UPDATABLE_COMPONENTS = {"smithproxy", "spider", "sift", "lored", "pcap-viewer", "tuntom",
                        "smithproxy-gui"}


def send_response(connection: socket.socket, response: dict) -> bool:
    """Send a best-effort reply without making client lifetime guardian lifetime."""
    try:
        connection.sendall(
            json.dumps(response, separators=(",", ":")).encode() + b"\n"
        )
        return True
    except OSError:
        return False


def cleanup(lab: Path, instance: str, expose_address: str, *, devel: bool = False) -> None:
    runtime = WorkspaceRuntime.for_workspace(lab, instance)
    SystemdComponents(lab, instance, expose_address, devel=devel).down()
    routing_down(runtime)
    pasta_down(lab, instance)
    network_down(lab, runtime)
    dns_down(lab, runtime)


def parent_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def serve(socket_path: Path, owner_uid: int, parent_pid: int, data_root: Path,
          config_root: Path,
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
    targets: set[tuple[Path, str, str]] = {(lab.resolve(), instance, expose_address)}
    tunnels = TunnelSupervisor()
    next_expiration = 0.0
    try:
        while parent_alive(parent_pid):
            if time.monotonic() >= next_expiration:
                # Retry failed teardown without starving other clients or
                # hammering systemd on every iteration.
                if tunnels.expire():
                    logging.warning("Tunnel cleanup incomplete; retrying in five seconds")
                next_expiration = time.monotonic() + 5
            readable, _, _ = select.select([listener], [], [], 0.5)
            if not readable:
                continue
            connection, _ = listener.accept()
            with connection:
                try:
                    connection.settimeout(5)
                    raw = bytearray()
                    while len(raw) < 65536:
                        chunk = connection.recv(min(4096, 65536 - len(raw)))
                        if not chunk:
                            break
                        raw.extend(chunk)
                    if len(raw) >= 65536:
                        raise ValueError("Guardian request too large")
                    payload = json.loads(raw)
                    lab = Path(str(payload["lab"])).resolve()
                    if not lab.is_relative_to(root):
                        raise RuntimeError("Workspace je mimo Saslik data root.")
                    target = (lab, str(payload["instance"]), str(payload["expose_address"]))
                    targets.add(target)
                    response = {"ok": True}
                    if payload.get("action") == "stop":
                        tunnels.close(target)
                        cleanup(*target, devel=devel)
                    elif payload.get("action") in {"tunnel-open", "tunnel-heartbeat", "tunnel-close", "tunnel-revoke"}:
                        response = tunnels.request(target, payload)
                    elif payload.get("action") == "diagnose-smithproxy":
                        diagnose_smithproxy(lab, str(payload["instance"]),
                                            int(payload.get("signal", 11)))
                    elif payload.get("action") == "gdb-start":
                        start_gdbserver(*target, str(payload.get("component", "")))
                    elif payload.get("action") == "gdb-stop":
                        stop_gdbserver(lab, str(payload["instance"]),
                                       str(payload.get("component", "")))
                    elif payload.get("action") in {"component-stop", "component-restart"}:
                        component = str(payload.get("component", ""))
                        if component not in UPDATABLE_COMPONENTS:
                            raise RuntimeError("Komponenta není povolená.")
                        manager = SystemdComponents(*target, devel=devel)
                        if component == "tuntom":
                            # Forget old leases as well as stopping their units;
                            # clients must establish fresh authenticated tunnels.
                            tunnels.close(target)
                        if payload["action"] == "component-stop":
                            manager.stop_component(component)
                        else:
                            manager.restart_component(component)
                    elif payload.get("action") == "probe-config":
                        SystemdComponents(*target, devel=devel).apply_probe_settings()
                    elif payload.get("action") == "probe-run":
                        SystemdComponents(*target, devel=devel).run_probe_once()
                    elif payload.get("action") == "maintenance":
                        repair_log_ownership(root, owner_uid)
                        maintain_component_logs(root)
                        repair_log_ownership(root, owner_uid)
                    elif payload.get("action") == "takeaway-start":
                        start_takeaway_unit(root, str(payload.get("job", "")), owner_uid)
                    elif payload.get("action") == "takeaway-cancel":
                        cancel_takeaway_unit(root, str(payload.get("job", "")))
                    elif payload.get("action") == "clone-workspace":
                        # Instance discovery normally follows the invoking user's
                        # XDG paths. A system guardian has its own HOME, so pin
                        # both roots explicitly for this privileged operation.
                        os.environ["SASLIK_DATA_DIR"] = str(root)
                        os.environ["SASLIK_CONFIG_DIR"] = str(config_root)
                        new_name = str(payload.get("new_name", ""))
                        dirty_sources = payload.get("dirty_sources")
                        if not isinstance(dirty_sources, list) or not all(
                                isinstance(item, str) for item in dirty_sources):
                            raise ValueError("Neplatný seznam lokálně změněných zdrojů.")
                        clone_instance(str(payload["instance"]), new_name,
                                       dirty_sources=dirty_sources)
                        restore_instance_ownership(new_name, owner_uid)
                    elif payload.get("action") == "delete-workspace":
                        os.environ["SASLIK_DATA_DIR"] = str(root)
                        os.environ["SASLIK_CONFIG_DIR"] = str(config_root)
                        delete_instance(str(payload["instance"]))
                    else:
                        raise RuntimeError("Neznámá guardian operace.")
                    send_response(connection, response)
                except Exception as exc:
                    # Exception messages may contain command arguments. Log only
                    # the type; endpoint phase diagnostics locate the failing step.
                    logging.error("Guardian request failed (%s)", type(exc).__name__)
                    send_response(connection, {"ok": False, "error": str(exc)})
    finally:
        try:
            tunnels.close()
        except Exception:
            logging.error("Tunnel cleanup incomplete during guardian shutdown")
            # Component-slice cleanup below remains the final fallback.
        for target in targets:
            try:
                cleanup(*target, devel=devel)
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
    parser.add_argument("--config-root", type=Path, required=True)
    parser.add_argument("--lab", type=Path, required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--expose-address", required=True)
    parser.add_argument("--devel", action="store_true")
    args = parser.parse_args(argv)
    serve(args.socket, args.owner_uid, args.parent_pid, args.data_root, args.config_root,
          args.lab, args.instance, args.expose_address, devel=args.devel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
