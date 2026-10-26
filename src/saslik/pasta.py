from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from .runtime import WorkspaceRuntime


IP_FORWARD = Path("/proc/sys/net/ipv4/ip_forward")


def _unit_instance(instance: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in instance)


def unit_name(runtime_prefix: str) -> str:
    return f"{runtime_prefix}-pasta.service"


def cleanup_needed(lab: Path, instance: str | None = None,
                   *, inspect_unit: bool = True) -> bool:
    """Return whether this workspace has pasta state that needs cleanup."""
    state = lab / "state"
    markers = (state / "pasta.pid", state / "pasta.ip_forward.before")
    try:
        pasta_egress = (state / "egress").read_text(encoding="ascii").strip() == "pasta"
    except OSError:
        pasta_egress = False
    if pasta_egress or any(path.exists() for path in markers):
        return True
    if not inspect_unit:
        return False
    runtime = WorkspaceRuntime.for_workspace(lab, instance or lab.name)
    name = unit_name(runtime.prefix)
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", name], check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _run(command: list[str], *, tolerate: bool = False) -> None:
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.DEVNULL if tolerate else None,
        stderr=subprocess.DEVNULL if tolerate else None,
    )
    if result.returncode and not tolerate:
        raise RuntimeError(f"Příkaz selhal ({result.returncode}): {' '.join(command)}")


def snapshot_host(lab: Path) -> None:
    """Remember host state before the reused runner changes it."""
    state = lab / "state"
    state.mkdir(parents=True, exist_ok=True)
    snapshot = state / "pasta.ip_forward.before"
    if not snapshot.exists():
        snapshot.write_text(IP_FORWARD.read_text(encoding="ascii"), encoding="ascii")


def _restore_host(lab: Path) -> None:
    snapshot = lab / "state/pasta.ip_forward.before"
    if snapshot.is_file():
        IP_FORWARD.write_text(snapshot.read_text(encoding="ascii").strip() + "\n", encoding="ascii")
        snapshot.unlink()


def _mount_namespace_reference(runtime: WorkspaceRuntime) -> Path:
    """Expose ip-netns through a path allowed by pasta's AppArmor profile."""
    source = Path("/run/netns") / runtime.namespace
    if not source.exists():
        raise RuntimeError(f"Network namespace {runtime.namespace} neexistuje.")
    target = Path("/run/user/0/saslik") / runtime.namespace
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch(exist_ok=True)
    _run(["umount", str(target)], tolerate=True)
    _run(["mount", "--bind", str(source), str(target)])
    return target


def _unmount_namespace_reference(runtime: WorkspaceRuntime) -> None:
    target = Path("/run/user/0/saslik") / runtime.namespace
    # Failed retries may have stacked more than one bind mount on the same
    # path. Peel every layer instead of assuming a single umount is enough.
    for _ in range(16):
        result = subprocess.run(
            ["umount", str(target)], check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode:
            break
    subprocess.run(
        ["umount", "-l", str(target)], check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        target.unlink(missing_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Nelze uklidit starou pasta namespace reference: {exc}") from exc


def pasta_up(lab: Path, instance: str) -> None:
    runtime = WorkspaceRuntime.for_workspace(lab, instance)
    binary = shutil.which("pasta")
    if not binary:
        raise RuntimeError("Pasta není nainstalovaná. Na Ubuntu/Debian použij: sudo apt install passt")
    state = lab / "state"
    state.mkdir(parents=True, exist_ok=True)
    pasta_down(lab, instance)
    namespace = _mount_namespace_reference(runtime)
    command = [
        binary, "--foreground", "--runas", "0", "--netns", str(namespace),
        "--netns-only", "--config-net",
        "--ns-ifname", "saslik-out", "--dns-forward", "169.254.1.1",
        "--tcp-ports", "none", "--udp-ports", "none",
        "--tcp-ns", "none", "--udp-ns", "none",
    ]
    try:
        _run([
            "systemd-run", "--no-ask-password", "--quiet", "--collect", "--service-type=exec",
            f"--unit={unit_name(runtime.prefix)}", f"--slice={runtime.slice_name}",
            "--property=KillMode=control-group", "--property=Restart=on-failure",
            "--property=RestartSec=500ms",
            f"--property=StandardOutput=append:{state / 'pasta.log'}",
            f"--property=StandardError=append:{state / 'pasta.log'}",
            *command,
        ])
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            result = subprocess.run(
                ["ip", "-n", runtime.namespace, "link", "show", "saslik-out"],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Pasta nevytvořila namespace interface saslik-out.")
    except Exception:
        _run(["systemctl", "--no-ask-password", "stop", unit_name(runtime.prefix)], tolerate=True)
        _unmount_namespace_reference(runtime)
        raise

    # Pasta owns the namespace default route. Keep the ingress veth for host
    # access, but remove the temporary NAT/forwarding installed by the reused
    # Spider runner. Every deletion is the exact inverse of its known rule.
    _run(["ip", "-n", runtime.namespace, "route", "del", "default", "via",
          runtime.host_address], tolerate=True)
    _run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s",
          f"{runtime.namespace_address}/32", "-j", "MASQUERADE"], tolerate=True)
    for port in ("55580", "33128", "55000"):
        _run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", port,
              "-j", "DNAT", "--to-destination", f"{runtime.namespace_address}:{port}"], tolerate=True)
    _run(["iptables", "-D", "FORWARD", "-i", runtime.host_interface, "-j", "ACCEPT"], tolerate=True)
    _run(["iptables", "-D", "FORWARD", "-o", runtime.host_interface, "-m", "conntrack", "--ctstate",
          "RELATED,ESTABLISHED", "-j", "ACCEPT"], tolerate=True)
    # Native Saslik networking owns a dedicated nftables table instead of
    # adding global iptables rules. Pasta is the egress owner in this mode.
    _run(["nft", "delete", "table", "ip", runtime.network_nft_table], tolerate=True)
    _restore_host(lab)
    (state / "egress").write_text("pasta\n", encoding="ascii")


def pasta_down(lab: Path, instance: str | None = None) -> None:
    instance = instance or lab.name
    runtime = WorkspaceRuntime.for_workspace(lab, instance)
    # NAT workspaces must not issue a mutating systemd operation for a pasta
    # unit they never owned. Besides being needless, a non-root caller may
    # otherwise provoke a desktop polkit authorization dialog.
    if not cleanup_needed(lab, instance):
        return
    # Never let an accidentally unprivileged cleanup fall back to a desktop
    # polkit prompt. Normal lifecycle calls arrive through sudo or the root
    # guardian; an unprivileged caller should fail quietly, not steal focus.
    _run(["systemctl", "--no-ask-password", "stop", unit_name(runtime.prefix)], tolerate=True)
    _run(["systemctl", "--no-ask-password", "reset-failed", unit_name(runtime.prefix)], tolerate=True)
    # One-way cleanup of pasta processes created before systemd ownership.
    pid_file = lab / "state/pasta.pid"
    if pid_file.is_file():
        try:
            pid = int(pid_file.read_text(encoding="ascii").strip())
            comm = Path(f"/proc/{pid}/comm")
            if comm.is_file() and comm.read_text(encoding="ascii").strip() in {"pasta", "pasta.avx2"}:
                os.kill(pid, signal.SIGTERM)
        except (ValueError, ProcessLookupError, PermissionError):
            pass
        pid_file.unlink(missing_ok=True)
    _unmount_namespace_reference(runtime)
    (lab / "state/egress").unlink(missing_ok=True)
    _restore_host(lab)


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="saslik-pasta")
    parser.add_argument("action", choices=("snapshot", "up", "down"))
    parser.add_argument("lab", type=Path)
    parser.add_argument("--instance", default="")
    args = parser.parse_args(argv)
    if args.action == "snapshot":
        snapshot_host(args.lab)
    elif args.action == "up":
        pasta_up(args.lab, args.instance or args.lab.name)
    else:
        pasta_down(args.lab, args.instance or args.lab.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
    target = Path("/run/user/0/saslik") / runtime.namespace
