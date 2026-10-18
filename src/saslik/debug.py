from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .components import SystemdComponents, _unit_instance, unit_name


DEBUG_COMPONENTS = {
    "smithproxy": ("build/smithproxy/smithproxy", 23450),
    "spider": ("build/spider/smithproxy-spider", 23451),
    "sift": ("build/sift/siftd", 23452),
    "pcap-viewer": ("runtime/pcap-viewer-venv/bin/capture-viewer", 23453),
    "pcap-storage": ("runtime/pcap-viewer-venv/bin/capture-storage", 23454),
}


def debug_unit(instance: str, component: str) -> str:
    if component not in DEBUG_COMPONENTS:
        raise ValueError("Tuto komponentu nelze ladit přes gdbserver.")
    return f"saslik-{_unit_instance(instance)}-gdb-{component}.service"


def component_binary(lab: Path, component: str) -> Path:
    try:
        relative, _ = DEBUG_COMPONENTS[component]
    except KeyError as exc:
        raise ValueError("Tuto komponentu nelze ladit přes gdbserver.") from exc
    binary = (lab.resolve() / relative).resolve()
    if not binary.is_relative_to(lab.resolve()) or not binary.is_file():
        raise RuntimeError(f"Debug binary komponenty {component} neexistuje.")
    return binary


def start_gdbserver(lab: Path, instance: str, expose_address: str,
                    component: str) -> None:
    gdbserver = shutil.which("gdbserver")
    if not gdbserver:
        raise RuntimeError("Chybí gdbserver. Nainstaluj balíček gdbserver.")
    status = SystemdComponents(lab, instance, expose_address).status().get(component, {})
    pid = int(status.get("pid") or 0)
    if status.get("state") != "running" or not pid:
        raise RuntimeError(f"Komponenta {component} neběží.")
    _, port = DEBUG_COMPONENTS[component]
    unit = debug_unit(instance, component)
    subprocess.run(["systemctl", "stop", unit], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    command = [
        "systemd-run", "--quiet", "--collect", "--service-type=exec",
        f"--unit={unit}", f"--slice=saslik-{_unit_instance(instance)}.slice",
        "--property=Restart=no", "--property=KillMode=control-group",
        gdbserver, "--once", "--attach", f"127.0.0.1:{port}", str(pid),
    ]
    result = subprocess.run(command, check=False, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "gdbserver se nepodařilo spustit.")


def stop_gdbserver(instance: str, component: str) -> None:
    subprocess.run(["systemctl", "stop", debug_unit(instance, component)], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def debug_status(lab: Path, instance: str) -> list[dict[str, object]]:
    result = []
    for component, (_, port) in DEBUG_COMPONENTS.items():
        unit = debug_unit(instance, component)
        state = subprocess.run(
            ["systemctl", "is-active", unit], check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout.strip()
        binary = component_binary(lab, component) if (lab / DEBUG_COMPONENTS[component][0]).is_file() else None
        service = subprocess.run(
            ["systemctl", "show", unit_name(instance, component),
             "--property=ActiveState,MainPID"], check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout
        properties = dict(line.split("=", 1) for line in service.splitlines() if "=" in line)
        pid = int(properties.get("MainPID", "0") or 0)
        result.append({
            "component": component,
            "available": binary is not None,
            "active": state in {"active", "activating"},
            "running": properties.get("ActiveState") == "active" and pid > 0,
            "pid": pid or None,
            "port": port,
            "binary": str(binary) if binary else "",
            "command": f"gdb -q {binary} -ex 'target remote 127.0.0.1:{port}'" if binary else "",
        })
    return result
