from __future__ import annotations

import argparse
import ipaddress
import os
import subprocess
import threading

from .instance import Instance, remember_instance, remembered_instance
from .maintenance import LogMaintenance, process_log
from .runner import LabRunner, data_root, ensure_friendly_data_link
from .server import serve


class SudoLease:
    """Keep the user's sudo timestamp alive only while Saslik is running."""

    def __init__(self, enabled: bool, interval: float = 45.0) -> None:
        self.enabled = enabled
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "SudoLease":
        if self.enabled:
            self._thread = threading.Thread(target=self._keepalive,
                                            name="saslik-sudo-lease", daemon=True)
            self._thread.start()
        return self

    def _keepalive(self) -> None:
        while not self._stop.wait(self.interval):
            subprocess.run(
                ["sudo", "-n", "-v"], check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)


def acquire_privileges() -> SudoLease:
    """Acquire and maintain one sudo ticket for the foreground lifetime."""
    if os.geteuid() == 0:
        return SudoLease(False)
    print("Saslik potřebuje sudo pro network namespace, rozhraní a routování.")
    print("Teď si jednou vyžádá heslo; jednotlivé akce už poběží bez dalších dotazů.")
    try:
        subprocess.run(["sudo", "-v"], check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("Příkaz sudo není nainstalovaný.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("Sudo oprávnění se nepodařilo získat.") from exc
    return SudoLease(True).start()


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="saslik", description="Smithproxy + Spider + Sift micro-launcher")
    value.add_argument("-i", "--instance", help="pojmenovaný lab (default: naposledy použitý)")
    value.add_argument("--devel", action="store_true",
                       help="zpřístupnit vývojářské nástroje včetně patchování zdrojů")
    display = value.add_mutually_exclusive_group()
    display.add_argument("--browser", action="store_const", const="browser", dest="display_mode",
                         help="otevřít v běžném výchozím browseru")
    display.add_argument("--no-browser", action="store_const", const="none", dest="display_mode",
                         help="browser neotevírat, pouze vypsat URL")
    # Never create a detached browser window implicitly. It is too easy to
    # keep looking at a stale app window after Saslik itself was restarted.
    value.set_defaults(display_mode="none")
    egress = value.add_mutually_exclusive_group()
    egress.add_argument("--pasta", action="store_true", help="použít pasta egress místo NAT")
    egress.add_argument("--egress", choices=("nat", "pasta"), help="přepsat egress režim instance")
    sub = value.add_subparsers(dest="command")
    web = sub.add_parser("web", help="spustit lokální web")
    web.add_argument("--host", default=os.environ.get("SASLIK_WEB_HOST", "127.0.0.1"))
    web.add_argument("--port", type=int, default=8765)
    web_display = web.add_mutually_exclusive_group()
    web_display.add_argument("--browser", action="store_const", const="browser", dest="display_mode",
                             default=argparse.SUPPRESS)
    web_display.add_argument("--no-browser", action="store_const", const="none", dest="display_mode",
                             default=argparse.SUPPRESS)
    for name in ("start", "reset", "fetch"):
        item = sub.add_parser(name)
        item.add_argument("--branch", default="master")
    sub.add_parser("status")
    sub.add_parser("stop")
    return value


def main(argv: list[str] | None = None) -> int:
    root = data_root()
    with process_log(root):
        return _main(argv, root)


def _main(argv: list[str] | None, root) -> int:
    args = parser().parse_args(argv)
    override = "pasta" if args.pasta else args.egress
    instance = Instance.load(args.instance or remembered_instance(), override)
    instance.ensure_config()
    remember_instance(instance.name)
    ensure_friendly_data_link()
    web_host = getattr(args, "host", os.environ.get("SASLIK_WEB_HOST", "127.0.0.1"))
    try:
        remote = not ipaddress.ip_address(web_host).is_loopback
    except ValueError:
        remote = web_host != "localhost"
    expose_address = "0.0.0.0" if remote else "127.0.0.1"
    runner = LabRunner(instance.data_dir.parent, instance=instance.name, egress=instance.egress,
                       expose_address=expose_address, devel=args.devel)
    runner.lab = instance.data_dir
    lease = acquire_privileges()
    try:
        # The web guardian repairs legacy root-owned logs before the first
        # periodic unprivileged pass. Console commands are normally shorter
        # than the maintenance interval and must not emit a spurious warning.
        maintenance = LogMaintenance(root).start(run_immediately=False)
        try:
            if args.command in {None, "web"}:
                serve(web_host, getattr(args, "port", 8765),
                      getattr(args, "display_mode", "app"), runner, devel=args.devel)
                return 0
            return runner.run_console(args.command, getattr(args, "branch", "master"))
        finally:
            maintenance.close()
    finally:
        lease.close()
