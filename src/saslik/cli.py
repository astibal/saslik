from __future__ import annotations

import argparse
import ipaddress
import os
import subprocess

from .instance import Instance
from .runner import LabRunner
from .server import serve


def acquire_privileges() -> None:
    """Acquire one sudo ticket before browser actions start."""
    if os.geteuid() == 0:
        return
    print("Saslik potřebuje sudo pro network namespace, rozhraní a routování.")
    print("Teď si jednou vyžádá heslo; jednotlivé akce už poběží bez dalších dotazů.")
    try:
        subprocess.run(["sudo", "-v"], check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("Příkaz sudo není nainstalovaný.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("Sudo oprávnění se nepodařilo získat.") from exc


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="saslik", description="Smithproxy + Spider + Sift micro-launcher")
    value.add_argument("-i", "--instance", default="default", help="pojmenovaný lab (default: default)")
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
    args = parser().parse_args(argv)
    override = "pasta" if args.pasta else args.egress
    instance = Instance.load(args.instance, override)
    instance.ensure_config()
    web_host = getattr(args, "host", os.environ.get("SASLIK_WEB_HOST", "127.0.0.1"))
    try:
        remote = not ipaddress.ip_address(web_host).is_loopback
    except ValueError:
        remote = web_host != "localhost"
    expose_address = "0.0.0.0" if remote else "127.0.0.1"
    runner = LabRunner(instance.data_dir.parent, instance=instance.name, egress=instance.egress,
                       expose_address=expose_address)
    runner.lab = instance.data_dir
    acquire_privileges()
    if args.command in {None, "web"}:
        serve(web_host, getattr(args, "port", 8765),
              getattr(args, "display_mode", "app"), runner)
        return 0
    return runner.run_console(args.command, getattr(args, "branch", "master"))
