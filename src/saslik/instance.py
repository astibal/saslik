from __future__ import annotations

import re
import shutil
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .runner import data_root


NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,47}$")


def validate_instance_name(value: str) -> str:
    value = value.strip()
    if not NAME_RE.fullmatch(value) or value in {".", ".."}:
        raise ValueError("Instance smí obsahovat jen písmena, čísla, tečku, _ a - (max. 48 znaků).")
    return value


def config_root() -> Path:
    import os
    configured = os.environ.get("SASLIK_CONFIG_DIR")
    if configured:
        return Path(configured).expanduser()
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid and sudo_uid.isdigit():
        import pwd
        return Path(pwd.getpwuid(int(sudo_uid)).pw_dir) / ".config/saslik"
    return Path.home() / ".config/saslik"


def remember_instance(name: str) -> None:
    name = validate_instance_name(name)
    root = config_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / "last-workspace").write_text(name + "\n", encoding="utf-8")


def remembered_instance() -> str:
    path = config_root() / "last-workspace"
    try:
        return validate_instance_name(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return "default"


@dataclass(frozen=True)
class Instance:
    name: str
    egress: str = "nat"

    @classmethod
    def load(cls, name: str, override_egress: str | None = None) -> "Instance":
        name = validate_instance_name(name)
        path = config_root() / name / "saslik.toml"
        stored = "nat"
        if path.is_file():
            with path.open("rb") as stream:
                value = tomllib.load(stream)
            stored = str(value.get("egress", "nat"))
        egress = override_egress or stored
        if egress not in {"nat", "pasta"}:
            raise ValueError("Egress musí být 'nat' nebo 'pasta'.")
        return cls(name=name, egress=egress)

    @property
    def config_dir(self) -> Path:
        return config_root() / self.name

    @property
    def data_dir(self) -> Path:
        # Preserve the first prototype's existing workspace as the default lab.
        if self.name == "default":
            return data_root() / "lab"
        return data_root() / "instances" / self.name

    def ensure_config(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        path = self.config_dir / "saslik.toml"
        if not path.exists():
            # A command-line --pasta is a launch override, not a permanent
            # mutation. Users can opt in persistently by editing this file.
            path.write_text('egress = "nat"\n', encoding="utf-8")

    @classmethod
    def discover(cls) -> list["Instance"]:
        names = {"default"}
        configs = config_root()
        if configs.is_dir():
            names.update(path.name for path in configs.iterdir() if path.is_dir())
        instances = data_root() / "instances"
        if instances.is_dir():
            names.update(path.name for path in instances.iterdir() if path.is_dir())
        return [cls.load(name) for name in sorted(names)]


def rename_instance(old_name: str, new_name: str) -> None:
    old = Instance.load(old_name)
    new_name = validate_instance_name(new_name)
    if old_name == "default":
        raise RuntimeError("Výchozí workspace 'default' nelze přejmenovat.")
    if old_name == new_name:
        return
    new = Instance.load(new_name)
    if new.config_dir.exists() or new.data_dir.exists():
        raise RuntimeError(f"Workspace už existuje: {new_name}")
    moved_config = False
    try:
        if old.config_dir.exists():
            new.config_dir.parent.mkdir(parents=True, exist_ok=True)
            old.config_dir.rename(new.config_dir)
            moved_config = True
        if old.data_dir.exists():
            new.data_dir.parent.mkdir(parents=True, exist_ok=True)
            old.data_dir.rename(new.data_dir)
    except Exception:
        if moved_config and new.config_dir.exists() and not old.config_dir.exists():
            new.config_dir.rename(old.config_dir)
        raise


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="saslik-instance")
    parser.add_argument("action", choices=("rename",))
    parser.add_argument("old_name")
    parser.add_argument("new_name")
    args = parser.parse_args(argv)
    try:
        rename_instance(args.old_name, args.new_name)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"saslik-instance: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
