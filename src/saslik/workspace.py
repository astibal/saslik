from __future__ import annotations

import argparse
import os
import secrets
import shutil
import subprocess
import sys
import json
import platform
import tarfile
import tempfile
from pathlib import Path

from .settings import setting_value


REPOSITORIES = {
    "smithproxy-spider": "https://github.com/astibal/smithproxy-spider.git",
    "sift": "https://github.com/astibal/sift.git",
    "smithproxy": "https://github.com/astibal/smithproxy.git",
    "capture-zone-viewer": "git@github.com:astibal/capture-zone-portal.git",
}

COMPONENT_SOURCES = {
    "smithproxy": ("smithproxy", "ref_smithproxy"),
    "spider": ("smithproxy-spider", "ref_spider"),
    "sift": ("sift", "ref_sift"),
    "pcap-viewer": ("capture-zone-viewer", "ref_pcap_viewer"),
}


def component_source_status(lab: Path, component: str) -> dict[str, str]:
    """Compare a managed checkout with its configured remote ref.

    The fetch uses a private tracking ref and does not touch FETCH_HEAD, so a
    background UI check cannot disturb an update already running in the lab.
    """
    if component not in COMPONENT_SOURCES:
        raise ValueError(f"Neznámá komponenta: {component}")
    checkout, ref_setting = COMPONENT_SOURCES[component]
    path = lab.resolve() / "src" / checkout
    if not (path / ".git").exists():
        return {"state": "missing", "detail": "zdroj ještě není stažený"}
    status = subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain"],
        check=True, text=True, stdout=subprocess.PIPE, timeout=5,
    ).stdout.strip()
    if status:
        return {"state": "dirty", "detail": "lokální změny"}
    ref = str(setting_value(lab, ref_setting))
    tracking = f"refs/saslik/source-status/{component}"
    environment = os.environ.copy()
    environment.setdefault("GIT_TERMINAL_PROMPT", "0")
    environment.setdefault("GIT_SSH_COMMAND", "ssh -oBatchMode=yes")
    subprocess.run(
        ["git", "-C", str(path), "fetch", "--quiet", "--no-write-fetch-head",
         "origin", f"+{ref}:{tracking}"],
        check=True, env=environment, timeout=20,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    head = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], check=True,
        text=True, stdout=subprocess.PIPE, timeout=5,
    ).stdout.strip()
    remote = subprocess.run(
        ["git", "-C", str(path), "rev-parse", tracking], check=True,
        text=True, stdout=subprocess.PIPE, timeout=5,
    ).stdout.strip()
    if head == remote:
        return {"state": "current", "detail": "aktuální"}
    behind = subprocess.run(
        ["git", "-C", str(path), "merge-base", "--is-ancestor", "HEAD", tracking],
        timeout=5,
    ).returncode == 0
    if behind:
        return {"state": "behind", "detail": "je dostupná novější verze"}
    ahead = subprocess.run(
        ["git", "-C", str(path), "merge-base", "--is-ancestor", tracking, "HEAD"],
        timeout=5,
    ).returncode == 0
    return {"state": "ahead" if ahead else "diverged",
            "detail": "lokálně napřed" if ahead else "větev se rozešla"}


def source_changes(lab: Path) -> list[str]:
    """Return managed source checkouts with local Git changes."""
    sources = lab.resolve() / "src"
    changed = []
    for name in REPOSITORIES:
        path = sources / name
        if not path.exists():
            continue
        if not (path / ".git").exists():
            raise RuntimeError(f"Saslik odmítá kontrolovat cizí adresář {path}.")
        status = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain"],
            check=True, text=True, stdout=subprocess.PIPE,
        ).stdout.strip()
        if status:
            changed.append(name)
    return changed


def discard_source_changes(lab: Path) -> list[str]:
    """Discard tracked and untracked changes only in managed source trees."""
    sources = lab.resolve() / "src"
    changed = source_changes(lab)
    for name in changed:
        path = sources / name
        # Submodules have their own worktrees. Clean them before forcing the
        # superproject's recorded submodule revisions back into place.
        _run(["git", "-C", str(path), "submodule", "foreach", "--recursive",
              "git reset --hard HEAD"])
        _run(["git", "-C", str(path), "submodule", "foreach", "--recursive",
              "git clean -fd"])
        _run(["git", "-C", str(path), "reset", "--hard", "HEAD"])
        _run(["git", "-C", str(path), "clean", "-fd"])
        _run(["git", "-C", str(path), "submodule", "update", "--init", "--recursive",
              "--force"])
    return changed


def _run(command: list[str], *, quiet: bool = False) -> None:
    environment = os.environ.copy()
    if command and command[0] == "git":
        environment.setdefault("GIT_TERMINAL_PROMPT", "0")
        environment.setdefault("GIT_SSH_COMMAND", "ssh -oBatchMode=yes")
    subprocess.run(command, check=True, env=environment,
                   stdout=subprocess.DEVNULL if quiet else None,
                   stderr=subprocess.DEVNULL if quiet else None)


def _sync_checkout(path: Path, repository: str, ref: str,
                   preserve_dirty: bool = False) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--recurse-submodules", repository, str(path)])
    if not (path / ".git").is_dir():
        raise RuntimeError(f"Saslik odmítá přepsat cizí adresář {path}.")
    changed = subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain"],
        check=True, text=True, stdout=subprocess.PIPE,
    ).stdout.strip()
    if changed:
        branch = subprocess.run(
            ["git", "-C", str(path), "branch", "--show-current"],
            check=True, text=True, stdout=subprocess.PIPE,
        ).stdout.strip()
        if branch != ref:
            raise RuntimeError(
                f"Zdrojový strom {path} má lokální změny na větvi "
                f"{branch or '(detached HEAD)'}, ale workspace používá {ref}. "
                "Změny můžeš zahodit v kartě Logy nebo přepnout nastavenou větev."
            )
        print(f"Dirty strom na stejné větvi {ref}; zkouším aktualizaci přes --ff-only: {path}")
        _run(["git", "-C", str(path), "remote", "set-url", "origin", repository])
        _run(["git", "-C", str(path), "fetch", "origin", ref])
        try:
            _run(["git", "-C", str(path), "merge", "--ff-only", "FETCH_HEAD"])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"Lokální změny v {path} nelze čistě spojit s origin/{ref}; "
                "pracovní strom zůstal zachovaný."
            ) from exc
        _run(["git", "-C", str(path), "submodule", "update", "--init", "--recursive"])
        message = "Zachovávám přenesené" if preserve_dirty else "Zachovávám"
        print(f"{message} lokální změny po aktualizaci {ref}: {path}")
        return
    # Managed checkouts follow the configured repository.  This also migrates
    # older HTTPS viewer checkouts to SSH without deleting local objects.
    _run(["git", "-C", str(path), "remote", "set-url", "origin", repository])
    _run(["git", "-C", str(path), "fetch", "origin", ref])
    _run(["git", "-C", str(path), "checkout", "-B", ref, "FETCH_HEAD"])
    _run(["git", "-C", str(path), "submodule", "update", "--init", "--recursive"])


def _ensure_checkout(path: Path, repository: str) -> None:
    """Clone a dependency once; never mutate an existing developer checkout."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--branch", "main", "--recurse-submodules",
              repository, str(path)])
    if not (path / ".git").is_dir():
        raise RuntimeError(f"Saslik odmítá použít cizí adresář {path}.")


def sync(lab: Path, smithproxy_ref: str) -> None:
    sources = lab / "src"
    preserved = _preserved_dirty_sources(lab)
    spider_repo = os.environ.get("SASLIK_SPIDER_REPOSITORY", REPOSITORIES["smithproxy-spider"])
    sift_repo = os.environ.get("SASLIK_SIFT_REPOSITORY", REPOSITORIES["sift"])
    smith_repo = os.environ.get("SASLIK_SMITHPROXY_REPOSITORY", REPOSITORIES["smithproxy"])
    _sync_checkout(sources / "smithproxy-spider", spider_repo,
                   str(setting_value(lab, "ref_spider")), "smithproxy-spider" in preserved)
    _sync_checkout(sources / "sift", sift_repo, str(setting_value(lab, "ref_sift")),
                   "sift" in preserved)
    _sync_checkout(sources / "smithproxy", smith_repo, smithproxy_ref,
                   "smithproxy" in preserved)
    sync_viewer(lab)
    _refresh_preserved_dirty_sources(lab, preserved)
    state = lab / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "source-ref").write_text(smithproxy_ref + "\n", encoding="utf-8")


def sync_viewer(lab: Path) -> None:
    viewer_repo = os.environ.get("SASLIK_PCAP_VIEWER_REPOSITORY",
                                 REPOSITORIES["capture-zone-viewer"])
    viewer_ref = os.environ.get("SASLIK_PCAP_VIEWER_REF",
                                str(setting_value(lab, "ref_pcap_viewer")))
    preserved = _preserved_dirty_sources(lab)
    _sync_checkout(lab / "src/capture-zone-viewer", viewer_repo, viewer_ref,
                   "capture-zone-viewer" in preserved)
    _refresh_preserved_dirty_sources(lab, preserved)


def sync_component(lab: Path, component: str, smithproxy_ref: str = "master") -> None:
    """Update exactly one managed source checkout."""
    sources = lab / "src"
    preserved = _preserved_dirty_sources(lab)
    values = {
        "smithproxy": ("smithproxy", "SASLIK_SMITHPROXY_REPOSITORY", smithproxy_ref),
        "spider": ("smithproxy-spider", "SASLIK_SPIDER_REPOSITORY",
                   str(setting_value(lab, "ref_spider"))),
        "sift": ("sift", "SASLIK_SIFT_REPOSITORY", str(setting_value(lab, "ref_sift"))),
        "pcap-viewer": ("capture-zone-viewer", "SASLIK_PCAP_VIEWER_REPOSITORY",
                        str(setting_value(lab, "ref_pcap_viewer"))),
    }
    if component not in values:
        raise ValueError(f"Neznámá komponenta: {component}")
    checkout, environment, ref = values[component]
    repository = os.environ.get(environment, REPOSITORIES[checkout])
    _sync_checkout(sources / checkout, repository, ref, checkout in preserved)
    _refresh_preserved_dirty_sources(lab, preserved)


def _preserved_dirty_sources(lab: Path) -> set[str]:
    path = lab / "state/cloned-dirty-sources.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {str(item) for item in value if str(item) in REPOSITORIES} if isinstance(value, list) else set()


def _refresh_preserved_dirty_sources(lab: Path, preserved: set[str]) -> None:
    if not preserved:
        return
    remaining = preserved.intersection(source_changes(lab))
    path = lab / "state/cloned-dirty-sources.json"
    if remaining:
        path.write_text(json.dumps(sorted(remaining)) + "\n", encoding="utf-8")
    else:
        path.unlink(missing_ok=True)


def install_viewer(lab: Path) -> None:
    viewer_source = lab / "src/capture-zone-viewer"
    viewer_venv = lab / "runtime/pcap-viewer-venv"
    if not (viewer_source / "pyproject.toml").is_file():
        raise RuntimeError("Capture.Zone PCAP Viewer nemá instalovatelný pyproject.toml.")
    if not (viewer_venv / "bin/python").is_file():
        _run([sys.executable, "-m", "venv", str(viewer_venv)])
    _run([str(viewer_venv / "bin/python"), "-m", "pip", "install", "--upgrade",
          str(viewer_source)])


def build(lab: Path) -> None:
    jobs = f"-j{os.cpu_count() or 1}"
    build_type = "Debug" if setting_value(lab, "debug_build") is True else "Release"
    projects = [
        (lab / "src/smithproxy", lab / "build/smithproxy", ["-DBUILD_TESTING=OFF"], "smithproxy"),
        (lab / "src/smithproxy-spider", lab / "build/spider", [], None),
        (lab / "src/sift", lab / "build/sift", ["-DBUILD_TESTING=OFF"], "siftd"),
    ]
    for source, destination, options, target in projects:
        _run(["cmake", "-S", str(source), "-B", str(destination),
              f"-DCMAKE_BUILD_TYPE={build_type}", *options])
        command = ["cmake", "--build", str(destination), jobs]
        if target:
            command.extend(["--target", target])
        _run(command)
    install_viewer(lab)


def build_component(lab: Path, component: str) -> None:
    """Build or install one component without touching the other runtimes."""
    if component == "pcap-viewer":
        install_viewer(lab)
        return
    projects = {
        "smithproxy": (lab / "src/smithproxy", lab / "build/smithproxy",
                       ["-DBUILD_TESTING=OFF"], "smithproxy"),
        "spider": (lab / "src/smithproxy-spider", lab / "build/spider", [], None),
        "sift": (lab / "src/sift", lab / "build/sift", ["-DBUILD_TESTING=OFF"], "siftd"),
    }
    if component not in projects:
        raise ValueError(f"Neznámá komponenta: {component}")
    source, destination, options, target = projects[component]
    build_type = "Debug" if setting_value(lab, "debug_build") is True else "Release"
    _run(["cmake", "-S", str(source), "-B", str(destination),
          f"-DCMAKE_BUILD_TYPE={build_type}", *options])
    command = ["cmake", "--build", str(destination), f"-j{os.cpu_count() or 1}"]
    if target:
        command.extend(["--target", target])
    _run(command)


def save_binary_bundle(lab: Path, destination: Path) -> None:
    required = {
        "build/smithproxy": lab / "build/smithproxy",
        "build/spider": lab / "build/spider",
        "build/sift": lab / "build/sift",
        "runtime/frontend": lab / "src/smithproxy-spider/frontend",
    }
    for source in required.values():
        if not source.exists():
            raise RuntimeError(f"Binary bundle nelze vytvořit, chybí {source}.")
    manifest = {
        "format": 1,
        "machine": platform.machine(),
        "system": platform.system(),
        "source_ref": (lab / "state/source-ref").read_text(encoding="utf-8").strip()
        if (lab / "state/source-ref").is_file() else "unknown",
    }
    with tempfile.TemporaryDirectory() as temporary:
        manifest_path = Path(temporary) / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        with tarfile.open(destination, "w:gz") as bundle:
            bundle.add(manifest_path, arcname="manifest.json")
            for archive_name, source in required.items():
                bundle.add(source, arcname=archive_name)


def load_binary_bundle(lab: Path, source: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(dir=lab) as temporary:
        staging = Path(temporary)
        try:
            with tarfile.open(source, "r:gz") as bundle:
                members = bundle.getmembers()
                allowed = ("manifest.json", "build/smithproxy/", "build/spider/",
                           "build/sift/", "runtime/frontend/")
                for member in members:
                    if member.issym() or member.islnk() or member.name.startswith("/") or ".." in Path(member.name).parts:
                        raise RuntimeError("Binary bundle obsahuje nebezpečnou cestu.")
                    if member.name != "manifest.json" and not any(
                            member.name == prefix.rstrip("/") or member.name.startswith(prefix)
                            for prefix in allowed[1:]):
                        raise RuntimeError(f"Neočekávaný soubor v binary bundle: {member.name}")
                bundle.extractall(staging)
        except tarfile.TarError as exc:
            raise RuntimeError("Soubor není platný Saslik binary bundle.") from exc
        manifest_path = staging / "manifest.json"
        if not manifest_path.is_file():
            raise RuntimeError("Binary bundle nemá manifest.")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("format") != 1 or manifest.get("machine") != platform.machine():
            raise RuntimeError(f"Binary bundle není určený pro {platform.machine()}.")
        for required in (staging / "build/smithproxy/smithproxy",
                         staging / "build/spider/smithproxy-spider",
                         staging / "build/sift/siftd", staging / "runtime/frontend"):
            if not required.exists():
                raise RuntimeError(f"Binary bundle je neúplný, chybí {required.name}.")
        build = lab / "build"
        build.mkdir(parents=True, exist_ok=True)
        for name in ("smithproxy", "spider", "sift"):
            destination = build / name
            if destination.exists():
                shutil.rmtree(destination)
            shutil.move(str(staging / "build" / name), destination)
        frontend = lab / "src/smithproxy-spider/frontend"
        if frontend.exists():
            shutil.rmtree(frontend)
        frontend.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staging / "runtime/frontend"), frontend)
        marker = lab / "state/binary-bundle.json"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return manifest


def _openssl(*arguments: str) -> None:
    _run(["openssl", *arguments], quiet=True)


def _validate_ca_pair(certificate: Path, key: Path) -> None:
    if not certificate.is_file() or not key.is_file():
        raise RuntimeError("Vybraný CA certifikát nebo klíč neexistuje.")
    cert_public = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ).stdout
    key_public = subprocess.run(
        ["openssl", "pkey", "-in", str(key), "-pubout"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ).stdout
    if cert_public != key_public:
        raise RuntimeError("CA certifikát a privátní klíč k sobě nepatří.")


def initialize_state(lab: Path, template: str = "spider-sift", *,
                     ca_cert: Path | None = None, ca_key: Path | None = None) -> bool:
    """Create state only for a new lab; never rewrite an existing config/CA."""
    state = lab / "state"
    config = state / "smithproxy.cfg"
    certs = state / "certs/default"
    env = state / "state.env"
    existing = (config.exists(), certs.exists(), env.exists())
    if any(existing):
        if not all(existing):
            raise RuntimeError("Neúplný persistentní stav; config, CA a state.env musí existovat spolu.")
        return False
    if (ca_cert is None) != (ca_key is None):
        raise RuntimeError("Existující CA vyžaduje certifikát i privátní klíč.")
    if ca_cert is not None and ca_key is not None:
        _validate_ca_pair(ca_cert, ca_key)
    state.mkdir(parents=True, exist_ok=True)
    certs.mkdir(parents=True)
    source = lab / "src/smithproxy"
    shutil.copy2(source / "etc/certs/default/sslca.json", certs / "sslca.json")
    if ca_cert is not None and ca_key is not None:
        shutil.copy2(ca_cert, certs / "ca-cert.pem")
        shutil.copy2(ca_key, certs / "ca-key.pem")
    else:
        _openssl("req", "-x509", "-newkey", "rsa:3072", "-sha256", "-days", "365",
                 "-nodes", "-keyout", str(certs / "ca-key.pem"), "-out",
                 str(certs / "ca-cert.pem"), "-subj",
                 "/CN=Smithproxy Saslik CA/O=Smithproxy Saslik/C=CZ",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout",
             str(certs / "srv-key.pem"), "-out", str(state / "server.csr"),
             "-subj", "/CN=smithproxy-test")
    extensions = state / "server.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:smithproxy-test,IP:10.254.77.2,IP:10.254.77.1\n",
        encoding="ascii",
    )
    _openssl("x509", "-req", "-in", str(state / "server.csr"), "-CA",
             str(certs / "ca-cert.pem"), "-CAkey", str(certs / "ca-key.pem"),
             "-CAcreateserial", "-out", str(certs / "srv-cert.pem"), "-days", "365",
             "-sha256", "-extfile", str(extensions))
    for prefix in ("portal", "cl"):
        shutil.copy2(certs / "srv-key.pem", certs / f"{prefix}-key.pem")
        shutil.copy2(certs / "srv-cert.pem", certs / f"{prefix}-cert.pem")
    for key in certs.glob("*-key.pem"):
        key.chmod(0o600)
    api_key = secrets.token_hex(24)
    spider_token = secrets.token_hex(24)
    _create_config(lab, api_key)
    from .routing import apply_starting_template
    apply_starting_template(lab, template)
    env.write_text(
        f"SMITHPROXY_API_KEY={api_key}\n"
        f"SPIDER_TOKEN={spider_token}\n"
        "SMITHPROXY_API_URL=https://10.254.77.2:55580\n"
        "SMITHPROXY_CONNECT_URL=http://10.254.77.2:33128\n"
        "SMITHPROXY_CALLBACK_URL=http://10.254.77.1:18080/webhook\n"
        f"SMITHPROXY_CA_CERT={certs / 'ca-cert.pem'}\n"
        "SMITHPROXY_CLI=10.254.77.2:55000\n",
        encoding="utf-8",
    )
    env.chmod(0o600)
    return True


def _create_config(lab: Path, api_key: str) -> None:
    state = lab / "state"
    source = lab / "src/smithproxy"
    certs = state / "certs/default"
    text = (source / "etc/smithproxy.cfg").read_text(encoding="utf-8")
    replacements = {
        "accept_tproxy = TRUE;": "accept_tproxy = TRUE;",
        "accept_redirect = TRUE;": "accept_redirect = FALSE;",
        "accept_socks = TRUE;": "accept_socks = TRUE;",
        "accept_http_connect = FALSE;": "accept_http_connect = TRUE;",
        'http_connect_port = "3128";': 'http_connect_port = "33128";',
        "http_connect_workers = 0;": "http_connect_workers = 1;",
        'certs_path = "/etc/smithproxy/certs/default/";': f'certs_path = "{certs}/";',
        'certs_ca_key_password = "smithproxy";': 'certs_ca_key_password = "";',
        'messages_dir = "/etc/smithproxy/msg/en/";': f'messages_dir = "{source / "etc/msg/en"}/";',
        "port = 50000;": "port = 55000;",
        'log_file = "/var/log/smithproxy/messages.%s.log";': f'log_file = "{state}/messages.%s.log";',
        'sslkeylog_file = "/var/log/smithproxy/sslkeylog.%s.log";': f'sslkeylog_file = "{state}/sslkeylog.%s.log";',
        'dir = "/var/smithproxy/data"': f'dir = "{state}"',
    }
    for old, new in replacements.items():
        if old not in text:
            raise RuntimeError(f"Výchozí Smithproxy config neobsahuje očekávanou hodnotu: {old}")
        text = text.replace(old, new, 1)
    settings = f'''settings = {{
    accept_api = TRUE;
    http_api = {{
        keys = [ "{api_key}" ];
        key_timeout = 3600;
        key_extend_on_access = TRUE;
        loopback_only = FALSE;
        bind_address = "0.0.0.0";
        allow_api_header = TRUE;
        port = 55580;
        pam_login = FALSE;
    }};
    webhook = {{
        enabled = TRUE;
        url = "http://10.254.77.1:18080/webhook";
        tls_verify = FALSE;
        api_override = TRUE;
        ping_interval = 5;
        sift = TRUE;
        sift_url = "http://10.254.77.1:18081/webhook";
    }};
'''
    if "settings = {" not in text:
        raise RuntimeError("Výchozí Smithproxy config nemá settings blok.")
    (state / "smithproxy.cfg").write_text(text.replace("settings = {", settings, 1),
                                           encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-workspace")
    parser.add_argument("action", choices=("sync", "build", "component-sync", "component-build",
                                           "viewer-sync", "viewer-install",
                                           "init", "bundle-save", "bundle-load", "bundle-clear",
                                           "discard-changes"))
    parser.add_argument("lab", type=Path)
    parser.add_argument("--ref", default="master")
    parser.add_argument("--template", choices=("spider-sift", "spider", "proxy"),
                        default="spider-sift")
    parser.add_argument("--ca-cert", type=Path)
    parser.add_argument("--ca-key", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--component", choices=("smithproxy", "spider", "sift", "pcap-viewer"))
    args = parser.parse_args(argv)
    try:
        if args.action == "sync":
            sync(args.lab, args.ref)
        elif args.action == "build":
            build(args.lab)
        elif args.action == "viewer-sync":
            sync_viewer(args.lab)
        elif args.action == "viewer-install":
            install_viewer(args.lab)
        elif args.action == "component-sync":
            if not args.component:
                raise RuntimeError("Chybí --component.")
            sync_component(args.lab, args.component, args.ref)
        elif args.action == "component-build":
            if not args.component:
                raise RuntimeError("Chybí --component.")
            build_component(args.lab, args.component)
        elif args.action == "init":
            created = initialize_state(args.lab, args.template,
                                       ca_cert=args.ca_cert, ca_key=args.ca_key)
            print("Nový persistentní config a CA vytvořeny." if created
                  else "Persistentní config a CA zachovány beze změny.")
        elif args.action == "bundle-clear":
            (args.lab / "state/binary-bundle.json").unlink(missing_ok=True)
        elif args.action == "discard-changes":
            changed = discard_source_changes(args.lab)
            print("Zahozeny lokální změny: " + (", ".join(changed) if changed else "žádné"))
        elif not args.bundle:
            raise RuntimeError("Chybí cesta k binary bundle.")
        elif args.action == "bundle-save":
            save_binary_bundle(args.lab, args.bundle)
        else:
            load_binary_bundle(args.lab, args.bundle)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"saslik-workspace: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
