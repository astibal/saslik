# VM appliance

The build pipeline provisions Ubuntu 26.04 LTS (`resolute`) into a rootfs,
installs it on a BIOS/UEFI-capable RAW disk, then exports QCOW2, VDI or OVA.
Workspace components still run in their own network namespaces inside the VM.

## Build and smoke test

Build in a new directory: builders deliberately refuse to overwrite rootfs
or RAW outputs. Reserve space for both the rootfs and disk/export artifacts.

```sh
sudo -v
make appliance APPLIANCE_BUILD=/tmp/saslik-appliance-build \
    APPLIANCE_DIST=/tmp/saslik-appliance-dist
make test-appliance APPLIANCE_IMAGE=/tmp/saslik-appliance-dist/saslik-amd64.qcow2
```

The smoke test uses a disposable overlay, QEMU user networking and DHCP
address `10.77.0.2`. It does not change host routes or modify the base image.
HTTPS is forwarded to `127.0.0.1:18765`. The test checks first-access setup,
public connection discovery, and rejection of unauthenticated private API
requests. It bypasses certificate verification only for this isolated test.
Serial output and test artifacts go to `artifacts/qemu-smoke`.
Repeat with `SASLIK_QEMU_FIRMWARE=uefi` to exercise the UEFI boot path
(requires the host `ovmf` package). Each run gets a private copy of firmware
variables. The default firmware is BIOS.

Host-side temporary work never has to use `/tmp`. All Make targets set
`TMPDIR` to `$(APPLIANCE_BUILD)/tmp` by default. Put large transient data on a
dedicated filesystem explicitly, for example:

```sh
make takeaway-linux BUILD_TMP=/lab/temp
```

The debootstrap rootfs staging lives separately in the managed appliance cache.
Paths such as `/tmp/pip-build-*` printed by commands running inside `chroot`
refer to the staged guest rootfs, not the host `/tmp`.

## Runtime

* `saslik.service` starts the HTTPS portal on port 8765 after boot.
* Persistent state lives in `/var/lib/saslik` (workspaces, captures, credentials
  and certificates). Preserve this directory across upgrades.
* The NIC obtains a DHCP address/default route while retaining
  `198.18.18.1/24` for routing into the appliance. Avoid placing multiple VMs
  with this same static address on the same L2 network.
* The first visitor sets the administrator password. Perform initial setup
  on an isolated/trusted network. No default password is distributed.
* Each VM creates its own portal certificate and machine identity. SSH is
  disabled until an administrator configures access and generates host keys.
* Inspect the portal with `journalctl -u saslik.service`; application logs are
  also available through the portal.

The current launcher needs root for namespace and service management, so the
appliance portal service explicitly runs as root. This is not a hardened
multi-tenant hosting environment. No broad passwordless sudo rule is added.

## Build cache

Appliance builds keep a disposable cache in `build/cache/appliance`. It holds
the suite/mirror-specific debootstrap tarball, downloaded APT archives and
short-lived staging directories. The cache is never copied into an appliance
or Takeaway artifact.

```sh
make prune-cache                 # normal TTL/size maintenance
make prune-cache PYTHON=.venv/bin/python
make clean-cache                 # intentionally discard all managed entries
PYTHONPATH=src .venv/bin/python -m saslik.build_cache prune \
    --cache build/cache/appliance --dry-run
```

Staging entries expire after two days; reusable bootstrap/APT data expires
after seven days since use. The complete cache is limited to 10 GiB and evicts
the least recently used entries first. The rootfs builder holds
`build/cache/appliance/.lock` for its complete run. Portal maintenance uses
the same non-blocking lock and skips cleanup while a build is active. In a
source checkout it checks the cache at most every six hours; installed wheels
do not invent a build cache. `SASLIK_BUILD_CACHE` may point maintenance at an
explicit cache directory.

## Takeaway clone lifecycle

A Takeaway image is sealed while it is still a directory staging tree, before
that tree is copied to a RAW/QCOW2 filesystem. This ordering is intentional:
deleting a private key from an already populated disk image would leave its
old blocks recoverable.

```sh
/opt/saslik/venv/bin/python -m saslik.takeaway seal \
    --data-root /path/to/staged/var/lib/saslik \
    --source-data-root /path/to/live/saslik \
    --target-data-root /var/lib/saslik
```

The seal keeps workspace configuration and binaries, but removes runtime
logs/captures, Git metadata and Saslik-managed credentials. It writes a
private `.takeaway-first-boot.json` marker. On the first VM boot,
`saslik-takeaway-firstboot.service` runs before the portal and generates fresh
workspace CAs and leaf certificates, Smithproxy API keys, Spider tokens and
SSH host keys. Portal credentials/TLS, gateway secrets and Skewer pairings are
left absent and are created or enrolled normally on the new VM. The service
removes the marker only after all workspaces were initialized successfully.

The Linux bundle rsync excludes known Smithproxy pickup storage, PCAP Viewer
runtime/captures, crash reports and capture/log suffixes before staging. These
paths are runtime data already removed by the seal and can be many times larger
than the actual workspace. They are therefore never copied merely to be
deleted afterwards.

The seal only knows secrets managed by Saslik. A future configurable Takeaway
export must explicitly declare any additional user files or component-specific
credentials that need removal; arbitrary values embedded in custom configs
cannot be identified safely by guessing.

## Linux Takeaway bundle

The same appliance rootfs can be distributed without a virtual disk. The Linux
bundle boots its immutable SquashFS runtime with `systemd-nspawn` and keeps all
writable state beside the extracted bundle:

```sh
make takeaway-linux TAKEAWAY_SOURCE_DATA="$HOME/.local/share/saslik"
tar xf dist/saslik-takeaway-linux-amd64.tar.gz
cd saslik-takeaway-linux-amd64
sudo ./saslik-tkw start
```

The launcher remains in the foreground and stops the complete runtime on
Ctrl-C. It also supports `status`, `stop`, `verify` and `eject`. The host needs
systemd-nspawn, `pasta` (the `passt` package), OverlayFS and SquashFS support.
Pasta gives the runtime outbound connectivity and forwards the allocated
portal, pairing and Tuntom ranges; it does not depend on
NetworkManager/systemd-networkd or add
rules to the host nftables/iptables configuration. Its persistent layout is:

```text
data/state/          /var/lib/saslik inside the runtime
data/library/        pickup/capture library, grouped by workspace
data/system/         writable OverlayFS layer for the immutable OS
```

Each workspace library directory is additionally mounted over that workspace's
`state/smithproxy-data`. Smithproxy therefore writes directly into the portable
library and PCAP storage sees the same files through its existing workspace
watch root. Moving the whole extracted directory moves both the lab and its
captures; `--library` overrides are intentionally deferred until the basic
lifecycle has been exercised end to end.

Multiple extracted bundles may run concurrently. A host-wide flock allocator
gives each running instance an exclusive slot and persists its preferred plan
in `data/host-plan.env`. The default mappings are:

```text
slot N portal       8765 + 2*N
slot N PSK          portal + 1
slot N Tuntom UDP   10001 + 256*N ... 10255 + 256*N
```

The allocator skips occupied TCP/UDP blocks and never adds host routes. All
workspace and service-point address ranges remain inside that bundle's outer
network namespace, so identical internal Network Plans do not collide. Use an
explicit host address or portal port when required:

```sh
sudo ./saslik-tkw start --port 9000
sudo ./saslik-tkw start --bind 192.0.2.10 --port 9000
```

The translated UI, PSK and Tuntom ports are passed into Saslik as advertised
public endpoints; internal listeners remain on their canonical ports. Copying
an already initialized bundle on one host is detected through a host registry;
copying it to another host is detected through the host machine identity. A
clone receives a fresh bundle/machine identity, a clean system overlay and a
first-boot credential rotation. A plain move keeps its identity and preferred
ports when they remain available.

## Remaining release gates

This is a development image recipe, not yet a release-ready appliance:

* Verify real BIOS and UEFI boots and workspace traffic end to end.
* Provision and test distributable component binaries, including licensing
  and private-repository availability; the recipe currently installs Saslik
  and build dependencies, not prebuilt workspace components.
* Provide an authenticated OS/Saslik update workflow with recovery. OS
  packages can be maintained with apt, but a portal update UI and a tested
  application upgrade path are not implemented by this recipe.
* Verify OVA import on VirtualBox and VMware.
