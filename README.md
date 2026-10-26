# Saslik

Small local web launcher for the Smithproxy + Spider + Sift development lab.
Saslik owns the workspace, namespace and component lifecycle. Long-running
components are transient systemd services grouped in a per-lab slice; upstream
Spider integration scripts are not used at runtime.

The lab also installs and starts the standalone Capture.Zone PCAP Viewer. Its
catalog, linked captures and derived analysis data live inside the selected
Saslik workspace. Override its source with `SASLIK_PCAP_VIEWER_REPOSITORY` and
`SASLIK_PCAP_VIEWER_REF`; the default is the `main` branch of
`astibal/capture-zone-portal`.

Saslik runs the viewer and its authenticated storage API as separate transient
services. The storage service watches Smithproxy's workspace data, safely picks
up completed captures and listens only on loopback; the browser-facing viewer
uses its private `0600` token through the shared-filesystem API. Startup and the
Status tab use each service's `/readyz` contract rather than a shallow HTTP ping.

## Tuntom workspace component

Tuntom is managed in **Workspace options → Components**, independently of the
Skewer client's local transport installation. Saslik clones `astibal/tuntom`
into `src/tuntom` (default ref `main`, repository override
`SASLIK_TUNTOM_REPOSITORY`) and builds the `tuntom` CMake target with the
workspace's Debug/Release setting. A successful build is atomically published
as `runtime/tuntom/tuntom`; failed builds leave the last working runtime intact.
Binary-bundle workspaces also build this separately managed component.

The privileged supervisor uses this workspace runtime, not a system-wide
`/usr/libexec` path or a path supplied by a remote client. As with the other
source-built lab components, the local workspace source is trusted code.
On first use Saslik creates the non-login `tuntom` system account if missing;
Tuntom starts privileged for network setup and then drops privileges.

There is no idle Tuntom daemon: authenticated clients get individual transient
systemd endpoints on demand. Updating Tuntom closes existing tunnel leases so
clients must reconnect, but does not restart Smithproxy or other components.
Automatic service restart is intentionally not offered: a tunnel restart needs
a fresh lease and network setup, not just a restarted process.

## Licensed components

Community components remain independent of licensing. A component that is
explicitly declared proprietary is checked immediately before Saslik replaces
or starts its transient systemd service. Saslik talks directly to the local
[`saslik-licensing`](https://github.com/astibal/saslik-licensing) facade at
`/run/saslik/licensing.sock`; set `SASLIK_LICENSING_SOCKET` only for development
or tests.

```text
signed license -> saslik-licensingd -> Unix socket -> Saslik preflight
                                                    |-- feature grant
                                                    `-- allow-listed arguments
```

The normal bootstrap is automatic. Saslik queries
`_saslik-license.saslik.io` for the current root-signed operational issuer
key. The C++ daemon—not the DNS client—verifies its signature and validity
against the root public key pinned at `/etc/saslik/licensing/root.pem`. Only an
accepted record is cached in `state/licensing/dns-key.txt`, so a temporary DNS
failure can use the last verified key. Until the TXT record and pinned root key
exist, startup remains ordinary community mode.

Without a public key or an installed license, Saslik runs in its normal
community mode and simply omits proprietary additions. Explicitly restarting
an unlicensed addition reports the missing entitlement without stopping the
running lab. A configured but broken key or unavailable licensing service is
reported as a configuration error. License-supplied text is never
used as a command line: each component adapter must explicitly map an allowed
key to an option, while unknown keys are ignored. The source-built `lored`
component is currently a development-only integration and is not gated. A
future distributed Lored feed or binary may require `component.lored`;
Smithproxy, Spider, Sift and the PCAP Viewer remain community components.

The issuer's Ed25519 public key can still be entered in workspace settings as a
development override, similarly to the IPinfo integration. The corresponding
private signing and root keys must remain offline and are never accepted by
this UI.

```bash
python3 -m pip install .
saslik
```

Named labs and egress selection:

```bash
saslik -i default              # classic veth + NAT egress (default)
saslik -i lab1 --pasta         # pasta userspace egress
saslik -i lab1 --egress pasta  # equivalent explicit form
```

Instance settings live in `~/.config/saslik/INSTANCE/saslik.toml`. Runtime
data lives under `~/.local/share/saslik`; when invoked through `sudo`, Saslik
uses the invoking user's home. The original prototype workspace is
retained as the `default` instance. Pasta mode requires the `passt` package.

Open <http://127.0.0.1:8765>. Saslik asks for a Smithproxy branch, initializes
its workspace, streams the build/start output and presents the resulting proxy,
CLI, API, Spider and CA endpoints. On the first start only, a template can seed
the initial Smithproxy configuration and an existing CA certificate/private-key
pair can be imported. Later starts never rewrite the configuration or CA.

Each workspace receives a stable runtime ID (`ws-001` … `ws-999`), its own
namespace, systemd slice and routing tables. Browser applications share the
portal HTTPS listener below stable mounts such as `/ws001/spider/` and
`/ws001/viewer/`. Nginx performs streaming and WebSocket proxying while Saslik
validates its existing portal session through `auth_request`; application data
never passes through Python. The forward-proxy protocol retains a dedicated
workspace port because it is not portal HTTP traffic. Internal component ports
remain unchanged inside each namespace.

## Requirements

Linux with systemd, Python 3.13+ including `venv`, `sudo`, nginx, Git, CMake, a C++
compiler, Wireshark CLI tools (`sharkd`, `tshark`, `editcap`) and the dependencies
required by Smithproxy, Spider and Sift. Saslik uses network namespaces,
nftables and transient systemd services and therefore needs root. Saslik itself stays
unprivileged. At startup it explains why privileges are needed, acquires one
interactive sudo ticket and invokes its runner actions through `sudo -n`.

Runtime data defaults to `~/.local/share/saslik/lab`. Override it with
`SASLIK_DATA_DIR`. The Spider repository defaults to
`https://github.com/astibal/smithproxy-spider.git`; override it with
`SASLIK_SPIDER_REPOSITORY`.

### Public custom installers

Files placed in `<workspace>/public/installers/` are offered for download on
the unauthenticated **Connect It** portal. Only regular files with simple ASCII
names are published; symlinks, dotfiles and `manifest.json` are never served.
Optional display metadata lives next to them in `manifest.json`:

```json
{"installers": [
  {"file": "skewer-android.apk", "title": "Skewer", "platform": "Android APK", "order": 10}
]}
```

Anything placed in this directory is intentionally public to every client that
can reach the portal.

## Console use

```bash
saslik status
saslik start --branch master
saslik stop
saslik reset --branch master
```

Route the current user's public IPv4 TCP/UDP traffic transparently through the
running lab (private, loopback and virtualization networks are excluded):

```bash
saslik-routing -i lab1 up
saslik-routing -i lab1 status
saslik-routing -i lab1 down
```

The routing helper owns one dedicated nftables table and one policy-routing
table. It never flushes global nftables/iptables rules, leaves IPv6 untouched
and removes only its exact rules on `down`.

## End-to-end health

Every running lab also owns a small `saslik-probe` client network namespace.
It is connected to the client side of the transparent Smithproxy ingress and
checks the complete path every 15 seconds:

```text
saslik-probe/eth0 → namespace TPROXY → Smithproxy → internet
```

The probe sends a raw DNS A query for `example.com` to `1.1.1.1`, performs
plain HTTP, performs HTTPS with trust verification disabled, and finally
compares the intercepted leaf issuer with the subject of the lab CA. Results,
latencies and the observed issuer appear under **Status → Průchod skrz lab**.
Namespace TPROXY is installed automatically with the lab; `saslik-routing up`
remains an explicit opt-in that additionally routes host-user traffic into it.

`saslik web` and plain `saslik` start the local UI server in the foreground.
Saslik requests sudo itself; no second terminal is needed. It prints the URL
and a ready-to-copy Chromium `--app` command, but never opens a browser
implicitly. It prints the portal URL for opening in any browser. The HTTP
listener binds to loopback only.

For an appliance or an explicitly trusted lab network, bind the UI remotely:

```bash
saslik -i lab1 web --host 0.0.0.0
```

In remote mode the HTTP CONNECT, API and CLI forwarders also listen on all IPv4
addresses. Endpoint cards use the hostname through which each browser opened
the UI, so the same page shows loopback links locally and routable links to a
remote client. This mode has no UI authentication yet; protect it with a host
firewall and use it only on a trusted network.

## Appliance image pipeline

The canonical appliance artifact is a raw disk image. Hypervisor-specific
images are exports of that one disk, so packaging never rebuilds or mutates the
guest OS:

```text
OS provisioner -> dist/saslik-amd64.raw
                         |-- saslik-amd64.qcow2  (KVM/QEMU)
                         |-- saslik-amd64.vdi    (VirtualBox)
                         `-- saslik-amd64.ova    (portable OVF + VMDK)
```

The provisioner first creates an inspectable Ubuntu Server 26.04 LTS
(`resolute`) root filesystem. It installs the kernel, systemd, QEMU guest
support, networking tools, the complete Smithproxy/Spider/Sift build toolchain
and Saslik itself under `/opt/saslik`. It deliberately does not enable a remote
Saslik controller yet: authentication, restricted privileges and appliance
networking are one subsequent provisioning stage.

```bash
sudo apt install debootstrap
make appliance-rootfs
# inspect build/appliance/rootfs before it is packed into a disk

# Create the canonical 16 GiB sparse disk (GPT, BIOS + UEFI):
make appliance-raw

# Before the controller is enabled, test the OS boot marker:
SASLIK_QEMU_EXPECT=boot make test-appliance \
  APPLIANCE_IMAGE=dist/saslik-amd64.raw
```

The image uses one virtual NIC with DHCP for its ordinary address and default
route, while retaining `198.18.18.1/24` as the stable routed appliance address.
The network configuration never replaces the DHCP lease or its gateway.

The OS provisioning recipe is intentionally a separate build stage. Until it
is added, normalize any bootable image produced by the provisioner into the
canonical raw artifact and export it:

```bash
make appliance-raw APPLIANCE_RAW_SOURCE=build/provisioned.img
make appliance-formats

# Individual exports are also available:
make appliance-qcow2
make appliance-vdi
make appliance-vmdk
make appliance-ova
```

`qemu-img convert` detects the source format, while all exports explicitly use
raw input. Replacing the raw file is therefore the only operation that changes
the appliance contents.

## QEMU appliance smoke test

The appliance test detects a raw or QCOW2 base image and always boots a
disposable QCOW2 overlay. The base image is never modified. QEMU user
networking gives the only guest a deterministic
`10.77.0.2` lease and exposes stable host endpoints without creating TAP
interfaces or changing host routes:

```bash
make test-appliance APPLIANCE_IMAGE=dist/saslik-amd64.qcow2
# or test the canonical intermediate directly:
make test-appliance APPLIANCE_IMAGE=dist/saslik-amd64.raw
# guest UI: 10.77.0.2:8765
# host UI:  http://127.0.0.1:18765/
# host SSH: 127.0.0.1:12222
```

The test waits for `/api/status`, verifies that it is a Saslik response and
then terminates QEMU. On failure, the serial console remains in
`artifacts/qemu-smoke/serial.log`. Override resources and ports with
`SASLIK_QEMU_MEMORY`, `SASLIK_QEMU_CPUS`, `SASLIK_QEMU_WEB_PORT` and
`SASLIK_QEMU_SSH_PORT`.
