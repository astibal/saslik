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

Local clients use stable loopback endpoints. In particular, configure the
same-host HTTP proxy as `http://127.0.0.1:33128`; Saslik forwards it into the
namespace without relying on PREROUTING/DNAT hairpin behaviour.

## Requirements

Linux with systemd, Python 3.11+ including `venv`, `sudo`, Git, CMake, a C++
compiler, Wireshark CLI tools (`sharkd`, `tshark`, `editcap`) and the dependencies
required by Smithproxy, Spider and Sift. Saslik uses network namespaces,
nftables and transient systemd services and therefore needs root. Saslik itself stays
unprivileged. At startup it explains why privileges are needed, acquires one
interactive sudo ticket and invokes its runner actions through `sudo -n`.

Runtime data defaults to `~/.local/share/saslik/lab`. Override it with
`SASLIK_DATA_DIR`. The Spider repository defaults to
`https://github.com/astibal/smithproxy-spider.git`; override it with
`SASLIK_SPIDER_REPOSITORY`.

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
implicitly. Use `--browser` to open a normal browser explicitly. The HTTP
listener binds to loopback only.

For an appliance or an explicitly trusted lab network, bind the UI remotely:

```bash
saslik -i lab1 web --host 0.0.0.0 --no-browser
```

In remote mode the HTTP CONNECT, API and CLI forwarders also listen on all IPv4
addresses. Endpoint cards use the hostname through which each browser opened
the UI, so the same page shows loopback links locally and routable links to a
remote client. This mode has no UI authentication yet; protect it with a host
firewall and use it only on a trusted network.

## QEMU appliance smoke test

The appliance test always boots a disposable QCOW2 overlay. The base image is
never modified. QEMU user networking gives the only guest a deterministic
`10.77.0.2` lease and exposes stable host endpoints without creating TAP
interfaces or changing host routes:

```bash
make test-appliance APPLIANCE_IMAGE=dist/saslik-amd64.qcow2
# guest UI: 10.77.0.2:8765
# host UI:  http://127.0.0.1:18765/
# host SSH: 127.0.0.1:12222
```

The test waits for `/api/status`, verifies that it is a Saslik response and
then terminates QEMU. On failure, the serial console remains in
`artifacts/qemu-smoke/serial.log`. Override resources and ports with
`SASLIK_QEMU_MEMORY`, `SASLIK_QEMU_CPUS`, `SASLIK_QEMU_WEB_PORT` and
`SASLIK_QEMU_SSH_PORT`.
