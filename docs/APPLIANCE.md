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
