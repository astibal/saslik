#!/usr/bin/env bash
set -Eeuo pipefail

# Boot a Saslik appliance without touching host networking or the base image.
# The single DHCP lease makes the guest address deterministic. Host-side
# checks use fixed forwards because slirp does not expose its subnet as a route.

image=${1:-dist/saslik-amd64.qcow2}
guest_ip=${SASLIK_QEMU_GUEST_IP:-10.77.0.2}
host_web_port=${SASLIK_QEMU_WEB_PORT:-18765}
host_ssh_port=${SASLIK_QEMU_SSH_PORT:-12222}
timeout_seconds=${SASLIK_QEMU_TIMEOUT:-180}
memory=${SASLIK_QEMU_MEMORY:-4096}
cpus=${SASLIK_QEMU_CPUS:-4}
artifacts=${SASLIK_QEMU_ARTIFACTS:-artifacts/qemu-smoke}
expect=${SASLIK_QEMU_EXPECT:-api}

fail() {
    printf 'saslik-qemu-test: %s\n' "$*" >&2
    exit 1
}

command -v qemu-system-x86_64 >/dev/null || fail 'chybí qemu-system-x86_64'
command -v qemu-img >/dev/null || fail 'chybí qemu-img'
command -v curl >/dev/null || fail 'chybí curl'
[[ -f $image ]] || fail "image neexistuje: $image"
[[ $guest_ip == 10.77.0.2 ]] || fail 'slirp test zatím podporuje guest IP 10.77.0.2'

mkdir -p "$artifacts"
workdir=$(mktemp -d --tmpdir saslik-qemu.XXXXXX)
overlay=$workdir/overlay.qcow2
serial_log=$artifacts/serial.log
qemu_log=$artifacts/qemu.log
pidfile=$workdir/qemu.pid

cleanup() {
    if [[ -s $pidfile ]]; then
        pid=$(<"$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            for _ in {1..50}; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    rm -rf -- "$workdir"
}
trap cleanup EXIT INT TERM

base_image=$(realpath "$image")
base_format=$(qemu-img info --output=json "$base_image" | python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])')
qemu-img create -q -f qcow2 -F "$base_format" -b "$base_image" "$overlay"
: >"$serial_log"
: >"$qemu_log"

accel=tcg
cpu_model=max
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    accel=kvm
    cpu_model=host
fi

printf 'Bootuji %s\n' "$base_image"
printf 'Guest: %s   UI: http://127.0.0.1:%s/   SSH: 127.0.0.1:%s\n' \
    "$guest_ip" "$host_web_port" "$host_ssh_port"

qemu-system-x86_64 \
    -name saslik-smoke \
    -machine "q35,accel=$accel" \
    -cpu "$cpu_model" \
    -smp "$cpus" \
    -m "$memory" \
    -nodefaults \
    -no-reboot \
    -display none \
    -serial "file:$serial_log" \
    -monitor none \
    -pidfile "$pidfile" \
    -daemonize \
    -drive "if=virtio,format=qcow2,file=$overlay,cache=unsafe" \
    -device virtio-rng-pci \
    -netdev "user,id=net0,net=10.77.0.0/24,host=10.77.0.1,dhcpstart=$guest_ip,hostname=saslik,hostfwd=tcp:127.0.0.1:$host_web_port-:8765,hostfwd=tcp:127.0.0.1:$host_ssh_port-:22" \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:53:41:53 \
    >"$qemu_log" 2>&1

deadline=$((SECONDS + timeout_seconds))
status_url="http://127.0.0.1:$host_web_port/api/status"
while (( SECONDS < deadline )); do
    if [[ $expect == boot ]] && grep -q 'SASLIK_APPLIANCE_READY' "$serial_log"; then
        printf 'OK: Ubuntu appliance dokončila boot (guest %s)\n' "$guest_ip"
        exit 0
    fi
    if [[ $expect == api ]] && \
       response=$(curl --silent --show-error --fail --max-time 2 "$status_url" 2>/dev/null) && \
       printf '%s' "$response" | grep -q '"instance"'; then
        printf 'OK: Saslik odpovídá na %s (guest %s)\n' "$status_url" "$guest_ip"
        exit 0
    fi
    if [[ -s $pidfile ]] && ! kill -0 "$(<"$pidfile")" 2>/dev/null; then
        printf '%s\n' 'QEMU skončilo před dokončením testu.' >&2
        tail -n 120 "$serial_log" >&2 || true
        exit 1
    fi
    sleep 1
done

printf 'Timeout po %ss; poslední výstup sériové konzole:\n' "$timeout_seconds" >&2
tail -n 120 "$serial_log" >&2 || true
exit 1
