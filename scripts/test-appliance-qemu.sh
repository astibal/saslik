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
firmware=${SASLIK_QEMU_FIRMWARE:-bios}

fail() {
    printf 'saslik-qemu-test: %s\n' "$*" >&2
    exit 1
}

command -v qemu-system-x86_64 >/dev/null || fail 'chybí qemu-system-x86_64'
command -v qemu-img >/dev/null || fail 'chybí qemu-img'
command -v curl >/dev/null || fail 'chybí curl'
[[ -f $image ]] || fail "image neexistuje: $image"
[[ $guest_ip == 10.77.0.2 ]] || fail 'slirp test zatím podporuje guest IP 10.77.0.2'
[[ $expect == boot || $expect == api ]] || fail 'SASLIK_QEMU_EXPECT musí být boot nebo api'
[[ $firmware == bios || $firmware == uefi ]] || fail 'SASLIK_QEMU_FIRMWARE musí být bios nebo uefi'

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

firmware_args=()
if [[ $firmware == uefi ]]; then
    ovmf_code=${SASLIK_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
    ovmf_vars=${SASLIK_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
    [[ -r $ovmf_code && -r $ovmf_vars ]] || fail 'chybí OVMF firmware (nainstaluj ovmf)'
    # Firmware variables belong to this run, never to the host template.
    cp -- "$ovmf_vars" "$workdir/OVMF_VARS.fd"
    firmware_args=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code"
                   -drive "if=pflash,format=raw,unit=1,file=$workdir/OVMF_VARS.fd")
fi

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
printf 'Guest: %s   UI: https://127.0.0.1:%s/   SSH (if enabled): 127.0.0.1:%s\n' \
    "$guest_ip" "$host_web_port" "$host_ssh_port"

qemu-system-x86_64 \
    -name saslik-smoke \
    -machine "q35,accel=$accel" \
    "${firmware_args[@]}" \
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
portal_url="https://127.0.0.1:$host_web_port"
# A fresh VM has a unique self-signed certificate. Only this local smoke
# test bypasses trust validation; production clients must verify the cert.
curl_args=(--insecure --silent --show-error --max-time 3)
while (( SECONDS < deadline )); do
    if [[ $expect == boot ]] && grep -q 'SASLIK_APPLIANCE_READY' "$serial_log"; then
        printf 'OK: Ubuntu appliance dokončila boot (guest %s)\n' "$guest_ip"
        exit 0
    fi
    if [[ $expect == api ]] && \
       response=$(curl "${curl_args[@]}" --fail "$portal_url/login" 2>/dev/null) && \
       printf '%s' "$response" | grep -q 'action="/setup"'; then
        curl "${curl_args[@]}" --fail "$portal_url/api/connect" \
            >"$artifacts/connect.json"
        python3 -c 'import json,sys; assert isinstance(json.load(sys.stdin), dict)' \
            <"$artifacts/connect.json"
        status=$(curl "${curl_args[@]}" --output /dev/null --write-out '%{http_code}' \
            "$portal_url/api/status")
        [[ $status == 401 ]] || fail "privátní API bez session vrátilo $status místo 401"
        printf 'OK: HTTPS, first-access setup, public Connect and protected API (guest %s)\n' "$guest_ip"
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
