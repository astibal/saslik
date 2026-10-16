#!/usr/bin/env bash
set -Eeuo pipefail

format=${1:-}
raw=${2:-dist/saslik-amd64.raw}
output=${3:-}

fail() {
    printf 'saslik-appliance-export: %s\n' "$*" >&2
    exit 1
}

command -v qemu-img >/dev/null || fail 'chybí qemu-img'
[[ -f $raw ]] || fail "RAW image neexistuje: $raw"
[[ -n $output ]] || fail 'chybí cesta výstupního souboru'
[[ $format == qcow2 || $format == vdi || $format == vmdk || $format == ova ]] || \
    fail "nepodporovaný formát: $format"

mkdir -p "$(dirname "$output")"
tmpdir=$(mktemp -d --tmpdir saslik-export.XXXXXX)
trap 'rm -rf -- "$tmpdir"' EXIT

case $format in
    qcow2)
        qemu-img convert -p -f raw -O qcow2 -o compat=1.1 -c "$raw" "$tmpdir/disk.qcow2"
        mv -f -- "$tmpdir/disk.qcow2" "$output"
        ;;
    vdi)
        qemu-img convert -p -f raw -O vdi "$raw" "$tmpdir/disk.vdi"
        mv -f -- "$tmpdir/disk.vdi" "$output"
        ;;
    vmdk)
        qemu-img convert -p -f raw -O vmdk -o subformat=streamOptimized "$raw" "$tmpdir/disk.vmdk"
        mv -f -- "$tmpdir/disk.vmdk" "$output"
        ;;
    ova)
        name=$(basename "$output" .ova)
        disk=${name}.vmdk
        ovf=${name}.ovf
        qemu-img convert -p -f raw -O vmdk -o subformat=streamOptimized "$raw" "$tmpdir/$disk"
        capacity=$(qemu-img info --output=json "$raw" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')
        disk_size=$(stat -c %s "$tmpdir/$disk")
        sed \
            -e "s/@NAME@/$name/g" \
            -e "s/@DISK@/$disk/g" \
            -e "s/@CAPACITY@/$capacity/g" \
            -e "s/@DISK_SIZE@/$disk_size/g" \
            "$(dirname "$0")/saslik-appliance.ovf.in" >"$tmpdir/$ovf"
        tar --format=ustar -C "$tmpdir" -cf "$tmpdir/appliance.ova" "$ovf" "$disk"
        mv -f -- "$tmpdir/appliance.ova" "$output"
        ;;
esac

printf '%s appliance: %s\n' "${format^^}" "$output"
