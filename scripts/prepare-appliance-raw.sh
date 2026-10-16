#!/usr/bin/env bash
set -Eeuo pipefail

source_image=${1:-}
output=${2:-dist/saslik-amd64.raw}

fail() {
    printf 'saslik-appliance: %s\n' "$*" >&2
    exit 1
}

command -v qemu-img >/dev/null || fail 'chybí qemu-img'
[[ -n $source_image ]] || fail \
    'chybí APPLIANCE_RAW_SOURCE; zadej bootovací obraz vytvořený OS builderem'
[[ -f $source_image ]] || fail "zdrojový obraz neexistuje: $source_image"

source_real=$(realpath "$source_image")
mkdir -p "$(dirname "$output")"
output_real=$(realpath -m "$output")
[[ $source_real != "$output_real" ]] || fail 'vstup a výstup nesmí být stejný soubor'

tmp=${output}.tmp
trap 'rm -f -- "$tmp"' EXIT
rm -f -- "$tmp"
qemu-img convert -p -O raw "$source_real" "$tmp"
converted_format=$(qemu-img info --output=json "$tmp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])')
[[ $converted_format == raw ]] || fail "interní chyba: výstup má formát $converted_format místo raw"
mv -f -- "$tmp" "$output"
trap - EXIT

printf 'RAW appliance: %s\n' "$output"
