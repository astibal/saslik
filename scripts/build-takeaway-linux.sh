#!/bin/bash
set -euo pipefail

fail() { printf 'saslik-takeaway-build: %s\n' "$*" >&2; exit 1; }
usage() {
    printf 'Usage: %s --rootfs DIR --source-data DIR --source DIR --output FILE [--work-root DIR] [--workspace NAME]...\n' "$0"
}

rootfs= source_data= source_dir= output= work_root= name=saslik-takeaway-linux-amd64
workspaces=()
while (($#)); do
    case $1 in
        --rootfs) rootfs=$2; shift 2 ;;
        --source-data) source_data=$2; shift 2 ;;
        --source) source_dir=$2; shift 2 ;;
        --output) output=$2; shift 2 ;;
        --work-root) work_root=$2; shift 2 ;;
        --name) name=$2; shift 2 ;;
        --workspace) workspaces+=("$2"); shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; fail "neznámý argument: $1" ;;
    esac
done
[[ $EUID -eq 0 ]] || fail 'builder musí běžet jako root'
[[ -d $rootfs && -f $rootfs/usr/share/saslik/build-info ]] || fail 'neplatný appliance rootfs'
[[ -d $source_data ]] || fail 'source-data neexistuje'
[[ -d $source_dir/src/saslik ]] || fail 'neplatný Saslik source'
[[ -n $output ]] || fail 'chybí --output'
for command in mksquashfs rsync tar gzip sha256sum python3; do
    command -v "$command" >/dev/null 2>&1 || fail "chybí příkaz: $command"
done

output=$(realpath -m "$output")
work_root=${work_root:-${TMPDIR:-/tmp}}
install -d -m 0700 "$work_root"
work_root=$(realpath "$work_root")
work_dir=$(mktemp -d --tmpdir="$work_root" saslik-takeaway.XXXXXX)
trap 'rm -rf -- "$work_dir"' EXIT
bundle="$work_dir/$name"
seed="$work_dir/seed"
metadata="$work_dir/takeaway"
install -d -m 0755 "$bundle"
install -d -m 0700 "$seed" "$metadata"

printf 'Kopíruji workspace state pro Takeaway seal…\n'
printf 'Vylučuji captures, logy a ostatní runtime data…\n'
# Never stage bulky runtime data which seal() would immediately discard.  In
# particular smithproxy-data and PCAP Viewer captures are often tens or
# hundreds of GiB.  Keep the filter anchored to known workspace state paths so
# similarly named source/configuration directories are not lost.
common_excludes=(
    --exclude='/lab/state/smithproxy-data/***' \
    --exclude='/lab/state/gretom/***' \
    --exclude='/lab/state/pcap-viewer/***' \
    --exclude='/lab/state/crashes/***' \
    --exclude='/instances/*/state/smithproxy-data/***' \
    --exclude='/instances/*/state/gretom/***' \
    --exclude='/instances/*/state/pcap-viewer/***' \
    --exclude='/instances/*/state/crashes/***' \
    --exclude='*.pcap' --exclude='*.pcapng' --exclude='*.har' \
    --exclude='*.log' --exclude='*.log.gz'
)
if ((${#workspaces[@]})); then
    rsync -aH --numeric-ids --safe-links "${common_excludes[@]}" \
        --exclude='/lab/***' --exclude='/instances/***' "$source_data/" "$seed/"
    for workspace in "${workspaces[@]}"; do
        [[ $workspace =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$ ]] || fail "neplatný workspace: $workspace"
        if [[ $workspace == default && -d $source_data/lab ]]; then
            install -d -m 0700 "$seed/lab"
            rsync -aH --numeric-ids --safe-links "${common_excludes[@]}" \
                "$source_data/lab/" "$seed/lab/"
        elif [[ -d $source_data/instances/$workspace ]]; then
            install -d -m 0700 "$seed/instances/$workspace"
            rsync -aH --numeric-ids --safe-links "${common_excludes[@]}" \
                "$source_data/instances/$workspace/" "$seed/instances/$workspace/"
        else
            fail "workspace neexistuje: $workspace"
        fi
    done
else
    rsync -aH --numeric-ids --safe-links "${common_excludes[@]}" \
        "$source_data/" "$seed/"
fi
printf 'Pečetím konfiguraci a odstraňuji původní identitu…\n'
PYTHONPATH="$source_dir/src" python3 -m saslik.takeaway seal \
    --data-root "$seed" --source-data-root "$source_data" \
    --target-data-root /var/lib/saslik

printf 'Připravuji immutable runtime…\n'
tar --numeric-owner --owner=0 --group=0 -C "$seed" -cf "$metadata/seed.tar" .
install -m 0755 "$source_dir/scripts/takeaway/saslik" "$bundle/saslik-tkw"
source_revision=$(git -C "$source_dir" rev-parse HEAD 2>/dev/null || printf unknown)
source_dirty=false
[[ -z $(git -C "$source_dir" status --porcelain 2>/dev/null) ]] || source_dirty=true
source_diff_sha256=$(
    { git -C "$source_dir" diff --binary HEAD 2>/dev/null || true
      git -C "$source_dir" ls-files --others --exclude-standard 2>/dev/null | sort || true; } |
        sha256sum | awk '{print $1}'
)
cat >"$metadata/manifest.json" <<EOF
{
  "format": 1,
  "kind": "saslik-takeaway-linux",
  "architecture": "$(dpkg --print-architecture 2>/dev/null || uname -m)",
  "created_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_revision": "$source_revision",
  "source_dirty": $source_dirty,
  "source_diff_sha256": "$source_diff_sha256"
}
EOF
printf 'Peču immutable Ubuntu runtime a seed do SquashFS…\n'
mksquashfs "$rootfs" "$metadata" "$bundle/saslik-takeaway.sqfs" \
    -keep-as-directory -noappend -comp zstd -processors 2 -quiet
printf 'Balím download bundle…\n'
printf 'Zapisuji manifest a kontrolní součty…\n'
(cd "$bundle" && sha256sum saslik-takeaway.sqfs saslik-tkw >SHA256SUMS)
cat >"$bundle/README.txt" <<EOF
Saslik Takeaway

  sudo ./saslik-tkw start
  sudo ./saslik-tkw status
  sudo ./saslik-tkw stop

Writable state is stored in ./data beside this read-only image.
EOF
install -d -m 0755 "$(dirname "$output")"
printf 'Publikuji download artefakt…\n'
tar --numeric-owner --owner=0 --group=0 -C "$work_dir" -czf "$output" "$name"
chmod 0644 "$output"
printf 'Linux Takeaway bundle: %s\n' "$output"
