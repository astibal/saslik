#!/usr/bin/env bash
set -Eeuo pipefail

suite=resolute
mirror=http://archive.ubuntu.com/ubuntu
source_dir=
output=

fail() {
    printf 'saslik-rootfs: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case $1 in
        --suite) suite=${2:?}; shift 2 ;;
        --mirror) mirror=${2:?}; shift 2 ;;
        --source) source_dir=${2:?}; shift 2 ;;
        --output) output=${2:?}; shift 2 ;;
        *) fail "neznámý argument: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || fail 'builder musí běžet jako root (použij make appliance-rootfs)'
command -v debootstrap >/dev/null || fail 'chybí debootstrap (sudo apt install debootstrap)'
command -v git >/dev/null || fail 'chybí git'
[[ -n $source_dir && -d $source_dir ]] || fail 'chybí platný --source'
[[ -f $source_dir/pyproject.toml ]] || fail '--source není checkout Sasliku'
[[ -n $output ]] || fail 'chybí --output'
[[ ! -e $output ]] || fail "výstup už existuje: $output (nejdřív jej vědomě odstraň)"

source_dir=$(realpath "$source_dir")
output=$(realpath -m "$output")
output_parent=$(dirname "$output")
mkdir -p "$output_parent"
staging=$(mktemp -d --tmpdir="$output_parent" .rootfs.XXXXXX)

cleanup() {
    rm -rf -- "$staging"
}
trap cleanup EXIT INT TERM

printf 'Bootstrapuji Ubuntu %s z %s\n' "$suite" "$mirror"
debootstrap --arch=amd64 --variant=minbase \
    --components=main,universe "$suite" "$staging" "$mirror"

cat >"$staging/etc/apt/sources.list.d/ubuntu.sources" <<EOF
Types: deb
URIs: $mirror
Suites: $suite ${suite}-updates ${suite}-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
rm -f -- "$staging/etc/apt/sources.list"
cp -L /etc/resolv.conf "$staging/etc/resolv.conf"

cat >"$staging/usr/sbin/policy-rc.d" <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 0755 "$staging/usr/sbin/policy-rc.d"

export DEBIAN_FRONTEND=noninteractive
chroot "$staging" apt-get update
chroot "$staging" apt-get -y dist-upgrade
chroot "$staging" apt-get install -y --no-install-recommends \
    linux-image-generic systemd-sysv systemd-resolved udev dbus \
    grub-pc-bin grub-efi-amd64-bin efibootmgr \
    openssh-server sudo qemu-guest-agent netplan.io \
    ca-certificates curl wget git openssh-client \
    python3 python3-dev python3-venv python3-pip python3-cryptography \
    python3-pyroute2 python3-pyparsing \
    build-essential g++ cmake make pkg-config ninja-build \
    libconfig-dev libconfig++-dev libssl-dev libssh-4 libssh-dev \
    libunwind-dev libmicrohttpd-dev libcurl4-openssl-dev libpam0g-dev \
    libhyperscan-dev nlohmann-json3-dev \
    swig libffi-dev libxml2-dev libxslt1-dev xmlsec1 \
    iproute2 iptables nftables nginx passt telnet openssl libnss3-tools \
    tshark tcpdump jq less nano

install -d -m 0755 "$staging/opt/saslik/source"
tar -C "$source_dir" \
    --exclude=.git --exclude=.venv --exclude=build --exclude=dist \
    --exclude=artifacts --exclude='*.pyc' -cf - . | \
    tar -C "$staging/opt/saslik/source" -xf -
chroot "$staging" python3 -m venv /opt/saslik/venv
chroot "$staging" /opt/saslik/venv/bin/pip install --no-cache-dir /opt/saslik/source

cat >"$staging/etc/hostname" <<'EOF'
saslik
EOF
cat >"$staging/etc/hosts" <<'EOF'
127.0.0.1 localhost
127.0.1.1 saslik
::1 localhost ip6-localhost ip6-loopback
EOF

git_revision=$(git -C "$source_dir" rev-parse HEAD 2>/dev/null || printf unknown)
mkdir -p "$staging/usr/share/saslik"
{
    printf 'format=1\n'
    printf 'ubuntu_suite=%s\n' "$suite"
    printf 'architecture=amd64\n'
    printf 'saslik_revision=%s\n' "$git_revision"
    printf 'built_at=%s\n' "$(date --utc +%Y-%m-%dT%H:%M:%SZ)"
} >"$staging/usr/share/saslik/build-info"
chroot "$staging" dpkg-query -W -f='${binary:Package}\t${Version}\n' \
    >"$staging/usr/share/saslik/packages.tsv"

rm -f -- "$staging/usr/sbin/policy-rc.d"
chroot "$staging" apt-get clean
rm -rf -- "$staging/var/lib/apt/lists/"*
rm -f -- "$staging/etc/resolv.conf"
ln -s ../run/systemd/resolve/stub-resolv.conf "$staging/etc/resolv.conf"

mv -- "$staging" "$output"
trap - EXIT INT TERM
printf 'Rootfs je připravený: %s\n' "$output"
