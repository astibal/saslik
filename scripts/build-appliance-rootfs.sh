#!/usr/bin/env bash
set -Eeuo pipefail

suite=resolute
mirror=http://archive.ubuntu.com/ubuntu
source_dir=
output=
cache=

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
        --cache) cache=${2:?}; shift 2 ;;
        *) fail "neznámý argument: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || fail 'builder musí běžet jako root (použij make appliance-rootfs)'
command -v debootstrap >/dev/null || fail 'chybí debootstrap (sudo apt install debootstrap)'
command -v git >/dev/null || fail 'chybí git'
command -v flock >/dev/null || fail 'chybí flock'
command -v sha256sum >/dev/null || fail 'chybí sha256sum'
[[ -n $source_dir && -d $source_dir ]] || fail 'chybí platný --source'
[[ -f $source_dir/pyproject.toml ]] || fail '--source není checkout Sasliku'
[[ -n $output ]] || fail 'chybí --output'
[[ ! -e $output ]] || fail "výstup už existuje: $output (nejdřív jej vědomě odstraň)"

source_dir=$(realpath "$source_dir")
output=$(realpath -m "$output")
cache=$(realpath -m "${cache:-$source_dir/build/cache/appliance}")
output_parent=$(dirname "$output")
mkdir -p "$output_parent"
mkdir -p "$cache" "$cache/staging" "$cache/bootstrap" "$cache/apt/archives"
cache_uid=${SUDO_UID:-0}
cache_gid=${SUDO_GID:-0}
PYTHONPATH="$source_dir/src" python3 -m saslik.build_cache prune --cache "$cache"
exec 8>"$cache/.lock"
flock 8
staging=$(mktemp -d --tmpdir="$cache/staging" rootfs.XXXXXX)
PYTHONPATH="$source_dir/src" python3 -m saslik.build_cache touch \
    --cache "$staging" --kind staging
apt_bound=0

cleanup() {
    if (( apt_bound )) && mountpoint -q "$staging/var/cache/apt/archives"; then
        umount "$staging/var/cache/apt/archives"
    fi
    rm -rf -- "$staging"
    chown -R "$cache_uid:$cache_gid" "$cache"
}
trap cleanup EXIT INT TERM

cache_key=$(printf '%s\n' "suite=$suite" "mirror=$mirror" \
    'arch=amd64' 'variant=minbase' 'components=main,universe' | sha256sum | cut -c1-24)
bootstrap="$cache/bootstrap/$cache_key"
if [[ -s $bootstrap/rootfs.tar && -s $bootstrap/.cache-entry.json ]]; then
    printf 'Používám cached Ubuntu bootstrap %s\n' "$cache_key"
    tar --numeric-owner -C "$staging" -xf "$bootstrap/rootfs.tar"
else
    printf 'Bootstrapuji Ubuntu %s z %s\n' "$suite" "$mirror"
    debootstrap --arch=amd64 --variant=minbase \
        --components=main,universe "$suite" "$staging" "$mirror"
    bootstrap_tmp="$cache/bootstrap/.${cache_key}.tmp.$$"
    rm -rf -- "$bootstrap_tmp"
    mkdir -p "$bootstrap_tmp"
    tar --numeric-owner -C "$staging" -cf "$bootstrap_tmp/rootfs.tar" .
    PYTHONPATH="$source_dir/src" python3 -m saslik.build_cache touch \
        --cache "$bootstrap_tmp" --kind bootstrap
    rm -rf -- "$bootstrap"
    mv -- "$bootstrap_tmp" "$bootstrap"
fi
PYTHONPATH="$source_dir/src" python3 -m saslik.build_cache touch \
    --cache "$bootstrap" --kind bootstrap

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
mount --bind "$cache/apt/archives" "$staging/var/cache/apt/archives"
apt_bound=1
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
# APT may reuse old files without changing mtime. Mark this bounded cache as
# recently useful; the size policy still evicts its oldest packages first.
find "$cache/apt/archives" -maxdepth 1 -type f -name '*.deb' -exec touch {} +

install -d -m 0755 "$staging/opt/saslik/source"
tar -C "$source_dir" \
    --exclude=.git --exclude=.venv --exclude=build --exclude=dist \
    --exclude=artifacts --exclude='*.pyc' -cf - . | \
    tar -C "$staging/opt/saslik/source" -xf -
chroot "$staging" python3 -m venv /opt/saslik/venv
chroot "$staging" /opt/saslik/venv/bin/pip install --no-cache-dir /opt/saslik/source

# Provision the portal, not a pre-initialized workspace: credentials, TLS keys
# and workspace CAs must be generated separately in every deployed VM.
install -m 0644 "$source_dir/scripts/appliance/saslik.service" \
    "$staging/etc/systemd/system/saslik.service"
install -m 0644 "$source_dir/scripts/appliance/saslik-takeaway-firstboot.service" \
    "$staging/etc/systemd/system/saslik-takeaway-firstboot.service"
chroot "$staging" systemctl enable saslik.service
chroot "$staging" systemctl enable saslik-takeaway-firstboot.service
install -d -m 0700 "$staging/var/lib/saslik"
# Helpers launched by sudo/systemd do not inherit the portal environment.
# Keep their default paths pointing to the same persistent data/config root.
install -d -m 0700 "$staging/var/lib/saslik/config" \
    "$staging/root/.config" "$staging/root/.local/share"
ln -s /var/lib/saslik "$staging/root/.local/share/saslik"
ln -s /var/lib/saslik/config "$staging/root/.config/saslik"

# Do not distribute a shared machine identity or SSH host private keys.
truncate -s 0 "$staging/etc/machine-id"
rm -f -- "$staging/var/lib/dbus/machine-id"
ln -s /etc/machine-id "$staging/var/lib/dbus/machine-id"
rm -f -- "$staging"/etc/ssh/ssh_host_*_key "$staging"/etc/ssh/ssh_host_*_key.pub
# SSH is opt-in: no default password or private login key is shipped.
chroot "$staging" systemctl disable ssh.service ssh.socket

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
umount "$staging/var/cache/apt/archives"
apt_bound=0
rm -rf -- "$staging/var/cache/apt/archives/"*
rm -rf -- "$staging/var/lib/apt/lists/"*
rm -f -- "$staging/etc/resolv.conf"
ln -s ../run/systemd/resolve/stub-resolv.conf "$staging/etc/resolv.conf"

# mktemp deliberately creates a private staging directory. The completed
# rootfs must be traversable by Make and unprivileged export/inspection tools.
chmod 0755 "$staging"
mv -- "$staging" "$output"
trap - EXIT INT TERM
chown -R "$cache_uid:$cache_gid" "$cache"
flock -u 8
PYTHONPATH="$source_dir/src" python3 -m saslik.build_cache prune --cache "$cache"
printf 'Rootfs je připravený: %s\n' "$output"
