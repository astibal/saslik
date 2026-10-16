#!/usr/bin/env bash
set -Eeuo pipefail

rootfs=
output=
disk_size=16G

fail() {
    printf 'saslik-disk: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case $1 in
        --rootfs) rootfs=${2:?}; shift 2 ;;
        --output) output=${2:?}; shift 2 ;;
        --size) disk_size=${2:?}; shift 2 ;;
        *) fail "neznámý argument: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || fail 'disk builder musí běžet jako root'
[[ -n $rootfs && -d $rootfs ]] || fail 'chybí platný --rootfs'
[[ -f $rootfs/usr/share/saslik/build-info ]] || fail 'rootfs nemá Saslik build-info'
[[ -n $output ]] || fail 'chybí --output'
[[ ! -e $output ]] || fail "výstup už existuje: $output"
for command in truncate parted losetup udevadm mkfs.ext4 mkfs.vfat blkid rsync mount umount chroot; do
    command -v "$command" >/dev/null || fail "chybí $command"
done

rootfs=$(realpath "$rootfs")
output=$(realpath -m "$output")
mkdir -p "$(dirname "$output")"
disk_tmp=${output}.tmp
mount_dir=$(mktemp -d --tmpdir saslik-disk.XXXXXX)
loop=

cleanup() {
    mountpoint -q "$mount_dir/dev/pts" && umount "$mount_dir/dev/pts" || true
    mountpoint -q "$mount_dir/dev" && umount "$mount_dir/dev" || true
    mountpoint -q "$mount_dir/proc" && umount "$mount_dir/proc" || true
    mountpoint -q "$mount_dir/sys" && umount "$mount_dir/sys" || true
    mountpoint -q "$mount_dir/run" && umount "$mount_dir/run" || true
    mountpoint -q "$mount_dir/boot/efi" && umount "$mount_dir/boot/efi" || true
    mountpoint -q "$mount_dir" && umount "$mount_dir" || true
    [[ -z $loop ]] || losetup -d "$loop" 2>/dev/null || true
    rm -f -- "$disk_tmp"
    rmdir "$mount_dir" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

truncate -s "$disk_size" "$disk_tmp"
parted -s "$disk_tmp" mklabel gpt
parted -s "$disk_tmp" mkpart bios 1MiB 3MiB
parted -s "$disk_tmp" set 1 bios_grub on
parted -s "$disk_tmp" mkpart ESP fat32 3MiB 515MiB
parted -s "$disk_tmp" set 2 esp on
parted -s "$disk_tmp" mkpart root ext4 515MiB 100%

loop=$(losetup --find --show --partscan "$disk_tmp")
udevadm settle
efi=${loop}p2
root=${loop}p3
[[ -b $efi && -b $root ]] || fail "kernel nevytvořil partition zařízení pro $loop"

mkfs.vfat -F 32 -n SASLIK_EFI "$efi"
mkfs.ext4 -F -L saslik-root "$root"
mount "$root" "$mount_dir"
mkdir -p "$mount_dir/boot/efi"
mount "$efi" "$mount_dir/boot/efi"
rsync -aHAX --numeric-ids "$rootfs/" "$mount_dir/"

root_uuid=$(blkid -s UUID -o value "$root")
efi_uuid=$(blkid -s UUID -o value "$efi")
cat >"$mount_dir/etc/fstab" <<EOF
UUID=$root_uuid / ext4 defaults,noatime 0 1
UUID=$efi_uuid /boot/efi vfat umask=0077 0 1
EOF

mkdir -p "$mount_dir/etc/netplan"
cat >"$mount_dir/etc/netplan/10-saslik.yaml" <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    appliance:
      match:
        name: "e*"
      dhcp4: true
      dhcp6: true
      addresses:
        - 198.18.18.1/24
EOF
chmod 0600 "$mount_dir/etc/netplan/10-saslik.yaml"

mkdir -p "$mount_dir/etc/systemd/system/multi-user.target.wants"
cat >"$mount_dir/etc/systemd/system/saslik-boot-ready.service" <<'EOF'
[Unit]
Description=Signal that the Saslik appliance completed boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo SASLIK_APPLIANCE_READY >/dev/ttyS0'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
ln -sf ../saslik-boot-ready.service \
    "$mount_dir/etc/systemd/system/multi-user.target.wants/saslik-boot-ready.service"
ln -sf /lib/systemd/system/systemd-networkd.service \
    "$mount_dir/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
ln -sf /lib/systemd/system/systemd-resolved.service \
    "$mount_dir/etc/systemd/system/multi-user.target.wants/systemd-resolved.service"

mount --bind /dev "$mount_dir/dev"
mount --bind /dev/pts "$mount_dir/dev/pts"
mount -t proc proc "$mount_dir/proc"
mount -t sysfs sys "$mount_dir/sys"
mount --bind /run "$mount_dir/run"
chroot "$mount_dir" grub-install --target=i386-pc --recheck "$loop"
chroot "$mount_dir" grub-install --target=x86_64-efi \
    --efi-directory=/boot/efi --bootloader-id=Saslik --removable --no-nvram
chroot "$mount_dir" update-grub

umount "$mount_dir/dev/pts"
umount "$mount_dir/dev"
umount "$mount_dir/proc"
umount "$mount_dir/sys"
umount "$mount_dir/run"
umount "$mount_dir/boot/efi"
umount "$mount_dir"
losetup -d "$loop"
loop=

mv -- "$disk_tmp" "$output"
trap - EXIT INT TERM
rmdir "$mount_dir"
printf 'Bootovací RAW appliance: %s\n' "$output"
