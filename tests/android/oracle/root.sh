#!/bin/sh
# Make a root directory out of an Android arm64 system image, for running
# its programs natively in a chroot and under gexc (compare.sh, art.sh).
#
#   root.sh IMAGE_DIR WORK_DIR
#
# IMAGE_DIR is an emulator system image as the SDK manager unpacks it (its
# system.img is used): "system-images;android-37.0;default;arm64-v8a" is
# the one this was written against. WORK_DIR gets the partitions and, in
# WORK_DIR/root, the tree: /system and the other partitions, every APEX's
# payload unpacked at /apex/<name> as apexd mounts it, the list apexd
# writes, and the linker configuration Android's own linkerconfig makes
# from them.
#
# Needs an arm64 Linux host (the last step runs linkerconfig from the
# image), root through sudo, python3, rsync and unzip. The tree ends up
# owned by the caller so that gexc can read it; what the image's owners
# were is in the partition images. It leaves /proc mounted and /dev bound
# in the root: unmount both before removing it.
set -eu
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
IMAGE=$1
WORK=$2
mkdir -p "$WORK"
WORK=$(CDPATH='' cd -- "$WORK" && pwd)
ROOT=$WORK/root

python3 "$HERE/unpack.py" "$IMAGE/system.img" "$WORK/parts"

sudo rm -rf "$ROOT"
mkdir -p "$ROOT" "$WORK/mnt"
copy() { # copy <partition image> <directory under the root>
    sudo mount -o loop,ro "$1" "$WORK/mnt"
    sudo mkdir -p "$2"
    sudo rsync -aHAX "$WORK/mnt/" "$2/"
    sudo umount "$WORK/mnt"
}
copy "$WORK/parts/system.img" "$ROOT"
for p in system_ext product vendor; do
    [ -f "$WORK/parts/$p.img" ] && copy "$WORK/parts/$p.img" "$ROOT/$p"
done
for apex in "$ROOT"/system/apex/*.apex "$ROOT"/system_ext/apex/*.apex "$ROOT"/product/apex/*.apex "$ROOT"/vendor/apex/*.apex; do
    [ -f "$apex" ] || continue
    rm -f "$WORK/apex_payload.img"
    sudo unzip -o -q "$apex" apex_payload.img -d "$WORK" || continue
    copy "$WORK/apex_payload.img" "$ROOT/apex/$(basename "$apex" .apex)"
done
sudo rm -f "$WORK/apex_payload.img"
sudo chown -R "$(id -u):$(id -g)" "$ROOT"
chmod -R u+rwX "$ROOT"

python3 "$HERE/apexinfo.py" "$ROOT"
# linkerconfig is the image's own program: it wants /proc and /dev as any
# Android program does. They stay mounted for the runs that follow.
mountpoint -q "$ROOT/proc" || sudo mount -t proc proc "$ROOT/proc"
mountpoint -q "$ROOT/dev" || sudo mount --bind /dev "$ROOT/dev"
sudo env -i PATH=/system/bin /usr/sbin/chroot "$ROOT" /apex/com.android.runtime/bin/linkerconfig --target /linkerconfig
sudo chown -R "$(id -u):$(id -g)" "$ROOT/linkerconfig"
mkdir -p "$ROOT/data/local/tmp"
echo "$ROOT"
