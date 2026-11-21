#!/bin/sh
# Make the ext4 images the kernel crate's ext4 tests read, and what Linux's
# own ext4 says is in each.
#
#   sudo ext4-fixture.sh OUT
#
# Writes into OUT, for each image NAME: NAME.img, made by mke2fs from a
# tree built here, and NAME.txt, a line for every file in it as the
# kernel this runs on shows it mounted read-only:
#
#   path<TAB>type<TAB>mode<TAB>uid<TAB>gid<TAB>size<TAB>links<TAB>mtime<TAB>
#   target or device<TAB>checksum<TAB>attributes
#
# (the type as find's %y; the checksum FNV-1a, 64 bits, of a regular
# file's bytes; the attributes name=hex, separated by commas.)
#
# apex: as Android's apexer makes an APEX's payload (4096-byte blocks,
# 256-byte inodes, no journal, extents, no checksums), with what such a
# payload has and what it could have: files with holes, a hard link,
# short and long symbolic links, a directory of several blocks, labels,
# an attribute too big for its inode, and special files.
#
# Needs root (owners, labels, device nodes, mount) and e2fsprogs.
set -eu
OUT=$(CDPATH='' cd -- "$1" && pwd)
WORK=$(mktemp -d)
# (The image is unmounted by then unless something failed, so the trap's
# umount failing is no failure of the script's.)
trap 'umount "$WORK/mnt" 2>/dev/null || true; rm -rf "$WORK"' EXIT
T=$WORK/tree
mkdir -p "$T/bin" "$T/lib64" "$T/etc/long/nested/deeper" "$T/etc/empty" "$T/many" "$WORK/mnt"

printf 'name: "com.example.fixture"\nversion: 1\n' >"$T/apex_manifest.pb"
# Bytes that are not all alike: each line its own number.
seq 1 1500 >"$T/bin/tool"
seq 1 1500 | sed 's/$/ a line of a library/' >"$T/lib64/libfixture.so"
: >"$T/etc/empty-file"
echo deep >"$T/etc/long/nested/deeper/file"
# A file with holes: a block of data, a hole, data, a hole to its end.
printf 'start' >"$T/lib64/holes"
printf 'middle' | dd of="$T/lib64/holes" bs=4096 seek=5 conv=notrunc status=none
truncate -s 40000 "$T/lib64/holes"
ln "$T/bin/tool" "$T/bin/tool2"
ln -s tool "$T/bin/short"
ln -s /system/bin/sh "$T/etc/abs"
ln -s ../lib64/a-name-long-enough-that-the-link-does-not-fit-in-the-inode-and-takes-a-block-of-its-own/libfixture.so "$T/etc/long-link"
i=0
while [ $i -lt 150 ]; do
    : >"$T/many/an-entry-with-a-long-name-to-fill-the-block-$i"
    i=$((i + 1))
done
mknod "$T/etc/null" c 1 3
mknod "$T/etc/disk" b 7 0
mkfifo "$T/etc/pipe"
chown -R 0:0 "$T"
chown 0:2000 "$T/bin" "$T/bin/tool"
chown 1000:1000 "$T/etc/empty-file"
chmod 0755 "$T/bin/tool"
chmod 0644 "$T/lib64/libfixture.so" "$T/apex_manifest.pb"
chmod 0600 "$T/etc/empty-file"
chmod 0750 "$T/etc/long"
chmod 4755 "$T/lib64/holes"
find "$T" -exec touch -h -d '2026-01-02 03:04:05 UTC' {} +
touch -d '2001-09-09 01:46:40 UTC' "$T/apex_manifest.pb"
setfattr -n security.selinux -v 'u:object_r:system_file:s0' "$T" "$T/bin" "$T/lib64" "$T/lib64/libfixture.so" "$T/apex_manifest.pb"
setfattr -n security.selinux -v 'u:object_r:system_linker_exec:s0' "$T/bin/tool"
setfattr -n user.comment -v 'a comment' "$T/bin/tool"
setfattr -n user.big -v "$(seq 1 120 | tr '\n' ' ')" "$T/lib64/libfixture.so"
setfattr -n security.capability -v 0sAQAAAgAgAAAAAAAAAAAAAAAAAAA= "$T/lib64/holes"

# mke2fs stamps the root and lost+found with the time it runs; a fixed one
# (the first image's) makes the same image every time.
E2FSPROGS_FAKE_TIME=1794734585 SOURCE_DATE_EPOCH=1794734585 mke2fs -q -t ext4 -O ^has_journal,^metadata_csum,^64bit,^flex_bg,^resize_inode,uninit_bg -b 4096 -I 256 -m 0 -N 200 \
    -U 7d1522e1-9dfa-5edb-a43e-98e3a4d20250 -E hash_seed=7d1522e1-9dfa-5edb-a43e-98e3a4d20250,root_owner=0:0 -L fixture \
    -d "$T" "$OUT/apex.img" 96
e2fsck -fn "$OUT/apex.img" >/dev/null

mount -o loop,ro "$OUT/apex.img" "$WORK/mnt"
python3 - "$WORK/mnt" >"$OUT/apex.txt" <<'PY'
import os, stat, sys
root = sys.argv[1]
def fnv(data):
    h = 0xcbf29ce484222325
    for b in data:
        h = ((h ^ b) * 0x100000001b3) & 0xffffffffffffffff
    return h
kinds = {stat.S_IFREG: "f", stat.S_IFDIR: "d", stat.S_IFLNK: "l", stat.S_IFCHR: "c", stat.S_IFBLK: "b", stat.S_IFIFO: "p", stat.S_IFSOCK: "s"}
paths = []
for d, dirs, files in os.walk(root):
    paths.append(d)
    for n in dirs + files:
        p = os.path.join(d, n)
        if not (os.path.isdir(p) and not os.path.islink(p)):
            paths.append(p)
for p in sorted(set(paths)):
    st = os.lstat(p)
    kind = kinds[stat.S_IFMT(st.st_mode)]
    extra, check = "-", "-"
    if kind == "l":
        extra = os.readlink(p)
    elif kind in "cb":
        extra = "%d:%d" % (os.major(st.st_rdev), os.minor(st.st_rdev))
    elif kind == "f":
        check = "%016x" % fnv(open(p, "rb").read())
    attrs = ",".join("%s=%s" % (a, os.getxattr(p, a, follow_symlinks=False).hex()) for a in sorted(os.listxattr(p, follow_symlinks=False))) or "-"
    rel = os.path.relpath(p, root)
    print("\t".join([rel, kind, "%o" % stat.S_IMODE(st.st_mode), str(st.st_uid), str(st.st_gid), str(st.st_size), str(st.st_nlink), str(int(st.st_mtime)), extra, check, attrs]))
PY
umount "$WORK/mnt"
ls -l "$OUT/apex.img" "$OUT/apex.txt"
