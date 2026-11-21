#!/bin/sh
# Make the test inputs that are built from sources in this tree and not kept
# in it:
#
#   tests/fixtures.sh OUT
#
# OUT gets
#   test.30, test.33   crates/gex-kernel/src/selinux/testdata/test.conf,
#                      compiled by checkpolicy -M at policy versions 30 and 33
#   labels.33          labels.conf, at 33
#   other.33           other.conf, at 33
#   apex.img           tests/android/oracle/ext4-fixture.sh's ext4 image, as
#                      Android's apexer makes an APEX's payload
#
# Then GEX_TEST_FIXTURES=OUT is what `cargo test -p gex-kernel` and
# tests/android/build.sh read them from; without it, the tests that need them
# say so and pass, and the Android programs that carry them are not built.
#
# Needs a Linux host with checkpolicy and e2fsprogs, and root through sudo
# for the image (it sets owners, labels and device nodes, and mounts the
# image to record what Linux sees in it, which must be the tree's apex.txt).
set -eu
OUT=${1:?usage: tests/fixtures.sh OUT}
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
POLICIES=$HERE/../crates/gex-kernel/src/selinux/testdata
EXT4=$HERE/../crates/gex-kernel/src/vfs/testdata/ext4
mkdir -p "$OUT"
OUT=$(CDPATH='' cd -- "$OUT" && pwd)
command -v checkpolicy >/dev/null || { echo "tests/fixtures.sh: needs checkpolicy" >&2; exit 1; }

checkpolicy -M -c 30 -o "$OUT/test.30" "$POLICIES/test.conf" >/dev/null
checkpolicy -M -c 33 -o "$OUT/test.33" "$POLICIES/test.conf" >/dev/null
checkpolicy -M -c 33 -o "$OUT/labels.33" "$POLICIES/labels.conf" >/dev/null
checkpolicy -M -c 33 -o "$OUT/other.33" "$POLICIES/other.conf" >/dev/null

WORK=$(mktemp -d)
trap 'sudo rm -rf "$WORK"' EXIT
sudo sh "$HERE/android/oracle/ext4-fixture.sh" "$WORK"
cp "$WORK/apex.img" "$OUT/apex.img"
# The kernel's ext4 tests hold the image to what Linux showed in the one the
# tree's listing was taken from; a kernel that shows this one otherwise
# makes those tests fail, so say so here.
if ! cmp -s "$WORK/apex.txt" "$EXT4/apex.txt"; then
    echo "tests/fixtures.sh: this kernel lists apex.img unlike $EXT4/apex.txt:" >&2
    diff "$EXT4/apex.txt" "$WORK/apex.txt" >&2 || true
    exit 1
fi
ls "$OUT"
