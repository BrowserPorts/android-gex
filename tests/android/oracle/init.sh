#!/bin/sh
# Run the image's own init under gexc, from where its first stage would
# hand over, and show what it logs.
#
#   init.sh ROOT [init's arguments...]
#
# ROOT is root.sh's. tests/android/bin/firststage (build.sh) makes the
# mounts and device nodes first-stage init makes and then runs
# /system/bin/init with the arguments given (default: selinux_setup,
# which loads the image's policy and runs the second stage). gexc mounts
# selinuxfs and gives a boot configuration that says not to enforce.
# The image's fstab, which describes the emulator's disks, is covered by
# fstab.gex, which describes what is here: no partitions to map, and a
# tmpfs for /data.
# init.gex.rc, at the /init.ranchu.rc init.rc imports and the image has
# not, copies Android's log into the kernel log, which gexc prints.
# GEXC is the gexc to use, built with the big64 feature as for
# compare.sh; TIMEOUT is how long to let init run (default 150 seconds:
# an init that boots does not end). GEX_TIME_SCALE, when set, slows the
# guest's time that many times: the image's programs give one another
# seconds (apexd gives ueventd twenty for its device nodes), which
# translated they do not keep to.
#
# What init writes to the kernel's log is printed, and after it anything
# else gexc said. This is a look at how far init gets, not a test with an
# answer: the last lines say what it wanted and did not find.
set -u
ROOT=$(CDPATH='' cd -- "$1" && pwd)
shift
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../../target/big64/release/gexc}
# Each program reads the same random bytes in every run, so that bionic's
# linker puts its libraries where it did last time and gexc finds their
# translations made (GEX_FIXED_RANDOM); and those outlive a rebuild of
# gexc that left the translator alone (cache-id.sh).
export GEX_FIXED_RANDOM="${GEX_FIXED_RANDOM:-1}"
# Room for what an image's programs come to: the cache keeps 4 GiB unless
# told, and a boot's translations and a comparison's push one another out.
# 12 GiB holds both.
export GEX_CACHE_MAX_BYTES="${GEX_CACHE_MAX_BYTES:-12884901888}"
if [ -z "${GEX_CACHE_BUILD:-}" ] && name=$(sh "$HERE/cache-id.sh" "$GEXC" 2>/dev/null); then
    export GEX_CACHE_BUILD="$name"
fi
# gexc runs as root, as the native side does: the root keeps the image's
# owners (root.sh), and a gexc that is the host's root says them.
gexc() {
    sudo env GEX_FIXED_RANDOM="$GEX_FIXED_RANDOM" GEX_CACHE_MAX_BYTES="$GEX_CACHE_MAX_BYTES" \
        ${GEX_CACHE_BUILD:+GEX_CACHE_BUILD="$GEX_CACHE_BUILD"} ${GEX_TIME_SCALE:+GEX_TIME_SCALE="$GEX_TIME_SCALE"} "$@"
}
FIRST=$HERE/../bin/firststage
[ -x "$FIRST" ] || { echo "init.sh: no $FIRST (tests/android/build.sh)" >&2; exit 1; }
CONFIG=$(mktemp)
ERR=$(mktemp)
# Android's log (init.gex.rc's logcat), kept: LOGDIR, or a new directory.
LOGDIR=${LOGDIR:-$(mktemp -d)}
echo "init.sh: Android's log goes to $LOGDIR/logcat.txt" >&2
printf 'androidboot.selinux = "permissive"\nandroidboot.hardware = "ranchu"\n' >"$CONFIG"
# The console's standard input stays open, as a device's console does:
# init runs a shell on it (its `console` service) and starts it again
# whenever it ends, and at end of file it ends at once, over and over.
(cd "$ROOT" && sleep 1000000 | gexc timeout "${TIMEOUT:-150}" "$GEXC" run --argv0 /firststage --uid 0 --mem64 --selinuxfs --bootconfig "$CONFIG" \
    --bind "$FIRST=/firststage" --bind "$HERE/fstab.gex=/vendor/etc/fstab.ranchu" --bind "$HERE/init.gex.rc=/init.ranchu.rc" --bind "$LOGDIR=/gexlog" --sysroot "$ROOT" "$FIRST" "$@" 2>"$ERR")
echo "init.sh: gexc exited $? (124: still running at the time limit)"
grep -a '^\[kmsg\]' "$ERR" | sed 's/^\[kmsg\] //'
echo "init.sh: and gexc said:"
grep -av '^\[kmsg\]\|loaded /\|address space\|pid [0-9]*: exec' "$ERR" | sort | uniq -c | sort -rn | head -20
rm -f "$CONFIG" "$ERR"
