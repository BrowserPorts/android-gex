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
# GEXC is the gexc to use, built with the big64 feature as for
# compare.sh; TIMEOUT is how long to let init run (default 150 seconds:
# an init that boots does not end).
#
# What init writes to the kernel's log is printed, and after it anything
# else gexc said. This is a look at how far init gets, not a test with an
# answer: the last lines say what it wanted and did not find.
set -u
ROOT=$(CDPATH='' cd -- "$1" && pwd)
shift
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../../target/big64/release/gexc}
FIRST=$HERE/../bin/firststage
[ -x "$FIRST" ] || { echo "init.sh: no $FIRST (tests/android/build.sh)" >&2; exit 1; }
CONFIG=$(mktemp)
ERR=$(mktemp)
printf 'androidboot.selinux = "permissive"\nandroidboot.hardware = "ranchu"\n' >"$CONFIG"
(cd "$ROOT" && timeout "${TIMEOUT:-150}" "$GEXC" run --argv0 /firststage --uid 0 --mem64 --selinuxfs --bootconfig "$CONFIG" \
    --bind "$FIRST=/firststage" --sysroot "$ROOT" "$FIRST" "$@" 2>"$ERR")
echo "init.sh: gexc exited $? (124: still running at the time limit)"
grep -a '^\[kmsg\]' "$ERR" | sed 's/^\[kmsg\] //'
echo "init.sh: and gexc said:"
grep -av '^\[kmsg\]\|loaded /\|address space\|pid [0-9]*: exec' "$ERR" | sort | uniq -c | sort -rn | head -20
rm -f "$CONFIG" "$ERR"
