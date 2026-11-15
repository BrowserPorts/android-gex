#!/bin/sh
# Start the image's servicemanager under gexc, with selinuxfs mounted and
# the image's own policy loaded, and call it (tests/android/src/smcall.c).
#
#   servicemanager.sh ROOT
#
# ROOT is root.sh's. GEXC is the gexc to use, built with the big64 feature
# as for compare.sh. The image's `service` and `dumpsys` are not used:
# libbinder waits for the property servicemanager.ready before its first
# call, which only init's property service can set.
set -u
ROOT=$(CDPATH='' cd -- "$1" && pwd)
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../../target/big64/release/gexc}
CLIENT=$HERE/../bin/smcall
[ -x "$CLIENT" ] || { echo "servicemanager.sh: no $CLIENT (tests/android/build.sh)" >&2; exit 1; }
ENVS="PATH=/system/bin HOME=/ ANDROID_ROOT=/system ANDROID_DATA=/data TMPDIR=/data/local/tmp"
args=""
for e in $ENVS; do args="$args --env $e"; done
ERR=$(mktemp)
out=$(cd "$ROOT" && timeout "${TIMEOUT:-180}" "$GEXC" run --argv0 /system/bin/sh --uid 0 --mem64 --selinuxfs $args \
    --bind "$CLIENT=/smcall" --sysroot "$ROOT" "$ROOT/system/bin/sh" -c '
        load_policy /vendor/etc/selinux/precompiled_sepolicy || exit 1
        /system/bin/servicemanager &
        # Until it is the context manager a call is a dead reply, which
        # the client says: any other failure is a failure.
        n=0
        while /smcall 2>/dev/null | grep -q "no servicemanager"; do
            n=$((n + 1))
            [ $n -gt 60 ] && { echo "servicemanager.sh: servicemanager never answered"; exit 1; }
            sleep 1
        done
        /smcall
        status=$?
        kill %1
        exit $status' 2>"$ERR")
status=$?
printf '%s\n' "$out"
if [ "$status" -eq 0 ] && [ "$(printf '%s\n' "$out" | tail -1)" = "smcall ok" ]; then
    echo "PASS servicemanager"
else
    echo "FAIL servicemanager: exit $status; stderr in $ERR"
    grep -v 'loaded /\|address space' "$ERR" | tail -20
    exit 1
fi
rm -f "$ERR"
