#!/bin/sh
# Start the image's servicemanager with the image's own policy loaded, and
# call it (tests/android/src/smcall.c): under gexc, or on this kernel.
#
#   servicemanager.sh ROOT
#
# ROOT is root.sh's. GEXC is the gexc to use, built with the big64 feature
# as for compare.sh; under it selinuxfs is mounted by gexc and the policy
# loaded by the image's load_policy.
#
# GEXC=native runs both in a chroot of ROOT on this kernel instead, the
# reference: it needs an arm64 Linux booted with SELinux on and not
# enforcing, the binder devices in /dev/binderfs with /dev/binder linked
# to one, and root through sudo. It loads the image's policy into the
# running kernel, so it wants a machine kept for that. Both ways print
# the same lines.
#
# The image's `service` and `dumpsys` are not used: libbinder waits for
# the property servicemanager.ready before its first call, which only
# init's property service can set.
set -u
ROOT=$(CDPATH='' cd -- "$1" && pwd)
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../../target/big64/release/gexc}
# As compare.sh: the same random bytes for each program in every run, so
# that gexc finds its translations made, and a name for the build.
export GEX_FIXED_RANDOM="${GEX_FIXED_RANDOM:-1}"
# Room for what an image's programs come to: the cache keeps 4 GiB unless
# told, and a boot's translations and a comparison's push one another out.
# 12 GiB holds both.
export GEX_CACHE_MAX_BYTES="${GEX_CACHE_MAX_BYTES:-12884901888}"
if [ "$GEXC" != native ] && [ -z "${GEX_CACHE_BUILD:-}" ] && name=$(sh "$HERE/cache-id.sh" "$GEXC" 2>/dev/null); then
    export GEX_CACHE_BUILD="$name"
fi
# gexc runs as root, as the native side does: the root keeps the image's
# owners (root.sh), and a gexc that is the host's root says them.
gexc() {
    sudo env GEX_FIXED_RANDOM="$GEX_FIXED_RANDOM" GEX_CACHE_MAX_BYTES="$GEX_CACHE_MAX_BYTES" \
        ${GEX_CACHE_BUILD:+GEX_CACHE_BUILD="$GEX_CACHE_BUILD"} ${GEX_TIME_SCALE:+GEX_TIME_SCALE="$GEX_TIME_SCALE"} "$@"
}
CLIENT=$HERE/../bin/smcall
[ -x "$CLIENT" ] || { echo "servicemanager.sh: no $CLIENT (tests/android/build.sh)" >&2; exit 1; }
ENVS="PATH=/system/bin HOME=/ ANDROID_ROOT=/system ANDROID_DATA=/data TMPDIR=/data/local/tmp"
ERR=$(mktemp)
# Until it is the context manager a call is a dead reply, which the client
# says: any other failure is a failure.
CALLS='
    n=0
    while /smcall 2>/dev/null | grep -q "no servicemanager"; do
        n=$((n + 1))
        [ $n -gt 60 ] && { echo "servicemanager.sh: servicemanager never answered"; exit 1; }
        sleep 1
    done
    /smcall'
if [ "$GEXC" = native ]; then
    POLICY=$ROOT/vendor/etc/selinux/precompiled_sepolicy
    # The policy in one write, which is all the kernel takes.
    sudo python3 -c "
import os, sys
data = open(sys.argv[1], 'rb').read()
fd = os.open('/sys/fs/selinux/load', os.O_WRONLY)
sys.exit(0 if os.write(fd, data) == len(data) else 1)" "$POLICY" || { echo "servicemanager.sh: cannot load $POLICY into this kernel (is SELinux on?)" >&2; exit 1; }
    mountpoint -q "$ROOT/proc" || sudo mount -t proc proc "$ROOT/proc"
    mountpoint -q "$ROOT/dev" || sudo mount --bind /dev "$ROOT/dev"
    mountpoint -q "$ROOT/dev/binderfs" || sudo mount --bind /dev/binderfs "$ROOT/dev/binderfs"
    sudo mkdir -p "$ROOT/sys/fs/selinux"
    mountpoint -q "$ROOT/sys/fs/selinux" || sudo mount -t selinuxfs selinuxfs "$ROOT/sys/fs/selinux"
    sudo cp "$CLIENT" "$ROOT/smcall"
    sudo env -i $ENVS /usr/sbin/chroot "$ROOT" /system/bin/servicemanager >/dev/null 2>>"$ERR" &
    out=$(sudo timeout "${TIMEOUT:-180}" env -i $ENVS /usr/sbin/chroot "$ROOT" /system/bin/sh -c "$CALLS" 2>>"$ERR")
    status=$?
    sudo pkill -x servicemanager
    sudo rm -f "$ROOT/smcall"
    sudo umount "$ROOT/sys/fs/selinux"
else
    args=""
    for e in $ENVS; do args="$args --env $e"; done
    out=$(cd "$ROOT" && gexc timeout "${TIMEOUT:-180}" "$GEXC" run --argv0 /system/bin/sh --uid 0 --mem64 --selinuxfs $args \
        --bind "$CLIENT=/smcall" --sysroot "$ROOT" "$ROOT/system/bin/sh" -c "
            load_policy /vendor/etc/selinux/precompiled_sepolicy || exit 1
            /system/bin/servicemanager &
            $CALLS
            status=\$?
            kill %1
            exit \$status" 2>"$ERR")
    status=$?
fi
printf '%s\n' "$out"
if [ "$status" -eq 0 ] && [ "$(printf '%s\n' "$out" | tail -1)" = "smcall ok" ]; then
    echo "PASS servicemanager"
else
    echo "FAIL servicemanager: exit $status; stderr in $ERR"
    grep -v 'loaded /\|address space' "$ERR" | tail -20
    exit 1
fi
rm -f "$ERR"
