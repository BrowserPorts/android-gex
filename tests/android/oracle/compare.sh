#!/bin/sh
# Run Android shell command lines both ways, natively in a chroot of the
# root and under gexc, and say which print or exit differently.
#
#   compare.sh ROOT [FILE]
#
# ROOT is root.sh's; FILE (default: standard input) has one command line a
# line, for the image's /system/bin/sh. Both runs are root with the same
# small environment. GEXC is the gexc to use: one built with the big64
# feature, since a stock Android process reserves more address space than
# the 16 GiB memory has. Lines gexc printed about calls it does not make
# are counted at the end.
#
# Needs an arm64 Linux host and root through sudo. The native side mounts
# /proc and binds /dev into the root.
set -u
ROOT=$(CDPATH='' cd -- "$1" && pwd)
FILE=${2:-/dev/stdin}
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../../target/big64/release/gexc}
# Each program reads the same random bytes in every run, so that bionic's
# linker puts its libraries where it did last time and gexc finds their
# translations made (GEX_FIXED_RANDOM); and those outlive a rebuild of
# gexc that left the translator alone (cache-id.sh).
export GEX_FIXED_RANDOM="${GEX_FIXED_RANDOM:-1}"
# Room for what an image's programs come to: the cache keeps 4 GiB unless
# told, and a boot's translations and a comparison's push one another out.
export GEX_CACHE_MAX_BYTES="${GEX_CACHE_MAX_BYTES:-34359738368}"
if [ -z "${GEX_CACHE_BUILD:-}" ] && name=$(sh "$HERE/cache-id.sh" "$GEXC" 2>/dev/null); then
    export GEX_CACHE_BUILD="$name"
fi
# gexc runs as root, as the native side does: the root keeps the image's
# owners (root.sh), and a gexc that is the host's root says them.
gexc() {
    sudo env GEX_FIXED_RANDOM="$GEX_FIXED_RANDOM" GEX_CACHE_MAX_BYTES="$GEX_CACHE_MAX_BYTES" \
        ${GEX_CACHE_BUILD:+GEX_CACHE_BUILD="$GEX_CACHE_BUILD"} ${GEX_TIME_SCALE:+GEX_TIME_SCALE="$GEX_TIME_SCALE"} "$@"
}
ENVS="PATH=/system/bin HOME=/ ANDROID_ROOT=/system ANDROID_DATA=/data TMPDIR=/data/local/tmp"
ERR=$(mktemp)
mountpoint -q "$ROOT/proc" || sudo mount -t proc proc "$ROOT/proc"
mountpoint -q "$ROOT/dev" || sudo mount --bind /dev "$ROOT/dev"
args=""
for e in $ENVS; do args="$args --env $e"; done
same=0
different=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$(sudo timeout 60 env -i $ENVS /usr/sbin/chroot "$ROOT" /system/bin/sh -c "$line" 2>/dev/null)
    ns=$?
    g=$(cd "$ROOT" && gexc timeout 300 "$GEXC" run --argv0 /system/bin/sh --uid 0 --mem64 $args --sysroot "$ROOT" "$ROOT/system/bin/sh" -c "$line" 2>>"$ERR")
    gs=$?
    if [ "$n" = "$g" ] && [ $ns -eq $gs ]; then
        same=$((same + 1))
        echo "same  [$ns] $line"
    else
        different=$((different + 1))
        echo "DIFF  $line"
        echo "  native[$ns]: $(printf %s "$n" | head -c 300)"
        echo "  gex[$gs]:    $(printf %s "$g" | head -c 300)"
    fi
done <"$FILE"
echo "$same same, $different different"
grep -h "unimplemented syscall\|not implemented" "$ERR" | sed 's/^\[gex:[0-9.]*\] //' | sort | uniq -c | sort -rn | head -20
rm -f "$ERR"
[ "$different" -eq 0 ]
