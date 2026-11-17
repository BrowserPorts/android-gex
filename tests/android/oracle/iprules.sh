#!/bin/sh
# Policy routing rules, Linux's and gex's: each line of iprules.txt run
# with the image's own `ip`, natively in a chroot of ROOT in a network
# namespace of its own and under gexc (whose rules start fresh with each
# run), and the two compared.
#
#   iprules.sh ROOT
set -u
ROOT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
GEXC=${GEXC:-gexc}
export GEX_FIXED_RANDOM="${GEX_FIXED_RANDOM:-1}" GEX_CACHE_MAX_BYTES="${GEX_CACHE_MAX_BYTES:-12884901888}"
mountpoint -q "$ROOT/proc" || sudo mount -t proc proc "$ROOT/proc"
same=0 diff=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$(sudo unshare -n chroot "$ROOT" /system/bin/sh -c "$line" 2>&1)
    g=$(cd "$ROOT" && sudo env GEX_FIXED_RANDOM="$GEX_FIXED_RANDOM" GEX_CACHE_MAX_BYTES="$GEX_CACHE_MAX_BYTES" GEX_LOG=off \
        ${GEX_CACHE_BUILD:+GEX_CACHE_BUILD="$GEX_CACHE_BUILD"} timeout 300 "$GEXC" run --mem64 --sysroot "$ROOT" system/bin/sh -c "$line" 2>&1 | grep -v '^\[gex\]')
    if [ "$n" = "$g" ]; then
        same=$((same + 1)); echo "same  $line"
    else
        diff=$((diff + 1)); echo "DIFF  $line"
        printf '%s\n' "$n" > /tmp/ipr-native.txt; printf '%s\n' "$g" > /tmp/ipr-gex.txt
        diff /tmp/ipr-native.txt /tmp/ipr-gex.txt | head -12
    fi
done < "$HERE/iprules.txt"
echo "$same same, $diff different"
