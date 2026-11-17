#!/bin/sh
# iptables' tables, Linux's and gex's: each case under xtables/ restored
# with the image's own iptables-restore (ip6tables-restore for ip6*), then
# its table printed with iptables-save, natively in a chroot of ROOT in a
# network namespace of its own and under gexc, and the two compared.
#
#   xtables.sh ROOT
#
# Needs the legacy ip_tables modules on the host (Linux 7.0 has them).
# GEXC as compare.sh takes it.
set -u
ROOT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
GEXC=${GEXC:-gexc}
export GEX_FIXED_RANDOM="${GEX_FIXED_RANDOM:-1}" GEX_CACHE_MAX_BYTES="${GEX_CACHE_MAX_BYTES:-12884901888}"
for m in ip_tables ip6_tables iptable_filter iptable_mangle iptable_raw iptable_nat ip6table_filter; do sudo modprobe $m; done
mountpoint -q "$ROOT/proc" || sudo mount -t proc proc "$ROOT/proc"
same=0 diff=0
for f in "$HERE"/xtables/*.rules; do
    case=$(basename "$f" .rules)
    tool=iptables
    case $case in ip6*) tool=ip6tables ;; esac
    table=$(sed -n 's/^\*//p' "$f" | head -1)
    sudo cp "$f" "$ROOT/data/local/tmp/case.rules" 2>/dev/null || { sudo mkdir -p "$ROOT/data/local/tmp"; sudo cp "$f" "$ROOT/data/local/tmp/case.rules"; }
    line="$tool-restore < /data/local/tmp/case.rules 2>&1; echo rc=\$?; $tool-save -t $table 2>&1 | grep -v '^#'"
    n=$(sudo unshare -n chroot "$ROOT" /system/bin/sh -c "$line" 2>&1)
    g=$(cd "$ROOT" && sudo env GEX_FIXED_RANDOM="$GEX_FIXED_RANDOM" GEX_CACHE_MAX_BYTES="$GEX_CACHE_MAX_BYTES" GEX_LOG=off \
        ${GEX_CACHE_BUILD:+GEX_CACHE_BUILD="$GEX_CACHE_BUILD"} timeout 300 "$GEXC" run --mem64 --sysroot "$ROOT" system/bin/sh -c "$line" 2>&1 | grep -v '^\[gex\]')
    if [ "$n" = "$g" ]; then
        same=$((same + 1)); echo "same  $case"
    else
        diff=$((diff + 1)); echo "DIFF  $case"
        printf '%s\n' "$n" > /tmp/xt-native.txt; printf '%s\n' "$g" > /tmp/xt-gex.txt
        diff /tmp/xt-native.txt /tmp/xt-gex.txt | head -20
    fi
done
echo "$same same, $diff different"
