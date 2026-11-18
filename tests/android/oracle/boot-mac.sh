#!/bin/sh
# Boot the oracle's Android image natively on a Mac, as init.sh does in a
# Linux VM, with what keeps the Mac usable while it runs.
#
#   boot-mac.sh NAME [seconds]
#
# Needs a gexc built with the big64 feature (GEXC), the image's root tree
# unpacked with its owners kept as user.gex.owner (owners-to-xattr.py) and
# its SELinux labels as the host's security.selinux (ROOT), and the boot
# configuration (CONFIG). The log is $OUT/init-NAME.txt, logcat's
# $OUT/gexlog-NAME/logcat.txt, the watcher's $OUT/watch-NAME.txt.
#
# The boot is stopped (the whole process group) when the Mac has under
# 25% of its memory free, or under 6 GB free on the disk that swaps (/): a
# boot grows to many GB, macOS swaps to the internal disk, and that disk
# is small. gexc's own footprint past MAX_GB (40) is a last stop only: it
# counts pages macOS compresses to almost nothing (dispatch tables that
# are mostly null), so the Mac's free memory is the measure.
set -u
NAME=${1:?boot name}
SECS=${2:-7200}
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-/Volumes/GexBuild/android-gex-android/target/release/gexc}
ROOT=${ROOT:-/Volumes/GexBuild/android-oracle/root}
CONFIG=${CONFIG:-/Volumes/GexBuild/android-oracle/bootcfg}
OUT=${OUT:-/Volumes/GexBuild/android-oracle/boots}
MAX_GB=${MAX_GB:-40}
FIRST=$HERE/../bin/firststage
LOG=$OUT/init-$NAME.txt
LOGDIR=$OUT/gexlog-$NAME
WATCH=$OUT/watch-$NAME.txt
mkdir -p "$OUT" "$LOGDIR"

free_pct() { memory_pressure | tail -1 | grep -o '[0-9]*%' | tr -d %; }
f=$(free_pct)
if [ "${f:-0}" -lt 40 ]; then
    echo "boot-mac: the Mac has $f% memory free; 40% is needed to start" >&2
    exit 1
fi

# The translation cache on the T7 (the internal disk is small), named for
# the build as init.sh names it.
export XDG_CACHE_HOME=${XDG_CACHE_HOME:-/Volumes/T7 APFS/gex-cache-mac}
mkdir -p "$XDG_CACHE_HOME"
export GEX_DENSE=1 GEX_HEAP_STATS=${GEX_HEAP_STATS:-300} GEX_LAZY_CATCH_UP=1 GEX_TIME_SCALE=8
export GEX_CACHE_MAX_BYTES=${GEX_CACHE_MAX_BYTES:-8589934592} GEX_FIXED_RANDOM=1
if [ -z "${GEX_CACHE_BUILD:-}" ] && name=$(sh "$HERE/cache-id.sh" "$GEXC" 2>/dev/null); then
    export GEX_CACHE_BUILD="$name"
fi

# gexc in a process group of its own, with its console input held open.
cd "$ROOT" || exit 1
set -m
(sleep 1000000 | exec "$GEXC" run --argv0 /firststage --uid 0 --mem64 --selinuxfs --bootconfig "$CONFIG" \
    --bind "$FIRST=/firststage" --bind "$HERE/fstab.gex=/vendor/etc/fstab.ranchu" \
    --bind "$HERE/init.gex.rc=/init.ranchu.rc" --bind "$LOGDIR=/gexlog" \
    --sysroot "$ROOT" "$FIRST" 2>"$LOG") &
GROUP=$!
set +m
start=$(date +%s)
echo "boot $NAME: group $GROUP, log $LOG" | tee "$WATCH"

# What gexc's footprint is made of, by kind of memory, into the watch
# file (the first time it passes 8 GB, and when the boot is stopped).
breakdown() {
    [ -n "${pid:-}" ] && { echo "--- footprint of gexc at ${t:-?}s"; footprint -p "$pid" 2>/dev/null | sed -n '1,40p'; } >> "$WATCH"
}
broke=0

stop() {
    breakdown
    echo "STOPPING: $1" | tee -a "$WATCH"
    kill -TERM -"$GROUP" 2>/dev/null
    sleep 3
    kill -KILL -"$GROUP" 2>/dev/null
}

while kill -0 "$GROUP" 2>/dev/null; do
    sleep 15
    t=$(( $(date +%s) - start ))
    pid=$(pgrep -g "$GROUP" -x gexc | head -1)
    # The footprint macOS counts (resident and compressed), in MB.
    fp=$( [ -n "$pid" ] && footprint -p "$pid" 2>/dev/null | awk '/phys_footprint:/{v=$2; u=$3; if (u ~ /GB/) v*=1024; else if (u ~ /KB/) v/=1024; print int(v); exit}' )
    disk=$(df -g / | awk 'NR==2{print $4}')
    f=$(free_pct)
    echo "${t}s footprint=${fp:-?}MB mac_free=${f}% disk_free=${disk}GB" >> "$WATCH"
    if [ "$broke" -eq 0 ] && [ -n "${fp:-}" ] && [ "$fp" -gt 8192 ]; then breakdown; broke=1; fi
    if [ "$t" -ge "$SECS" ]; then stop "time limit"; break; fi
    if [ "${f:-100}" -lt 25 ]; then stop "Mac memory ${f}% free"; break; fi
    if [ "${disk:-100}" -lt 6 ]; then stop "disk ${disk} GB free"; break; fi
    if [ -n "${fp:-}" ] && [ "$fp" -gt $((MAX_GB * 1024)) ]; then stop "gexc footprint ${fp} MB"; break; fi
done
wait "$GROUP" 2>/dev/null
echo "boot $NAME ended after $(( $(date +%s) - start ))s" | tee -a "$WATCH"
