#!/bin/sh
# Boot an Android 17 arm64 emulator image under gexc, on macOS or Linux,
# from where the image's first-stage init would hand over to the rest of
# init, and stop it before it takes the machine with it.
#
#   boot.sh ROOT OUT NAME [SECONDS]
#
# ROOT is a root tree made from the image (README.md says how), OUT a
# directory for what the boot writes, NAME this boot's name, SECONDS how
# long it may run (7200 unless given). It writes
#   OUT/init-NAME.txt         gexc's standard error: init's kernel log
#                             ([kmsg] lines) and gexc's own
#   OUT/gexlog-NAME/logcat.txt  Android's log (init.gex.rc runs logcat)
#   OUT/watch-NAME.txt        a line every 15 seconds: time, gexc's memory,
#                             the machine's free memory and disk
#   OUT/frame-NAME.ppm        the display's last frame, once something draws
#
# It needs gexc built with the big64 feature (GEXC; this checkout's
# target/release/gexc unless given) and tests/android/build.sh's programs
# (bin/firststage). The boot configuration is bootconfig here (CONFIG):
# the image's own graphics (its EGL, gralloc and composer, which reach the
# host over the goldfish pipe: gex's gfxstream renderer on the host's
# OpenGL ES) and a permissive SELinux. bootconfig.swiftshader is the
# emulator's guest rendering instead (ANGLE over SwiftShader, which
# swiftshader.sh puts into the root).
#
# The boot is slow (the guest's clock runs at an eighth of the host's,
# GEX_TIME_SCALE) and large: several GB of memory. It is stopped (its whole
# process group) when the machine has less than MIN_FREE (25) percent of
# its memory free, the disks it writes to or swaps to have less than
# MIN_DISK_GB (6) free, or gexc's own memory passes MAX_GB (40). It will
# not start with less than START_FREE (40) percent free.
#
# Environment it passes on to gexc, each with a default: GEX_HOST_FORWARD
# (unset; 5555 lets `adb connect 127.0.0.1:5555` reach the image's adbd),
# GEX_VIRTIO_GPU (1080x1920; the display gfxstream's renderer takes too),
# GEX_GFXSTREAM_FRAME (OUT/screen-NAME.ppm, the frame the guest last
# posted), GEX_CACHE_MAX_BYTES (8 GiB of translations,
# kept in gex's usual cache directory, XDG_CACHE_HOME).
set -u
ROOT=${1:?usage: boot.sh ROOT OUT NAME [SECONDS]}
OUT=${2:?usage: boot.sh ROOT OUT NAME [SECONDS]}
NAME=${3:?usage: boot.sh ROOT OUT NAME [SECONDS]}
SECS=${4:-7200}
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../../target/release/gexc}
CONFIG=${CONFIG:-$HERE/bootconfig}
MIN_FREE=${MIN_FREE:-25}
START_FREE=${START_FREE:-40}
MIN_DISK_GB=${MIN_DISK_GB:-6}
MAX_GB=${MAX_GB:-40}
FIRST=$HERE/../bin/firststage

fail() {
    echo "boot.sh: $1" >&2
    exit 1
}
[ -x "$GEXC" ] || fail "no gexc at $GEXC (build it with the big64 feature, or set GEXC)"
[ -x "$FIRST" ] || fail "no $FIRST (run tests/android/build.sh)"
[ -d "$ROOT/system/bin" ] || fail "$ROOT is not a root tree made from the image (see README.md)"
[ -f "$CONFIG" ] || fail "no boot configuration at $CONFIG"
mkdir -p "$OUT/gexlog-$NAME" || exit 1
OUT=$(CDPATH='' cd -- "$OUT" && pwd)
LOG=$OUT/init-$NAME.txt
LOGDIR=$OUT/gexlog-$NAME
WATCH=$OUT/watch-$NAME.txt

# The machine's free memory, in percent; gexc's memory, in MB; the free
# space, in GB, of the disk that holds a path.
case $(uname -s) in
Darwin)
    free_pct() { memory_pressure | tail -1 | grep -o '[0-9]*%' | tr -d %; }
    # The footprint macOS counts: resident and compressed.
    mem_mb() { footprint -p "$1" 2>/dev/null | awk '/phys_footprint:/{v=$2; u=$3; if (u ~ /GB/) v*=1024; else if (u ~ /KB/) v/=1024; print int(v); exit}'; }
    # gexc's host descriptors: all of them, and the cached translations.
    host_fds() { lsof -n -P -p "$1" -Fn 2>/dev/null | awk '/^n/{n++; if ($0 ~ /\.cwasm$/) c++} END{print n+0, c+0}'; }
    # macOS swaps to the disk that holds /.
    SWAP_DISK=/
    ;;
Linux)
    free_pct() { awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{if (t) print int(a * 100 / t)}' /proc/meminfo; }
    mem_mb() { awk '/^VmRSS:|^VmSwap:/{s+=$2} END{print int(s / 1024)}' "/proc/$1/status" 2>/dev/null; }
    host_fds() { n=0; c=0; for f in /proc/"$1"/fd/*; do n=$((n + 1)); case $(readlink "$f") in *.cwasm) c=$((c + 1)) ;; esac; done; echo "$n $c"; }
    SWAP_DISK=$OUT
    ;;
*) fail "only macOS and Linux hosts" ;;
esac
disk_gb() { df -k "$1" | awk 'NR==2{print int($4 / 1048576)}'; }

f=$(free_pct)
[ "${f:-0}" -ge "$START_FREE" ] || fail "the machine has $f% of its memory free; $START_FREE% is needed to start"

# macOS's allocator keeps freed large blocks and zeroes one by writing it
# when it is handed out again, so each thread's dispatch tables (large and
# mostly untouched) would cost all their pages; gexc turns that cache off
# for itself, and this keeps it off for anything it starts.
export MallocLargeCache=0
# The display: gex's virtio-gpu at the emulator's phone size.
export GEX_VIRTIO_GPU=${GEX_VIRTIO_GPU:-1080x1920}
export GEX_VIRTIO_GPU_FRAME=${GEX_VIRTIO_GPU_FRAME:-$OUT/frame-$NAME.ppm}
export GEX_GFXSTREAM_FRAME=${GEX_GFXSTREAM_FRAME:-$OUT/screen-$NAME.ppm}
# The emulator's own services, over vsock (the sensors HAL wants them).
export GEX_EMULATOR_HOST=${GEX_EMULATOR_HOST:-1}
# Translation: dense dispatch, threads take only the code they run, the
# guest's clock slowed to the translated code's pace, and the same random
# numbers every boot, so that libraries load where the cache has them.
export GEX_DENSE=${GEX_DENSE:-1} GEX_LAZY_CATCH_UP=1 GEX_TIME_SCALE=${GEX_TIME_SCALE:-8} GEX_FIXED_RANDOM=1
export GEX_CACHE_MAX_BYTES=${GEX_CACHE_MAX_BYTES:-8589934592}
if [ -z "${GEX_CACHE_BUILD:-}" ] && name=$(sh "$HERE/cache-id.sh" "$GEXC" 2>/dev/null); then
    export GEX_CACHE_BUILD="$name"
fi

# gexc in a process group of its own, with its console input held open
# (init gives the console a shell, which would end at once at end of file).
# A shell without a terminal gives a background job no group of its own
# (dash's `set -m` does nothing then), so on Linux setsid makes one.
cd "$ROOT" || exit 1
export GEXC CONFIG FIRST HERE LOGDIR ROOT LOG
BODY='sleep 1000000 | exec "$GEXC" run --argv0 /firststage --uid 0 --mem64 --selinuxfs --bootconfig "$CONFIG" \
    --bind "$FIRST=/firststage" --bind "$HERE/fstab.gex=/vendor/etc/fstab.ranchu" \
    --bind "$HERE/init.gex.rc=/init.ranchu.rc" --bind "$LOGDIR=/gexlog" \
    --sysroot "$ROOT" "$FIRST" 2>"$LOG"'
case $(uname -s) in
Linux) setsid sh -c "$BODY" & ;;
*)
    set -m
    sh -c "$BODY" &
    set +m
    ;;
esac
GROUP=$!
start=$(date +%s)
echo "boot $NAME: group $GROUP, log $LOG" | tee "$WATCH"

stop() {
    echo "STOPPING: $1" | tee -a "$WATCH"
    kill -TERM -"$GROUP" 2>/dev/null
    sleep 3
    kill -KILL -"$GROUP" 2>/dev/null
}

trap 'stop "interrupted"; exit 1' INT TERM
while kill -0 "$GROUP" 2>/dev/null; do
    sleep 15
    t=$(($(date +%s) - start))
    pid=$(pgrep -g "$GROUP" -x "$(basename "$GEXC")" | head -1)
    mem=$([ -n "$pid" ] && mem_mb "$pid")
    disk=$(disk_gb "$OUT")
    swap=$(disk_gb "$SWAP_DISK")
    [ "${swap:-100}" -lt "${disk:-100}" ] && disk=$swap
    f=$(free_pct)
    echo "${t}s gexc=${mem:-?}MB free=${f}% disk=${disk}GB" >>"$WATCH"
    # Every five minutes, gexc's host descriptors: every guest process's
    # host files and every translation mapped from the cache are its, and
    # the host's limit on them is the guests' too.
    if [ -n "$pid" ] && [ $((t / 15 % 20)) -eq 0 ]; then
        hf=$(host_fds "$pid")
        echo "${t}s host descriptors=${hf%% *} cached translations=${hf##* }" >>"$WATCH"
    fi
    if [ "$t" -ge "$SECS" ]; then stop "time limit"; break; fi
    if [ "${f:-100}" -lt "$MIN_FREE" ]; then stop "memory ${f}% free"; break; fi
    if [ "${disk:-100}" -lt "$MIN_DISK_GB" ]; then stop "disk ${disk} GB free"; break; fi
    if [ -n "${mem:-}" ] && [ "$mem" -gt $((MAX_GB * 1024)) ]; then stop "gexc at ${mem} MB"; break; fi
done
wait "$GROUP" 2>/dev/null
echo "boot $NAME ended after $(($(date +%s) - start))s" | tee -a "$WATCH"
