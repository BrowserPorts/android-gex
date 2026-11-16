#!/bin/sh
# Run one of the image's daemons under gexc as init would run it, without
# the boot before it: seconds where init.sh takes minutes to get there.
#
#   service.sh ROOT [name:type...] -- program [arguments...]
#
# ROOT is root.sh's. Each name:type is a socket the daemon's .rc file asks
# init for ("lmkd:seqpacket+passcred"): tests/android/bin/svcrun (build.sh)
# makes it in /dev/socket and names it in the environment as init does,
# then runs the program. There is no init, so no property area and nobody
# to answer for servicemanager unless it is the program: what a daemon
# does with the kernel on its own is what this shows. TIMEOUT is how long
# to let it run (default 60 seconds); TRACE, system calls for gexc to
# print (GEX_STRACE_ONLY).
#
# Everything gexc and the program print comes out as it is.
set -u
ROOT=$(CDPATH='' cd -- "$1" && pwd)
shift
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../../target/big64/release/gexc}
RUN=$HERE/../bin/svcrun
[ -x "$RUN" ] || { echo "service.sh: no $RUN (tests/android/build.sh)" >&2; exit 1; }
export GEX_FIXED_RANDOM="${GEX_FIXED_RANDOM:-1}"
export GEX_CACHE_MAX_BYTES="${GEX_CACHE_MAX_BYTES:-12884901888}"
if [ -z "${GEX_CACHE_BUILD:-}" ] && name=$(sh "$HERE/cache-id.sh" "$GEXC" 2>/dev/null); then
    export GEX_CACHE_BUILD="$name"
fi
cd "$ROOT" && sudo env GEX_FIXED_RANDOM="$GEX_FIXED_RANDOM" GEX_CACHE_MAX_BYTES="$GEX_CACHE_MAX_BYTES" \
    ${GEX_CACHE_BUILD:+GEX_CACHE_BUILD="$GEX_CACHE_BUILD"} ${TRACE:+GEX_STRACE_ONLY="$TRACE"} \
    timeout "${TIMEOUT:-60}" "$GEXC" run --argv0 /svcrun --uid 0 --mem64 --selinuxfs \
    --bind "$RUN=/svcrun" --sysroot "$ROOT" "$RUN" "$@"
echo "service.sh: gexc exited $? (124: still running at the time limit)"
