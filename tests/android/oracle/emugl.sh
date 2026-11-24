#!/bin/sh
# The image's own OpenGL ES (its vendor libEGL_emulation and
# libGLESv2_emulation, gfxstream's guest) drawing through gex, without a
# boot: tests/android/src/emugl.c, run inside ROOT (root.sh's) as root,
# with the emulator's devices (GEX_EMULATOR_HOST=1). Its EGL reaches gex's
# gfxstream renderer over the goldfish pipe; it clears a pbuffer and reads
# it back, and its last line is "emugl ok". Lines starting "log" are the
# drivers' own log, which the program takes in place of logd.
#
#   emugl.sh ROOT
#
# GEXC is the gexc to use (this checkout's big64 release build unless
# given); TRACE, system calls for gexc to print (GEX_STRACE_ONLY).
set -u
ROOT=$(CDPATH='' cd -- "${1:?usage: emugl.sh ROOT}" && pwd)
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../../target/big64/release/gexc}
PROG=$HERE/../bin/dyn/emugl
[ -x "$PROG" ] || { echo "emugl.sh: no $PROG (tests/android/build.sh)" >&2; exit 1; }
cd "$ROOT" && GEX_EMULATOR_HOST=1 ${TRACE:+GEX_STRACE_ONLY="$TRACE"} timeout "${TIMEOUT:-300}" \
    "$GEXC" run --argv0 /emugl --uid 0 --mem64 --bind "$PROG=/emugl" --sysroot "$ROOT" "$PROG"
