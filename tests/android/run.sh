#!/bin/sh
# Run the Android programs under gexc and check what each prints and how it
# exits. Builds them first when bin/ is missing; GEXC picks the runner.
# With program names, only those run; without, all of them.
#
# GEXC=native runs them as they are, which an arm64 Linux host can: the
# reference they are written against. What they write to stderr goes to
# bin/, or to the temporary directory when bin/ cannot be written.
set -u

HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/../.." && pwd)
GEXC=${GEXC:-$ROOT/target/release/gexc}
[ -d "$HERE/bin" ] || "$HERE/build.sh" || exit 1
ERR=$HERE/bin
[ -w "$ERR" ] || ERR=${TMPDIR:-/tmp}

fail=0

# check <program> <its last line> <its exit status>
check() {
    if [ "$GEXC" = native ]; then
        out=$("$HERE/bin/$1" 2>"$ERR/$1.err")
    else
        out=$("$GEXC" run "$HERE/bin/$1" 2>"$ERR/$1.err")
    fi
    status=$?
    last=$(printf '%s\n' "$out" | tail -1)
    if [ "$status" -eq "$3" ] && [ "$last" = "$2" ]; then
        echo "PASS $1"
    else
        echo "FAIL $1: exit $status, last line '$last' (wanted exit $3, '$2'); stderr in $ERR/$1.err"
        fail=1
    fi
}

run() {
    case $1 in
    hello) check hello "hello ok" 0 ;;
    tagged) check tagged "tagged ok" 0 ;;
    thread) check thread "thread ok" 0 ;;
    simd) check simd "simd ok" 0 ;;
    exclusive) check exclusive "exclusive ok" 0 ;;
    casp) check casp "casp ok" 0 ;;
    prctl) check prctl "prctl ok" 0 ;;
    crc) check crc "crc ok" 0 ;;
    crypto) check crypto "crypto ok" 0 ;;
    *)
        echo "FAIL $1: no such program"
        fail=1
        ;;
    esac
}

if [ "$#" -gt 0 ]; then
    for p in "$@"; do
        run "$p"
    done
else
    for p in hello tagged thread simd exclusive casp prctl crc crypto; do
        run "$p"
    done
fi
exit $fail
