#!/bin/sh
# Run the Android programs under gexc and check what each prints and how it
# exits. Builds them first when bin/ is missing; GEXC picks the runner.
# With program names, only those run (low/<name> for the one linked at the
# linker's default base, as Android's static executables are); without,
# all of them at both bases.
#
# GEXC=native runs them as they are, which an arm64 Linux host can: the
# reference they are written against. What they write to stderr goes to
# bin/, or to the temporary directory when bin/ cannot be written.
set -u

HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/../.." && pwd)
GEXC=${GEXC:-$ROOT/target/release/gexc}
[ -d "$HERE/bin/low" ] || "$HERE/build.sh" || exit 1
ERR=$HERE/bin
[ -w "$ERR" ] || ERR=${TMPDIR:-/tmp}
mkdir -p "$ERR/low"

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

# run <program>, or low/<program> for the one linked at the default base
run() {
    case ${1#low/} in
    hello) check "$1" "hello ok" 0 ;;
    tagged) check "$1" "tagged ok" 0 ;;
    tbi) check "$1" "tbi ok" 0 ;;
    thread) check "$1" "thread ok" 0 ;;
    simd) check "$1" "simd ok" 0 ;;
    exclusive) check "$1" "exclusive ok" 0 ;;
    casp) check "$1" "casp ok" 0 ;;
    prctl) check "$1" "prctl ok" 0 ;;
    crc) check "$1" "crc ok" 0 ;;
    crypto) check "$1" "crypto ok" 0 ;;
    block) check "$1" "block ok" 0 ;;
    procfd) check "$1" "procfd ok" 0 ;;
    mremap) check "$1" "mremap ok" 0 ;;
    mainstack) check "$1" "mainstack ok" 0 ;;
    sigqueue) check "$1" "sigqueue ok" 0 ;;
    futex) check "$1" "futex ok" 0 ;;
    pipesz) check "$1" "pipesz ok" 0 ;;
    auxv) check "$1" "auxv ok" 0 ;;
    protect) check "$1" "protect ok" 0 ;;
    sigframe) check "$1" "sigframe ok" 0 ;;
    execfault) check "$1" "execfault ok" 0 ;;
    efault) check "$1" "efault ok" 0 ;;
    pdeath) check "$1" "pdeath ok" 0 ;;
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
    all="hello tagged tbi thread simd exclusive casp prctl crc crypto block procfd mremap mainstack sigqueue futex pipesz auxv protect sigframe execfault efault pdeath"
    for p in $all; do
        run "$p"
    done
    for p in $all; do
        run "low/$p"
    done
fi
exit $fail
