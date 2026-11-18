#!/bin/sh
# Run the Android programs under gexc and check what each prints and how it
# exits. Builds them first when bin/ is missing; GEXC picks the runner.
# With program names, only those run (low/<name> for the one linked at the
# linker's default base, as Android's static executables are); without,
# all of them at both bases.
#
# AOSP's own tests of the binder driver run too, where aosp/build.sh has
# built them: aosp/<name> names one.
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

# check <program> <its last line> <its exit status> [root]
# With "root", gexc runs it as uid 0; run as it is, it says for itself
# when it lacks the right (exit 77).
check() {
    if [ "$GEXC" = native ]; then
        out=$("$HERE/bin/$1" 2>"$ERR/$1.err")
    elif [ "${4:-}" = root ]; then
        out=$("$GEXC" run --uid 0 "$HERE/bin/$1" 2>"$ERR/$1.err")
    else
        out=$("$GEXC" run "$HERE/bin/$1" 2>"$ERR/$1.err")
    fi
    status=$?
    last=$(printf '%s\n' "$out" | tail -1)
    if [ "$status" -eq "$3" ] && [ "$last" = "$2" ]; then
        echo "PASS $1"
    elif [ "$status" -eq 77 ]; then
        # What it needs is not there (a device the host does not have).
        echo "SKIP $1: $last"
    else
        echo "FAIL $1: exit $status, last line '$last' (wanted exit $3, '$2'); stderr in $ERR/$1.err"
        fail=1
    fi
}

# run <program>, or low/<program> for the one linked at the default base
# gtest <name>: one of AOSP's tests (aosp/build.sh), with binderhost as
# the context manager a device would have. It passes when it exits 0 and
# says its tests passed; the ones it skips for what a driver lacks are its
# own to skip.
gtest() {
    if [ ! -x "$HERE/bin/aosp/$1" ]; then
        echo "SKIP aosp/$1: not built (aosp/build.sh)"
        return
    fi
    mkdir -p "$ERR/aosp"
    if [ "$GEXC" = native ]; then
        out=$("$HERE/bin/binderhost" "$HERE/bin/aosp/$1" 2>"$ERR/aosp/$1.err")
    else
        out=$("$GEXC" run "$HERE/bin/binderhost" "$HERE/bin/aosp/$1" 2>"$ERR/aosp/$1.err")
    fi
    status=$?
    passed=$(printf '%s\n' "$out" | grep '^\[  PASSED  \]')
    if [ "$status" -eq 0 ] && [ -n "$passed" ]; then
        echo "PASS aosp/$1: ${passed#\[  PASSED  \] }"
    elif [ "$status" -eq 77 ]; then
        echo "SKIP aosp/$1: $(printf '%s\n' "$out" | tail -1)"
    else
        echo "FAIL aosp/$1: exit $status; output in $ERR/aosp/$1.out, stderr in $ERR/aosp/$1.err"
        printf '%s\n' "$out" >"$ERR/aosp/$1.out"
        fail=1
    fi
}

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
    signalfd) check "$1" "signalfd ok" 0 ;;
    mknod) check "$1" "mknod ok" 0 root ;;
    binder) check "$1" "binder ok" 0 ;;
    binderwork) check "$1" "binderwork ok" 0 ;;
    binderfreeze) check "$1" "binderfreeze ok" 0 ;;
    binderfs) check "$1" "binderfs ok" 0 ;;
    bindersg) check "$1" "bindersg ok" 0 ;;
    binderctx) check "$1" "binderctx ok" 0 ;;
    selinuxfs) check "$1" "selinuxfs ok" 0 root ;;
    procattr) check "$1" "procattr ok" 0 root ;;
    filelabel) check "$1" "filelabel ok" 0 root ;;
    kmsg) check "$1" "kmsg ok" 0 root ;;
    sharedfutex) check "$1" "sharedfutex ok" 0 ;;
    propfutex) check "$1" "propfutex ok" 0 ;;
    nflog) check "$1" "nflog ok" 0 root ;;
    rss) check "$1" "rss ok" 0 ;;
    seccomp) check "$1" "seccomp ok" 0 ;;
    mountns) check "$1" "mountns ok" 0 root ;;
    uevent) check "$1" "uevent ok" 0 root ;;
    rlimit) check "$1" "rlimit ok" 0 root ;;
    sysdev) check "$1" "sysdev ok" 0 root ;;
    dirlink) check "$1" "dirlink ok" 0 root ;;
    loopdev) check "$1" "loopdev ok" 0 root ;;
    ext4mount) check "$1" "ext4mount ok" 0 root ;;
    mounts) check "$1" "mounts ok" 0 root ;;
    dmctl) check "$1" "dmctl ok" 0 root ;;
    owners) check "$1" "owners ok" 0 root ;;
    statdev) check "$1" "statdev ok" 0 root ;;
    ptyhup) check "$1" "ptyhup ok" 0 ;;
    rndbits) check "$1" "rndbits ok" 0 root ;;
    oomadj) check "$1" "oomadj ok" 0 root ;;
    ctlsock) check "$1" "ctlsock ok" 0 root ;;
    psi) check "$1" "psi ok" 0 root ;;
    ctty) check "$1" "ctty ok" 0 ;;
    apexns) check "$1" "apexns ok" 0 root ;;
    settod) check "$1" "settod ok" 0 root ;;
    seqpacket) check "$1" "seqpacket ok" 0 ;;
    uffd) check "$1" "uffd ok" 0 root ;;
    bpfsysctl) check "$1" "bpfsysctl ok" 0 root ;;
    bpfmap) check "$1" "bpfmap ok" 0 root ;;
    btf) check "$1" "btf ok" 0 root ;;
    bpfprog) check "$1" "bpfprog ok" 0 root ;;
    bpfmaps2) check "$1" "bpfmaps2 ok" 0 root ;;
    ringbuf) check "$1" "ringbuf ok" 0 root ;;
    bpffreeze) check "$1" "bpffreeze ok" 0 root ;;
    bpfinfo) check "$1" "bpfinfo ok" 0 root ;;
    cgroup2) check "$1" "cgroup2 ok" 0 root ;;
    cgroupbpf) check "$1" "cgroupbpf ok" 0 root ;;
    bpfrun) check "$1" "bpfrun ok" 0 root ;;
    sockhook) check "$1" "sockhook ok" 0 root ;;
    cgroup1) check "$1" "cgroup1 ok" 0 root ;;
    sockopt) check "$1" "sockopt ok" 0 root ;;
    ipv6) check "$1" "ipv6 ok" 0 ;;
    abortmsg)
        # What gexc says of the crash is the test: natively the message is
        # a crash dumper's to find.
        if [ "$GEXC" = native ]; then
            echo "SKIP abortmsg: gexc's own line"
        else
            "$GEXC" run "$HERE/bin/abortmsg" >/dev/null 2>"$ERR/abortmsg.err"
            if grep -q "crashed: SIGABRT.*abort message: the reason it gave" "$ERR/abortmsg.err"; then
                echo "PASS abortmsg"
            else
                echo "FAIL abortmsg: gexc did not say the abort message; stderr in $ERR/abortmsg.err"
                fail=1
            fi
        fi
        ;;
    waits)
        check "$1" "waits ok" 0
        # And with its time slowed, where its clocks and waits still agree.
        [ "$GEXC" = native ] || GEX_TIME_SCALE=4 check "$1" "waits ok" 0
        ;;
    aosp/*) gtest "${1#aosp/}" ;;
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
    all="hello tagged tbi thread simd exclusive casp prctl crc crypto block procfd mremap mainstack sigqueue futex pipesz auxv protect sigframe execfault efault pdeath signalfd mknod binder binderwork binderfreeze binderfs bindersg binderctx selinuxfs procattr filelabel kmsg sharedfutex mountns uevent rlimit sysdev dirlink loopdev ext4mount mounts dmctl owners statdev waits ptyhup rndbits oomadj ctlsock abortmsg psi ctty apexns settod seqpacket uffd bpfsysctl bpfmap btf bpfprog bpfmaps2 ringbuf bpfinfo cgroup2 cgroupbpf bpfrun sockhook cgroup1 sockopt ipv6 bpffreeze propfutex nflog rss seccomp"
    for p in $all; do
        run "$p"
    done
    for p in $all; do
        run "low/$p"
    done
    run aosp/binderDriverInterfaceTest
fi
exit $fail
