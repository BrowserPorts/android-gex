#!/bin/sh
# Snapshots of a running program and resuming from them (gexc's
# GEX_SNAP_HOLD_AT, GEX_SNAP_OUT and `run --restore`): a program run whole,
# then run again and snapshotted partway (the run ends with the snapshot),
# then resumed from the snapshot. What the two runs print together must be
# what the whole run printed, wherever the snapshot fell.
#
#   GEXC=path/to/gexc sh tests/android/snapshot.sh
#
# The programs are tests/android/build.sh's. AT lists the seconds into the
# run to take the snapshot at (each its own run); the first run warms the
# translation cache, so that the snapshot falls where the program is.
set -u
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../target/release/gexc}
AT=${AT:-0.6 1.0 1.4 1.9}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
status=0

# snapone: one thread, its heap, a mapping, a signal handler and mask, and a
# host file read through one descriptor (its own source). snaptwo: three
# threads, two waiting on a condition variable's futexes and one sleeping,
# each with its own id and thread-local value. snapthree: an event loop on
# epoll over a periodic timerfd, an eventfd and a signalfd, and an
# absolute deadline on the monotonic clock taken at its start. snapfour:
# two processes, a parent and its forked child, talking over two pipes,
# the child's state in its own memory and its end waited for. snapfive:
# the same with a child that execs another program (the other build of
# it, which a run at the low base can exec).
for p in snapone snaptwo snapthree snapfour snapfive; do
case $p in
    snapone) set -- "$HERE/bin/$p" "$HERE/src/$p.c" ;;
    snapfive) set -- "$HERE/bin/low/$p" "$HERE/bin/$p" ;;
    *) set -- "$HERE/bin/$p" ;;
esac
"$GEXC" run "$@" >/dev/null 2>&1
"$GEXC" run "$@" >"$work/whole" 2>"$work/whole.err"
if [ "$(tail -1 "$work/whole")" != "$p ok" ]; then
    echo "FAIL $p: the whole run did not finish (see below)"
    tail -3 "$work/whole.err"
    status=1
    continue
fi
for at in $AT; do
    rm -rf "$work/snap"
    GEX_SNAP_HOLD_AT=$at GEX_SNAP_OUT="$work/snap" GEX_SNAP_STOP=1 "$GEXC" run "$@" >"$work/first" 2>"$work/first.err"
    # Finished before the snapshot was due: nothing to resume.
    if cmp -s "$work/first" "$work/whole" && ! grep -q 'snapshot hold' "$work/first.err"; then
        echo "SKIP $p at ${at}s (it had finished)"
        continue
    fi
    if ! grep -q 'snapshot written: pid' "$work/first.err"; then
        echo "FAIL $p at ${at}s: no snapshot ($(grep -a 'snapshot' "$work/first.err" | tail -1))"
        status=1
        continue
    fi
    "$GEXC" run --restore "$work/snap" "$@" >"$work/rest" 2>"$work/rest.err"
    if cat "$work/first" "$work/rest" | cmp -s - "$work/whole"; then
        echo "PASS $p at ${at}s ($(wc -l <"$work/first" | tr -d ' ') lines, then $(wc -l <"$work/rest" | tr -d ' ') resumed)"
    else
        echo "FAIL $p at ${at}s: the two runs together are not the whole run"
        cat "$work/first" "$work/rest" | diff - "$work/whole" | head -5
        tail -3 "$work/rest.err"
        status=1
    fi
done
done
exit $status
