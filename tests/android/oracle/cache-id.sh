#!/bin/sh
# A name for this checkout's translator, for GEX_CACHE_BUILD (gex_cache's
# build_fingerprint): the same for two builds of gexc that translate and
# compile alike, so that a rebuild for a change to the kernel finds the
# translations the last build made.
#
#   GEX_CACHE_BUILD=$(sh tests/android/oracle/cache-id.sh GEXC) GEXC run ...
#
# It is made from what git has for everything a gexc is built from except
# what decides what a program sees and not how its code is translated or
# compiled: the kernel (crates/gex-kernel, and gex-kmem, its reach into a
# process's memory), the devices the host renders and shows for it
# (gex-gfxstream, gex-gl, gex-gpu, gex-wayland, gex-xwm, and their files in
# hosts/native), the page's block store (gex-store) and ejected projects
# (gex-eject), and the native host's terminal, usage and stall reports.
# None of those define anything a translated module imports. GEXC is the
# gexc the name is for, built from this checkout. There is no name, nothing is printed and the
# exit is 1 (gexc left without the variable takes each build as new, as it
# always did) when the name would not be that gexc's: with a change not
# yet committed in any of those places, or a file there newer than GEXC
# (it was built before the checkout came to be what it is).
set -eu
GEXC=$(CDPATH='' cd -- "$(dirname "$1")" && pwd)/$(basename "$1")
cd "$(dirname "$0")/../../.."
PARTS="Cargo.lock Cargo.toml rust-toolchain.toml third_party"
for c in crates/*; do
    case ${c#crates/} in
    gex-kernel | gex-kmem | gex-gfxstream | gex-gl | gex-gpu | gex-wayland | gex-xwm | gex-store | gex-eject) ;;
    *) PARTS="$PARTS $c" ;;
    esac
done
for f in $(git ls-files hosts/native); do
    case $f in
    hosts/native/src/gfxstream.rs | hosts/native/src/gl.rs | hosts/native/src/wayland.rs | hosts/native/src/pty.rs | hosts/native/src/usage.rs | hosts/native/src/stall.rs) ;;
    *) PARTS="$PARTS $f" ;;
    esac
done
# shellcheck disable=SC2086
if [ -n "$(git status --porcelain -- $PARTS)" ]; then
    echo "cache-id: uncommitted changes outside the kernel; this build has no name" >&2
    exit 1
fi
# shellcheck disable=SC2086
if [ -n "$(find $PARTS -type f -newer "$GEXC" -print -quit)" ]; then
    echo "cache-id: sources newer than $GEXC; this build has no name" >&2
    exit 1
fi
# shellcheck disable=SC2086
git ls-tree HEAD -- $PARTS | git hash-object --stdin | cut -c1-16
