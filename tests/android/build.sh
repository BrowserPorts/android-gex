#!/bin/sh
# Build the Android test programs with the NDK into bin/.
#
# They are static executables: bionic linked in, so they need neither
# Android's linker nor a system image. Static is not position-independent
# here: bionic's static start-up applies no relocations, and Android builds
# its own static executables the same way.
#
# Each is built twice. bin/ has it linked at 0x400000, above where a 32-bit
# guest memory keeps gex's own tables, so it runs in either memory. bin/low/
# has it at the linker's default, 0x200000, where Android's own static
# executables are (first-stage init among them): it needs a 64-bit memory,
# which gexc gives it.
#
# The NDK is ANDROID_NDK_HOME, or the newest one under the SDK
# (ANDROID_HOME, or the SDK's default place on this host).
set -eu

HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
OUT=$HERE/bin
TARGET=${GEX_ANDROID_TARGET:-aarch64-linux-android30}
mkdir -p "$OUT/low"

case $(uname -s) in
Darwin) host=darwin-x86_64 sdk=${ANDROID_HOME:-$HOME/Library/Android/sdk} ;;
*) host=linux-x86_64 sdk=${ANDROID_HOME:-$HOME/Android/Sdk} ;;
esac
ndk=${ANDROID_NDK_HOME:-}
if [ -z "$ndk" ]; then
    ndk=$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1)
fi
if [ -z "$ndk" ] || [ ! -d "$ndk/toolchains/llvm/prebuilt/$host/bin" ]; then
    echo "tests/android/build.sh: no NDK (set ANDROID_NDK_HOME)" >&2
    exit 1
fi
CC=$ndk/toolchains/llvm/prebuilt/$host/bin/clang
# The policy selinuxfs.c carries, to load into the kernel it runs on.
POLICY=$HERE/../../crates/gex-kernel/src/selinux/testdata/test.33

for p in hello tagged tbi thread simd exclusive casp prctl crc crypto block procfd mremap mainstack sigqueue futex pipesz auxv protect sigframe execfault efault pdeath signalfd mknod binder binderwork binderfreeze binderfs bindersg binderctx binderhost selinuxfs; do
    "$CC" --target="$TARGET" -O2 -Wall -Werror -static -DTEST_POLICY="\"$POLICY\"" -Wl,--image-base=0x400000 -o "$OUT/$p" "$HERE/src/$p.c"
    "$CC" --target="$TARGET" -O2 -Wall -Werror -static -DTEST_POLICY="\"$POLICY\"" -o "$OUT/low/$p" "$HERE/src/$p.c"
done
