#!/bin/sh
# Build AOSP's own tests of the binder driver into ../bin/aosp/, from an
# AOSP checkout: AOSP=<its path>, at the release this fork follows
# (android-17.0.0_r1). Nothing of AOSP's is kept here; the sources are
# compiled where they lie.
#
# binderDriverInterfaceTest is the driver's protocol by ioctl. It takes two
# things from libbinder, a constant and a question about the driver's
# features, which shim/ answers the same way, so it is built without
# libbinder: static, with the NDK's googletest. The kernel's binder header
# is the checkout's (bionic's copy), since an NDK's may be older than the
# test.
#
# The NDK is found as ../build.sh finds it.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
OUT=$HERE/../bin/aosp
TARGET=${GEX_ANDROID_TARGET:-aarch64-linux-android30}
: "${AOSP:?set AOSP to an AOSP checkout}"
TESTS=$AOSP/frameworks/native/libs/binder/tests
UAPI=$AOSP/bionic/libc/kernel/uapi
[ -f "$TESTS/binderDriverInterfaceTest.cpp" ] || { echo "tests/android/aosp/build.sh: no frameworks/native in $AOSP" >&2; exit 1; }
[ -f "$UAPI/linux/android/binder.h" ] || { echo "tests/android/aosp/build.sh: no bionic in $AOSP" >&2; exit 1; }

case $(uname -s) in
Darwin) host=darwin-x86_64 sdk=${ANDROID_HOME:-$HOME/Library/Android/sdk} ;;
*) host=linux-x86_64 sdk=${ANDROID_HOME:-$HOME/Android/Sdk} ;;
esac
ndk=${ANDROID_NDK_HOME:-}
if [ -z "$ndk" ]; then
    ndk=$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1)
fi
if [ -z "$ndk" ] || [ ! -d "$ndk/toolchains/llvm/prebuilt/$host/bin" ]; then
    echo "tests/android/aosp/build.sh: no NDK (set ANDROID_NDK_HOME)" >&2
    exit 1
fi
CXX=$ndk/toolchains/llvm/prebuilt/$host/bin/clang++
GTEST=$ndk/sources/third_party/googletest
[ -f "$GTEST/src/gtest-all.cc" ] || { echo "tests/android/aosp/build.sh: no googletest in $ndk" >&2; exit 1; }

mkdir -p "$OUT/uapi/linux/android"
# Only the binder header: the rest of the kernel's are the NDK's.
cp "$UAPI/linux/android/binder.h" "$OUT/uapi/linux/android/binder.h"
[ -f "$OUT/gtest-all.o" ] || "$CXX" --target="$TARGET" -O2 -std=c++17 -I"$GTEST/include" -I"$GTEST" -c -o "$OUT/gtest-all.o" "$GTEST/src/gtest-all.cc"
"$CXX" --target="$TARGET" -O2 -std=gnu++20 -static -Wl,--image-base=0x400000 \
    -I"$OUT/uapi" -I"$HERE/shim" -I"$GTEST/include" \
    -o "$OUT/binderDriverInterfaceTest" "$TESTS/binderDriverInterfaceTest.cpp" "$OUT/gtest-all.o"
