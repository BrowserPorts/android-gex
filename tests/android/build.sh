#!/bin/sh
# Build the Android test programs with the NDK into bin/.
#
# They are static, position-independent executables: bionic linked in, so
# they need neither Android's linker nor a system image, and loaded where
# the kernel puts them (a static executable linked at the NDK's default
# base lies in gex's reserved low region).
#
# The NDK is ANDROID_NDK_HOME, or the newest one under the SDK
# (ANDROID_HOME, or the SDK's default place on this host).
set -eu

HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
OUT=$HERE/bin
TARGET=${GEX_ANDROID_TARGET:-aarch64-linux-android30}
mkdir -p "$OUT"

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

for p in hello tagged thread simd exclusive; do
    "$CC" --target="$TARGET" -O2 -Wall -Werror -static-pie -o "$OUT/$p" "$HERE/src/$p.c"
done
