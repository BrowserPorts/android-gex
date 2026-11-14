#!/bin/sh
# Run a Java program on the image's own ART both ways, natively in a chroot
# of the root and under gexc, and compare what it prints.
#
#   art.sh ROOT
#
# ROOT is root.sh's. Hello.java beside this script is compiled with javac
# and turned into a dex jar with d8 (D8_JAR: the d8.jar of an Android SDK's
# build-tools). ART runs it with its interpreter, on the core libraries
# alone and no boot image: its JIT maps a 64 MiB file below 4 GiB by trial,
# which costs gexc a copy of the file each try.
#
# Needs an arm64 Linux host, root through sudo, a JDK, and a gexc built
# with the big64 feature (GEXC).
set -eu
ROOT=$(CDPATH='' cd -- "$1" && pwd)
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../../target/big64/release/gexc}
: "${D8_JAR:?set D8_JAR to an Android SDK build-tools d8.jar}"

work=$(mktemp -d)
javac -source 8 -target 8 -nowarn -d "$work" "$HERE/Hello.java" 2>/dev/null
java -cp "$D8_JAR" com.android.tools.r8.D8 --min-api 30 --output "$work/hello.jar" "$work"/Hello*.class
sudo mkdir -p "$ROOT/data/local/tmp"
sudo cp "$work/hello.jar" "$ROOT/data/local/tmp/hello.jar"
rm -rf "$work"

A=/apex/com.android.art/javalib
BCP=$A/core-oj.jar:$A/core-libart.jar:$A/okhttp.jar:$A/bouncycastle.jar:$A/apache-xml.jar:/apex/com.android.i18n/javalib/core-icu4j.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar
ENVS="PATH=/system/bin:/apex/com.android.art/bin ANDROID_ROOT=/system ANDROID_DATA=/data ANDROID_ART_ROOT=/apex/com.android.art ANDROID_I18N_ROOT=/apex/com.android.i18n ANDROID_TZDATA_ROOT=/apex/com.android.tzdata"
VM=/apex/com.android.art/bin/dalvikvm64
set -- "-Xbootclasspath:$BCP" -Xusejit:false -Xint -cp /data/local/tmp/hello.jar Hello

mountpoint -q "$ROOT/proc" || sudo mount -t proc proc "$ROOT/proc"
mountpoint -q "$ROOT/dev" || sudo mount --bind /dev "$ROOT/dev"
native=$(sudo timeout 120 env -i $ENVS /usr/sbin/chroot "$ROOT" $VM "$@" 2>/dev/null) || true
args=""
for e in $ENVS; do args="$args --env $e"; done
gex=$(cd "$ROOT" && timeout 900 "$GEXC" run --argv0 $VM --uid 0 --mem64 $args --sysroot "$ROOT" "$ROOT$VM" "$@" 2>/dev/null) || true
if [ -n "$native" ] && [ "$native" = "$gex" ]; then
    printf '%s\n' "$gex"
    echo "PASS art"
else
    echo "FAIL art"
    echo "native:"
    printf '%s\n' "$native"
    echo "gex:"
    printf '%s\n' "$gex"
    exit 1
fi
