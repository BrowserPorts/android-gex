#!/bin/sh
# Run a Java program on the image's own ART both ways, natively in a chroot
# of the root and under gexc, and compare what it prints.
#
#   art.sh ROOT
#
# ROOT is root.sh's. Hello.java beside this script is compiled with javac
# and turned into a dex jar with d8 (D8_JAR: the d8.jar of an Android SDK's
# build-tools). ART runs it on the core libraries alone and no boot image,
# and without its JIT, which maps a 64 MiB file below 4 GiB by trial and
# costs gexc a copy of the file each try. Twice: with the portable
# interpreter (-Xint), and with the one written in assembly, which takes a
# null reference from the fault its load raises, as compiled code does.
#
# Needs an arm64 Linux host, root through sudo, a JDK, and a gexc built
# with the big64 feature (GEXC).
set -eu
ROOT=$(CDPATH='' cd -- "$1" && pwd)
HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
GEXC=${GEXC:-$HERE/../../../target/big64/release/gexc}
# As compare.sh: the same random bytes for each program in every run, so
# that gexc finds its translations made, and a name for the build.
export GEX_FIXED_RANDOM="${GEX_FIXED_RANDOM:-1}"
# Room for what an image's programs come to: the cache keeps 4 GiB unless
# told, and a boot's translations and a comparison's push one another out.
export GEX_CACHE_MAX_BYTES="${GEX_CACHE_MAX_BYTES:-34359738368}"
if [ -z "${GEX_CACHE_BUILD:-}" ] && name=$(sh "$HERE/cache-id.sh" "$GEXC" 2>/dev/null); then
    export GEX_CACHE_BUILD="$name"
fi
# gexc runs as root, as the native side does: the root keeps the image's
# owners (root.sh), and a gexc that is the host's root says them.
gexc() {
    sudo env GEX_FIXED_RANDOM="$GEX_FIXED_RANDOM" GEX_CACHE_MAX_BYTES="$GEX_CACHE_MAX_BYTES" \
        ${GEX_CACHE_BUILD:+GEX_CACHE_BUILD="$GEX_CACHE_BUILD"} ${GEX_TIME_SCALE:+GEX_TIME_SCALE="$GEX_TIME_SCALE"} "$@"
}
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
mountpoint -q "$ROOT/proc" || sudo mount -t proc proc "$ROOT/proc"
mountpoint -q "$ROOT/dev" || sudo mount --bind /dev "$ROOT/dev"
args=""
for e in $ENVS; do args="$args --env $e"; done

status=0
for interp in -Xint ""; do
    name="art${interp:+ $interp}"
    set -- "-Xbootclasspath:$BCP" -Xusejit:false $interp -cp /data/local/tmp/hello.jar Hello
    native=$(sudo timeout 120 env -i $ENVS /usr/sbin/chroot "$ROOT" $VM "$@" 2>/dev/null) || true
    gex=$(cd "$ROOT" && gexc timeout 1800 "$GEXC" run --argv0 $VM --uid 0 --mem64 $args --sysroot "$ROOT" "$ROOT$VM" "$@" 2>/dev/null) || true
    if [ -n "$native" ] && [ "$native" = "$gex" ]; then
        printf '%s\n' "$gex"
        echo "PASS $name"
    else
        echo "FAIL $name"
        echo "native:"
        printf '%s\n' "$native"
        echo "gex:"
        printf '%s\n' "$gex"
        status=1
    fi
done
exit $status
