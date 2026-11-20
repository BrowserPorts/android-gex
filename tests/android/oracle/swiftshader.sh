#!/bin/sh
# Build SwiftShader's Vulkan driver for Android arm64 with the NDK and put
# it into the oracle's root tree as /vendor/lib64/hw/vulkan.pastel.so, so
# that the emulator image's surfaceflinger has a GLES with no host GPU:
# ANGLE (in the image) over SwiftShader, chosen at boot by
#   androidboot.hardwareegl = "angle"
#   androidboot.hardware.vulkan = "pastel"
#   androidboot.opengles.version = "196610"
# (bootconfig, which boot.sh uses, says so). The
# image's own GLES (libEGL_emulation, vulkan.ranchu) is the emulator's
# host-GPU pipe, which gex does not have.
#
#   swiftshader.sh WORK ROOT
#
# WORK holds the checkout, the build and the headers; ROOT is the oracle's
# root tree (its owners kept as user.gex.owner, labels as security.selinux).
# The driver is the oracle's alone and is never committed.
#
# SwiftShader builds for Android with the NDK (ANDROID_NDK_BUILD) but its
# CMake has no Android case; two small patches add one, as src/Android.bp
# builds it for a device: the Android memory source, and the device's own
# libnativewindow, libcutils and libsync (the NDK's stubs lack the VNDK
# functions it calls). The Android headers it includes come from AOSP at
# the image's tag.
set -eu
WORK=${1:?work directory}
ROOT=${2:?the oracle root}
TAG=android-17.0.0_r1
NDK=${ANDROID_NDK_HOME:-$(find "$HOME/Library/Android/sdk/ndk" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)}
case $(uname -s) in Darwin) HOST=darwin-x86_64 ;; *) HOST=linux-x86_64 ;; esac
S=$WORK/swiftshader
B=$WORK/swiftshader-build
I=$WORK/swiftshader-android-include
mkdir -p "$WORK"

[ -d "$S" ] || git clone -q --depth 1 https://github.com/google/swiftshader "$S"

# The Android platform case, and the Android pieces of the driver.
python3 - "$S" <<'EOF'
import sys
s_dir = sys.argv[1]
def patch(path, old, new):
    p = f"{s_dir}/{path}"
    s = open(p).read()
    if new in s:
        return
    assert s.count(old) == 1, (path, old[:40])
    open(p, "w").write(s.replace(old, new))
patch("CMakeLists.txt",
      'elseif(FUCHSIA)\n    target_compile_definitions(vk_base INTERFACE "VK_USE_PLATFORM_FUCHSIA")\nelse()',
      'elseif(FUCHSIA)\n    target_compile_definitions(vk_base INTERFACE "VK_USE_PLATFORM_FUCHSIA")\n'
      'elseif(ANDROID)\n    target_compile_definitions(vk_base INTERFACE "VK_USE_PLATFORM_ANDROID_KHR")\nelse()')
patch("src/Vulkan/CMakeLists.txt",
      'add_library(vk_swiftshader SHARED\n    ${VULKAN_SRC_FILES}\n)',
      'if(ANDROID)\n    list(APPEND VULKAN_SRC_FILES VkDeviceMemoryExternalAndroid.cpp)\n'
      '    list(APPEND VULKAN_LINKER_FLAGS "-Wl,-Bsymbolic")\nendif()\n\n'
      'add_library(vk_swiftshader SHARED\n    ${VULKAN_SRC_FILES}\n)\n'
      'if(ANDROID)\n    target_compile_definitions(vk_swiftshader PRIVATE "SWIFTSHADER_EXTERNAL_MEMORY_ANDROID_HARDWARE_BUFFER")\n'
      '    target_link_libraries(vk_swiftshader PRIVATE\n'
      '        "${ANDROID_SYSTEM_LIB64}/libnativewindow.so"\n'
      '        "${ANDROID_SYSTEM_LIB64}/libcutils.so"\n'
      '        "${ANDROID_SYSTEM_LIB64}/libsync.so"\n'
      '        log)\nendif()')
patch("src/Vulkan/CMakeLists.txt",
      'elseif(FUCHSIA)\n    set(VULKAN_API_LIBRARY_NAME "libvulkan.so")\nelse()',
      'elseif(FUCHSIA)\n    set(VULKAN_API_LIBRARY_NAME "libvulkan.so")\n'
      'elseif(ANDROID)\n    set(VULKAN_API_LIBRARY_NAME "vulkan.pastel.so")\nelse()')
EOF

# Android's headers, from AOSP at the image's tag.
fetch() { # project path-in-project dest
    mkdir -p "$(dirname "$I/$3")"
    [ -s "$I/$3" ] || curl -sf "https://android.googlesource.com/platform/$1/+/refs/tags/$TAG/$2?format=TEXT" | base64 -d > "$I/$3"
}
fetch frameworks/native vulkan/include/hardware/hwvulkan.h hardware/hwvulkan.h
fetch frameworks/native vulkan/include/vulkan/vk_android_native_buffer.h vulkan/vk_android_native_buffer.h
fetch frameworks/native libs/nativewindow/include/vndk/hardware_buffer.h vndk/hardware_buffer.h
for h in hardware.h gralloc.h gralloc1.h fb.h; do
    fetch hardware/libhardware "include/hardware/$h" "hardware/$h"
done
fetch system/core libcutils/include/cutils/native_handle.h cutils/native_handle.h
for h in graphics.h graphics-base.h graphics-base-v1.0.h graphics-base-v1.1.h graphics-base-v1.2.h graphics-sw.h; do
    fetch system/core "libsystem/include/system/$h" "system/$h"
done
fetch system/core libsync/include/sync/sync.h sync/sync.h
fetch system/core libsync/include/ndk/sync.h ndk/sync.h
# The VNDK header's Android 15 additions need a newer NDK than r25, and
# the driver does not call them: kept to what came before.
python3 - "$I/vndk/hardware_buffer.h" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read()
# From the comment before the typedef that ends "} AHardwareBufferLongOptions;".
end = s.find("} AHardwareBufferLongOptions;")
cut = s.rfind("/**", 0, s.rfind("typedef struct", 0, end)) if end != -1 else -1
if cut != -1 and "__END_DECLS" in s[cut:]:
    s = s[:cut] + "\n__END_DECLS\n\n#endif /* ANDROID_VNDK_NATIVEWINDOW_AHARDWAREBUFFER_H */\n"
    open(p, "w").write(s)
EOF
# The version string SwiftShader's Android build generates from git.
python3 "$S/src/commit_id.py" gen "$I/commit.h"
sed -i.bak "s/\"b'\([^']*\)'\"/\"\1\"/g" "$I/commit.h" && rm -f "$I/commit.h.bak"

# The build. AHARDWAREBUFFER_FORMAT_YCbCr_P210 is newer than NDK r25.
mkdir -p "$B"
flags="-O2 -DNDEBUG -isystem '$I' -DAHARDWAREBUFFER_FORMAT_YCbCr_P210=0x3c"
(cd "$B" && cmake -G Ninja "$S" \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS_RELEASE="$flags" -DCMAKE_C_FLAGS_RELEASE="$flags" \
    -DANDROID_SYSTEM_LIB64="$ROOT/system/lib64" \
    -DSWIFTSHADER_BUILD_TESTS=OFF -DSWIFTSHADER_BUILD_BENCHMARKS=OFF \
    -DSWIFTSHADER_WARNINGS_AS_ERRORS=OFF -DSWIFTSHADER_BUILD_PVR=OFF >/dev/null)
(cd "$B" && nice ninja -j "${JOBS:-3}" vk_swiftshader)

# Into the tree, as the image's own Vulkan driver is kept there.
D=$ROOT/vendor/lib64/hw/vulkan.pastel.so
"$NDK/toolchains/llvm/prebuilt/$HOST/bin/llvm-strip" --strip-debug -o "$D" "$B/bin/vulkan.pastel.so"
chmod 644 "$D"
if [ "$(uname -s)" = Darwin ]; then
    xattr -w security.selinux "u:object_r:same_process_hal_file:s0" "$D"
    xattr -w user.gex.owner "0 0" "$D"
else
    setfattr -n security.selinux -v "u:object_r:same_process_hal_file:s0" "$D" 2>/dev/null || true
fi
echo "swiftshader: $D"
