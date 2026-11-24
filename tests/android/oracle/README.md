# The Android oracle

Scripts that run Android 17's own userland under gexc and compare it with the
same programs on a real arm64 Linux kernel. The Android system image is the
test oracle: it shows what gex must do, and it is never part of gex.

You supply:

- the Android 17 arm64 emulator system image
  (`system-images;android-37.0;default;arm64-v8a`);
- an arm64 Linux host (or virtual machine) with root through `sudo`,
  `python3`, `rsync` and `unzip`, to unpack the image and as the reference
  the comparisons are made against;
- the Android NDK, for `tests/android/build.sh` and `swiftshader.sh`;
- for a boot on macOS, a case-sensitive APFS volume (the image has names
  that differ only in case) with some 5 GB free, and as much again for the
  translation cache.

gexc is built with the `big64` feature (a 64 GiB guest memory, which an
Android process needs):

```console
$ cargo build --release -p gexc --features big64
$ sh tests/android/build.sh
```

## A root tree from the image

On the arm64 Linux host:

```console
$ tests/android/oracle/root.sh IMAGE_DIR WORK
```

`IMAGE_DIR` is the system image as the SDK manager unpacks it (its
`system.img` is read). `WORK/root` becomes the tree: the image's partitions,
every APEX's payload where apexd would mount it, and the linker
configuration the image's own `linkerconfig` makes. It keeps the image's
owners, modes and SELinux labels, so on Linux gexc runs on it as root.
`WORK/owners.txt` lists every file's owner. `root.sh` leaves `/proc` and
`/dev` mounted in the tree; unmount both before removing it.

For macOS, copy the tree with its labels and give it its owners as the
attribute gexc reads on a host it is not root on (`user.gex.owner`):

```console
linux$ sudo tar --xattrs --xattrs-include='*' --one-file-system -C WORK/root -cf root.tar .
mac$ mkdir ROOT && tar -xpf root.tar -C ROOT
mac$ python3 tests/android/oracle/owners-to-xattr.py ROOT owners.txt
```

The image's own graphics are gfxstream's guest: its EGL, gralloc and
composer send their work to the emulator's host renderer over the goldfish
pipe, and keep buffers in the goldfish address space. gex has both devices
(`GEX_EMULATOR_HOST=1`) and its own gfxstream renderer
(`crates/gex-gfxstream`) on the host's OpenGL ES (Mesa), so the boot
configuration (`bootconfig`) leaves the image's choices as they are and
says OpenGL ES 3.1. `emugl.sh ROOT` checks that path without a
boot: the image's own EGL and GLES drivers, run in the root, draw and read
back through gex's renderer. `bootconfig.swiftshader` is the emulator's
guest rendering instead: `swiftshader.sh WORK ROOT` builds SwiftShader's Vulkan
driver with the NDK and puts it in the tree, and that configuration
chooses ANGLE over it. The configuration's `androidboot.logcat` is what
the emulator gives
when started without `-logcat` (`*:V`): the image's `goldfish-logcat`
service needs it to start, and writes to `/dev/hvc1`, which gex has with
`GEX_EMULATOR_HOST=1`.

## Booting

```console
$ tests/android/oracle/boot.sh ROOT OUT NAME [SECONDS]
```

On Linux, run it as root. It starts the image's init where its first stage
would hand over (`tests/android/src/firststage.c` makes the mounts and
device nodes first stage makes), with `fstab.gex` (no partitions to map,
`/data` in memory) and `init.gex.rc` (logcat into `OUT/gexlog-NAME`). It
writes init's log to `OUT/init-NAME.txt` and a line every 15 seconds to
`OUT/watch-NAME.txt`, and stops the boot before the machine runs out of
memory or disk; the header of `boot.sh` lists its settings.

A boot is slow: the guest's clock runs at an eighth of the host's, a first
boot translates everything (later ones find it in the cache), and the
machine should have nothing else heavy running.

With `GEX_HOST_FORWARD=5555` in its environment, the host's
127.0.0.1:5555 reaches the image's adbd:

```console
$ adb connect 127.0.0.1:5555
$ adb -s 127.0.0.1:5555 shell ps -A
```

Commands take minutes, at the guest's pace.

## Comparisons with Linux

Each runs the same thing natively in a chroot of the tree on the arm64 Linux
host and under gexc, and prints the differences. They need the Linux host
and root.

| Script | Compares |
|---|---|
| `compare.sh` | the shell command lines in `commands.txt` |
| `art.sh` | a Java program (`Hello.java`) on the image's ART |
| `servicemanager.sh` | the image's servicemanager, called over binder |
| `service.sh` | one of the image's daemons, started as init would |
| `init.sh` | the image's init, as `boot.sh` runs it |
| `xtables.sh` | iptables rule sets restored and saved (`xtables/`) |
| `iprules.sh` | policy routing rules (`iprules.txt`) |

`ext4-fixture.sh` makes the ext4 image the kernel's tests read, and
`selinux-ask.py` and `selinux-reload.py` ask a Linux kernel's SELinux the
questions the kernel's SELinux tests replay.
