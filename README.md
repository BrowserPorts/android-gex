# android-gex

android-gex is [stellite-gex](https://github.com/BrowserPorts/stellite-gex)
with an Android personality: gex's Linux kernel and AArch64 translator,
extended to run Android's userland. gex runs unmodified programs by
translating their machine code to WebAssembly and running it against its own
kernel, written in Rust.

- Parent: [stellite-gex](https://github.com/BrowserPorts/stellite-gex),
  Stellite's fork of [HeyPuter/gex](https://github.com/HeyPuter/gex)
- Sibling: [unixnu-gex](https://github.com/BrowserPorts/unixnu-gex), the same
  base with a Darwin personality
- Submodule: [mesa-stellite](https://github.com/BrowserPorts/mesa-stellite),
  at `third_party/mesa`

The Android work is on the branch `android`. The rest of the tree is
stellite-gex, whose README covers the engine, the page and Wine.

## What it adds

Kernel interfaces that Android needs and gex did not have:

- binder and binderfs
- selinuxfs and a policy engine
- signalfd, userfaultfd and seccomp
- mount namespaces with propagation and bind mounts
- loop devices, read-only ext4 and a subset of device-mapper
- cgroup v1 and v2
- eBPF: maps, program load, an interpreter and cgroup attach
- netlink: uevent, route rules, xfrm and nfnetlink_log
- legacy iptables
- a 2D virtio-gpu DRM device, and vsock

It also makes the arm64 translator answer as the hardware does: floating
point, fault retry and per-page access checks.

The work is checked by booting a prebuilt Android 17 arm64 emulator image.
That image is a test oracle only. This repository holds no Android image and
ships none.

## Building

```sh
make gexc
make check
```

`make help` lists the other targets. Android's processes need a large guest
memory, which the native host gives with the `big64` feature, a 64 GiB guest
memory:

```sh
cargo build --release -p gexc --features big64
```

What the build needs:

- the Rust toolchain that `rust-toolchain.toml` names
- the submodules `third_party/mesa`, `third_party/opengl-registry` and
  `third_party/vk-gl-cts`
- the Android NDK, for the test programs (r25 is the one used)
- on macOS, the tools `scripts/host-env.sh` names

No AOSP checkout is needed.

## Running the tests

The test programs in `tests/android/src` are small static C programs linked
against bionic. They need neither Android's linker nor a system image.

```sh
sh tests/android/build.sh
GEXC=target/release/gexc sh tests/android/run.sh
```

`build.sh` finds the NDK through `ANDROID_NDK_HOME`. `run.sh` runs each
program under gexc and checks what it prints and how it exits. With
`GEXC=native` it runs them as they are, on an arm64 Linux host, which is the
reference they are written against. You supply that host.

Some kernel tests and four of the programs (`selinuxfs`, `procattr`,
`filelabel` and `ext4mount`) take compiled inputs that are built from sources
in this tree rather than kept in it. On a Linux host with `checkpolicy`,
`e2fsprogs` and root through `sudo`:

```sh
sh tests/fixtures.sh OUT
GEX_TEST_FIXTURES=OUT cargo test -p gex-kernel
GEX_TEST_FIXTURES=OUT sh tests/android/build.sh
```

Without `GEX_TEST_FIXTURES` the kernel tests that need them say they are
skipped, and `build.sh` leaves those four programs out.

`tests/android/oracle` boots Android's own userland under gexc from an image
you supply, an Android 17 arm64 emulator system image. Its README lists what
it needs and how to run it.

## Status

Working:

- 95 small bionic C programs, each run at two link addresses, pass on the
  native host and match an arm64 Linux host
- AOSP's `binderDriverInterfaceTest` passes, 20 of 20
- the image's servicemanager answers
- the image's init boots on the macOS native host: apexd activates the
  image's 50 APEXes, then logd, netd, the HALs and the zygote start, and
  system_server starts its core services
- adb on the host connects to the guest and runs shell commands, through
  `GEX_HOST_FORWARD`

Not working:

- Android does not reach `boot_completed`, and there is no display
- boots are slow, and the guest's clock is slowed to suit
- much of the Android kernel work is in the native host only, and the browser
  host lacks it
- there is no ashmem, and memory shared between processes is kept coherent by
  copying, not truly shared

## Licence

GNU Affero General Public License, version 3 only (`LICENSE`). gex is
Copyright (C) 2026 Puter Technologies Inc. The Android work in this fork is
Copyright (C) 2026 Ryan Wilson. Third-party code keeps its own licence, and
`NOTICE` lists it.

## Contributing

This repository takes no pull requests and no issues. Both are turned off
for the BrowserPorts organisation.
