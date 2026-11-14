#!/usr/bin/env python3
"""What a kernel's SELinux makes of its own SIDs before a policy, with one,
and when another takes its place. As root, on a boot with SELinux on (as
selinux-ask.py says how) and no policy loaded yet:

    selinux-reload.py show <label>
    selinux-reload.py load <policy>
    selinux-reload.py become <a context of the loaded policy> <another policy>
"""
import os
import sys

FS = "/sys/fs/selinux"
NAMES = ["kernel", "security", "unlabeled", "file", "init", "any_socket", "port", "netif", "netmsg", "node", "devnull"]


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read().rstrip(b"\0\n").decode()
    except OSError as e:
        return f"errno {e.errno}"


def load(path):
    data = open(path, "rb").read()
    fd = os.open(f"{FS}/load", os.O_WRONLY)
    try:
        # In one write: the kernel takes no policy in pieces.
        os.write(fd, data)
    finally:
        os.close(fd)


def show(when):
    print(f"# {when}")
    print(f"current => {read('/proc/self/attr/current')}")
    print(f"prev => {read('/proc/self/attr/prev')}")
    for name in NAMES:
        print(f"initial_contexts/{name} => {read(f'{FS}/initial_contexts/{name}')}")
    for f in ["enforce", "policyvers", "mls", "deny_unknown", "reject_unknown"]:
        print(f"{f} => {read(f'{FS}/{f}')}")
    status = open(f"{FS}/status", "rb").read(20)
    print("status => " + " ".join(str(int.from_bytes(status[i:i + 4], "little")) for i in range(0, 20, 4)))


# show <label> | load <policy> | become <context> <policy>
what = sys.argv[1]
if what == "show":
    show(sys.argv[2])
elif what == "load":
    load(sys.argv[2])
    show(f"with {os.path.basename(sys.argv[2])}")
elif what == "become":
    # This process takes a context of the policy that is loaded, and is
    # looked at again once another policy has taken that one's place.
    context, second = sys.argv[2:4]
    try:
        with open("/proc/self/attr/current", "w") as f:
            f.write(context)
        print(f"setcon {context} => {read('/proc/self/attr/current')}")
    except OSError as e:
        print(f"setcon {context} => errno {e.errno}")
    load(second)
    show(f"with {os.path.basename(second)} in its place")
