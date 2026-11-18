#!/usr/bin/env python3
# Keep a tree's owners where gex reads them on a host it is not root on:
# the host attribute user.gex.owner, "uid gid", on every file (symbolic
# links included, where the host keeps attributes on them, as macOS does).
#
#   owners-to-xattr.py ROOT OWNERS
#
# OWNERS has a line a file, "uid gid ./path", as
#   find . -xdev -printf "%U %G %p\n"
# prints it in the tree the owners were read from (as root, where they are
# kept). For a tree unpacked by a user who could not keep them (an Android
# image on a Mac); gex then says them (crates/gex-kernel/src/vfs/hostfs.rs,
# OWNER_ATTR).
import ctypes
import ctypes.util
import os
import sys

NAME = b"user.gex.owner"

def main():
    root, owners = sys.argv[1], sys.argv[2]
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    darwin = sys.platform == "darwin"
    if darwin:
        # setxattr(path, name, value, size, position, options)
        XATTR_NOFOLLOW = 0x0001
        def put(path, value):
            return libc.setxattr(path, NAME, value, len(value), 0, XATTR_NOFOLLOW)
    else:
        def put(path, value):
            return libc.lsetxattr(path, NAME, value, len(value), 0)
    done = failed = 0
    with open(owners, "rb") as f:
        for line in f:
            line = line.rstrip(b"\n")
            if not line:
                continue
            uid, gid, rel = line.split(b" ", 2)
            path = os.path.join(root.encode(), rel[2:] if rel.startswith(b"./") else rel) if rel != b"." else root.encode()
            value = uid + b" " + gid
            ok = put(path, value) == 0
            if not ok and ctypes.get_errno() == 13 and not os.path.islink(path):
                # The host asks for write permission to set an attribute:
                # given for the moment, the mode then as it was.
                mode = os.lstat(path).st_mode & 0o7777
                os.chmod(path, mode | 0o200)
                ok = put(path, value) == 0
                os.chmod(path, mode)
            if not ok:
                failed += 1
                if failed <= 5:
                    print("could not set", path.decode(errors="replace"), os.strerror(ctypes.get_errno()), file=sys.stderr)
            else:
                done += 1
    print(f"{done} owners kept, {failed} not")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
