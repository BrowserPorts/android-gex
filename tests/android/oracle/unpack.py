#!/usr/bin/env python3
# Unpack the logical partitions of an Android system image: the disk image
# an emulator system image ships as system.img, whose GPT has a `super`
# partition holding system, system_ext, product and vendor.
#
#   unpack.py SYSTEM_IMG OUT_DIR
#
# Writes OUT_DIR/<name>.img for each logical partition with any extents.
# The layout is liblp's (system/core/fs_mgr/liblp/include/liblp/metadata_format.h).
import os
import struct
import sys

SECTOR = 512


def super_offset(f):
    """The byte offset of the GPT partition named `super`."""
    f.seek(SECTOR)
    head = f.read(92)
    if head[:8] != b"EFI PART":
        sys.exit("no GPT in the image")
    entries_lba, count, size = struct.unpack_from("<QII", head, 72)
    f.seek(entries_lba * SECTOR)
    for _ in range(count):
        entry = f.read(size)
        name = entry[56:128].decode("utf-16-le").rstrip("\0")
        if name == "super":
            return struct.unpack_from("<Q", entry, 32)[0] * SECTOR
    sys.exit("no super partition in the image")


def main():
    image, out = sys.argv[1], sys.argv[2]
    f = open(image, "rb")
    base = super_offset(f)
    # The geometry block, its backup, then the metadata.
    f.seek(base + 4096)
    if struct.unpack_from("<I", f.read(4096), 0)[0] != 0x616C4467:
        sys.exit("no logical partition geometry in super")
    f.seek(base + 4096 * 3)
    header = f.read(256)
    magic, _major, _minor, header_size = struct.unpack_from("<IHHI", header, 0)
    if magic != 0x414C5030:
        sys.exit("no logical partition metadata in super")
    tables_size = struct.unpack_from("<I", header, 44)[0]
    (p_off, p_num, p_size), (e_off, e_num, e_size) = (struct.unpack_from("<III", header, 80 + 12 * i) for i in range(2))
    f.seek(base + 4096 * 3 + header_size)
    tables = f.read(tables_size)
    extents = [struct.unpack_from("<QIQI", tables, e_off + i * e_size) for i in range(e_num)]
    os.makedirs(out, exist_ok=True)
    for i in range(p_num):
        name, _attrs, first, num, _group = struct.unpack_from("<36sIIII", tables, p_off + i * p_size)
        name = name.rstrip(b"\0").decode()
        if not num:
            continue
        with open(os.path.join(out, name + ".img"), "wb") as o:
            for sectors, kind, data, _source in extents[first : first + num]:
                if kind != 0:  # not a linear extent: a hole
                    o.seek(sectors * SECTOR, 1)
                    continue
                f.seek(base + data * SECTOR)
                left = sectors * SECTOR
                while left:
                    block = f.read(min(left, 1 << 22))
                    o.write(block)
                    left -= len(block)
        print(name, os.path.getsize(os.path.join(out, name + ".img")))


main()
