#!/usr/bin/env python3
# Write ROOT/apex/apex-info-list.xml for a root whose APEX payloads are
# unpacked under ROOT/apex/<name>, as apexd writes it when it activates
# them. linkerconfig reads it to give each APEX its linker namespace.
#
#   apexinfo.py ROOT
import os
import sys


def varint(b, i):
    v = shift = 0
    while True:
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        shift += 7
        if not c & 0x80:
            return v, i


def manifest(path):
    """The name and version of an apex_manifest.pb (fields 1 and 2)."""
    b = open(path, "rb").read()
    i, name, version = 0, "", 0
    while i < len(b):
        key, i = varint(b, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            v, i = varint(b, i)
            if field == 2:
                version = v
        elif wire == 2:
            n, i = varint(b, i)
            if field == 1:
                name = b[i : i + n].decode()
            i += n
        elif wire == 1:
            i += 8
        elif wire == 5:
            i += 4
        else:
            break
    return name, version


root = sys.argv[1]
lines = ['<?xml version="1.0" encoding="utf-8"?>', "<apex-info-list>"]
for d in sorted(os.listdir(os.path.join(root, "apex"))):
    pb = os.path.join(root, "apex", d, "apex_manifest.pb")
    if not os.path.isfile(pb):
        continue
    name, version = manifest(pb)
    partition, path = "SYSTEM", "/system/apex/%s.apex" % d
    for part in ("system_ext", "product", "vendor"):
        if os.path.exists(os.path.join(root, part, "apex", d + ".apex")):
            partition, path = part.upper(), "/%s/apex/%s.apex" % (part, d)
    lines.append(
        '    <apex-info moduleName="%s" modulePath="%s" preinstalledModulePath="%s" versionCode="%d" versionName="" '
        'isFactory="true" isActive="true" lastUpdateMillis="0" provideSharedApexLibs="false" partition="%s"></apex-info>'
        % (name, path, path, version, partition)
    )
lines.append("</apex-info-list>")
open(os.path.join(root, "apex", "apex-info-list.xml"), "w").write("\n".join(lines) + "\n")
print(len(lines) - 3, "apexes")
