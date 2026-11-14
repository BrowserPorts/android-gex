#!/usr/bin/env python3
"""Ask a kernel's SELinux what it makes of things, through selinuxfs.

    ask.py < questions > answers

Each line of standard input is a question; the same line comes back with the
kernel's answer after " => ":

    context <context>                      the context as the kernel writes it
    access <scon> <tcon> <class> [<perms>] allowed decided auditallow auditdeny flags
    create <scon> <tcon> <class> [<name>]  the context a new object gets
    member <scon> <tcon> <class>           the context of a polyinstantiated member
    relabel <scon> <tcon> <class>          the context a relabel gives
    validatetrans <old> <new> <class> <task>  ok, if the relabel is one the class's rules let that task make
    read <file>                            a file of selinuxfs, or of /proc/self/attr
    bool <name> <0|1>                      set a boolean, and commit it

A class is given by name. An answer the kernel refuses is "errno <name>".
The policy sequence number is left out of access answers: it is how many
policies this boot has loaded. Needs root and selinuxfs at /sys/fs/selinux.

The kernel has to have SELinux on. Ubuntu's has it built in and off: boot
it once with lsm=landlock,lockdown,yama,integrity,selinux on its command
line (a boot menu entry of its own, chosen for one boot with grub-reboot),
mount selinuxfs if nothing has, and write a policy to /sys/fs/selinux/load.
A policy loads only if it has the kernel's initial SIDs and a genfscon for
selinuxfs. Nothing is enforced unless enforce is written, and a reboot
without the option undoes it all.
"""
import errno
import os
import sys

FS = "/sys/fs/selinux"


def transact(name, text):
    fd = os.open(f"{FS}/{name}", os.O_RDWR)
    try:
        os.write(fd, text.encode())
        return os.read(fd, 65536).rstrip(b"\0").decode()
    finally:
        os.close(fd)


def class_number(name):
    with open(f"{FS}/class/{name}/index") as f:
        return f.read().strip()


def answer(line):
    kind, *args = line.split()
    if kind == "context":
        return transact("context", args[0])
    if kind == "access":
        perms = args[3] if len(args) > 3 else "ffffffff"
        allowed, decided, auditallow, auditdeny, _seqno, flags = transact("access", f"{args[0]} {args[1]} {class_number(args[2])} {perms}").split()
        return f"{allowed} {decided} {auditallow} {auditdeny} {flags}"
    if kind in ("create", "member", "relabel"):
        text = f"{args[0]} {args[1]} {class_number(args[2])}"
        if len(args) > 3:
            text += " " + args[3]
        return transact(kind, text)
    if kind == "validatetrans":
        fd = os.open(f"{FS}/validatetrans", os.O_WRONLY)
        try:
            os.write(fd, f"{args[0]} {args[1]} {class_number(args[2])} {args[3]}".encode())
        finally:
            os.close(fd)
        return "ok"
    if kind == "bool":
        with open(f"{FS}/booleans/{args[0]}", "w") as f:
            f.write(args[1])
        with open(f"{FS}/commit_pending_bools", "w") as f:
            f.write("1")
        with open(f"{FS}/booleans/{args[0]}") as f:
            return f.read().strip()
    if kind == "read":
        path = args[0] if args[0].startswith("/") else f"{FS}/{args[0]}"
        with open(path, "rb") as f:
            return f.read().rstrip(b"\0\n").decode()
    raise ValueError(kind)


for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith("#"):
        print(line)
        continue
    try:
        print(f"{line} => {answer(line)}")
    except OSError as e:
        print(f"{line} => errno {errno.errorcode.get(e.errno, e.errno)}")
