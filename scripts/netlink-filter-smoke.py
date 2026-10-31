#!/usr/bin/env python3 -I
"""Drive netlink unicast and broadcast delivery through a socket filter.

Attaches a classic BPF filter that loads a byte relative to the network
header, then requests one link via NETLINK_ROUTE (a unicast reply) and
listens for a uevent broadcast triggered by writing "change" to the loopback
device's uevent file. Those are the two paths CVE-2026-99211 changes.
Needs root for the uevent trigger. Usage: netlink-filter-smoke.py [COUNT]
"""
import ctypes
import os
import select
import socket
import struct
import sys
import time

NETLINK_ROUTE = 0
NETLINK_KOBJECT_UEVENT = 15
RTM_GETLINK = 18
NLM_F_REQUEST = 1
SO_ATTACH_FILTER = 26
SKF_NET_OFF = -0x100000

# ldb [SKF_NET_OFF + 0]; ret #65535   (read via the network header, accept all)
FILTER = [(0x30, 0, 0, SKF_NET_OFF & 0xFFFFFFFF), (0x06, 0, 0, 0xFFFF)]


def attach_filter(sock):
    insns = (ctypes.c_char * (8 * len(FILTER)))()
    for i, (code, jt, jf, k) in enumerate(FILTER):
        struct.pack_into("=HBBI", insns, 8 * i, code, jt, jf, k)
    prog = struct.pack("HL", len(FILTER), ctypes.addressof(insns))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, prog)
    return insns


def unicast_once():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
    keep = attach_filter(s)
    s.bind((0, 0))
    # nlmsghdr + ifinfomsg asking for ifindex 1 (lo), a non-dump request.
    ifinfo = struct.pack("BxHiII", socket.AF_UNSPEC, 0, 1, 0, 0)
    hdr = struct.pack("IHHII", 16 + len(ifinfo), RTM_GETLINK, NLM_F_REQUEST, 1, 0)
    s.send(hdr + ifinfo)
    s.settimeout(5)
    data = s.recv(65536)
    s.close()
    del keep
    msg_type = struct.unpack_from("IHHII", data)[1]
    if msg_type != 16:  # RTM_NEWLINK
        raise SystemExit(f"unexpected netlink reply type {msg_type}")


def broadcast_once():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_KOBJECT_UEVENT)
    keep = attach_filter(s)
    s.bind((0, 1))
    with open("/sys/class/net/lo/uevent", "w") as f:
        f.write("change\n")
    ready, _, _ = select.select([s], [], [], 5)
    if not ready:
        raise SystemExit("no uevent broadcast received")
    data = s.recv(65536)
    s.close()
    del keep
    if b"change@" not in data:
        raise SystemExit(f"unexpected uevent payload {data[:40]!r}")


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    start = time.monotonic()
    for _ in range(count):
        unicast_once()
        broadcast_once()
    print(f"{count} filtered netlink unicast replies and {count} broadcasts ok "
          f"in {time.monotonic() - start:.1f}s")


if __name__ == "__main__":
    main()
