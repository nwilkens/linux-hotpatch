#!/usr/bin/env python3 -I
"""Open TCP connections that carry an IPv4 Record Route option.

The listener stores such options on the request socket and hands them to the
child socket, so closing these connections runs the code CVE-2026-98432 patches.
Usage: tcp-ipopts-smoke.py HOST PORT [COUNT]
"""
import socket
import sys
import time

# Record Route: type 7, length 39, pointer 4, then 9 empty slots.
RECORD_ROUTE = bytes([7, 39, 4]) + bytes(36) + b"\x00"


def connect_once(host, port, with_options):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    if with_options:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, RECORD_ROUTE)
    s.connect((host, port))
    banner = s.recv(64)
    s.close()
    return banner


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    host, port = sys.argv[1], int(sys.argv[2])
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 200
    start = time.monotonic()
    for i in range(count):
        connect_once(host, port, with_options=True)
        if i % 4 == 0:
            connect_once(host, port, with_options=False)
    print(f"{count} connections with IP options to {host}:{port} ok "
          f"in {time.monotonic() - start:.1f}s")


if __name__ == "__main__":
    main()
