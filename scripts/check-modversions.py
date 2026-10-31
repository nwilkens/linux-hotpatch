#!/usr/bin/env python3
"""Compare a module's __versions CRCs with the exported-symbol CRCs in vmlinux.

kmod before 34 cannot parse the compact __versions layout (u32 next, u32 crc,
name), so kpatch-build's own check is skipped on kernels that use it.

usage: check-modversions.py <module.ko> <vmlinux>
"""
import mmap
import struct
import sys

SHT_SYMTAB = 2


class Elf:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.m = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        if self.m[:4] != b"\x7fELF" or self.m[4] != 2 or self.m[5] != 1:
            raise SystemExit(f"{path}: not a little-endian ELF64 file")
        shoff = struct.unpack_from("<Q", self.m, 0x28)[0]
        (shentsize, shnum, shstrndx) = struct.unpack_from("<HHH", self.m, 0x3A)
        self.sections = []
        for i in range(shnum):
            off = shoff + i * shentsize
            (name, typ, _flags, addr, offset, size, link, _info, _align, entsize) = (
                struct.unpack_from("<IIQQQQIIQQ", self.m, off)
            )
            self.sections.append((name, typ, addr, offset, size, link, entsize))
        strtab = self.sections[shstrndx]
        self.by_name = {}
        for sec in self.sections:
            self.by_name[self.cstr(strtab[3] + sec[0])] = sec

    def cstr(self, off):
        end = self.m.find(b"\0", off)
        return self.m[off:end].decode("ascii", "replace")

    def section(self, name):
        sec = self.by_name.get(name)
        if sec is None:
            raise SystemExit(f"missing section {name}")
        return sec

    def section_bytes(self, name):
        sec = self.section(name)
        return self.m[sec[3] : sec[3] + sec[4]]

    def addr_to_off(self, addr):
        for (_n, _t, saddr, offset, size, _l, _e) in self.sections:
            if saddr and saddr <= addr < saddr + size:
                return offset + addr - saddr
        raise SystemExit(f"address {addr:#x} not in any section")

    def symbols(self, wanted):
        found = {}
        for sec in self.sections:
            if sec[1] != SHT_SYMTAB:
                continue
            strtab = self.sections[sec[5]]
            for off in range(sec[3], sec[3] + sec[4], 24):
                (name, _info, _other, _shndx, value, _size) = struct.unpack_from(
                    "<IBBHQQ", self.m, off
                )
                sname = self.cstr(strtab[3] + name)
                if sname in wanted:
                    found[sname] = value
        missing = wanted - found.keys()
        if missing:
            raise SystemExit(f"vmlinux lacks symbols: {sorted(missing)}")
        return found


def legacy_layout(data):
    """Pre-6.13 entries are 64 bytes: u64 crc then a NUL-padded name."""
    if not data or len(data) % 64:
        return False
    for pos in range(0, len(data), 64):
        if data[pos + 4 : pos + 8] != b"\0\0\0\0" or b"\0" not in data[pos + 8 : pos + 64]:
            return False
    return True


def module_versions(ko):
    data = ko.section_bytes("__versions")
    out = {}
    if legacy_layout(data):
        for pos in range(0, len(data), 64):
            crc = struct.unpack_from("<Q", data, pos)[0]
            name = data[pos + 8 : pos + 64].split(b"\0", 1)[0].decode()
            out[name] = crc & 0xFFFFFFFF
        return out
    pos = 0
    while pos + 8 < len(data):
        (nxt, crc) = struct.unpack_from("<II", data, pos)
        if nxt == 0:
            break
        if nxt < 12 or nxt % 4 or pos + nxt > len(data):
            raise SystemExit(f"malformed __versions entry at {pos:#x}")
        name = data[pos + 8 : pos + nxt].split(b"\0", 1)[0].decode()
        out[name] = crc
        pos += nxt
    if not out:
        raise SystemExit("no symbol versions found in module")
    return out


def vmlinux_crcs(vm):
    syms = vm.symbols(
        {
            "__start___ksymtab", "__stop___ksymtab", "__start___kcrctab",
            "__start___ksymtab_gpl", "__stop___ksymtab_gpl", "__start___kcrctab_gpl",
        }
    )
    crcs = {}
    for suffix in ("", "_gpl"):
        start = syms["__start___ksymtab" + suffix]
        stop = syms["__stop___ksymtab" + suffix]
        crc_off = vm.addr_to_off(syms["__start___kcrctab" + suffix])
        i = 0
        for addr in range(start, stop, 12):
            off = vm.addr_to_off(addr)
            (_value_off, name_off) = struct.unpack_from("<ii", vm.m, off)
            name = vm.cstr(vm.addr_to_off(addr + 4 + name_off))
            crcs[name] = struct.unpack_from("<I", vm.m, crc_off + 4 * i)[0]
            i += 1
    return crcs


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    ko = Elf(sys.argv[1])
    vm = Elf(sys.argv[2])
    want = module_versions(ko)
    have = vmlinux_crcs(vm)
    bad = 0
    for name, crc in sorted(want.items()):
        got = have.get(name)
        if got is None:
            print(f"MISSING  {name}")
            bad += 1
        elif got != crc:
            print(f"MISMATCH {name} module={crc:#010x} vmlinux={got:#010x}")
            bad += 1
        else:
            print(f"ok       {name} {crc:#010x}")
    if bad:
        raise SystemExit(f"{bad} symbol version(s) disagree with vmlinux")
    print(f"{len(want)} symbol versions match vmlinux")


if __name__ == "__main__":
    main()
