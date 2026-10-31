#!/usr/bin/env python3
"""Print the "object function sympos" records a kpatch module will patch.

Reads the .kpatch.funcs section (struct kpatch_patch_func: new_addr,
new_size, old_addr, old_size, sympos, name, objname) and resolves the name
and objname pointers through the section's relocations.

usage: kpatch-funcs.py <module.ko>
"""
import struct
import sys

FUNC_SIZE = 56
NAME_OFF = 40
OBJNAME_OFF = 48
SYMPOS_OFF = 32


class Elf:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.m = f.read()
        if self.m[:4] != b"\x7fELF" or self.m[4] != 2 or self.m[5] != 1:
            raise SystemExit(f"{path}: not a little-endian ELF64 file")
        shoff = struct.unpack_from("<Q", self.m, 0x28)[0]
        (shentsize, shnum, shstrndx) = struct.unpack_from("<HHH", self.m, 0x3A)
        self.sections = []
        for i in range(shnum):
            off = shoff + i * shentsize
            (name, typ, _flags, addr, offset, size, link, info, _align, entsize) = (
                struct.unpack_from("<IIQQQQIIQQ", self.m, off)
            )
            self.sections.append(dict(name=name, type=typ, addr=addr, offset=offset,
                                      size=size, link=link, info=info, entsize=entsize))
        strtab = self.sections[shstrndx]
        for sec in self.sections:
            sec["sname"] = self.cstr(strtab["offset"] + sec["name"])
        self.by_name = {sec["sname"]: sec for sec in self.sections}

    def cstr(self, off):
        end = self.m.find(b"\0", off)
        return self.m[off:end].decode("ascii", "replace")

    def symbols(self):
        sec = next(s for s in self.sections if s["type"] == 2)
        strtab = self.sections[sec["link"]]
        out = []
        for off in range(sec["offset"], sec["offset"] + sec["size"], 24):
            (name, info, _other, shndx, value, _size) = struct.unpack_from("<IBBHQQ", self.m, off)
            out.append((self.cstr(strtab["offset"] + name), info & 0xF, shndx, value))
        return out


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    elf = Elf(sys.argv[1])
    funcs = elf.by_name.get(".kpatch.funcs")
    rela = elf.by_name.get(".rela.kpatch.funcs")
    strings = elf.by_name.get(".kpatch.strings")
    if not (funcs and rela and strings):
        raise SystemExit("not a kpatch module: .kpatch.funcs is missing")
    syms = elf.symbols()
    count = funcs["size"] // FUNC_SIZE
    names = [[None, None] for _ in range(count)]
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        (r_offset, r_info, r_addend) = struct.unpack_from("<QQq", elf.m, off)
        field = r_offset % FUNC_SIZE
        if field not in (NAME_OFF, OBJNAME_OFF):
            continue
        sym = syms[r_info >> 32]
        target = sym[3] + r_addend
        # A section symbol's value is 0 and the addend is the string offset;
        # a named symbol inside .kpatch.strings carries the offset in its value.
        if elf.sections[sym[2]]["sname"] != ".kpatch.strings":
            raise SystemExit(f"unexpected relocation target {sym[0]} in .kpatch.funcs")
        names[r_offset // FUNC_SIZE][0 if field == NAME_OFF else 1] = elf.cstr(strings["offset"] + target)
    for i, (name, objname) in enumerate(names):
        if name is None or objname is None:
            raise SystemExit(f"record {i} has no name or object")
        sympos = struct.unpack_from("<Q", elf.m, funcs["offset"] + i * FUNC_SIZE + SYMPOS_OFF)[0]
        print(objname, name, sympos)


if __name__ == "__main__":
    main()
