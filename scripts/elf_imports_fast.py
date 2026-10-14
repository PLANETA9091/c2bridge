#!/usr/bin/env python3
"""ELF JUMP_SLOT import check via PT_DYNAMIC, fast version.
Usage: elf_imports_fast.py <module...>
"""
import struct, sys

WANT = {'syscall', 'sendto', 'sendmsg', 'sendmmsg', 'send', 'write',
        '__sendmmsg', '__send', 'sendto64'}

def parse(path):
    d = open(path, 'rb').read()
    if d[:4] != b'\x7fELF':
        print(f"{path}: not ELF"); return
    e_phoff, = struct.unpack_from('<Q', d, 0x20)
    e_phentsize, = struct.unpack_from('<H', d, 0x36)
    e_phnum, = struct.unpack_from('<H', d, 0x38)
    loads, dyn = [], None
    for i in range(e_phnum):
        o = e_phoff + i*e_phentsize
        p_type, p_flags, p_off, p_vaddr = struct.unpack_from('<IIQQ', d, o)
        p_filesz, p_memsz = struct.unpack_from('<QQ', d, o+24)
        if p_type == 1: loads.append((p_vaddr, p_off, p_filesz, p_memsz))
        if p_type == 2: dyn = (p_off, p_filesz)
    def v2o(v):
        for va, off, fsz, msz in loads:
            if va <= v < va + msz:
                return off + (v - va)
        return None
    if not dyn:
        print(f"{path}: no PT_DYNAMIC"); return
    doff, dsz = dyn
    tags = {}
    o = doff
    while o + 16 <= doff + dsz:
        t, v = struct.unpack_from('<QQ', d, o)
        if t == 0: break
        tags[t] = v
        o += 16
    if 6 not in tags or 5 not in tags:
        print(f"{path}: no DT_SYMTAB/STRTAB"); return
    strtab_o = v2o(tags[5]); symtab_o = v2o(tags[6])
    strsz = tags.get(10, 1 << 20)
    strtab = d[strtab_o:strtab_o+min(strsz, 8<<20)]
    def symname(idx):
        st_name, = struct.unpack_from('<I', d, symtab_o + idx*24)
        e = strtab.find(b'\0', st_name)
        return strtab[st_name:e].decode('latin1')
    found = {}; total = 0; sample = []
    if 23 in tags and 2 in tags:
        ro = v2o(tags[23]); n = min(tags[2] // 24, 200000)
        if ro is not None:
            tbl = d[ro:ro + n*24]
            for r_off, r_info, _ in struct.iter_unpack('<QQq', tbl):
                rtyp = r_info & 0xffffffff
                if rtyp in (6, 7):
                    total += 1
                    nm = symname(r_info >> 32)
                    if len(sample) < 10: sample.append(nm)
                    if nm in WANT:
                        found[nm] = found.get(nm, 0) + 1
    print(f"{path.split('/')[-1]:52s} slots={total} found={found} sample={sample[:6]}")

for p in sys.argv[1:]:
    try: parse(p)
    except Exception as e: print(f"{p}: ERR {e}")
