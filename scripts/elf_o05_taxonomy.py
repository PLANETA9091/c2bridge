#!/usr/bin/env python3
"""Full taxonomy of raw 0f 05 sites + syscall-GOT callers across ALL exec segments.
Usage: elf_o05_taxonomy.py <module...>
"""
import struct, sys
from collections import Counter

def go(path, show=12):
    d = open(path, 'rb').read()
    e_phoff, = struct.unpack_from('<Q', d, 0x20)
    e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
    loads, dyn = [], None
    for i in range(e_phnum):
        o = e_phoff + i*e_phentsize
        p_type, p_flags, p_off, p_vaddr = struct.unpack_from('<IIQQ', d, o)
        p_filesz, p_memsz = struct.unpack_from('<QQ', d, o+32)
        if p_type == 1: loads.append([p_vaddr, p_off, p_filesz, p_memsz, p_flags])
        if p_type == 2: dyn = (p_off, p_filesz)
    def v2o(v):
        for va, off, fsz, msz, fl in loads:
            if va <= v < va + msz: return off + (v - va)
        return None
    name = path.split('/')[-1]
    if not dyn:
        print(f"== {name}: no PT_DYNAMIC"); return
    tags = {}
    o = dyn[0]
    while o + 16 <= dyn[0] + dyn[1]:
        t, v = struct.unpack_from('<QQ', d, o)
        if t == 0: break
        tags[t] = v; o += 16
    got_v = None; symname = None
    if 23 in tags and 2 in tags and 5 in tags and 6 in tags:
        strtab_o = v2o(tags[5]); symtab_o = v2o(tags[6])
        if strtab_o is not None and symtab_o is not None:
            strtab = d[strtab_o:strtab_o+min(tags.get(10, 1<<20), 8<<20)]
            def symname(idx):
                st_name, = struct.unpack_from('<I', d, symtab_o + idx*24)
                e = strtab.find(b'\0', st_name)
                return strtab[st_name:e].decode('latin1')
            ro = v2o(tags[23]); n = min(tags[2] // 24, 200000)
            if ro is not None:
                for i in range(n):
                    r_off, r_info, _ = struct.unpack_from('<QQq', d, ro + i*24)
                    if (r_info & 0xffffffff) in (6, 7) and symname(r_info >> 32) == 'syscall':
                        got_v = r_off; break
    print(f"== {name} size={len(d)} syscallGOT={hex(got_v) if got_v else None}")
    execsegs = [(va, off, fsz) for va, off, fsz, msz, fl in loads if (fl & 1) and fsz > 4096]
    if not execsegs:
        execsegs = [(loads[0][0], loads[0][1], loads[0][2])]
    # ff25 stubs -> GOT ; ff15 direct -> GOT
    stubs = set(); f15 = []
    if got_v:
        for seg_va, seg_off, seg_sz in execsegs:
            buf = d[seg_off:seg_off+seg_sz]
            i = 0
            while True:
                i = buf.find(b'\xff\x25', i)
                if i < 0 or i + 6 > len(buf): break
                rel, = struct.unpack_from('<i', buf, i+2)
                if seg_va + i + 6 + rel == got_v: stubs.add(seg_va + i)
                i += 2
            i = 0
            while True:
                i = buf.find(b'\xff\x15', i)
                if i < 0 or i + 6 > len(buf): break
                rel, = struct.unpack_from('<i', buf, i+2)
                if seg_va + i + 6 + rel == got_v: f15.append(seg_va + i)
                i += 2
    # e8 -> stubs
    calls = []
    for st in stubs:
        for seg_va, seg_off, seg_sz in execsegs:
            buf = d[seg_off:seg_off+seg_sz]
            i = 0
            while True:
                i = buf.find(b'\xe8', i)
                if i < 0 or i + 5 > len(buf): break
                rel, = struct.unpack_from('<i', buf, i+1)
                if seg_va + i + 5 + rel == st: calls.append(seg_va + i)
                i += 1
    print(f"   plt-stubs={len(stubs)} ff15-direct={len(f15)} e8-calls={len(calls)}")
    for va in sorted(set(calls))[:20]:
        fo = v2o(va)
        if fo: print(f"   call va=0x{va:x} pre: {d[fo-10:fo].hex(' ')}")
    # taxonomy of all raw 0f 05
    cls = Counter(); rex = []; cnt = 0
    for seg_va, seg_off, seg_sz in execsegs:
        buf = d[seg_off:seg_off+seg_sz]
        i = 0
        while True:
            i = buf.find(b'\x0f\x05', i)
            if i < 0: break
            cnt += 1
            pre = buf[max(0,i-8):i]
            rex3 = buf[i-3] if i >= 3 else 0
            m2 = buf[i-2] if i >= 2 else 0
            r1 = buf[i-1] if i >= 1 else 0
            if 0x40 <= rex3 <= 0x4f:
                cls['rex'] += 1
                if len(rex) < 400: rex.append((seg_off+i, pre, buf[i+2:i+10]))
            elif (i >= 6 and buf[i-6] == 0xb8 and buf[i-5:i-2] == b'\x00\x00\x00') or (i >= 10 and buf[i-10] == 0xb8):
                cls['b8-family'] += 1
            elif m2 == 0x89 and (r1 & 0xc7) == 0xc0:
                cls['?89'] += 1
            elif m2 == 0x8b and (r1 & 0xf8) == 0xc0:
                cls['?8b'] += 1
            else:
                cls['other'] += 1
            i += 2
    print(f"   raw05={cnt} taxonomy={dict(cls)}")
    interesting = [(off, pre, post) for off, pre, post in rex if 0x40 <= pre[-3] <= 0x4f and pre[-2:-1] == b'\x89' or pre[-2:-1] == b'\x8b']
    for off, pre, post in interesting[:show]:
        print(f"   o05 off=0x{off:x} pre[{pre.hex(' ')}] post[{post.hex(' ')}]")

for p in sys.argv[1:]:
    try: go(p)
    except Exception as e:
        import traceback; traceback.print_exc(); print(f"{p}: ERR {e}")
