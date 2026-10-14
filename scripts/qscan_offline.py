#!/usr/bin/env python3
"""Offline '?'-class + fixed-form syscall-stub scanner (v75-ledger priority ii).

Replicates c2b_ss_scan_chunk (src/c2bridge.c:16091) semantics:
  fixed A:  b8 <nr32> 0f 05                    (mov eax,imm32; syscall)
  fixed B:  48 c7 c0 <nr> 00 00 00 0f 05       (mov rax,imm32; syscall)
  '?'-cls:  0f 05 preceded by
              89 <mod=3,rm=0>   = mov eax,r32   (2B imm)
              8b <mod=3,reg=0>  = mov eax,r32   (2B imm)
            optionally 1-byte 0x90 filler between mov and syscall;
            REX-reject: byte before the mov (or before filler) in 0x40-0x4f
            (glibc syscall() form 48 89 f8 = 64-bit mov = reject).
Reports hits with file offset + nr + 24B hex context. No cap: full census.
"""
import sys, glob, os

def scan(data):
    hits = []
    n = len(data)
    # fixed A: b8 xx 00 00 00 0f 05
    i = 0
    while True:
        i = data.find(b'\x0f\x05', i)
        if i < 0: break
        # fixed A check (syscall at i, i>=6)
        if i >= 6 and data[i-5] == 0xb8 and data[i-4] == 0 and data[i-3] == 0 and data[i-2] == 0:
            hits.append((i-5, data[i-1], 'A', i))
        # fixed B check
        if i >= 9 and data[i-8] == 0x48 and data[i-7] == 0xc7 and data[i-6] == 0xc0 \
           and data[i-5] == 0 and data[i-4] == 0:
            hits.append((i-8, data[i-3], 'B', i))
        # '?'-class: mov eax,r32 immediately before
        ok_rex = (i < 3) or not (0x40 <= data[i-3] <= 0x4f)
        if ok_rex and i >= 2:
            m2 = data[i-2]
            r1 = data[i-1]
            if m2 == 0x89 and (r1 & 0xc7) == 0xc0:
                hits.append((i-2, 0xffff, '?89', i))
            elif m2 == 0x8b and (r1 & 0xf8) == 0xc0:
                hits.append((i-2, 0xffff, '?8b', i))
            elif i >= 3 and r1 == 0x90 and not (i >= 4 and 0x40 <= data[i-4] <= 0x4f):
                m3 = data[i-3]
                r2 = data[i-2]
                if m3 == 0x89 and (r2 & 0xc7) == 0xc0:
                    hits.append((i-3, 0xffff, '?90:89', i))
                elif m3 == 0x8b and (r2 & 0xf8) == 0xc0:
                    hits.append((i-3, 0xffff, '?90:8b', i))
        i += 2
    return hits

def raw05_census(data):
    c = 0
    i = 0
    while True:
        i = data.find(b'\x0f\x05', i)
        if i < 0: break
        c += 1; i += 2
    return c

def ctx(data, off, before=12, after=12):
    a = max(0, off-before); b = min(len(data), off+after)
    return data[a:b].hex(' ')

def main():
    paths = sys.argv[1:]
    for p in paths:
        try:
            data = open(p, 'rb').read()
        except OSError as e:
            print(f"{p}: ERR {e}")
            continue
        raw = raw05_census(data)
        hits = scan(data)
        from collections import Counter
        cls = Counter(h[2] for h in hits)
        print(f"=== {p}  size={len(data)}  raw_0f05={raw}  hits={len(hits)}  {dict(cls)}")
        for off, nr, cls_, sysat in hits[:64]:
            print(f"  off=0x{off:08x} nr=0x{nr:04x} cls={cls_}  ctx: {ctx(data, off)}")
        if len(hits) > 64:
            print(f"  ... +{len(hits)-64} more")
    return 0

if __name__ == '__main__':
    sys.exit(main())
