#!/usr/bin/env python3
"""engine_challenge_xref.py — locate the CS:GO engine's S2C_CHALLENGE parser.

Finds the VA of "Invalid challenge packet." (and qconnect/getchallenge
strings) inside the engine binary, scans .text for RIP-relative 4-byte
displacements referencing those VAs, and dumps an objdump window around
each xref. Output goes to stdout; keep it small (dedup windows).

Env: ENGINE = path to the engine .so
"""
import os
import struct
import subprocess
import sys

E = os.environ.get('ENGINE')
if not E:
    print('ENGINE env required', file=sys.stderr)
    sys.exit(2)

data = open(E, 'rb').read()
assert data[:4] == b'\x7fELF' and data[4] == 2, 'not ELF64'

e_shoff, = struct.unpack_from('<Q', data, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 0x3a)
secs = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    name, typ, flags, addr, offset, size = struct.unpack_from('<IIQQQQ', data, off)
    secs.append(dict(idx=i, name_off=name, typ=typ, addr=addr,
                     offset=offset, size=size))
shstr = secs[e_shstrndx]
end0 = data.index(b'\0', shstr['offset'] + 0)  # validate


def sname(n):
    end = data.index(b'\0', shstr['offset'] + n)
    return data[shstr['offset'] + n:end].decode('latin1')


for s in secs:
    s['sname'] = sname(s['name_off'])

print(f'== {E} ({len(data)} bytes) ==')
print('== sections ==')
for s in secs:
    if s['size']:
        print(f"  {s['sname']:20s} addr={s['addr']:#x} off={s['offset']:#x} size={s['size']:#x}")

# ---- string VAs ----
targets = {}
needles = (b'Invalid challenge packet.', b'qconnect0x', b'getchallenge',
           b'Connecting to public')
for s in secs:
    if s['typ'] == 8 or s['size'] == 0:      # SHT_NOBITS
        continue
    blob = data[s['offset']:s['offset'] + s['size']]
    for needle in needles:
        start = 0
        while True:
            i = blob.find(needle, start)
            if i < 0:
                break
            va = s['addr'] + i
            targets.setdefault(needle.decode('latin1'), set()).add(va)
            start = i + 1

print('== string VAs ==')
for k, vs in sorted(targets.items()):
    for v in sorted(vs):
        print(f'  {v:#014x}  {k}')

all_targets = set()
for vs in targets.values():
    all_targets |= vs

# ---- scan .text for RIP-relative refs ----
text = next((s for s in secs if s['sname'] == '.text'), None)
if text is None:
    print('no .text', file=sys.stderr)
    sys.exit(1)
tb = data[text['offset']:text['offset'] + text['size']]
hits = {}
n = len(tb)
for off in range(0, n - 4):
    disp, = struct.unpack_from('<i', tb, off)
    if disp == 0:
        continue
    va_after = text['addr'] + off + 4
    t = va_after + disp
    if t in all_targets:
        hits.setdefault(t, []).append(va_after)

print('== xrefs (RIP-relative) ==')
for t, ends in sorted(hits.items()):
    print(f'  target {t:#014x}: {len(ends)} refs at ' +
          ' '.join(f'{e:#x}' for e in ends[:12]))

# ---- objdump windows ----
seen = []
for t, ends in sorted(hits.items()):
    for endva in ends:
        lo = max(text['addr'], endva - 4608)
        hi = min(text['addr'] + text['size'], endva + 320)
        key = lo // 2048
        if key in seen:
            continue
        seen.append(key)
        print(f'\n===== xref -> {t:#014x}  (ref at {endva:#x}) =====')
        r = subprocess.run(['objdump', '-d', '--start-address', hex(lo),
                            '--stop-address', hex(hi), E],
                           capture_output=True, text=True)
        sys.stdout.write(r.stdout)
