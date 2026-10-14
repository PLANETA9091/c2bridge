#!/usr/bin/env python3
"""run468_re_0x22.py — the AUTH-BLOB TRACK: full decode + diff of the 0x22
ConnectRequest frames (offline RE, the 2139 priority (i)).

Material:
  - run453 pcap: the RAW lane (the engine's native 0x22, '22 4c 00 0d'
    framing, 512B — the server stayed SILENT on it);
  - run467 pcap: the GNS lane (the bridge's synthetic 0x22, '22 0d' + the
    x25519-pub + the 174B auth blob — the one that got the 0x23-accept).

Outputs: per-lane census, full hex, protobuf walk of both, the field diff.
"""
import struct, sys

def pcap_frames(fn):
    data = open(fn, 'rb').read()
    off = 24
    while off + 16 <= len(data):
        ts, tus, cl, ol = struct.unpack('<IIII', data[off:off+16]); off += 16
        pkt = data[off:off+cl]; off += cl
        if len(pkt) < 48: continue
        if struct.unpack('>H', pkt[0:2])[0] != 0x0800: continue
        p = 20; ihl = (pkt[p] & 0xf) * 4
        if pkt[p+9] != 17: continue
        src = '.'.join(str(b) for b in pkt[p+12:p+16])
        dst = '.'.join(str(b) for b in pkt[p+16:p+20])
        u = p + ihl
        sport, dport = struct.unpack('>HH', pkt[u:u+4])
        pl = pkt[u+8:]
        if (dst == '152.233.19.133' and dport == 28022) or \
           (src == '152.233.19.133' and sport == 28022):
            yield ts+tus/1e6, src, sport, dst, dport, pl

def pb_walk(buf, base=0):
    out = []
    i = 0
    while i < len(buf):
        start = i
        tag = buf[i]; i += 1
        fnum = tag >> 3; wt = tag & 7
        if fnum == 0:
            out.append((base+start, f'BAD fnum=0 (tag {tag:#x})')); break
        if wt == 0:
            v = 0; sh = 0
            while i < len(buf):
                b = buf[i]; i += 1
                v |= (b & 0x7f) << sh
                if not (b & 0x80): break
                sh += 7
                if sh > 63: break
            out.append((base+start, f'f{fnum} varint', v))
        elif wt == 1:
            if i+8 > len(buf): out.append((base+start, 'TRUNC f64')); break
            v = struct.unpack('<Q', buf[i:i+8])[0]; i += 8
            out.append((base+start, f'f{fnum} fixed64', v))
        elif wt == 2:
            v = 0; sh = 0
            while i < len(buf):
                b = buf[i]; i += 1
                v |= (b & 0x7f) << sh
                if not (b & 0x80): break
                sh += 7
                if sh > 63: break
            if i+v > len(buf):
                out.append((base+start, f'f{fnum} len{v} OOB-STOP')); break
            body = buf[i:i+v]; i += v
            printable = v >= 2 and all(32 <= c < 127 or c in (10, 13, 9) for c in body)
            out.append((base+start, f'f{fnum} len{v}',
                        body.decode('latin1') if printable else body.hex()))
        elif wt == 5:
            if i+4 > len(buf): out.append((base+start, 'TRUNC f32')); break
            v = struct.unpack('<I', buf[i:i+4])[0]; i += 4
            out.append((base+start, f'f{fnum} fixed32', v))
        else:
            out.append((base+start, f'BAD wt={wt} (tag {tag:#x})')); break
    return out

print('========== RUN453: the RAW lane (the engine NATIVE 0x22) ==========')
seen = set()
for t, src, sp, dst, dp, pl in pcap_frames('/home/z/my-project/c2b-forensics/run453/pcap.a1.pcap'):
    if pl and pl[0] == 0x22:
        lane = f'{sp}->{dp}'
        if lane in seen: continue
        seen.add(lane)
        print(f'\n--- lane {lane} len={len(pl)} ---')
        print('hex:', pl.hex()[:700])
        for o, desc, *v in pb_walk(pl[1:], base=1):
            s = f'  @{o:3d} {desc}'
            if v: s += f'  {v[0]}'
            print(s[:220])

print('\n========== RUN467: the GNS lane (the bridge SYNTHETIC 0x22) ==========')
seen = set()
for t, src, sp, dst, dp, pl in pcap_frames('/home/z/my-project/c2b-forensics/run467/pcap.a1.pcap'):
    if pl and pl[0] == 0x22:
        lane = f'{sp}->{dp}'
        if lane in seen: continue
        seen.add(lane)
        print(f'\n--- lane {lane} len={len(pl)} ---')
        print('hex:', pl.hex()[:700])
        for o, desc, *v in pb_walk(pl[1:], base=1):
            s = f'  @{o:3d} {desc}'
            if v: s += f'  {v[0]}'
            print(s[:220])
