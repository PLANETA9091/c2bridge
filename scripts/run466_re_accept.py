#!/usr/bin/env python3
"""run466_re_accept.py — byte-level protobuf decode of the 0x23 ConnectOK
frames from a run pcap (offline RE, 2039-priority (ii): what does the server
CONFIGURE/EXPECT in the accept?).

Framing (k_ESteamNetworkingUDPMsgID): [0x23][CMsgSteamDatagramConnectionless...]
The accept body = protobuf; generic walk with fixed32/varint/len-delim census.
"""
import struct, sys

fn = sys.argv[1] if len(sys.argv) > 1 else '/home/z/my-project/c2b-forensics/run465/pcap.a1.pcap'
data = open(fn, 'rb').read()

frames = []
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
    if not ((dst == '152.233.19.133' and dport == 28022) or
            (src == '152.233.19.133' and sport == 28022)): continue
    d = 'OUT' if dst == '152.233.19.133' else 'IN '
    if pl and pl[0] == 0x23:
        frames.append((ts+tus/1e6, d, pl))

def pb_walk(buf, indent=0, base=0):
    """Generic protobuf walk: prints field census; tolerates garbage."""
    i = 0
    out = []
    while i < len(buf):
        start = i
        tag = buf[i]; i += 1
        fnum = tag >> 3; wt = tag & 7
        if fnum == 0:
            out.append((base+start, 'BAD fnum=0 stop', hex(tag))); break
        if wt == 0:   # varint
            v = 0; sh = 0
            while i < len(buf):
                b = buf[i]; i += 1
                v |= (b & 0x7f) << sh
                if not (b & 0x80): break
                sh += 7
                if sh > 63: break
            out.append((base+start, f'f{fnum} varint', v))
        elif wt == 1:  # fixed64
            if i+8 > len(buf): out.append((base+start,'TRUNC f64')); break
            v = struct.unpack('<Q', buf[i:i+8])[0]; i += 8
            out.append((base+start, f'f{fnum} fixed64', v))
        elif wt == 2:  # len-delim
            v = 0; sh = 0
            while i < len(buf):
                b = buf[i]; i += 1
                v |= (b & 0x7f) << sh
                if not (b & 0x80): break
                sh += 7
                if sh > 63: break
            if i+v > len(buf):
                out.append((base+start, f'f{fnum} LEN {v} TRUNC/OOB stop')); break
            body = buf[i:i+v]; i += v
            printable = all(32 <= c < 127 or c in (10,13,9) for c in body)
            out.append((base+start, f'f{fnum} len{v}',
                        body.decode('latin1') if printable and v >= 2 else body.hex()))
        elif wt == 5:  # fixed32
            if i+4 > len(buf): out.append((base+start,'TRUNC f32')); break
            v = struct.unpack('<I', buf[i:i+4])[0]; i += 4
            out.append((base+start, f'f{fnum} fixed32', v))
        else:
            out.append((base+start, f'BAD wt={wt} stop', hex(tag))); break
    return out

for t, d, pl in frames:
    print(f'=== 0x23-accept {d} len={len(pl)} ===')
    print('hex:', pl.hex())
    # try walk at offset 1 (after msg id)
    for o, desc, v in pb_walk(pl[1:], base=1):
        print(f'  @{o:3d} {desc:24s} {v}')
    print()
