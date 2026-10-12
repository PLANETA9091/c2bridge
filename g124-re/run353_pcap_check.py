#!/usr/bin/env python3
"""Quick pcap UDP flow analyzer for c2bridge forensics (run353)."""
import struct, sys
from collections import Counter

def read_pcap(path):
    data = open(path, 'rb').read()
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        endian = '<'
    elif magic == b'\xa1\xb2\xc3\xd4':
        endian = '>'
    else:
        raise SystemExit('bad magic ' + magic.hex())
    _, _, _, _, _, _, linktype = struct.unpack(endian + 'IHHiIIi', data[:24])
    off = 24
    pkts = []
    while off + 16 <= len(data):
        ts_s, ts_us, incl, orig = struct.unpack(endian + 'IIII', data[off:off+16])
        off += 16
        pkts.append((ts_s + ts_us/1e6, data[off:off+incl], linktype))
        off += incl
    return pkts

def parse_udp(raw, linktype):
    if linktype == 0:
        if len(raw) < 4: return None
        ip = raw[4:]
    elif linktype == 1:
        if len(raw) < 14: return None
        ip = raw[14:]
    elif linktype == 113:
        if len(raw) < 16: return None
        ip = raw[16:]
    elif linktype == 276:  # LINUX_SLL2: 20B header
        if len(raw) < 20: return None
        ip = raw[20:]
    else:
        return None
    if len(ip) < 20: return None
    if (ip[0] >> 4) != 4: return None
    ihl = (ip[0] & 0xf) * 4
    if len(ip) < ihl + 8: return None
    src = '.'.join(str(b) for b in ip[12:16])
    dst = '.'.join(str(b) for b in ip[16:20])
    udp = ip[ihl:]
    sport, dport, ulen = struct.unpack('>HHH', udp[:6])
    payload = udp[8:]
    return (src, sport, dst, dport, payload)

def main(path):
    pkts = read_pcap(path)
    flows = Counter()
    udp_all = []
    for ts, raw, lt in pkts:
        u = parse_udp(raw, lt)
        if u:
            src, sp, dst, dp, pl = u
            udp_all.append((ts, src, sp, dst, dp, pl))
            flows[(src, sp, dst, dp)] += 1
    print('pkts total:', len(pkts), ' udp:', len(udp_all))
    print('--- top flows ---')
    for k, v in flows.most_common(10):
        print(v, k)
    k513 = [u for u in udp_all if len(u[5]) == 513]
    print('--- 513B datagrams:', len(k513))
    if k513:
        ts, src, sp, dst, dp, pl = k513[0]
        print('sample:', src, sp, '->', dst, dp, pl[:28].hex(), 'ascii:', pl[:16])
        print('first t=%.3f last t=%.3f' % (k513[0][0], k513[-1][0]))
    kk = [u for u in udp_all if len(u[5]) >= 5 and u[5][:4] == b'\xff\xff\xff\xff' and u[5][4:5] == b'k']
    print("--- 'k'-connectionless datagrams:", len(kk))
    if kk:
        ts, src, sp, dst, dp, pl = kk[0]
        print('sample:', src, sp, '->', dst, dp, pl[:28].hex())

if __name__ == '__main__':
    main(sys.argv[1])
