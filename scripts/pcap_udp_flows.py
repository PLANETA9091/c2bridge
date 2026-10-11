#!/usr/bin/env python3
"""List UDP flows (src ip:port <-> dst ip:port, pkt count, bytes) in a pcap."""
import struct, sys
from collections import Counter

def read_pcaps(path):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1": end = "<"
    elif magic == b"\xa1\xb2\xc2\xd3": end = ">"
    else: raise SystemExit("not a classic pcap")
    fields = struct.unpack(end + "IHHiIII", data[:24])
    link = fields[6]
    pkts, off = [], 24
    while off + 16 <= len(data):
        ts, tus, clen, olen = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        pkts.append((ts + tus / 1e6, data[off:off + clen]))
        off += clen
    return link, pkts

def parse_udp(link, pkt):
    if link == 276:
        if len(pkt) < 20 or struct.unpack(">H", pkt[0:2])[0] != 0x0800: return None
        ip = pkt[20:]
    elif link == 113:
        if len(pkt) < 16 or struct.unpack(">H", pkt[14:16])[0] != 0x0800: return None
        ip = pkt[16:]
    elif link == 1:
        if len(pkt) < 14 or struct.unpack(">H", pkt[12:14])[0] != 0x0800: return None
        ip = pkt[14:]
    else: return None
    ihl = (ip[0] & 0xf) * 4
    if ip[9] != 17: return None
    udp = ip[ihl:]
    if len(udp) < 8: return None
    sp, dp = struct.unpack(">HH", udp[0:4])
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    return src, sp, dst, dp, udp[8:]

def main():
    link, pkts = read_pcaps(sys.argv[1])
    flows = Counter(); fb = Counter()
    for ts, pkt in pkts:
        u = parse_udp(link, pkt)
        if not u: continue
        src, sp, dst, dp, d = u
        key = f"{src}:{sp} -> {dst}:{dp}" if (src, sp) <= (dst, dp) else f"{dst}:{dp} -> {src}:{sp}"
        flows[key] += 1; fb[key] += len(d)
    for k, c in flows.most_common(30):
        print(f"{c:6} pkts {fb[k]:8}B  {k}")

main()
