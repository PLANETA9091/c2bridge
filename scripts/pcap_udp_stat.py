#!/usr/bin/env python3
"""pcap_udp_stat.py — UDP flow stats + wire-type histogram для c2b forensics pcaps.
Usage: pcap_udp_stat.py <file.pcap> [file2.pcap ...]
Выводит: потоки (src:sp -> dst:dp, pkts, bytes), первые байты UDP payload,
частоту wire-типов GNS (0x20 ChallengeReq, 0x21 ChallengeReply, 0x22 ConnectRequest,
0x24 Accept, 0x25 ConnectOK) и A2S-типов (T=0x54,I=0x49,A=0x41).
"""
import struct
import sys
from collections import Counter, defaultdict

GNS = {0x20: "ChallengeReq", 0x21: "ChallengeReply", 0x22: "ConnectRequest",
       0x23: "?", 0x24: "Accept", 0x25: "ConnectOK", 0x26: "?",
       0x40: "Data(0x40)"}


def read_pcap(path):
    flows = Counter()
    bytes_by_flow = Counter()
    wt = Counter()
    wt_flows = defaultdict(Counter)
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            print(f"{path}: too short")
            return
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            print(f"{path}: not classic pcap ({magic.hex()})")
            return
        network = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_s, ts_us, incl, orig = struct.unpack(endian + "IIII", ph)
            pkt = f.read(incl)
            if network == 276:      # LINUX_SLL2: proto(2)+pad(2)+ifidx(4)+ll(2)+pt(1)+al(1)+src(8)
                if len(pkt) < 20:
                    continue
                if struct.unpack(">H", pkt[0:2])[0] != 0x0800:
                    continue
                ip = pkt[20:]
            elif network == 113:    # LINUX_SLL: pt(2)+arphrd(2)+alen(2)+addr(8)+proto(2)
                if len(pkt) < 16:
                    continue
                if struct.unpack(">H", pkt[14:16])[0] != 0x0800:
                    continue
                ip = pkt[16:]
            else:                   # Ethernet
                if len(pkt) < 34:
                    continue
                if struct.unpack(">H", pkt[12:14])[0] != 0x0800:
                    continue
                ip = pkt[14:]
            if len(ip) < 20:
                continue
            ihl = (ip[0] & 0x0F) * 4
            proto = ip[9]
            if proto != 17:
                continue
            src = ".".join(str(b) for b in ip[12:16])
            dst = ".".join(str(b) for b in ip[16:20])
            udp = ip[ihl:]
            if len(udp) < 8:
                continue
            sp, dp = struct.unpack(">HH", udp[:4])
            payload = udp[8:]
            key = f"{src}:{sp} -> {dst}:{dp}"
            flows[key] += 1
            bytes_by_flow[key] += len(payload)
            if payload:
                b0 = payload[0]
                name = GNS.get(b0)
                if name and len(payload) in range(20, 1400):
                    wt[name] += 1
                    wt_flows[name][key] += 1
                elif b0 in (0x54, 0x49, 0x41, 0x63):
                    wt[f"A2S:{chr(b0)}"] += 1
    print(f"=== {path} ===")
    for k, n in flows.most_common(25):
        print(f"  {n:6d} pkts {bytes_by_flow[k]:9d} B  {k}")
    if len(flows) > 25:
        print(f"  ... and {len(flows) - 25} more flows")
    print("  -- wire types --")
    for k, n in wt.most_common(20):
        print(f"  {k:18s} x{n}")
        for fk, fn in wt_flows[k].most_common(3):
            print(f"      {fn:6d}x {fk}")
    print()


if __name__ == "__main__":
    for p in sys.argv[1:]:
        read_pcap(p)
