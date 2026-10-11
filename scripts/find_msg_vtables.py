#!/usr/bin/env python3
"""Locate CNetMessagePB vtables in engine_client.so via the known
CCLCMsg_Move::WriteToBuffer anchor @0x286720 and enumerate the sibling
vtables (all classes whose vtable contains a WriteToBuffer-like slot).

Usage: find_msg_vtables.py <engine_client.so>
"""
import struct
import sys


def main():
    data = open(sys.argv[1], "rb").read()
    anchor = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x286720
    pat = struct.pack("<Q", anchor)
    hits = []
    off = 0
    while True:
        i = data.find(pat, off)
        if i < 0:
            break
        off = i + 1
        hits.append(i)
    print(f"anchor {hex(anchor)} referenced at file offsets:",
          [hex(h) for h in hits])
    for h in hits:
        # vtable slot index = the position from the vtable start; the vtable
        # start = scan back: the previous entries = the valid function ptrs
        # (0x55.. prologs -> the addresses inside .text). Walk back up to 40.
        slot = 0
        start = h
        while slot < 40:
            prev = start - 8
            if prev < 0:
                break
            v = struct.unpack("<Q", data[prev:prev + 8])[0]
            if v == 0 or v > len(data) or v < 0x1000:
                break
            start = prev
            slot += 1
        print(f"  vtable candidate start={hex(start)} "
              f"anchor-slot={((h - start) // 8)}")
        # dump the neighborhood entries (the anchors and the neighbors)
        for k in range(-4, 8):
            i2 = h + k * 8
            if 0 <= i2 <= len(data) - 8:
                v = struct.unpack("<Q", data[i2:i2 + 8])[0]
                tag = " <- W2B" if k == 0 else ""
                print(f"    [{((i2 - start) // 8):2d}] {hex(v)}{tag}")


main()
