#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""capture_legacy_ref.py — find a REAL CS:GO-legacy server via the Steam
master server and capture its EXACT wire replies for the farm to replay.

Why (run 65/66): with a non-self target (docker bridge) the engine FINALLY
sends qconnect0x00000000, our 'i' prompt makes it send 'j'+14-zeros (JOIN),
but our hand-built reserve-'A'/'B' replies produce silence. The engine's
authoritative peer is a REAL CS:GO server - so capture one live and replay
its bytes verbatim.

Captures (per legacy server found):
  info_i.bin      full 'I' reply (after the 0x41 challenge dance)
  chal_A.bin      the reply to our qconnect0x00000000 (expect 'A' + reserve)
  join_reply.bin  the reply to our 'j'+14-zeros
  player_d.bin    the 'D' reply to the A2S_PLAYER challenge dance
  ref.json        server addr + metadata

If no legacy server answers (2026: most 730 servers are CS2), writes
ref.json {"legacy": false} and the farm keeps its synthetic behavior.

stdlib only. Run on the GitHub runner (full network).
"""

import json
import os
import socket
import struct
import sys
import time

MASTER_CANDIDATES = [
    ("155.133.248.46", 27011),
    ("208.64.200.39", 27011),
    ("208.64.200.65", 27011),
    ("162.254.197.42", 27011),
]
FF = b"\xff\xff\xff\xff"


def le32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def udp(req, addr, timeout=1.5, expect=1400):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(req, addr)
        d, _ = s.recvfrom(expect)
        return d
    except OSError:
        return None
    finally:
        s.close()


def master_pages(limit_pages=6):
    for m in MASTER_CANDIDATES:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            last = b""
            servers = []
            for _ in range(limit_pages):
                s.sendto(b"\\appid\\730" + last + b"\\n\\\n", m)
                d, _ = s.recvfrom(65535)
                txt = d.decode(errors="replace")
                chunk = txt.split("\\final\\")[0]
                entries = [e.encode() for e in chunk.split("\\")
                           if e and e[0].isdigit() and ":" in e]
                servers.extend(entries)
                if "\\final\\" in txt or not entries:
                    break
                last = b"\\" + entries[-1]
                time.sleep(0.2)
            s.close()
            if servers:
                return servers
        except OSError:
            continue
    return []


def a2s_info(addr):
    """A2S_INFO with the 0x41 challenge dance; returns (blob, game_name)."""
    d = udp(FF + b"TSource Engine Query\x00", addr)
    if not d or d[:5] != FF + b"A":
        return (d, None) if d else (None, None)
    d = udp(FF + b"TSource Engine Query\x00" + d[5:9], addr)
    if not d or d[4:5] != b"I":
        return d, None
    p = d[5:]
    try:
        i = p.index(b"\x00", 1)          # skip protocol byte + name
        j = p.index(b"\x00", i + 1)      # map
        k = p.index(b"\x00", j + 1)      # folder
        g0 = k + 1
        g1 = p.index(b"\x00", g0)
        return d, p[g0:g1].decode(errors="replace")
    except ValueError:
        return d, None


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/legacy_ref"
    os.makedirs(outdir, exist_ok=True)
    ref = {"legacy": False, "servers_scanned": 0}

    print("querying steam master...", flush=True)
    servers = master_pages()
    print("master returned %d servers" % len(servers), flush=True)
    ref["servers_scanned"] = len(servers)
    if not servers:
        json.dump(ref, open(os.path.join(outdir, "ref.json"), "w"))
        return 0

    legacy = None
    games = {}
    for raw in servers[:400]:
        ip, _, port = raw.decode().partition(":")
        addr = (ip, int(port))
        blob, game = a2s_info(addr)
        if not blob:
            continue
        ref["servers_scanned"] += 0
        games[game] = games.get(game, 0) + 1
        if game == "Counter-Strike: Global Offensive":
            legacy = (addr, blob)
            break
    print("game histogram: %s" % games, flush=True)
    ref["games"] = games
    if not legacy:
        print("NO legacy CS:GO server found", flush=True)
        json.dump(ref, open(os.path.join(outdir, "ref.json"), "w"))
        return 0

    addr, info = legacy
    print("LEGACY SERVER FOUND: %s:%d" % addr, flush=True)
    open(os.path.join(outdir, "info_i.bin"), "wb").write(info)
    ref.update({"legacy": True, "addr": list(addr)})

    # qconnect -> 'A' reply (the authoritative reserve-challenge format!)
    d = udp(FF + b"qconnect0x00000000\x00", addr, timeout=3)
    if d:
        open(os.path.join(outdir, "chal_A.bin"), "wb").write(d)
        print("qconnect reply: %dB %s" % (len(d), d[:20].hex()), flush=True)
        ref["chal_A_first"] = d[4:5].decode(errors="replace")
    time.sleep(0.5)

    # 'j' join request -> reply
    d = udp(FF + b"j00000000000000\x00", addr, timeout=3)
    if d:
        open(os.path.join(outdir, "join_reply.bin"), "wb").write(d)
        print("join reply: %dB %s" % (len(d), d[:20].hex()), flush=True)
        ref["join_reply_first"] = d[4:5].decode(errors="replace")
    time.sleep(0.5)

    # A2S_PLAYER challenge dance -> 'D'
    d = udp(FF + b"U\x00\x00\x00\x00", addr, timeout=3)
    if d and d[:5] == FF + b"A":
        d = udp(FF + b"U" + d[5:9], addr, timeout=3)
    if d:
        open(os.path.join(outdir, "player_d.bin"), "wb").write(d)
        print("players reply: %dB first=%r" % (len(d), d[4:5]), flush=True)

    json.dump(ref, open(os.path.join(outdir, "ref.json"), "w"))
    print("REF CAPTURED", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
