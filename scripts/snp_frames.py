#!/usr/bin/env python3
"""snp_frames.py — the SNP frame decoder per Valve's official SNP_WIRE_FORMAT.md
(GameNetworkingSockets src/steamnetworkingsockets/clientlib/SNP_WIRE_FORMAT.md,
fetched 2026-10-12 = the era's reference copy at g124-re/SNP_WIRE_FORMAT.md).

THE 2208-ROUND MODEL = CORRECTED: the [80][K][98][M][00][C][D] frames = NOT
the reliable-msg family.  The REAL decode:
  [80][K]              = StopWaiting(ww=00, pkt_num_offset=K)     100000ww
  [81][K][x]           = StopWaiting(ww=01, 16-bit offset)       100000 01
  [98][n16][d16]       = Ack(w=1, nnn=000): latest_received=n16,  1001wnnn
                         delay=d16 (the 32usec scale; 0xffff = invalid)
  [37][n32][data..]    = Unreliable segment (e=1,m=1,o=0,sss=111  00emosss
                         = the msg-num u32 + the data to the pkt end)
  [40..7F]             = Reliable segment (010mmsss)              010mmsss
  [88..8F]             = Select lane (10001nnn)

THE a2 CORPUS RE-READ (the run341 attempt-2) = THE TRANSPORT IS HEALTHY:
the acks advance BOTH directions; the client sent 4 unreliable messages
('q', the g98-probe x2, the cl_interp); the server sent the 'A' + the
ack-only keepalives; ZERO reliable segments = the signon data = NEVER
transmitted (the server holds it); the 2208 "mutual announce-without-body
deadlock" = an artifact of the wrong frame model.

USAGE:  python3 snp_frames.py /tmp/g124_plaintext_a2.txt
        python3 snp_frames.py --selftest
"""
import sys

STOPW = 0x80  # the 100000ww lead: (b0 & 0xFC) == 0x80
ACK = 0x90  # 1001wnnn


def varint(b, i):
    v, sh = 0, 0
    while True:
        c = b[i]
        i += 1
        v |= (c & 0x7F) << sh
        if not (c & 0x80):
            return v, i
        sh += 7


def decode_frames(pt):
    """decode one decrypted SNP payload -> the list of the frame dicts."""
    out, i = [], 0
    n = len(pt)
    while i < n:
        b0 = pt[i]
        f = {"off": i}
        if b0 < 0x04:  # padding 000000xx = this many bytes total
            f["t"] = "pad"
            i += 1 + b0
        elif (b0 & 0x80) == 0x00:  # unreliable segment 00emosss
            e = (b0 >> 4) & 1
            m = (b0 >> 3) & 1
            o = (b0 >> 2) & 1
            sss = b0 & 7
            i += 1
            if m:
                num = int.from_bytes(pt[i:i + 4], "little")
                i += 4
            else:
                num = int.from_bytes(pt[i:i + 2], "little")
                i += 2
            off = None
            if o:
                off, i = varint(pt, i)
            if sss < 5:
                sz = ((sss << 8) | pt[i]) if False else None
                # per the doc: the upper 3 bits append to the lower 8 in the
                # explicit size field which follows => size = (sss<<8)|b
                sz = (sss << 8) | pt[i]
                i += 1
            else:
                sz = None  # to the end of the packet
            data = pt[i:] if sz is None else pt[i:i + sz]
            i = n if sz is None else min(n, i + sz)
            f.update(t="unrel", e=e, msg=num, off=off, size=(sz if sz
                     is not None else len(data)), data=data.hex())
        elif (b0 & 0xE0) == 0x40:  # reliable segment 010mmsss
            mm = (b0 >> 3) & 3
            sss = b0 & 7
            i += 1
            if mm == 0:
                pos = int.from_bytes(pt[i:i + 3], "little")
                i += 3
            elif mm == 1:
                pos = int.from_bytes(pt[i:i + 4], "little")
                i += 4
            elif mm == 2:
                pos = int.from_bytes(pt[i:i + 6], "little")
                i += 6
            else:
                f.update(t="rel-BAD-mm")
                break
            if sss < 5:
                sz = (sss << 8) | pt[i]
                i += 1
            else:
                sz = None
            data = pt[i:] if sz is None else pt[i:i + sz]
            i = n if sz is None else min(n, i + sz)
            f.update(t="rel", pos=pos, size=(sz if sz is not None else
                     len(data)), data=data.hex())
        elif (b0 & 0xFC) == STOPW:  # stop waiting 100000ww
            ww = b0 & 3
            i += 1
            nb = 1 if ww == 0 else (2 if ww == 1 else
                                    (3 if ww == 2 else 8))
            off = int.from_bytes(pt[i:i + nb], "little")
            i += nb
            f.update(t="stopw", off=off)
        elif (b0 & 0xF0) == ACK:  # ack 1001wnnn
            w = (b0 >> 3) & 1
            nblk = b0 & 7
            i += 1
            nb = 4 if w == 0 else 2
            latest = int.from_bytes(pt[i:i + nb], "little")
            i += nb
            delay = int.from_bytes(pt[i:i + 2], "little")
            i += 2
            blocks = []
            if nblk == 7:
                nblk = pt[i]
                i += 1
            for _ in range(nblk):
                bb = pt[i]
                i += 1
                a = bb >> 4
                nk = bb & 0xF
                if a >= 8:
                    a, i = ((a & 7), i)
                    a, i = _vext(pt, i, a)
                if nk >= 8:
                    nk, i = ((nk & 7), i)
                    nk, i = _vext(pt, i, nk)
                blocks.append((a, nk))
            f.update(t="ack", latest=latest, delay=delay, blocks=blocks)
        elif (b0 & 0xF8) == 0x88:  # select lane 10001nnn
            i += 1
            if (b0 & 7) == 7:
                lane, i = varint(pt, i)
            else:
                lane = (b0 & 7) + 1
            f.update(t="lane", lane=lane)
        else:  # 101xxxxx / 11xxxxxx / 100001xx = reserved
            f.update(t="reserved", b0=f"{b0:02x}")
            i += 1
        out.append(f)
    return out


def _vext(pt, i, low3):
    v, sh = low3, 0
    while True:
        c = pt[i]
        i += 1
        v |= (c & 0x7F) << (3 + sh)
        if not (c & 0x80):
            return v, i
        sh += 7


def fmt_frames(pt):
    out = []
    for f in decode_frames(pt):
        if f["t"] == "stopw":
            out.append(f"StopWait(off={f['off']})")
        elif f["t"] == "ack":
            s = f"Ack(latest={f['latest']},delay={f['delay']:#06x}"
            if f["delay"] == 0xFFFF:
                s += "=inv"
            if f["blocks"]:
                s += ",blocks=" + repr(f["blocks"])
            out.append(s + ")")
        elif f["t"] == "unrel":
            o = "" if f["off"] is None else f",off={f['off']}"
            out.append(f"Unrel(msg={f['msg']}{o},sz={f['size']},"
                       f"data={f['data'][:48]}{'..' if len(f['data']) > 48 else ''})")
        elif f["t"] == "rel":
            out.append(f"REL(pos={f['pos']},sz={f['size']},"
                       f"data={f['data'][:48]})")
        elif f["t"] == "lane":
            out.append(f"Lane({f['lane']})")
        else:
            out.append(f"{f['t'].upper()}({f.get('b0', '')})")
    return " | ".join(out)


def selftest():
    # the a2 corpus shapes (the run341 attempt-2, byte-exact)
    cases = [
        (bytes.fromhex("8001980100ffff3701000000ffffffff71636f6e6e656374"
                       "3078303030303030303000"),
         "StopWait(off=1) | Ack(latest=1,delay=0xffff=inv) | "
         "Unrel(msg=1,off=0,sz=24,data=00ffffffff71636f6e6e65637430783030"
         "30303030303000)"),
        (bytes.fromhex("800098020005003701000000ffffffff4100000000030000"
                       "000000070aee000000300101636f6e6e656374307830303030"
                       "3030303000"),
         "StopWait(off=0) | Ack(latest=2,delay=0x0005) | "
         "Unrel(msg=1,off=0,sz=43,data=00ffffffff41000000000300000000000"
         "70aee0000003001..)"),
        (bytes.fromhex("80009804002306"), "StopWait(off=0) | "
         "Ack(latest=4,delay=0x0623)"),
        (bytes.fromhex("8001980300081d370300000007020000000802"),
         "StopWait(off=1) | Ack(latest=3,delay=0x1d08) | "
         "Unrel(msg=3,off=0,sz=8,data=0007020000000802)"),
    ]
    for pt, want in cases:
        got = fmt_frames(pt)
        assert got == want, f"\n{pt.hex()}\n GOT: {got}\nWANT: {want}"
    # the ack-with-blocks: 1001wnnn + 1 block (a=3,nk=0 => 0x30)
    pt = bytes.fromhex("990400050030")
    f = decode_frames(pt)[0]
    assert f["t"] == "ack" and f["latest"] == 4 and f["delay"] == 5 \
        and f["blocks"] == [(3, 0)], f
    print("SELFTEST PASS (StopWait + Ack + Unrel + the a2 corpus "
          "byte-exact + the ack-blocks)")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        selftest()
        return
    for path in sys.argv[1:]:
        nrel = nunrel = 0
        acks = {"C>S": [], "S>C": []}
        for ln in open(path, errors="replace"):
            ln = ln.strip()
            if not ln or "PT=" not in ln:
                continue
            hdr, pt = ln.split("PT=", 1)
            d = hdr.split()
            direction, seq = d[0], d[1].split("=")[1]
            pt = bytes.fromhex(pt)
            print(f"{direction} {seq}: {fmt_frames(pt)}")
            for f in decode_frames(pt):
                if f["t"] == "rel":
                    nrel += 1
                elif f["t"] == "unrel":
                    nunrel += 1
                elif f["t"] == "ack":
                    acks[direction].append(f["latest"])
        print(f"\n== census: reliable-segments={nrel} unreliable={nunrel}")
        for d, a in acks.items():
            print(f"   {d} ack-latest: {a}")


if __name__ == "__main__":
    main()
