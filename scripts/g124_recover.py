#!/usr/bin/env python3
"""g124_recover.py — the g124/g126 live-intercept consumer (v2).

THE INPUT = the run klog (client_keys_root.txt): the g124/g126 lines
  [c2b] g126: KEY bits=256 key=<64hex> ks=<16hex>
  [c2b] g126: IV gcm=<16hex> len=<n> iv=<hex>   (the hook logs 16B, the
         bytes beyond len = the zero pad — v1 KEPT the pad = the 16B nonce
         = the GHASH J0 path = the guaranteed tag-miss; v2 truncates)
THE PAIRING = the pure pointer arithmetic (the EVP_AES_GCM_CTX = {ks @+0,
gcm @+0x100}) => the iv's gcm-0x100 == the key's ks = the SAME GCM ctx.

THE NONCE TRUTH (run335): the setiv = PER-PACKET on a live ctx — the
captured ivs = CONSECUTIVE actual nonces (the u64-LE counter on iv[0:8]:
27aba531.. -> 28aba531.. = +1/pkt), i.e. iv_captured = base + p0 ALREADY
includes the packet number.  v1 used them as the connection base = the
double-count.  v2 = the two-phase recovery:
  PHASE A (the direct oracle): every (pkt, captured-iv) — no arithmetic.
  PHASE B (the base derivation): from a phase-A hit (iv_j, seq16): for the
  k-expansion pkt = seq + 0x10000*k derive base = iv_j - pkt, then decrypt
  EVERYTHING with nonce = base + pkt (the tag = the only oracle).
  LEGACY fallback: the captured iv = the connection base (the v1 model).

USAGE:
  python3 g124_recover.py <run_dir>            # auto: pcap.aN.pcap + the klog
  python3 g124_recover.py <pcap> <klog>        # explicit
  python3 g124_recover.py --selftest           # the parse + the phases
"""
import re
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_sns_decrypt import (read_pcap, game_flow, decrypt_stream,
                              parse_data_pkt, gcm_decrypt, FLAG_DATA)

RE_KEY = re.compile(r"g12[46]: KEY bits=256 key=([0-9a-f]{64}) ks=([0-9a-f]+)")
RE_IV = re.compile(r"g12[46]: IV gcm=([0-9a-f]+) len=([0-9a-f]+) iv=([0-9a-f]+)")
RE_PATCH = re.compile(r"g12[46]: PATCHED (\w+) base=([0-9a-f]+)")

KSPAN = 64  # the pkt-number k-expansion: pkt = seq16 + 0x10000*k, k<KSPAN


def parse_g124_klog(path):
    """the g124 (the cb0ca8 SNS lib) AND the g126 (the game's steamclient.so)
    lines = the same format; the tags = interchangeable.  THE FIX (v2): the
    iv = truncated to the LOGGED len (the hook pads to 16B with zeros; the
    16B nonce = the GHASH J0 path = the wrong cipher input)."""
    keys, ivs, patched = [], [], set()
    for ln in open(path, errors="replace"):
        m = RE_KEY.search(ln)
        if m:
            keys.append({"key": bytes.fromhex(m.group(1)),
                         "ks": int(m.group(2), 16)})
            continue
        m = RE_IV.search(ln)
        if m:
            ln_i = int(m.group(2), 16)
            raw = bytes.fromhex(m.group(3))
            take = min(ln_i, len(raw)) if ln_i else min(12, len(raw))
            ivs.append({"gcm": int(m.group(1), 16),
                        "len": ln_i,
                        "iv": raw[:take]})
            continue
        m = RE_PATCH.search(ln)
        if m:
            patched.add(m.group(1))
    return keys, ivs, patched


def pair_kv(keys, ivs):
    """gcm - 0x100 == ks => the (key, iv) pair; the fallback = the order."""
    pairs = []
    for iv in ivs:
        hit = [k for k in keys if k["ks"] and k["ks"] + 0x100 == iv["gcm"]]
        if hit:
            pairs.append((hit[0]["key"], iv["iv"]))
    if pairs:
        return pairs, "ptr"
    if keys and ivs:
        n = min(len(keys), len(ivs))
        return [(keys[i]["key"], ivs[i]["iv"]) for i in range(n)], "order"
    return [], "none"


def data_pkts(pkts, flow):
    """the in-flow data packets -> [(idx, ts, srv, seq, chunk)]"""
    out = []
    b = flow[1]
    for i, (ts, pay, src, sp, dst, dp) in enumerate(pkts):
        if {(src, sp), (dst, dp)} != set(flow):
            continue
        if not pay or not (pay[0] & FLAG_DATA):
            continue
        flags, to_conn, seq, chunk = parse_data_pkt(pay)
        if chunk is None or len(chunk) <= 16:
            continue
        out.append((i, ts, (src, sp) == b, seq, chunk))
    return out


def phase_a_direct(dp, pairs):
    """PHASE A: the captured ivs = the ACTUAL per-pkt nonces (the setiv =
    per-packet on the live ctx).  Every (pkt, iv) with NO arithmetic.
    -> [(pkt_idx, pair_idx, srv, seq, pt)]"""
    hits = []
    for (i, ts, srv, seq, chunk) in dp:
        for pi, (k, iv) in enumerate(pairs):
            pt = gcm_decrypt(k, iv, chunk)
            if pt is not None:
                hits.append((i, pi, srv, seq, pt))
    return hits


def u64le(b8):
    return int.from_bytes(b8, "little")


def leu64(v):
    return (v & ((1 << 64) - 1)).to_bytes(8, "little")


def derive_bases(hits, pairs, dp):
    """PHASE B: from each phase-A hit (iv_j == base + p_j, the hit pkt's
    seq16 = p_j & 0xFFFF): the k-expansion p_j = seq + 0x10000*k =>
    base = iv_j - p_j; the VALIDATION = the OTHER packets decrypt under
    the model (the tag = the oracle) — the caller does that implicitly.
    -> [(key, base_iv12)] (the bases = the per-ctx connection bases)"""
    bases = []
    for (i, pi, srv, seq, pt) in hits:
        k, iv = pairs[pi]
        for kk in range(KSPAN):
            p = seq + 0x10000 * kk
            u = u64le(iv[0:8]) - p
            if u < 0:
                break
            bases.append((k, leu64(u) + iv[8:12]))
    return bases


def phase_b_model(dp, bases):
    """the full decrypt under the derived bases: nonce = base + pkt,
    pkt = seq16 + 0x10000*k (the k-expansion).  -> hits like phase A"""
    out = []
    for (i, ts, srv, seq, chunk) in dp:
        for (k, base) in bases:
            u = u64le(base[0:8])
            for kk in range(KSPAN):
                nonce = leu64(u + seq + 0x10000 * kk) + base[8:12]
                pt = gcm_decrypt(k, nonce, chunk)
                if pt is not None:
                    out.append((i, -1, srv, seq, pt))
                    break
            else:
                continue
            break
    return out


def selftest():
    """the parse (the 16B-pad truncation) + the ptr-pairing + the FULL
    phase-A/B pipeline on the synthetic mid-stream capture."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = bytes(range(32))
    base = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaab")
    # the game = the per-pkt setiv: the captured ivs = base+5, base+6, base+7
    caps = []
    for p in (5, 6, 7):
        n = bytearray(base)
        n[0:8] = ((int.from_bytes(base[0:8], "little") + p)
                  .to_bytes(8, "little"))
        caps.append(bytes(n))
    chunks = []
    for p, n in zip((5, 6, 7), caps):
        ct = AESGCM(key).encrypt(n, f"PKT{p}-PAYLOAD".encode(), None)
        chunks.append((p, ct))
    with open("/tmp/g124_self_klog.txt", "w") as f:
        f.write("[c2b] g126: PATCHED setkey base=1000 pid=1\n")
        f.write(f"[c2b] g126: KEY bits=256 key={key.hex()} ks=7f00dead0000\n")
        f.write("[c2b] g126: PATCHED setiv base=1000 pid=1\n")
        for n in caps:  # the 16B pad = the run335 log shape
            f.write(f"[c2b] g126: IV gcm=7f00dead0100 len=c "
                    f"iv={n.hex()}00000000\n")
    keys, ivs, patched = parse_g124_klog("/tmp/g124_self_klog.txt")
    assert patched == {"setkey", "setiv"}, patched
    assert all(len(v["iv"]) == 12 for v in ivs), \
        [v["iv"].hex() for v in ivs]  # THE PAD = TRUNCATED
    pairs, mode = pair_kv(keys, ivs)
    assert mode == "ptr" and len(pairs) == 3, (mode, len(pairs))
    # the synthetic flow: the pkt with seq=p carries the nonce caps[p-5]
    flow = (("10.0.0.1", 1111), ("10.0.0.2", 2222))
    pkts = []
    for (p, ct) in chunks:
        pay = struct.pack("<BIH", FLAG_DATA, 1, p & 0xFFFF) + ct
        pkts.append((0.0 + p, pay, "10.0.0.1", 1111, "10.0.0.2", 2222))
    dp = data_pkts(pkts, flow)
    assert len(dp) == 3, len(dp)
    a = phase_a_direct(dp, pairs)
    assert len(a) == 3, f"phase A: {len(a)}/3"
    assert a[0][4] == b"PKT5-PAYLOAD" and a[2][4] == b"PKT7-PAYLOAD"
    bases = derive_bases(a, pairs, dp)
    assert any(b[1] == base for b in bases), "the true base = derived"
    b = phase_b_model(dp, bases)
    assert len(b) == 3, f"phase B: {len(b)}/3"
    assert b[1][4] == b"PKT6-PAYLOAD"
    print("SELFTEST PASS (the pad-truncation + the ptr-pairing + "
          "the phase-A direct + the phase-B base-derivation)")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        selftest()
        return
    if len(sys.argv) == 2:
        rd = sys.argv[1].rstrip("/")
        pcaps = sorted(f for f in os.listdir(rd) if f.startswith("pcap.a"))
        klog = os.path.join(rd, "client_keys_root.txt")
        if not pcaps or not os.path.exists(klog):
            print(f"no pcap/klog in {rd}"); return 2
        pcap = os.path.join(rd, pcaps[0])
    else:
        pcap, klog = sys.argv[1], sys.argv[2]

    keys, ivs, patched = parse_g124_klog(klog)
    print(f"[i] klog: keys={len(keys)} ivs={len(ivs)} patched={patched or '-'}")
    pairs, mode = pair_kv(keys, ivs)
    print(f"[i] pairs ({mode}): {len(pairs)}")
    if not pairs:
        print("[!] no pairs — the klog = without the g124/g126 hits (the "
              "diag = the PATCHED lines + the setkey#/setiv# profile)")
        return 2
    seen = {}
    for k, v in pairs:
        seen[(k.hex(), v.hex())] = seen.get((k.hex(), v.hex()), 0) + 1
    for j, ((kh, vh), n) in enumerate(list(seen.items())[:8]):
        print(f"  pair{j} x{n}: key={kh[:16]}.. iv={vh}")

    pkts = read_pcap(pcap)
    flow = game_flow(pkts)
    print(f"[i] pcap: {len(pkts)} pkts, flow={flow}")
    if flow is None:
        print("[!] no game flow"); return 2
    dp = data_pkts(pkts, flow)
    print(f"[i] data pkts in-flow: {len(dp)}")

    wins = []
    # PHASE A: the captured ivs = the actual per-pkt nonces
    a = phase_a_direct(dp, pairs) if pairs else []
    print(f"[i] phase A (the direct nonces): {len(a)} hits")
    wins += a
    # PHASE B: derive the bases from the hits, decrypt everything
    bases = derive_bases(a, pairs, dp) if a else []
    print(f"[i] phase B (the derived bases): {len(bases)} candidates")
    if bases:
        bb = phase_b_model(dp, bases)
        print(f"[i] phase B: {len(bb)} pkt hits")
        wins += bb
    # LEGACY: the captured iv = the connection base (the v1 model)
    if not wins:
        for ai, (ka, va) in enumerate(pairs):
            for bi, (kb, vb) in enumerate(pairs):
                if ai == bi and len(pairs) > 1:
                    continue
                res = decrypt_stream(pkts, flow, ka, kb, va, vb,
                                     verbose=False)
                ok = [r for r in res if r["pt"] is not None]
                if ok:
                    print(f"[i] legacy kS=pair{ai} kR=pair{bi}: "
                          f"{len(ok)} hits")
                    for r in ok:
                        wins.append((0, -1, r["srv"], r["seq"], r["pt"]))
    if not wins:
        print("[!] no tag pass in any phase — the diag: the pcap flow vs "
              "the klog pid/timing; the captured ctxs vs the data channel")
        return 1

    print(f"\n*** THE S2 PLAINTEXT = RECOVERED ({len(wins)} pkt hits) ***")
    seen_i = set()
    with open("/tmp/g124_plaintext.txt", "wb") as f:
        for (i, pi, srv, seq, pt) in wins:
            if i in seen_i:
                continue
            seen_i.add(i)
            d = "S>C" if srv else "C>S"
            f.write(f"{d} seq={seq} PT={pt.hex()}\n".encode())
    shown = 0
    seen_i = set()
    for (i, pi, srv, seq, pt) in wins:
        if i in seen_i:
            continue
        seen_i.add(i)
        d = "S>C" if srv else "C>S"
        print(f"  {d} seq={seq} PT[{len(pt)}]: {pt[:96].hex()}")
        shown += 1
        if shown >= 24:
            break
    print(f"-> /tmp/g124_plaintext.txt ({len(seen_i)} unique pkts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
