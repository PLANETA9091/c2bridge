#!/usr/bin/env python3
"""g124_recover.py — the g124/g126 live-intercept consumer (v3, torn-tolerant).

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

RE_KEY = re.compile(r"g12[46]: KEY bits=(\d+) key=([0-9a-f]+) ks=([0-9a-f]+)")
RE_IV = re.compile(r"g12[46]: IV gcm=([0-9a-f]+) len=([0-9a-f]+) iv=([0-9a-f]+)")
RE_PATCH = re.compile(r"g12[46]: PATCHED (\w+) base=([0-9a-f]+)")

KSPAN = 64  # the pkt-number k-expansion: pkt = seq16 + 0x10000*k, k<KSPAN
NONCE_HEX = 24  # the game nonce = 12B (the J0 path) => 24 hex
KEY_HEX = 64   # AES-256 key = 32B
PTR_HEX = 16   # the canonical x86-64 userspace ptr = 16 hex (00007f...)


def _win16(h):
    """the TORN pointer field -> the candidate 16-hex strings.  The stdout
    interleave INSERTS hex garbage around/inside the field (the run340/341
    class: ks=`00`+ptr+`00` = 20 chars, gcm=`0b70`+ptr+`1976` = 24).  The
    canonical Linux mmap ptr = 00007fxxxxxxxxxx = the window filter; the
    fallback = all windows.  len<16 = the TRUNCATED field = the fragment
    (the prefix-match in pair_kv)."""
    h = h.lower()
    if len(h) < PTR_HEX:
        return ["frag:" + h]
    wins = [h[i:i + PTR_HEX] for i in range(len(h) - PTR_HEX + 1)]
    pref = [w for w in wins if w.startswith("00007f")]
    return pref or wins


def _win24(h):
    """the TORN iv field -> the candidate 24-hex nonces.  The canonical
    clean shape = 32-hex (the 16B log pad 0000-tail) => the 24-prefix;
    otherwise ALL 24-windows (the garbage can sit anywhere: the run341
    iv=`0200`+nonce24+12x`0` = 40 chars, the true nonce at the off 4)."""
    h = h.lower()
    out = []
    if len(h) == NONCE_HEX:
        out.append(h)
    elif len(h) == 2 * NONCE_HEX + 8 and h.endswith("0000"):
        out.append(h[:NONCE_HEX])  # the clean 16B-pad shape
    for i in range(len(h) - NONCE_HEX + 1):
        w = h[i:i + NONCE_HEX]
        if w not in out:
            out.append(w)
    return out


def _win64(h):
    """the TORN key field -> the candidate 64-hex keys (all windows; the
    tag = the oracle picks)."""
    h = h.lower()
    if len(h) == KEY_HEX:
        return [h]
    seen = []
    for i in range(len(h) - KEY_HEX + 1):
        w = h[i:i + KEY_HEX]
        if w not in seen:
            seen.append(w)
    return seen


def parse_g124_klog(path):
    """the g124 (the cb0ca8 SNS lib) AND the g126 (the game's steamclient.so)
    lines = the same format; the tags = interchangeable.  v3 = TORN-TOLERANT
    (the run340/341 stdout-interleave class): every field = the candidate
    windows — the keys = the 64-hex windows, the pointers = the 16-hex
    windows (the 00007f-filter), the nonces = the 24-hex windows.  The tag
    oracle downstream = the picker; the parse = the generator."""
    keys, ivs, patched = [], [], set()
    for ln in open(path, errors="replace"):
        m = RE_KEY.search(ln)
        if m:
            for kh in _win64(m.group(2)):
                for ksh in _win16(m.group(3)):
                    keys.append({"key": bytes.fromhex(kh),
                                 "ks": ksh,  # 'frag:...' or the 16-hex
                                 "bits": int(m.group(1))})
            continue
        m = RE_IV.search(ln)
        if m:
            for gh in _win16(m.group(1)):
                for nh in _win24(m.group(3)):
                    ivs.append({"gcm": gh,           # 'frag:...' or the 16-hex
                                "len": m.group(2),   # the informational
                                "iv": bytes.fromhex(nh)})
            continue
        m = RE_PATCH.search(ln)
        if m:
            patched.add(m.group(1))
    return keys, ivs, patched


def _ptr_eq_ks100(ks, gcm):
    """gcm == ks + 0x100 (the EVP_AES_GCM_CTX layout {ks @+0, gcm @+0x100}).
    Both = 'frag:...' or the 16-hex.  The fragment = the truncated field =
    the prefix-match against the zero-padded counterpart."""
    if ks.startswith("frag:") and gcm.startswith("frag:"):
        return False  # two fragments = nothing to anchor on
    if not ks.startswith("frag:") and not gcm.startswith("frag:"):
        return int(ks, 16) + 0x100 == int(gcm, 16)
    if gcm.startswith("frag:"):
        base = f"{int(ks, 16) + 0x100:016x}"
        return base.startswith(gcm[5:])
    base = f"{(int(gcm, 16) - 0x100) & ((1 << 64) - 1):016x}"
    return base.startswith(ks[5:])


def pair_kv(keys, ivs):
    """gcm - 0x100 == ks => the (key, iv) pair; the v3 = the candidate
    cross-product (the torn fields = the windows; the fragment pointers =
    the prefix-match) + the dedup; the fallback = the order."""
    pairs, seen = [], set()
    for iv in ivs:
        hit = [k for k in keys if _ptr_eq_ks100(k["ks"], iv["gcm"])]
        for k in hit:
            tk = (k["key"].hex(), iv["iv"].hex())
            if tk in seen:
                continue
            seen.add(tk)
            pairs.append((k["key"], iv["iv"]))
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
    """the parse (the 16B-pad truncation + the TORN shapes) + the
    ptr-pairing + the FULL phase-A/B pipeline on the synthetic mid-stream
    capture.  The torn shapes = the run340/341 stdout-interleave class."""
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
    # the realistic 00007f-region pointers (the _win16 00007f-filter path)
    ks = 0x00007f00dead0000
    gcm = ks + 0x100
    ksh, gcmh = f"{ks:016x}", f"{gcm:016x}"
    with open("/tmp/g124_self_klog.txt", "w") as f:
        f.write("[c2b] g126: PATCHED setkey base=1000 pid=1\n")
        # the CLEAN key line (the run341 a2 class)
        f.write(f"[c2b] g126: KEY bits=256 key={key.hex()} ks={ksh}\n")
        # the TORN key line (the run341 a1 class: the 00-prefix/suffix
        # garbage + the ptr windows) — the SAME key re-logged torn = the
        # dedup folds it; the parse must produce the true key window
        f.write(f"00[c2b] g126: KEY bits=256 key=00{key.hex()}00 "
                f"ks=00{ksh}00\n")
        f.write("[c2b] g126: PATCHED setiv base=1000 pid=1\n")
        for j, n in enumerate(caps):  # the 16B pad = the run335 log shape
            if j == 1:  # the TORN iv line (the run341 line-324 class)
                f.write(f"8469[c2b] g126: IV gcm=0b70{gcmh}1976 "
                        f"len=7f340000000cba00 iv=0200{n.hex()}00000000\n")
            else:
                f.write(f"[c2b] g126: IV gcm={gcmh} len=c "
                        f"iv={n.hex()}00000000\n")
    keys, ivs, patched = parse_g124_klog("/tmp/g124_self_klog.txt")
    assert patched == {"setkey", "setiv"}, patched
    assert all(len(v["iv"]) == 12 for v in ivs), \
        [v["iv"].hex() for v in ivs]  # THE PAD = TRUNCATED / THE WINDOWS = 12B
    pairs, mode = pair_kv(keys, ivs)
    # the torn key-line = the 5 windows sharing the ks => the garbage
    # windows PASS the ptr-pairing (the oracle downstream = the picker):
    # the pairs >= the 3 true, the contains-checks = the correctness
    assert mode == "ptr" and len(pairs) >= 3, (mode, len(pairs))
    # the torn key-line candidates folded to the TRUE key via the dedup:
    assert any(bytes(p[0]) == key for p in pairs)
    # the torn iv-line candidate = the TRUE nonce recovered (the off-4 window)
    assert any(bytes(p[1]) == caps[1] for p in pairs)
    # the synthetic flow: the pkt with seq=p carries the nonce caps[p-5]
    flow = (("10.0.0.1", 1111), ("10.0.0.2", 2222))
    pkts = []
    for (p, ct) in chunks:
        pay = struct.pack("<BIH", FLAG_DATA, 1, p & 0xFFFF) + ct
        pkts.append((0.0 + p, pay, "10.0.0.1", 1111, "10.0.0.2", 2222))
    dp = data_pkts(pkts, flow)
    assert len(dp) == 3, len(dp)
    a = phase_a_direct(dp, pairs)
    # ONLY the true (key, nonce) combos pass the tag — the garbage
    # windows = no hit (the 128-bit tag)
    assert len(a) == 3, f"phase A: {len(a)}/3"
    assert a[0][4] == b"PKT5-PAYLOAD" and a[2][4] == b"PKT7-PAYLOAD"
    bases = derive_bases(a, pairs, dp)
    assert any(b[1] == base for b in bases), "the true base = derived"
    b = phase_b_model(dp, bases)
    assert len(b) == 3, f"phase B: {len(b)}/3"
    assert b[1][4] == b"PKT6-PAYLOAD"
    print("SELFTEST PASS (the pad-truncation + the TORN windows + "
          "the ptr-pairing + the phase-A direct + the phase-B "
          "base-derivation)")


def recover_pcap(pcap, pairs, tag):
    """the FULL pipeline for ONE pcap (the attempt): the phases A/B + the
    legacy; -> the list of the unique (idx, srv, seq, pt) wins."""
    pkts = read_pcap(pcap)
    flow = game_flow(pkts)
    print(f"[i] pcap.{tag}: {len(pkts)} pkts, flow={flow}")
    if flow is None:
        print(f"[!] pcap.{tag}: no game flow")
        return [], pkts, flow
    dp = data_pkts(pkts, flow)
    print(f"[i] pcap.{tag}: data pkts in-flow: {len(dp)}")

    wins = []
    # PHASE A: the captured ivs = the actual per-pkt nonces
    a = phase_a_direct(dp, pairs) if pairs else []
    print(f"[i] pcap.{tag} phase A (the direct nonces): {len(a)} hits")
    wins += a
    # PHASE B: derive the bases from the hits, decrypt everything
    bases = derive_bases(a, pairs, dp) if a else []
    print(f"[i] pcap.{tag} phase B (the derived bases): {len(bases)} "
          f"candidates")
    if bases:
        bb = phase_b_model(dp, bases)
        print(f"[i] pcap.{tag} phase B: {len(bb)} pkt hits")
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
                    print(f"[i] pcap.{tag} legacy kS=pair{ai} kR=pair{bi}: "
                          f"{len(ok)} hits")
                    for r in ok:
                        wins.append((0, r["srv"], r["seq"], r["pt"]))
    uniq, seen_i = [], set()
    for (i, pi, srv, seq, pt) in wins:
        if i in seen_i:
            continue
        seen_i.add(i)
        uniq.append((i, srv, seq, pt))
    return uniq, pkts, flow


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
        pcaps = [os.path.join(rd, f) for f in pcaps]
    else:
        pcaps = [sys.argv[1]]
        klog = sys.argv[2]

    keys, ivs, patched = parse_g124_klog(klog)
    print(f"[i] klog: key-cands={len(keys)} iv-cands={len(ivs)} "
          f"patched={patched or '-'}")
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

    # THE PER-PCAP LOOP (v3): the klog = the BOTH attempts' lines mixed
    # (the run341 class) and the pcaps = per-attempt — the tag oracle
    # filters the cross-attempt noise (the foreign keys = no tag pass).
    all_out = []
    rc = 1
    for pcap in pcaps:
        tag = os.path.basename(pcap).replace("pcap.", "").replace(".pcap", "")
        uniq, pkts, flow = recover_pcap(pcap, pairs, tag)
        if not uniq:
            print(f"[!] pcap.{tag}: no tag pass in any phase — the diag: "
                  "the pcap flow vs the klog pid/timing; the captured ctxs "
                  "vs the data channel")
            continue
        rc = 0
        print(f"\n*** pcap.{tag}: THE S2 PLAINTEXT = RECOVERED "
              f"({len(uniq)} unique pkt hits) ***")
        out = os.path.join("/tmp", f"g124_plaintext_{tag}.txt")
        with open(out, "wb") as f:
            for (i, srv, seq, pt) in uniq:
                d = "S>C" if srv else "C>S"
                f.write(f"{d} seq={seq} PT={pt.hex()}\n".encode())
        for (i, srv, seq, pt) in uniq[:24]:
            d = "S>C" if srv else "C>S"
            print(f"  {d} seq={seq} PT[{len(pt)}]: {pt[:96].hex()}")
        print(f"-> {out} ({len(uniq)} unique pkts)")
        all_out += [(tag,) + u for u in uniq]

    # the combined plaintext (the pipeline compat: /tmp/g124_plaintext.txt)
    if all_out:
        with open("/tmp/g124_plaintext.txt", "wb") as f:
            for (tag, i, srv, seq, pt) in all_out:
                d = "S>C" if srv else "C>S"
                f.write(f"[{tag}] {d} seq={seq} PT={pt.hex()}\n".encode())
        print(f"-> /tmp/g124_plaintext.txt ({len(all_out)} total, "
              "the attempt-tagged)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
