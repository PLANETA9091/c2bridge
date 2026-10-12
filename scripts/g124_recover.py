#!/usr/bin/env python3
"""g124_recover.py — the g124 live-intercept consumer.

THE INPUT = the run klog (client_keys_root.txt): the g124 lines
  [c2b] g124: KEY bits=256 key=<64hex> ks=<16hex>
  [c2b] g124: IV gcm=<16hex> len=<n> iv=<hex>
THE PAIRING = the pure pointer arithmetic (the g124 RE: the EVP_AES_GCM_CTX
= {ks @+0, gcm @+0x100}) => the iv's gcm-0x100 == the key's ks = the SAME
GCM ctx = the (key, iv) pair. Each pair = one direction's send ctx.
THE DECRYPT = the direct: no KDF, no premaster, no nonce-model search —
decrypt_stream(pkts, flow, k_send, k_recv, iv_send, iv_recv) with the pair
assignments (2 pairs => 2 assignments) and the AEAD tag = the oracle.

USAGE:
  python3 g124_recover.py <run_dir>            # auto: pcap.aN.pcap + the klog
  python3 g124_recover.py <pcap> <klog>        # explicit
  python3 g124_recover.py --selftest           # the parser + the GCM roundtrip
"""
import re
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_sns_decrypt import (read_pcap, game_flow, decrypt_stream,
                              parse_data_pkt, gcm_decrypt, FLAG_DATA)

RE_KEY = re.compile(r"g124: KEY bits=256 key=([0-9a-f]{64}) ks=([0-9a-f]+)")
RE_IV = re.compile(r"g124: IV gcm=([0-9a-f]+) len=([0-9a-f]+) iv=([0-9a-f]+)")
RE_PATCH = re.compile(r"g124: PATCHED (\w+) base=([0-9a-f]+)")


def parse_g124_klog(path):
    keys, ivs, patched = [], [], set()
    for ln in open(path, errors="replace"):
        m = RE_KEY.search(ln)
        if m:
            keys.append({"key": bytes.fromhex(m.group(1)),
                         "ks": int(m.group(2), 16)})
            continue
        m = RE_IV.search(ln)
        if m:
            raw = bytes.fromhex(m.group(3))
            ivs.append({"gcm": int(m.group(1), 16),
                        "len": int(m.group(2), 16),
                        "iv": raw[:m.group(2) and min(len(raw), 16)]})
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


def selftest():
    """the parser + the FULL GCM roundtrip with the synthetic klog: the
    klog key/iv => the encrypt a chunk => the klog-style lines => the
    parse => the pair => the gcm_decrypt via the SNS nonce model = PASS."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = bytes(range(32))
    iv = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaab")
    nonce = bytearray(iv)
    nonce[0:8] = ((int.from_bytes(iv[0:8], "little") + 7)
                  .to_bytes(8, "little"))
    ct = AESGCM(key).encrypt(bytes(nonce), b"HELLO-S2-PLAINTEXT", None)
    with open("/tmp/g124_self_klog.txt", "w") as f:
        f.write("[c2b] g124: PATCHED setkey base=1000 pid=1\n")
        f.write(f"[c2b] g124: KEY bits=256 key={key.hex()} ks=7f00dead0000\n")
        f.write("[c2b] g124: PATCHED setiv base=1000 pid=1\n")
        f.write(f"[c2b] g124: IV gcm=7f00dead0100 len=c iv={iv.hex()}\n")
    keys, ivs, patched = parse_g124_klog("/tmp/g124_self_klog.txt")
    assert patched == {"setkey", "setiv"}, patched
    pairs, mode = pair_kv(keys, ivs)
    assert mode == "ptr" and len(pairs) == 1, (mode, pairs)
    k, v = pairs[0]
    assert k == key and v == iv, "pair mismatch"
    got = gcm_decrypt(k, bytes(nonce), ct)
    assert got == b"HELLO-S2-PLAINTEXT", got
    print("SELFTEST PASS (the parse + the ptr-pairing + the GCM roundtrip)")


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
        print("[!] no pairs — the klog = without the g124 hits (the diag = "
              "the PATCHED lines + the setkey#/setiv# profile)")
        return 2
    for i, (k, v) in enumerate(pairs):
        print(f"  pair{i}: key={k.hex()} iv={v.hex()}")

    pkts = read_pcap(pcap)
    flow = game_flow(pkts)
    print(f"[i] pcap: {len(pkts)} pkts, flow={flow}")
    if flow is None:
        print("[!] no game flow"); return 2
    data = [p for p in pkts if p[1] and (p[1][0] & FLAG_DATA)
            and {(p[2], p[3]), (p[4], p[5])} == set(flow)]
    print(f"[i] data pkts in-flow: {len(data)}")
    if len(pairs) == 1:
        pairs = pairs * 2  # the same pair both directions = try-any
    wins = 0
    for ai, (ka, va) in enumerate(pairs):
        for bi, (kb, vb) in enumerate(pairs):
            if ai == bi and len(pairs) > 1:
                continue
            print(f"[i] try kS=pair{ai} kR=pair{bi} ...")
            res = decrypt_stream(pkts, flow, ka, kb, va, vb, verbose=False)
            ok = [r for r in res if r["pt"] is not None]
            print(f"    -> {len(ok)}/{len(res)} pkts TAG-PASS")
            for r in ok[:6]:
                d = "S>C" if r["srv"] else "C>S"
                print(f"    {d} seq={r['seq']} PT[{len(r['pt'])}]: "
                      f"{r['pt'][:96].hex()}")
            if ok:
                wins += len(ok)
                with open("/tmp/g124_plaintext.txt", "ab") as f:
                    for r in ok:
                        d = "S>C" if r["srv"] else "C>S"
                        f.write(f"{d} seq={r['seq']} "
                                f"PT={r['pt'].hex()}\n".encode())
    if wins:
        print(f"\n*** THE S2 PLAINTEXT = RECOVERED ({wins} pkts) -> "
              f"/tmp/g124_plaintext.txt ***")
        return 0
    print("\n[!] no tag pass — the pairs = wrong-session or the nonce "
          "model = off (the diag = the pcap flow vs the klog pid/timing)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
