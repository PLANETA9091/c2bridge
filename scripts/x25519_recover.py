#!/usr/bin/env python3
"""x25519_recover.py — the offline priv-key recovery from the g117/g118
pubdup heap windows + the FULL KDF + the GCM-verified decrypt (the
zero-models path = the clean S2 plaintext).

The chain (the g117 design): the serialized crypt_inner '08 01 12 20 <pub32>'
= the client's X25519 pub on the heap; the OTHER instance of the same pub =
the ECX key struct with the PRIVATE key = the adjacent 32B. The pubdup klog
line = the 160B ctx window around the dup => the priv = one of the 32B slices
of that window. This tool = the brute over the slices: each slice =
X25519(priv, server_pub-from-pcap) => the premaster => kdf_client_view =>
the keys + THE IVs => the data-pkt decrypt (the AEAD tag = the oracle).
The tag PASS = the mathematically-certain recovery — NO nonce models.

Usage:
  x25519_recover.py <pcap.aN.pcap> --keys-from-log client_keys_root.txt
  x25519_recover.py --selftest
"""
import argparse
import re
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)

from pcap_sns_decrypt import (read_pcap, game_flow, extract_handshake,
                              kdf_client_view, decrypt_stream, FLAG_DATA)

RE_CXI = re.compile(r"g113: cxi @([0-9a-f]+) pub=([0-9a-f]{64})")
RE_PUBDUP = re.compile(r"g113: pubdup @([0-9a-f]+) ctx=([0-9a-f]+)")
RE_PUBDUP2 = re.compile(r"g113: pubdup2 @([0-9a-f]+) pub=([0-9a-f]{64}) "
                        r"ctx=([0-9a-f]+)")
RE_KEYBE = re.compile(r"(?:le|be) keybe=([0-9a-f]{64})")


def parse_klog(path):
    pubs, dups, keys = [], [], []
    for line in open(path, "r", errors="replace"):
        m = RE_PUBDUP2.search(line)
        if m:
            dups.append((int(m.group(1), 16), bytes.fromhex(m.group(3)),
                         bytes.fromhex(m.group(2))))
            continue
        m = RE_PUBDUP.search(line)
        if m:
            dups.append((int(m.group(1), 16), bytes.fromhex(m.group(2)),
                         None))
            continue
        m = RE_KEYBE.search(line)
        if m:
            k = bytes.fromhex(m.group(1))
            if k not in keys:
                keys.append(k)
            continue
        m = RE_CXI.search(line)
        if m:
            p = bytes.fromhex(m.group(2))
            if p not in pubs:
                pubs.append(p)
    return pubs, dups, keys


def priv_candidates(ctx, pub):
    """Every 32B slice of the pubdup ctx window (the pub sits at the offset
    64 when the base clamp did not fire; the priv = the adjacent 32B = the
    side unknown => the brute). Skips the slices = the pub itself."""
    out = []
    for o in range(0, max(1, len(ctx) - 31)):
        sl = ctx[o:o + 32]
        if len(sl) != 32 or sl == pub or sl == b"\x00" * 32:
            continue
        if sl not in out:
            out.append(sl)
    return out


def premaster_of(priv_bytes, server_pub_bytes):
    try:
        sk = X25519PrivateKey.from_private_bytes(priv_bytes)
        pk = X25519PublicKey.from_public_bytes(server_pub_bytes)
        return sk.exchange(pk)
    except Exception:
        return None


def try_priv(priv_bytes, pcap_ctx, keys, quick=4):
    """pcap_ctx = (pkts, flow, hs). Returns (how, ks,kr,ivs,ivr,res) on the
    PASS: 'keybe' = the KDF output matches the captured AES key (the pure
    KDF proof, no IV model), 'gcm' = the AEAD tag on the data pkts."""
    pkts, flow, hs = pcap_ctx
    pm = premaster_of(priv_bytes, hs["server"]["key_data"])
    if pm is None:
        return None
    ks, kr, ivs, ivr = kdf_client_view(
        pm, hs["client"]["nonce"], hs["server"]["nonce"],
        hs["client"]["connid"], hs["server"]["connid"],
        hs["server"]["cert_inner"], hs["client"]["cert_inner"],
        hs["server"]["crypt_inner"], hs["client"]["crypt_inner"])
    for kb in keys:
        if ks == kb or kr == kb:
            res = decrypt_stream(pkts, flow, ks, kr, ivs, ivr, verbose=False)
            return ("keybe", ks, kr, ivs, ivr, res)
    dp = [p for p in pkts if p[1] and (p[1][0] & FLAG_DATA)][:quick]
    sub = decrypt_stream(dp, flow, ks, kr, ivs, ivr, verbose=False)
    if any(r["pt"] is not None for r in sub):
        return ("gcm", ks, kr, ivs, ivr,
                decrypt_stream(pkts, flow, ks, kr, ivs, ivr, verbose=False))
    return None


def run(pcap_path, klog_path):
    pubs, dups, keys = parse_klog(klog_path)
    print(f"klog: {len(pubs)} cxi pub(s), {len(dups)} dup window(s), "
          f"{len(keys)} keybe key(s)")
    if not dups:
        print("NO dup windows => the priv = NOT captured. The next lever = "
              "the g119 global dup pass (pubdup2) or the wider ctx.")
        return 1
    pkts = read_pcap(pcap_path)
    flow = game_flow(pkts)
    if not flow:
        print("no SNS handshake flow found in the pcap")
        return 1
    hs = extract_handshake(pkts, flow)
    if not hs["server"]["key_data"]:
        print("the server pub = MISSING from the handshake")
        return 1
    print(f"server pub: {hs['server']['key_data'].hex()}")
    cpub = hs["client"]["key_data"]
    print(f"client pub: {cpub.hex() if cpub else None}")
    # the candidate windows: THE ONES CONTAINING THE CLIENT PUB FIRST (the
    # priv = the session's key struct = near the session's pub instances);
    # the rest = the fallback. The pubdup2 lines = identified by the pub;
    # the legacy pubdup = the same-chunk self/other instances.
    pri, rest = [], []
    seen = set()
    for addr, ctx, upub in dups:
        if ctx in seen:
            continue
        seen.add(ctx)
        if cpub and cpub in ctx:
            pri.append((addr, ctx))
        elif upub is None or cpub is None or upub == cpub:
            rest.append((addr, ctx))
    print(f"candidate windows: {len(pri)} client-pub + {len(rest)} other")
    pcap_ctx = (pkts, flow, hs)
    tried = 0
    for addr, ctx in pri + rest:
        for sl in priv_candidates(ctx, cpub):
            tried += 1
            got = try_priv(sl, pcap_ctx, keys)
            if got:
                how, ks, kr, ivs, ivr, res = got
                pm = premaster_of(sl, hs["server"]["key_data"])
                print(f"*** RECOVERED ({how} oracle) ***")
                print(f"priv = {sl.hex()}")
                print(f"premaster = {pm.hex()}")
                print(f"KeySend = {ks.hex()}\nKeyRecv = {kr.hex()}")
                print(f"IVSend = {ivs.hex()}\nIVRecv = {ivr.hex()}")
                ok = sum(1 for r in res if r["pt"] is not None)
                print(f"decrypt: {ok}/{len(res)} pkts VERIFIED")
                if how == "gcm":
                    dp = [p for p in pkts if p[1] and (p[1][0] & FLAG_DATA)]
                    decrypt_stream(dp[:12], flow, ks, kr, ivs, ivr)
                return 0
    print(f"no priv verified ({tried} candidates tried; the keybe oracle = "
          f"{len(keys)} keys). If the client-pub windows = 0 => the g119 "
          "pubdup2 pass = REQUIRED (the cross-chunk struct). If the windows "
          "> 0 and no hit => the KDF hypothesis = suspect (the gns-ref "
          "re-check) or the priv = beyond the ctx.")
    return 1


def selftest():
    """Synthetic: the priv -> the pub -> the fake pubdup ctx (the priv = the
    adjacent slice) -> the recovery => the premaster roundtrip."""
    import hashlib
    import os
    import tempfile
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat)
    spriv = X25519PrivateKey.generate()
    cpriv_raw = X25519PrivateKey.generate().private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    cpriv = X25519PrivateKey.from_private_bytes(cpriv_raw)
    cpub_b = cpriv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    spub_b = spriv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    expect = cpriv.exchange(X25519PublicKey.from_public_bytes(spub_b))
    # the fake pubdup ctx: 64B filler + the pub + the priv (the adjacent) +
    # 32B filler; the addr = 0x1000 => the base clamp did not fire
    filler = hashlib.sha256(b"x").digest()
    ctx = filler + cpub_b + cpriv_raw + filler
    klog = (f"[c2b] g113: pubdup @00001000 ctx={ctx.hex()}\n"
            f"[c2b] g113: cxi @00000fe0 pub={cpub_b.hex()}\n")
    f = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
    f.write(klog)
    f.close()
    pubs, dups, keys = parse_klog(f.name)
    os.unlink(f.name)
    assert len(pubs) == 1 and len(dups) == 1, "klog parse FAIL"
    assert dups[0][1] == ctx, "ctx parse FAIL"
    for sl in priv_candidates(ctx, cpub_b):
        pm = premaster_of(sl, spub_b)
        if pm == expect:
            print("selftest: PASS (the priv recovered from the pubdup ctx, "
                  "the premaster roundtrip = exact)")
            return 0
    print("selftest: FAIL (the priv NOT in the candidate slices)")
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?", default=None)
    ap.add_argument("--keys-from-log", default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        raise SystemExit(selftest())
    if not a.pcap or not a.keys_from_log:
        ap.error("pcap + --keys-from-log required (or --selftest)")
    raise SystemExit(run(a.pcap, a.keys_from_log))


if __name__ == "__main__":
    main()
