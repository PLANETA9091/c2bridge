#!/usr/bin/env python3
"""pcap_sns_decrypt.py — SteamNetworkingSockets (GNS/SNS) direct-UDP pcap decryptor.

Reconstructs the AES-256-GCM session keys from the on-wire handshake
(ConnectRequest 0x20 / ConnectOK 0x21: CMsgSteamDatagramSessionCryptInfo
 key_type/key_data(X25519 pub)/nonce + the inner cert/crypt serialized bytes)
+ the client-side ephemeral secret, per ValveSoftware/GameNetworkingSockets
src/steamnetworkingsockets/clientlib/steamnetworkingsockets_connections.cpp
(CSteamNetworkConnectionBase::Recv_CryptInfo / the HKDF-QUIC-style expansion):

  salt   = u64le(server_nonce) || u64le(client_nonce)          (client view)
  PRK    = HMAC-SHA256(key=premaster(X25519), msg=salt)
  ctx    = u32le(client_connid) || u32le(server_connid) || "Steam datagram"
           || server_cert_inner || client_cert_inner
           || server_crypt_inner || client_crypt_inner
  out_k  = HMAC-SHA256(key=PRK, msg=prev_digest || ctx || byte(k))  k=1..4
           (prev = 32 zero bytes for k=1)
  client: KeySend=out1 KeyRecv=out2 IVSend=out3[:12] IVRecv=out4[:12]
  per-packet IV: *(uint64*)iv += pkt_num  (first 8 bytes, LE add)
  data packet:    [flags u8][u32 to_connid][u16 seq]
                  [flags&1: varint len + stats blob][flags&2: u16 dt]
                  [ciphertext || 16B tag]   AAD = none

Modes:
  --selftest                 synthetic X25519 end-to-end roundtrip (validates
                             the whole KDF + framing against real crypto)
  pcap --premaster HEX       KDF from the recovered X25519 premaster secret
  pcap --keys-from-log FILE  pull the g100 in-process AES key-schedule hits
                             (keybe= / window hex) from the c2b log and
                             brute-verify each candidate against the pcap
                             (GCM tag = the oracle). Recovers the base IV by
                             scanning each hit's dumped memory window.
"""
import argparse
import hashlib
import hmac
import struct
import sys
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# message type ids (k_ESteamNetworkingUDPMsgID):
ID_CHALLENGE_REQUEST = 0x20
ID_CHALLENGE_REPLY = 0x21
ID_CONNECT_REQUEST = 0x22
ID_CONNECT_OK = 0x23
ID_CLOSED = 0x24
ID_NOCONN = 0x25
FLAG_DATA = 0x80
FLAG_PROTOBUF_BLOB = 0x01
FLAG_TIME_SINCE_PREV = 0x02


# ---------------------------------------------------------------- protobuf --
def pb_fields(buf):
    """Minimal protobuf field walker -> {tag: [values]}. Defensive against
    snaplen truncation: on any out-of-bounds, return what we have."""
    out = {}
    i = 0
    n = len(buf)
    while i < n:
        key = 0
        shift = 0
        while True:
            if i >= n:
                return out
            b = buf[i]
            i += 1
            key |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                break
        tag = key >> 3
        wt = key & 7
        if wt == 0:  # varint
            v = 0
            shift = 0
            while True:
                if i >= n:
                    return out
                b = buf[i]
                i += 1
                v |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            out.setdefault(tag, []).append(v)
        elif wt == 1:  # fixed64
            if i + 8 > n:
                return out
            out.setdefault(tag, []).append(struct.unpack_from("<Q", buf, i)[0])
            i += 8
        elif wt == 2:  # length-delimited: keep raw bytes
            l = 0
            shift = 0
            while True:
                if i >= n:
                    return out
                b = buf[i]
                i += 1
                l |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            if i + l > n:
                l = n - i  # truncated field
            out.setdefault(tag, []).append(bytes(buf[i:i + l]))
            i += l
        elif wt == 5:  # fixed32
            if i + 4 > n:
                return out
            out.setdefault(tag, []).append(struct.unpack_from("<I", buf, i)[0])
            i += 4
        else:
            break  # unknown wiretype — stop
    return out


# ------------------------------------------------------------------- pcap --
def read_pcap(path):
    """-> [(ts, udp_payload, src, sport, dst, dport)]"""
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        en = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        en = ">"
    elif magic == b"\x4d\x3c\xb2\xa1":
        en = "<"
    elif magic == b"\xa1\xb2\x3c\x4d":
        en = ">"
    else:
        raise SystemExit(f"not a classic pcap: {magic.hex()}")
    linktype = struct.unpack_from(en + "I", data, 20)[0]
    off = 24
    pkts = []
    while off + 16 <= len(data):
        ts_s, ts_u, incl, orig = struct.unpack_from(en + "IIII", data, off)
        off += 16
        frame = data[off:off + incl]
        off += incl
        pkts.append((ts_s + ts_u / 1e6, frame))
    out = []
    for ts, frame in pkts:
        ethertype = None
        if linktype == 276:  # LINUX_SLL2
            if len(frame) < 20:
                continue
            ethertype = struct.unpack_from(">H", frame, 0)[0]
            ip = frame[20:]
        elif linktype == 113:  # LINUX_SLL1
            if len(frame) < 16:
                continue
            ethertype = struct.unpack_from(">H", frame, 14)[0]
            ip = frame[16:]
        else:  # Ethernet (1) and the default path
            p = 0
            while True:
                if len(frame) < p + 14:
                    break
                ethertype = struct.unpack_from(">H", frame, p + 12)[0]
                if ethertype in (0x8100, 0x88a8):
                    p += 4
                    continue
                break
            if ethertype != 0x0800:
                continue
            ip = frame[p + 14:]
        if ethertype != 0x0800:
            continue
        if len(ip) < 20:
            continue
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 17:  # UDP
            continue
        udp = ip[ihl:]
        if len(udp) < 8:
            continue
        sport, dport, ulen = struct.unpack_from(">HHH", udp, 0)
        payload = udp[8:ulen] if ulen >= 8 and ulen - 8 <= len(udp) else udp[8:]
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        out.append((ts, payload, src, sport, dst, dport))
    return out


def game_flow(pkts):
    """Pick the flow carrying the actual SNS connection. The rank =
    (the DATA 0x8x packets, the handshake 0x22/0x23 msgs) desc — the
    run324 lesson: the pcap = MULTIPLE :28022 sessions (the aborted
    :37343 + the live :55574); the aborted = the handshake-heavy
    (the full challenge cycles) and won the (0x22/0x23, msgs) rank,
    while the REAL session = the data-heavy = 0 oracle packets = the
    decrypt silently skipped."""
    flows = {}
    for ts, pay, src, sp, dst, dp in pkts:
        if not pay:
            continue
        t = pay[0]
        key = tuple(sorted([(src, sp), (dst, dp)]))
        f = flows.setdefault(key, [0, 0, 0])
        if t in (ID_CONNECT_REQUEST, ID_CONNECT_OK, ID_CHALLENGE_REQUEST,
                 ID_CHALLENGE_REPLY):
            f[1] += 1
            if t in (ID_CONNECT_REQUEST, ID_CONNECT_OK):
                f[2] += 1
        if t & 0xF8 == 0x80 or (t & FLAG_DATA):
            f[0] += 1
    if not flows:
        return None
    # the data-carrying flow wins; the handshake-only flow = the fallback
    best = max(flows, key=lambda k: (flows[k][0], flows[k][2], flows[k][1]))
    return best


# ------------------------------------------------------------- handshake --
NO_LEN_MSGS = (0x22, 0x23)  # the connect-family: [msgid][proto], custom-built


def parse_control(pay):
    """Observed steamclient SNS build:
    0x22/0x23 (the connect-family) = [msgid u8][protobuf @1]
    0x20/0x21/0x24/0x25 (SendMsg)   = [msgid u8][u16 LE len][protobuf @3]
    (GNS master: SendMsg uses UDPPaddedMessageHdr; ConnectRequest/OK are
    hand-serialized without the length.)"""
    if not pay:
        return None, None
    msgid = pay[0]
    if msgid in NO_LEN_MSGS:
        f = pb_fields(pay[1:])
        return msgid, (f if f else None)
    if len(pay) >= 3:
        ln = struct.unpack_from("<H", pay, 1)[0]
        if 0 < ln <= len(pay) - 3:
            return msgid, pb_fields(pay[3:3 + ln])
    return msgid, None


def _b(v):
    """bytes-only filter (a truncated parse can yield ints for the tags)."""
    return bytes(v) if isinstance(v, (bytes, bytearray)) else None


def extract_handshake(pkts, flow):
    """-> dict with the client/server crypt+cert+connid from 0x22/0x23"""
    a, b = flow  # sorted (ip,port) pair; client = whoever sent 0x22
    hs = {"client": None, "server": None, "ts_first": None, "ts_last": None}
    for ts, pay, src, sp, dst, dp in pkts:
        if {(src, sp), (dst, dp)} != set(flow):
            continue
        if not pay or pay[0] not in (ID_CONNECT_REQUEST, ID_CONNECT_OK):
            continue
        msgid, f = parse_control(pay)
        if not f:
            continue
        if msgid == ID_CONNECT_REQUEST:
            side = "client"
            connid = f.get(1, [None])[0]
        elif msgid == ID_CONNECT_OK:
            side = "server"
            connid = f.get(5, [None])[0]
        else:
            continue
        crypt_signed = _b(f.get(7, [None])[0])
        cert_signed = _b(f.get(4, [None])[0]) or _b(f.get(8, [None])[0])
        info = {}
        inner = None
        if crypt_signed:
            cf = pb_fields(crypt_signed)
            inner = _b(cf.get(1, [None])[0])
            if inner:
                ci = pb_fields(inner)
                info["key_type"] = ci.get(1, [None])[0]
                info["key_data"] = _b(ci.get(2, [None])[0])
                info["nonce"] = ci.get(3, [None])[0]
        cert_inner = None
        if cert_signed:
            sf = pb_fields(cert_signed)
            # Valve-internal CertSigned: the inner cert = field 4 (observed
            # 226108011220... = the CMsgSteamDatagramCertificate); the GNS
            # master uses field 1 — try both.
            cert_inner = _b(sf.get(4, [None])[0]) or _b(sf.get(1, [None])[0])
        hs[side] = {"connid": connid, "crypt_inner": inner,
                    "nonce": info.get("nonce"),
                    "key_data": info.get("key_data"),
                    "key_type": info.get("key_type"),
                    "cert_inner": cert_inner}
        if hs["ts_first"] is None:
            hs["ts_first"] = ts
        hs["ts_last"] = ts
    return hs


# ------------------------------------------------------------------- kdf --
def kdf_client_view(premaster, client_nonce, server_nonce, client_connid,
                    server_connid, server_cert_inner, client_cert_inner,
                    server_crypt_inner, client_crypt_inner):
    """Returns (key_send, key_recv, iv_send, iv_recv) — the CLIENT side."""
    salt = struct.pack("<QQ", server_nonce, client_nonce)
    prk = hmac.new(premaster, salt, hashlib.sha256).digest()
    ctx = (struct.pack("<II", client_connid & 0xFFFFFFFF,
                       server_connid & 0xFFFFFFFF)
           + b"Steam datagram"
           + server_cert_inner + client_cert_inner
           + server_crypt_inner + client_crypt_inner)
    outs = []
    prev = b"\x00" * 32
    for k in range(1, 5):
        prev = hmac.new(prk, prev + ctx + bytes([k]), hashlib.sha256).digest()
        outs.append(prev)
    return outs[0], outs[1], outs[2][:12], outs[3][:12]


# --------------------------------------------------------------- packets --
def parse_data_pkt(pay):
    """0x80-family data packet -> (flags, to_connid, seq, chunk|None)"""
    if len(pay) < 7 or not (pay[0] & FLAG_DATA):
        return None, None, None, None
    flags = pay[0]
    to_conn = struct.unpack_from("<I", pay, 1)[0]
    seq = struct.unpack_from("<H", pay, 5)[0]  # pack(1): flags@0,conn@1,seq@5
    p = 7
    if flags & FLAG_PROTOBUF_BLOB:
        ln = 0
        shift = 0
        while p < len(pay):
            c = pay[p]
            p += 1
            ln |= (c & 0x7F) << shift
            shift += 7
            if not (c & 0x80):
                break
        p += ln  # skip stats blob (opaque here)
    if flags & FLAG_TIME_SINCE_PREV:
        p += 2
    chunk = pay[p:] if p < len(pay) else b""
    return flags, to_conn, seq, chunk


def gcm_decrypt(key, iv, chunk):
    """ct||tag -> plaintext or None"""
    if len(chunk) <= 16:
        return None
    try:
        return AESGCM(key).decrypt(iv, chunk, None)
    except Exception:
        return None


def decrypt_stream(pkts, flow, key_send, key_recv, iv_send, iv_recv,
                   verbose=True):
    """Both directions. client->server uses (key_send, iv_send);
    server->client uses (key_recv, iv_recv). Returns per-packet results."""
    a, b = flow
    res = []
    for ts, pay, src, sp, dst, dp in pkts:
        if {(src, sp), (dst, dp)} != set(flow):
            continue
        if not pay or not (pay[0] & FLAG_DATA):
            continue
        flags, to_conn, seq, chunk = parse_data_pkt(pay)
        if chunk is None or len(chunk) <= 16:
            continue
        from_server = (src, sp) == b
        key, base_iv = (key_recv, iv_recv) if from_server else (key_send,
                                                                iv_send)
        got = None
        pkt_num_used = None
        for k in range(4):
            pkt = seq + 0x10000 * k
            iv = bytearray(base_iv)
            iv0 = int.from_bytes(iv[0:8], "little") + pkt
            iv[0:8] = iv0.to_bytes(8, "little")
            pt = gcm_decrypt(key, bytes(iv), chunk)
            if pt is not None:
                got = pt
                pkt_num_used = pkt
                break
        res.append({"ts": ts, "srv": from_server, "seq": seq,
                    "to_conn": to_conn, "len": len(pay),
                    "chunk": len(chunk), "pt": got, "pkt_num": pkt_num_used})
        if verbose:
            d = "S>C" if from_server else "C>S"
            if got is not None:
                print(f"  {d} t={ts:.3f} seq={seq} pkt={pkt_num_used} "
                      f"chunk={len(chunk)} PT[{len(got)}]={got.hex()}")
            else:
                print(f"  {d} t={ts:.3f} seq={seq} chunk={len(chunk)} "
                      f"DECRYPT-FAIL")
    return res


def snp_frames(pt):
    """Walk the SNP frame stream (SNP_WIRE_FORMAT.md). -> [(kind, size)]"""
    out = []
    i = 0
    n = len(pt)
    while i < n:
        t = pt[i]
        if t & 0x80:  # 1xxx = acks/stats/etc — opaque, stop census at first
            out.append(("ctrl/ack", n - i))
            break
        if (t & 0xE0) == 0x00:  # unreliable segment 00emosss
            e = (t >> 5) & 1
            sss = t & 7
            i += 1
            sz = None
            if sss <= 4:
                sz = ((t & 7) << 8) | pt[i] if False else None
                # per doc: upper 3 bits append to the explicit size byte:
                sz = ((t & 7) << 8) | pt[i]
                i += 1
            elif sss == 7:
                sz = n - i
            else:
                out.append(("unrel-reserved", 0))
                break
            out.append(("unrel" + ("-last" if e else ""), sz + 1))
            i += sz
        elif (t & 0xE0) == 0x40:  # reliable segment 010mmsss
            mm = (t >> 3) & 3
            sss = t & 7
            i += 1
            sppos = mm  # 0:1B,1:2B,2:4B,3:8B stream_pos
            i += 1 << mm
            if sss == 7:
                sz = n - i
            else:
                sz = ((t & 7) << 8) | pt[i]
                i += 1
            out.append(("reliable", sz + 1))
            i += sz
        elif (t & 0xE0) == 0x60:  # lane-change etc
            out.append(("frame60+", n - i))
            break
        else:
            out.append(("?", n - i))
            break
    return out


# --------------------------------------------------------------- selftest --
def selftest2():
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey)
    cpriv = X25519PrivateKey.generate()
    spriv = X25519PrivateKey.generate()
    cpub = cpriv.public_key().public_bytes_raw()
    spub = spriv.public_key().public_bytes_raw()
    premaster = cpriv.exchange(spriv.public_key())
    c_nonce = 0x1122334455667788
    s_nonce = 0x99AABBCCDDEEFF00
    c_conn, s_conn = 0xDDCCBBAA, 0x11223344
    cert_c = b"\x0a\x10CLIENTCERTINNERBYTESxx01"
    cert_s = b"\x0a\x10SERVERCERTINNERBYTESxx02"
    # crypt inner = key_type + key_data + nonce, the real shape:
    def crypt_inner(pub, nonce):
        b = b"\x08\x01" + b"\x12\x20" + pub + b"\x18" + \
            struct.pack("<Q", nonce)
        return b
    ci_c = crypt_inner(cpub, c_nonce)
    ci_s = crypt_inner(spub, s_nonce)
    ks, kr, ivs, ivr = kdf_client_view(
        premaster, c_nonce, s_nonce, c_conn, s_conn, cert_s, cert_c,
        ci_s, ci_c)
    print("selftest keys:")
    print("  KeySend =", ks.hex())
    print("  KeyRecv =", kr.hex())
    print("  IVSend  =", ivs.hex())
    print("  IVRecv  =", ivr.hex())
    ok = True
    # C>S packet: seq 7
    seq = 7
    iv = bytearray(ivs)
    v = int.from_bytes(iv[0:8], "little") + seq
    iv[0:8] = v.to_bytes(8, "little")
    ct = AESGCM(ks).encrypt(bytes(iv), b"C2S-PAYLOAD-0123", None)
    hdr = bytes([FLAG_DATA]) + struct.pack("<IH", c_conn, seq)
    flags, to, sq, chunk = parse_data_pkt(hdr + ct)
    iv2 = bytearray(ivs)
    v2 = int.from_bytes(iv2[0:8], "little") + sq
    iv2[0:8] = v2.to_bytes(8, "little")
    pt = gcm_decrypt(ks, bytes(iv2), chunk)
    good = pt == b"C2S-PAYLOAD-0123"
    print(f"  C>S roundtrip seq=7: {'OK' if good else 'FAIL'}")
    ok &= good
    # S>C with the wire-seq wrap: seq = 0xFFFE -> pkt 0x1FFFE
    seq = 0xFFFE
    iv = bytearray(ivr)
    v = int.from_bytes(iv[0:8], "little") + 0x1FFFE
    iv[0:8] = v.to_bytes(8, "little")
    ct = AESGCM(kr).encrypt(bytes(iv), b"S2C-PAYLOAD-9876", None)
    hdr = bytes([FLAG_DATA]) + struct.pack("<IH", c_conn, seq)
    _, _, sq, chunk = parse_data_pkt(hdr + ct)
    pt = None
    for k in range(4):
        pkt = sq + 0x10000 * k
        iv2 = bytearray(ivr)
        v2 = int.from_bytes(iv2[0:8], "little") + pkt
        iv2[0:8] = v2.to_bytes(8, "little")
        pt = gcm_decrypt(kr, bytes(iv2), chunk)
        if pt is not None:
            break
    good = pt == b"S2C-PAYLOAD-9876"
    print(f"  S>C wrap-expansion seq=0xFFFE: "
          f"{'OK' if good else 'FAIL'} (pkt={pkt:#x})")
    ok &= good
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ------------------------------------------------------------ keys mode --
def parse_g100_log(path):
    """-> [(key32, window_bytes)] from the c2b g100/g113 log lines.
    The match = the bare 'aes256ks' substring: the g100 era = 'g100:
    aes256ks', the g113 era (the client-hook AES scan) = 'g113: aes256ks'
    — the prefix-bound filter = the run322-class silent-miss bug."""
    out = []
    import re
    for line in open(path, "r", errors="replace"):
        if "aes256ks" not in line:
            continue
        mb = re.search(r"keybe=([0-9a-f]{64})", line)
        mw = re.search(r"win=([0-9a-f]*)", line)
        if not mb:
            continue
        key = bytes.fromhex(mb.group(1))
        win = bytes.fromhex(mw.group(1)) if mw else b""
        out.append((key, win))
    return out


def brute_keys(pkts, flow, cands):
    """Try each candidate key(+window IVs) against each direction's packets.
    GCM tag = the oracle. Returns the (key, base_iv, direction) winners."""
    a, b = flow
    # the longest C>S and S>C data packets = the best oracles
    samples = {"cs": [], "sc": []}
    for ts, pay, src, sp, dst, dp in pkts:
        if {(src, sp), (dst, dp)} != set(flow):
            continue
        if not pay or not (pay[0] & FLAG_DATA):
            continue
        flags, to, seq, chunk = parse_data_pkt(pay)
        if not chunk or len(chunk) <= 16:
            continue
        d = "sc" if (src, sp) == b else "cs"
        samples[d].append((seq, chunk))
    for d in samples:
        samples[d].sort(key=lambda x: -len(x[1]))
    print(f"oracle packets: C>S={len(samples['cs'])} S>C={len(samples['sc'])}")
    for idx, (key, win) in enumerate(cands):
        for d in ("cs", "sc"):
            if not samples[d]:
                continue
            seq, chunk = samples[d][0]
            ivs = [None]
            if win:
                # every 12B window of the dumped memory
                for o in range(0, max(1, len(win) - 11)):
                    ivs.append(win[o:o + 12])
            for ivc in ivs:
                if ivc is None:
                    continue  # need the exact base iv; can't brute 96 bits
                for k in range(2):
                    pkt = seq + 0x10000 * k
                    iv = bytearray(ivc)
                    v = int.from_bytes(iv[0:8], "little") + pkt
                    iv[0:8] = v.to_bytes(8, "little")
                    if gcm_decrypt(key, bytes(iv), chunk) is not None:
                        return (key, bytes(ivc), d, idx, pkt)
    return None


# ------------------------------------------------------------------ main --
def parse_g103_log(path):
    """-> [(key32, tail16)] from the c2b chacha-capture log lines.
    Accepts BOTH the g103 chacha-state scan lines ('g103: CHA' with the
    explicit tail=) AND the g110 hook captures ('g110: KEYn ... key=<64hex>
    ictx=<32hex>' — the ictx dump = the 16B ctr||nonce block = the tail)."""
    out = []
    import re
    for line in open(path, "r", errors="replace"):
        if "g103: CHA" in line:
            mk = re.search(r"key=([0-9a-f]{64})", line)
            mt = re.search(r"tail=([0-9a-f]{32})", line)
        elif "g110: KEY" in line:
            mk = re.search(r"key=([0-9a-f]{64})", line)
            mt = re.search(r"ictx=([0-9a-f]{32})", line)
        else:
            continue
        if not mk:
            continue
        tail = bytes.fromhex(mt.group(1)) if mt else b"\x00" * 16
        out.append((bytes.fromhex(mk.group(1)), tail))
    return out


def chacha_decrypt(key, nonce12, chunk):
    if len(chunk) <= 16:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import (
            ChaCha20Poly1305)
        return ChaCha20Poly1305(key).decrypt(nonce12, chunk, None)
    except Exception:
        return None


def chacha_brute(pkts, flow, cands):
    """The captured state = [sigma|key|ctr|last-nonce]. The nonce = the
    per-packet base + pkt (the first 8B LE add). Brute: for each key,
    direction, pkt and wrap k: nonce = captured - pkt_num; the Poly1305
    tag = the oracle. Returns (key, base_iv12, dir, pkt_num) or None."""
    a, b = flow
    trials = []
    for ts, pay, src, sp, dst, dp in pkts:
        if {(src, sp), (dst, dp)} != set(flow):
            continue
        if not pay or not (pay[0] & FLAG_DATA):
            continue
        flags, to_conn, seq, chunk = parse_data_pkt(pay)
        if chunk is None or len(chunk) <= 16:
            continue
        d = "sc" if (src, sp) == b else "cs"
        trials.append((d, seq, chunk))
    trials.sort(key=lambda x: -len(x[2]))  # the longest = the best oracle
    for key, tail in cands:
        for d, seq, chunk in trials[:6]:
            for k in range(4):
                pkt = seq + 0x10000 * k
                nonce = bytearray(tail[4:16])
                n0 = (int.from_bytes(nonce[0:8], "little") - pkt) \
                    & 0xFFFFFFFFFFFFFFFF
                nonce[0:8] = n0.to_bytes(8, "little")
                pt = chacha_decrypt(key, bytes(nonce), chunk)
                if pt is not None:
                    return key, bytes(nonce), d, pkt, pt
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--premaster", default=None)
    ap.add_argument("--keys-from-log", default=None)
    ap.add_argument("--chacha-log", default=None)
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest2())

    if not args.pcap:
        ap.error("pcap required (or --selftest)")
    pkts = read_pcap(args.pcap)
    print(f"pcap: {len(pkts)} udp packets")
    flow = game_flow(pkts)
    if not flow:
        raise SystemExit("no SNS handshake flow found")
    print(f"game flow: {flow[0][0]}:{flow[0][1]} <-> {flow[1][0]}:{flow[1][1]}")
    hs = extract_handshake(pkts, flow)
    for side in ("client", "server"):
        h = hs[side]
        if not h:
            print(f"{side}: MISSING")
            continue
        nonce = h["nonce"]
        ns = f"{nonce:#x}" if isinstance(nonce, int) else str(nonce)
        print(f"{side}: connid={h['connid']:#x} nonce="
              f"{ns} key_type={h['key_type']} "
              f"pub={h['key_data'].hex() if h['key_data'] else None}")
        print(f"        cert_inner={h['cert_inner'].hex() if h['cert_inner'] else None}")
        print(f"        crypt_inner={h['crypt_inner'].hex() if h['crypt_inner'] else None}")

    data_pkts = [p for p in pkts if p[1] and (p[1][0] & FLAG_DATA)]
    print(f"data packets (0x8x): {len(data_pkts)}")

    if args.premaster:
        pm = bytes.fromhex(args.premaster)
        ks, kr, ivs, ivr = kdf_client_view(
            pm, hs["client"]["nonce"], hs["server"]["nonce"],
            hs["client"]["connid"], hs["server"]["connid"],
            hs["server"]["cert_inner"], hs["client"]["cert_inner"],
            hs["server"]["crypt_inner"], hs["client"]["crypt_inner"])
        print(f"KeySend={ks.hex()}\nKeyRecv={kr.hex()}\nIVSend={ivs.hex()}"
              f"\nIVRecv={ivr.hex()}")
        decrypt_stream(pkts, flow, ks, kr, ivs, ivr)
    elif args.chacha_log:
        cands = parse_g103_log(args.chacha_log)
        print(f"g103 chacha candidates: {len(cands)}")
        hit = chacha_brute(pkts, flow, cands)
        if not hit:
            print("NO CHACHA CANDIDATE VERIFIED")
            sys.exit(2)
        key, base_iv, d, pkt, pt0 = hit
        print(f"VERIFIED chacha key={key.hex()} dir={d} "
              f"base_iv={base_iv.hex()} (pkt={pkt})")
        print(f"first PT[{len(pt0)}]={pt0.hex()}")
        # full stream both directions with the winning key/base
        a, b = flow
        n_ok = n_tot = 0
        for ts, pay, src, sp, dst, dp in pkts:
            if {(src, sp), (dst, dp)} != set(flow):
                continue
            if not pay or not (pay[0] & FLAG_DATA):
                continue
            flags, to_conn, seq, chunk = parse_data_pkt(pay)
            if chunk is None or len(chunk) <= 16:
                continue
            from_server = (src, sp) == b
            n_tot += 1
            for k in range(4):
                pkt2 = seq + 0x10000 * k
                nonce = bytearray(base_iv)
                n0 = (int.from_bytes(nonce[0:8], "little") + pkt2) \
                    & 0xFFFFFFFFFFFFFFFF
                nonce[0:8] = n0.to_bytes(8, "little")
                pt = chacha_decrypt(key, bytes(nonce), chunk)
                if pt is not None:
                    n_ok += 1
                    dd = "S>C" if from_server else "C>S"
                    print(f"  {dd} t={ts:.3f} seq={seq} pkt={pkt2} "
                          f"PT[{len(pt)}]={pt.hex()}")
                    break
        print(f"decrypted {n_ok}/{n_tot} data packets (single-key view)")
    elif args.keys_from_log:
        cands = parse_g100_log(args.keys_from_log)
        print(f"g100 candidates: {len(cands)}")
        hit = brute_keys(pkts, flow, cands)
        if not hit:
            print("NO KEY CANDIDATE VERIFIED")
            sys.exit(2)
        key, base_iv, d, idx, pkt = hit
        print(f"VERIFIED key[{idx}] dir={d} base_iv={base_iv.hex()} "
              f"(pkt={pkt}) key={key.hex()}")
        # decrypt the full stream with the winning direction mapping
        ks, kr = (key, None) if d == "cs" else (None, key)
        ivs, ivr = (base_iv, None) if d == "cs" else (None, base_iv)
        res = decrypt_stream(pkts, flow, ks or key, kr or key,
                             ivs or base_iv, ivr or base_iv, verbose=True)
        n_ok = sum(1 for r in res if r["pt"] is not None)
        print(f"decrypted {n_ok}/{len(res)} data packets")
    else:
        print("(give --premaster/--keys-from-log/--chacha-log to decrypt)")


if __name__ == "__main__":
    main()
