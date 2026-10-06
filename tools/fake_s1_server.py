#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""c2b fake-S1-server FARM — response-matrix probe against the CS:GO legacy engine.

WHY (worklog session-20261005-15): static RE of engine_client.so is exhausted.
The 'A'-case parser is fully known (chal le32 -> authproto le32 [3 => keysize
u16 must be 0] -> value ReadLong -> flag u8 -> ReadString -> strstr("reserve")
=> OnReserveAccepted (no-op without a pending MM reserve); strstr("connect")
=> redirect flow). What is NOT known: which wire response makes the engine
SEND its connect packet (client_client.so builds it) — the entry prize for
CL v2 phase B (S2 ConnectRequest with crypt).

HOW: UDP socket on 127.0.0.1:29015 (the steam://connect target). PUSH-mode:
every push_interval seconds serve the next matrix entry to the client addr
(source addr == the address the engine connects to, so the strict 'B' source
validation passes). Engine retries (qconnect0x...) are LOGGED, never answered
(push cadence is deterministic and not driven by retry timing). After a
consume-class entry (or ANY non-qconnect RX) pushes pause consume_gap seconds
so a developing reaction is not clobbered by the next (wrong) response.

EVIDENCE: logdir/packets.log (every RX/PUSH with hexdump), logdir/dump/*.bin
(full packets that are not qconnect), logdir/CONNECT_*.bin (JACKPOT markers —
the engine sent its connect packet; verdict PASS). A second log-only socket on
port+1 catches ConnectRedirect flows.

All connectionless packets carry the ffffffff OOB prefix. Matrix builders
mirror src/c2bridge.c c2b_clv2_build_chalreply() (fmt5/fmt8 proven live in
runs 45-52) and the engine_client.so RE notes (session-20261005-14/15).

stdlib only; python3 on the runner is fine.
"""

import argparse
import os
import socket
import struct
import sys
import time


def log_exc(msg):
    import traceback
    return "%s: %s" % (msg, traceback.format_exc(limit=3).replace("\n", " | "))


def le16(v):
    return struct.pack("<H", v & 0xFFFF)


def le32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


RES = b"reserve\x00"
RES9 = b"reserve" * 9 + b"\x00"          # fmt8 N-agnostic tail
CONNSTR = b"connect 127.0.0.1:29016\x00"  # 'A'-parser redirect flow

# EXACT A2S_INFO 'I' reply captured from the REAL CS2 server (CYBERSHOKE
# 152.233.19.133:28022, 2026-10-05): kept for reference/verification.
REAL_INFO = bytes.fromhex(
    "ffffffff491143533220355835207c203576352023323837205b42525d20e28094204359"
    "42455253484f4b452e4e45540064655f6d6972616765006373676f00436f756e7465722d"
    "537472696b65203200da02004000646c0001312e34312e382e3800b1766d070aee000000"
    "3001656d7074792c3576352c357673352c3578352c62742c63796265722c6379626572"
    "73686f6b652c64655f6d69726167652c64726f702c6475656c2c656e2c6700da020000"
    "00000000")


# REAL steamid captured from the CYBERSHOKE server's EDF 0x10 field
REAL_STEAMID = bytes.fromhex("070aee0000003001")

# ---- THE REAL 'A' REPLY (2026-10-06, live CS:GO-legacy servers
# 191.96.94.111:27015 / 46.174.52.230:27015 / 46.174.55.194:27015 — all three
# answered our qconnect0x00000000 with the IDENTICAL 59-byte structure):
#   'A' + le32(challenge) + le32(3) + u16(0) + le32(value=SERVER STEAMID
#   LOW-32!) + u8(0)
#   + "connect0x00000000\0" (THE ECHO OF OUR qconnect TOKEN — NOT "reserve"!)
#   + "96\0" + NUL padding to 59 bytes.
# The string contains "connect" -> per the engine RE this drives the
# REDIRECT/CONNECT flow (not the MM-reserve no-op) -> the engine should
# finally SEND its connect packet (the phase-B capture prize).
REAL_A_VARIANTS = [
    # (value, mystery4) — rotate per qconnect; the engine sends ONE qconnect
    # per attempt (run 72: the reply consumes the retry), so each harness
    # attempt tests one variant.
    (0x00F2CC9B, b"\x00\x30\x01\x01"),   # v0: run-72 baseline (steamid-low)
    (0x00F2CC9B, b"\x00\x00\x30\x01"),   # v1: mystery = steamid-high32 LE
    (0x00000000, b"\x00\x00\x30\x01"),   # v2: zero value + steamid-high
    (0x00F2CC9B, b"\x01\x00\x30\x01"),   # v3: alt high
    (0x00000000, b"\x00\x30\x01\x01"),   # v4: zero value, baseline mystery
]
_real_a_vi = [0]


def real_legacy_A(chal, qc_val, value=0x00F2CC9B):
    """Byte-exact reconstruction of the live legacy-server reply (all three
    captured servers share the structure):
      'A' + le32(chal) + le32(3) + u16(0) + le32(value) + u8(0)
      + b'\x00\x30\x01\x01'   <- four bytes the static RE missed (constant
                                   across servers, sits between flag and the
                                   string; parser consumes them somehow)
      + "connect0x<ECHO of the engine's qconnect token>\0" + "96\0"
      + NUL padding to 55 bytes payload (59 with the ffff prefix)."""
    pkt = (b"A"
           + le32(chal)
           + le32(3)          # authproto = Steam
           + le16(0)          # keysize = 0
           + le32(value)
           + b"\x00"          # flag = 0
           + b"\x00\x30\x01\x01"
           + b"connect0x" + ("%.8X" % (qc_val & 0xFFFFFFFF)).encode()
           + b"\x00"
           + b"96\x00")
    return pkt + b"\x00" * (55 - len(pkt))


def build_join_sequence():
    """DEPRECATED by the real-capture flow: the real legacy servers never
    replied to bare 'j' - the join path belongs to the MM-reserve flow we do
    NOT need. The engine's qconnect now gets the REAL 'A' reply immediately."""
    return []


def edf_variant(flags, game_port):
    """EDF section builder. flags = which optional fields to include.
    RUN 62 MATRIX (per-time-window): the engine sends NOTHING during the whole
    connect window (run 61 strace ground truth) - the CS:GO-era connect needs
    the server's steamid (EDF 0x10) to request a Steam auth session ticket
    for the connect packet. Variants isolate: port-only, steamid-only, both,
    full (58/59 bad), none (57/60 handoff control)."""
    out = b""
    if flags & 0x80:
        out += le16(game_port)
    if flags & 0x10:
        out += REAL_STEAMID
    if flags & 0x20:
        out += le16(game_port + 1)
    if flags & 0x01:
        out += b"c2b,farm\x00"
    return out


# EDF variant matrix, served per time window (~attempt length)
EDF_MATRIX = [
    (0x80, "port-only"),
    (0x80 | 0x10, "port+steamid"),
    (0x10, "steamid-only"),
    (0x00, "none (57/60 control)"),
    (0x80 | 0x10 | 0x20 | 0x01, "full (58/59 control)"),
]
WINDOW = 260.0  # seconds per variant (~one harness attempt)


def serverinfo(game_port, t_abs, version="1.38.0.4"):
    """Legacy identity base + time-windowed EDF variant."""
    idx = int(t_abs / WINDOW) % len(EDF_MATRIX)
    flags, name = EDF_MATRIX[idx]
    body = (b"\x11"                          # protocol 17
            + b"c2b-farm\x00"
            + b"de_dust2\x00"
            + b"csgo\x00"
            + b"Counter-Strike: Global Offensive\x00"
            + le16(730)                      # appid
            + b"\x00\x18\x00"                # 0 players, 24 max, 0 bots
            + b"dl"                          # dedicated, linux
            + b"\x00\x00"                    # public, VAC off
            + version.encode() + b"\x00")    # REAL bundle version
    edf = edf_variant(flags, game_port)
    if edf:
        body += bytes([flags]) + edf
    return b"\xff\xff\xff\xffI" + body, name


class Ctx(object):
    """Per-run mutable context for builders (chal counter + last qc echo)."""

    def __init__(self):
        self.chal = 0x10000001
        self.qc_val = 0

    def next_chal(self):
        c = self.chal
        self.chal = (self.chal + 1) & 0xFFFFFFFF or 0x10000001
        return c


def a_reserve(ctx, value=None, flag=0, s=RES, proto=3, ks=True):
    """'A' full CS:GO-MM layout: 'A', chal le32, proto le32, [ks u16=0], value
    le32, flag u8, ReadString. (Message char FIRST — the engine dispatches on
    the byte right after the ffff prefix.)"""
    out = b"A" + le32(ctx["chal"]) + le32(proto)
    if ks and proto == 3:
        out += le16(0)
    out += le32(ctx["qc_val"] if value is None else value)
    out += bytes([flag & 0xFF]) + s
    return out


def sinfo_blob():
    """A2S_INFO 'I' reply (Source server-browser format, shared by the engine's
    S2C_SERVERINFO case): protocol byte + name/map/folder/game + appid + counts
    + servertype/env/visibility/vac + version. No EDF. appid 730 = CS:GO legacy
    (the appid the runner client owns)."""
    return (b"\x11"                                    # protocol 17
            + b"c2b-farm\x00"
            + b"de_dust2\x00"
            + b"csgo\x00"
            + b"Counter-Strike: Global Offensive\x00"
            + struct.pack("<H", 730)                   # appid
            + b"\x00"                                  # players
            + b"\x18"                                  # max 24
            + b"\x00"                                  # bots
            + b"d"                                     # dedicated
            + b"l"                                     # linux
            + b"\x00"                                  # public
            + b"\x00"                                  # VAC off (we run -insecure)
            + b"1.38.0.4\x00")                         # version


# name -> (cls, builder(ctx)->bytes-without-ffff-prefix-or-None)
# cls: "silent" | "ignore" (engine should keep retrying) | "consume" (parseable;
# may move the engine's state machine -> longer silence after serving)
def build_matrix():
    m = []

    def add(name, cls, fn):
        m.append((name, cls, fn))

    add("silent", "silent", lambda ctx: None)

    # ---- group A reserve (proven parseable layout, fmt5/fmt8 family) ----
    add("real_A", "consume",
        lambda ctx: real_legacy_A(ctx["chal"], ctx["qc_val"]))
    add("real_A_v0", "consume",
        lambda ctx: real_legacy_A(ctx["chal"], ctx["qc_val"], value=0))
    add("a_res_qc", "consume",
        lambda ctx: a_reserve(ctx))                            # value = qc echo
    add("a_res_v0", "consume",
        lambda ctx: a_reserve(ctx, value=0))                   # fmt5 control
    add("a_res_vmax", "consume",
        lambda ctx: a_reserve(ctx, value=0xFFFFFFFF))
    add("a_res_bigstr", "consume",
        lambda ctx: a_reserve(ctx, value=0, s=RES9))           # fmt8 N-agnostic
    add("a_res_flag1", "consume",
        lambda ctx: a_reserve(ctx, flag=1))                    # gate 482410 path
    add("a_res_str8", "consume",
        lambda ctx: a_reserve(ctx, s=b"reserve\x00\x00\x00"))

    # ---- group A redirect (strstr("connect") flow, no "reserve") ----
    add("a_conn_ip", "consume",
        lambda ctx: a_reserve(ctx, value=0, s=CONNSTR))
    add("a_conn_only", "consume",
        lambda ctx: a_reserve(ctx, value=0, s=b"connect\x00"))

    # ---- group A proto!=3 (keysize u16 skipped? layout probe) ----
    add("a_p0_res", "consume",
        lambda ctx: a_reserve(ctx, proto=0, ks=False))
    add("a_p0_val", "ignore",
        lambda ctx: a_reserve(ctx, proto=0, ks=False, s=b"\x00"))

    # ---- group A binary / aborts ----
    add("a_5b", "consume", lambda ctx: b"A" + le32(ctx["chal"]))       # run 45 baseline
    add("a_ks_bad", "consume",                                  # Invalid Steam key size
        lambda ctx: b"A" + le32(ctx["chal"]) + le32(3) + le16(4) + b"0\x00\x00")
    add("a_15b", "ignore",                                      # string read = ""
        lambda ctx: b"A" + le32(ctx["chal"]) + le32(3) + le16(0) + le32(0) + b"\x00")

    # ---- group B (S2C_CONNECTION: '.' + 8B token; strict source validation) ----
    add("b_dot8A", "consume", lambda ctx: b"B." + b"A" * 8)
    add("b_dot0", "consume", lambda ctx: b"B." + b"\x00" * 8)
    add("b_dotff", "consume", lambda ctx: b"B." + b"\xff" * 8)
    add("b_dotle0", "consume", lambda ctx: b"B." + le32(0) + le32(0))
    add("b_dot_num", "consume", lambda ctx: b"B." + le32(1) + le32(0))
    add("b_bare", "consume", lambda ctx: b"B")
    add("b_dot", "consume", lambda ctx: b"B.")

    # ---- group 9 (S2C_CONNREJECT / redirect) ----
    add("9_full", "consume", lambda ctx: b"9Server full\x00")
    add("9_conn_ip", "consume", lambda ctx: b"9" + CONNSTR)
    add("9_redir_field", "consume",
        lambda ctx: b"9reject\x00ConnectRedirectAddress:127.0.0.1:29016\x00")

    # ---- misc connectionless (reaction probes) ----
    add("l_ack", "ignore", lambda ctx: b"l")
    add("l_ack_str", "ignore", lambda ctx: b"lACK\x00")
    add("i_sinfo", "ignore", lambda ctx: b"I" + sinfo_blob())
    add("C_sinfo", "ignore", lambda ctx: b"C" + sinfo_blob())
    add("nul8", "ignore", lambda ctx: b"\x00" * 8)
    add("caret", "ignore", lambda ctx: b"^" + b"A" * 8)
    add("ilow", "ignore", lambda ctx: b"i" + b"A" * 8)
    add("jay", "ignore", lambda ctx: b"j" + b"A" * 8)
    add("pee", "ignore", lambda ctx: b"p" + b"A" * 8)
    add("pct", "ignore", lambda ctx: b"%" + b"A" * 8)
    add("tee", "ignore", lambda ctx: b"t" + b"A" * 8)
    add("junk32", "ignore", lambda ctx: bytes(range(32)))
    return m


MATRIX = build_matrix()


def build_join_sequence():
    """After the engine's 'j' (join request), the reservation exists
    client-side. Sequence mirrors the MM reserve flow: reserve-'A' challenge
    (multiple formats, repeated like a real server), then 'B' accept."""
    seq = []
    for _ in range(2):
        seq.append(("a_res_qc", a_reserve))
        seq.append(("a_res_v0", lambda c: a_reserve(c, value=0)))
    seq.append(("a_res_bigstr", lambda c: a_reserve(c, value=0, s=RES9)))
    seq.append(("b_dot8A", lambda c: b"B." + b"A" * 8))
    seq.append(("b_dot0", lambda c: b"B." + b"\x00" * 8))
    seq.append(("b_dotle0", lambda c: b"B." + le32(0) + le32(0)))
    return seq


JOIN_SEQUENCE = build_join_sequence()


def hexd(b, maxb=96):
    s = binascii_hex(b[:maxb])
    if len(b) > maxb:
        s += "..."
    return s


def binascii_hex(b):
    return "".join("%02x" % c for c in b)


class Farm(object):
    def __init__(self, bind, ports, logdir, interval, consume_gap, silent_rx_gap):
        self.bind = bind
        self.ports = ports          # list: primary query/game port + alt game ports + redirect
        self.logdir = logdir
        self.interval = interval
        self.consume_gap = consume_gap
        self.silent_rx_gap = silent_rx_gap
        self.ctx = {"chal": 0, "qc_val": 0}
        self.chal = Ctx()
        self.idx = 0
        self.last_addr = None
        self.last_sock = None       # pushes go out where the last qconnect came in
        self.stats = {"rx": 0, "qc": 0, "connect": 0, "other": 0, "push": 0,
                      "redir": 0, "a2s": 0, "join": 0}
        self.a2s_answered_at = 0.0
        self.push_armed = False
        self.version = "1.38.0.4"
        self.engine_ports_file = None
        self.engine_ports = []
        self.push_host = "127.0.0.1"
        # REAL-SERVER REPLAY (run 66+: tools/capture_legacy_ref.py captures a
        # real CS:GO-legacy server's exact bytes; replay them verbatim)
        self.ref = {}
        try:
            refdir = os.path.join(self.logdir, "legacy_ref")
            for tag, fn in (("info_i", "info_i.bin"), ("chal_A", "chal_A.bin"),
                            ("join_reply", "join_reply.bin"),
                            ("player_d", "player_d.bin")):
                p = os.path.join(refdir, fn)
                if os.path.exists(p):
                    self.ref[tag] = open(p, "rb").read()
            rj = os.path.join(refdir, "ref.json")
            if os.path.exists(rj):
                self.ref["meta"] = json.load(open(rj))
        except Exception:
            pass
        # RUN 70 LESSON: the REAL info_i (with EDF 0xb1) re-creates the
        # client's 10s re-poll loop and the handoff NEVER fires (0 qconnect).
        # Runs 57/60/68 proved the handoff needs a NO-EDF serverinfo, and the
        # auth path gets the server identity from the 'A'-reply's value field
        # (= the server steamid low-32 bits) — the EDF steamid is redundant.
        # So: replay the real identity strings but STRIP the EDF tail.
        if "info_i" in self.ref:
            d = self.ref["info_i"]
            try:
                p = d[5:]
                i = 1
                for _ in range(4):          # name, map, folder, game
                    i = p.index(b"\x00", i) + 1
                i += 2 + 7                   # appid u16 + players/max/bots/type/env/vis/vac
                i = p.index(b"\x00", i) + 1  # version string
                blob = bytearray(d[:5] + p[:i])
                # RUN 71: the real legacy server reports appid=0 in the u16
                # field — the client refuses to hand off (it must match the
                # game's appid 730; the synthetic replies with 730 DID hand
                # off). Patch it.
                apid = 5 + 1
                for _ in range(4):            # name, map, folder, game
                    apid = blob.index(b"\x00", apid) + 1
                blob[apid:apid + 2] = le16(730)
                self.ref["info_i_noedf"] = bytes(blob)
            except ValueError:
                pass
        # JOIN flow state: after the engine answers our 'i' prompt with
        # 'j'+token (run 65: 3/3 causal), the reservation exists client-side
        # -> serve the reserve-'A' sequence instead of the raw matrix.
        self.join_seq = []          # pending (name, builder) responses
        self.join_last = 0.0
        self.dump_dir = os.path.join(logdir, "dump")
        os.makedirs(self.dump_dir, exist_ok=True)
        self.plog = open(os.path.join(logdir, "packets.log"), "a", buffering=1)
        self.t0 = time.time()
        self.next_push = time.time() + 1.0
        self.silent_until = 0.0
        self.hb = time.time() + 30.0

    def log(self, msg):
        self.plog.write("[T+%07.3f] %s\n" % (time.time() - self.t0, msg))

    def dump(self, tag, data):
        fn = "%s_t%08.3f_%d.bin" % (tag, time.time() - self.t0, len(data))
        path = os.path.join(self.dump_dir, fn)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def handle_rx(self, sock):
        data, addr = sock.recvfrom(65535)
        self.stats["rx"] += 1
        now = time.time()
        port = sock.getsockname()[1]
        self.log("RX :%d %dB src=%s:%d hex=%s" % (port, len(data), addr[0],
                                                  addr[1], hexd(data)))
        # ANY packet reveals the client's socket; remember it so pushes/A2S
        # replies always have a target (run 54: only qconnect set last_addr ->
        # the A2S_INFO phase never got a reply and pushes never armed).
        self.last_addr = addr
        if port != self.ports[0]:
            self.log("  *** packet on ALT port %d (default-port theory / "
                     "redirect) ***" % port)
        payload = data[4:] if data[:4] == b"\xff\xff\xff\xff" else None
        if payload is None:
            self.stats["other"] += 1
            self.dump("nonoob", data)
            self.silent_until = now + self.silent_rx_gap
            return
        # ---- A2S queries: the REAL server (and every modern Steam server)
        # answers a bare 'T' with a 0x41 CHALLENGE; the client re-sends with
        # the challenge and only then gets the 'I' (sandbox forensics vs
        # CYBERSHOKE: bare T -> 41 + le32). Runs 57-62 always replied 'I'
        # directly - the steam client's query lib likely treats that as
        # invalid -> engine never receives serverinfo -> retry loop. ----
        if payload[:1] == b"T":
            self.stats["a2s"] += 1
            try:
                if len(payload) <= 21:
                    # bare "TSource Engine Query\0" -> challenge step
                    self.ctx["chal2"] = (self.ctx.get("chal2", 0x5EED0000)
                                         + 1) & 0xFFFFFFFF
                    self.log("  -> A2S_INFO bare -> 0x41 challenge "
                             "0x%08X" % self.ctx["chal2"])
                    sock.sendto(b"\xff\xff\xff\xffA"
                                + le32(self.ctx["chal2"]), addr)
                    return
                # challenge-carrying query -> the 'I' reply (REAL server
                # bytes when the legacy ref was captured)
                if "info_i_noedf" in self.ref:
                    blob, vname = self.ref["info_i_noedf"], "REAL-NOEDF-REPLAY"
                elif "info_i" in self.ref:
                    blob, vname = self.ref["info_i"], "REAL-LEGACY-REPLAY"
                else:
                    blob, vname = serverinfo(self.ports[0], now - self.t0,
                                             self.version)
                self.log("  -> A2S_INFO+chal %dB -> EDF variant '%s' blob "
                         "%dB" % (len(payload), vname, len(blob)))
                sock.sendto(blob, addr)
                self.a2s_answered_at = now
                if not self.push_armed:
                    self.next_push = min(
                        self.next_push,
                        max(now + 20.0, self.silent_until))
            except OSError as e:
                self.log(log_exc("A2S reply failed"))
            return
        if payload.startswith(b"qconnect0x"):
            self.stats["qc"] += 1
            tail = payload[10:10 + 8]
            try:
                self.ctx["qc_val"] = int(tail, 16)
            except ValueError:
                self.ctx["qc_val"] = 0
            self.push_armed = True
            self.last_sock = sock      # answer from the same port the engine chose
            self.next_push = min(self.next_push, max(now + 0.5, now))
            self.log("  -> qconnect qc_val=0x%08X (pushes ARMED on this socket)"
                     % self.ctx["qc_val"])
            # THE REAL FLOW (live legacy servers, byte-exact structure):
            # answer with 'A' + challenge + "connect0x<echo of the engine's
            # qconnect token>" -> engine takes the redirect/connect path.
            # v17: rotate the (value, mystery4) pair per qconnect — the
            # auth path needs a valid server steamid and the exact field
            # mapping is unknown; one variant per harness attempt.
            vi = _real_a_vi[0] % len(REAL_A_VARIANTS)
            _real_a_vi[0] += 1
            val, mys = REAL_A_VARIANTS[vi]
            try:
                pkt = real_legacy_A(self.ctx["chal"], self.ctx["qc_val"],
                                    value=val)
                pkt = pkt[:16] + mys + pkt[20:]   # splice the variant mystery
                sock.sendto(b"\xff\xff\xff\xff" + pkt, addr)
                self.stats["push"] += 1
                self.log("  -> REAL-LEGACY-A[v%d] %dB val=0x%08X mys=%s "
                         "chal=0x%08X qc=0x%08X hex=%s"
                         % (vi, len(pkt), val, mys.hex(), self.ctx["chal"],
                            self.ctx["qc_val"], hexd(pkt)))
            except OSError as e:
                self.log(log_exc("real-A reply failed"))
            return
        if payload.startswith(b"getchallenge"):
            self.push_armed = True
            self.log("  -> classic getchallenge (pushes ARMED)")
            return
        if payload.startswith(b"connect"):
            self.stats["connect"] += 1
            n = self.stats["connect"]
            self.log("*** JACKPOT #%d: ENGINE CONNECT PACKET %dB src=%s:%d ***"
                     % (n, len(data), addr[0], addr[1]))
            path = self.dump("connect", data)
            marker = os.path.join(self.logdir, "CONNECT_%02d.bin" % n)
            with open(marker, "wb") as f:
                f.write(data)
            with open(marker + ".txt", "w") as f:
                f.write("from %s:%d\nsize %d\nsaved %s\nhex %s\n"
                        % (addr[0], addr[1], len(data), path, hexd(data, 4096)))
            self.silent_until = now + self.silent_rx_gap  # do not clobber
            return
        # ---- 'j' JOIN REQUEST (run 65 JACKPOT: our 'i' prompt makes the
        # engine send 'j'+14-zeros; NOW the pending reserve exists -> the
        # reserve-'A' sequence must follow IMMEDIATELY) ----
        if payload[:1] == b"j":
            self.stats["join"] += 1
            self.log("*** JOIN REQUEST #%d: %r ***" % (self.stats["join"],
                                                       payload[:20]))
            self.dump("join_rx", data)
            self.join_seq = JOIN_SEQUENCE
            self.join_last = now
            self.silent_until = 0.0
            self.next_push = now + 0.3   # fire the first reserve reply fast
            self.push_armed = True
            if "join_reply" in self.ref:
                try:
                    sock.sendto(self.ref["join_reply"], addr)
                    self.log("  -> REPLAYED real join_reply %dB"
                             % len(self.ref["join_reply"]))
                except OSError as e:
                    self.log(log_exc("join_reply replay failed"))
            return
        # ---- A2S_PLAYER 'U': challenge dance -> 'D' empty player list ----
        if payload[:1] == b"U":
            self.stats["a2s"] += 1
            try:
                if len(payload) <= 5:
                    self.log("  -> A2S_PLAYER bare -> 0x41 challenge")
                    self.ctx["chal2"] = (self.ctx.get("chal2", 0x5EED0000)
                                         + 1) & 0xFFFFFFFF
                    sock.sendto(b"\xff\xff\xff\xffA"
                                + le32(self.ctx["chal2"]), addr)
                else:
                    blob = self.ref.get("player_d") or b"\xff\xff\xff\xffD\x00"
                    self.log("  -> A2S_PLAYER+chal -> 'D' reply %dB" % len(blob))
                    sock.sendto(blob, addr)
            except OSError as e:
                self.log(log_exc("A2S_PLAYER reply failed"))
            return
        self.stats["other"] += 1
        self.dump("other_rx", data)
        self.silent_until = now + self.silent_rx_gap

    def push_next(self, sock):  # sock = primary (connect-target source)
        if self.join_seq:
            name, fn = self.join_seq.pop(0)
            cls = "join"
        else:
            name, cls, fn = MATRIX[self.idx % len(MATRIX)]
            self.idx += 1
        self.ctx["chal"] = self.chal.next_chal()
        now = time.time()
        try:
            payload = fn(self.ctx)
        except Exception as e:  # builder bug must not kill the farm
            self.log("PUSH idx=%d name=%s BUILDER-ERROR %s" % (self.idx, name, e))
            payload = None
        if payload is None or cls == "silent":
            self.log("PUSH idx=%d name=%s (silent)" % (self.idx, name))
        else:
            data = b"\xff\xff\xff\xff" + payload
            targets = []
            if self.engine_ports:
                # INTO the engine's sockets (source = connect target 29015,
                # so the strict 'B' source validation passes)
                targets = [(self.primary_sock, (self.push_host, p))
                           for p in self.engine_ports]
            elif self.last_addr is not None:
                targets = [(sock, self.last_addr)]
            for s, dst in targets:
                try:
                    s.sendto(data, dst)
                    self.stats["push"] += 1
                    self.log("PUSH idx=%d name=%s cls=%s %dB dst=%s:%d "
                             "chal=0x%08X qc=0x%08X hex=%s"
                             % (self.idx, name, cls, len(data), dst[0],
                                dst[1], self.ctx["chal"],
                                self.ctx["qc_val"], hexd(data)))
                except OSError as e:
                    self.log("PUSH idx=%d name=%s SEND-ERROR %s"
                             % (self.idx, name, e))
            if not targets:
                self.log("PUSH idx=%d name=%s DROPPED (no target yet)"
                         % (self.idx, name))
        if cls == "join":
            gap = 1.2
        elif cls in ("ignore", "silent"):
            gap = self.interval
        else:
            gap = self.consume_gap
        self.next_push = max(now + gap, self.silent_until)

    def run(self):
        socks = []
        for port in self.ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.bind, port))
            socks.append(s)
        self.primary_sock = socks[0]  # source = connect target (29015)
        self.log("FARM UP bind=%s ports=%s entries=%d interval=%.1fs "
                 "consume_gap=%.1fs window=%.0fs"
                 % (self.bind, self.ports, len(MATRIX),
                    self.interval, self.consume_gap, WINDOW))
        for i, (flags, name) in enumerate(EDF_MATRIX):
            self.log("  edf[%d] %-24s flags=0x%02x" % (i, name, flags))
        self.log("  legacy ref: %s"
                 % (sorted(k for k in self.ref if k != "meta") or "NONE"))
        for i, (name, cls, _) in enumerate(MATRIX):
            self.log("  matrix[%02d] %-14s %s" % (i, name, cls))
        while True:
            try:
                self.loop_once(socks)
            except Exception:  # the farm must NEVER die (run 54: heartbeat
                self.log(log_exc("LOOP-ERROR (continuing)"))  # format crash)
                time.sleep(0.5)

    def load_engine_ports(self):
        """Harness writes the engine's REAL UDP ports (ss -ulnp) per attempt;
        matrix pushes must reach the ENGINE's connectionless dispatcher, not
        the steam client's A2S query socket (runs 57-62 bug)."""
        if not self.engine_ports_file:
            return
        try:
            txt = open(self.engine_ports_file).read().split()
            ports = sorted({int(p) for p in txt if p.isdigit()
                            and 1024 < int(p) < 65536})[:8]
            if ports and ports != self.engine_ports:
                self.log("engine ports updated: %s" % ports)
                self.engine_ports = ports
        except OSError:
            pass

    def loop_once(self, socks):
        now = time.time()
        self.load_engine_ports()
        timeout = 0.5
        if (self.push_armed and self.last_addr is not None) \
                or self.engine_ports:
            timeout = max(0.05, min(timeout, self.next_push - now))
        r, _, _ = select_select(socks, [], [], timeout)
        for s in r:
            self.handle_rx(s)
        now = time.time()
        # A2S grace: if the client asked for serverinfo but no qconnect ever
        # came, still arm pushes 20s later (matrix evidence must not starve)
        if (not self.push_armed and self.a2s_answered_at
                and now - self.a2s_answered_at >= 20.0):
            self.push_armed = True
            self.log("PUSHES ARMED via A2S grace (no qconnect in 20s)")
        if ((self.push_armed or self.engine_ports)
                and now >= self.next_push and now >= self.silent_until):
            self.push_next(socks[0])
        if time.time() >= self.hb:
            self.log("HEARTBEAT rx=%(rx)d qc=%(qc)d a2s=%(a2s)d "
                     "connect=%(connect)d other=%(other)d push=%(push)d "
                     "redir=%(redir)d armed=%(armed)d matrix_idx=%(idx)d "
                     "last=%(last)s"
                     % dict(self.stats, armed=int(self.push_armed),
                            idx=self.idx, last=self.last_addr))
            self.hb = time.time() + 30.0


def select_select(r, w, x, t):
    import select
    return select.select(r, w, x, t)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=29015)
    ap.add_argument("--alt-ports", default="29016",
                    help="extra full-peer ports (redirect catch; 27015 is "
                         "deliberately NOT bound - the engine needs it)")
    ap.add_argument("--log", default="/tmp/c2b-farm")
    ap.add_argument("--push-interval", type=float, default=2.0)
    ap.add_argument("--consume-gap", type=float, default=10.0)
    ap.add_argument("--silent-rx-gap", type=float, default=12.0,
                    help="push pause after any non-qconnect RX")
    ap.add_argument("--version", default="1.38.0.4",
                    help="serverinfo version string (must match the client!)")
    ap.add_argument("--engine-ports-file", default=None,
                    help="file the harness updates with the engine's UDP ports")
    ap.add_argument("--push-host", default="127.0.0.1",
                    help="host portion of engine-port push targets (docker "
                         "gateway when running in a container)")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for i, (name, cls, _) in enumerate(MATRIX):
            print("%02d %-14s %s" % (i, name, cls))
        return 0
    os.makedirs(args.log, exist_ok=True)
    ports = [args.port] + [int(p) for p in args.alt_ports.split(",")
                           if int(p) != args.port]
    farm = Farm(args.bind, ports, args.log, args.push_interval,
                args.consume_gap, args.silent_rx_gap)
    farm.version = args.version
    farm.engine_ports_file = args.engine_ports_file
    farm.push_host = args.push_host
    farm.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
