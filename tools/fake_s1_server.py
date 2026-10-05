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


def le16(v):
    return struct.pack("<H", v & 0xFFFF)


def le32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


RES = b"reserve\x00"
RES9 = b"reserve" * 9 + b"\x00"          # fmt8 N-agnostic tail
CONNSTR = b"connect 127.0.0.1:29016\x00"  # 'A'-parser redirect flow


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
    """'A' full CS:GO-MM layout: chal le32, proto le32, [ks u16=0], value le32,
    flag u8, ReadString."""
    out = le32(ctx["chal"]) + le32(proto)
    if ks and proto == 3:
        out += le16(0)
    out += le32(ctx["qc_val"] if value is None else value)
    out += bytes([flag & 0xFF]) + s
    return out


def sinfo_blob():
    """Minimal classic S2C_SERVERINFO print-string-ish blob (reaction probe)."""
    return (b"\x11" + b"127.0.0.1:29015\x00" + b"c2b-farm\x00" + b"de_dust2\x00"
            + b"cstrike\x00" + b"Counter-Strike\x00" + b"\x00\x00"
            + b"\x00\x00\x00\x00" + b"\x01\xd3\x04\x08\x00\x64\x64\x00"
            + b"0.0.0.0\x00")


# name -> (cls, builder(ctx)->bytes-without-ffff-prefix-or-None)
# cls: "silent" | "ignore" (engine should keep retrying) | "consume" (parseable;
# may move the engine's state machine -> longer silence after serving)
def build_matrix():
    m = []

    def add(name, cls, fn):
        m.append((name, cls, fn))

    add("silent", "silent", lambda ctx: None)

    # ---- group A reserve (proven parseable layout, fmt5/fmt8 family) ----
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
    add("a_5b", "consume", lambda ctx: le32(ctx["chal"]))       # run 45 baseline
    add("a_ks_bad", "consume",                                  # Invalid Steam key size
        lambda ctx: le32(ctx["chal"]) + le32(3) + le16(4) + b"0\x00\x00")
    add("a_15b", "ignore",                                      # string read = ""
        lambda ctx: le32(ctx["chal"]) + le32(3) + le16(0) + le32(0) + b"\x00")

    # ---- group B (S2C_CONNECTION: '.' + 8B token; strict source validation) ----
    add("b_dot8A", "consume", lambda ctx: b"." + b"A" * 8)
    add("b_dot0", "consume", lambda ctx: b"." + b"\x00" * 8)
    add("b_dotff", "consume", lambda ctx: b"." + b"\xff" * 8)
    add("b_dotle0", "consume", lambda ctx: b"." + le32(0) + le32(0))
    add("b_dot_num", "consume", lambda ctx: b"." + le32(1) + le32(0))
    add("b_bare", "consume", lambda ctx: b"")
    add("b_dot", "consume", lambda ctx: b".")

    # ---- group 9 (S2C_CONNREJECT / redirect) ----
    add("9_full", "consume", lambda ctx: b"Server full\x00")
    add("9_conn_ip", "consume", lambda ctx: CONNSTR)
    add("9_redir_field", "consume",
        lambda ctx: b"reject\x00ConnectRedirectAddress:127.0.0.1:29016\x00")

    # ---- misc connectionless (reaction probes) ----
    add("l_ack", "ignore", lambda ctx: b"")
    add("l_ack_str", "ignore", lambda ctx: b"ACK\x00")
    add("i_sinfo", "ignore", lambda ctx: sinfo_blob())
    add("C_sinfo", "ignore", lambda ctx: sinfo_blob())
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


def hexd(b, maxb=96):
    s = binascii_hex(b[:maxb])
    if len(b) > maxb:
        s += "..."
    return s


def binascii_hex(b):
    return "".join("%02x" % c for c in b)


class Farm(object):
    def __init__(self, bind, port, logdir, interval, consume_gap, silent_rx_gap):
        self.bind = bind
        self.port = port
        self.logdir = logdir
        self.interval = interval
        self.consume_gap = consume_gap
        self.silent_rx_gap = silent_rx_gap
        self.ctx = {"chal": 0, "qc_val": 0}
        self.chal = Ctx()
        self.idx = 0
        self.last_addr = None
        self.stats = {"rx": 0, "qc": 0, "connect": 0, "other": 0, "push": 0,
                      "redir": 0}
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

    def handle_rx(self, sock, redir=False):
        data, addr = sock.recvfrom(65535)
        self.stats["rx"] += 1
        now = time.time()
        tag = "REDIR" if redir else "RX"
        self.log("%s %dB src=%s:%d hex=%s" % (tag, len(data), addr[0], addr[1],
                                              hexd(data)))
        if redir:
            self.stats["redir"] += 1
            self.dump("redir_rx", data)
            return
        payload = data[4:] if data[:4] == b"\xff\xff\xff\xff" else None
        if payload is None:
            self.stats["other"] += 1
            self.dump("nonoob", data)
            self.silent_until = now + self.silent_rx_gap
            return
        if payload.startswith(b"qconnect0x"):
            self.stats["qc"] += 1
            tail = payload[10:10 + 8]
            try:
                self.ctx["qc_val"] = int(tail, 16)
            except ValueError:
                self.ctx["qc_val"] = 0
            self.last_addr = addr
            self.log("  -> qconnect qc_val=0x%08X (retry, no reply: push-mode)"
                     % self.ctx["qc_val"])
            return
        if payload.startswith(b"getchallenge"):
            self.last_addr = addr
            self.log("  -> classic getchallenge (retry, no reply)")
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
        self.stats["other"] += 1
        self.dump("other_rx", data)
        self.silent_until = now + self.silent_rx_gap

    def push_next(self, sock):
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
            try:
                sock.sendto(data, self.last_addr)
                self.stats["push"] += 1
                self.log("PUSH idx=%d name=%s cls=%s %dB dst=%s:%d chal=0x%08X "
                         "qc=0x%08X hex=%s"
                         % (self.idx, name, cls, len(data), self.last_addr[0],
                            self.last_addr[1], self.ctx["chal"],
                            self.ctx["qc_val"], hexd(data)))
            except OSError as e:
                self.log("PUSH idx=%d name=%s SEND-ERROR %s" % (self.idx, name, e))
        gap = self.interval if cls in ("ignore", "silent") else self.consume_gap
        self.next_push = max(now + gap, self.silent_until)

    def run(self):
        main = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        main.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        main.bind((self.bind, self.port))
        redir = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        redir.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        redir.bind((self.bind, self.port + 1))
        self.log("FARM UP bind=%s:%d (redirect-catch :%d) entries=%d "
                 "interval=%.1fs consume_gap=%.1fs"
                 % (self.bind, self.port, self.port + 1, len(MATRIX),
                    self.interval, self.consume_gap))
        for i, (name, cls, _) in enumerate(MATRIX):
            self.log("  matrix[%02d] %-14s %s" % (i, name, cls))
        while True:
            now = time.time()
            timeout = 0.5
            if self.last_addr is not None:
                timeout = max(0.05, min(timeout, self.next_push - now))
            r, _, _ = select_select([main, redir], [], [], timeout)
            for s in r:
                self.handle_rx(s, redir=(s is redir))
            now = time.time()
            if (self.last_addr is not None and now >= self.next_push
                    and now >= self.silent_until):
                self.push_next(main)
            if time.time() >= self.hb:
                self.log("HEARTBEAT rx=%(rx)d qc=%(qc)d connect=%(connect)d "
                         "other=%(other)d push=%(push)d redir=%(redir)d "
                         "matrix_idx=%d last=%s"
                         % dict(self.stats, matrix_idx=self.idx,
                                last=self.last_addr))
                self.hb = time.time() + 30.0


def select_select(r, w, x, t):
    import select
    return select.select(r, w, x, t)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=29015)
    ap.add_argument("--log", default="/tmp/c2b-farm")
    ap.add_argument("--push-interval", type=float, default=2.0)
    ap.add_argument("--consume-gap", type=float, default=10.0)
    ap.add_argument("--silent-rx-gap", type=float, default=12.0,
                    help="push pause after any non-qconnect RX")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for i, (name, cls, _) in enumerate(MATRIX):
            print("%02d %-14s %s" % (i, name, cls))
        return 0
    os.makedirs(args.log, exist_ok=True)
    Farm(args.bind, args.port, args.log, args.push_interval, args.consume_gap,
         args.silent_rx_gap).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
