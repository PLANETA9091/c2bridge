#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""a2s_relay.py — 41e-l: прозрачный UDP-релей для A2S-трансформа НА СЕТЕВОМ
уровне.

ПОЧЕМУ (run 85/86): A2S_INFO в connect-флоу делает НЕ движок и НЕ через
libc-хуки клиентского процесса (в хуках моста и LD_PRELOAD-шима steam-клиента
НОЛЬ 'T' — Valve-код ходит мимо interposition). Единственная точка, где
обязателен весь UDP на цель — ЯДРО: iptables DNAT направляет весь
пользовательский UDP на цель сюда; релей пересылает его на реальный сервер
и обратно, ТРАНСФОРМИРУЯ 'I'-ответы (run 70/71 lessons фермы: no-EDF +
appid=730 + версия бандла, иначе тихий abort INGAME->MAINMENU без 'j').

КАК:
  * iptables (ставит харнесс, root):
      iptables -t nat -I OUTPUT 1 -p udp -d TIP --dport TPORT \
        -m owner ! --uid-owner 0 -j DNAT --to-destination LIP:RPORT
    owner-match исключает САМ релей (root) из DNAT — без петли.
  * приём: обычный UDP-сокет на 0.0.0.0:RPORT; addr отправителя = клиент.
  * upstream: обычный сокет на реальный TIP:TPORT (uid 0 -> мимо DNAT).
  * ответ клиенту: сокет с IP_TRANSPARENT, ПРИВЯЗАННЫЙ к TIP:TPORT —
    пакеты уходят с ИСХОДНЫМ адресом источника сервера (валидация
    источника у движка/клиента проходит). Нужен root.
  * rp_filter: харнесс ставит lo/all в 0 (строгий rp_filter на lo дропнул бы
    пакеты с "чужим" src, входящие через lo).

stdlib only. Запуск: sudo python3 a2s_relay.py --target IP:PORT \
  --listen 0.0.0.0:RPORT --version 1.38.0.4 --log /path/log
"""

import argparse
import select
import socket
import struct
import sys
import time

SOL_IP = 0
IP_TRANSPARENT = 19

LOGF = None


def log(msg):
    line = "[relay] %s\n" % msg
    sys.stdout.write(line)
    sys.stdout.flush()
    if LOGF:
        try:
            LOGF.write(line)
            LOGF.flush()
        except (OSError, ValueError):
            pass


def le16(v):
    return struct.pack("<H", v & 0xFFFF)


def transform_i(d, version):
    """'I'-ответ: срезать EDF, appid->730, версию->version (формат 1:1 с
    c2bridge.c c2b_a2s_transform_i / fake_s1_server.py). None = не трогать."""
    n = len(d)
    if n < 40 or n > 1400:
        return None
    if d[:4] != b"\xff\xff\xff\xff" or d[4:5] != b"I":
        return None
    p = d[5:]
    i = 1
    for _ in range(4):
        j = p.find(b"\x00", i)
        if j < 0 or (j + 1 - i) > 256:
            return None
        i = j + 1
    if i + 2 + 7 > len(p):
        return None
    apid = i
    i += 2 + 7
    j = p.find(b"\x00", i)
    if j < 0 or (j - i) > 32:
        return None
    out = d[:4] + b"I" + p[0:apid] + le16(730) + p[apid + 2:apid + 2 + 7] \
        + version.encode() + b"\x00"
    return out


class ClientUp(object):
    """Пара (upstream-сокет, время последней активности)."""
    __slots__ = ("sock", "ts")

    def __init__(self, target):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ts = time.time()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="real server ip:port")
    ap.add_argument("--listen", required=True, help="0.0.0.0:RPORT")
    ap.add_argument("--version", default="1.38.0.4")
    ap.add_argument("--idle", type=int, default=300,
                    help="upstream idle timeout, s")
    ap.add_argument("--stats", type=int, default=30,
                    help="stats log interval, s")
    ap.add_argument("--log", default="", help="append log to file")
    a = ap.parse_args()

    global LOGF
    if a.log:
        LOGF = open(a.log, "a", buffering=1)

    tip, tport = a.target.rsplit(":", 1)
    tport = int(tport)
    lip, lport = a.listen.rsplit(":", 1)
    lport = int(lport)

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind((lip, lport))
    rx.setblocking(False)

    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
    tx.bind((tip, tport))            # спуф источника: src = реальный сервер
    tx.setblocking(False)

    log("up: target=%s:%d listen=%s:%d version=%s (uid0: DNAT-exempt)"
        % (tip, tport, lip, lport, a.version))

    ups = {}                          # addr -> ClientUp
    stats = {"q": 0, "r": 0, "i": 0, "bytes": 0}
    t_stat = time.time() + a.stats

    while True:
        rl = [rx] + [c.sock for c in ups.values()]
        r, _, _ = select.select(rl, [], [], 5)
        now = time.time()
        if rx in r:
            try:
                while True:
                    data, addr = rx.recvfrom(65535)
                    cu = ups.get(addr)
                    if cu is None:
                        cu = ups[addr] = ClientUp(tip)
                    cu.ts = now
                    cu.sock.sendto(data, (tip, tport))
                    stats["q"] += 1
                    stats["bytes"] += len(data)
                    if data[:4] == b"\xff\xff\xff\xff" and data[4:5] == b"T":
                        log("T-query from %s:%d (%dB) -> server"
                            % (addr[0], addr[1], len(data)))
            except BlockingIOError:
                pass
        for caddr in list(ups):
            cu = ups[caddr]
            if cu.sock in r:
                try:
                    while True:
                        data, _ = cu.sock.recvfrom(65535)
                        if data[:4] == b"\xff\xff\xff\xff" and data[4:5] == b"I":
                            nd = transform_i(data, a.version)
                            if nd:
                                log("I-reply %dB -> transformed %dB (no-EDF "
                                    "appid=730 ver=%s) -> client %s:%d"
                                    % (len(data), len(nd), a.version,
                                       caddr[0], caddr[1]))
                                stats["i"] += 1
                                data = nd
                        tx.sendto(data, caddr)
                        stats["r"] += 1
                except BlockingIOError:
                    pass
            if now - cu.ts > a.idle:
                cu.close()
                del ups[caddr]
        if now >= t_stat:
            log("stats: q=%(q)d r=%(r)d i_transformed=%(i)d bytes=%(bytes)d "
                "clients=%d" % dict(stats, clients=len(ups)))
            t_stat = now + a.stats


if __name__ == "__main__":
    main()
