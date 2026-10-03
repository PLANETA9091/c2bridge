#!/usr/bin/env python3
"""Two-hop SSH helper: sandbox -> relay(141.147.25.20:22, user 'relay') -> direct-tcpip 127.0.0.1:2201 -> user 'agent'.
Private key stays inside the sandbox. Usage: python3 hop_ssh.py "<command>" [timeout_sec]
"""
import os
import sys
import paramiko

KEY_PATH = os.environ.get("C2B_KEY", "/home/z/.ssh/session_key")
RELAY = ("141.147.25.20", 22)
TARGET = ("127.0.0.1", 2201)


def connect():
    pkey = paramiko.Ed25519Key.from_private_key_file(KEY_PATH)
    t1 = paramiko.Transport(RELAY)
    t1.connect(username="relay", pkey=pkey)
    chan = t1.open_channel("direct-tcpip", TARGET, ("", 0))
    t2 = paramiko.Transport(chan)
    t2.connect(username="agent", pkey=pkey)
    return t1, t2


def run_cmd(t2, cmd, timeout=60):
    s = t2.open_session()
    s.settimeout(timeout)
    s.exec_command(cmd)
    out, err = b"", b""
    while not s.exit_status_ready():
        if s.recv_ready():
            out += s.recv(65536)
        if s.recv_stderr_ready():
            err += s.recv_stderr(65536)
    while s.recv_ready():
        out += s.recv(65536)
    while s.recv_stderr_ready():
        err += s.recv_stderr(65536)
    code = s.recv_exit_status()
    s.close()
    return code, out.decode(errors="replace"), err.decode(errors="replace")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "uname -a; whoami; hostname"
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    t1, t2 = connect()
    try:
        code, out, err = run_cmd(t2, cmd, timeout)
        if out:
            print(out, end="" if out.endswith("\n") else "\n")
        if err:
            print("[stderr] " + err.strip(), file=sys.stderr)
        sys.exit(code)
    finally:
        try:
            t2.close()
        finally:
            t1.close()


if __name__ == "__main__":
    main()
