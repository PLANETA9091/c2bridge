#!/usr/bin/env python3
"""Open a shell session on hop-1 (relay) itself and run a command."""
import os
import sys
import paramiko

KEY_PATH = os.environ.get("C2B_KEY", "/home/z/.ssh/session_key")
RELAY = ("141.147.25.20", 22)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "uname -a; nproc; free -h | head -2; df -h / | tail -1"
    pkey = paramiko.Ed25519Key.from_private_key_file(KEY_PATH)
    t1 = paramiko.Transport(RELAY)
    t1.connect(username="relay", pkey=pkey)
    try:
        s = t1.open_session()
        s.settimeout(30)
        s.exec_command(cmd)
        out = b""
        while not s.exit_status_ready():
            if s.recv_ready():
                out += s.recv(65536)
        while s.recv_ready():
            out += s.recv(65536)
        code = s.recv_exit_status()
        print(out.decode(errors="replace"))
        sys.exit(code)
    finally:
        t1.close()


if __name__ == "__main__":
    main()
