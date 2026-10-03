#!/usr/bin/env python3
"""Fetch files from the relay VPS via single-hop SFTP. Usage: relay_get.py <remote> <local> [...]"""
import os
import sys
import paramiko

KEY_PATH = os.environ.get("C2B_KEY", "/home/z/.ssh/session_key")
RELAY = ("141.147.25.20", 22)


def main():
    pairs = list(zip(sys.argv[1::2], sys.argv[2::2]))
    pkey = paramiko.Ed25519Key.from_private_key_file(KEY_PATH)
    t = paramiko.Transport(RELAY)
    t.connect(username="relay", pkey=pkey)
    try:
        sftp = paramiko.SFTPClient.from_transport(t)
        for remote, local in pairs:
            sftp.get(remote, local)
            st = sftp.stat(remote)
            print(f"got {remote} -> {local} ({st.st_size} bytes)")
        sftp.close()
    finally:
        t.close()


if __name__ == "__main__":
    main()
