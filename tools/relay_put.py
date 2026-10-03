#!/usr/bin/env python3
"""Put files onto the relay VPS via single-hop SFTP. Usage: relay_put.py <local> <remote> [...]"""
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
        for local, remote in pairs:
            sftp.put(local, remote)
            st = sftp.stat(remote)
            print(f"put {local} -> {remote} ({st.st_size} bytes)")
        sftp.close()
    finally:
        t.close()


if __name__ == "__main__":
    main()
