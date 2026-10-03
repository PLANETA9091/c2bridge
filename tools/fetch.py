#!/usr/bin/env python3
"""Fetch files from the Desktop via two-hop SFTP. Usage: fetch.py <remote> <local> [...]
(Remote paths must be readable by user 'agent'.)"""
import sys
import paramiko

KEY_PATH = "/home/z/.ssh/session_key"
RELAY = ("141.147.25.20", 22)
TARGET = ("127.0.0.1", 2201)


def main():
    pairs = list(zip(sys.argv[1::2], sys.argv[2::2]))
    pkey = paramiko.Ed25519Key.from_private_key_file(KEY_PATH)
    t1 = paramiko.Transport(RELAY)
    t1.connect(username="relay", pkey=pkey)
    chan = t1.open_channel("direct-tcpip", TARGET, ("", 0))
    t2 = paramiko.Transport(chan)
    t2.connect(username="agent", pkey=pkey)
    try:
        sftp = paramiko.SFTPClient.from_transport(t2)
        for remote, local in pairs:
            sftp.get(remote, local)
            st = sftp.stat(remote)
            print(f"fetched {remote} -> {local} ({st.st_size} bytes)")
        sftp.close()
    finally:
        t2.close()
        t1.close()


if __name__ == "__main__":
    main()
