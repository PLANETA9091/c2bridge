#!/usr/bin/env python3
"""test_vpk_pipeline.py — end-to-end unit test of the vpk-pruning pipeline
WITHOUT the game: builds a synthetic v1 VPK set (dir + 2 chunks), a fake
strace log with lseek/read patterns, then runs vpk_parse -> strace_readmap ->
lite_extract and verifies the pruning decisions.

Run:  python3 test_vpk_pipeline.py
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = "/tmp/c2b-vpk-test"
GAME = os.path.join(TMP, "game")


def write_vpk(dirpath, entries):
    """entries: (ext, root, name, crc, preload_bytes, archive, offset, length)"""
    groups = {}
    order = []
    for e in entries:
        ext = e[0]
        if ext not in groups:
            groups[ext] = {}
            order.append(ext)
        groups[ext].setdefault(e[2].rsplit("/", 1)[0] if "/" in e[2] else "", [])
    # simpler: linear tree build grouped by ext, root, then files
    tree = b""
    seen = set()
    for e in entries:
        ext = e[0]
        if ext in seen:
            continue
        seen.add(ext)
        tree += ext.encode() + b"\x00"
        ext_entries = [x for x in entries if x[0] == ext]
        roots_seen = set()
        for x in ext_entries:
            root = x[1]
            if root in roots_seen:
                continue
            roots_seen.add(root)
            tree += root.encode() + b"\x00"
            for y in ext_entries:
                if y[1] != root:
                    continue
                _, _, name, crc, preload, archive, offset, length = y
                tree += name.encode() + b"\x00"
                tree += struct.pack("<IHHIIH", crc, len(preload), archive,
                                    offset, length, 0xFFFF)
                tree += preload
            tree += b"\x00"
        tree += b"\x00"
    tree += b"\x00"
    with open(dirpath, "wb") as f:
        f.write(struct.pack("<III", 0x55AA55AA, 1, len(tree)))
        f.write(tree)


def main():
    shutil.rmtree(TMP, ignore_errors=True)
    os.makedirs(GAME)

    rng = zlib.crc32(b"seed")  # deterministic-ish filler
    fill = bytes((i * 31 + 17) % 256 for i in range(7000))
    fill2 = bytes((i * 7 + 3) % 256 for i in range(30600))

    f1 = fill[0:1000]
    f2 = fill[1000:6000]
    f3 = fill[6000:7000]
    f4 = fill2[0:30000]
    f6 = fill2[30000:30600]
    f5 = b"SOUND-CONTENT-24BYTE!"  # stored whole in dir preload

    with open(os.path.join(GAME, "pak01_000.vpk"), "wb") as f:
        f.write(fill)
    with open(os.path.join(GAME, "pak01_001.vpk"), "wb") as f:
        f.write(fill2)

    entries = [
        ("vtf", "materials", "test/f1", zlib.crc32(f1) & 0xFFFFFFFF, b"", 0, 0, 1000),
        ("vtf", "materials", "test/f2", zlib.crc32(f2) & 0xFFFFFFFF, b"", 0, 1000, 5000),
        ("vtf", "materials", "test/f3", zlib.crc32(f3) & 0xFFFFFFFF, b"", 0, 6000, 1000),
        ("mdl", "models", "test/f4", zlib.crc32(f4) & 0xFFFFFFFF, b"", 1, 0, 30000),
        ("mdl", "models", "test/f6", zlib.crc32(f6) & 0xFFFFFFFF, b"", 1, 30000, 600),
        ("wav", "sound", "test/f5", zlib.crc32(f5) & 0xFFFFFFFF, f5, 0x7FFF, 0, 0),
    ]
    write_vpk(os.path.join(GAME, "pak01_dir.vpk"), entries)

    # fake strace log (strace -yy format)
    P0 = GAME + "/pak01_000.vpk"
    P1 = GAME + "/pak01_001.vpk"
    lines = [
        f"100 openat(AT_FDCWD{GAME}>, \"{P0}\", O_RDONLY|O_CLOEXEC) = 3<{P0}>",
        f"100 lseek(3<{P0}>, 0, SEEK_SET) = 0",
        f"100 read(3<{P0}>, \"AAAA\", 1000) = 1000",          # f1 full
        f"100 lseek(3<{P0}>, 2000, SEEK_SET) = 2000",
        f"100 read(3<{P0}>, \"AAAA\", 1000) = 1000",          # f2 partial [2000,3000)
        f"100 close(3<{P0}>) = 0",
        f"101 openat(AT_FDCWD{GAME}>, \"{P1}\", O_RDONLY|O_CLOEXEC) = 4<{P1}>",
        f"101 _llseek(4<{P1}>, 0, 10000, 0x7f00, SEEK_SET) = 0",
        f"101 readv(4<{P1}>, [{{iov_base=0x1, iov_len=8192}}, {{iov_base=0x2, iov_len=1808}}], 2) = 10000",
        f"101 lseek(4<{P1}>, 30000, SEEK_SET) = 30000",
        f"101 pread64(4<{P1}>, \"AAAA\", 150, 30000) = 150",  # f6 head
        f"101 close(4<{P1}>) = 0",
        # a non-vpk read (goes into the loose copy set via readmap? no — manifest)
        f"102 openat(AT_FDCWD{GAME}>, \"{GAME}/bin/x.so\", O_RDONLY|O_CLOEXEC) = 5<{GAME}/bin/x.so>",
        f"102 read(5<{GAME}/bin/x.so>, \"ELF\", 4096) = 4096",
        f"102 close(5<{GAME}/bin/x.so>) = 0",
        # noise: ENOENT + unfinished
        f"103 openat(AT_FDCWD{GAME}>, \"/nonexistent\", O_RDONLY) = -1 ENOENT (No such file)",
        f"104 read(9</gone>, \"AAAA\", 10) = 10 <unfinished ...>",
    ]
    log = os.path.join(TMP, "strace.a1.log")
    with open(log, "w") as f:
        f.write("\n".join(lines) + "\n")

    os.makedirs(os.path.join(GAME, "bin"), exist_ok=True)
    with open(os.path.join(GAME, "bin", "x.so"), "wb") as f:
        f.write(b"\x7fELF-fake-so-content" * 100)

    man = os.path.join(TMP, "manifest.txt")
    with open(man, "w") as f:
        f.write("bin/x.so\n")
        f.write("csgo/pak01_000.vpk\n")  # must be IGNORED (.vpk skip)
        f.write("missing/file.cfg\n")

    # ---- run the pipeline ----
    idx_json = os.path.join(TMP, "index.json")
    r = subprocess.run([sys.executable, os.path.join(HERE, "vpk_parse.py"), "dump",
                        os.path.join(GAME, "pak01_dir.vpk"), idx_json],
                       capture_output=True, text=True)
    print(r.stdout, r.stderr)
    assert r.returncode == 0, "vpk_parse dump failed"

    rmap = os.path.join(TMP, "readmap.json")
    r = subprocess.run([sys.executable, os.path.join(HERE, "strace_readmap.py"),
                        "--out", rmap, log], capture_output=True, text=True)
    print(r.stdout, r.stderr)
    assert r.returncode == 0, "readmap failed"

    stage = os.path.join(TMP, "stage")
    r = subprocess.run([sys.executable, os.path.join(HERE, "lite_extract.py"),
                        "--index", idx_json, "--readmap", rmap,
                        "--manifest", man, "--game-dir", GAME, "--out", stage],
                       capture_output=True, text=True)
    print(r.stdout, r.stderr)
    assert r.returncode == 0, "lite_extract failed"

    # ---- verify ----
    ok = True

    def expect(path, cond, note):
        nonlocal ok
        print(("  OK  " if cond else "  FAIL") + f" {note}")
        if not cond:
            ok = False

    idx = json.load(open(idx_json))
    expect("index", idx["file_count"] == 6, f"index has 6 files (got {idx['file_count']})")

    def rd(rel):
        p = os.path.join(stage, rel)
        return open(p, "rb").read() if os.path.exists(p) else None

    expect("f1", rd("csgo/materials/test/f1.vtf") == f1, "f1 extracted exact")
    expect("f2", rd("csgo/materials/test/f2.vtf") == f2, "f2 extracted exact (partial read)")
    expect("f3-absent", rd("csgo/materials/test/f3.vtf") is None, "f3 pruned (never read)")
    expect("f4", rd("csgo/models/test/f4.mdl") == f4, "f4 extracted exact (readv window)")
    expect("f6", rd("csgo/models/test/f6.mdl") == f6, "f6 extracted exact (pread)")
    expect("f5-in-dir", rd("csgo/pak01_dir.vpk") is not None, "dir vpk ships whole")
    expect("dir-no-f5-copy", rd("csgo/sound/test/f5.wav") is None,
           "f5 not extracted (lives in dir vpk)")
    expect("so", rd("bin/x.so") is not None, "non-vpk .so copied")
    expect("no-chunks", rd("csgo/pak01_000.vpk") is None and rd("csgo/pak01_001.vpk") is None,
           "chunk archives NOT shipped")
    expect("no-bad-copy", rd("missing/file.cfg") is None, "missing manifest file ignored")

    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
