#!/usr/bin/env python3
"""test_vpk_embedded.py — synthetic test for vpk_rebuild.py 'embedded' mode."""
import json
import os
import shutil
import struct
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from vpk_parse import VpkIndex, MAGIC, DIR_ARCHIVE, collect_preloads  # noqa: E402

WORK = "/tmp/test-vpk-embedded"
PRE1 = b"PRELOAD-one-\x01\x02" * 7
PRE2 = b"small"
BODY = b"CHUNK-BODY-bytes!"  # for the chunk entry (must NOT appear in output)
CRC = lambda b: zlib.crc32(b) & 0xFFFFFFFF

EMBEDDED = [  # (vpk_path, preload, length)
    ("materials/console/bg01_widescreen.vtf", PRE1, 0),
    (" /banmdls.res", PRE2, 0),
]
CHUNKED = [("shaders/fxc/some_vs30.vcs", CRC(BODY), 5, 0, len(BODY))]


def make_fixture(out_path):
    """Synthetic ORIGINAL dir vpk: v2, 2 embedded (preload-only) + 1 chunk entry."""
    files = []
    for p, pb, ln in EMBEDDED:
        files.append((p, CRC(pb), len(pb), DIR_ARCHIVE, 0, 0, pb))
    files.append((CHUNKED[0][0], CHUNKED[0][1], 0, CHUNKED[0][2],
                  CHUNKED[0][3], CHUNKED[0][4], b""))
    files.sort(key=lambda f: f[0])
    tree = bytearray()
    by_ext = {}
    for p, crc, plen, arc, off, ln, pb in files:
        ext, root, path = _key(p)
        by_ext.setdefault(ext, {}).setdefault(root, []).append((path, crc, plen, arc, off, ln, pb))
    for ext in sorted(by_ext):
        tree += ext.encode() + b"\0"
        for root in sorted(by_ext[ext]):
            tree += root.encode() + b"\0"
            for path, crc, plen, arc, off, ln, pb in sorted(by_ext[ext][root]):
                tree += path.encode() + b"\0"
                tree += struct.pack("<IHHIIH", crc, plen, arc, off, ln, 0xFFFF)
                tree += pb
            tree += b"\0"
        tree += b"\0"
    tree += b"\0"
    with open(out_path, "wb") as f:
        f.write(struct.pack("<IIIIIII", MAGIC, 2, len(tree), 0, 0, 0, 0))
        f.write(tree)


def _key(p):
    if "/" in p:
        root, rest = p.split("/", 1)
    else:
        root, rest = " ", p
    base = rest.rsplit("/", 1)[-1]
    dirpart = rest[: len(rest) - len(base) - 1] if "/" in rest else ""
    name, ext = (base.rsplit(".", 1) + [" "])[:2] if "." in base else (base, " ")
    return ext or " ", root, (f"{dirpart}/{name}" if dirpart else name)


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    fix = os.path.join(WORK, "orig_pak01_dir.vpk")
    make_fixture(fix)

    index = {"dir_file": fix, "chunks": {}, "files": (
        [{"path": p, "crc": CRC(pb), "archive": DIR_ARCHIVE, "offset": 0,
          "length": 0, "preload_len": len(pb)} for p, pb, _ in EMBEDDED]
        + [{"path": CHUNKED[0][0], "crc": CHUNKED[0][1],
            "archive": CHUNKED[0][2], "offset": CHUNKED[0][3],
            "length": CHUNKED[0][4], "preload_len": 0}])}
    ipath = os.path.join(WORK, "index.json")
    json.dump(index, open(ipath, "w"))

    out = os.path.join(WORK, "rebuilt_dir.vpk")
    r = subprocess.run([sys.executable, os.path.join(HERE, "vpk_rebuild.py"),
                        "embedded", "--index", ipath, "--out", out],
                       capture_output=True, text=True)
    print(r.stdout, r.stderr)
    assert r.returncode == 0, "embedded build failed"

    idx = VpkIndex(out)
    paths = {e.path for e in idx.entries}
    assert paths == {p for p, _, _ in EMBEDDED}, f"tree mismatch: {paths}"
    for e in idx.entries:
        assert e.archive == DIR_ARCHIVE and e.length == 0, e.path
    got = collect_preloads(out, {p for p, _, _ in EMBEDDED})
    assert got == {p: pb for p, pb, _ in EMBEDDED}, "preload bytes mismatch"
    assert BODY not in open(out, "rb").read(), "chunk body leaked into output"
    print("ALL PASS: embedded-only rebuild "
          f"({len(paths)} entries, {os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
