#!/usr/bin/env python3
"""test_vpk_rebuild.py — synthetic roundtrip test for vpk_rebuild.py (no game needed)."""
import json
import os
import shutil
import struct
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "vpk_rebuild.py")
WORK = "/tmp/test-vpk-rebuild"
STAGE = os.path.join(WORK, "stage")

FILES = {  # relpath under STAGE (game-dir layout: csgo/ mounts the vpk)
    "csgo/materials/x/y.vtf": os.urandom(1000),
    "csgo/materials/z.multi.ext": b"multi-dot\x00content" * 10,
    "csgo/noext. ": b"no-extension-file",  # index convention: ext key is ' '
    "csgo/a.bin": os.urandom(1 << 20),
    "csgo/big.dat": os.urandom((1 << 20) + 777),  # >1 MiB
    "csgo/resource/ui.res": b"platform resource \x01\x02",
    # genuinely loose (must NOT be embedded):
    "bin/libfoo.so": b"\x7fELF-fake",
    "csgo/cfg/server.vdf": b"loose config",
    "csgo/pak01_dir.vpk": b"original-dir-index-must-stay-loose",
}
# index paths: NO 'csgo/' prefix; mount-root files start with ' /'
MEMBERS = ["materials/x/y.vtf", "materials/z.multi.ext", "noext. ",
           "a.bin", "big.dat", "resource/ui.res",
           "not-in-stage-but-in-index.vtf"]  # index member w/o stage file


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(STAGE)
    for rel, data in FILES.items():
        p = os.path.join(STAGE, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)

    index = {"files": [{"path": m} for m in MEMBERS], "chunks": {}}
    ipath = os.path.join(WORK, "index.json")
    json.dump(index, open(ipath, "w"))

    out = os.path.join(WORK, "pak01_dir.vpk")
    r = subprocess.run([sys.executable, TOOL, "build", "--stage", STAGE,
                        "--index", ipath, "--out", out],
                       capture_output=True, text=True)
    print(r.stdout, r.stderr)
    assert r.returncode == 0, "build failed"

    r = subprocess.run([sys.executable, TOOL, "verify", out],
                       capture_output=True, text=True)
    print(r.stdout, r.stderr)
    assert r.returncode == 0, "verify failed"

    sys.path.insert(0, HERE)
    from vpk_parse import VpkIndex, DIR_ARCHIVE
    idx = VpkIndex(out)
    paths = {e.path for e in idx.entries}
    # vpk_parse renders root/name.ext; mount-root files render as " /a.bin"
    expect = {"materials/x/y.vtf", "materials/z.multi.ext", " /noext. ",
              " /a.bin", " /big.dat", "resource/ui.res"}
    assert paths == expect, f"tree mismatch: {paths ^ expect}"

    buf = open(out, "rb").read()
    _, version, tree_size = struct.unpack_from("<III", buf, 0)
    assert version == 2
    data_start = 12 + 16 + tree_size
    for e in idx.entries:
        content = buf[data_start + e.offset: data_start + e.offset + e.length]
        assert e.archive == DIR_ARCHIVE, e.path
        assert (zlib.crc32(content) & 0xFFFFFFFF) == e.crc, e.path
        vpk_path = e.path[2:] if e.path.startswith(" /") else e.path
        assert content == FILES["csgo/" + vpk_path], f"content mismatch {e.path}"

    # dir vpk itself + loose files must remain on disk untouched
    assert open(os.path.join(STAGE, "csgo/pak01_dir.vpk"), "rb").read() \
        == b"original-dir-index-must-stay-loose"
    assert open(os.path.join(STAGE, "bin/libfoo.so"), "rb").read() == b"\x7fELF-fake"

    print("ALL PASS: roundtrip, crc, membership, loose preserved "
          f"({len(expect)} embedded, size {os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
