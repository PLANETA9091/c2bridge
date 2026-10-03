#!/usr/bin/env python3
"""lite_extract.py — build the minimal loose staging tree (vpk pruning).

Inputs:
  --index index.json        (vpk_parse.py dump of pak01_dir.vpk)
  --readmap readmap.json    (strace_readmap.py output)
  --manifest manifest.txt   (lite-manifest.py output — non-vpk files: binaries,
                            cfgs, *.so — mmap'd files are not in the readmap!)
  --game-dir GAME_DIR       full install
  --out STAGE               staging tree (later packed by pack-bundle.sh)

What lands in staging:
  staging/csgo/pak01_dir.vpk            whole (needed to mount + preload content)
  staging/csgo/<inner files>            ONLY entries whose bytes intersect the
                                        readmap; extracted from chunks, CRC32
                                        verified against the vpk index
  staging/<non-vpk files>               copied per --manifest (skips *.vpk)

Chunk archives themselves are NOT shipped: loose files shadow the vpk lookup.
"""
import argparse
import json
import os
import re
import shutil
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vpk_parse import collect_preloads  # noqa: E402

DIR_ARCHIVE = 0x7FFF
FORCE_NON_VPK = tuple(  # MUST be a tuple: a generator would exhaust on first use!
    re.compile(p) for p in (
        r"^csgo_linux64", r"\.so(\.\d+)*$", r"^bin/", r"^csgo/bin/",
        r"^linux64/", r"\.vdf$", r"gameinfo\.gi", r"^csgo/cfg/",
        r"\.(txt|lst|vcs)$",
    )
)


def human(n):
    return f"{n / 1048576:.1f} MiB" if n >= 1048576 else f"{n / 1024:.0f} KiB"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", required=True)
    ap.add_argument("--readmap", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--game-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mount", default="csgo",
                    help="mount point of this dir-vpk inside the game dir "
                         "(csgo for pak01, platform for platform_pak01)")
    ap.add_argument("--min-overlap", type=int, default=1,
                    help="min intersecting bytes to include an inner file")
    ap.add_argument("--allow-crc-mismatch", action="store_true")
    a = ap.parse_args()

    idx = json.load(open(a.index))
    readmap = json.load(open(a.readmap))["paths"]
    gd = os.path.normpath(a.game_dir)
    stage = a.out
    os.makedirs(stage, exist_ok=True)

    # ---- 1. inner-file selection via range intersection ----
    by_chunk = {}
    for e in idx["files"]:
        if e["archive"] == DIR_ARCHIVE:
            continue
        by_chunk.setdefault(idx["chunks"] and e["archive"], []).append(e)

    chunk_ranges = {}
    for path, rs in readmap.items():
        base = os.path.basename(path)
        if base.endswith(".vpk") and "_dir" not in base:
            chunk_ranges[base] = rs

    include = []          # entries to extract
    included_bytes = 0
    excluded_bytes = 0
    embedded = 0
    for e in idx["files"]:
        if e["archive"] == DIR_ARCHIVE:
            # File is embedded in the dir vpk itself (v2 data section / v1
            # inline). For CS:GO legacy these entries have length==0, i.e. the
            # WHOLE file is its preload head. Ship them wholesale: total cost
            # is bounded by the dir-file size (~16 MiB for pak01), and the
            # engine treats preload+length as the complete content.
            include.append(e)
            included_bytes += e["preload_len"] + e["length"]
            embedded += 1
            continue
        cname = os.path.basename(idx["dir_file"]).rsplit("_dir.", 1)[0] + f"_{e['archive']:03d}.vpk"
        rs = chunk_ranges.get(cname)
        if not rs:
            excluded_bytes += e["length"]
            continue
        s0, e0 = e["offset"], e["offset"] + e["length"]
        hit = 0
        for s, r_end in rs:
            lo, hi = max(s, s0), min(r_end, e0)
            if hi > lo:
                hit += hi - lo
                if hit >= a.min_overlap:
                    break
        if hit >= a.min_overlap:
            include.append(e)
            included_bytes += e["length"]
        else:
            excluded_bytes += e["length"]

    print(f"[vpk] inner files: include {len(include)} ({human(included_bytes)}), "
          f"skip {len(idx['files']) - len(include)} ({human(excluded_bytes)}), "
          f"embedded-in-dir {embedded}")

    # preload heads for the included entries (single tree pass)
    preloads = collect_preloads(idx["dir_file"], {e["path"] for e in include})
    print(f"[vpk] preload heads captured: {len(preloads)}")

    # ---- 2. extract included entries with CRC verification ----
    crc_fail = 0
    chunk_dir = os.path.dirname(os.path.abspath(idx["dir_file"]))  # chunks sit next to the dir vpk
    chunk_paths = {}
    # data-section start for v2 dir-embedded bodies
    with open(idx["dir_file"], "rb") as f:
        _hdr = f.read(12)
    _magic, _ver, _tsize = struct.unpack_from("<III", _hdr, 0)
    dir_data_start = 12 + (16 if _ver == 2 else 0) + _tsize
    for e in include:
        if e["archive"] == DIR_ARCHIVE:
            # content lives inside the dir vpk: preload head (+ optional body)
            data = preloads.get(e["path"], b"")
            if e["length"] > 0:
                if _ver != 2:
                    print(f"::error::v1 dir-embedded body unsupported: {e['path']}")
                    return 1
                with open(idx["dir_file"], "rb") as f:
                    f.seek(dir_data_start + e["offset"])
                    data += f.read(e["length"])
        else:
            cname = os.path.basename(idx["dir_file"]).rsplit("_dir.", 1)[0] + f"_{e['archive']:03d}.vpk"
            src = chunk_paths.get(cname)
            if src is None:
                src = os.path.join(chunk_dir, cname)
                if not os.path.exists(src):
                    print(f"::error::chunk missing: {src}"); return 1
                chunk_paths[cname] = src
            with open(src, "rb") as f:
                f.seek(e["offset"])
                body = f.read(e["length"])
            # CS:GO legacy: file content = preload(head) + archive body(length)
            data = preloads.get(e["path"], b"") + body
        if len(data) and (zlib.crc32(data) & 0xFFFFFFFF) != e["crc"]:
            crc_fail += 1
            if not a.allow_crc_mismatch:
                print(f"::error::CRC mismatch {e['path']} — aborting "
                      f"(use --allow-crc-mismatch to override)")
                return 1
        dst = os.path.join(stage, a.mount, e["path"])
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(data)

    # ---- 3. dir vpk ships whole ----
    dst = os.path.join(stage, a.mount, os.path.basename(idx["dir_file"]))
    shutil.copy2(idx["dir_file"], dst)

    # ---- 4. non-vpk files from the manifest ----
    copied, copy_bytes = 0, 0
    for line in open(a.manifest, errors="replace"):
        rel = line.strip()
        if not rel or rel.startswith("#") or rel.endswith(".vpk"):
            continue
        rel = rel[len(gd):].lstrip("/") if rel.startswith(gd) else rel.lstrip("/")
        forced = any(rx.search(rel) for rx in FORCE_NON_VPK)
        try:
            size = os.path.getsize(os.path.join(gd, rel))
        except OSError:
            continue
        if not forced and size > 8 * 1024 * 1024:
            continue
        dst = os.path.join(stage, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            shutil.copy2(os.path.join(gd, rel), dst)
            copied += 1
            copy_bytes += size
        except OSError as ex:
            print(f"  warn: copy failed {rel}: {ex}")

    # ---- 4b. root-level executables: execve'd binaries never appear in openat ----
    import glob as _glob
    for srcp in _glob.glob(os.path.join(gd, "csgo_linux64*")):
        if os.path.isfile(srcp):
            dstp = os.path.join(stage, os.path.basename(srcp))
            shutil.copy2(srcp, dstp)
            os.chmod(dstp, 0o755)
            copied += 1
            copy_bytes += os.path.getsize(srcp)
            print(f"  root copy: {os.path.basename(srcp)}")

    # ---- 5. report ----
    total = sum(os.path.getsize(os.path.join(dp, f))
                for dp, _, fns in os.walk(stage) for f in fns)
    n_files = sum(len(fns) for _, _, fns in os.walk(stage))
    print(f"[stage] {n_files} files, {human(total)} at {stage}")
    print(f"        vpk-extracted: {len(include)} files / {human(included_bytes)}"
          + (f"  CRC FAILURES: {crc_fail}" if crc_fail else "  (all CRC ok)"))
    print(f"        non-vpk copied: {copied} files / {human(copy_bytes)}")
    return 0 if crc_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
