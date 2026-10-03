#!/usr/bin/env python3
"""vpk_rebuild.py — rebuild pak01_dir.vpk so its tree contains ONLY the files
we ship, each embedded whole inside the dir file (archive=0x7FFF, v2 data
section). Rationale: Source 1 treats a missing chunk archive referenced by the
tree as fatal "pack file corruption". If a pruned file is absent from the TREE
entirely, the engine just gets a normal file-not-found and falls back.

Usage:
  vpk_rebuild.py build  --stage STAGE --index index.json --out OUT.vpk
                        [--dedupe]   # also delete embedded files from STAGE
  vpk_rebuild.py verify OUT.vpk

build embeds every STAGE file whose vpk path (staging path minus the "csgo/"
mount prefix) is a member of the original vpk index — i.e. it really is an
inner vpk file we decided to keep. Genuinely loose files (bin/, cfg,
pak01_dir.vpk itself, ...) stay untouched. Entries carry preload_len=0;
content lives in the v2 file-data section.
"""
import argparse
import json
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vpk_parse import VpkIndex, MAGIC, DIR_ARCHIVE, collect_preloads  # noqa: E402


def split_vpk_key(vpk_path):
    """'materials/models/x/y.multi.vtf' -> (ext, root, path).

    vpk_path is the INDEX path (no 'csgo/' prefix — the vpk mounts at csgo/).
    Tree keys: extension (no dot; ' ' for none) / root (' ' for mount root) /
    path-in-root. '. ' suffix artifacts from index path rendering are handled.
    """
    if "/" in vpk_path:
        root, rest = vpk_path.split("/", 1)
    else:
        root, rest = " ", vpk_path
    base = rest.rsplit("/", 1)[-1]
    dirpart = rest[: len(rest) - len(base) - 1] if "/" in rest else ""
    if "." in base:
        name, ext = base.rsplit(".", 1)
        ext = ext or " "
    else:
        name, ext = base, " "
    path = f"{dirpart}/{name}" if dirpart else name
    return ext, root, path


def human(n):
    return f"{n / 1048576:.1f} MiB" if n >= 1048576 else f"{n / 1024:.0f} KiB"


def cmd_build(a):
    idx = json.load(open(a.index))
    stage = os.path.normpath(a.stage)

    # ---- pass 1: collect embedded candidates (membership in original index) --
    # index paths carry NO mount prefix; staging mirrors the game dir layout
    members = set()
    for e in idx["files"]:
        p = e["path"]
        members.add(p[len(a.mount) + 1:] if p.startswith(a.mount + "/") else p)
    mprefix = a.mount + "/"
    cand = []  # (vpk_path, abspath, size)
    for cur, _dirs, files in os.walk(stage):
        for fn in files:
            ap = os.path.join(cur, fn)
            rel = os.path.relpath(ap, stage).replace(os.sep, "/")
            vpk_path = rel[len(mprefix):] if rel.startswith(mprefix) else rel
            if vpk_path in members:
                cand.append((vpk_path, ap, os.path.getsize(ap)))
    cand.sort()
    embedded_bytes = sum(c[2] for c in cand)
    print(f"embed {len(cand)} vpk-member files, {human(embedded_bytes)}")

    # ---- pass 2: crc32 + build tree ----
    tree = {}  # ext -> root -> path -> entry dict
    for vpk_path, ap, size in cand:
        ext, root, path = split_vpk_key(vpk_path)
        crc = 0
        with open(ap, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                crc = zlib.crc32(b, crc)
        tree.setdefault(ext, {}).setdefault(root, {})[path] = {
            "vpk": vpk_path, "size": size, "crc": crc & 0xFFFFFFFF}

    # ---- serialize tree (offsets assigned in write order of data section) ----
    rel_ap = {vpk: ap for vpk, ap, _size in cand}
    out = bytearray()
    write_order = []      # vpk paths in EXACTLY the order offsets are assigned
    data_off = 0
    n_entries = 0
    for ext in sorted(tree):
        roots = tree[ext]
        out += ext.encode() + b"\0"
        for root in sorted(roots):
            out += root.encode() + b"\0"
            for path in sorted(roots[root]):
                e = roots[root][path]
                out += path.encode() + b"\0"
                out += struct.pack("<IHHIIH", e["crc"], 0, DIR_ARCHIVE,
                                   data_off, e["size"], 0xFFFF)
                write_order.append(e["vpk"])
                data_off += e["size"]
                n_entries += 1
            out += b"\0"      # end of this root's file list
        out += b"\0"          # end of this ext's root list
    out += b"\0"              # end of ext list
    tree_size = len(out)

    # ---- write: v2 header, tree, data ----
    os.makedirs(os.path.dirname(os.path.abspath(a.out)) or ".", exist_ok=True)
    with open(a.out, "wb") as f:
        f.write(struct.pack("<IIIIIII", MAGIC, 2, tree_size,
                            data_off, 0, 0, 0))
        f.write(out)
        for vpk in write_order:
            with open(rel_ap[vpk], "rb") as src:
                while True:
                    b = src.read(1 << 22)
                    if not b:
                        break
                    f.write(b)
    print(f"wrote {a.out}: {n_entries} entries, tree {human(tree_size)}, "
          f"data {human(data_off)}, total {human(28 + tree_size + data_off)}")

    if a.dedupe:
        removed = 0
        for _vpk, ap, _size in cand:
            try:
                os.remove(ap)
                removed += 1
            except OSError:
                pass
        print(f"dedupe: removed {removed} embedded files from stage")
    return 0


def cmd_embedded(a):
    """Rebuild the dir vpk containing ONLY the originally-embedded entries
    (archive==0x7FFF). CS:GO legacy stores these as length==0 entries whose
    whole content is the preload blob inside the tree. Chunk-sourced files are
    NOT in the tree at all — they ship as loose files instead. The engine
    never touches a chunk -> no 'pack file corruption', and it never needs to
    read a body from the data section (CS:GO has no such entries natively).
    """
    idx = json.load(open(a.index))
    dir_file = idx["dir_file"]
    emb = [e for e in idx["files"] if e["archive"] == DIR_ARCHIVE]
    preloads = collect_preloads(dir_file, {e["path"] for e in emb})
    print(f"embedded entries: {len(emb)}, preload blobs: {len(preloads)}")

    tree = {}
    total_preload = 0
    for e in emb:
        pb = preloads.get(e["path"], b"")
        if len(pb) != e["preload_len"]:
            print(f"::error::preload size mismatch {e['path']}")
            return 1
        ext, root, path = split_vpk_key(e["path"])
        tree.setdefault(ext, {}).setdefault(root, {})[path] = {
            "crc": e["crc"], "preload": pb, "length": e["length"],
            "offset": e["offset"]}
        total_preload += len(pb)

    data_off = 0
    out = bytearray()
    bodies = []  # (src_offset_in_dir, length) for length>0 embedded entries
    n = 0
    for ext in sorted(tree):
        roots = tree[ext]
        out += ext.encode() + b"\0"
        for root in sorted(roots):
            out += root.encode() + b"\0"
            for path in sorted(roots[root]):
                e = roots[root][path]
                out += path.encode() + b"\0"
                rec_pos = len(out)
                out += struct.pack("<IHHIIH", e["crc"], len(e["preload"]),
                                   DIR_ARCHIVE, 0, 0, 0xFFFF)
                out += e["preload"]
                if e["length"] > 0:
                    bodies.append((e["offset"], e["length"]))
                    # entry points into OUR data section: fix offset/length
                    out[rec_pos:rec_pos + 18] = struct.pack(
                        "<IHHIIH", e["crc"], len(e["preload"]), DIR_ARCHIVE,
                        data_off, e["length"], 0xFFFF)
                    data_off += e["length"]
                n += 1
            out += b"\0"
        out += b"\0"
    out += b"\0"
    tree_size = len(out)

    with open(dir_file, "rb") as f:
        head = f.read(12)
    _, ver, tsize = struct.unpack_from("<III", head, 0)
    dir_data_start = 12 + (16 if ver == 2 else 0) + tsize

    with open(a.out, "wb") as f:
        f.write(struct.pack("<IIIIIII", MAGIC, 2, tree_size,
                            data_off, 0, 0, 0))
        f.write(out)
        for off, ln in bodies:
            with open(dir_file, "rb") as src:
                src.seek(dir_data_start + off)
                remaining = ln
                while remaining > 0:
                    b = src.read(min(1 << 22, remaining))
                    if not b:
                        break
                    f.write(b)
                    remaining -= len(b)
    print(f"wrote {a.out}: {n} embedded entries, "
          f"preload {human(total_preload)}, tree {human(tree_size)}, "
          f"data {human(data_off)}")
    return 0


def cmd_verify(a):
    with open(a.out, "rb") as f:
        buf = f.read()
    idx = VpkIndex(a.out)
    version, tree_size = struct.unpack_from("<II", buf, 4)
    data_start = 12 + (16 if version == 2 else 0) + tree_size
    bad = 0
    for e in idx.entries:
        off = data_start + e.offset
        data = buf[off:off + e.length]
        if (zlib.crc32(data) & 0xFFFFFFFF) != e.crc:
            bad += 1
            if bad <= 5:
                print(f"CRC FAIL {e.path}")
        if e.archive != DIR_ARCHIVE:
            print(f"NON-DIR ENTRY {e.path}")
            bad += 1
    print(f"verify {a.out}: {len(idx.entries)} entries, "
          f"{human(idx.total_length)} data, crc_errors={bad}")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--stage", required=True)
    b.add_argument("--index", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--mount", default="csgo",
                   help="mount point of this dir-vpk inside the game dir")
    b.add_argument("--dedupe", action="store_true")
    v = sub.add_parser("verify")
    v.add_argument("out")
    em = sub.add_parser("embedded")
    em.add_argument("--index", required=True)
    em.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.cmd == "build":
        return cmd_build(a)
    if a.cmd == "embedded":
        return cmd_embedded(a)
    return cmd_verify(a)


if __name__ == "__main__":
    sys.exit(main())
