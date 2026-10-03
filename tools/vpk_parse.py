#!/usr/bin/env python3
"""vpk_parse.py — parse CS:GO legacy pak01_dir.vpk (Valve Pak v1/v2) index.

The dir-vpk contains the full tree of inner files:
    extension -> root dir -> name, each entry = (crc32, archive, offset, length).
Inner content lives in pak01_NNN.vpk chunk archives; entries with
archive==0x7fff are stored inside the dir file itself (v1: inline after the
entry; v2: in the file_data section — either way they are "free" once the
dir file ships whole).

Usage:
  vpk_parse.py list  pak01_dir.vpk
  vpk_parse.py dump  pak01_dir.vpk out.json
  vpk_parse.py extract pak01_dir.vpk <game-dir> <inner/path/file.ext> OUT
"""
import json
import struct
import sys
import zlib

MAGIC = 0x55AA1234  # bytes on disk: 34 12 AA 55 (little-endian read)
DIR_ARCHIVE = 0x7FFF


class VpkParseError(Exception):
    pass


class Entry:
    __slots__ = ("path", "crc", "archive", "offset", "length", "preload_len")

    def __init__(self, path, crc, archive, offset, length, preload_len):
        self.path = path
        self.crc = crc
        self.archive = archive
        self.offset = offset
        self.length = length
        self.preload_len = preload_len

    def to_json(self):
        return {
            "path": self.path, "crc": self.crc, "archive": self.archive,
            "offset": self.offset, "length": self.length,
            "preload_len": self.preload_len,
        }


class VpkIndex:
    def __init__(self, dir_path):
        self.dir_path = dir_path
        self.version = None
        self.entries = []           # list[Entry], sorted by path
        self.total_length = 0
        self._parse()

    @staticmethod
    def _read_cstring(buf, pos):
        end = buf.index(b"\x00", pos)
        return buf[pos:end].decode("utf-8", errors="replace"), end + 1

    def _parse(self):
        with open(self.dir_path, "rb") as f:
            buf = f.read()
        if len(buf) < 12:
            raise VpkParseError("file too small")
        magic, version, tree_size = struct.unpack_from("<III", buf, 0)
        if magic != MAGIC:
            raise VpkParseError(f"bad magic 0x{magic:08x}")
        if version not in (1, 2):
            raise VpkParseError(f"unsupported vpk version {version}")
        self.version = version
        pos = 12
        if version == 2:
            pos += 16  # file_data_size, archive_md5_size, other_md5_size, signature_size
        tree_end = pos + tree_size

        entries = []
        while pos < tree_end:
            ext, pos = self._read_cstring(buf, pos)
            if not ext:
                break
            while pos < tree_end:
                root, pos = self._read_cstring(buf, pos)
                if not root:
                    break
                while pos < tree_end:
                    name, pos = self._read_cstring(buf, pos)
                    if not name:
                        break
                    crc, preload_len, archive, offset, length, term = \
                        struct.unpack_from("<IHHIIH", buf, pos)
                    pos += 18
                    if term != 0xFFFF:
                        raise VpkParseError(f"bad entry terminator 0x{term:04x} at {pos-2}")
                    pos += preload_len
                    if archive == DIR_ARCHIVE and version == 1:
                        pos += length  # v1: inline data right after entry
                    entries.append(Entry(
                        f"{root}/{name}.{ext}", crc, archive, offset, length, preload_len))
        self.entries = sorted(entries, key=lambda e: e.path)
        self.total_length = sum(e.length for e in self.entries)

    def chunk_name(self, archive_idx):
        base = self.dir_path
        # "pak01_dir.vpk" -> "pak01"; fallback: replace "_dir." with "_"
        stem = base[: base.rfind(".")]
        if stem.endswith("_dir"):
            stem = stem[:-4]
        return f"{stem}_{archive_idx:03d}.vpk"

    def dump_json(self, out_path, game_dir=None):
        import os
        chunks = {}
        dir_dir = os.path.dirname(os.path.abspath(self.dir_path))
        for e in self.entries:
            if e.archive != DIR_ARCHIVE:
                chunks.setdefault(self.chunk_name(e.archive), 0)
        if game_dir:
            for c in list(chunks):
                p = os.path.join(dir_dir, c)
                chunks[c] = os.path.getsize(p) if os.path.exists(p) else -1
        data = {
            "version": self.version,
            "dir_file": self.dir_path,
            "file_count": len(self.entries),
            "total_length": self.total_length,
            "chunks": chunks,
            "files": [e.to_json() for e in self.entries],
        }
        with open(out_path, "w") as f:
            json.dump(data, f)
        return data


def collect_preloads(dir_path, wanted):
    """Single tree pass returning {path: preload_bytes} for the wanted paths only.

    CS:GO legacy semantic (verified empirically): file content = preload(head)
    + archive body(length). Entries with preload_len==0 are pure archive files.
    """
    with open(dir_path, "rb") as f:
        buf = f.read()
    magic, version, tree_size = struct.unpack_from("<III", buf, 0)
    if magic != MAGIC:
        raise VpkParseError(f"bad magic 0x{magic:08x}")
    pos = 12
    if version == 2:
        pos += 16
    tree_end = pos + tree_size
    out = {}
    while pos < tree_end:
        ext, pos = VpkIndex._read_cstring(buf, pos)
        if not ext:
            break
        while pos < tree_end:
            root, pos = VpkIndex._read_cstring(buf, pos)
            if not root:
                break
            while pos < tree_end:
                name, pos = VpkIndex._read_cstring(buf, pos)
                if not name:
                    break
                crc, plen, arc, off, length, term = struct.unpack_from("<IHHIIH", buf, pos)
                pos += 18
                preload = buf[pos:pos + plen]
                pos += plen
                if arc == DIR_ARCHIVE and version == 1:
                    pos += length
                path = f"{root}/{name}.{ext}"
                if plen and path in wanted:
                    out[path] = preload
    return out


def read_entry_data(game_dir, idx, entry):
    """Extract one entry's full content from its chunk (or dir file)."""
    import os
    if entry.archive == DIR_ARCHIVE:
        return None  # caller treats DIR_ARCHIVE as "already available"
    src = os.path.join(os.path.dirname(os.path.abspath(idx.dir_path)),
                       idx.chunk_name(entry.archive))
    with open(src, "rb") as f:
        f.seek(entry.offset)
        body = f.read(entry.length)
    preloads = collect_preloads(idx.dir_path, {entry.path})
    return preloads.get(entry.path, b"") + body


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cmd, dir_vpk = sys.argv[1], sys.argv[2]
    idx = VpkIndex(dir_vpk)
    if cmd == "list":
        print(f"vpk v{idx.version}: {len(idx.entries)} files, "
              f"inner content = {idx.total_length / 1048576:.1f} MiB")
        by_chunk = {}
        for e in idx.entries:
            k = "DIR" if e.archive == DIR_ARCHIVE else idx.chunk_name(e.archive)
            by_chunk[k] = by_chunk.get(k, [0, 0])
            by_chunk[k][0] += 1
            by_chunk[k][1] += e.length
        for k in sorted(by_chunk, key=lambda k: str(by_chunk[k][1]), reverse=True)[:12]:
            c, s = by_chunk[k]
            print(f"  {k:>20}: {c:6d} files {s / 1048576:9.1f} MiB")
    elif cmd == "dump":
        out = sys.argv[3]
        gd = sys.argv[4] if len(sys.argv) > 4 else None
        data = idx.dump_json(out, gd)
        print(f"dumped {data['file_count']} files -> {out}")
    elif cmd == "extract":
        game_dir, inner, out = sys.argv[3], sys.argv[4], sys.argv[5]
        for e in idx.entries:
            if e.path == inner and e.archive != DIR_ARCHIVE:
                data = read_entry_data(game_dir, idx, e)
                real = zlib.crc32(data) & 0xFFFFFFFF
                if real != e.crc:
                    print(f"CRC MISMATCH {inner}: {real:08x} != {e.crc:08x}")
                    return 1
                with open(out, "wb") as f:
                    f.write(data)
                print(f"extracted {inner} ({len(data)} bytes, CRC ok)")
                return 0
        print(f"not found in archive chunks: {inner}")
        return 1
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
