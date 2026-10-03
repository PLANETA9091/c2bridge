#!/usr/bin/env python3
"""strace_readmap.py — build per-file READ OFFSET MAPS from strace logs.

Input : logs of `strace -f -qq -yy -e trace=openat,read,readv,pread64,preadv,
        lseek,lseek64,_llseek,close` (see run-test.sh --strace).
Output: readmap.json {"paths": {abs_path: [[start,end), ...merged...]}}

Why offsets? The engine OPENS ~200 vpk chunks but reads only a few MiB of each.
With file positions tracked (lseek/llseek) plus pread's explicit offsets we can
map every read onto INNER-FILE boundaries from the vpk index — and ship only
the inner files that were actually touched (vpk pruning).

Notes:
  - fd->path comes from -yy annotations (present on every traced line).
  - read/readv advance the tracked position; pread64/preadv carry explicit
    offsets and do not move it; close resets fd state (fd reuse safety).
  - strace prints whence symbolically (SEEK_SET/SEEK_CUR/SEEK_END).
  - unfinished/resumed lines are skipped (small undercount; union across
    attempts covers lazy loads).
"""
import json
import re
import sys

FD_PATH = re.compile(r"^\d+\s+(read|readv|pread64|preadv|lseek|lseek64|_llseek|close)"
                     r"\((\d+)<([^>]*)>")
RET = re.compile(r"=\s*(-?\d+)\s*$")
RX_READ = re.compile(r"\)\s*=\s*(-?\d+)\s*$")
RX_PREAD = re.compile(r",\s*(-?\d+)\)\s*=\s*(-?\d+)\s*$")               # offset) = ret
RX_LSEEK = re.compile(r",\s*(-?\d+),\s*SEEK_(SET|CUR|END)\)\s*=\s*(-?\d+)\s*$")
RX_LLSEEK = re.compile(r",\s*(\d+),\s*(\d+),\s*0x[0-9a-f]+,\s*SEEK_(SET|CUR|END)\)\s*=\s*\d+$")


def build_readmaps(logs, only_prefix=None):
    ranges = {}   # path -> list[(s, e)]
    fds = {}      # fd -> (path, pos)

    def add(path, s, e):
        if e > s and (only_prefix is None or path.startswith(only_prefix)):
            ranges.setdefault(path, []).append((s, e))

    for log in logs:
        with open(log, errors="replace") as f:
            for line in f:
                if "<unfinished" in line or "<... " in line:
                    continue
                m = FD_PATH.match(line)
                if not m:
                    continue
                op, fd, path = m.group(1), int(m.group(2)), m.group(3)

                if op == "close":
                    fds.pop(fd, None)
                    continue

                st = fds.get(fd)
                if st is None or st[0] != path:
                    st = (path, 0)
                    fds[fd] = st
                pos = st[1]

                if op in ("lseek", "lseek64"):
                    lm = RX_LSEEK.search(line)
                    if lm:
                        off, whence = int(lm.group(1)), lm.group(2)
                        if whence == "SET":
                            pos = off
                        elif whence == "CUR":
                            pos += off
                        # END: size unknown -> ignore (not used for vpk reads)
                elif op == "_llseek":
                    lm = RX_LLSEEK.search(line)
                    if lm:
                        off = (int(lm.group(1)) << 32) | int(lm.group(2))
                        whence = lm.group(3)
                        if whence == "SET":
                            pos = off
                        elif whence == "CUR":
                            pos += off
                elif op == "pread64":
                    pm = RX_PREAD.search(line)
                    if pm and int(pm.group(2)) > 0:
                        off, ret = int(pm.group(1)), int(pm.group(2))
                        add(path, off, off + ret)
                elif op == "preadv":
                    pm = RX_PREAD.search(line)
                    if pm and int(pm.group(2)) > 0:
                        off, ret = int(pm.group(1)), int(pm.group(2))
                        add(path, off, off + ret)
                elif op in ("read", "readv"):
                    rm = RX_READ.search(line)
                    if rm and int(rm.group(1)) > 0:
                        ret = int(rm.group(1))
                        add(path, pos, pos + ret)
                        pos += ret

                fds[fd] = (path, pos)

    merged = {}
    for path, rs in ranges.items():
        rs.sort()
        out = []
        for s, e in rs:
            if out and s <= out[-1][1]:
                out[-1][1] = max(out[-1][1], e)
            else:
                out.append([s, e])
        merged[path] = out
    return merged


def main():
    args = sys.argv[1:]
    logs, out, prefix = [], "readmap.json", None
    i = 0
    while i < len(args):
        if args[i] == "--out":
            out = args[i + 1]; i += 2
        elif args[i] == "--only-prefix":
            prefix = args[i + 1]; i += 2
        else:
            logs.append(args[i]); i += 1
    merged = build_readmaps(logs, prefix)
    total_bytes = sum(e - s for rs in merged.values() for s, e in rs)
    with open(out, "w") as f:
        json.dump({"paths": merged}, f)
    print(f"readmap: {len(merged)} paths, {total_bytes / 1048576:.1f} MiB read -> {out}")


if __name__ == "__main__":
    main()
