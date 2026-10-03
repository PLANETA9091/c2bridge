#!/usr/bin/env python3
"""lite-manifest.py — build the minimal-client file manifest from strace logs.

Why not plain `openat` manifests? The engine OPENS ~200 vpk chunk files at boot
but only READS their headers. A bundle of everything opened weighs ~7 GiB.
This tool attributes actual read bytes to file paths (strace -yy fd decoding)
and includes a file only when it is really used:

  include if  read_bytes >= --min-read (default 512 KiB)
          or  size <= --max-small (default 8 MiB)
          or  path matches --force regexes (binaries, configs, gameinfo)

Inputs : one or more strace logs from `strace -f -qq -yy -e
         trace=openat,read,readv,pread64,preadv -o LOG` (multiple logs are
         merged automatically: re-pack later, e.g. after the handshake lands,
         by feeding old + new logs together).
Output : lite-manifest-v2.txt  (one path per line, relative to --game-dir)
         plus a human report on stdout (counts, sizes, excluded top offenders).

Usage:
  python3 lite-manifest.py --game-dir "/path/csgo legacy" \
      --strace a1.log a2.log a3.log --out lite-manifest-v2.txt
"""
import argparse
import os
import re
import sys

# fd annotated by -yy:  3</mnt/.../file>
FD_RX = re.compile(r"^\d+\s+(read|readv|pread64|preadv)\(\d+<(/[^>]*)>")
RET_RX = re.compile(r"\)\s+=\s+(\d+)\s*$")
OPEN_RX = re.compile(r"openat\((?:AT_FDCWD|-?\d+),\s+\"([^\"]+)\"")
OPEN_OK_RX = re.compile(r"\)\s+=\s+(\d+)")  # fd >= 0 means success (also `= 3</p>`)

FORCE_RX = [
    re.compile(p)
    for p in (
        r"^csgo_linux64",          # top-level launcher binaries
        r"\.so(\.\d+)*$",          # every shared object
        r"^bin/",                  # engine + game bin trees
        r"^csgo/bin/",
        r"^linux64/",
        r"\.vdf$",                 # steam/game manifests
        r"gameinfo\.gi",
        r"^csgo/cfg/",
        r"\.(txt|lst|vcs)$",
    )
]

def read_stats(paths):
    """path -> bytes successfully read (sum over all logs)."""
    reads = {}
    for log in paths:
        with open(log, errors="replace") as f:
            for line in f:
                m = FD_RX.match(line)
                if not m:
                    continue
                r = RET_RX.search(line)
                if not r:
                    continue  # unfinished/failed
                n = int(r.group(1))
                if n <= 0:
                    continue
                p = m.group(2)
                reads[p] = reads.get(p, 0) + n
    return reads

def opened_paths(paths):
    """set of game-dir-relative paths successfully opened at least once."""
    opened = set()
    for log in paths:
        with open(log, errors="replace") as f:
            for line in f:
                m = OPEN_RX.search(line)
                if not m:
                    continue
                r = OPEN_OK_RX.search(line.split(m.group(0), 1)[1])
                if not r:
                    continue
                p = m.group(1)
                if not p.startswith("/"):
                    continue  # relative cwd opens are rare; abs only
                opened.add(os.path.normpath(p))
    return opened

def human(n):
    return f"{n / 1048576:.1f} MiB" if n >= 1048576 else f"{n / 1024:.0f} KiB"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--game-dir", required=True)
    ap.add_argument("--strace", nargs="+", required=True)
    ap.add_argument("--out", default="lite-manifest-v2.txt")
    ap.add_argument("--min-read", type=int, default=512 * 1024)
    ap.add_argument("--max-small", type=int, default=8 * 1024 * 1024)
    ap.add_argument("--include-all-vpk", action="store_true",
                    help="fallback: force every opened .vpk into the manifest")
    a = ap.parse_args()
    gd = os.path.normpath(a.game_dir)

    reads = read_stats(a.strace)
    opened = opened_paths(a.strace)
    print(f"[i] opened(success): {len(opened)} paths; with reads: {len(reads)} paths")

    keep, report = [], []
    excluded_saved = 0
    total_kept = 0
    for p in sorted(opened):
        rel = os.path.relpath(p, gd)
        if rel.startswith(".."):
            continue  # outside the game dir (system libs — node provides its own)
        try:
            size = os.path.getsize(p)
        except OSError:
            continue  # transient (deleted temp)
        rb = reads.get(p, 0)
        if rb >= a.min_read:
            why = f"read={human(rb)}"
        elif size <= a.max_small:
            why = f"small={human(size)}"
        elif any(rx.search(rel) for rx in FORCE_RX):
            why = "forced"
        elif a.include_all_vpk and rel.endswith(".vpk"):
            why = "vpk-all"
        else:
            excluded_saved += size
            report.append((size, rb, rel))
            continue
        keep.append(rel)
        total_kept += size

    with open(a.out, "w") as f:
        f.write("# lite-manifest-v2: files actually needed (read>=min or small or forced)\n")
        for rel in keep:
            f.write(rel + "\n")

    print(f"[=] KEEP {len(keep)} files, {human(total_kept)} content")
    if report:
        print(f"[=] EXCLUDED {len(report)} files, saved {human(excluded_saved)}; top offenders:")
        for size, rb, rel in sorted(report, reverse=True)[:12]:
            print(f"      -{human(size):>11} (read {human(rb):>9})  {rel}")
    print(f"[=] manifest written: {a.out}")

if __name__ == "__main__":
    sys.exit(main())
