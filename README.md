# c2bridge

CS:GO legacy client (Source 1) -> c2bridge network translator -> CS2 community
servers (Source 2). Mod code, test harness and CI - the only things that live
here.

## Repo layout

```
src/                     c2bridge.c (the S1->S2 translator), c2b_spy.c, tables
run-test.sh              PC rig harness (Xvfb + LD_PRELOAD + verdict loop)
run-test-node.sh         portable node harness (VPS OR GitHub hosted runner)
scripts/steam-login.sh   headless Steam client login (burner account)
scripts/setup-node.sh    one-shot VPS/runner preparation
scripts/fetch-bundle.sh  CI: fetch the private lite bundle from MEGA
tools/lite-manifest.py   strace -> minimal-file manifest (read-bytes aware)
tools/pack-bundle.sh     manifest -> c2b-lite-<date>.tar.zst
.github/workflows/       ci.yml | bundle-smoke.yml | e2e-cloud.yml | e2e-node.yml | e2e-pc.yml
```

## CI: what runs where

| workflow         | runner            | what it does                                          | cost |
|------------------|-------------------|-------------------------------------------------------|------|
| `ci`             | ubuntu-latest     | build matrix (gcc/clang x ASan/UBSan) + selftest       | free |
| `bundle-smoke`   | ubuntu-latest     | verify the private MEGA bundle link is alive           | free |
| **`e2e-cloud`**  | ubuntu-latest     | boot lite client headless (smoke) + optional full connect e2e | free* |
| `e2e-node`       | self-hosted VPS   | same, on an always-on box (optional, later)            | $/mo |
| `e2e-pc`         | self-hosted (rig) | full e2e on the dev rig                                | free |

`*` free on a **public** repo (unlimited minutes); private repo = 2000 min/mo
(smoke ~15 min/day + manual full runs fits comfortably).

### The lite bundle (how a 30 GiB game becomes a ~2 GiB CI artifact)

1. On the rig, capture what the client *actually reads* (not just opens!):
   ```
   bash run-test.sh --strace --no-sleep        # boot + connect, writes strace.a*.log
   python3 tools/lite-manifest.py --game-dir "<csgo legacy>" \
       --strace /tmp/c2b-strace/strace.a*.log --out lite-manifest-v2.txt
   ```
   `openat`-only manifests weigh ~7 GiB because the engine OPENS ~200 vpk
   chunks but READS only headers. `lite-manifest.py` sums read bytes per file
   (`strace -yy` fd decoding) and keeps a file only if it was read >= 512 KiB,
   is small (<= 8 MiB) or matches forced patterns (binaries/configs).
2. Pack it:
   ```
   bash tools/pack-bundle.sh --game-dir "<csgo legacy>" --manifest lite-manifest-v2.txt
   ```
3. Upload `c2b-lite-<date>.tar.zst` to a **private MEGA folder** (`c2b-lite`),
   set the `MEGA_URL` (or `MEGA_USER`/`MEGA_PASS`) repo secret.
4. Re-pack when the bridge learns new phases (e.g. after the connect handshake
   lands -> map chunks): feed old + new strace logs together.

### Game bundle policy (copyright)

- Valve assets are **never** in this repo (enforced by `.gitignore` too).
- The minimal "lite" CS:GO client pack lives in a **private MEGA folder**.
- MEGA credentials go to repo **Secrets**; they never appear in code or logs.
- CI caches the extracted bundle with `actions/cache` (limit 10 GB/repo), so
  MEGA transfer happens roughly once per cache eviction, not per run.

### e2e without your PC and without a VPS (e2e-cloud)

```
GitHub hosted runner (free) ── apt: xvfb/steam/i386 libs
  ├─ cache: lite bundle (MEGA on miss)
  ├─ cache: steam client + login sentry  -> Steam Guard code needed ONLY on the
  │   very first run (cached sentry = "same device" afterwards)
  ├─ build bridge (gcc) + selftest
  ├─ steam-login.sh (burner account)     -> Xvfb session
  ├─ run-test-node.sh                    -> steam://connect trigger (no UI bots)
  └─ artifacts: verdict.txt, harness.log, console.log, c2b logs
```

Secrets for `e2e-cloud.yml`:

| secret             | what                                                    |
|--------------------|---------------------------------------------------------|
| `STEAM_USER`       | burner Steam account name (owns CS:GO, free)            |
| `STEAM_PASS`       | its password                                            |
| `MEGA_URL`         | private MEGA folder link `https://mega.nz/folder/ID#KEY`|
| `STEAM_GUARD_CODE` | optional: pre-set first-run email code                  |

Steam Guard reality check: the first hosted run is a new "device" -> pass the
email code via the workflow input once; the sentry cache makes later runs
silent. If Steam rotates the guard anyway, re-pass a fresh code. Burner
account + `-insecure` = nothing of value at risk.

### Build

```
# selftest (no game files required):
gcc -O2 -DC2B_SELFTEST -o /tmp/c2b-selftest src/c2bridge.c && /tmp/c2b-selftest
# bridge:
gcc -O2 -shared -fPIC -o c2bridge64.so src/c2bridge.c
gcc -O2 -shared -fPIC -o c2b_spy64.so   src/c2b_spy.c
```

## Harness quickstart

Rig (full-featured): `bash run-test.sh --menu-only | --target IP:PORT [--strace] [--no-sleep]`

Node (portable, CI too):
```
C2B_GAME_DIR=~/csgo-lite bash run-test-node.sh                 # full: connect e2e
C2B_GAME_DIR=~/csgo-lite C2B_SMOKE=1 bash run-test-node.sh    # smoke: boot proof only
```

The rig harness isolates engine locks in a private mount namespace (coexists
with a live CS2), retries the probabilistic hook race up to 3x, and suspends
the machine at the end unless `--no-sleep`.
