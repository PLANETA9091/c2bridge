#!/bin/bash
# verify-lite-v2.sh — FULL vpk-pruning pipeline on the rig:
#   wait for lseek-strace run -> vpk index -> readmap -> non-vpk manifest ->
#   lite_extract (CRC-verified loose tree) -> pack -> unpack -> boot-verify.
set -u

# --- c2b lock hygiene (auto-patch): stale /tmp/source_engine_*.lock owned by
# this uid silently blocks OTHER users' games (engine checks lock owner uid).
c2b_clean_engine_locks() {
  find /tmp -maxdepth 1 -user "$(id -un)" -name 'source_engine_*.lock' -delete 2>/dev/null || true
}
c2b_clean_engine_locks
trap c2b_clean_engine_locks EXIT INT TERM
# --- end c2b lock hygiene

GD="/mnt/shared/ntfs-data/SteamLibrary/steamapps/common/csgo legacy"
T=/home/agent/c2b-test
cd "$T" || exit 1

echo "== [1/7] waiting for the strace run to finish (max 25 min)"
for i in $(seq 1 150); do
  pgrep -f 'run-test[.]sh --strace' >/dev/null 2>&1 || break
  sleep 10
done
if pgrep -f 'run-test[.]sh --strace' >/dev/null 2>&1; then
  echo "ABORT: strace run still active"; exit 1
fi
L=$(ls -t runs/ | head -1)
echo "strace run $L: $(cat runs/$L/verdict.txt 2>/dev/null)"

echo "== [2/7] vpk index (pak01_dir.vpk)"
python3 "$T"/vpk_parse.py list "$GD/csgo/pak01_dir.vpk" || exit 1
python3 "$T"/vpk_parse.py dump "$GD/csgo/pak01_dir.vpk" "$T"/index.json "$GD" || exit 1

echo "== [3/7] readmap (offset-aware)"
python3 "$T"/strace_readmap.py --out "$T"/readmap.json --only-prefix "$GD" \
  /tmp/c2b-strace/strace.a*.log || exit 1

echo "== [4/7] non-vpk manifest (openat-based)"
python3 "$T"/lite-manifest.py --game-dir "$GD" \
  --strace /tmp/c2b-strace/strace.a*.log --out "$T"/lite-manifest-v2.txt || exit 1

echo "== [5/7] lite_extract -> /tmp/csgo-lite-stage"
rm -rf /tmp/csgo-lite-stage
python3 "$T"/lite_extract.py \
  --index "$T"/index.json \
  --readmap "$T"/readmap.json \
  --manifest "$T"/lite-manifest-v2.txt \
  --game-dir "$GD" \
  --out /tmp/csgo-lite-stage || exit 1

echo "== [6/7] pack"
rm -rf /tmp/c2b-lite-out; mkdir -p /tmp/c2b-lite-out
bash "$T"/pack-bundle.sh --stage-ready /tmp/csgo-lite-stage --out-dir /tmp/c2b-lite-out || exit 1
ARC=$(ls -t /tmp/c2b-lite-out/c2b-lite-*.tar.* 2>/dev/null | head -1)
echo "ARC=$ARC"

echo "== [7/7] unpack + boot-verify from the pruned bundle"
rm -rf /tmp/csgo-lite-test; mkdir -p /tmp/csgo-lite-test
case "$ARC" in
  *.tar.zst) tar --zstd -xf "$ARC" -C /tmp/csgo-lite-test 2>/dev/null || tar -I zstd -xf "$ARC" -C /tmp/csgo-lite-test ;;
  *.tar.gz)  tar -xzf "$ARC" -C /tmp/csgo-lite-test ;;
esac
chmod -R 777 /tmp/csgo-lite-test
echo "bundle tree: $(find /tmp/csgo-lite-test -type f | wc -l) files, $(du -sh /tmp/csgo-lite-test | cut -f1)"
bash "$T"/run-test.sh --game-dir /tmp/csgo-lite-test --menu-only --no-sleep --duration 120
VL=$(ls -t runs/ | head -1)
echo "== BUNDLE-BOOT VERDICT: $(cat runs/$VL/verdict.txt 2>/dev/null)"
