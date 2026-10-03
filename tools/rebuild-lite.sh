#!/bin/bash
# rebuild-lite.sh — one-shot lite-bundle rebuild + boot-verify (fixed scheme).
#
# Fix vs 20261002 bundle: platform/ content (ALL 524 .vcs shaders + 342 .vtf,
# 935 MiB — chunk-sourced files) was MISSING entirely -> engine trap (SIGTRAP
# in libtier0 from shaderapidx9 during menu shader load). Now platform ships
# FULL (loose), csgo ships pruned, both dir-vpks are embedded-only rebuilds.
#
# All artifacts live under /home/agent (PERSISTENT) — /tmp dies on reboot.
set -u
c2b_clean_engine_locks() {
  find /tmp -maxdepth 1 -user "$(id -un)" -name 'source_engine_*.lock' -delete 2>/dev/null || true
}
c2b_clean_engine_locks
trap c2b_clean_engine_locks EXIT INT TERM

T=/home/agent/c2b-test
GD="/mnt/shared/ntfs-data/SteamLibrary/steamapps/common/csgo legacy"
STAGE=/home/agent/csgo-lite-stage
OUT=/home/agent/c2b-lite-out
TEST=/var/tmp/csgo-lite-test   # MUST be world-traversable: game runs as GAME_USER=btw,
                               # and /home/agent is mode 700. /var/tmp is persistent + world-access.
LIB12=/home/agent/c2bridge/lib12
ts() { date +%H:%M:%S; }

if [[ "${SKIP_EXTRACT:-0}" == "1" && -d "$STAGE/platform/shaders" ]]; then
  echo "[$(ts)] == [1-2/8] SKIPPED (staging exists, SKIP_EXTRACT=1)"
else
  echo "[$(ts)] == [1/8] csgo-mount PRUNED extraction (readmap-driven)"
  rm -rf "$STAGE"
  python3 "$T"/lite_extract.py \
    --index "$T"/index.json \
    --readmap "$T"/readmap.json \
    --manifest "$T"/lite-manifest-v2.txt \
    --game-dir "$GD" \
    --out "$STAGE" || { echo "ABORT: csgo extract failed"; exit 1; }

  echo "[$(ts)] == [2/8] platform-mount: ship ORIGINAL platform/ verbatim (vpk+chunks)"
  echo "  (shaders are read ONLY via vpk tree — 0 openat for .vcs even in original!)
  loose .vcs/.vtf are invisible to the shader system, so the original
  platform_pak01_dir.vpk + all 6 chunks must ship unchanged"
  rm -rf "$STAGE/platform"
  mkdir -p "$STAGE/platform"
  rsync -a --no-perms --chmod=Du+rwX,Fu+rw "$GD/platform/" "$STAGE/platform/" \
    || { echo "ABORT: platform rsync failed"; exit 1; }
fi

echo "[$(ts)] == [3/8] embedded-only dir-vpk rebuild (csgo mount only)"
python3 "$T"/vpk_rebuild.py embedded --index "$T"/index.json \
  --out "$STAGE/csgo/pak01_dir.vpk" || { echo "ABORT: csgo vpk rebuild"; exit 1; }
# platform dir-vpk ships verbatim inside the platform/ rsync — do NOT rebuild it

echo "[$(ts)] == [4/8] lib12 compat libs into bundle"
mkdir -p "$STAGE/lib12"
cp -f "$LIB12"/libpng12* "$STAGE/lib12/" 2>/dev/null && echo "libpng12 shipped" || echo "WARN: no lib12"

echo "[$(ts)] == [5/8] self-checks"
[[ -x "$STAGE/csgo_linux64" ]] || { echo "ABORT: launcher missing"; exit 1; }
VCS=$(find "$STAGE/platform/shaders" -name '*.vcs' 2>/dev/null | wc -l)
echo "platform shaders available: $VCS .vcs (inside vpk chunks — loose count is irrelevant)"
NCH=$(find "$STAGE/platform" -name 'platform_pak01_[0-9]*.vpk' | wc -l)
echo "platform chunks shipped: $NCH (need 6)"
[[ "$NCH" -ge 6 ]] || { echo "ABORT: platform chunks missing"; exit 1; }
[[ -f "$STAGE/platform/platform_pak01_dir.vpk" ]] || { echo "ABORT: platform dir vpk missing"; exit 1; }
find "$STAGE/csgo" -name 'pak01_dir.vpk' | grep -q . || { echo "ABORT: pak01_dir.vpk missing"; exit 1; }

echo "[$(ts)] == [6/8] pack"
ARC=$(ls -t "$OUT"/c2b-lite-*.tar.* 2>/dev/null | head -1)
if [[ "${SKIP_PACK:-0}" == "1" && -n "$ARC" ]]; then
  echo "SKIPPED (SKIP_PACK=1), reusing ARC=$ARC"
else
  rm -rf "$OUT"; mkdir -p "$OUT"
  bash "$T"/pack-bundle.sh --stage-ready "$STAGE" --out-dir "$OUT" || { echo "ABORT: pack failed"; exit 1; }
  ARC=$(ls -t "$OUT"/c2b-lite-*.tar.* 2>/dev/null | head -1)
fi
[[ -n "$ARC" ]] || { echo "ABORT: no archive produced"; exit 1; }
echo "ARC=$ARC"

echo "[$(ts)] == [7/8] unpack for boot test"
rm -rf "$TEST"; mkdir -p "$TEST"
case "$ARC" in
  *.tar.zst) tar --zstd -xf "$ARC" -C "$TEST" 2>/dev/null || tar -I zstd -xf "$ARC" -C "$TEST" ;;
  *.tar.gz)  tar -xzf "$ARC" -C "$TEST" ;;
esac
chmod -R 777 "$TEST"
echo "bundle tree: $(find "$TEST" -type f | wc -l) files, $(du -sh "$TEST" | cut -f1)"
VCS2=$(find "$TEST/platform/shaders" -name '*.vcs' 2>/dev/null | wc -l)
echo "vcs loose in bundle: $VCS2 (expected 0 — they live in the vpk)"

echo "[$(ts)] == [8/8] boot test from pruned bundle"
bash "$T"/run-test.sh --game-dir "$TEST" --menu-only --no-sleep --duration 300
VL=$(ls -t "$T"/runs/ | head -1)
echo "== BUNDLE-BOOT VERDICT ($VL): $(cat "$T/runs/$VL/verdict.txt" 2>/dev/null)"
echo "[$(ts)] == rebuild-lite DONE"
