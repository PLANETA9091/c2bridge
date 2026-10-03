#!/usr/bin/env bash
# pack-bundle.sh — pack the minimal CS:GO legacy client ("lite bundle") for CI.
#
# Two modes:
#   A) manifest mode (chunk-granularity, legacy):
#      pack-bundle.sh --game-dir DIR --manifest FILE [--out-dir D]
#   B) stage-ready mode (vpk-pruned loose tree from tools/lite_extract.py):
#      pack-bundle.sh --stage-ready STAGE [--out-dir D]
#
# Output: c2b-lite-<date>.tar.zst + size report. NEVER commit it to the repo —
# upload to a private MEGA folder; CI pulls it via scripts/fetch-bundle.sh.
set -euo pipefail

GAME_DIR="" ; MANIFEST="" ; OUT_DIR="$PWD" ; STAGE="" ; STAGE_READY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --game-dir) GAME_DIR="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    --out-dir)  OUT_DIR="$2"; shift 2 ;;
    --stage)    STAGE="$2"; shift 2 ;;
    --stage-ready) STAGE_READY="$2"; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT_DIR"

if [[ -n "$STAGE_READY" ]]; then
  STAGE="$STAGE_READY"
  echo "== packing stage-ready tree: $STAGE"
else
  [[ -d "$GAME_DIR" ]] || { echo "ERROR: game dir not found: $GAME_DIR" >&2; exit 1; }
  [[ -f "$MANIFEST" ]] || { echo "ERROR: manifest not found: $MANIFEST" >&2; exit 1; }
  STAGE="${STAGE:-$(mktemp -d /tmp/c2b-lite-stage.XXXXXX)}"
  echo "== staging $(grep -vc '^#' "$MANIFEST") files -> $STAGE"
  ( cd "$GAME_DIR" && rsync -a --files-from="$MANIFEST" --no-perms --chmod=Du+rwX,Fu+rw . "$STAGE"/ ) \
    || { echo "rsync not available, using cp --parents" >&2
         ( cd "$GAME_DIR" && grep -v '^#' "$MANIFEST" | while IFS= read -r f; do
             [[ -f "$f" ]] && cp --parents "$f" "$STAGE"/ ; done ) ; }
  chmod +x "$STAGE"/csgo_linux64 2>/dev/null || true
  LIBSRC=/tmp/c2b/libs
  if [[ -d "$LIBSRC" ]] && compgen -G "$LIBSRC/*" >/dev/null; then
    mkdir -p "$STAGE/lib12"
    cp -f "$LIBSRC"/libpng12.so.0* "$STAGE/lib12/" 2>/dev/null || true
    cp -f "$LIBSRC"/*.so.* "$STAGE/lib12/" 2>/dev/null || true
    echo "== shipped compat libs: $(ls "$STAGE/lib12" 2>/dev/null | tr '\n' ' ')"
  fi
fi

# self-checks
[[ -x "$STAGE/csgo_linux64" ]] || echo "WARNING: launcher not staged!" >&2
find "$STAGE" -name 'pak01_dir.vpk' | grep -q . || echo "WARNING: csgo/pak01_dir.vpk missing!" >&2

DATE=$(date +%Y%m%d)
ARC="$OUT_DIR/c2b-lite-$DATE.tar.zst"
echo "== packing -> $ARC"
tar -C "$STAGE" -cf - . | zstd -T0 -6 -o "$ARC" 2>/dev/null || \
  tar -C "$STAGE" -czf "${ARC%.tar.zst}.tar.gz" .

echo "== bundle summary =="
du -h "$ARC"
echo "files: $(find "$STAGE" -type f | wc -l)   stage: $STAGE"
echo "next : upload to private MEGA folder (c2b-lite), set MEGA_URL repo secret"
