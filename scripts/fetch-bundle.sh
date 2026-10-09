#!/usr/bin/env bash
# fetch-bundle.sh - download the private CS:GO "lite" bundle from MEGA (CI nodes).
#
# Secrets required (pick one):
#   MEGA_USER + MEGA_PASS   MEGA account via rclone (recommended: resumable, scriptable)
#   MEGA_DIR                folder name in MEGA root holding the bundle (default: csgo)
#   MEGA_URL                full private folder link "https://mega.nz/folder/ID#KEY"
#
# The bundle NEVER lives in the repo. Pair with actions/cache so MEGA is hit
# only once per cache eviction:
#
#   - uses: actions/cache@v4
#     with:
#       path: ~/csgo-lite
#       key: csgo-lite-v1
#   - run: bash scripts/fetch-bundle.sh ~/csgo-lite
#     if: steps.cache.outputs.cache-hit != 'true'
#
set -euo pipefail

DEST="${1:-$HOME/csgo-lite}"

if [[ -d "$DEST" && -n "$(ls -A "$DEST" 2>/dev/null)" ]]; then
  echo "bundle already present at $DEST ($(du -sh "$DEST" | cut -f1)) - skipping fetch"
  exit 0
fi

# rclone with the MEGA backend: distro builds (Ubuntu 24.04 = rclone 1.60.1)
# ship WITHOUT mega ("couldn't find backend for type mega") — install the
# official current build when the backend is missing.
if ! command -v rclone >/dev/null 2>&1 || ! rclone help backends 2>/dev/null | grep -qw mega; then
  curl -fsSL -o /tmp/rclone.deb https://downloads.rclone.org/rclone-current-linux-amd64.deb
  sudo apt-get install -y -qq /tmp/rclone.deb
fi

if [[ -n "${MEGA_USER:-}" && -n "${MEGA_PASS:-}" ]]; then
  MEGA_DIR="${MEGA_DIR:-csgo}"   # user's MEGA folder created 20261003
  # run 117: `rclone config create ... pass "$(rclone obscure ...)"` broke when
  # the obscured string starts with '-' ("unknown shorthand flag: '7' in -7Fz...").
  # Env-based remote config (same pattern as the MEGA_URL branch below) bypasses
  # CLI flag parsing entirely - values can never be mistaken for flags.
  export RCLONE_CONFIG_C2BMEGA_TYPE=mega
  export RCLONE_CONFIG_C2BMEGA_USER="$MEGA_USER"
  export RCLONE_CONFIG_C2BMEGA_PASS="$(rclone obscure "$MEGA_PASS")"
  REMOTE="c2bmega:$MEGA_DIR"
elif [[ -n "${MEGA_URL:-}" ]]; then
  # run 69: the connection-string form ":mega,link=URL:" breaks when the
  # folder key starts with '-' (rclone parses it as a CLI flag). Env-based
  # remote config bypasses connection-string parsing entirely.
  export RCLONE_CONFIG_C2BMEGA_TYPE=mega
  export RCLONE_CONFIG_C2BMEGA_LINK="$MEGA_URL"
  REMOTE="c2bmega:"
else
  echo "ERROR: set MEGA_USER/MEGA_PASS or MEGA_URL (repo secret)" >&2
  exit 1
fi

mkdir -p "$DEST"
rclone copy "$REMOTE" "$DEST" --transfers 4 --checkers 8 --stats-one-line

# unpack if the bundle ships as a single archive
if compgen -G "$DEST/*.tar.zst" >/dev/null; then
  tar --zstd -xf "$DEST"/*.tar.zst -C "$DEST" --strip-components=1
  rm -f "$DEST"/*.tar.zst
elif compgen -G "$DEST/*.tar.gz" >/dev/null; then
  tar -xzf "$DEST"/*.tar.gz -C "$DEST" --strip-components=1
  rm -f "$DEST"/*.tar.gz
fi

echo "bundle ready: $(du -sh "$DEST" | cut -f1) at $DEST"
