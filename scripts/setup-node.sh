#!/bin/bash
# setup-node.sh — one-shot preparation of a dedicated e2e node (x86_64 VPS or runner).
# Installs everything run-test-node.sh needs and prints the actions-runner steps.
# Tested on Debian/Ubuntu (apt); best-effort Arch (pacman) detection included.
#
# Usage: bash setup-node.sh [node-user]
# After this: install the GitHub actions runner with label `c2b-node`
#   ./config.sh --url https://github.com/<you>/c2bridge --token <t> --labels c2b-node
#   sudo ./svc.sh install && sudo ./svc.sh start

set -euo pipefail
NODE_USER="${1:-$(id -un)}"
NODE_HOME="$HOME/c2b-node"

echo "== c2bridge node setup (user: $NODE_USER) =="

if command -v apt-get >/dev/null 2>&1; then
  echo "== Debian/Ubuntu: installing packages =="
  sudo apt-get update -qq
  # runtime + UI + tools; steam client needs i386 libs
  sudo dpkg --add-architecture i386 || true
  sudo apt-get install -y -qq \
    xvfb xdotool x11-utils x11-xserver-utils xkb-data \
    strace zstd unzip curl wget ca-certificates jq \
    build-essential pkg-config libc6:i386 libstdc++6:i386 \
    libglib2.0-0:i386 libgtk2.0-0:i386 libnss3:i386 libx11-6:i386 || true
  # Steam client (official repo) — provides the full client the legacy game needs
  if ! command -v steam >/dev/null 2>&1 && ! [[ -d "$HOME/.local/share/Steam" ]]; then
    echo "== adding Valve steam repo =="
    wget -qO- https://repo.steampowered.com/steam/archive/stable/steam.asc | gpg --dearmor | sudo tee /usr/share/keyrings/steam.gpg >/dev/null 2>&1 || true
    echo "deb [arch=amd64,i386 signed-by=/usr/share/keyrings/steam.gpg] https://repo.steampowered.com/steam/ stable steam" | sudo tee /etc/apt/sources.list.d/steam.list >/dev/null 2>&1 || true
    sudo apt-get update -qq && sudo apt-get install -y -qq steam-launcher || \
      echo "WARNING: steam-launcher not installed — install Steam manually"
  fi
  # rclone for the MEGA bundle fetch
  command -v rclone >/dev/null 2>&1 || { sudo apt-get install -y -qq rclone || true; }
elif command -v pacman >/dev/null 2>&1; then
  echo "== Arch: installing packages =="
  sudo pacman -S --noconfirm --needed \
    xorg-server-xvfb xdotool xorg-xdpyinfo xorg-setxkbmap strace zstd unzip curl wget \
    base-devel steam rclone lib32-glibc || true
else
  echo "WARNING: unknown package manager — install manually: xvfb xdotool setxkbmap strace zstd steam rclone"
fi

echo "== directories =="
mkdir -p "$NODE_HOME"/{bridge/lib12,runs,tmp}
cp -v "$NODE_HOME"/steam-login.sh "$NODE_HOME/" 2>/dev/null || true
[[ -f "$NODE_HOME/target.conf" ]] || echo "152.233.19.133:28022 community" > "$NODE_HOME/target.conf"

echo "== optional: fetch the lite bundle now (needs MEGA secrets) =="
echo "  MEGA_URL='https://mega.nz/folder/ID#KEY' bash $(dirname "$0")/fetch-bundle.sh ~/csgo-lite"
echo "  then export C2B_GAME_DIR=~/csgo-lite"

cat <<'EOF'

== GitHub actions runner (label: c2b-node) ==
  1. Repo -> Settings -> Actions -> Runners -> New self-hosted runner (linux x64)
  2. ./config.sh --url <repo-url> --token <token> --labels c2b-node
  3. sudo ./svc.sh install && sudo ./svc.sh start

== secrets for e2e-node.yml ==
  STEAM_USER / STEAM_PASS        burner Steam account (owns CS:GO legacy / free)
  MEGA_URL (or MEGA_USER/MEGA_PASS)  private MEGA folder with the lite bundle
  STEAM_GUARD_CODE               only for the very first login (email code)

== run a test manually ==
  C2B_GAME_DIR=~/csgo-lite bash run-test-node.sh
EOF
echo "== setup complete =="
