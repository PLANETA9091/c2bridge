#!/bin/bash
# steam-login.sh — headless Steam client login for a burner account (CI nodes).
# Env:
#   STEAM_USER        (required) account name
#   STEAM_PASS        (required) password
#   STEAM_GUARD_CODE  optional: email/2FA code for the FIRST login from a new device
#   C2B_GAME_USER     user owning the steam client (default: current user)
#   C2B_STEAM_SH      path to steam.sh (default ~/.local/share/Steam/steam.sh)
#
# Strategy: run the full client under Xvfb with -login args (creates the sentry +
# session files so later starts are silent auto-login). Steam Guard: the first
# login from a new device needs a code ONCE; pass it via STEAM_GUARD_CODE.
set -u
GAME_USER="${C2B_GAME_USER:-$(id -un)}"
GAME_HOME="$(getent passwd "$GAME_USER" | cut -d: -f6)"
STEAM_SH="${C2B_STEAM_SH:-$GAME_HOME/.local/share/Steam/steam.sh}"
[[ -x "$STEAM_SH" ]] || { echo "steam.sh not found at $STEAM_SH"; exit 3; }
: "${STEAM_USER:?STEAM_USER required}" "${STEAM_PASS:?STEAM_PASS required}"

# Xvfb for the login UI
pgrep -f "Xvfb :99" >/dev/null 2>&1 || {
  sudo -n -u "$GAME_USER" Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >/tmp/c2b-login-xvfb.log 2>&1 &
  sleep 2
}

LOG=/tmp/c2b-steam-login.log
if [[ -n "${STEAM_GUARD_CODE:-}" ]]; then
  echo "[steam-login] login WITH guard code"
  sudo -n -u "$GAME_USER" env DISPLAY=:99 HOME="$GAME_HOME" \
    "$STEAM_SH" -login "$STEAM_USER" "$STEAM_PASS" -set_steam_guard_code "$STEAM_GUARD_CODE" -silent >"$LOG" 2>&1 &
else
  echo "[steam-login] login (no code; ok if a sentry already exists on this node)"
  sudo -n -u "$GAME_USER" env DISPLAY=:99 HOME="$GAME_HOME" \
    "$STEAM_SH" -login "$STEAM_USER" "$STEAM_PASS" -silent >"$LOG" 2>&1 &
fi

# wait for the client to be fully up
OK=0
for i in $(seq 1 48); do
  sleep 5
  if pgrep -u "$GAME_USER" -f "ubuntu12_32/steam" >/dev/null 2>&1 && [[ -e "$GAME_HOME/.steam/steam.pipe" ]]; then
    OK=1; echo "[steam-login] client up after ~$((i*5))s"; break
  fi
done
(( OK )) || { echo "[steam-login] TIMEOUT — check $LOG (first login may need STEAM_GUARD_CODE)"; exit 1; }

# the -login handshake continues AFTER the client is up (and on a new device it
# blocks on Steam Guard until the code is entered) - poll for the session
LUV="$GAME_HOME/.steam/steam/config/loginusers.vdf"
[[ -e "$LUV" ]] || LUV="$GAME_HOME/.local/share/Steam/config/loginusers.vdf"
SESSION=0
for i in $(seq 1 36); do
  if [[ -e "$LUV" ]] && grep -aq '"mostrecent"\s*"1"' "$LUV"; then
    SESSION=1; echo "[steam-login] session detected after ~$((i*5))s"; break
  fi
  sleep 5
done

# verify an actual account is logged in (loginusers.vdf: mostrecent=1 and not a stub)
if (( SESSION )); then
  echo "[steam-login] OK: account logged in ($LUV)"
else
  DIAG=/tmp/c2b-steam-login-diag.txt
  {
    echo "== steam-login diagnostics $(date -u +%H:%M:%SZ) =="
    echo "-- Xvfb :99 window titles (login dialogs live here) --"
    DISPLAY=:99 xdotool search --onlyvisible --name '.*' getwindowname %@ 2>/dev/null | head -30 || echo "(xdotool failed)"
    echo "-- dialog processes (zenity argv contains the dialog TEXT = the reason) --"
    ps -eo user,pid,args | grep -aiE 'zenity|xmessage|kdialog|steam.*guard|Steam Guard' | grep -v grep || echo "(none)"
    echo "-- steam client console log tail --"
    tail -80 "$GAME_HOME/.steam/steam/logs/console-linux.txt" 2>/dev/null || echo "(no console-linux.txt)"
    echo "-- config dir --"
    ls -la "$GAME_HOME/.local/share/Steam/config/" 2>/dev/null | head -20
    echo "-- sentry/session files --"
    ls -la "$GAME_HOME/.steam/steam/config/" 2>/dev/null | grep -iE 'sentry|login|config' || echo "(no .steam/steam/config files)"
    ss_files=$(find "$GAME_HOME/.local/share/Steam" -maxdepth 2 -name 'ssfn*' 2>/dev/null | head -5)
    echo "ssfn files: ${ss_files:-none}"
    echo "-- loginusers.vdf --"
    cat "$LUV" 2>/dev/null || echo "(absent)"
  } > "$DIAG" 2>&1
  echo "[steam-login] WARNING: client is up but no login session found ($LUV)"
  echo "[steam-login] hints: correct credentials? Steam Guard code needed once? (STEAM_GUARD_CODE=12345)"
  echo "[steam-login] diagnostics written to $DIAG:"
  cat "$DIAG"
  exit 2
fi
