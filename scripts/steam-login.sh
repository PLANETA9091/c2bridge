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
#
# run 43 fixes (fresh-VM login stalls, runs 39/40/42):
#  * probe.log evidence: modern steamcmd uses ~/.local/share/Steam as its data
#    root ("Redirecting stderr to '/home/runner/.local/share/Steam/logs/..."),
#    NOT /tmp/steamcmd/<...>. Harvest ssfn via find over all plausible roots.
#  * run 42: client received -login (wrote loginusers.vdf AutoLogin=1) but the
#    session never completed and the Xvfb screenshot was BLANK -> the CEF
#    login UI likely never rendered on the GPU-less runner. Launch the client
#    with CEF software rendering switches.
#  * if the session still doesn't appear, drive the visible login window with
#    xdotool (prefill may be ignored by the new login UI): type user, Tab,
#    password, Enter - then a second pass with password-only.
#  * detect the mmap() storm memory-starved client early and restart it once
#    instead of burning the whole 180s wait on a dead client.
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

# ---------- run40/43: harvest the device token (ssfn) ALWAYS ----------
# The steamcmd credential probe logs in BEFORE us and receives the
# approved-device token (ssfn*) into ITS data dir. Modern steamcmd puts that
# under ~/.local/share/Steam (see probe.log stderr line), older builds used
# their install dir or ~/Steam. Search ALL plausible roots with find.
echo "[steam-login] harvesting ssfn device tokens (steamcmd probe data)"
SSFN_COPIED=0
STAGE=/tmp/c2b-ssfn-stage
rm -rf "$STAGE" && mkdir -p "$STAGE"
find /tmp/steamcmd /tmp/c2b-steamcmd "$HOME/Steam" "$GAME_HOME/Steam" \
     "$GAME_HOME/.local/share/Steam" -maxdepth 3 -name 'ssfn*' -type f \
     -exec cp -f {} "$STAGE/" \; 2>/dev/null || true
for SF in "$STAGE"/ssfn*; do
  [[ -f "$SF" ]] || continue
  for DST in \
      "$GAME_HOME/.local/share/Steam" \
      "$GAME_HOME/.local/share/Steam/config" \
      "$GAME_HOME/.steam/steam" \
      "$GAME_HOME/.steam/steam/config"; do
    mkdir -p "$DST" 2>/dev/null || true
    cp -f "$SF" "$DST/" 2>/dev/null || true
  done
  echo "[steam-login] copied $(basename "$SF") into client steam dirs"
  SSFN_COPIED=1
done
(( SSFN_COPIED )) || echo "[steam-login] no ssfn found anywhere (guard likely OFF; ok)"

# ---------- Steam Guard: approve THIS device once via steamcmd ----------
# steamcmd's own output confirms the flow: "You can also enter this code at
# any time using 'set_steam_guard_code'". After a code-approved login steamcmd
# stores the approved-device token (ssfn*) - copy it into the client's config
# so the client's -login passes without a prompt.
if [[ -n "${STEAM_GUARD_CODE:-}" ]]; then
  echo "[steam-login] guard code provided -> approving device via steamcmd"
  SCMD=/tmp/c2b-steamcmd
  if [[ ! -x "$SCMD/steamcmd.sh" ]]; then
    mkdir -p "$SCMD"
    curl -fsSL -o "$SCMD/sc.tar.gz" https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz \
      && tar xzf "$SCMD/sc.tar.gz" -C "$SCMD" || echo "[steam-login] WARNING: steamcmd download failed"
  fi
  if [[ -x "$SCMD/steamcmd.sh" ]]; then
    sudo apt-get install -y -qq lib32gcc-s1 >/dev/null 2>&1 || true
    ( cd "$SCMD" && timeout 120 ./steamcmd.sh +login "$STEAM_USER" "$STEAM_PASS" \
        +set_steam_guard_code "$STEAM_GUARD_CODE" +quit >"$LOG" 2>&1 )
    if grep -q "Logged in OK" "$LOG"; then
      echo "[steam-login] steamcmd: device approved (guard accepted)"
    else
      echo "[steam-login] WARNING: steamcmd guard login did not confirm OK:"
      grep -aiE "guard|error|denied|failed" "$LOG" | head -5
    fi
    rm -rf "$STAGE" && mkdir -p "$STAGE"
    find "$HOME/Steam" "$SCMD" -maxdepth 3 -name 'ssfn*' -type f \
      -exec cp -f {} "$STAGE/" \; 2>/dev/null || true
    for SF in "$STAGE"/ssfn*; do
      [[ -f "$SF" ]] || continue
      for DST in "$GAME_HOME/.local/share/Steam" \
                 "$GAME_HOME/.local/share/Steam/config" \
                 "$GAME_HOME/.steam/steam/config"; do
        cp -f "$SF" "$DST/" 2>/dev/null || true
      done
      echo "[steam-login] copied $(basename "$SF") into client config"
    done
  fi
fi

# ---------- client launch ----------
# CEF (steamwebhelper) renders the login window; on the GPU-less runner the
# default GPU path can come up BLANK (run 42: webhelper processes alive, Xvfb
# screenshot empty). Force software rendering everywhere.
launch_client() {
  sudo -n -u "$GAME_USER" env DISPLAY=:99 HOME="$GAME_HOME" \
    LIBGL_ALWAYS_SOFTWARE=1 \
    STEAM_FORCE_DESKTOPUI_SOFTWARE_RENDERING=1 \
    "$STEAM_SH" -login "$STEAM_USER" "$STEAM_PASS" -silent \
      -cef-disable-gpu -cef-disable-gpu-compositing -no-cef-sandbox \
    >"$LOG" 2>&1 &
}
launch_client

# ---------- xdotool assist ----------
# If the session doesn't appear, the new login UI may be showing a form that
# ignored the -login password. Activate the Steam window and type. Two tries:
# (a) username first, Tab, password, Enter; (b) Tab once (skip prefilled
# username), password, Enter.
xdotool_login_assist() {
  local MODE_A="$1" WID NAME FOCUSED=0
  command -v xdotool >/dev/null 2>&1 || { echo "[steam-login] xdotool missing"; return 9; }
  for WID in $(DISPLAY=:99 xdotool search --onlyvisible --name '.' 2>/dev/null); do
    NAME="$(DISPLAY=:99 xdotool getwindowname "$WID" 2>/dev/null || true)"
    case "$NAME" in
      Steam|steam|Sign*|*Sign\ in*|*Steam\ Guard*)
        DISPLAY=:99 xdotool windowactivate "$WID" >/dev/null 2>&1 || true
        DISPLAY=:99 xdotool windowfocus "$WID" >/dev/null 2>&1 || true
        echo "[steam-login] xdotool: focused window '$NAME' (id $WID), mode=$MODE_A"
        FOCUSED=1
        break
        ;;
    esac
  done
  (( FOCUSED )) || { echo "[steam-login] xdotool: no steam window found to focus"; return 8; }
  printf '%s' "$STEAM_PASS" >/tmp/.c2b-pw
  if [[ "$MODE_A" == "userfirst" ]]; then
    printf '%s' "$STEAM_USER" >/tmp/.c2b-user
    DISPLAY=:99 xdotool key --delay 60 ctrl+a >/dev/null 2>&1 || true
    DISPLAY=:99 xdotool type --delay 60 --file /tmp/.c2b-user >/dev/null 2>&1
    DISPLAY=:99 xdotool key Tab >/dev/null 2>&1 || true
    DISPLAY=:99 xdotool type --delay 60 --file /tmp/.c2b-pw >/dev/null 2>&1
    rm -f /tmp/.c2b-user
  else
    DISPLAY=:99 xdotool key Tab >/dev/null 2>&1 || true
    DISPLAY=:99 xdotool type --delay 60 --file /tmp/.c2b-pw >/dev/null 2>&1
  fi
  DISPLAY=:99 xdotool key Return >/dev/null 2>&1 || true
  rm -f /tmp/.c2b-pw
  echo "[steam-login] xdotool: credentials typed, Enter sent"
}

# wait for the client to be fully up; also watch for the mmap storm
OK=0
RESTARTED=0
for i in $(seq 1 48); do
  sleep 5
  if pgrep -u "$GAME_USER" -f "ubuntu12_32/steam" >/dev/null 2>&1 && [[ -e "$GAME_HOME/.steam/steam.pipe" ]]; then
    OK=1; echo "[steam-login] client up after ~$((i*5))s"; break
  fi
  # run 42: client boots memory-starved (mmap() failed x62), never logs in,
  # and we waste the whole timeout. Detect early, restart once.
  if (( ! RESTARTED )) && (( i >= 6 )) && \
     pgrep -u "$GAME_USER" -f "ubuntu12_32/steam" >/dev/null 2>&1; then
    CL="$GAME_HOME/.steam/steam/logs/console-linux.txt"
    if [[ -f "$CL" ]]; then
      STORMN=$(tail -c 4000 "$CL" 2>/dev/null | grep -c 'mmap() failed' || true)
      if (( STORMN >= 10 )); then
        echo "[steam-login] memory-starved client (mmap x$STORMN) -> restarting once"
        RESTARTED=1
        pkill -9 -f 'ubuntu12_32/steam' 2>/dev/null || true
        pkill -9 -f steamwebhelper 2>/dev/null || true
        sleep 5
        launch_client
      fi
    fi
  fi
done
(( OK )) || { echo "[steam-login] TIMEOUT — check $LOG (first login may need STEAM_GUARD_CODE)"; exit 1; }

# the -login handshake continues AFTER the client is up - poll for the session,
# with xdotool assists at ~45s and ~75s if the session hasn't appeared
LUV="$GAME_HOME/.steam/steam/config/loginusers.vdf"
[[ -e "$LUV" ]] || LUV="$GAME_HOME/.local/share/Steam/config/loginusers.vdf"
SESSION=0
for i in $(seq 1 36); do
  if [[ -e "$LUV" ]] && grep -aq '"mostrecent"\s*"1"' "$LUV"; then
    SESSION=1; echo "[steam-login] session detected after ~$((i*5))s"; break
  fi
  if (( i == 9 )); then  xdotool_login_assist userfirst || true; fi
  if (( i == 15 )); then xdotool_login_assist passfirst || true; fi
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
    DISPLAY=:99 xdotool search --name '.*' getwindowname %@ 2>/dev/null | head -40 || echo "(xdotool failed)"
    echo "-- Xvfb window tree (geometry = is the login window rendered at all?) --"
    DISPLAY=:99 xwininfo -root -tree 2>/dev/null | head -50 || echo "(xwininfo failed)"
    echo "-- Xvfb screenshot --"
    DISPLAY=:99 import -window root /tmp/c2b-login-screen.png 2>/dev/null \
      && echo "(saved /tmp/c2b-login-screen.png)" || echo "(import failed)"
    echo "-- dialog processes (zenity argv contains the dialog TEXT = the reason) --"
    ps -eo user,pid,args | grep -aiE 'zenity|xmessage|kdialog|steam.*guard|Steam Guard' | grep -v grep || echo "(none)"
    echo "-- steam client console log tail --"
    grep -av 'mmap() failed' "$GAME_HOME/.steam/steam/logs/console-linux.txt" 2>/dev/null | tail -60 || echo "(no console-linux.txt)"
    echo "-- mmap() failed count in last 4KB (memory-starvation evidence) --"
    tail -c 4000 "$GAME_HOME/.steam/steam/logs/console-linux.txt" 2>/dev/null | grep -ac 'mmap() failed' || true
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
