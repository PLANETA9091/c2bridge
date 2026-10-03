#!/bin/bash
# run-test-node.sh v1 — PORTABLE e2e harness for a dedicated node (VPS / self-hosted runner).
# This is the "no-PC" variant of the PC harness: no suspend, no cross-user sudo,
# no unshare lock-shim (dedicated box), all paths via env.
#
# Connect trigger: `steam steam://connect/<ip:port>` (engine-level IPC) — needs NO
# UI automation, works even with the legacy client's modal dialogs on screen.
#
# Required env:
#   C2B_GAME_DIR     path to the CS:GO legacy install (lite bundle or full)
# Optional env:
#   C2B_TARGET       ip:port to connect to (default: read $C2B_NODE_HOME/target.conf)
#   C2B_NODE_HOME    work dir (default ~/c2b-node)
#   C2B_BRIDGE_DIR   dir with c2b_spy64.so + c2bridge64*.so (default $C2B_NODE_HOME/bridge)
#   C2B_GAME_USER    user the game runs as (default: current user; on nodes = the only user)
#   C2B_DURATION     per-attempt wait seconds (default 240)
#   C2B_ATTEMPTS     launch retries (default 3)
#   C2B_TRANSLATE    1 = bridge translate modes ON (default 1: C2B_UPLINK/DOWNLINK=1)
#   C2B_SMOKE        1 = boot-only mode: menu + bridge preload sanity, NO connect
#                    (daily free-tier smoke; no target needed)
#   C2B_STEAM_USER / C2B_STEAM_PASS / C2B_STEAM_GUARD_CODE
#                    if set and the steam client is not logged in, steam-login.sh is invoked
# Results: $C2B_NODE_HOME/runs/<TS>/  (verdict.txt, harness.log, console.log, c2b logs)

set -u

TS="$(date +%Y%m%dT%H%M%S)"
NODE_HOME="${C2B_NODE_HOME:-$HOME/c2b-node}"
RUNDIR="$NODE_HOME/runs/$TS"
GAME_DIR="${C2B_GAME_DIR:?C2B_GAME_DIR is required (path to CS:GO legacy install)}"
GAME_USER="${C2B_GAME_USER:-$(id -un)}"
GAME_HOME="$(getent passwd "$GAME_USER" | cut -d: -f6)"
BRIDGE_DIR="${C2B_BRIDGE_DIR:-$NODE_HOME/bridge}"
DURATION="${C2B_DURATION:-240}"
MAX_ATTEMPTS="${C2B_ATTEMPTS:-3}"
TRANSLATE="${C2B_TRANSLATE:-1}"
SMOKE="${C2B_SMOKE:-0}"
CONLOG="$GAME_DIR/csgo/console.log"

mkdir -p "$RUNDIR" "$NODE_HOME"
RESULT="$RUNDIR/verdict.txt"
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$RUNDIR/harness.log"; }
finish() { # $1 exit code, $2 verdict
  echo "$2" > "$RESULT"
  echo "$1" > "$RUNDIR/exit.code"
  log "VERDICT: $2"
  pkill -x csgo_linux64 2>/dev/null; sleep 2; pkill -9 -x csgo_linux64 2>/dev/null
  for f in "$NODE_HOME/tmp"/c2b-*.log; do [[ -f "$f" ]] && cp -f "$f" "$RUNDIR/"; done 2>/dev/null
  sudo -n cp -f "$CONLOG" "$RUNDIR/console.log" 2>/dev/null || cp -f "$CONLOG" "$RUNDIR/console.log" 2>/dev/null || true
  exit "$1"
}
trap 'finish 2 "ABORTED"' INT TERM

# ---------- 0. preconditions ----------
command -v Xvfb >/dev/null 2>&1 || finish 3 "FAIL: Xvfb not installed (run setup-node.sh)"
command -v xdotool >/dev/null 2>&1 || finish 3 "FAIL: xdotool not installed"
[[ -x "$GAME_DIR/csgo_linux64" ]] || finish 3 "FAIL: $GAME_DIR/csgo_linux64 not found (bad bundle?)"
ls "$BRIDGE_DIR"/c2b_spy64.so >/dev/null 2>&1 || finish 3 "FAIL: bridge binaries missing in $BRIDGE_DIR"

# ---------- 0b. dependency audit (dlopen of engine modules fails silently
# when a NEEDED lib is missing: the engine only prints the 32-bit probe's
# wrong-ELF-class error, see run 37123582445) ----------
if command -v ldd >/dev/null 2>&1; then
  M="$RUNDIR/ldd_missing.txt"
  { ldd "$GAME_DIR"/bin/linux64/*.so 2>/dev/null; ldd "$GAME_DIR"/bin/*.so 2>/dev/null; } \
    | awk '/not found/{print $1}' | sort -u > "$M" 2>/dev/null || true
  [[ -s "$M" ]] && log "MISSING LIBS (dlopen will fail): $(tr '\n' ' ' < "$M")"
fi

TARGET="${C2B_TARGET:-}"
if (( ! SMOKE )); then
  if [[ -z "$TARGET" && -f "$NODE_HOME/target.conf" ]]; then
    TARGET=$(grep -vE '^\s*(#|$)' "$NODE_HOME/target.conf" | head -1 | awk '{print $1}')
  fi
  [[ -n "$TARGET" ]] || finish 3 "FAIL: no target (set C2B_TARGET or $NODE_HOME/target.conf)"
fi
log "node e2e: mode=$([[ $SMOKE -eq 1 ]] && echo smoke || echo full) target=${TARGET:-none} game=$GAME_DIR bridge=$BRIDGE_DIR translate=$TRANSLATE"

TMPD="$NODE_HOME/tmp"
mkdir -p "$TMPD"
BIN_DST="$TMPD"

# ---------- 1. stage bridge + libs (world-readable; the game user must read them) ----------
mkdir -p "$BIN_DST/libs"
cp -f "$BRIDGE_DIR"/*.so "$BIN_DST/" || finish 3 "FAIL: cannot stage bridge .so"
cp -f "$BRIDGE_DIR"/lib12/* "$BIN_DST/libs/" 2>/dev/null || true
cp -f "$BRIDGE_DIR"/lib/*   "$BIN_DST/libs/" 2>/dev/null || true
chmod 755 "$BIN_DST" "$BIN_DST/libs" 2>/dev/null; chmod 644 "$BIN_DST"/*.so "$BIN_DST"/libs/* 2>/dev/null
[[ -e "$BIN_DST/libs/libpng12.so.0" ]] || log "WARNING: no libpng12 staged (menu will crash; put it in $BRIDGE_DIR/lib12/)"
log "bridge staged: $(ls "$BIN_DST"/*.so | tr '\n' ' ')"

# ---------- 2. Xvfb (persistent across runs: steam lives on this display) ----------
if pgrep -f "Xvfb :99" >/dev/null 2>&1; then
  log "Xvfb :99 already running (reusing)"
else
  pkill -f "Xvfb :99" 2>/dev/null; sleep 1
  sudo -n -u "$GAME_USER" Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >"$TMPD/xvfb.log" 2>&1 & XVFB_PID=$!
  sleep 2
  kill -0 "$XVFB_PID" 2>/dev/null || finish 3 "FAIL: Xvfb did not start"
  log "Xvfb :99 up"
fi
# keymap repair BEFORE the game initializes SDL (Xvfb xkbcomp may drop keysyms)
sudo -n -u "$GAME_USER" env DISPLAY=:99 setxkbmap -model pc105 -layout us 2>/dev/null \
  || log "WARNING: setxkbmap failed (keymap may be incomplete)"

# ---------- 2b. steam client (auth) ----------
STEAM_SH="${C2B_STEAM_SH:-$GAME_HOME/.local/share/Steam/steam.sh}"
steam_client_alive() {
  pgrep -u "$GAME_USER" -f "ubuntu12_32/steam" >/dev/null 2>&1 \
    && [[ -e "$GAME_HOME/.steam/steam.pipe" ]]
}
if ! steam_client_alive; then
  rm -f "$GAME_HOME/.steam/steam.pipe" 2>/dev/null; sudo -n rm -f "$GAME_HOME/.steam/steam.pipe" 2>/dev/null
  if [[ -n "${C2B_STEAM_USER:-}" && -x "$NODE_HOME/steam-login.sh" ]]; then
    log "steam client down -> running steam-login.sh (burner login)"
    bash "$NODE_HOME/steam-login.sh" || log "WARNING: steam-login.sh failed (continuing)"
  fi
  if ! steam_client_alive; then
    log "starting steam client (silent)"
    sudo -n -u "$GAME_USER" env DISPLAY=:99 HOME="$GAME_HOME" \
      sh -c "nohup '$STEAM_SH' -silent >'$TMPD/steam-start.log' 2>&1 &"
    STEAM_T0=$(date +%s)
    W=0
    until steam_client_alive; do
      W=$((W+5)); (( W >= 240 )) && { log "WARNING: steam not ready after ${W}s"; break; }
      sleep 5
    done
    log "steam ready after ~${W}s"
  fi
else
  log "steam client already running (warm)"
fi
# A client left over from a CI bootstrap step may be mid-self-update: the pipe
# file flaps and the engine's SteamAPI_Init dies with "create pipe failed"
# (run 37127120737, steamclient.so itself loaded OK; run 37128611184 showed the
# SAME failure ~90s AFTER a 6s-stable client — the cache-restored client
# restarted right after our check). Require the pipe to be CONNECTABLE and the
# core client PID UNCHANGED on two checks 6s apart; otherwise restart the
# client under our control.
pipe_connect_ok() {
  local P="$GAME_HOME/.steam/steam.pipe" T
  [[ -e "$P" ]] || return 1
  T=$(stat -c %F "$P" 2>/dev/null)
  if [[ "$T" == "socket" ]]; then
    python3 - "$P" <<'PYEOF' 2>/dev/null || return 1
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(sys.argv[1])
s.close()
PYEOF
  elif [[ "$T" == "fifo" ]]; then
    python3 - "$P" <<'PYEOF' 2>/dev/null || return 1
import os, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_NONBLOCK)
os.close(fd)
PYEOF
  else
    return 0  # regular file / symlink: presence is all we can verify
  fi
}
# core client only: "ubuntu12_32/steam" followed by space or EOL — this does
# NOT match steamwebhelper (ubuntu12_32/steamwebhelper), whose churn would
# break PID-stability detection
CORE_STEAM_RE='ubuntu12_32/steam( |$)'
steam_client_stable() {
  local P1 P2
  pipe_connect_ok || return 1
  P1=$(pgrep -u "$GAME_USER" -f "$CORE_STEAM_RE" 2>/dev/null | head -1)
  [[ -n "$P1" ]] || return 1
  sleep 6
  pipe_connect_ok || return 1
  P2=$(pgrep -u "$GAME_USER" -f "$CORE_STEAM_RE" 2>/dev/null | head -1)
  [[ -n "$P2" && "$P1" == "$P2" ]]
}
if ! steam_client_stable; then
  log "steam client unstable -> controlled restart"
  pkill -u "$GAME_USER" -f "ubuntu12_32/stea[m]" 2>/dev/null
  sleep 3; pkill -9 -u "$GAME_USER" -f "ubuntu12_32/stea[m]" 2>/dev/null
  rm -f "$GAME_HOME/.steam/steam.pipe" 2>/dev/null
  sudo -n -u "$GAME_USER" env DISPLAY=:99 HOME="$GAME_HOME" \
    sh -c "nohup '$STEAM_SH' -silent >'$TMPD/steam-restart.log' 2>&1 &"
  W=0
  until steam_client_stable; do
    W=$((W+5)); (( W >= 180 )) && { log "WARNING: steam still unstable after ${W}s"; break; }
    sleep 5
  done
  log "steam stability wait done (~${W}s)"
fi
# zenity --error dialogs (e.g. the userns complaint) BLOCK client startup
pkill -f "zenity --error" 2>/dev/null || true
# ---- steam self-update awareness ----
# A bootstrap-only client has NO linux64/steamclient.so; the client installs
# it when its self-update completes. Wait (bounded) for that marker, then
# prefer the client's OWN copy for ~/.steam/sdk64 (perfect version match).
SW=0
while (( SW < 240 )); do
  [[ -e "$GAME_HOME/.local/share/Steam/linux64/steamclient.so" ]] && {
    log "steam self-update marker present after ~${SW}s"; break; }
  pgrep -u "$GAME_USER" -f "ubuntu12_32/steam" >/dev/null 2>&1 || {
    log "steam client gone during update wait (~${SW}s)"; break; }
  sleep 5; (( SW += 5 ))
done
(( SW >= 240 )) && log "WARNING: self-update marker not seen in ${SW}s"
# dump steam client state (diag for pipe/version issues) — reusable so we can
# snapshot the client's state at the EXACT moment of a SteamAPI failure
dump_steam_state() {
  {
    echo "== snapshot at $(date +%H:%M:%S) =="
    echo "== .local/share/Steam top =="; ls -la "$GAME_HOME/.local/share/Steam/" 2>/dev/null | head -25
    echo "== linux64 dir =="; ls -la "$GAME_HOME/.local/share/Steam/linux64/" 2>/dev/null | head -15
    echo "== package version =="; ls "$GAME_HOME/.local/share/Steam/package/" 2>/dev/null | head -10
    echo "== steam procs =="; ps -f -u "$GAME_USER" 2>/dev/null | grep -i steam | head -10
    echo "== engine procs =="; pgrep -af 'csgo_linux64|hl2_linux' 2>/dev/null | head -8 || echo none
    echo "== engine locks =="; ls -la /tmp/source_engine_*.lock 2>/dev/null || echo "no lock files"
    echo "== steam.pipe =="; ls -la "$GAME_HOME/.steam/steam.pipe" 2>/dev/null; stat -c '%F %a %U' "$GAME_HOME/.steam/steam.pipe" 2>/dev/null; file "$GAME_HOME/.steam/steam.pipe" 2>/dev/null
    echo "== pipe connect test =="; pipe_connect_ok && echo CONNECT_OK || echo CONNECT_FAIL
    echo "== bootstrap_log tail =="; tail -30 "$GAME_HOME/.local/share/Steam/logs/bootstrap_log.txt" 2>/dev/null
    echo "== console_linux tail =="; tail -20 "$GAME_HOME/.local/share/Steam/logs/console_linux.txt" 2>/dev/null
  } > "$1" 2>/dev/null || true
}
dump_steam_state "$RUNDIR/steam_state.txt"

# The engine dlopens ~/.steam/sdk64/steamclient.so to talk to the local Steam
# client; a bootstrap-only install often lacks the symlink AND the .so itself
# (run 37125759327). Try known locations, then any 64-bit steamclient.so under
# .local/share/Steam, then the official full-client tarball (extract ONLY
# steamclient.so - do not touch the live client's files).
if [[ ! -e "$GAME_HOME/.steam/sdk64/steamclient.so" ]]; then
  mkdir -p "$GAME_HOME/.steam"
  SC=""
  for CAND in \
    "$GAME_HOME/.steam/root/linux64/steamclient.so" \
    "$GAME_HOME/.local/share/Steam/linux64/steamclient.so" \
    "$GAME_HOME/.local/share/Steam/ubuntu12_64/steamclient.so" \
    /usr/lib/steam/linux64/steamclient.so ; do
    [[ -e "$CAND" ]] && { SC="$CAND"; break; }
  done
  if [[ -z "$SC" ]] && command -v file >/dev/null 2>&1; then
    while IFS= read -r f; do
      file -b "$f" 2>/dev/null | grep -q 'x86-64' && { SC="$f"; break; }
    done < <(find "$GAME_HOME/.local/share/Steam" -maxdepth 5 -name steamclient.so 2>/dev/null)
  fi
  if [[ -z "$SC" ]]; then
    # steamclient.so ships in the Steam client's bins_sdk package: fetch the
    # update manifest, pull bins_sdk_ubuntu12.zip.<hash>, extract only
    # linux64/steamclient.so (never touches the live client's files).
    log "steamclient.so not installed - fetching from Steam CDN (bins_sdk)"
    MF="$TMPD/steam_client_manifest.vdf"
    if curl -fsSL -o "$MF" https://media.steampowered.com/client/steam_client_ubuntu12; then
      PKG=$(sed -n 's/.*"file"[[:space:]]*"\(bins_sdk_ubuntu12\.zip\.[0-9a-f]*\)".*/\1/p' "$MF" | head -1)
      if [[ -n "$PKG" ]] && curl -fsSL -o "$TMPD/bins_sdk.zip" \
           "https://media.steampowered.com/client/$PKG"; then
        mkdir -p "$TMPD/sdk-extract"
        if command -v unzip >/dev/null 2>&1; then
          unzip -o -q "$TMPD/bins_sdk.zip" -d "$TMPD/sdk-extract" '*linux64/*' 2>/dev/null || true
        else
          python3 - "$TMPD/bins_sdk.zip" "$TMPD/sdk-extract" <<'PYEOF' 2>/dev/null || true
import sys, zipfile
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
PYEOF
        fi
        SC=$(find "$TMPD/sdk-extract" -path '*linux64/*' 2>/dev/null | head -1)
      fi
    fi
  fi
  if [[ -n "$SC" && -e "$SC" ]]; then
    ln -sfn "$(dirname "$SC")" "$GAME_HOME/.steam/sdk64"
    log "created ~/.steam/sdk64 -> $(dirname "$SC")"
  else
    log "WARNING: steamclient.so unavailable; Steam-API init will fail"
  fi
fi
# hide steam's own UI windows (no WM on the node: they overlap the game)
XD() { sudo -n -u "$GAME_USER" env DISPLAY=:99 xdotool "$@"; }
for W in $(XD search --name 'Steam' 2>/dev/null; XD search --name 'steam' 2>/dev/null); do
  WN=$(XD getwindowname "$W" 2>/dev/null)
  case "$WN" in
    Steam|steam)
      WW=$(XD getwindowgeometry --shell "$W" 2>/dev/null | grep -aoP 'WIDTH=\K\d+')
      [[ "${WW:-0}" -gt 400 ]] && XD windowunmap "$W" 2>/dev/null && log "unmapped steam window $W"
      ;;
  esac
done

# ---------- 3. launch + trigger loop ----------
# T-0 pipe sanity: run 12 proved the pipe can die in the ~90s between our
# stability check and the engine's SteamAPI_Init. Re-verify RIGHT NOW.
if ! pipe_connect_ok; then
  log "WARNING: pipe not connectable at T-0 -> waiting up to 120s for recovery"
  W=0
  until pipe_connect_ok; do
    W=$((W+5)); (( W >= 120 )) && { log "WARNING: pipe still down after ${W}s (launching anyway)"; break; }
    sleep 5
  done
  (( W < 120 )) && log "pipe recovered after ~${W}s"
fi

VERDICT_CODE=1; VERDICT_TEXT="FAIL: no verdict"
CONNECTED=0
for (( ATTEMPT=1; ATTEMPT<=MAX_ATTEMPTS; ATTEMPT++ )); do
  if (( ATTEMPT > 1 )); then
    log "attempt $ATTEMPT/$MAX_ATTEMPTS: relaunching"
    pkill -9 -x csgo_linux64 2>/dev/null
    pkill -9 -x hl2_linux 2>/dev/null
    pkill -9 -f "$GAME_DIR" 2>/dev/null
    sleep 2
    # stale single-instance lock: clear ONLY when no engine process survived;
    # deleting a LIVE holder's file would let two engines race on fresh inodes
    if ! pgrep -f 'csgo_linux64|hl2_linux' >/dev/null 2>&1; then
      rm -f /tmp/source_engine_*.lock 2>/dev/null \
        || sudo -n rm -f /tmp/source_engine_*.lock 2>/dev/null || true
      [[ -n "$(ls /tmp/source_engine_*.lock 2>/dev/null)" ]] \
        && log "WARNING: engine lock file still present after cleanup"
    fi
    rm -f "$CONLOG" 2>/dev/null
  fi
  OUT="$RUNDIR/csgo_stdout.a${ATTEMPT}.log"

  MODES=""
  [[ $TRANSLATE -eq 1 ]] && MODES="C2B_UPLINK=1 C2B_DOWNLINK=1"
  BRIDGE_SO="$BIN_DST/c2bridge64.stable.so"
  [[ -f "$BRIDGE_SO" ]] || BRIDGE_SO="$BIN_DST/c2bridge64.so"

  # Diagnostic on attempt 1: gdb batch INSIDE sudo as the game user - catches
  # SIGSEGV with a full backtrace and the engine Error() int3 path (strace
  # only showed WHO died; setuid sudo can't be ptraced from outside, run
  # 37122969873).
  DBG_INNER=""
  if (( ATTEMPT == 1 )) && command -v gdb >/dev/null 2>&1; then
    DBG_INNER="exec gdb -batch -return-child-result \
      -ex 'set confirm off' \
      -ex 'handle SIGPIPE nostop noprint' \
      -ex 'handle SIGHUP nostop noprint' \
      -ex 'handle SIGUSR1 nostop noprint' \
      -ex 'handle SIGUSR2 nostop noprint' \
      -ex 'handle SIGALRM nostop noprint' \
      -ex 'handle SIGCONT nostop noprint' \
      -ex run \
      -ex 'thread apply all bt' \
      --args ./csgo_linux64"
  elif (( ATTEMPT == 1 )) && command -v strace >/dev/null 2>&1; then
    DBG_INNER="exec strace -f -qq -e trace=execve,execveat,kill,tgkill,mprotect,prctl -o $RUNDIR/strace_game.a1.log ./csgo_linux64"
  fi

  sudo -n -u "$GAME_USER" env HOME="$GAME_HOME" USER="$GAME_USER" DISPLAY=:99 \
    LD_LIBRARY_PATH="$BIN_DST/libs:$GAME_DIR/bin/linux64:$GAME_DIR/bin/x64:$GAME_DIR/bin" \
    SDL_AUDIODRIVER=dummy \
    LD_PRELOAD="$BIN_DST/c2b_spy64.so $BRIDGE_SO" \
    $MODES \
    sh -c "cd '$GAME_DIR' && ${DBG_INNER:-exec ./csgo_linux64} -novid -nojoy -nosteamcontroller -nobreakpad -insecure -nosound -windowed -w 1280 -h 720 -condebug" \
    >"$OUT" 2>&1 &
  log "attempt $ATTEMPT: client launched, waiting up to ${DURATION}s for menu"

  # wait for the main menu (modals may cover it — steam://connect still works)
  MENU=0
  END=$((SECONDS + DURATION))
  while (( SECONDS < END )); do
    pgrep -x csgo_linux64 >/dev/null 2>&1 || {
      log "attempt $ATTEMPT: client died"
      dump_steam_state "$RUNDIR/steam_state_died.a${ATTEMPT}.txt"
      (( ATTEMPT == 1 )) && sudo -n dmesg 2>/dev/null | tail -60 > "$RUNDIR/dmesg.a1.log"
      break; }
    grep -aq 'CSGO_GAME_UI_STATE_MAINMENU' "$OUT" 2>/dev/null && { MENU=1; log "attempt $ATTEMPT: menu reached"; break; }
    # fast-fail: a SteamAPI pipe failure leaves a MODAL error dialog on screen
    # and the harness stalled the full DURATION doing nothing (run 37128611184
    # attempt 2: 240s wasted). Snapshot client state, kill, retry with a
    # settled client instead.
    if grep -aq -e 'Failed to connect with local Steam Client' -e '\[S_API FAIL\]' "$OUT" 2>/dev/null; then
      log "attempt $ATTEMPT: SteamAPI pipe failure in game log -> fast-fail instead of ${DURATION}s modal stall"
      dump_steam_state "$RUNDIR/steam_state_fatal.a${ATTEMPT}.txt"
      pkill -9 -x csgo_linux64 2>/dev/null
      sleep 2
      break
    fi
    sleep 5
  done
  (( MENU )) || continue
  sleep 8   # let steam auth settle

  # ---- smoke mode: boot proof only (menu + no preload failure) ----
  if (( SMOKE )); then
    sleep 12  # let the menu settle; a bundle gap usually crashes here
    if pgrep -x csgo_linux64 >/dev/null 2>&1 \
       && ! grep -aq 'ERROR: ld.so: object' "$OUT" 2>/dev/null; then
      VERDICT_CODE=0; VERDICT_TEXT="PASS: smoke boot from lite bundle (menu stable, bridge preloaded, attempt $ATTEMPT)"
      break
    fi
    log "attempt $ATTEMPT: smoke check failed (died or preload error)"
    continue
  fi

  # ---- THE TRIGGER: steam://connect (engine-level IPC, no UI automation) ----
  log "attempt $ATTEMPT: firing steam://connect/$TARGET"
  sudo -n -u "$GAME_USER" env DISPLAY=:99 HOME="$GAME_HOME" \
    "$STEAM_SH" "steam://connect/$TARGET" >"$TMPD/steam-connect.a${ATTEMPT}.log" 2>&1 &

  END=$((SECONDS + DURATION))
  while (( SECONDS < END )); do
    pgrep -x csgo_linux64 >/dev/null 2>&1 || { log "attempt $ATTEMPT: client died during connect"; break; }
    if grep -aqiE 'Connected\(|Signing up to server|Connected to' "$OUT" 2>/dev/null \
       || sudo -n grep -aqiE 'Connected\(|Signing up to server|Connected to' "$CONLOG" 2>/dev/null; then
      CONNECTED=1; log "attempt $ATTEMPT: CONNECTION MARKER FOUND"; break
    fi
    # bridge-side evidence also counts: translated uplink traffic to the target
    if grep -aqE 'up #0x[0-9a-f]+  len=0x[0-9a-f]{3,}' "$OUT" 2>/dev/null; then
      log "attempt $ATTEMPT: bridge is passing real traffic (uplink len>255)"
    fi
    sleep 5
  done
  (( CONNECTED )) && { VERDICT_CODE=0; VERDICT_TEXT="PASS: connected to $TARGET (attempt $ATTEMPT)"; break; }
done

(( VERDICT_CODE != 0 )) && VERDICT_TEXT="FAIL: no connection to ${TARGET:-<smoke>} (menu=$MENU, logs: $RUNDIR)"
finish "$VERDICT_CODE" "$VERDICT_TEXT"
