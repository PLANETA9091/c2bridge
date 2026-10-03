#!/bin/bash
# c2b-test v5: on-demand test harness for the c2bridge project
# (CS:GO legacy client [S1] -> c2bridge translate -> CS2 community servers [S2])
#
# Usage: run-test.sh [--target IP:PORT] [--duration SEC] [--no-sleep] [--menu-only] [--arm-hours N] [--variant NAME] [--no-bridge]
#                     [--game-dir DIR]  (default: PC steam library; env C2B_GAME_DIR also works)
#  - boots Xvfb + CS:GO legacy client with c2bridge injected
#  - coexists with a running CS2: engine lock is shadowed inside a PRIVATE mount
#    namespace (unshare -m), the host /tmp is never modified -> games don't fight
#  - never suspends while CS2 (user's game) is running
#  - uses project lib12/libpng12 (without it: pango fatal crash at menu)
#  - defaults to c2bridge64.stable.so symlink if present (plain c2bridge64.so
#    currently crashes when arming its GC hook)
#  - RETRY: the bridge IClient hook has a probabilistic race (segfault right
#    after "IClient vt+0x60 hooked", jump to 0x1b23b6). If the client dies early,
#    the launch is retried up to 3 times (warm boots take ~10s to menu).
#  - with --target: client executes `connect <target>`; success = connection markers
#    and/or fresh live_state snapshot from c2bridge
#  - without --target: smoke test, verdict = client reached main menu
#  - default: system SUSPENDS at the end (--no-sleep to keep awake)
#  - --arm-hours N: set RTC wake alarm N hours after suspend
#  - v7: the engine silently defers an early `connect` ("Deferring connect
#    command!" at startup, never completed) and CS:GO cfgs have no `wait`.
#    Instead: key BINDS registered via csgo/cfg/c2b_connect.cfg, hooked BOTH
#    from autoexec.cfg (engine reads it natively - cannot be dropped like
#    cmdline +commands) and `+exec`; each bind echoes a marker so the harness
#    can SEE whether the cfg loaded and whether the synthetic key fired.
#    Harness presses F12/KP_END/F11 via xdotool once the menu state appears
#    and RETRIES every 12s until a marker lands; --oldconnect reverts
#  - --strace: record every file the client opens (openat) -> runs/<TS>/lite-manifest.txt
#    (basis for the minimal "lite" client pack for VM/CI nodes)
#
# Results: /home/agent/c2b-test/last-result.txt and runs/<timestamp>/

set -u

# --- c2b lock hygiene (auto-patch): stale /tmp/source_engine_*.lock owned by
# this uid silently blocks OTHER users' games (engine checks lock owner uid).
c2b_clean_engine_locks() {
  find /tmp -maxdepth 1 -user "$(id -un)" -name 'source_engine_*.lock' -delete 2>/dev/null || true
}
c2b_clean_engine_locks
trap c2b_clean_engine_locks EXIT INT TERM
# --- end c2b lock hygiene

TS="$(date +%Y%m%dT%H%M%S)"
RUNDIR="/home/agent/c2b-test/runs/$TS"
CONF="/home/agent/c2b-test/target.conf"
GAME_DIR="${C2B_GAME_DIR:-/mnt/shared/ntfs-data/SteamLibrary/steamapps/common/csgo legacy}"
GAME_USER="${C2B_GAME_USER:-btw}"   # the desktop user that owns Steam (games run as this user)
GAME_HOME="/home/$GAME_USER"
CONLOG="$GAME_DIR/csgo/console.log"
BIN_SRC="/home/agent/c2bridge"
BIN_DST="/tmp/c2b"
PNG12_SRC="$GAME_HOME/.local/share/Steam/steamapps/common/SteamLinuxRuntime/steam-runtime/lib/x86_64-linux-gnu/libpng12.so.0"
DURATION=120
TARGET=""
MENU_ONLY=0
DO_SLEEP=1
ARM_HOURS=0
VARIANT=""
NO_BRIDGE=0
MAX_ATTEMPTS=3
STRACE=0
OLD_CONNECT=0
AUTOEXEC_PATCHED=0

mkdir -p "$RUNDIR"
RESULT="$RUNDIR/verdict.txt"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$RUNDIR/harness.log"; }

# steam client readiness: the REAL client binary must be alive and its IPC pipe
# must be FRESH (bootstrap recreates the pipe early, long before IPC is served;
# a stale pipe from a crashed session fakes readiness).
STEAM_T0=0   # epoch of steam start; 0 = warm path (any pipe age ok)
steam_client_alive() {
  pgrep -u "$GAME_USER" -f "ubuntu12_32/steam" >/dev/null 2>&1 \
    && [[ -e "$GAME_HOME/.steam/steam.pipe" ]] \
    && (( $(stat -c %Y "$GAME_HOME/.steam/steam.pipe" 2>/dev/null || echo 0) >= STEAM_T0 ))
}
steam_wait() { # returns 0 when ready, 1 on timeout
  steam_client_alive && return 0
  local W=0
  until steam_client_alive; do
    W=$((W + 5))
    if (( W >= 240 )); then log "WARNING: steam not fully ready after ${W}s (continuing)"; return 1; fi
    sleep 5
  done
  sleep 10   # let the client settle its IPC before we trust it
  if steam_client_alive; then
    log "steam client ready (waited ~${W}s, pipe verified)"
    return 0
  fi
  log "WARNING: steam client not stable after first contact"
  return 1
}

# hide steam's OWN windows: without a window manager its fullscreen UI overlaps
# the game and steals clicks/keys. Unmapped windows stop rendering but the
# client keeps running (auth/IPC are sockets, not windows).
steam_hide_windows() {
  local XD="sudo -n -u $GAME_USER env DISPLAY=:99 xdotool" W WNAME WW
  for W in $($XD search --name 'Steam' 2>/dev/null; $XD search --name 'steam' 2>/dev/null); do
    WNAME=$($XD getwindowname "$W" 2>/dev/null)
    case "$WNAME" in
      Steam|steam)
        WW=$($XD getwindowgeometry --shell "$W" 2>/dev/null | grep -aoP 'WIDTH=\K\d+')
        [[ "${WW:-0}" -gt 400 ]] && { $XD windowunmap "$W" 2>/dev/null && log "unmapped steam window $W (${WW}px wide)"; }
        ;;
    esac
  done
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --no-sleep) DO_SLEEP=0; shift ;;
    --menu-only) MENU_ONLY=1; shift ;;
    --arm-hours) ARM_HOURS="$2"; shift 2 ;;
    --variant) VARIANT="$2"; shift 2 ;;
    --no-bridge) NO_BRIDGE=1; shift ;;
    --strace) STRACE=1; shift ;;
    --oldconnect) OLD_CONNECT=1; shift ;;
    --game-dir) GAME_DIR="$2"; CONLOG="$GAME_DIR/csgo/console.log"; shift 2 ;;
    *) log "unknown arg $1"; shift ;;
  esac
done

# default target from config file (first non-comment line: "IP:PORT optional-tag")
if [[ -z "$TARGET" && $MENU_ONLY -eq 0 && -f "$CONF" ]]; then
  TARGET=$(grep -vE '^\s*(#|$)' "$CONF" | head -1 | awk '{print $1}')
fi

finish() { # $1 = exit code, $2 = verdict text
  echo "$2" > "$RESULT"
  echo "$1" > "$RUNDIR/exit.code"
  log "VERDICT: $2"
  # cleanup: only OUR instance (exact process name), never user games
  sudo -n pkill -x csgo_linux64 2>/dev/null
  sleep 2
  sudo -n pkill -9 -x csgo_linux64 2>/dev/null
  # NOTE: Xvfb :99 is NEVER killed here: the steam client stays attached to it
  # across runs (warm steam = fast boots); killing Xvfb makes steam crash with
  # "XIO: fatal IO error" and the next run has to bootstrap steam from scratch.
  :
  for f in /tmp/c2b/*.log; do
    [[ -f "$f" ]] && cp -f "$f" "$RUNDIR/c2b-$(basename "$f")"
  done 2>/dev/null
  sudo -n cp -f "$CONLOG" "$RUNDIR/console.log" 2>/dev/null
  # restore the game cfg area: remove our autoexec hook + bind cfg
  if [[ "${AUTOEXEC_PATCHED:-0}" -eq 1 ]]; then
    sudo -n sed -i '/^exec c2b_connect$/d' "$GAME_DIR/csgo/cfg/autoexec.cfg" 2>/dev/null
    sudo -n chown "$GAME_USER:$GAME_USER" "$GAME_DIR/csgo/cfg/autoexec.cfg" 2>/dev/null
    sudo -n rm -f "$GAME_DIR/csgo/cfg/c2b_connect.cfg" 2>/dev/null
  fi
  echo "$2" > /home/agent/c2b-test/last-result.txt
  date -Iseconds >> /home/agent/c2b-test/last-result.txt
  # safety: user came back while the test was running -> never suspend under them
  pgrep -x cs2 >/dev/null 2>&1 && DO_SLEEP=0
  if [[ $DO_SLEEP -eq 1 ]]; then
    if (( ARM_HOURS > 0 )); then
      WAKE_EPOCH=$(( $(date +%s) + ARM_HOURS * 3600 ))
      sudo -n sh -c "echo 0 > /sys/class/rtc/rtc0/wakealarm; echo $WAKE_EPOCH > /sys/class/rtc/rtc0/wakealarm"
      log "RTC wake alarm armed for $(date -d "@$WAKE_EPOCH" '+%F %T')"
    fi
    log "suspending system in 10s"
    sleep 10
    sudo -n systemctl suspend -i 2>/dev/null || sudo -n systemctl suspend 2>/dev/null
  else
    log "suspension skipped (user CS2 running or --no-sleep)"
  fi
  exit "$1"
}
trap 'finish 2 "ABORTED (script interrupted)"' INT TERM

# ---------- 0. preconditions ----------
# Only conflict we cannot shim: another CS:GO (our own headless instance)
if pgrep -x csgo_linux64 >/dev/null 2>&1; then
  DO_SLEEP=0
  finish 4 "BUSY: another csgo_linux64 instance already running"
fi
# NOTE: CS2 (or any other Source game) holding /tmp/source_engine_*.lock is FINE -
# we shadow the lock inside a private mount namespace below; host /tmp untouched.
if pgrep -x cs2 >/dev/null 2>&1; then
  DO_SLEEP=0
  log "CS2 is live: engine-lock isolation active, suspension disabled"
fi

# NOTE: steam itself is started in section 2b, AFTER Xvfb (a fresh-boot steam
# needs a live display; starting it before Xvfb made it die silently).

# ---------- 1. deploy fresh bridge binaries + libs (game-user readable!) ----------
# IMPORTANT: the game runs as GAME_USER, which CANNOT traverse /home/agent
# (mode 700). Everything the engine loads at runtime MUST live under $BIN_DST.
mkdir -p "$BIN_DST"
chmod 1777 "$BIN_DST" 2>/dev/null || sudo -n chmod 1777 "$BIN_DST"   # game user writes its c2b logs here
rm -f "$BIN_DST"/*.log   # stale logs from previous runs would confuse analysis
cp -f "$BIN_SRC"/*.so "$BIN_DST/" || finish 3 "FAIL: cannot copy bridge binaries"
log "bridge binaries deployed to $BIN_DST"

# runtime libs (libpng12 for pangoft2/VGUI text: without it the engine dies with
# a deliberate FatalError; libicu for older ld.so paths) -> staged world-readable
mkdir -p "$BIN_DST/libs"
chmod 755 "$BIN_DST/libs" 2>/dev/null || sudo -n chmod 755 "$BIN_DST/libs"
cp -f "$BIN_SRC"/lib12/* "$BIN_DST/libs/" 2>/dev/null
cp -f "$BIN_SRC"/lib/*   "$BIN_DST/libs/" 2>/dev/null
chmod 644 "$BIN_DST"/libs/* 2>/dev/null || sudo -n chmod 644 "$BIN_DST"/libs/*
if [[ -e "$BIN_DST/libs/libpng12.so.0" ]]; then
  log "libs staged to $BIN_DST/libs (project lib12/libpng12 present)"
else
  if sudo -n cp -f "$PNG12_SRC" "$BIN_DST/libs/" 2>/dev/null; then
    sudo -n chmod 644 "$BIN_DST/libs"/libpng12*
    log "staged libpng12 from SteamLinuxRuntime (project lib12 missing)"
  else
    log "WARNING: no libpng12 anywhere (menu will crash)"
  fi
fi

# ---------- 2. Xvfb (persistent across runs: steam lives on this display) ----------
XVFB_STARTED_BY_US=0
if pgrep -f "Xvfb :99" >/dev/null 2>&1; then
  log "Xvfb :99 already running (reusing)"
else
  pkill -f "Xvfb :99" 2>/dev/null; sleep 1
  sudo -n -u "$GAME_USER" Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >/tmp/c2b-xvfb.log 2>&1 &
  XVFB_PID=$!
  XVFB_STARTED_BY_US=1
  sleep 2
  kill -0 "$XVFB_PID" 2>/dev/null || finish 3 "FAIL: Xvfb did not start"
  log "Xvfb :99 up (pid $XVFB_PID)"
fi

# ---------- 2b. keymap repair (MUST happen before the game initializes SDL) ----------
# Xvfb's xkbcomp can fail on some keysyms ("Could not resolve keysym ..."), leaving
# an incomplete keymap: SDL then can't map F12/KP_END keycodes -> xdotool presses
# reach the engine as UNKNOWN keys and binds never fire. Reloading the full evdev
# map right after Xvfb start fixes the scancode table SDL will snapshot.
sudo -n -u "$GAME_USER" env DISPLAY=:99 setxkbmap -model pc105 -layout us 2>/dev/null \
  || sudo -n -u "$GAME_USER" env DISPLAY=:99 setxkbmap us 2>/dev/null \
  || log "WARNING: setxkbmap unavailable (keymap may be incomplete)"

# ---------- 2c. steam client for auth (must run AFTER Xvfb is up) ----------
if ! pgrep -u "$GAME_USER" -f "ubuntu12_32/steam" >/dev/null 2>&1; then
  # no real client running (steam.sh alone = bootstrap, unreliable):
  # a stale steam.pipe from a previous session fakes readiness -> remove it;
  # steam recreates it when the client is actually accepting IPC
  rm -f "$GAME_HOME/.steam/steam.pipe" 2>/dev/null
  sudo -n rm -f "$GAME_HOME/.steam/steam.pipe" 2>/dev/null
  log "steam client not running - starting steam (headless silent) for auth"
  STEAM_T0=$(date +%s)
  sudo -n -u "$GAME_USER" env DISPLAY=:99 HOME="$GAME_HOME" \
    sh -c "nohup $GAME_HOME/.local/share/Steam/steam.sh -silent >/tmp/c2b-steam-start.log 2>&1 &"
  sleep 3
  steam_wait || true   # fresh boots: first launch can take a couple of minutes
  steam_hide_windows
else
  log "steam client already running (warm)"
fi

# ---------- 3. engine-lock shim (private mount namespace) ----------
# strace traces dir: must be game-user writable; copies land in RUNDIR each run
STRACE_DIR=/tmp/c2b-strace   # must be game-user writable (traces are copied into RUNDIR each run)
LOCKFILE=$(ls /tmp/source_engine_*.lock 2>/dev/null | head -1)
[[ -z "$LOCKFILE" ]] && LOCKFILE=/tmp/source_engine_2849099857.lock
mkdir -p /tmp/c2b-locks
chmod 777 /tmp/c2b-locks 2>/dev/null   # after a reboot this dir is fresh: the game user must be able to use it too
SHIM=/tmp/c2b-locks/engine.lock
# create the shim as the CURRENT user (its own dir); never depend on cross-user dir writes
[[ -f "$SHIM" ]] || { : > "$SHIM" 2>/dev/null || sudo -n -u "$GAME_USER" sh -c ": > '$SHIM'" 2>/dev/null || touch "$SHIM"; }
[[ -f "$SHIM" ]] || finish 3 "FAIL: cannot create engine lock shim $SHIM"
# the ENGINE checks the lock file's ownership: it must belong to the game user
sudo -n chown "$GAME_USER:$GAME_USER" "$SHIM" 2>/dev/null || chown "$GAME_USER:$GAME_USER" "$SHIM" 2>/dev/null
chmod 666 "$SHIM" 2>/dev/null || sudo -n chmod 666 "$SHIM"
[[ -f "$LOCKFILE" ]] || { touch "$LOCKFILE" 2>/dev/null || sudo -n -u "$GAME_USER" touch "$LOCKFILE" 2>/dev/null || sudo -n touch "$LOCKFILE"; }
chmod 666 "$LOCKFILE" 2>/dev/null || sudo -n chmod 666 "$LOCKFILE"
sudo -n rm -f "$CONLOG"   # game appends; start clean so markers are fresh
log "engine lock shim: $SHIM -> $LOCKFILE (bind-mount inside private mount ns only)"
if [[ $STRACE -eq 1 ]]; then
  mkdir -p "$STRACE_DIR"
  chmod 777 "$STRACE_DIR" 2>/dev/null
  sudo -n chown "$GAME_USER:$GAME_USER" "$STRACE_DIR" 2>/dev/null || true
  [[ -w "$STRACE_DIR" ]] || chmod 777 "$STRACE_DIR"
  rm -f "$STRACE_DIR"/strace.a*.log
  log "strace enabled -> $STRACE_DIR"
fi

# ---------- 4. bridge selection ----------
BRIDGE_SO="$BIN_DST/c2bridge64.so"
# prefer the "stable" symlink if present (e.g. -> c2bridge64.t42v7h.so);
# the plain c2bridge64.so build currently crashes when it arms its GC hook
[[ -f "$BIN_SRC/c2bridge64.stable.so" ]] && BRIDGE_SO="$BIN_DST/c2bridge64.stable.so"
[[ -n "$VARIANT" ]] && BRIDGE_SO="$BIN_DST/c2bridge64.$VARIANT.so"
[[ $NO_BRIDGE -eq 1 ]] && BRIDGE_SO=""
log "bridge: ${BRIDGE_SO:-none (spy only)}"

if [[ -n "$TARGET" ]]; then
  if [[ $OLD_CONNECT -eq 1 ]]; then
    CONNECT_ARG="+connect $TARGET"
    log "test mode: connect to $TARGET (direct +connect)"
  else
    # CS:GO legacy has NO `wait` in console cfgs and silently defers an early
    # `connect` ("Deferring connect command!" at startup, never completed).
    # Solution: register KEY BINDS early (binds are passive -> nothing to
    # defer), hooked BOTH from autoexec.cfg (engine reads it natively) and
    # `+exec`; each bind echoes a marker so the harness can SEE whether the
    # cfg loaded and whether the synthetic key actually reached the engine.
    CONNECT_CFG="$GAME_DIR/csgo/cfg/c2b_connect.cfg"
    sudo -n tee "$CONNECT_CFG" >/dev/null <<EOF
echo C2B_CONNECT_CFG_EXECUTED
bind "F12" "echo C2B_F12_FIRED; connect $TARGET"
bind "KP_END" "echo C2B_KP_END_FIRED; connect $TARGET"
bind "F11" "echo C2B_F11_FIRED; connect $TARGET"
EOF
    sudo -n chmod 644 "$CONNECT_CFG" 2>/dev/null
    AUTOEXEC_CFG="$GAME_DIR/csgo/cfg/autoexec.cfg"
    if [[ -f "$AUTOEXEC_CFG" ]]; then
      sudo -n grep -aq 'exec c2b_connect' "$AUTOEXEC_CFG" 2>/dev/null || \
        echo 'exec c2b_connect' | sudo -n tee -a "$AUTOEXEC_CFG" >/dev/null
    else
      echo 'exec c2b_connect' | sudo -n tee "$AUTOEXEC_CFG" >/dev/null
    fi
    sudo -n chown "$GAME_USER:$GAME_USER" "$AUTOEXEC_CFG" 2>/dev/null
    AUTOEXEC_PATCHED=1
    CONNECT_ARG="+exec c2b_connect"
    log "test mode: connect to $TARGET (binds F12/F11/KP_END via autoexec+exec, xdotool retry)"
  fi
else
  CONNECT_ARG=""
  log "test mode: menu-only smoke"
fi

# ---------- 5. launch + verdict loop (with retry) ----------
VERDICT_CODE=1
VERDICT_TEXT="FAIL: no verdict"
for (( ATTEMPT=1; ATTEMPT<=MAX_ATTEMPTS; ATTEMPT++ )); do
  # ---- user-game protection: never fight the player's own CS2 ----
  DEFER_WAIT="${C2B_DEFER_WAIT:-1800}"
  if pgrep -x cs2 >/dev/null 2>&1; then
    log "user CS2 is live — deferring attempt $ATTEMPT (up to ${DEFER_WAIT}s)"
    W0=$SECONDS
    while pgrep -x cs2 >/dev/null 2>&1 && (( SECONDS - W0 < DEFER_WAIT )); do
      sleep 20
    done
    if pgrep -x cs2 >/dev/null 2>&1; then
      finish 5 "DEFERRED: user CS2 running (waited ${DEFER_WAIT}s) — rerun later"
    fi
    log "CS2 exited — proceeding with attempt $ATTEMPT"
  fi
  if (( ATTEMPT > 1 )); then
    log "attempt $ATTEMPT/$MAX_ATTEMPTS: relaunching after early death"
    sudo -n pkill -9 -x csgo_linux64 2>/dev/null
    sleep 2
    sudo -n rm -f "$CONLOG"
    steam_wait || true   # steam may have finished booting meanwhile
    steam_hide_windows
  fi
  OUT="$RUNDIR/csgo_stdout.a${ATTEMPT}.log"
  RUNSTR="${C2B_RUNSTR:-}"
  [[ $STRACE -eq 1 ]] && RUNSTR="strace -f -qq -yy -e trace=openat,read,readv,pread64,preadv,lseek,_llseek,close -o '$STRACE_DIR/strace.a${ATTEMPT}.log'"

  sudo -n unshare -m --propagation private sh -c "
    mount --make-rprivate / 2>/dev/null
    mount --bind '$SHIM' '$LOCKFILE' || exit 3
    exec sudo -n -u "$GAME_USER" env HOME="$GAME_HOME" USER="$GAME_USER" \
      DISPLAY=:99 \
      C2B_UPLINK=1 C2B_DOWNLINK=1 \
      LD_LIBRARY_PATH=\"$BIN_DST/libs:$GAME_DIR/bin/linux64:$GAME_DIR/bin/x64:$GAME_DIR/bin\" \
      SDL_AUDIODRIVER=dummy \
      SDL_VIDEO_X11_VISUALID= \
      LD_PRELOAD=\"$BIN_DST/c2b_spy64.so $BRIDGE_SO\" \
      sh -c \"cd '$GAME_DIR' && exec nice -n 19 ionice -c 3 $RUNSTR ./csgo_linux64 -novid -nojoy -nosteamcontroller -nobreakpad -insecure -nosound -windowed -w 1280 -h 720 -condebug $CONNECT_ARG\"" \
    >"$OUT" 2>&1 &
  GAME_PID=$!
  log "attempt $ATTEMPT: client launched in private mount ns (pid $GAME_PID), waiting up to ${DURATION}s"

  sleep 5  # let unshare->sudo->sh->exec chain materialize the game process
  CONNECTED=0; MENU=0; NEW_SNAP=0; DEAD_STREAK=0; DIED_EARLY=0; CONNECT_FIRED=0
  CFG_LOADED=0; PRESS_COOLDOWN=$((SECONDS + 4)); STEAM_URL_FIRED=0
  END=$((SECONDS + DURATION))
  while (( SECONDS < END )); do
    if pgrep -x csgo_linux64 >/dev/null 2>&1; then
      DEAD_STREAK=0
    else
      DEAD_STREAK=$((DEAD_STREAK + 1))
      log "attempt $ATTEMPT: client not visible (streak $DEAD_STREAK)"
      if (( DEAD_STREAK >= 2 )); then log "attempt $ATTEMPT: client process exited early"; DIED_EARLY=1; break; fi
    fi
    if grep -aqiE 'Connected to|Signing up to server|Server responded' "$OUT" 2>/dev/null || sudo -n grep -aqiE 'Connected to|Signing up to server|Server responded' "$CONLOG" 2>/dev/null; then
      CONNECTED=1
      log "attempt $ATTEMPT: connection marker found"
    fi
    if (( ! CFG_LOADED )) && { grep -aq 'C2B_CONNECT_CFG_EXECUTED' "$OUT" 2>/dev/null || sudo -n grep -aq 'C2B_CONNECT_CFG_EXECUTED' "$CONLOG" 2>/dev/null; }; then
      CFG_LOADED=1
      log "attempt $ATTEMPT: c2b_connect.cfg executed (binds registered)"
    fi
    if (( ! CONNECT_FIRED )) && { grep -aqiE 'C2B_F12_FIRED|C2B_F11_FIRED|C2B_KP_END_FIRED|Connecting to|deferred connect firing' "$OUT" 2>/dev/null || sudo -n grep -aqiE 'C2B_F12_FIRED|C2B_F11_FIRED|C2B_KP_END_FIRED|Connecting to|deferred connect firing' "$CONLOG" 2>/dev/null; }; then
      CONNECT_FIRED=1
      log "attempt $ATTEMPT: connect bind FIRED"
    fi
    # loose match: catches both "INVALID -> MAINMENU" and "MAINMENU -> MAINMENU"
    if grep -aq 'CSGO_GAME_UI_STATE_MAINMENU' "$OUT" "$CONLOG" 2>/dev/null; then
      MENU=1
    fi
    # ---- PRIMARY connect trigger: steam://connect (engine-level IPC) ----
    # Proven 2026-10-01: steam forwards the URL to the RUNNING client and the
    # engine fires `connect <target>` — no keybinds, no modal dismissal needed.
    # Fired ONCE per attempt, ~8s after the menu state first appears.
    if (( MENU && ! STEAM_URL_FIRED && SECONDS >= PRESS_COOLDOWN + 8 )); then
      STEAM_URL_FIRED=1
      STEAM_URL_BIN="$GAME_HOME/.local/share/Steam/ubuntu12_32/steam"
      [[ -x "$STEAM_URL_BIN" ]] || STEAM_URL_BIN="$GAME_HOME/.local/share/Steam/steam.sh"
      log "attempt $ATTEMPT: firing steam://connect/$TARGET (primary trigger)"
      sudo -n -u "$GAME_USER" env DISPLAY=:99 HOME="$GAME_HOME" \
        "$STEAM_URL_BIN" "steam://connect/$TARGET" \
        >"$RUNDIR/steam-connect.a${ATTEMPT}.log" 2>&1 &
    fi
    # menu state seen -> press the connect binds via xdotool, retrying every
    # 12s until a bind marker proves the key actually reached the engine
    if (( MENU && ! CONNECT_FIRED && SECONDS >= PRESS_COOLDOWN )); then
      XD="sudo -n -u "$GAME_USER" env DISPLAY=:99 xdotool"
      WID=$($XD search --onlyvisible --class csgo 2>/dev/null | tail -1)
      [[ -z "$WID" ]] && WID=$($XD search --onlyvisible --classname csgo 2>/dev/null | tail -1)
      [[ -z "$WID" ]] && WID=$($XD search --onlyvisible --name 'Counter-Strike' 2>/dev/null | tail -1)
      [[ -z "$WID" ]] && WID=$($XD search --onlyvisible --name '.' 2>/dev/null | tail -1)
      if [[ -n "$WID" ]]; then
        $XD windowactivate "$WID" 2>/dev/null
        $XD windowfocus "$WID" 2>/dev/null
        sleep 1
        # ---- modal gauntlet dismissal ----
        # The legacy client opens a CHAIN of blocking dialogs at the menu:
        #   1) "Старая версия CS:GO"  (ПРОДОЛЖИТЬ at ~(610,479))
        #   2) "Античит Valve"        (OK at ~(834,498))
        #   3) "Старая версия CS:GO"  (OK at ~(834,506))
        # While ANY modal is up it eats ALL keyboard input (binds never fire!).
        # Fixed 1280x800 layout -> fixed button positions. Blind clicks with no
        # modal up land in the news panel (harmless); ESC below closes it.
        $XD mousemove 610 479 2>/dev/null; sleep 0.35; $XD click 1 2>/dev/null; sleep 0.6
        $XD mousemove 834 498 2>/dev/null; sleep 0.35; $XD click 1 2>/dev/null; sleep 0.6
        $XD mousemove 834 506 2>/dev/null; sleep 0.35; $XD click 1 2>/dev/null; sleep 0.6
        # ESC primer: close anything the blind clicks opened (news overlay etc.)
        $XD keydown Escape 2>/dev/null; sleep 0.15; $XD keyup Escape 2>/dev/null
        sleep 0.5
        # HELD presses (300ms): xdotool's instant tap (12ms down+up) can fall
        # entirely between engine input pumps while the menu is still loading
        # (frames can take 100ms+), so the engine never sees the key.
        $XD keydown F12 2>/dev/null;    sleep 0.3; $XD keyup F12 2>/dev/null
        sleep 0.5
        $XD keydown KP_END 2>/dev/null; sleep 0.3; $XD keyup KP_END 2>/dev/null
        PRESS_COOLDOWN=$((SECONDS + 12))
        WNAME=$($XD getwindowname "$WID" 2>/dev/null)
        log "attempt $ATTEMPT: modal-gauntlet + F12/KP_END (held) on window $WID '${WNAME:0:60}'"
      else
        PRESS_COOLDOWN=$((SECONDS + 12))
        log "attempt $ATTEMPT: no visible window for xdotool yet"
      fi
    fi
    N=$(find /home/agent/c2bridge/live_state -name '*.snap' -newermt "@$(( $(date +%s) - DURATION - 120 - 300 ))" 2>/dev/null | wc -l)
    (( N > 0 )) && { NEW_SNAP=1; log "attempt $ATTEMPT: fresh live_state snapshot produced"; }
    (( CONNECTED || (MENU_ONLY && MENU) )) && break
    sleep 5
  done

  # ---- per-attempt verdict ----
  if (( CONNECTED )); then
    VERDICT_CODE=0; VERDICT_TEXT="PASS: connection markers present (target $TARGET, attempt $ATTEMPT)"
    break
  fi
  if [[ $MENU_ONLY -eq 1 && $MENU -eq 1 ]]; then
    VERDICT_CODE=0; VERDICT_TEXT="PASS: client reached MAIN MENU (smoke, attempt $ATTEMPT)"
    break
  fi
  if [[ $MENU_ONLY -eq 0 && $NEW_SNAP -eq 1 ]]; then
    VERDICT_CODE=0; VERDICT_TEXT="PASS: live_state snapshot produced (target $TARGET, attempt $ATTEMPT)"
    break
  fi
  # failure: retry if the client died early (probabilistic hook race),
  # otherwise a full-duration run found nothing -> retry once too (cold boots
  # can be slow; warm retries reach the menu in ~10s), but only up to MAX
  if (( ATTEMPT < MAX_ATTEMPTS )); then
    log "attempt $ATTEMPT failed (died_early=$DIED_EARLY) -> will retry"
  fi
done

# ---------- 5a. failure detail ----------
if [[ $VERDICT_CODE -ne 0 ]]; then
  VERDICT_TEXT="FAIL: menu=$MENU cfg=$CFG_LOADED fired=$CONNECT_FIRED target=${TARGET:-none} (logs: $RUNDIR)"
fi

# ---------- 5b. lite manifest (basis for the minimal client pack) ----------
if [[ $STRACE -eq 1 ]]; then
  log "building lite-manifest from strace logs"
  cp -f "$STRACE_DIR"/strace.a*.log "$RUNDIR/" 2>/dev/null
  {
    echo "# unique files opened by the client (abs or rel to $GAME_DIR)"
    cat "$STRACE_DIR"/strace.a*.log 2>/dev/null \
      | grep -aoP 'openat\([^,]+, "\K[^"]+' \
      | grep -vE '^(/proc|/sys|/dev|/tmp|/run|/home|/usr|/lib|/lib64|/etc|/var|/snap)' \
      | sort -u
  } > "$RUNDIR/lite-manifest.txt"
  TOT=$(python3 - "$GAME_DIR" "$RUNDIR/lite-manifest.txt" <<'PYEOF'
import os, sys
game, man = sys.argv[1], sys.argv[2]
tot = 0
for line in open(man, errors="replace"):
    p = line.strip()
    if not p or p.startswith("#"):
        continue
    if not os.path.isabs(p):
        p = os.path.join(game, p)
    try:
        tot += os.path.getsize(p)
    except OSError:
        pass
print(tot)
PYEOF
)
  log "lite-manifest: $(grep -vc '^#' "$RUNDIR/lite-manifest.txt") files, ~$((TOT / 1024 / 1024)) MiB unique content"
fi

# ---------- 6. final verdict ----------
finish "$VERDICT_CODE" "$VERDICT_TEXT"
