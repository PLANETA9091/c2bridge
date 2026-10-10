# g55 notes — the grace/approval map (RE of engine_client.so__2cd041, run204/205 era)

## State the milestone reached (run204 = GH run 38075436141, d6d11dc)
- THE POST-'k' BARRIER IS BROKEN. The fmt-9 'A' payload (g53/g54 bytes) parses
  end-to-end: the win-tail Msg "Server using '' lobbies, requiring pw no, lobby
  id 0" fires (console.aN.log — NOT csgo_stdout), the pw-empty + b2=1 +
  pw-cvar-empty gate passes -> 25d766: state+0x4b9=1 (THE TRUE CONNECT) +
  332e80() + the vt+0x160 notifier.
- The engine then runs ITS OWN outbound connect to the REAL target
  152.233.19.133:28022 (target.conf "community" = CYBERSHOKE 5x5, live-checked
  A2S: players=0/64 — the server is EMPTY, fullness is NOT the blocker):
  - pcap.a1: 27005<->28022 h20/h21 session keepalives flow (366 out / 365 in,
    26B h21 echo, fresh challenge per keepalive `11 <u32>` — the engine USES
    the latest challenge in its 'k' — the challenge dance WORKS).
  - OUT 'k' x10 (20 captures / 2-way dup): `ff ff ff ff 'k' proto=3 auth=3
    chal u32 u16(0) + protobuf ticket with the REAL owner SteamID3
    [U:1:687168219]` — the engine's OWN GetAuthSessionTicket works (real
    steamclient, real login).
  - The server NEVER replies with an accept: ALL 365 replies are 26B h21
    keepalives; no 'B' (S2C_CONNECTION), no h23-with-cid, no rejection msg.
    Engine loops "Server did not approve grace request, retrying..." x30 ->
    "Connection failed after 30 retries" -> exit ("client died during connect"
    in the harness = the engine exiting after the 30 retries, NOT a crash:
    no SIGSEGV/SIGABRT anywhere; a2/a3/a4 backtraces = idle render-thread
    samples from the gdb variant).

## THE DECODED DECISION MAP (the 'B'/connect parser tail, 25d6b6..25d93b)
Fields (all set by the LAST injected/real payload parse):
- 0x4c0 = the connect-flag (set ONLY at 25cf46 after strstr("connect") finds
  our "connect0x..." string).
- 0x4c2 = b2; 0x4c5 = the pw-string copy (15B); 0x4d8 = chal; 0x4dc = proto;
- 0x4e0 = the 64-bit auth value (the g53-analyzed 645be0 read of payload
  bytes 10..17; OURS = 0x00ee0a07 — a 32-bit fake);
- 0x4e8 = the LOBBY ID u64 (the SECOND 645be0 read, writer 25d2fd; the
  "lobby id %u" in the lobbies Msg = rcx @25d6db). THE APPROVAL FLAG.
- 0x4b9 = connected (the win @25d766).

Win-tail (25d712, after the lobbies Msg):
  pw(0x4c5)!=0 -> 25d866 (the reservation-error path);
  pw==0 && 0x4e8!=0 -> 25d7b5 (the modifier chain — NO 0x4b9 win);
  pw==0 && 0x4e8==0 && b2!=0 && pw-cvar empty -> 25d766 WIN (0x4b9=1) ->
  332e80() + vt+0x160 -> RETURN (259f50). NOTE: the win path itself does NOT
  call the sender 24b520.

Modifier chain (25d7b5, reached on pw!=0 or 0x4e8!=0):
  strstr("connect-retry"/"connect-matchmaking-only"/"connect-lan-only"/
  "connect-granted" @0x9379c6/9379d4/9377c7/9377d8) — NONE matches
  "connect0x..." -> 25d8ed: pw==0 -> je 25d8e0 -> call 24b520.
  pw!=0 && count(f75fe0+8)<=1 && 0x4e8==0 -> 25d90e Msg "Server did not
  approve grace request, retrying..." -> 25d824: vt+0x1b0(1) = the retry.
  pw!=0 && count<=1 && 0x4e8!=0 -> 25d921 -> 25d8e0 -> call 24b520
  (the "Server approved grace request..." Msg @25d92b prints only on the
  connect-granted-FOUND variant).

24b520 = CClientState::SendConnectPacket (the ONLY callers: 24bc1c = the
in-function retry, 25d8e3 = the tail above):
  0x4c0==0 -> RETURN (nothing). One-shot: 0x4c0 cleared.
  pw!=0 -> 24b56b: vt+0x198(state, &0x4f0-snap, proto 0x4dc, chal 0x4d8,
          authbyte 0x4c1, value 0x4e0) — THE UNCONDITIONAL 'k' SEND.
  pw==0 -> 24b5c0: 0x4e8==0 -> 24b56b (THE SAME unconditional send — the
          lobby==0 path has NO 0x4e0 checks! The current retry 'k's ride
          this path);
          0x4e8!=0 -> 24b5ca: count<=1 -> 24b5d9: vt+0x218() check -> else
          4b87a0()/0x2d0/4120ca0-vt+0x160 fallbacks -> 24b675: 0x4e0 checks:
          bits 52-55 == 0 -> 24b830; bits 48-51 nibble must make
          ((x>>48)&0xf0 - 0x30) & 0xe0 == 0, i.e. (0x4e0>>48) in [0x30,0x3f]
          (a gameserver-class SteamID64 top) — else 24b859: vt+0x190(1) +
          ConMsg "You cannot connect to this CS:GO server" = REJECT.

## WHY THE REAL SERVER NEVER APPROVES
The real flow: our 'k' -> the REAL server validates the Steam auth session
server-side -> sends 'B' S2C_CONNECTION with the reservation/lobby fields ->
the parse sets 0x4e8 -> "approved" -> the signon. CYBERSHOKE keeps the session
alive (h21) but never sends 'B' -> 0x4e8 stays 0 -> the loop. The bridge-side
parses/bytes are all PROVEN correct; the missing byte is the server's 'B'.

## g55 OPTIONS (the next round picks ONE)
(a) SYNTHETIC 'B' ACCEPT (preferred): the bridge injects a "ffffffff B"
    payload shaped per the FULLY DECODED 'B' handler (0x25a8b0 — the same
    parser! netadr-echo checks hdr[0x1c]/snap[0x50c] etc., cstate==1, chal,
    proto==3, the "connect0x..." string, pw='', b2=1, lobby u64 NONZERO) ->
    0x4e8!=0 -> the tail takes 25d7b5 -> 24b520 -> the 0x4e8!=0 send path —
    REQUIRES the 0x4e0 SteamID-encoding fix in the same payload: set the
    64-bit value bytes 10..17 so (v>>48) in [0x30,0x3f] (e.g. v = 0x0030_0000
    <chal-ish>) — else "You cannot connect" reject. The 'A' fmt-9 keeps the
    lobby=0 win (0x4b9=1); the 'B' adds the approval.
    RISK: the 'B' netadr/hdr-echo checks (the hdr[0x1c]==snap[0x50c] in 1..3
    OR ==0 window) — the injected packet must pass them; the g16 recv-channel
    already delivers engine-facing packets (the 'B' baits phase-6 exist!).
(b) lobby=1 in the fmt-9 'A' ALONE: flips "did not approve" -> the silent
    24b520, BUT the send takes the 0x4e8!=0 path with OUR fake 0x4e0
    (0x00ee0a07: bits 52-55 = 0) -> 24b830 -> 0x4e0!=0 -> 24b695 ->
    ((0>>48&0xf0)-0x30)&0xe0 = 0xc0 != 0 -> THE REJECT. The 'k' flow STOPS.
    VIABLE ONLY TOGETHER WITH the 0x4e0 fix: value u64 = (0x30ULL<<48) | low.
    This changes the fmt-9 bytes 10..17 (the value+flag+MYSTERY trio) — the
    g53 split-flag byte (MYSTERY[3]=0) is byte 18 — UNTOUCHED; the value read
    = bytes 10..17 via 645be0 (the u64) — set 0x0030000000000000 + keep the
    low-32 0x00ee0a07? -> v>>48 = 0x30 exactly -> the bit checks PASS ->
    24b6a7 = the ticket building with the SteamID — the engine would then
    GetAuthSessionTicket(0x3000_0000_0000_0000|low) — a GARBAGE target SteamID
    — the ticket may fail to generate (kcap=0 risk) — acceptable to TEST.
(c) leave the loop as-is; the verdict stays honest ("no connection") and the
    next round targets the SERVER-side 'B' via the phase-6 'B'-bait plumbing
    (the existing bait injector already knows how to deliver 'B'-shaped
    engine-facing packets).

## Observable greps for the next forensics (console.aN.log — NOT stdout!)
- "Server approved grace request" (0x938a58 @25d92b) = THE APPROVAL PATH HIT.
- "You cannot connect to this CS:GO server" (0x938278 @24b86a) = the 0x4e0
  reject (option (b) without the value fix).
- "Server error - failed to handle reservation" (0x9389b8 @25d893) = the
  pw!=0 reservation path.
- "Retrying public" count == 0 with the lobbies Msg present = the loop broke.
- menu=/LOADINGSCREEN + pcap h23 (28022->any, `23 0d <cid>`) = the signon
  traffic STARTED (c2bridge.c:12194 precedent: the h23 cid packets ~0.3s).
