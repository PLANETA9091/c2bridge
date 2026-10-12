/* c2b_client_hook.c — g110: THE CLIENT-SIDE SDR-CRYPTO HOOK (LD_PRELOAD
 * into the steam client chain, NOT the game).
 *
 * WHY (the worklog g109b verdict, run308/309): the game's SDR datagrams =
 * ALL to the loopback relay 127.0.0.1:57343 (0xdfff), ZERO direct :28022
 * sends => the real SDR endpoint (the crypto + the socket) = the :57343
 * receiver = THE STEAM CLIENT (the 32-bit ubuntu12_32/steam core; the
 * engine = imports-only, cb0ca8 = the hooked-zero, sdk64 = never mapped
 * in the pipe-mode runs). The client's SNS = statically linked into its
 * steamclient.so => the game-side preload can NOT see it; THIS .so =
 * preloaded into the CLIENT (the harness = the client's starter).
 *
 * WHAT: one patch site = ChaCha20_ctr32 (the chokepoint: every path —
 * the EVP do_cipher chain AND the direct CCrypto calls — converges into
 * it; the g104 verdict = the EVP-init hook = zero calls = the EVP = NOT
 * the entry, the ctr32 = the funnel). The capture = the (key, ictx)
 * pairs deduped by the key + the call profile. The session keys = the
 * g100-decryptor input (the 0x83-decrypt pipeline = complete except the
 * key extraction — THIS = the extraction).
 *
 * SITES (the offline RE = the run264 bins, the local prologue scan
 * scripts/g110_prologue_scan.py, the PT_LOAD-corrected vaddrs):
 *   -m32 steamclient.so__00a027 (the client's core lib):
 *        ctr32 @0x2404b80, pro16 = 55 53 56 57 31 c0 3b 44 24 1c 0f 84 ba 04 00 00
 *        (push ebp/ebx/esi/edi; xor eax,eax; cmp eax,[esp+0x1c]; je rel32
 *        = the 5-stack-args (out,in,len,key,ictx) cdecl signature: the
 *        key = [esp+0x10], the ictx = [esp+0x14] AT THE ENTRY)
 *        version check: sigma 'expand 32-byte k' @0x2405a60
 *   -m64 steamclient.so__d975c5 (steam/linux64 — the insurance variant):
 *        ssse3-chain site @0x206bc74, pro16 = 41 54 41 55 41 56 41 57 48 83 ec 58 f3 0f 6f 09
 *        + the marker f3 0f 6f 51 10 @+0x10 (the g105-exact pattern)
 *        (rdi=out rsi=in rdx=len RCX=KEY R8=ICTX, r9 = the ra slot)
 *        version check: sigma @0x206bbc0
 * The base = the LOWEST mapped start among the 'steamclient.so' maps
 * lines (the runtime patch = base + the vaddr).
 *
 * SAFETY: the watcher thread = polls the maps (500ms, 10 min cap); the
 * patch = only on the EXACT pro16+sigma match (the version drift = the
 * skip + the log); the capture = the bounded reads, no malloc, the raw
 * write(2) + the /tmp append; the caps = 24 keys / 32 call-lines. The
 * wrong-arch .so in LD_PRELOAD = the loader skips it (the warning only).
 * Killswitch: C2B_G110=0. Log: stderr + /tmp/c2b_client_keys.log.
 *
 * Build (the workflow, BOTH):
 *   gcc -m32 -O2 -shared -fPIC -o c2b_client_hook.so   src/c2b_client_hook.c -lpthread
 *   gcc -m64 -O2 -shared -fPIC -o c2b_client_hook64.so src/c2b_client_hook.c -lpthread */

#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef uint64_t u64;
typedef int64_t  i64;
typedef uintptr_t uptr;
/* the ABI-sized types: ssize_t/size_t = 4B on the i386, 8B on the x86-64 */
#if defined(__x86_64__)
typedef i64 ssz_t;
typedef u64 sz_t;
#else
typedef i32 ssz_t;
typedef u32 sz_t;
#endif

/* the raw libc decls (the g105 style: no stdio in the hot path; the
 * read/write/close = NOT visible without unistd.h = the raw externs =
 * the glibc-compatible ABI-exact signatures) */
extern i32   open(const char *, i32, ...);
extern i32   close(i32);
extern ssz_t read(i32, void *, sz_t);
extern ssz_t write(i32, const void *, sz_t);
extern void *getenv(const char *);
extern i32   getpid(void);
extern int   memcmp(const void *, const void *, sz_t);
extern i32   mprotect(void *, sz_t, i32);
/* g113: pread64 = the explicit 64-bit-offset symbol (the i386 `pread`
 * symbol = the 32-bit off_t variant = the 2GB cap = BELOW the 3GB VA
 * split of the 32-bit core; pread64 = exported by the glibc on both
 * the arches) */
extern ssz_t pread64(i32, void *, sz_t, int64_t);

#define O_RDONLY   0
#define O_WRONLY   1
#define O_CREAT    0100
#define O_APPEND   02000
#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4

/* the arch-specific site table */
#if defined(__x86_64__)
#define ARCH_TAG   "64"
#define SITE_OFF   0x206bc74u
#define SIGMA_OFF  0x206bbc0u
#define MARKER_ON  1
static const u8 PRO16[16] = {
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x83, 0xec, 0x58, 0xf3, 0x0f, 0x6f, 0x09
};
static const u8 MARKER[5] = { 0xf3, 0x0f, 0x6f, 0x51, 0x10 };
#else   /* the i386 */
#define ARCH_TAG   "32"
#define SITE_OFF   0x2404b80u
#define SIGMA_OFF  0x2405a60u
#define MARKER_ON  0
static const u8 PRO16[16] = {
    0x55, 0x53, 0x56, 0x57, 0x31, 0xc0, 0x3b, 0x44,
    0x24, 0x1c, 0x0f, 0x84, 0xba, 0x04, 0x00, 0x00
};
static const u8 MARKER[5] = { 0 };
#endif

static const u8 SIGMA[16] = {
    'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
    '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
};

/* the g113 forward decl (the thread = spawned from the watch fn below) */
static void *c2b_g113_thread(void *arg);

#define KEYS_PATH "/tmp/c2b_client_keys.log"
#define KEY_CAP   24
#define CALL_CAP  32

static u8   g_tramp[64] __attribute__((aligned(4096)));
static u8   g_key0[32];
static u32  g_keys;      /* the distinct keys logged */
static u32  g_calls;     /* the total calls seen */
static u32  g_calllog;   /* the call-profile lines logged */
static i32  g_patched;
static i32  g_keysfd = -1;

/* the log helper: the raw writes to the stderr + the /tmp append (the
 * O_APPEND write = atomic-enough for the <512B lines) */
static void klog(const char *s, u32 n)
{
    write(2, s, n);
    if (g_keysfd < 0)
        g_keysfd = open(KEYS_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_keysfd >= 0)
        write(g_keysfd, s, n);
}

static void klog_s(const char *s) { u32 n = 0; while (s[n]) n++; klog(s, n); }

static void klog_h(u32 v)
{
    static const char hx[] = "0123456789abcdef";
    char b[8];
    i32 i;
    for (i = 0; i < 8; i++) b[i] = hx[(v >> (28 - 4 * i)) & 0xF];
    klog(b, 8);
}

static void klog_x(const u8 *p, u32 n)
{
    static const char hx[] = "0123456789abcdef";
    char b[128];
    u32 i;
    if (n > 64) n = 64;
    for (i = 0; i < n; i++) {
        b[2 * i]     = hx[p[i] >> 4];
        b[2 * i + 1] = hx[p[i] & 0xF];
    }
    klog(b, 2 * n);
}

/* the shared capture: the dedup by the key, the caps, the log line =
 * [c2b] g110: KEYn len=N key=<64hex> ictx=<32hex> */
static void c2b_g110_capture(u64 len, const void *key, const void *ictx)
{
    u32 n = __atomic_add_fetch(&g_calls, 1, __ATOMIC_RELAXED);
    u32 z;

    if (g_calllog < CALL_CAP) {
        u32 idx = __atomic_add_fetch(&g_calllog, 1, __ATOMIC_RELAXED);
        klog_s("[c2b] g110: call#");
        klog_h(idx);
        klog_s(" len=");
        klog_h((u32)len);
        klog_s("\n");
    }
    (void)n;
    if (!key || g_keys >= KEY_CAP) return;
    {
        u32 same = 0;
        u32 first;
        for (z = 0; z < 32; z++)
            same |= (u32)(g_key0[z] ^ ((const u8 *)key)[z]);
        first = __atomic_load_n(&g_keys, __ATOMIC_RELAXED);
        if (!same && first) return;              /* the dedupe */
        /* the new distinct key (or the first ever) */
        {
            u32 idx = __atomic_add_fetch(&g_keys, 1, __ATOMIC_RELAXED);
            klog_s("[c2b] g110: KEY");
            klog_h(idx);
            klog_s(" len=");
            klog_h((u32)len);
            klog_s(" key=");
            klog_x((const u8 *)key, 32);
            klog_s(" ictx=");
            klog_x((const u8 *)ictx, ictx ? 16 : 0);
            klog_s("\n");
            for (z = 0; z < 32; z++) g_key0[z] = ((const u8 *)key)[z];
        }
    }
}

/* ---------------- the capture detours ---------------- */

#if defined(__x86_64__)
/* the g105 style: the asm stub passes the orig retaddr via r9 */
extern void c2b_g110_stub(void);
__asm__(
    ".text\n"
    ".globl c2b_g110_stub\n"
    ".type c2b_g110_stub, @function\n"
    "c2b_g110_stub:\n"
    "  movq (%rsp), %r9\n"
    "  jmp  c2b_g110_detour_c\n"
);
static void c2b_g110_detour_c(const void *out, const void *in, u64 len,
                              const void *key, const void *ictx, void *ra)
    __attribute__((used));
static void c2b_g110_detour_c(const void *out, const void *in, u64 len,
                              const void *key, const void *ictx, void *ra)
{
    void (*tramp)(const void *, const void *, u64, const void *,
                  const void *) = (void (*)(const void *, const void *,
                  u64, const void *, const void *))g_tramp;
    (void)out; (void)in; (void)ra;
    c2b_g110_capture(len, key, ictx);
    if (g_tramp[16] == 0xff)   /* the abs-jump built = the tramp ready */
        tramp(out, in, len, key, ictx);
}

#else   /* the i386: the cdecl detour = the SAME stack layout as ctr32 */
static void c2b_g110_detour_c(const void *out, const void *in, u32 len,
                              const void *key, const void *ictx);
static void c2b_g110_detour_c(const void *out, const void *in, u32 len,
                              const void *key, const void *ictx)
{
    void (*tramp)(const void *, const void *, u32, const void *,
                  const void *) = (void (*)(const void *, const void *,
                  u32, const void *, const void *))g_tramp;
    (void)out; (void)in;
    c2b_g110_capture((u64)len, key, ictx);
    if (g_tramp[16] == 0xe9)   /* the rel-jump built = the tramp ready */
        tramp(out, in, len, key, ictx);
}
#endif

/* ---------------- the watcher / patcher ---------------- */

/* the ABI-sized memcpy (the small fixed-size use only) */
extern void *memcpy(void *, const void *, sz_t);

/* the strict parse of ONE maps line: "7f..-7f.. r--p off dev ino path".
 * Returns 1 + *out_lo = the start addr when the line = a steamclient.so
 * mapping (the substring match in the path part). */
static i32 line_is_steamclient(const char *s, i32 n, uptr *out_lo)
{
    uptr a = 0, b = 0;
    i32 k = 0, c, i, nhex = 0;

    while (k < n && s[k] != '-') {
        c = s[k];
        if (c >= '0' && c <= '9') a = (a << 4) | (uptr)(c - '0');
        else if (c >= 'a' && c <= 'f') a = (a << 4) | (uptr)(c - 'a' + 10);
        else return 0;
        k++; nhex++;
    }
    if (k >= n || s[k] != '-' || nhex < 1) return 0;
    k++;
    while (k < n && s[k] != ' ') {
        c = s[k];
        if (c >= '0' && c <= '9') b = (b << 4) | (uptr)(c - '0');
        else if (c >= 'a' && c <= 'f') b = (b << 4) | (uptr)(c - 'a' + 10);
        else return 0;
        k++;
    }
    if (k >= n || s[k] != ' ' || b <= a) return 0;
    for (i = k; i + 14 <= n; i++) {
        if (s[i] == 's' && s[i + 1] == 't' && s[i + 2] == 'e' &&
            s[i + 3] == 'a' && s[i + 4] == 'm' && s[i + 5] == 'c' &&
            s[i + 6] == 'l' && s[i + 7] == 'i' && s[i + 8] == 'e' &&
            s[i + 9] == 'n' && s[i + 10] == 't' && s[i + 11] == '.' &&
            s[i + 12] == 's' && s[i + 13] == 'o') {
            *out_lo = a;
            return 1;
        }
    }
    return 0;
}

static void *c2b_g110_watch(void *arg)
{
    int  round;
    (void)arg;

    /* g110c (run311 lesson): the STREAM parse — the run311 = the ZERO
     * outcomes (not even the mismatch) = the maps buffer (256KB static)
     * = the TAIL TRUNCATION (the g107d lesson = the SAME bug class) = the
     * steamclient.so = never seen in ANY process (979x64 + 5x32 = all
     * silent). The stream parse = the complete-line assembly = the tail-
     * safe; the buffers = the STACK locals = no per-process .bss (the
     * 979 processes x 256KB static = the memory blowup = the removed).
     * The rounds cap = 240 (2 min): the steam core maps the lib at the
     * boot; the webhelper fork-storm = the bounded pollers. */
    for (round = 0; round < 240 && !g_patched; round++) {
        i32 fdm = open("/proc/self/maps", O_RDONLY);
        char chunk[65536], line[4096];
        i32 llen = 0;
        uptr liblo = 0;
        ssz_t r;

        if (fdm < 0) return (void *)0;
#if !defined(__x86_64__)
        /* the g110d: the one-shot start marker (the watcher = alive?) */
        if (round == 0) {
            klog_s("[c2b] g110: watch start arch=" ARCH_TAG " pid=");
            {
                char pids[11];
                u32 v = (u32)getpid();
                i32 i, started = 0;
                for (i = 9; i >= 0; i--) { pids[i] = (char)('0' + (v % 10)); v /= 10; }
                pids[10] = 0;
                for (i = 0; i < 10; i++) {
                    if (pids[i] != '0' || started || i == 9) {
                        klog(pids + i, 1);
                        started = 1;
                    }
                }
            }
            klog_s("\n");
        }
#endif
        while ((r = read(fdm, chunk, sizeof(chunk))) > 0) {
            sz_t i = 0;
            while (i < (sz_t)r) {
                sz_t j = i, seg;
                while (j < (sz_t)r && chunk[j] != '\n') j++;
                seg = j - i;
                if (llen + (i32)seg > (i32)sizeof(line) - 1)
                    seg = (sz_t)sizeof(line) - 1 - (sz_t)llen;
                if (seg) {
                    memcpy(line + llen, chunk + i, seg);
                    llen += (i32)seg;
                }
                if (j == (sz_t)r) break;      /* the incomplete = the next chunk */
                i = j + 1;
                {
                    uptr a;
                    if (line_is_steamclient(line, llen, &a) &&
                        (!liblo || a < liblo)) liblo = a;
                }
                llen = 0;
            }
        }
        close(fdm);
        if (llen > 0) {   /* the tail line without \n */
            uptr a;
            if (line_is_steamclient(line, llen, &a) &&
                (!liblo || a < liblo)) liblo = a;
        }
        if (!liblo) {
            /* the steamclient.so = not mapped yet — the retry */
            struct timespec ts = { 0, 500000000 };
            nanosleep(&ts, 0);
            continue;
        }

        /* the found: the version check + the patch (once) */
        {
            u8 *tgt = (u8 *)(liblo + SITE_OFF);
            u8 *sig = (u8 *)(liblo + SIGMA_OFF);
            u32 k;
            i32 ok = 1;

            if (memcmp(sig, SIGMA, 16) != 0) {
                klog_s("[c2b] g110: sigma MISMATCH @+");
                klog_h(SIGMA_OFF);
                klog_s(" lib=");
                klog_h((u32)liblo);
                klog_s(" have=");
                klog_x(sig, 16);
                klog_s("\n");
                return (void *)0;   /* the version drift = NO patch */
            }
            for (k = 0; k < 16; k++)
                if (tgt[k] != PRO16[k]) { ok = 0; break; }
            if (ok && MARKER_ON)
                for (k = 0; k < 5; k++)
                    if (tgt[0x10 + k] != MARKER[k]) { ok = 0; break; }
            if (!ok) {
                klog_s("[c2b] g110: prologue MISMATCH @+");
                klog_h(SITE_OFF);
                klog_s(" have=");
                klog_x(tgt, 16);
                klog_s("\n");
                return (void *)0;
            }
            if (tgt[0] == 0xe9 || tgt[0] == 0xff) {
                klog_s("[c2b] g110: already patched\n");
                g_patched = 1;
                return (void *)0;
            }

            /* the trampoline: the saved pro16 + the jump back (entry+16).
             * g110e (the local-test crash): (1) the g_tramp = the 4096-
             * aligned (the mprotect = the EINVAL on the 16-aligned = THE
             * run313 'tramp mprotect fail' = the whole silent chain);
             * (2) the x86-64 = the ABS jump ff25+8B (the g105-exact, the
             * NO-range-limit) — the e9 rel32 = the ±2GB = the local test
             * = the i32 truncation = the jump to the stack = the SIGSEGV;
             * the i386 = the e9 rel32 = the always-within. */
            {
                u8 *tp = g_tramp;
                for (k = 0; k < 16; k++) tp[k] = tgt[k];
#if defined(__x86_64__)
                {
                    uptr da = (uptr)(tgt + 16);
                    tp[16] = 0xff; tp[17] = 0x25;   /* jmp [rip+0] */
                    tp[18] = 0; tp[19] = 0; tp[20] = 0; tp[21] = 0;
                    for (k = 0; k < 8; k++) tp[22 + k] = (u8)(da >> (8 * k));
                }
#else
                {
                    i32 rel = (i32)((uptr)(tgt + 16) - ((uptr)tp + 21));
                    tp[16] = 0xe9;
                    tp[17] = (u8)rel;
                    tp[18] = (u8)(rel >> 8);
                    tp[19] = (u8)(rel >> 16);
                    tp[20] = (u8)(rel >> 24);
                }
#endif
                if (mprotect((void *)tp, 4096,
                             PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                    klog_s("[c2b] g110: tramp mprotect fail errno-layout\n");
                    return (void *)0;
                }
            }
            /* the entry patch: the x86-64 = ff25+abs8 + the 2x nop = 16B
             * (the g105-exact, the range-free); the i386 = e9 rel32 + the
             * nop pad = 16B */
            if (mprotect((void *)((uptr)tgt & ~(uptr)0xFFF), 0x2000,
                         PROT_READ | PROT_WRITE) != 0) {
                klog_s("[c2b] g110: mprotect fail\n");
                return (void *)0;
            }
            {
#if defined(__x86_64__)
                uptr da = (uptr)&c2b_g110_stub;
                tgt[0] = 0xff; tgt[1] = 0x25;   /* jmp [rip+0] */
                tgt[2] = 0; tgt[3] = 0; tgt[4] = 0; tgt[5] = 0;
                for (k = 0; k < 8; k++) tgt[6 + k] = (u8)(da >> (8 * k));
                tgt[14] = 0x90;
                tgt[15] = 0x90;
#else
                i32 rel;
                uptr dst = (uptr)&c2b_g110_detour_c;
                rel = (i32)(dst - (uptr)tgt);
                tgt[0] = 0xe9;
                tgt[1] = (u8)rel;
                tgt[2] = (u8)(rel >> 8);
                tgt[3] = (u8)(rel >> 16);
                tgt[4] = (u8)(rel >> 24);
                for (k = 5; k < 16; k++) tgt[k] = 0x90;
#endif
            }
            if (mprotect((void *)((uptr)tgt & ~(uptr)0xFFF), 0x2000,
                         PROT_READ | PROT_EXEC) != 0) {
                klog_s("[c2b] g110: mprotect RX fail\n");
            }
            g_patched = 1;
            klog_s("[c2b] g110: PATCHED arch=" ARCH_TAG " base=");
            klog_h((u32)liblo);
            klog_s(" site=+");
            klog_h(SITE_OFF);
            klog_s(" pid=");
            klog_h((u32)getpid());
            klog_s("\n");
            /* g110e: the patch self-check = the tramp + the site bytes
             * (the local-test crash = the jmp-back = the corrupt; the
             * bytes = THE decider) */
            klog_s("[c2b] g110: site16=");
            klog_x(tgt, 16);
            klog_s("\n[c2b] g110: tramp30=");
            klog_x(g_tramp, 30);
            klog_s("\n");
            /* g113: the AES-256-GCM key-schedule scan = the run321 verdict
             * (the chacha = silent, the cipher = AES-GCM) — the flow-
             * triggered heap scan = the keys = the decryptor --keys-from-log */
            {
                pthread_t t13;
                if (pthread_create(&t13, 0, c2b_g113_thread, 0) == 0)
                    pthread_detach(t13);
                else
                    klog_s("[c2b] g113: pthread_create FAILED\n");
            }
        }
        return (void *)0;
    }
    if (!g_patched) {
        /* the no-find outcome = the 32-bit candidates ONLY (the 979x
         * webhelper storm = the log-spam prevention; the 32-bit steam
         * core = the real target = the diagnostic = required) */
#if !defined(__x86_64__)
        klog_s("[c2b] g110: no steamclient.so in 2min (arch=" ARCH_TAG ")\n");
#endif
    }
    return (void *)0;
}

/* ---------------- g113: the AES-256-GCM key-schedule scan ----------------
 * THE RUN321 VERDICT (the first PASS!): the SDR session = REAL (the flow
 * 10.1.0.243:42157 <-> 152.233.19.133:28022, the FULL handshake captured,
 * 98 data packets) but the chacha = ZERO calls => the negotiated cipher =
 * AES-256-GCM (the ciphers=2 = the original g100-era finding). The session
 * keys = the EVP_AES_GCM_CTX = IN THE CLIENT's heap (the g100 lessons: the
 * ctx = the tcmalloc arenas, the ks = 60 u32 inline). THE g100-PROVEN
 * DETECTOR = the FIPS-197 schedule filter (the 96-bit: w[8]=w[0]^SubWord(
 * RotWord(w[7]))^rcon10, w[9]=w[1]^w[8], w[10]=w[2]^w[9], both domains) =
 * zero false positives on the heap. The hit = the keybe=<64hex> dump (the
 * decryptor parse_g100_log = the format) + the ±512B window (the EVP
 * iv[16] = the base-IV recovery offline). THE SCAN = FLOW-TRIGGERED: the
 * /proc/net/udp must show the :6DC6 (28022) remote = the LIVE session —
 * no session = no scan = the g111c melt-lesson honored (the duty cycle =
 * ~0 while idle; the 20s cap/cycle x the 15s gap x 24 cycles = the ~8 min
 * session window). The dedup = 8 distinct keys, the stop = 4+ (the both
 * directions + a rekey). The same keys log = the single artifact file. */

static u8 c2b_g113_sbox[256];
static u32 c2b_g113_ready;
static u8 c2b_g113_keys[8][32];
static u32 c2b_g113_nkeys;

static void c2b_g113_init(void)
{
    u8 alog[256], lg[256];
    u16 i;
    u8 v = 1;
    for (i = 0; i < 255; i++) {
        u8 lo;
        alog[i] = v;
        lg[v] = (u8)i;
        lo = (u8)(v << 1);
        if (v & 0x80) lo ^= 0x1b;
        v = (u8)(lo ^ v);
    }
    for (i = 1; i < 256; i++) {
        u8 s = alog[(u8)((u8)(255 - lg[i]) % 255)];
        u8 b = s ^ (u8)((s << 1) | (s >> 7)) ^ (u8)((s << 2) | (s >> 6))
             ^ (u8)((s << 3) | (s >> 5)) ^ (u8)((s << 4) | (s >> 4))
             ^ 0x63;
        c2b_g113_sbox[i] = b;
    }
    c2b_g113_sbox[0] = 0x63;
    c2b_g113_ready = 1;
}

static u32 c2b_g113_subw(u32 x)
{
    return ((u32)c2b_g113_sbox[(x >> 24) & 0xff] << 24)
         | ((u32)c2b_g113_sbox[(x >> 16) & 0xff] << 16)
         | ((u32)c2b_g113_sbox[(x >> 8) & 0xff] << 8)
         | (u32)c2b_g113_sbox[x & 0xff];
}

static void c2b_g113_hex(const u8 *p, u32 n)
{
    u32 i;
    for (i = 0; i < n; i++) klog_x(p + i, 1);
}

/* 1 = the live SDR flow present (the udp table has the :6DC6 remote) */
static i32 c2b_g113_flow(void)
{
    static char b[262144];
    i32 fd, r, n = 0, off;
    const char *paths[2] = { "/proc/net/udp", "/proc/net/udp6" };
    u32 pi;
    for (pi = 0; pi < 2; pi++) {
        fd = open(paths[pi], O_RDONLY);
        if (fd < 0) continue;
        n = 0;
        for (;;) {
            r = (i32)read(fd, b + n, (i64)(sizeof(b) - 1 - (u64)n));
            if (r <= 0) break;
            n += r;
            if (n >= (i32)sizeof(b) - 1) break;
        }
        close(fd);
        b[n] = 0;
        for (off = 0; off + 5 <= n; off++)
            if (b[off] == ':' && b[off+1] == '6' && b[off+2] == 'D' &&
                b[off+3] == 'C' && b[off+4] == '6' &&
                (b[off+5] == ' ' || b[off+5] == '\n'))
                return 1;
    }
    return 0;
}

/* 0 = the deadline; the hit-dump = the keybe= + the ±512B window */
static i32 c2b_g113_scanbuf(const u8 *buf, u32 n, uptr base, u32 *hits,
                            i64 *ts, i64 cap)
{
    u64 off;
    for (off = 512; off + 64 <= (u64)n; off += 4) {
        const u32 *w = (const u32 *)(buf + off);
        u32 t, s8, k;
        i32 isle;
        struct timespec now;
        if (((*hits) & 7) == 0) {
            clock_gettime(1, &now);
            if ((i64)now.tv_sec * 1000000000ll + (i64)now.tv_nsec - *ts > cap)
                return 1;
        }
        t = (w[7] << 8) | (w[7] >> 24);
        s8 = c2b_g113_subw(t) ^ 0x01000000u;
        if ((w[0] ^ s8) == w[8] && (w[1] ^ w[8]) == w[9] &&
            (w[2] ^ w[9]) == w[10])
            isle = 0;
        else {
            t = (w[7] >> 8) | (w[7] << 24);
            s8 = c2b_g113_subw(t) ^ 0x00000001u;
            if ((w[0] ^ s8) == w[8] && (w[1] ^ w[8]) == w[9] &&
                (w[2] ^ w[9]) == w[10])
                isle = 1;
            else
                continue;
        }
        /* the hit: the dedup vs the already-dumped keys */
        {
            u32 same = 0;
            u32 z;
            for (k = 0; k < c2b_g113_nkeys; k++) {
                same = 1;
                for (z = 0; z < 32; z++)
                    if (c2b_g113_keys[k][z] != ((const u8 *)w)[z]) {
                        same = 0; break;
                    }
                if (same) break;
            }
            if (same) { (*hits)++; continue; }
        }
        if (c2b_g113_nkeys < 8) {
            for (k = 0; k < 32; k++)
                c2b_g113_keys[c2b_g113_nkeys][k] = ((const u8 *)w)[k];
            c2b_g113_nkeys++;
        }
        klog_s("[c2b] g113: aes256ks @");
        klog_h((u32)(base + off));
        klog_s(isle ? " le keybe=" : " be keybe=");
        if (isle) {
            c2b_g113_hex((const u8 *)w, 32);
        } else {
            u8 kb[32];
            for (k = 0; k < 8; k++) {
                kb[k*4+0] = (u8)(w[k] >> 24);
                kb[k*4+1] = (u8)(w[k] >> 16);
                kb[k*4+2] = (u8)(w[k] >> 8);
                kb[k*4+3] = (u8)(w[k]);
            }
            c2b_g113_hex(kb, 32);
        }
        {
            u64 s2 = off >= 512 ? off - 512 : 0;
            u64 en = off + 512;
            if (en > (u64)n) en = n;
            klog_s(" win=");
            c2b_g113_hex(buf + s2, (u32)(en - s2));
            klog_s("\n");
        }
        (*hits)++;
        if (*hits >= 32 || c2b_g113_nkeys >= 8) return 1;
    }
    return 0;
}

static void *c2b_g113_thread(void *arg)
{
    static char mp[262144];
    static u8 seg[1 << 20];
    u32 cyc;
    (void)arg;
    {
        const char *e = (const char *)getenv("C2B_G113");
        if (e && e[0] == '0') return (void *)0;
    }
    if (!c2b_g113_ready) c2b_g113_init();
    for (cyc = 0; cyc < 24; cyc++) {
        struct timespec ts = { 15, 0 };
        u32 hits = 0;
        i64 t0, cap = 20 * 1000000000ll;
        i32 fdm, stop = 0;
        char *p, *e2;
        i64 n = 0;
        struct timespec now;

        nanosleep(&ts, 0);
        if (!c2b_g113_flow()) continue;
        klog_s("[c2b] g113: flow :6DC6 present, scan cycle\n");
        if (!c2b_g113_ready) c2b_g113_init();
        fdm = open("/proc/self/maps", O_RDONLY);
        if (fdm < 0) continue;
        for (;;) {
            i32 r = (i32)read(fdm, mp + n, (i64)sizeof(mp) - 1 - n);
            if (r <= 0) break;
            n += r;
            if (n >= (i64)sizeof(mp) - 1) break;
        }
        close(fdm);
        if (n <= 0) continue;
        mp[n] = 0;
        fdm = open("/proc/self/mem", O_RDONLY);
        if (fdm < 0) continue;
        clock_gettime(1, &now);
        t0 = (i64)now.tv_sec * 1000000000ll + (i64)now.tv_nsec;
        p = mp;
        e2 = mp + n;
        while (p < e2 && !stop) {
            uptr lo = 0, hi = 0;
            i32 wr = 0, c, mfd;
            while (p < e2 && *p == '\n') p++;
            if (p >= e2) break;
            while (p < e2 && *p != '-') {
                c = *p;
                if (c >= '0' && c <= '9') lo = (lo << 4) | (uptr)(c - '0');
                else if (c >= 'a' && c <= 'f')
                    lo = (lo << 4) | (uptr)(c - 'a' + 10);
                else break;
                p++;
            }
            if (p >= e2 || *p != '-') break;
            p++;
            while (p < e2 && *p != ' ') {
                c = *p;
                if (c >= '0' && c <= '9') hi = (hi << 4) | (uptr)(c - '0');
                else if (c >= 'a' && c <= 'f')
                    hi = (hi << 4) | (uptr)(c - 'a' + 10);
                else break;
                p++;
            }
            if (p >= e2 || *p != ' ') break;
            p++;
            if (p < e2 && *p == 'r') p++;
            if (p < e2 && *p == 'w') { wr = 1; p++; }
            else if (p < e2 && *p == '-') p++;
            while (p < e2 && *p != '\n') p++;
            if (!wr || hi <= lo || (hi - lo) < 4096) continue;
            if ((hi - lo) > (1ull << 30)) continue;   /* the guard */
            mfd = fdm;
            {
                u64 pos = lo;
                while (pos < hi && !stop) {
                    u64 want = (hi - pos) > sizeof(seg) ? sizeof(seg) : (hi - pos);
                    i64 r = pread64(mfd, seg, want, (int64_t)pos);
                    if (r <= 0) break;
                    stop = c2b_g113_scanbuf(seg, (u32)r, (uptr)pos,
                                            &hits, &t0, cap);
                    pos += (u64)r;
                }
            }
        }
        close(fdm);
        klog_s("[c2b] g113: cycle done hits=");
        klog_h(hits);
        klog_s(" keys=");
        klog_h(c2b_g113_nkeys);
        klog_s("\n");
        if (c2b_g113_nkeys >= 4) break;
    }
    return (void *)0;
}

__attribute__((constructor)) static void c2b_g110_init(void)
{
    const char *e = (const char *)getenv("C2B_G110");
    pthread_t t;

    if (e && e[0] == '0') return;
    /* g110d: the banner = the pid + the comm (WHO loaded = the 5x arch=32
     * identity = the run312 unknown; the comm = /proc/self/comm = 16B) */
    {
        char comm[17];
        i32 fd = open("/proc/self/comm", O_RDONLY);
        i32 n = 0;
        char pids[11];
        u32 v = (u32)getpid();
        i32 i, started = 0;

        for (i = 9; i >= 0; i--) { pids[i] = (char)('0' + (v % 10)); v /= 10; }
        pids[10] = 0;
        klog_s("[c2b] g110: hook loaded arch=" ARCH_TAG " pid=");
        for (i = 0; i < 10; i++) {
            if (pids[i] != '0' || started || i == 9) {
                klog(pids + i, 1);
                started = 1;
            }
        }
        klog_s(" comm=");
        if (fd >= 0) {
            n = (i32)read(fd, comm, 16);
            close(fd);
        }
        if (n > 0) {
            while (n > 0 && (comm[n - 1] == '\n' || comm[n - 1] == 0)) n--;
            klog(comm, (u32)n);
        } else {
            klog_s("?");
        }
        klog_s("\n");
    }
    if (pthread_create(&t, 0, c2b_g110_watch, 0) == 0)
        pthread_detach(t);
    else
        klog_s("[c2b] g110: pthread_create FAILED\n");
}
