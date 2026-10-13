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
#include <string.h>

/* v27: общий контракт hook=>мост (структура-ноут + чистый сканер CLV2).
 * hook = LD_PRELOAD = глобальный скоуп => мост видит через dlsym(0,...). */
#include "c2b_k27.h"

/* v27: экспортируемый инсанс-ноут 'A' (заполняет g126-dec-снифф).
 * Порядок записи: поля, ЗАТЕМ seq bump (release). См. c2b_k27.h. */
__attribute__((visibility("default")))
c2b_k27_A_t g_c2b_k27_A;

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
 * /proc/net/udp must show the :6D76 (28022) remote = the LIVE session —
 * no session = no scan = the g111c melt-lesson honored (the duty cycle =
 * ~0 while idle; the 45s cap/cycle x the 15s gap x 24 cycles = the ~8 min
 * session window). The dedup = 8 distinct keys, the stop = 4+ (the both
 * directions + a rekey). The same keys log = the single artifact file. */

static u8 c2b_g113_sbox[256];
static u32 c2b_g113_ready;
static u8 c2b_g113_keys[8][32];
static u32 c2b_g113_nkeys;
/* g117: the crypt_inner X25519 pubs (the dedup set) — the pub = the KNOWN
 * 32B = the heap anchor for the priv hunt => the offline X25519 premaster
 * => the FULL KDF (the keys + THE IVs = no nonce models at all). */
/* g120: 8 -> 128 slots. THE RUN330 ROOT CAUSE #1: the 8-slot registry =
 * filled IN SCAN ORDER and the cxi byte-literal = NOT zero-FP for the
 * CONTENT: the binary-data overlaps registered the pattern garbage
 * ('0000000038011220...' x-repeats) as pubs => the client session pub
 * fc9d46df... = NEVER made it into the registry => the global dup scan
 * = hunted the WRONG pubs (the run330 pubdup2 = 7 windows, ZERO for the
 * client pub). 128 slots + the quality gate (>= 18 distinct bytes) =
 * the real session pubs all fit; the residual gate-passing noise =
 * HARMLESS for the bloom scan (the dumps = only on the full 32B
 * matches; the bloom FP ~= npubs/65536). */
#define C2B_G113_NPUBS_MAX 128
/* g122: the ctx window 512 -> 16384. THE RUN332 DISAMBIGUATION: 39
 * client-pub windows captured, 5541 32B slices bruted via the PURE
 * X25519_base test (X25519(priv, BASE) = the client pub = ZERO KDF
 * assumptions, priv_presence_test.py) = NO priv in ANY +/-512B window
 * => the priv = NOT adjacent to any captured pub copy: the session
 * keypair object = BIGGER than 512B or the priv = a separate
 * allocation in the same arena. THE FIX: +/-16KB windows — the heap
 * locality bet (the allocator arenas = the MB scale, the keygen = the
 * priv + the pub = allocated together). The volume: ~115 pubdup2 x
 * 32KB hex = ~3.7MB/cycle klog = acceptable. The offline brute = the
 * X25519_base test (the same tool, the stride-4 = 4-aligned slices =
 * the allocator granularity). */
#define C2B_G113_DUPCTX 16384
static u8 c2b_g113_pubs[C2B_G113_NPUBS_MAX][32];
static u32 c2b_g113_npubs;

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

/* 1 = the live SDR flow present (the udp table has the :6D76 remote —
 * 28022 = 0x6D76; the run322 g113 = the ':6DC6' typo = 0x6DC6 = 28102 =
 * the trigger NEVER fired = the scan never ran = zero keys. FIXED here) */
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
                b[off+3] == '7' && b[off+4] == '6' &&
                (b[off+5] == ' ' || b[off+5] == '\n'))
                return 1;
    }
    return 0;
}

/* g118: mode = 0 = the cxi byte-scan (THE PRIZE: the pubdup => the priv =>
 * the KDF), 1 = the AES schedule scan. The two-pass split = the cxi = the
 * guaranteed first budget (run327: the AES ate the 45s and the cxi = starved
 * in ONE completed cycle). Return 1 = the deadline.
 * g118 clock fix: the deadline check = every 64KB offset (the old
 * ((*hits)&7)==0 = TRUE on EVERY iteration while hits=0 = the vDSO
 * clock_gettime per 4 bytes = ~85% of the scan time = the coverage
 * regression). g118: off starts at 0 (the old 512 = the dead leftover of
 * the ±512 window = the first 512B of EVERY 1MB segment skipped). */
static i32 c2b_g113_scanbuf(const u8 *buf, u32 n, uptr base, u32 *hits,
                            i64 *ts, i64 cap, u32 mode)
{
    u64 off;
    if (mode == 1)
    for (off = 0; off + 64 <= (u64)n; off += 4) {
        const u32 *w = (const u32 *)(buf + off);
        u32 t, s8, k;
        i32 isle;
        struct timespec now;
        if ((off & 0xFFFF) == 0) {
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
            /* g117: the window = ±2048B (the run326 lesson: the 512B window
             * = missed the GCM ctx H/nonce blocks — the offline structure
             * read needs the FULL context neighborhood) */
            u64 s2 = off >= 2048 ? off - 2048 : 0;
            u64 en = off + 2048;
            if (en > (u64)n) en = n;
            klog_s(" win=");
            c2b_g113_hex(buf + s2, (u32)(en - s2));
            klog_s("\n");
        }
        (*hits)++;
        if (*hits >= 32 || c2b_g113_nkeys >= 8) return 1;
    }
    /* g117: the BYTE-STEP pattern pass — the serialized crypt_inner
     * '08 01 12 20 <pub32>' (key_type=1, the field-1 len-32 = the X25519
     * pub) = ZERO false positives (4B literal). The hit = the pub + the
     * tail (the nonce) = the connection identity; THEN the pub-dup hunt
     * IN THE SAME CHUNK (the u64 prefilter = ~zero cost): the OTHER pub
     * instance = the ECX key struct (the priv = adjacent) => the offline
     * X25519(priv, server_pub-from-pcap) = the premaster => the FULL KDF
     * = the keys + THE IVs => the clean decrypt, no nonce models.
     * The unaligned serialization = the 4-step AES loop can miss it =>
     * the dedicated byte loop with the deadline checks (every 64K). */
    if (mode == 0) {
        u64 o2;
        struct timespec tn;
        for (o2 = 0; o2 + 76 <= (u64)n; o2++) {
            u32 du2, z2;
            u8 pk[32];
            u32 same;
            if ((o2 & 0xFFFF) == 0) {
                clock_gettime(1, &tn);
                if ((i64)tn.tv_sec * 1000000000ll + (i64)tn.tv_nsec - *ts
                    > cap)
                    return 1;
            }
            if (buf[o2] != 0x08 || buf[o2 + 1] != 0x01 ||
                buf[o2 + 2] != 0x12 || buf[o2 + 3] != 0x20)
                continue;
            for (z2 = 0; z2 < 32; z2++) pk[z2] = buf[o2 + 4 + z2];
            same = 0;
            for (du2 = 0; du2 < c2b_g113_npubs; du2++) {
                u32 z3;
                u32 eq = 1;
                for (z3 = 0; z3 < 32; z3++)
                    if (c2b_g113_pubs[du2][z3] != pk[z3]) { eq = 0; break; }
                if (eq) { same = 1; break; }
            }
            /* g120: the QUALITY GATE — the real X25519 pub = uniform
             * random (E[distinct bytes in 32] ~= 20.4); the pattern
             * garbage the old registry filled with (the run330 'pub='
 * lines with the u16-ramps and the 0908-fragments) = <= 10
             * distinct. The gate = 18 = the real keys pass, the noise
             * = rejected BEFORE it eats a slot. */
            if (!same && c2b_g113_npubs < C2B_G113_NPUBS_MAX) {
                u8 seenb[256];
                u32 distinct = 0, qb;
                memset(seenb, 0, sizeof(seenb));
                for (qb = 0; qb < 32; qb++) {
                    if (!seenb[pk[qb]]) { seenb[pk[qb]] = 1; distinct++; }
                }
                if (distinct >= 18) {
                    /* g122: the WIDE LOCALITY DUMP at the registration =
                     * once per unique pub: +/-16KB around the FIRST
                     * serialization copy. The run332 lesson: the priv =
                     * NOT within +/-512B of ANY pub copy (the pure
                     * X25519_base test over 5541 slices = NO hit) => the
                     * arena-neighborhood bet. The cxi serializations =
                     * the keygen's allocation neighborhood = the priv =
                     * plausibly within 16KB. Volume: ~54 unique pubs x
                     * 32KB hex = ~1.7MB/cycle. The offline = the same
                     * X25519_base brute. */
                    {
                        u64 s5 = o2 >= C2B_G113_DUPCTX
                                 ? o2 - C2B_G113_DUPCTX : 0;
                        u64 e5 = o2 + 40 + C2B_G113_DUPCTX;
                        if (e5 > (u64)n) e5 = n;
                        klog_s("[c2b] g113: cxidump @");
                        klog_h((u32)(base + o2));
                        klog_s(" pub=");
                        c2b_g113_hex(pk, 32);
                        klog_s(" ctx=");
                        c2b_g113_hex(buf + s5, (u32)(e5 - s5));
                        klog_s("\n");
                    }
                    for (z2 = 0; z2 < 32; z2++)
                        c2b_g113_pubs[c2b_g113_npubs][z2] = pk[z2];
                    c2b_g113_npubs++;
                }
            }
            klog_s("[c2b] g113: cxi @");
            klog_h((u32)(base + o2));
            klog_s(" pub=");
            c2b_g113_hex(pk, 32);
            klog_s(" tail=");
            c2b_g113_hex(buf + o2 + 36, 32);
            klog_s("\n");
            /* the pub-dup hunt: the OTHER instances of the pub in this
             * chunk = the key struct (the priv = the 32B neighbor) */
            {
                u64 o3;
                u64 p0;
                for (z2 = 0; z2 < 8; z2++)
                    ((u8 *)&p0)[z2] = pk[z2];
                for (o3 = 0; o3 + 32 <= (u64)n; o3++) {
                    u64 q0;
                    u32 z4, eq;
                    u64 s3, e3;
                    if ((o3 & 0xFFF) == 0) {
                        clock_gettime(1, &tn);
                        if ((i64)tn.tv_sec * 1000000000ll
                            + (i64)tn.tv_nsec - *ts > cap)
                            return 1;
                    }
                    for (z4 = 0; z4 < 8; z4++)
                        ((u8 *)&q0)[z4] = buf[o3 + z4];
                    if (q0 != p0) continue;
                    eq = 1;
                    for (z4 = 0; z4 < 32; z4++)
                        if (buf[o3 + z4] != pk[z4]) { eq = 0; break; }
                    if (!eq) continue;
                    klog_s("[c2b] g113: pubdup @");
                    klog_h((u32)(base + o3));
                    klog_s(" ctx=");
                    s3 = o3 >= 64 ? o3 - 64 : 0;
                    e3 = o3 + 96;
                    if (e3 > (u64)n) e3 = n;
                    c2b_g113_hex(buf + s3, (u32)(e3 - s3));
                    klog_s("\n");
                }
            }
        }
    }
    /* g119: mode 2 = THE GLOBAL DUP SCAN: the pub registry (the pubs =
     * collected across ALL the cycles by the cxi pass) x the FULL heap =
     * the cross-chunk instances of each pub. THE run328 LESSON: the client
     * session pub e1485f89... = found ONLY in its own serialized
     * crypt_inner (the self-match @d4eab6d8); the ECX key struct (the priv
     * = the adjacent 32B, the run328-PROVEN layout for the CM pubs: {priv
     * 32B, ptr, u64, pub 32B}) = in ANOTHER 1MB segment = the same-chunk
     * hunt = blind. The ctx = ±512B (the CM layout = the priv 48B before
     * the pub; the wider window = the margin for the other shapes). */
    if (mode == 2) {
        /* g120: THE SINGLE-PASS BLOOM. THE RUN330 ROOT CAUSE #2: the old
         * loop = PUBS-OUTER x HEAP-INNER = the FULL heap walk PER pub
         * (8-64x the cost) = the 65s cap + TRUNC on BOTH cycles (vs the
         * 2.5s single pass of the g118 era) => the dup pass = covered
         * only a fraction of the heap EVEN for the pubs it had. THE FIX:
         * ONE heap walk; per offset = the u64 load + the 65536-bit bloom
         * (the registry pubs' first-u64 low-16-bits; FP ~= npubs/65536 ~=
         * 0.1%) + on the bloom hit = the full verify against the registry.
         * The per-offset cost ~= the AES pass cost (~2.5s/heap) => the
         * 40s cap = the FULL heap per cycle, no truncation. The bitmap =
         * rebuilt per chunk call (the registry grows across cycles). */
        static u8 bmap[8192]; /* 65536 bits */
        u64 o2;
        struct timespec tn;
        u32 pi;
        memset(bmap, 0, sizeof(bmap));
        for (pi = 0; pi < c2b_g113_npubs; pi++) {
            u64 p0;
            u32 z2;
            for (z2 = 0; z2 < 8; z2++)
                ((u8 *)&p0)[z2] = c2b_g113_pubs[pi][z2];
            p0 &= 0xFFFF;
            bmap[(p0 >> 3) & 8191] |= (u8)(1u << (p0 & 7));
        }
        for (o2 = 0; o2 + 32 <= (u64)n; o2++) {
            u64 q0;
            u32 z3, lo;
            u64 s3, e3;
            if ((o2 & 0xFFFF) == 0) {
                clock_gettime(1, &tn);
                if ((i64)tn.tv_sec * 1000000000ll
                    + (i64)tn.tv_nsec - *ts > cap)
                    return 1;
            }
            for (z3 = 0; z3 < 8; z3++)
                ((u8 *)&q0)[z3] = buf[o2 + z3];
            lo = (u32)(q0 & 0xFFFF);
            if (!(bmap[(lo >> 3) & 8191] & (u8)(1u << (lo & 7))))
                continue;
            for (pi = 0; pi < c2b_g113_npubs; pi++) {
                const u8 *P = c2b_g113_pubs[pi];
                u32 z4, eq;
                u64 p0;
                for (z4 = 0; z4 < 8; z4++)
                    ((u8 *)&p0)[z4] = P[z4];
                if (q0 != p0) continue;
                eq = 1;
                for (z4 = 0; z4 < 32; z4++)
                    if (buf[o2 + z4] != P[z4]) { eq = 0; break; }
                if (!eq) continue;
                klog_s("[c2b] g113: pubdup2 @");
                klog_h((u32)(base + o2));
                klog_s(" pub=");
                c2b_g113_hex(P, 32);
                klog_s(" ctx=");
                s3 = o2 >= C2B_G113_DUPCTX ? o2 - C2B_G113_DUPCTX : 0;
                e3 = o2 + 512 + C2B_G113_DUPCTX;
                if (e3 > (u64)n) e3 = n;
                c2b_g113_hex(buf + s3, (u32)(e3 - s3));
                klog_s("\n");
                break;
            }
        }
    }
    return 0;
}


static void *c2b_g113_thread(void *arg)
{
    /* g118: 256KB -> 16MB. THE PRIMARY run327 ROOT CAUSE: the game = ~92K
     * maps lines (~8MB text) => the old 256KB read = the FIRST ~3% of the
     * mappings ONLY = the per-boot coverage lottery (the SAME disease as
     * the g102 probe crash, in the coverage form: run326 = the keys' region
     * inside the window, run327 = beyond it = 0 hits with a live session).
     * 16MB = ~180K lines headroom. */
    static char mp[16 << 20];
    static u8 seg[1 << 20];
    u32 cyc;
    const char *go;
    (void)arg;
    {
        const char *e = (const char *)getenv("C2B_G113");
        if (e && e[0] == '0') return (void *)0;
    }
    /* g115: the trigger = DUAL. (a) the GO-FILE (C2B_G113_GO): the harness
     * = touches it right after firing steam://connect — the exact session
     * start, zero false triggers, zero boot-duty (the game-side mode =
     * the 64-bit hook in csgo_linux64). (b) the :6D76 flow (the legacy,
     * the client-side mode): the run323 autopsy = the SDR client socket =
     * UNCONNECTED (rem=00000000:0000 in /proc/net/udp = the :6D76 rem =
     * NEVER there; the ss probe = 0 lines for the same reason) => the
     * client path = mostly a no-op = harmless belt+suspenders. */
    /* g118: the GO trigger = 64-BIT ONLY. The hook64 = the GAME build
     * (csgo_linux64 = the right address space); the client32 procs inherit
     * the exported C2B_G113_GO = 5 watchers x the full-heap scans = the CPU
     * steal from the game + the klog noise (run327). The client32 = the
     * :6D76 flow only (= a no-op per run323 = harmless). */
    go = (const char *)getenv("C2B_G113_GO");
#if !defined(__x86_64__)
    go = 0;
#endif
    /* g121: the GO trigger = THE GAME PROCESS ONLY. THE RUN331 AUTOPSY:
     * the klog (the FIXED path /tmp/c2b_client_keys.log) = INTERLEAVED
     * from >= 2 scanning processes — the cxi address sequence = NOT
     * ascending within any single pass (3a2565f0 -> 643e3270 -> ...
     * -> 081164e8 -> 3a2565f0 = 2+ interleaved map walks) = the hook
     * (LD_PRELOAD) = inherited by the steam-side 64-BIT children (the
     * g118 exclusion = the 32-bit only). Each process = its OWN static
     * registry + its own cycle-done in the SHARED klog: the run331
     * done lines (pubs=3) = the STEAM-side scanner's registry (099204c9
     * / a6b00ee9 / 4896f00e = the CM pubs), while the client session
     * pub 61a7ac2d (cxi @0164a2c8) = only in the GAME's registry — the
     * pubdup2 = hunted the WRONG process's registry => the client pub =
     * ZERO dup windows. THE FIX: the comm check — the go-file fires the
     * scan ONLY in csgo_linux64 (the substring 'csgo' = the suffix-safe
     * match; no steam-side proc = csgo*). The steam-side scanners = off
     * (their own klog noise + the CPU steal from the game = gone). The
     * :6D76 path = untouched (self-selecting per run323). */
#if defined(__x86_64__)
    {
        char comm[64];
        i32 cfd = open("/proc/self/comm", O_RDONLY);
        if (cfd >= 0) {
            i32 nr = (i32)read(cfd, comm, (size_t)sizeof(comm) - 1);
            close(cfd);
            if (nr > 0) {
                comm[nr] = 0;
                if (!strstr(comm, "csgo")) go = 0;
            }
        }
    }
#endif
    if (!c2b_g113_ready) c2b_g113_init();
    for (cyc = 0; cyc < 24; cyc++) {
        /* g118: the gap 15s -> 8s = more lottery tickets in a short session
         * (run327: the client died at t+30s in the dwell = 2 cycles total). */
        struct timespec ts = { 8, 0 };
        u32 hits = 0;
        /* g119: the THREE-pass caps: pass 0 = the cxi (the registry fill)
         * = the first 20s; pass 1 = the GLOBAL dup (the cross-chunk priv
         * hunt = THE actual prize) = the 40s; pass 2 = the AES schedules
         * (the fallback + the keybe verification) = the 65s overall. */
        i64 t0, caps[3];
        i32 fdm, stop = 0, pass, mtrunc = 0;
        char *p, *e2;
        i64 n = 0;
        struct timespec now;

        nanosleep(&ts, 0);
        if (go && go[0]) {
            i32 gfd = open(go, O_RDONLY);
            if (gfd < 0) continue;
            close(gfd);
            klog_s("[c2b] g113: go-file present, scan cycle\n");
        } else {
            if (!c2b_g113_flow()) continue;
            klog_s("[c2b] g113: flow :6D76 present, scan cycle\n");
        }
        if (!c2b_g113_ready) c2b_g113_init();
        fdm = open("/proc/self/maps", O_RDONLY);
        if (fdm < 0) continue;
        for (;;) {
            i32 r;
            if (n >= (i64)sizeof(mp) - 1) { mtrunc = 1; break; }
            r = (i32)read(fdm, mp + n, (i64)sizeof(mp) - 1 - n);
            if (r <= 0) break;
            n += r;
        }
        close(fdm);
        if (n <= 0) continue;
        mp[n] = 0;
        fdm = open("/proc/self/mem", O_RDONLY);
        if (fdm < 0) continue;
        clock_gettime(1, &now);
        t0 = (i64)now.tv_sec * 1000000000ll + (i64)now.tv_nsec;
        caps[0] = 20 * 1000000000ll;
        caps[1] = 40 * 1000000000ll;
        caps[2] = 65 * 1000000000ll;
        e2 = mp + n;
        /* g119: the THREE full walks over the SAME maps snapshot: pass 0 =
         * the cxi scan (the pubs), pass 1 = the global dup (the registry x
         * the heap = the cross-chunk priv hunt), pass 2 = the AES. */
        for (pass = 0; pass < 3; pass++) {
            stop = 0;
            p = mp;
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
                /* g118: the guard 1GB -> 8GB (the run327 heap layout = the
                 * keys' region can sit in a >1GB rw mapping; the deadline =
                 * the real limiter, the guard = vs the absurd only). */
                if ((hi - lo) > (8ull << 30)) continue;
                mfd = fdm;
                {
                    u64 pos = lo;
                    while (pos < hi && !stop) {
                        u64 want = (hi - pos) > sizeof(seg) ? sizeof(seg) : (hi - pos);
                        i64 r = pread64(mfd, seg, want, (int64_t)pos);
                        if (r <= 0) break;
                        stop = c2b_g113_scanbuf(seg, (u32)r, (uptr)pos,
                                                &hits, &t0, caps[pass],
                                                (u32)pass);
                        pos += (u64)r;
                    }
                }
            }
        }
        close(fdm);
        /* g118: the honest cycle diagnostics = the elapsed + the maps-window
         * truncation + the deadline truncation (the run327 zero-hit = the
         * invisible mix of the 256KB maps window + the coverage luck). */
        clock_gettime(1, &now);
        klog_s("[c2b] g113: cycle done hits=");
        klog_h(hits);
        klog_s(" keys=");
        klog_h(c2b_g113_nkeys);
        klog_s(" pubs=");
        klog_h(c2b_g113_npubs);
        {
            i64 el = ((i64)now.tv_sec * 1000000000ll + (i64)now.tv_nsec - t0)
                     / 1000000ll;
            klog_s(" ms=");
            klog_h((u32)el);
        }
        if (mtrunc) klog_s(" MAPSTRUNC");
        if (stop) klog_s(" TRUNC");
        klog_s("\n");
        if (c2b_g113_nkeys >= 4) break;
    }
    return (void *)0;
}

/* ---------------- g124: THE LIVE-INTERCEPT (the AES-GCM EVP init) --------
 * THE PIVOT (the worklog 1638 verdict): the offline heap hunt = EXHAUSTED
 * (the priv = not in the pub ±16KB neighborhoods x 6 runs; the IV = not in
 * the key ±512B neighborhoods x ~8M AEAD opens x 3 models). BOTH session
 * secrets = wiped or in the opaque custom ctxs => the capture at the INIT
 * = the only path through the wipe: the key + the IV = LIVE at the
 * wire-speed init = NO heap race, NO nonce model, the decryptor input =
 * DIRECT (ks/kr/ivs/ivr = the setkey/setiv args themselves).
 *
 * THE RE (the run333 bins libsteamnetworkingsockets.so__cb0ca8.so, the
 * 64-bit game copy, LOAD1 off==va, the objdump = /home/z/my-project/
 * g124-re/sns.asm): the SNS lib = a FULL statically-linked OpenSSL (the
 * OBJ db names 'id-aes256-GCM' etc @0x4317xx; the algo-name link table
 * {name_ptr, data_slot, 8} @0x15200+; NO curve25519 constants (the
 * 121665/p25519/base-point = ZERO hits) => the X25519 = NOT in this lib
 * (the game's = elsewhere; the cxi/pubdup line = continues separately)).
 * The AES = pure AES-NI (no S-box): 1032 aesenc, 196 pclmul*, 31
 * aeskeygenassist.
 *
 * THE MAPPED INIT PATH (aes_gcm_init_key @0x23d120 — the EVP_F_AES_INIT_KEY
 * ERR call (lib=6 func=0xa5 reason=0x126) @0x23bbf0 = the sibling aes_init_key
 * @0x23b9ad = the classifier):
 *   AESNI branch: aesni_set_encrypt_key(key=rdi, bits=esi(=keylen<<3), ks=rdx)
 *                 @0x2734b0 (rounds=14 @ks+0xf0 for bits=256)
 *              -> CRYPTO_gcm128_init(gcm=rdi=&gctx->gcm(@+0x100), ks=rsi,
 *                 block=rdx=aesni_encrypt@0x273b40) @0x251be0
 *              -> CRYPTO_gcm128_setiv(gcm=rdi, iv=rsi, len=rdx=@gctx+0x2c0)
 *                 @0x251f50 (the 12B fast path = J0 = iv||1; else the GHASH)
 * THE EVP_AES_GCM_CTX LAYOUT (the direct observation): ks @+0x000,
 * key_set @+0xf8, iv_set @+0xfc, gcm @+0x100 (sizeof(GCM128)=0x1b8),
 * iv-saved @+0x2b8, ivlen @+0x2c0. => the (key,iv) PAIRING = the pure
 * pointer arithmetic: gcm_ptr - 0x100 == ks_ptr (both = logged).
 *
 * THE HOOK SITES (the chokepoints BELOW the EVP layer = the funnel: every
 * GCM user — the EVP or the direct CCrypto — passes both):
 *   SITE A  setkey  @+0x2734b0  aesni_set_encrypt_key(rdi=key, esi=bits,
 *                   rdx=ks): the capture = bits==256 (the SNS session =
 *                   AES-256-GCM per the keybe) => key=<64hex> ks=<ptr>.
 *   SITE B  setiv   @+0x251f50  CRYPTO_gcm128_setiv(rdi=gcm, rsi=iv,
 *                   rdx=len): the capture = iv=<hex> len gcm=<ptr>.
 * THE PROLOGUES (the raw bytes = the version-drift kill; the anchor =
 * the DEEP sig = the whole 48B/28B head blocks incl. the cmp $0x100,%esi /
 * the mov 0x160(%rdi),%rbp):
 *   setkey 19B: 41 57 48 85 ff 41 56 41 55 41 54 55 53 0f 84 ad 04 00 00
 *               (push r15; test rdi,rdi; push r14/r13/r12; push rbp/rbx;
 *                je +0x4ad) = the WHOLE-INSTRUCTION boundary @19
 *               (the g110 m64 lesson: its 16B patch SPLITS the 5B movdqa —
 *                the latent bug = moot (the chacha = silent) but g124 =
 *                correct-by-construction: the patch len = the boundary).
 *   setiv 21B:  41 57 41 56 41 55 41 54 55 53 48 89 fb 48 83 ec 18
 *               48 83 fa 0c (pushes; mov rdi,rbx; sub $0x18,rsp;
 *                cmp $0xc,%rdx) = the boundary @21.
 * THE PATCH = the g110 recipe: the site = ff25+abs8 (14B, the range-free)
 * + the nop pad to the boundary; the tramp = the saved prologue + the abs
 * jmp back to entry+N (N = 19/21). The detour = the C fn (the same regs
 * ABI: at the entry rsp%16=8 = the call shape; the caller-saved = dead at
 * any fn entry; the callee-saved = the C prologue preserves) = the log +
 * the tramp call = the double-ret = the original ra = preserved.
 * THE KLOG = the shared /tmp/c2b_client_keys.log (the g110 sink):
 *   [c2b] g124: KEY bits=256 key=<64hex> ks=<16hex>
 *   [c2b] g124: IV gcm=<16hex> len=<n> iv=<hex>
 *   [c2b] g124: setkey#/setiv# = the call-profile (the cap 8 = the diag)
 *   [c2b] g124: PATCHED setkey|setiv base= pid=  /  SIG-MISMATCH  /  nomap
 * The decryptor (the next round): the pair (key,iv) by ks == gcm-0x100,
 * decrypt_stream(pkts, flow, k_a, k_b, iv_a, iv_b) — the tag = the oracle.
 * Killswitch: C2B_G124=0. The caps = 16 keys / 16 ivs (the dedup). */
#if defined(__x86_64__)
#define G124_SETKEY_OFF 0x2734b0u
#define G124_SETIV_OFF  0x251f50u
static const u8 G124_SETKEY_SIG[48] = {
    0x41, 0x57,                   /* push %r15 */
    0x48, 0x85, 0xff,             /* test %rdi,%rdi */
    0x41, 0x56, 0x41, 0x55,       /* push %r14; push %r13 */
    0x41, 0x54, 0x55, 0x53,       /* push %r12; push %rbp; push %rbx */
    0x0f, 0x84, 0xad, 0x04, 0x00, 0x00,  /* je +0x4ad (the null-key out) */
    0x48, 0x85, 0xd2,             /* test %rdx,%rdx */
    0x0f, 0x84, 0xa4, 0x04, 0x00, 0x00,  /* je +0x4a4 (the null-ks out) */
    0x89, 0xf0,                   /* mov %esi,%eax */
    0x83, 0xe0, 0xbf,             /* and $0xffffffbf,%eax */
    0x83, 0xc0, 0x80,             /* add $0xffffff80,%eax */
    0x0f, 0x84, 0xa6, 0x01, 0x00, 0x00,  /* je (the bits=128 path) */
    0x81, 0xfe, 0x00, 0x01, 0x00, 0x00   /* cmp $0x100,%esi */
};
static const u8 G124_SETIV_SIG[28] = {
    0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,  /* pushes r15..r12 */
    0x55, 0x53,                                      /* push rbp; push rbx */
    0x48, 0x89, 0xfb,             /* mov %rdi,%rbx */
    0x48, 0x83, 0xec, 0x18,       /* sub $0x18,%rsp */
    0x48, 0x83, 0xfa, 0x0c,       /* cmp $0xc,%rdx (the J0 fast path) */
    0x48, 0x8b, 0xaf, 0x60, 0x01, 0x00, 0x00  /* mov 0x160(%rdi),%rbp */
};
static u8 g124_tramp_a[64] __attribute__((aligned(4096)));
static u8 g124_tramp_b[64] __attribute__((aligned(4096)));
static u32 g124_patched;      /* bit0 = the setkey, bit1 = the setiv */
static u32 g124_nsetkey;      /* the total setkey calls seen */
static u32 g124_nsetiv;       /* the total setiv calls seen */
static u32 g124_prof_k;       /* the key-profile lines logged (cap 8) */
static u32 g124_prof_i;       /* the iv-profile lines logged (cap 8) */
#define G124_KEY_CAP 16
#define G124_IV_CAP  16
static u8  g124_keyseen[G124_KEY_CAP][32];
static u32 g124_nkeys;
static u8  g124_ivseen[G124_IV_CAP][16];
static u32 g124_nivs;

/* the 64-bit pointer print (the (key,iv) pairing = the ptr arithmetic) */
static void klog_p(uptr v)
{
    static const char hx[] = "0123456789abcdef";
    char b[16];
    i32 i;
    for (i = 0; i < 16; i++) b[i] = hx[(v >> (60 - 4 * i)) & 0xF];
    klog(b, 16);
}

/* the setkey capture: the dedup by the 32B key, the caps, the ks ptr =
 * the pairing anchor (gcm - 0x100 == ks) */
static void c2b_g124_key_capture(i32 bits, const void *key, const void *ks)
{
    u32 n = __atomic_add_fetch(&g124_nsetkey, 1, __ATOMIC_RELAXED);
    u32 z, j, dup;

    (void)n;
    if (g124_prof_k < 8) {
        u32 idx = __atomic_add_fetch(&g124_prof_k, 1, __ATOMIC_RELAXED);
        klog_s("[c2b] g124: setkey#");
        klog_h(idx);
        klog_s(" bits=");
        klog_h((u32)bits);
        klog_s("\n");
    }
    if (!key || bits != 256 || g124_nkeys >= G124_KEY_CAP) return;
    dup = 0;
    for (j = 0; j < g124_nkeys; j++) {
        u32 same = 0;
        for (z = 0; z < 32; z++)
            same |= (u32)(g124_keyseen[j][z] ^ ((const u8 *)key)[z]);
        if (!same) { dup = 1; break; }
    }
    if (dup) return;
    for (z = 0; z < 32; z++)
        g124_keyseen[g124_nkeys][z] = ((const u8 *)key)[z];
    g124_nkeys++;
    klog_s("[c2b] g124: KEY bits=256 key=");
    klog_x((const u8 *)key, 32);
    klog_s(" ks=");
    klog_p((uptr)ks);
    klog_s("\n");
}

/* the setiv capture: the dedup by the first-16B, the len = the logged */
static void c2b_g124_iv_capture(const void *gcm, const void *iv, sz_t len)
{
    u32 n = __atomic_add_fetch(&g124_nsetiv, 1, __ATOMIC_RELAXED);
    u8  buf[16];
    u32 cl, z, j, dup;

    (void)n;
    if (g124_prof_i < 8) {
        u32 idx = __atomic_add_fetch(&g124_prof_i, 1, __ATOMIC_RELAXED);
        klog_s("[c2b] g124: setiv#");
        klog_h(idx);
        klog_s(" len=");
        klog_h((u32)len);
        klog_s("\n");
    }
    if (!iv || g124_nivs >= G124_IV_CAP) return;
    for (z = 0; z < 16; z++) buf[z] = 0;
    cl = len > 16 ? 16 : (u32)len;
    if (cl) memcpy(buf, iv, cl);
    dup = 0;
    for (j = 0; j < g124_nivs; j++) {
        u32 same = 0;
        for (z = 0; z < 16; z++)
            same |= (u32)(g124_ivseen[j][z] ^ buf[z]);
        if (!same) { dup = 1; break; }
    }
    if (dup) return;
    for (z = 0; z < 16; z++) g124_ivseen[g124_nivs][z] = buf[z];
    g124_nivs++;
    klog_s("[c2b] g124: IV gcm=");
    klog_p((uptr)gcm);
    klog_s(" len=");
    klog_h((u32)len);
    klog_s(" iv=");
    klog_x(buf, 16);
    klog_s("\n");
}

/* the detours: the same-signature C fns (the log + the tramp = the
 * double-ret; the args = the regs at the entry = re-passed to the tramp) */
static i32 c2b_g124_setkey_detour(const void *key, i32 bits, void *ks);
static i32 c2b_g124_setkey_detour(const void *key, i32 bits, void *ks)
{
    i32 (*tramp)(const void *, i32, void *) =
        (i32 (*)(const void *, i32, void *))g124_tramp_a;
    c2b_g124_key_capture(bits, key, ks);
    /* the tramp = the saved SIG (48B) + the ff25 abs-jmp => the ready
     * check = @sizeof(G124_SETKEY_SIG) = 48 (NOT the 19B patch-shape —
     * the hooktest round-1 bug: the check @19 = the saved-orig byte =
     * never 0xff => the -2 = the tramp = never called) */
    if (g124_tramp_a[sizeof(G124_SETKEY_SIG)] == 0xff)
        return tramp(key, bits, ks);
    return -2;
}
static void c2b_g124_setiv_detour(void *gcm, const void *iv, sz_t len);
static void c2b_g124_setiv_detour(void *gcm, const void *iv, sz_t len)
{
    void (*tramp)(void *, const void *, sz_t) =
        (void (*)(void *, const void *, sz_t))g124_tramp_b;
    c2b_g124_iv_capture(gcm, iv, len);
    if (g124_tramp_b[sizeof(G124_SETIV_SIG)] == 0xff)
        tramp(gcm, iv, len);
}

/* the one-site patcher: the exact-sig gate (the version drift = the skip),
 * the tramp = the saved sig + the abs jmp to entry+siglen, the site =
 * ff25+abs8 + the nop pad to the boundary */
static void c2b_g124_patch(u8 *tgt, const u8 *sig, u32 siglen, u8 *tramp,
                           uptr detour, const char *name, u32 bit, uptr base)
{
    u32 k;

    if (memcmp(tgt, sig, siglen) != 0) {
        klog_s("[c2b] g124: SIG-MISMATCH ");
        klog_s(name);
        klog_s(" have=");
        klog_x(tgt, 16);
        klog_s("\n");
        return;
    }
    if (tgt[0] == 0xff) {           /* the already-patched */
        __atomic_or_fetch(&g124_patched, bit, __ATOMIC_RELAXED);
        return;
    }
    for (k = 0; k < siglen; k++) tramp[k] = tgt[k];
    {
        uptr da = (uptr)(tgt + siglen);
        tramp[siglen + 0] = 0xff; tramp[siglen + 1] = 0x25;
        tramp[siglen + 2] = 0; tramp[siglen + 3] = 0;
        tramp[siglen + 4] = 0; tramp[siglen + 5] = 0;
        for (k = 0; k < 8; k++) tramp[siglen + 6 + k] = (u8)(da >> (8 * k));
    }
    if (mprotect((void *)tramp, 4096,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        klog_s("[c2b] g124: tramp mprotect fail\n");
        return;
    }
    if (mprotect((void *)((uptr)tgt & ~(uptr)0xFFF), 0x2000,
                 PROT_READ | PROT_WRITE) != 0) {
        klog_s("[c2b] g124: site mprotect fail\n");
        return;
    }
    {
        uptr da = detour;
        tgt[0] = 0xff; tgt[1] = 0x25;
        tgt[2] = 0; tgt[3] = 0; tgt[4] = 0; tgt[5] = 0;
        for (k = 0; k < 8; k++) tgt[6 + k] = (u8)(da >> (8 * k));
        for (k = 14; k < siglen; k++) tgt[k] = 0x90;
    }
    if (mprotect((void *)((uptr)tgt & ~(uptr)0xFFF), 0x2000,
                 PROT_READ | PROT_EXEC) != 0) {
        klog_s("[c2b] g124: site mprotect RX fail\n");
    }
    __atomic_or_fetch(&g124_patched, bit, __ATOMIC_RELAXED);
    klog_s("[c2b] g124: PATCHED ");
    klog_s(name);
    klog_s(" base=");
    klog_p(base);
    klog_s(" pid=");
    klog_h((u32)getpid());
    klog_s("\n");
}

/* the maps-line match: 'libsteamnetworkingsockets.so' in the path part */
static i32 line_is_sns(const char *s, i32 n, uptr *out_lo)
{
    /* "libsteamnetworkingsockets.so" = 28 chars: s[11]='w' (after 'net'),
     * ".so" = s[25..27] */
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
    for (i = k; i + 28 <= n; i++) {
        if (s[i] == 'l' && s[i + 1] == 'i' && s[i + 2] == 'b' &&
            s[i + 3] == 's' && s[i + 4] == 't' && s[i + 5] == 'e' &&
            s[i + 6] == 'a' && s[i + 7] == 'm' && s[i + 11] == 'w' &&
            s[i + 25] == '.' && s[i + 26] == 's' && s[i + 27] == 'o') {
            *out_lo = a;
            return 1;
        }
    }
    return 0;
}

static void *c2b_g124_watch(void *arg)
{
    int round;
    (void)arg;

    /* the SNS lib = mapped at the game boot (the run333 bins = the game's
     * own dump) => the poll = short; 360 x 500ms = 3 min = the margin */
    for (round = 0; round < 360; round++) {
        i32 fdm = open("/proc/self/maps", O_RDONLY);
        char chunk[65536], line[4096];
        i32 llen = 0;
        uptr liblo = 0;
        ssz_t r;

        if ((g124_patched & 3) == 3) return (void *)0;
        if (fdm < 0) return (void *)0;
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
                if (j == (sz_t)r) break;
                i = j + 1;
                {
                    uptr a;
                    if (line_is_sns(line, llen, &a) &&
                        (!liblo || a < liblo)) liblo = a;
                }
                llen = 0;
            }
        }
        close(fdm);
        if (llen > 0) {
            uptr a;
            if (line_is_sns(line, llen, &a) && (!liblo || a < liblo))
                liblo = a;
        }
        if (!liblo) {
            struct timespec ts = { 0, 500000000 };
            nanosleep(&ts, 0);
            continue;
        }
        if (!(g124_patched & 1))
            c2b_g124_patch((u8 *)(liblo + G124_SETKEY_OFF), G124_SETKEY_SIG,
                           sizeof(G124_SETKEY_SIG), g124_tramp_a,
                           (uptr)&c2b_g124_setkey_detour, "setkey", 1,
                           liblo);
        if (!(g124_patched & 2))
            c2b_g124_patch((u8 *)(liblo + G124_SETIV_OFF), G124_SETIV_SIG,
                           sizeof(G124_SETIV_SIG), g124_tramp_b,
                           (uptr)&c2b_g124_setiv_detour, "setiv", 2,
                           liblo);
        if ((g124_patched & 3) == 3) return (void *)0;
        /* the sig mismatch = the version drift = NO patch (the log = once
         * via the patch fn) = the stop (the retry = the same verdict) */
        if (g124_patched) return (void *)0;
        return (void *)0;
    }
    if ((g124_patched & 3) != 3)
        klog_s("[c2b] g124: nomap 3min\n");
    return (void *)0;
}
#endif  /* __x86_64__ */

/* ---------------- g126: THE TRUE CRYPTO HOME (the game's steamclient.so) --
 * THE RUN334 VERDICT (the worklog 1740): the g124 = PATCHED x2 in the game
 * pid (the cb0ca8 SNS lib = mapped) BUT the ZERO detour calls = the patched
 * fns = NEVER EXECUTED = the cb0ca8 OpenSSL = the DECOY copy. The schedule
 * builder = the GAME's OWN 64-bit steamclient.so (the d975c5, 46.7MB: 21x
 * aeskeygenassist, the 'aes-256-gcm' string @file 0xd3bdee, the CCrypto
 * strings x7, the order-L @0xd8e630 = the X25519 = also here) => THE g126 =
 * the g124 recipe x THE NEW OFFSETS (the capstone RE = this round, the
 * binary = the run334 bins steamclient.so__d975c5.so, va = file + 0x1000).
 *
 * THE RE (the sc_g126_*.py = /home/z/my-project/g124-re/):
 *   SITE A  aesni_set_encrypt_key @0x201d780 (rdi=key, esi=bits, rdx=ks):
 *           the sig = the file-verified 35B head (the null guards + the je
 *           displacements 0x463/0x45a + the ia32cap const $0x10000800 —
 *           the worklog's 48B head = TRUNCATED to 35B: the 48B head = CONTAINS
 *           the rip-relative 'and r10d,[rip+0xd182fc]' @+41 => the tramp
 *           re-exec = reads the WRONG ia32cap => the whole-instruction
 *           boundary @35 = the LAST position-independent boundary; the two
 *           rel32 je = the FORWARD jumps = the tramp-safe semantics (the
 *           same property the g124-setkey proved on the real lib)).
 *   SITE B  CRYPTO_gcm128_setiv @0x212d6c0 (rdi=gcm, rsi=iv, rdx=len): the
 *           FOUND = the shape hunt (the cb0ca8 setiv @0x251f50 = the
 *           reference): the 6-push prologue + mov rbp,rsi + mov rbx,rdi +
 *           mov rax,[rdi+0x160] (the GCM128 block-fn ptr @+0x160 = THE SAME
 *           offset as cb0ca8!) + movups [rdi+0x30],xmm0 (the Yi zero) +
 *           cmp rdx,0xc (the J0 fast path) => the sig = the file-verified
 *           31B head = ALL position-independent (the [rdi+0x160] = the
 *           base-relative = the tramp-safe; the pxor = the 66-prefix 4B
 *           form = the byte-exact gate = the build-time verification).
 *   THE INIT FN (the setkey+setiv pairing): the setiv E8 callers = 10;
 *           the fn @0x2106d90 = the EVP aes_gcm_init_key equivalent (call
 *           0x2119ac0 = the EVP_C_DATA; lea r12,[rbx+0x100] = the gcm sub-ctx;
 *           call 0x212d3d0 = the gcm128_init(gcm=r12, ks=rbx, block);
 *           movsxd rdx,[rbx+0x2c0] = the ivlen @+0x2c0; call 0x212d6c0 =
 *           setiv(gcm, iv, ivlen); the flags key_set @+0xf8 / iv_set @+0xfc)
 *           => THE EVP_AES_GCM_CTX LAYOUT = IDENTICAL TO cb0ca8 (gcm @ks+0x100)
 *           => THE (key,iv) PAIRING = gcm_ptr - 0x100 == ks_ptr = THE SAME
 *           RULE the g124_recover.py consumer already implements.
 * THE MAPS MATCH = 'steamclient.so' (the game's own copy = ONE per the game
 * pid; the sig gate = the wrong-copy safety: the mismatch = NO patch + the
 * log). The klog = the SAME shared sink, the tag = g126 (the format = the
 * consumer-compatible: the KEY/IV lines = the identical fields).
 * Killswitch: C2B_G126=0. The caps = 16 keys / 16 ivs (the dedup). */
#if defined(__x86_64__)
#define G126_SETKEY_OFF 0x201d780u
#define G126_SETIV_OFF  0x212d6c0u
static const u8 G126_SETKEY_SIG[35] = {
    0x48, 0x83, 0xec, 0x08,              /* sub $0x8,%rsp */
    0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff,  /* mov $-1,%rax */
    0x48, 0x85, 0xff,                    /* test %rdi,%rdi */
    0x0f, 0x84, 0x63, 0x04, 0x00, 0x00,  /* je +0x463 (the null-key out) */
    0x48, 0x85, 0xd2,                    /* test %rdx,%rdx */
    0x0f, 0x84, 0x5a, 0x04, 0x00, 0x00,  /* je +0x45a (the null-ks out) */
    0x41, 0xba, 0x00, 0x08, 0x00, 0x10   /* mov $0x10000800,%r10d */
};
static const u8 G126_SETIV_SIG[31] = {
    0x41, 0x57,                          /* push %r15 */
    0x66, 0x0f, 0xef, 0xc0,              /* pxor %xmm0,%xmm0 (66-prefix) */
    0x41, 0x56,                          /* push %r14 */
    0x41, 0x55,                          /* push %r13 */
    0x41, 0x54,                          /* push %r12 */
    0x55,                                /* push %rbp */
    0x48, 0x89, 0xf5,                    /* mov %rsi,%rbp (iv) */
    0x53,                                /* push %rbx */
    0x48, 0x89, 0xfb,                    /* mov %rdi,%rbx (gcm) */
    0x48, 0x83, 0xec, 0x28,              /* sub $0x28,%rsp */
    0x48, 0x8b, 0x87, 0x60, 0x01, 0x00, 0x00  /* mov 0x160(%rdi),%rax */
};
/* ---- v18-g126C/D: THE DECRYPT TAPS (SITE C = decrypt_ctr32, D = decrypt).
 * THE RE (g126_dec_re*.py, this round, the run335 bins d975c5 = the SAME
 * lib the g126 = verified on): the EVP aes_gcm_cipher @0x21063c0 = the
 * dispatcher: the enc flag = [r15+0x10], the stream fn = [rax+0x2d0], the
 * gcm sub-ctx = +0x100 (the SAME layout as cb0ca8). The enc==0 (DECRYPT)
 * branches: stream!=0 => call 0x212eeb0 = CRYPTO_gcm128_decrypt_ctr32
 * (gcm, in, out, len, ctr=r8); stream==0 => call 0x212e2e0 =
 * CRYPTO_gcm128_decrypt (gcm, in, out, len). (The enc!=0 twins = 0x212e950
 * encrypt_ctr32 / 0x212dc60 encrypt — NOT tapped.) The ctx reads in both
 * = 0x160(key)/0x168(block)/0x180(stream) = the SAME offsets as cb0ca8.
 * THE PRIZE: the out-buffer AFTER the tramp = THE DECRYPTED SERVER TRUTH
 * (the S2's class-81 msgs the g77-tap sees encrypted on fd 0x38/0x43).
 * The logs carry in= (the first 8B) => the direction-proof for free: the
 * decrypt-in = the wire bytes (the g77-tap matches), the encrypt-in = the
 * plaintext. The rate = the first 64 + every 8th per fn. The patch = the
 * same c2b_g126_patch recipe (the sig = the whole-instruction head, the
 * base-relative = tramp-safe; the boundary = 26B / 20B = the verified
 * next-instr edges). Killswitch: shared C2B_G126=0. */
#define G126_DEC_OFF    0x212e2e0u   /* CRYPTO_gcm128_decrypt      */
#define G126_DECC32_OFF 0x212eeb0u   /* CRYPTO_gcm128_decrypt_ctr32 */
static const u8 G126_DEC_SIG[26] = {
    0x41, 0x57,                          /* push %r15 */
    0x48, 0x89, 0xc8,                    /* mov %rcx,%rax (len) */
    0x49, 0x89, 0xd7,                    /* mov %rdx,%r15 (out) */
    0x41, 0x56,                          /* push %r14 */
    0x48, 0x89, 0xc2,                    /* mov %rax,%rdx */
    0x49, 0x89, 0xfe,                    /* mov %rdi,%r14 (gcm) */
    0x41, 0x55,                          /* push %r13 */
    0x41, 0x54,                          /* push %r12 */
    0x55,                                /* push %rbp */
    0x53,                                /* push %rbx */
    0x48, 0x83, 0xec, 0x58               /* sub $0x58,%rsp */
};
static const u8 G126_DECC32_SIG[20] = {
    0x41, 0x57,                          /* push %r15 */
    0x41, 0x56,                          /* push %r14 */
    0x41, 0x55,                          /* push %r13 */
    0x49, 0x89, 0xd5,                    /* mov %rdx,%r13 (out) */
    0x41, 0x54,                          /* push %r12 */
    0x55,                                /* push %rbp */
    0x48, 0x89, 0xcd,                    /* mov %rcx,%rbp (len) */
    0x53,                                /* push %rbx */
    0x48, 0x83, 0xec, 0x38               /* sub $0x38,%rsp */
};
static u8 g126_tramp_a[64] __attribute__((aligned(4096)));
static u8 g126_tramp_b[64] __attribute__((aligned(4096)));
static u8 g126_tramp_c[64] __attribute__((aligned(4096)));
static u8 g126_tramp_d[64] __attribute__((aligned(4096)));
static u32 g126_patched;      /* bit0=setkey bit1=setiv bit2=dec bit3=decc32 */
static u32 g126_nsetkey;
static u32 g126_nsetiv;
static u32 g126_prof_k;
static u32 g126_prof_i;
static u32 g126_ndecc32;      /* the decrypt_ctr32 calls seen */
static u32 g126_ndecl;        /* the decrypt calls seen */
static u32 g126_prof_dc;      /* the dec-profile lines logged (cap 8) */
static u32 g126_prof_dcl;     /* the decl-profile lines logged (cap 8) */
#define G126_KEY_CAP 16
#define G126_IV_CAP  16
static u8  g126_keyseen[G126_KEY_CAP][32];
static u32 g126_nkeys;
static u8  g126_ivseen[G126_IV_CAP][16];
static u32 g126_nivs;

static void c2b_g126_key_capture(i32 bits, const void *key, const void *ks)
{
    u32 n = __atomic_add_fetch(&g126_nsetkey, 1, __ATOMIC_RELAXED);
    u32 z, j, dup;

    (void)n;
    if (g126_prof_k < 8) {
        u32 idx = __atomic_add_fetch(&g126_prof_k, 1, __ATOMIC_RELAXED);
        klog_s("[c2b] g126: setkey#");
        klog_h(idx);
        klog_s(" bits=");
        klog_h((u32)bits);
        klog_s("\n");
    }
    if (!key || bits != 256 || g126_nkeys >= G126_KEY_CAP) return;
    dup = 0;
    for (j = 0; j < g126_nkeys; j++) {
        u32 same = 0;
        for (z = 0; z < 32; z++)
            same |= (u32)(g126_keyseen[j][z] ^ ((const u8 *)key)[z]);
        if (!same) { dup = 1; break; }
    }
    if (dup) return;
    for (z = 0; z < 32; z++)
        g126_keyseen[g126_nkeys][z] = ((const u8 *)key)[z];
    g126_nkeys++;
    klog_s("[c2b] g126: KEY bits=256 key=");
    klog_x((const u8 *)key, 32);
    klog_s(" ks=");
    klog_p((uptr)ks);
    klog_s("\n");
}

static void c2b_g126_iv_capture(const void *gcm, const void *iv, sz_t len)
{
    u32 n = __atomic_add_fetch(&g126_nsetiv, 1, __ATOMIC_RELAXED);
    u8  buf[16];
    u32 cl, z, j, dup;

    (void)n;
    if (g126_prof_i < 8) {
        u32 idx = __atomic_add_fetch(&g126_prof_i, 1, __ATOMIC_RELAXED);
        klog_s("[c2b] g126: setiv#");
        klog_h(idx);
        klog_s(" len=");
        klog_h((u32)len);
        klog_s("\n");
    }
    if (!iv || g126_nivs >= G126_IV_CAP) return;
    for (z = 0; z < 16; z++) buf[z] = 0;
    cl = len > 16 ? 16 : (u32)len;
    if (cl) memcpy(buf, iv, cl);
    dup = 0;
    for (j = 0; j < g126_nivs; j++) {
        u32 same = 0;
        for (z = 0; z < 16; z++)
            same |= (u32)(g126_ivseen[j][z] ^ buf[z]);
        if (!same) { dup = 1; break; }
    }
    if (dup) return;
    for (z = 0; z < 16; z++) g126_ivseen[g126_nivs][z] = buf[z];
    g126_nivs++;
    klog_s("[c2b] g126: IV gcm=");
    klog_p((uptr)gcm);
    klog_s(" len=");
    klog_h((u32)len);
    klog_s(" iv=");
    klog_x(buf, 16);
    klog_s("\n");
}

static i32 c2b_g126_setkey_detour(const void *key, i32 bits, void *ks);
static i32 c2b_g126_setkey_detour(const void *key, i32 bits, void *ks)
{
    i32 (*tramp)(const void *, i32, void *) =
        (i32 (*)(const void *, i32, void *))g126_tramp_a;
    c2b_g126_key_capture(bits, key, ks);
    if (g126_tramp_a[sizeof(G126_SETKEY_SIG)] == 0xff)
        return tramp(key, bits, ks);
    return -2;
}
static void c2b_g126_setiv_detour(void *gcm, const void *iv, sz_t len);
static void c2b_g126_setiv_detour(void *gcm, const void *iv, sz_t len)
{
    void (*tramp)(void *, const void *, sz_t) =
        (void (*)(void *, const void *, sz_t))g126_tramp_b;
    c2b_g126_iv_capture(gcm, iv, len);
    if (g126_tramp_b[sizeof(G126_SETIV_SIG)] == 0xff)
        tramp(gcm, iv, len);
}

/* v27: IN-CHANNEL CLV2 SNIFF — расшифрованный plaintext на ff×4+'A'/'B'.
 * 'A' = сервер-челлендж (run361: chal=0, proto=3, val=relay_session_id) =>
 * мост отвечает 'k' in-channel с ЭТИМ chal (k27). 'B' = accept = WIN-сигнал.
 * Сессия-источник (мост vs движок) = пост-фактум по gcm + in=<8B> ↔ pcap.
 * Rate: лог первые 16; нота мосту = дедап по (gcm,chal,proto,val). */
/* v45: полная 'B'-нота мосту (та же форма, что 'A'-нота; консюмер =
 * c2b_a2eb_maybe в c2bridge.c — даунлинк серверского accept движку).
 * НЕ static: мост достаёт dlsym(0,"g_c2b_k27_B") — как g_c2b_k27_A. */
c2b_k27_A_t g_c2b_k27_B;

static void c2b_g126_k27_sniff(const void *gcm, const void *in,
                               const void *out, sz_t len)
{
    static u32 sn_n, sn_chal, sn_val, sn_proto, sn_rawlen;
    static const void *sn_gcm;
    static unsigned char sn_raw[C2B_K27_RAWMAX];
    static u32 sn_have;
    u32 off = 0, chal, val, proto, mo = 0, rl;
    unsigned char cls;
    if (!out || len < 14) return;
    if (!c2b_k27_scan_clv2((const unsigned char *)out, (unsigned)len, off,
                           &cls, &chal, &proto, &val, &mo))
        return;
    if (cls == (unsigned char)'B') {
        static u32 sn_bn;
        static unsigned char sn_braw[C2B_K27_RAWMAX];
        static u32 sn_brl;
        if (sn_n < 16) {
            sn_n++;
            klog_s("[c2b] g126: DEC-B!!! n=");
            klog_h(sn_n);
            klog_s(" len=");
            klog_h((u32)len);
            klog_s(" gcm=");
            klog_p((uptr)gcm);
            klog_s("\n");
        }
        /* v45: ПОЛНЫЙ 'B'-капчер для моста (a2e-B даунлинк = серверский
         * accept -> движковый loopback, g48/g49-проверенный 'B'-case) +
         * raw-hexdump (первые 48B) = вход для v46 ('B'-парсер 0x25a8b0,
         * фаза B(в) таск-текста). Дедап по сырым байтам (как у 'A'): тот
         * же 'B' перекриптуется повторно — не бампаем. rl = len-mo (сканер
         * гарантирует mo+14 <= len); единственный кламп = RAWMAX. */
        {
            u32 brl = (u32)len - mo;
            if (brl > C2B_K27_RAWMAX) brl = C2B_K27_RAWMAX;
            if (brl >= 14 &&
                !(sn_brl == brl &&
                  memcmp(sn_braw, (const unsigned char *)out + mo, brl) == 0)) {
                memcpy(sn_braw, (const unsigned char *)out + mo, brl);
                sn_brl = brl;
                g_c2b_k27_B.chal = chal;
                g_c2b_k27_B.proto = proto;
                g_c2b_k27_B.val = val;
                g_c2b_k27_B.gcm = (unsigned long long)(uptr)gcm;
                g_c2b_k27_B.rawlen = brl;   /* ДО seq-bump (контракт) */
                memcpy((void *)g_c2b_k27_B.raw, sn_braw, brl);
                __atomic_store_n(&g_c2b_k27_B.seq, g_c2b_k27_B.seq + 1,
                                 __ATOMIC_RELEASE);
                if (sn_bn < 4) {
                    sn_bn++;
                    klog_s("[c2b] g126: DEC-B raw n=");
                    klog_h(sn_bn);
                    klog_s(" len=");
                    klog_h(brl);
                    klog_s(" chal=");
                    klog_h(chal);
                    klog_s(" val=");
                    klog_h(val);
                    klog_s(" raw=");
                    klog_x(sn_braw, brl < 48 ? brl : 48);
                    klog_s("\n");
                }
            }
        }
        return;
    }
    /* v43: капчер ПОЛНОГО wire-'A' (от ff×4) — ДО дедапа, чтобы сравнивать
     * сырые байты: run381-факт — 'A'#1 и 'A'#2 отличаются ТОЛЬКО echo
     * (chal/val/proto/gcm равны) => старый дедап по четвёрке ГЛОТИЛ 'A'#2.
     * rl = len-mo (сканер гарантирует mo+14 <= len => rl >= 14 > 0);
     * единственный кламп = RAWMAX => memcpy-границы доказуемы. */
    rl = (u32)len - mo;
    if (rl > C2B_K27_RAWMAX) rl = C2B_K27_RAWMAX;
    /* 'A': дедап (тот же gcm + те же сырые байты = повторный расшифр) */
    if (sn_have && sn_chal == chal && sn_val == val &&
        sn_proto == proto && sn_gcm == gcm && sn_rawlen == rl &&
        rl <= C2B_K27_RAWMAX &&
        memcmp(sn_raw, (const unsigned char *)out + mo, rl) == 0)
        return;
    sn_gcm = gcm; sn_chal = chal; sn_val = val; sn_proto = proto;
    sn_rawlen = rl;
    if (rl) memcpy(sn_raw, (const unsigned char *)out + mo, rl);
    sn_have = 1;
    if (sn_n < 16) {
        sn_n++;
        klog_s("[c2b] g126: DEC-A n=");
        klog_h(sn_n);
        klog_s(" len=");
        klog_h((u32)len);
        klog_s(" chal=");
        klog_h(chal);
        klog_s(" proto=");
        klog_h(proto);
        klog_s(" val=");
        klog_h(val);
        klog_s(" gcm=");
        klog_p((uptr)gcm);
        if (in) {
            u8 bi27[8];
            u32 z27, cl27 = len < 8 ? (u32)len : 8;
            for (z27 = 0; z27 < 8; z27++) bi27[z27] = 0;
            memcpy(bi27, in, cl27);
            klog_s(" in=");
            klog_x(bi27, 8);
        }
        /* v43: raw-хвост после первых 19B (val-конец + флаги + echo) —
         * байты @19+ в лог = верификация патчей a2e пост-фактум */
        if (rl > 19) {
            klog_s(" raw19=");
            klog_x(sn_raw + 19, rl - 19 > 23 ? 23 : rl - 19);
        }
        klog_s("\n");
    }
    /* нота мосту: поля + raw, ЗАТЕМ seq (release) — см. c2b_k27.h */
    g_c2b_k27_A.chal = chal;
    g_c2b_k27_A.proto = proto;
    g_c2b_k27_A.val = val;
    g_c2b_k27_A.gcm = (unsigned long long)(uptr)gcm;
    if (rl <= C2B_K27_RAWMAX) {
        memcpy((void *)g_c2b_k27_A.raw, sn_raw, rl);
        g_c2b_k27_A.rawlen = rl;
    }
    (void)__atomic_add_fetch(&g_c2b_k27_A.seq, 1u, __ATOMIC_RELEASE);
}

/* the decrypt capture: the out = THE PLAINTEXT (post-tramp), the in-head =
 * the direction-proof; the rate = the first 64 + every 8th; the len-gate =
 * the sane SNP range (1..2KB); the log = [c2b] g126: DEC32|DECL n=len= rc=
 * gcm= in=<8hex> out=<24hex> */
static void c2b_g126_dec_capture(const void *gcm, const void *in,
                                 const void *out, sz_t len, i32 rc,
                                 u32 tag32)
{
    u32 *ctr = tag32 ? &g126_ndecc32 : &g126_ndecl;
    u32 *prof = tag32 ? &g126_prof_dc : &g126_prof_dcl;
    const char *tag = tag32 ? "DEC32" : "DECL";
    u32 n = __atomic_add_fetch(ctr, 1, __ATOMIC_RELAXED);
    u8 bi[8], bo[64];   /* v28: 64B — полный хвост 'A' (echo) для декода конверта */
    u32 cl, z;

    if (!out || !len || len > 0x800) return;
    /* v27: снифф ДО rate-гейта — 'A'/'B' редкие, пропуск = потеря окна */
    c2b_g126_k27_sniff(gcm, in, out, len);
    if (n > 64 && (n & 7) != 0) return;
    {
        /* v23 k23: ОДНОРАЗОВЫЙ снейкшот стека (24 qwords вверх от кадра)
         * на ПЕРВОМ расшифре SNP-пути = GNS-контекст движка в старших
         * кадрах: кандидаты = iface-инстанс/conn-объект (для v24-релея —
         * хэндлы GNS непрозрачны, скан бесполезен, только захват). */
        static u32 k23_stack_done;
        if (tag32 &&
            !__atomic_exchange_n(&k23_stack_done, 1u, __ATOMIC_RELAXED)) {
            const void **fa = (const void **)__builtin_frame_address(0);
            u32 q23;
            klog_s("[c2b] k23: decstack gcm=");
            klog_p((uptr)gcm);
            klog_s("\n");
            for (q23 = 0; q23 < 24; q23++) {
                klog_s((q23 & 3) ? " " : "\n[c2b] k23: q");
                klog_h(q23);
                klog_s("=");
                klog_p((uptr)fa[q23]);
            }
            klog_s("\n");
        }
    }
    for (z = 0; z < 64; z++) bo[z] = 0;
    cl = len < 64 ? (u32)len : 64;
    memcpy(bo, out, cl);
    if (*prof < 8) {
        (*prof)++;
        klog_s("[c2b] g126: "); klog_s(tag); klog_s("# prof n=");
        klog_h(n); klog_s("\n");
    }
    klog_s("[c2b] g126: "); klog_s(tag);
    klog_s(" n="); klog_h(n);
    klog_s(" len="); klog_h((u32)len);
    klog_s(" rc="); klog_h((u32)rc);
    klog_s(" gcm="); klog_p((uptr)gcm);
    if (in) {
        for (z = 0; z < 8; z++) bi[z] = 0;
        cl = len < 8 ? (u32)len : 8;
        memcpy(bi, in, cl);
        klog_s(" in="); klog_x(bi, 8);
    }
    klog_s(" out="); klog_x(bo, 64);
    klog_s("\n");
}

/* SITE D = CRYPTO_gcm128_decrypt (the 4-arg non-stream path) */
static i32 c2b_g126_dec_detour(void *gcm, const void *in, void *out, sz_t len);
static i32 c2b_g126_dec_detour(void *gcm, const void *in, void *out, sz_t len)
{
    i32 (*tramp)(void *, const void *, void *, sz_t) =
        (i32 (*)(void *, const void *, void *, sz_t))g126_tramp_c;
    i32 rc = tramp(gcm, in, out, len);
    c2b_g126_dec_capture(gcm, in, out, len, rc, 0);
    return rc;
}
/* SITE C = CRYPTO_gcm128_decrypt_ctr32 (the 5-arg stream path = the SNP
 * fast path — the dispatcher's enc==0 + stream!=0 = THE SNS inbound) */
static i32 c2b_g126_decc32_detour(void *gcm, const void *in, void *out,
                                  sz_t len, const void *ctrfn);
static i32 c2b_g126_decc32_detour(void *gcm, const void *in, void *out,
                                  sz_t len, const void *ctrfn)
{
    i32 (*tramp)(void *, const void *, void *, sz_t, const void *) =
        (i32 (*)(void *, const void *, void *, sz_t, const void *))
            g126_tramp_d;
    i32 rc = tramp(gcm, in, out, len, ctrfn);
    c2b_g126_dec_capture(gcm, in, out, len, rc, 1);
    return rc;
}

/* ---- v31: THE ENCRYPT TAPS (SITE E = encrypt, F = encrypt_ctr32).
 * THE RE (this round, the steamclient.so__d975c5 objdump, the twins of the
 * verified dec sites): the dispatcher's enc!=0 twins = 0x212dc60 encrypt /
 * 0x212e950 encrypt_ctr32. THE PRIZE: the in-buffer = THE ENGINES'S OWN
 * APP MESSAGES IN THE CLEAR (the S2 'hello' = the in-channel 'k'-equi-
 * valent — run258 '51B tolerated hello'; run368: raw 'k' = 0x24 PARSE_
 * ERROR on BOTH lanes => the netmessage = the only language left). The
 * enc ABI = the same family as the dec (rdi=gcm rsi=in rdx=out rcx=len
 * r8=ctr). Sig E = the exact 26B twin of the DEC sig (the tail = sub
 * $0x68 vs $0x58 — byte-verified). Sig F = the 15B head (push r15; mov
 * %rsi,%r15; movabs $0xfffffffe0,%rsi — the boundary-safe edge; the dec
 * twin lacks the movabs = a distinct sig). Rate = the first 8 + every
 * 8th per fn (the self-sends = our krel/g98 = the same lib = the same
 * tap — the rate + the gcm tag keep the noise bounded). C2B_G126=0 off. */
#define G126_ENC_OFF    0x212dc60u   /* CRYPTO_gcm128_encrypt      */
#define G126_ENCC32_OFF 0x212e950u   /* CRYPTO_gcm128_encrypt_ctr32 */
static const u8 G126_ENC_SIG[26] = {
    0x41, 0x57,                          /* push %r15 */
    0x48, 0x89, 0xc8,                    /* mov %rcx,%rax (len) */
    0x49, 0x89, 0xd7,                    /* mov %rdx,%r15 (out) */
    0x41, 0x56,                          /* push %r14 */
    0x48, 0x89, 0xc2,                    /* mov %rax,%rdx */
    0x49, 0x89, 0xfe,                    /* mov %rdi,%r14 (gcm) */
    0x41, 0x55,                          /* push %r13 */
    0x41, 0x54,                          /* push %r12 */
    0x55,                                /* push %rbp */
    0x53,                                /* push %rbx */
    0x48, 0x83, 0xec, 0x68               /* sub $0x68,%rsp (the enc twin) */
};
static const u8 G126_ENCC32_SIG[15] = {
    0x41, 0x57,                          /* push %r15 */
    0x49, 0x89, 0xf7,                    /* mov %rsi,%r15 (in) */
    0x48, 0xbe, 0xe0, 0xff, 0xff, 0xff, 0x0f,
    0x00, 0x00, 0x00                     /* movabs $0xfffffffe0,%rsi */
};
static u8 g126_tramp_e[64] __attribute__((aligned(4096)));
static u8 g126_tramp_f[64] __attribute__((aligned(4096)));
static u32 g126_nenc;         /* the encrypt calls seen */
static u32 g126_nencc32;      /* the encrypt_ctr32 calls seen */
static u32 g126_prof_ec;      /* the enc-profile lines logged (cap 8) */
static u32 g126_prof_ecl;     /* the encc32-profile lines logged (cap 8) */

static void c2b_g126_enc_capture(void *gcm, const void *in, const void *out,
                                 sz_t len, i32 rc, u32 c32)
{
    u32 z;
    u8 bo[8];
    u32 n = c32 ? ++g126_nencc32 : ++g126_nenc;
    u32 *prof = c32 ? &g126_prof_ecl : &g126_prof_ec;
    if ((n & 0x07) != 1 && n > 8) return;
    if (len > 0x10000) return;    /* the junk guard */
    memcpy(bo, out, sizeof bo);
    if (*prof < 8) {
        (*prof)++;
        klog_s("[c2b] g126: ENC"); if (c32) klog_s("C32");
        klog_s("# prof n="); klog_h(n); klog_s("\n");
    }
    klog_s("[c2b] g126: ENC"); if (c32) klog_s("C32");
    klog_s(" n="); klog_h(n);
    klog_s(" len="); klog_h((u32)len);
    klog_s(" rc="); klog_h((u32)rc);
    klog_s(" gcm="); klog_p((uptr)gcm);
    if (in) {
        u32 hl = (u32)len < 96 ? (u32)len : 96;
        klog_s(" pt=");  /* THE PLAINTEXT (the app msgs in the clear) */
        for (z = 0; z < hl; z++) klog_h(((const u8 *)in)[z]);
    }
    klog_s(" ct="); klog_x(bo, 8);
    klog_s("\n");
}

/* SITE E = CRYPTO_gcm128_encrypt (the 4-arg non-stream path) */
static i32 c2b_g126_enc_detour(void *gcm, const void *in, void *out, sz_t len);
static i32 c2b_g126_enc_detour(void *gcm, const void *in, void *out, sz_t len)
{
    i32 (*tramp)(void *, const void *, void *, sz_t) =
        (i32 (*)(void *, const void *, void *, sz_t))g126_tramp_e;
    i32 rc = tramp(gcm, in, out, len);
    c2b_g126_enc_capture(gcm, in, out, len, rc, 0);
    return rc;
}
/* SITE F = CRYPTO_gcm128_encrypt_ctr32 (the 5-arg stream path = the SNP
 * fast path — the dispatcher's enc!=0 + stream!=0 = OUR outbound) */
static i32 c2b_g126_encc32_detour(void *gcm, const void *in, void *out,
                                  sz_t len, const void *ctrfn);
static i32 c2b_g126_encc32_detour(void *gcm, const void *in, void *out,
                                  sz_t len, const void *ctrfn)
{
    i32 (*tramp)(void *, const void *, void *, sz_t, const void *) =
        (i32 (*)(void *, const void *, void *, sz_t, const void *))
            g126_tramp_f;
    i32 rc = tramp(gcm, in, out, len, ctrfn);
    c2b_g126_enc_capture(gcm, in, out, len, rc, 1);
    return rc;
}

static void c2b_g126_patch(u8 *tgt, const u8 *sig, u32 siglen, u8 *tramp,
                           uptr detour, const char *name, u32 bit, uptr base)
{
    u32 k;

    if (memcmp(tgt, sig, siglen) != 0) {
        klog_s("[c2b] g126: SIG-MISMATCH ");
        klog_s(name);
        klog_s(" have=");
        klog_x(tgt, 16);
        klog_s("\n");
        return;
    }
    if (tgt[0] == 0xff) {           /* the already-patched */
        __atomic_or_fetch(&g126_patched, bit, __ATOMIC_RELAXED);
        return;
    }
    for (k = 0; k < siglen; k++) tramp[k] = tgt[k];
    {
        uptr da = (uptr)(tgt + siglen);
        tramp[siglen + 0] = 0xff; tramp[siglen + 1] = 0x25;
        tramp[siglen + 2] = 0; tramp[siglen + 3] = 0;
        tramp[siglen + 4] = 0; tramp[siglen + 5] = 0;
        for (k = 0; k < 8; k++) tramp[siglen + 6 + k] = (u8)(da >> (8 * k));
    }
    if (mprotect((void *)tramp, 4096,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        klog_s("[c2b] g126: tramp mprotect fail\n");
        return;
    }
    if (mprotect((void *)((uptr)tgt & ~(uptr)0xFFF), 0x2000,
                 PROT_READ | PROT_WRITE) != 0) {
        klog_s("[c2b] g126: site mprotect fail\n");
        return;
    }
    {
        uptr da = detour;
        tgt[0] = 0xff; tgt[1] = 0x25;
        tgt[2] = 0; tgt[3] = 0; tgt[4] = 0; tgt[5] = 0;
        for (k = 0; k < 8; k++) tgt[6 + k] = (u8)(da >> (8 * k));
        for (k = 14; k < siglen; k++) tgt[k] = 0x90;
    }
    if (mprotect((void *)((uptr)tgt & ~(uptr)0xFFF), 0x2000,
                 PROT_READ | PROT_EXEC) != 0) {
        klog_s("[c2b] g126: site mprotect RX fail\n");
    }
    __atomic_or_fetch(&g126_patched, bit, __ATOMIC_RELAXED);
    klog_s("[c2b] g126: PATCHED ");
    klog_s(name);
    klog_s(" base=");
    klog_p(base);
    klog_s(" pid=");
    klog_h((u32)getpid());
    klog_s("\n");
}

/* the maps-line match: 'steamclient.so' in the path part (14 chars) */
static i32 line_is_sc(const char *s, i32 n, uptr *out_lo)
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
            s[i + 12] == 's' && s[i + 13] == 'o' &&
            (i + 14 >= n || s[i + 14] != '2')) {   /* not steamclient2? */
            *out_lo = a;
            return 1;
        }
    }
    return 0;
}

static void *c2b_g126_watch(void *arg)
{
    int round;
    (void)arg;

    /* the game's steamclient.so = mapped at the boot (the run334 bins = the
     * game pid's dump) => the poll = short; 360 x 500ms = 3 min = the margin */
    for (round = 0; round < 360; round++) {
        i32 fdm = open("/proc/self/maps", O_RDONLY);
        char chunk[65536], line[4096];
        i32 llen = 0;
        uptr liblo = 0;
        ssz_t r;

        if ((g126_patched & 3) == 3) return (void *)0;
        if (fdm < 0) return (void *)0;
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
                if (j == (sz_t)r) break;
                i = j + 1;
                {
                    uptr a;
                    if (line_is_sc(line, llen, &a) &&
                        (!liblo || a < liblo)) liblo = a;
                }
                llen = 0;
            }
        }
        close(fdm);
        if (llen > 0) {
            uptr a;
            if (line_is_sc(line, llen, &a) && (!liblo || a < liblo))
                liblo = a;
        }
        if (!liblo) {
            struct timespec ts = { 0, 500000000 };
            nanosleep(&ts, 0);
            continue;
        }
        if (!(g126_patched & 1))
            c2b_g126_patch((u8 *)(liblo + G126_SETKEY_OFF), G126_SETKEY_SIG,
                           sizeof(G126_SETKEY_SIG), g126_tramp_a,
                           (uptr)&c2b_g126_setkey_detour, "setkey", 1,
                           liblo);
        if (!(g126_patched & 2))
            c2b_g126_patch((u8 *)(liblo + G126_SETIV_OFF), G126_SETIV_SIG,
                           sizeof(G126_SETIV_SIG), g126_tramp_b,
                           (uptr)&c2b_g126_setiv_detour, "setiv", 2,
                           liblo);
        /* v18-g126C/D: the decrypt taps (the bits 4/8) — the same recipe;
         * the sig-mismatch = the build drift = the skip (the log via the
         * patch fn), the A/B bits = still the exit anchor */
        if (!(g126_patched & 8))
            c2b_g126_patch((u8 *)(liblo + G126_DECC32_OFF), G126_DECC32_SIG,
                           sizeof(G126_DECC32_SIG), g126_tramp_d,
                           (uptr)&c2b_g126_decc32_detour, "decc32", 8,
                           liblo);
        if (!(g126_patched & 4))
            c2b_g126_patch((u8 *)(liblo + G126_DEC_OFF), G126_DEC_SIG,
                           sizeof(G126_DEC_SIG), g126_tramp_c,
                           (uptr)&c2b_g126_dec_detour, "dec", 4,
                           liblo);
        /* v31: the encrypt taps (bits 16/32) — the engine's own app msgs
         * in the clear (the S2 'hello' hunt; run368 verdict: the raw 'k'
         * = dead on both lanes => the netmessage = the only language). */
        if (!(g126_patched & 16))
            c2b_g126_patch((u8 *)(liblo + G126_ENC_OFF), G126_ENC_SIG,
                           sizeof(G126_ENC_SIG), g126_tramp_e,
                           (uptr)&c2b_g126_enc_detour, "enc", 16,
                           liblo);
        if (!(g126_patched & 32))
            c2b_g126_patch((u8 *)(liblo + G126_ENCC32_OFF), G126_ENCC32_SIG,
                           sizeof(G126_ENCC32_SIG), g126_tramp_f,
                           (uptr)&c2b_g126_encc32_detour, "encc32", 32,
                           liblo);
        if ((g126_patched & 3) == 3) return (void *)0;
        if (g126_patched) return (void *)0;
        return (void *)0;
    }
    if ((g126_patched & 3) != 3)
        klog_s("[c2b] g126: nomap 3min\n");
    return (void *)0;
}

/* ---------------- g128: THE CA-CERT TRUST-TABLE DIAG ----------------
 * THE RUN345 VERDICT (the rounds 2243->0008 worklog gap): the connect =
 * 14x PASS, the AUTHDIAG = the client cert = HEALTHY (avail=0x64=Current
 * msg="OK" @t10/t30, 'Certificate expires in 47h58m') — BUT the stdout =
 * THE REAL WALL:
 *   'problem detected locally (4003): Bad cert: CA key 13151444190962006299
 *    is not known to us' + '[ConnectOK] Ignored bad ... Failed crypto init.'
 * => the engine's GNS REJECTS the S2's ConnectOK (the server cert = signed
 * by the CA key NOT in the client's trusted-CA table) => the connection =
 * dead at the crypto-init => the C2S_CONNECT 'k' = never built => THE
 * APP-LEVEL SIGNON STALL = THE CERT-TRUST WALL.
 * THE RE (g124-re/sc_cert_re*.py, the d975c5 build): the check fn =
 * steamclient.so @0x1fe80a0 (the 33B prologue-sig), the fail-tail = the
 * 'CA key %llu is not known to us' string-lea (the ONLY xref @0x1fe8271),
 * the return = 0=fail / the nonnull key-struct=ok (the caller @0x1fe83e8:
 * test rax,rax; je = the kill-path). THE TABLE = the rip-rel globals:
 *   fn+0x5a: 8b 05 d32 -> GATE   @+0x2c4bba4 (0 = the list never loaded)
 *   fn+0x68: 8b 05 d32 -> COUNT  @+0x2c4bb70
 *   fn+0x73: 4c 8d 3d d32 -> IDXARR @+0x2c4bb60 (the s32 index-array ptr)
 *   fn+0x9b: 48 8b 15 d32 -> KEYTBL @+0x2c4bb90 (the 24B-stride entries:
 *              [0]=the CA-key u64, [8]=the pubkey obj, [0x10]=the chain)
 * THE DIAG = read-only, the 12 polls @15s (the table = populated by the
 * network-config load = the timing = unknown), the exec-seg sig-scan
 * (the 39B fail-tail, the 2x disp32 wildcards + the STRING-VERIFY = the
 * build-independent confirmation), the entries-dump (<=12 CA-key u64s).
 * THE VERDICT-MATRIX: the GATE=0/COUNT=0 => the table never populated =>
 * the fix = the network-config-fetch hunt; the COUNT>0 && no the S2's key
 * 0xb68350cff5aa391b => the fix = the entry-injection + the sig-verify
 * bypass (the call @fn+0x126 = the crypto-verify, 0=ok). The killswitch =
 * C2B_G128=0. */
static const u8 G128_TAIL_A[8] = {
    0x48, 0x8b, 0x7c, 0x24, 0x08,       /* mov 0x8(%rsp),%rdi */
    0x48, 0x8d, 0x35                    /* lea disp32(%rip),%rsi */
};
static const u8 G128_TAIL_B[6] = {
    0x4c, 0x89, 0xe2,                   /* mov %r12,%rdx */
    0x31, 0xc0,                         /* xor %eax,%eax */
    0xe8                                /* call rel32 */
};
static const u8 G128_TAIL_C[17] = {
    0x31, 0xc0,                         /* xor %eax,%eax (the 0=fail ret) */
    0x48, 0x83, 0xc4, 0x28,             /* add $0x28,%rsp */
    0x5b, 0x5d,                         /* pop %rbx,%rbp */
    0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, /* pop %r12-%r15 */
    0xc3                                /* ret */
};
static const u8 G128_PRO[33] = {
    0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, /* push %r15..%r12 */
    0x49, 0x89, 0xf4,                   /* mov %rsp,%r12 */
    0x55,                               /* push %rbp */
    0x48, 0x89, 0xfd,                   /* mov %rdi,%rbp */
    0x53,                               /* push %rbx */
    0x48, 0x89, 0xd3,                   /* mov %rdx,%rbx */
    0x48, 0x83, 0xec, 0x28,             /* sub $0x28,%rsp */
    0x48, 0x89, 0x4c, 0x24, 0x18,       /* mov %rcx,0x18(%rsp) */
    0x4c, 0x89, 0x44, 0x24, 0x08        /* mov %r8,0x8(%rsp) */
};

static void c2b_g128_report(u8 *lo, uptr span, u32 pass)
{
    uptr i;
    u8 *p, *fn = 0;
    i32 disp;
    const u8 *s;
    u32 back;
    uptr idxarr = 0, keytbl = 0;
    u32 count = 0;

    for (i = 0; i + 40 < span; i++) {
        p = lo + i;
        if (p[0] != 0x48 || p[5] != 0x48 || p[6] != 0x8d) continue;
        if (memcmp(p, G128_TAIL_A, 8) != 0) continue;
        if (memcmp(p + 12, G128_TAIL_B, 6) != 0) continue;
        if (memcmp(p + 22, G128_TAIL_C, 17) != 0) continue;
        memcpy(&disp, p + 8, 4);
        s = (const u8 *)((uptr)(p + 12) + (uptr)(i32)disp);
        if (memcmp(s, "CA key %llu is not known to us", 30) != 0) continue;
        for (back = 0; back < 0x800; back++) {
            u8 *q = p + 5 - back;
            if (memcmp(q, G128_PRO, 33) == 0) { fn = q; break; }
        }
        klog_s("[c2b] g128: SITE str=");
        klog_p((uptr)s);
        klog_s(" fn=");
        if (fn) klog_h((u32)((uptr)fn - (uptr)lo));
        else klog_s("nofn");
        klog_s(" pass=");
        klog_h(pass);
        klog_s("\n");
        if (!fn) return;
        /* the 4 rip-rel globals: the FIXED fn-rel offs + the SHAPE-check */
        {
            struct { u32 at; const u8 *sh; u32 shlen; const char *nm; } G[4] = {
                { 0x5a, (const u8 *)"\x8b\x05", 2, "GATE" },
                { 0x68, (const u8 *)"\x8b\x05", 2, "COUNT" },
                { 0x73, (const u8 *)"\x4c\x8d\x3d", 3, "IDXARR" },
                { 0x9b, (const u8 *)"\x48\x8b\x15", 3, "KEYTBL" }
            };
            u32 gi;
            for (gi = 0; gi < 4; gi++) {
                u8 *ip = fn + G[gi].at;
                i32 d2;
                uptr tgt;
                if (memcmp(ip, G[gi].sh, G[gi].shlen) != 0) {
                    klog_s("[c2b] g128: SHAPE-MISMATCH ");
                    klog_s(G[gi].nm);
                    klog_s(" have=");
                    klog_x(ip, 8);
                    klog_s("\n");
                    continue;
                }
                memcpy(&d2, ip + G[gi].shlen, 4);
                tgt = (uptr)ip + G[gi].shlen + 4 + (uptr)(i32)d2;
                /* NO window-check: the globals = in .data/.bss = OUTSIDE
                 * the exec-seg (the validator: the GATE @+0x2cbbba4 vs the
                 * exec-end @+0x2ae14bf) — the SHAPE-match + the SITE
                 * string-verify = the guards (the disp32 = the verified
                 * compiler-emit). The klog = the module-rel via the fn. */
                klog_s("[c2b] g128: ");
                klog_s(G[gi].nm);
                klog_s(" @+");
                klog_h((u32)(tgt - (uptr)fn));
                if (gi == 0) {
                    u32 v = *(volatile u32 *)tgt;
                    klog_s(" =");
                    klog_h(v);
                } else if (gi == 1) {
                    count = *(volatile u32 *)tgt;
                    klog_s(" =");
                    klog_h(count);
                } else if (gi == 2) {
                    idxarr = *(volatile uptr *)tgt;
                    klog_s(" =");
                    klog_p(idxarr);
                } else {
                    keytbl = *(volatile uptr *)tgt;
                    klog_s(" =");
                    klog_p(keytbl);
                }
                klog_s("\n");
            }
        }
        if (idxarr && keytbl && count && count < 0x1000) {
            u32 e;
            for (e = 0; e < count && e < 12; e++) {
                i32 idx;
                u64 key;
                memcpy(&idx, (const void *)(idxarr + 4u * e), 4);
                if (idx < 0 || idx > 0x10000) continue;
                memcpy(&key, (const void *)(keytbl + 24u * (u32)idx), 8);
                klog_s("[c2b] g128: CAKEY[");
                klog_h(e);
                klog_s("] idx=");
                klog_h((u32)idx);
                klog_s(" key=");
                klog_h((u32)(key >> 32));
                klog_h((u32)key);
                klog_s("\n");
            }
        }
        return;   /* the site = unique (the single string-xref) */
    }
    klog_s("[c2b] g128: nosite pass=");
    klog_h(pass);
    klog_s("\n");
}

static void *c2b_g128_watch(void *arg)
{
    u32 poll;
    (void)arg;
    for (poll = 1; poll <= 12; poll++) {
        char buf[131072];
        i32 fd = open("/proc/self/maps", O_RDONLY);
        i32 n;
        char *s;
        u32 done = 0;

        if (fd < 0) return 0;
        n = (i32)read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) return 0;
        buf[n] = 0;
        s = buf;
        while (s && *s && !done) {
            char *e = strchr(s, '\n');
            uptr a = 0, b = 0;
            i32 k = 0;
            int isx = 0;
            /* the maps-line: start-end perms ... path */
            while (s[k] && s[k] != '-') {
                char c = s[k];
                if (c >= '0' && c <= '9') a = (a << 4) | (uptr)(c - '0');
                else if (c >= 'a' && c <= 'f') a = (a << 4) | (uptr)(c - 'a' + 10);
                else break;
                k++;
            }
            if (s[k] == '-') {
                k++;
                while (s[k] && s[k] != ' ') {
                    char c = s[k];
                    if (c >= '0' && c <= '9') b = (b << 4) | (uptr)(c - '0');
                    else if (c >= 'a' && c <= 'f') b = (b << 4) | (uptr)(c - 'a' + 10);
                    else break;
                    k++;
                }
                if (s[k] == ' ' && b > a) {
                    /* the perms = r w x p: the x = @k+3 */
                    isx = (s[k + 3] == 'x');
                    if (isx) {
                        i32 j;
                        for (j = k; s[j] && s[j] != '\n'; j++) {
                            if (s[j] == 's' && s[j + 1] == 't' &&
                                s[j + 2] == 'e' && s[j + 3] == 'a' &&
                                s[j + 4] == 'm' && s[j + 5] == 'c' &&
                                s[j + 6] == 'l' && s[j + 7] == 'i' &&
                                s[j + 8] == 'e' && s[j + 9] == 'n' &&
                                s[j + 10] == 't' && s[j + 11] == '.' &&
                                s[j + 12] == 's' && s[j + 13] == 'o' &&
                                s[j + 14] != '2') {
                                c2b_g128_report((u8 *)a, b - a, poll);
                                done = 1;
                                break;
                            }
                        }
                    }
                }
            }
            s = e ? e + 1 : 0;
        }
        if (done && poll >= 4) return 0;  /* the repeats = the count-change watch */
        {
            struct timespec ts = { 15, 0 };
            nanosleep(&ts, 0);
        }
    }
    klog_s("[c2b] g128: exhausted 3min\n");
    return 0;
}
#endif  /* __x86_64__ */

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
#if defined(__x86_64__)
    /* g115: the GAME-side scan — the 64-bit hook = preloaded into the
     * game (csgo_linux64 = THE SDR socket owner + THE SNS crypto home =
     * the run323 ss_udp_all proof: 'UNCONN 0.0.0.0:51253 *:* users:((
     * "csgo_linux64",pid=6219,fd=56))'). The 64-bit = NEVER patched
     * (the site = the 32-bit core's ChaCha20) => the post-PATCH spawn
     * = never fires here => the constructor spawn = REQUIRED. The
     * trigger = the C2B_G113_GO go-file (the harness = touches it at
     * the connect fire); no env = the flow mode = a no-op in the game
     * (the unconnected rem = invisible) = zero idle duty. */
    {
        pthread_t t13;
        if (pthread_create(&t13, 0, c2b_g113_thread, 0) == 0)
            pthread_detach(t13);
        else
            klog_s("[c2b] g113: pthread_create FAILED (game)\n");
    }
    /* g124: the LIVE-INTERCEPT watcher (the AES-GCM init capture) —
     * independent of the go-file: the patch = ASAP (the SNS lib = mapped
     * at the boot; the session init = at the connect). The killswitch =
     * C2B_G124=0. */
    {
        const char *e24 = (const char *)getenv("C2B_G124");
        if (!(e24 && e24[0] == '0')) {
            pthread_t t24;
            if (pthread_create(&t24, 0, c2b_g124_watch, 0) == 0)
                pthread_detach(t24);
            else
                klog_s("[c2b] g124: pthread_create FAILED\n");
        }
    }
    /* g126: the TRUE CRYPTO HOME watcher (the game's steamclient.so: the
     * setkey @0x201d780 + the setiv @0x212d6c0 = the run334 verdict: the
     * cb0ca8 SNS OpenSSL = the decoy). The killswitch = C2B_G126=0. */
    {
        const char *e26 = (const char *)getenv("C2B_G126");
        if (!(e26 && e26[0] == '0')) {
            pthread_t t26;
            if (pthread_create(&t26, 0, c2b_g126_watch, 0) == 0)
                pthread_detach(t26);
            else
                klog_s("[c2b] g126: pthread_create FAILED\n");
        }
    }
    /* g128: the CA-TRUST-TABLE diag (the run345 verdict: the 'Bad cert: CA
     * key ... is not known to us' = THE signon wall). The killswitch =
     * C2B_G128=0. */
    {
        const char *e28 = (const char *)getenv("C2B_G128");
        if (!(e28 && e28[0] == '0')) {
            pthread_t t28;
            if (pthread_create(&t28, 0, c2b_g128_watch, 0) == 0)
                pthread_detach(t28);
            else
                klog_s("[c2b] g128: pthread_create FAILED\n");
        }
    }
#endif
}
