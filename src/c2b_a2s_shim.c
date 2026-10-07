/* c2b_a2s_shim.c — 41e-k: минимальный LD_PRELOAD-шим для STEAM-КЛИЕНТА.
 *
 * ЗАЧЕМ (run 85): A2S_INFO-запрос в connect-флоу делает НЕ движок, а
 * steam-клиент (SteamMatchMakingServers проксирует UDP через клиентский
 * процесс) — LD_PRELOAD в движок этот трафик НЕ видит (в хуках моста
 * ноль 'T'). Ферма (runs 57/60/68 + run 70/71 lessons) доказала:
 * продолжение connect-потока требует serverinfo БЕЗ EDF-хвоста, с
 * appid u16=730 (appid владельца клиента) и версией БАНДЛА. Реальный
 * CS2-сервер шлёт EDF + версию 1.41.8.8 -> тихий abort на
 * INGAME->MAINMENU без 'j'.
 *
 * ЧТО: интерпозеры sendto/recvfrom/sendmsg/recvmsg (libc), которые:
 *   - на 'T'-запросе (ffffffff 54 "Source Engine Query" 00) запоминают
 *     адрес назначения (таблица из 4 peer, LRU);
 *   - на 'I'-ответе (ffffffff 49) С ЗАПОМНЕННОГО peer перестраивают
 *     пакет: срезают EDF-хвост, патчат appid=730, подставляют версию из
 *     C2B_A2S_VERSION (формат парсера 1:1 с src/c2bridge.c
 *     c2b_a2s_transform_i и tools/fake_s1_server.py).
 *
 * Остальной UDP — чистый passthrough. Без потоков, без детуров, без
 * зависимости от движка. Сборка:
 *   gcc -O2 -shared -fPIC -o c2b_a2s_shim.so c2b_a2s_shim.c -ldl
 *
 * Лог (опционально): C2B_A2S_LOG=/path/file — события добавляются туда
 * (stdout steam-клиента не трогаем). */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

typedef uint8_t  u8;
typedef uint32_t u32;

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *)-1L)
#endif

typedef ssize_t (*s2t_fn)(int, const void *, size_t, int,
                          const struct sockaddr *, socklen_t);
typedef ssize_t (*r2f_fn)(int, void *, size_t, int,
                          struct sockaddr *, socklen_t *);
typedef ssize_t (*smg_fn)(int, const struct msghdr *, int);
typedef ssize_t (*rmg_fn)(int, struct msghdr *, int);

static void *g_s2t, *g_r2f, *g_smg, *g_rmg;

#define SHIM_PEERS 4
static u8 g_peer[SHIM_PEERS][16];
static socklen_t g_peerlen[SHIM_PEERS];
static u32 g_peer_ok[SHIM_PEERS];      /* слот занят */
static u32 g_peer_rr;                  /* следующий слот для записи (LRU-деш) */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static char g_ver[24] = "1.38.0.4";    /* C2B_A2S_VERSION */
static char g_log[256];                /* C2B_A2S_LOG */
static u32 g_inited;

static void shim_init(void)
{
    const char *e;
    if (g_inited) return;
    pthread_mutex_lock(&g_mu);
    if (!g_inited) {
        e = getenv("C2B_A2S_VERSION");
        if (e && e[0]) {
            u32 i;
            for (i = 0; e[i] && i < sizeof(g_ver) - 1; i++) g_ver[i] = e[i];
            g_ver[i] = 0;
        }
        e = getenv("C2B_A2S_LOG");
        if (e && e[0]) {
            u32 i;
            for (i = 0; e[i] && i < sizeof(g_log) - 1; i++) g_log[i] = e[i];
            g_log[i] = 0;
        }
        g_inited = 1;
    }
    pthread_mutex_unlock(&g_mu);
}

static void slog(const char *a, const char *b, long n)
{
    FILE *f;
    char buf[64];
    time_t t = time(0);
    struct tm tmv;
    if (!g_log[0]) return;
    localtime_r(&t, &tmv);
    strftime(buf, sizeof(buf), "%H:%M:%S", &tmv);
    f = fopen(g_log, "a");
    if (!f) return;
    fprintf(f, "[%s] %s%s", buf, a, b ? b : "");
    if (n >= 0) fprintf(f, " %ld", n);
    fprintf(f, "\n");
    fclose(f);
}

/* ---- A2S 'I' трансформ (порт из c2bridge.c 41e-j) ---- */
static u32 shim_transform_i(const unsigned char *in, u32 n,
                            unsigned char *out, u32 cap)
{
    u32 i, j, apid, olen;
    if (n < 40 || n > 1400 || cap < n + 32) return 0;
    if (in[0] != 0xff || in[1] != 0xff || in[2] != 0xff || in[3] != 0xff)
        return 0;
    if (in[4] != 'I') return 0;
    i = 6;
    for (j = 0; j < 4; j++) {
        u32 sl = 0;
        while (i < n && in[i] != 0) {
            i++;
            if (++sl > 256) return 0;
        }
        if (i >= n) return 0;
        i++;
    }
    if (i + 2 + 7 > n) return 0;
    apid = i;
    i += 2 + 7;
    if (i >= n) return 0;
    {
        u32 vend = i;
        while (vend < n && in[vend] != 0) {
            vend++;
            if (vend - i > 32) return 0;
        }
        if (vend >= n) return 0;
    }
    olen = 0;
    out[olen++] = 0xff; out[olen++] = 0xff; out[olen++] = 0xff; out[olen++] = 0xff;
    for (i = 4; i < apid; i++) out[olen++] = in[i];
    out[olen++] = 0xda; out[olen++] = 0x02;              /* appid = 730 */
    for (i = apid + 2; i < apid + 2 + 7; i++) out[olen++] = in[i];
    for (i = 0; g_ver[i] != 0; i++) out[olen++] = (unsigned char)g_ver[i];
    out[olen++] = 0;
    return olen;
}

static int peer_known(const struct sockaddr *a, socklen_t al)
{
    u32 i;
    int hit = -1;
    if (!a || al == 0 || al > 16) return -1;
    pthread_mutex_lock(&g_mu);
    for (i = 0; i < SHIM_PEERS; i++) {
        if (g_peer_ok[i] && g_peerlen[i] == al &&
            memcmp(g_peer[i], a, al) == 0) { hit = (int)i; break; }
    }
    pthread_mutex_unlock(&g_mu);
    return hit;
}

static void peer_record(const struct sockaddr *a, socklen_t al)
{
    u32 i;
    if (!a || al == 0 || al > 16) return;
    pthread_mutex_lock(&g_mu);
    for (i = 0; i < SHIM_PEERS; i++) {
        if (g_peer_ok[i] && g_peerlen[i] == al &&
            memcmp(g_peer[i], a, al) == 0) {
            pthread_mutex_unlock(&g_mu);
            return;                                       /* уже знаем */
        }
    }
    i = g_peer_rr % SHIM_PEERS;
    g_peer_rr++;
    memcpy(g_peer[i], a, al);
    g_peerlen[i] = al;
    g_peer_ok[i] = 1;
    pthread_mutex_unlock(&g_mu);
    slog("shim: A2S 'T' peer recorded #", "", (long)(g_peer_rr));
}

static int is_connless_t(const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    return len > 6 && p[0] == 0xff && p[1] == 0xff && p[2] == 0xff &&
           p[3] == 0xff && p[4] == 'T';
}

static int is_connless_i(const void *buf, ssize_t r)
{
    const unsigned char *p = (const unsigned char *)buf;
    return r > 10 && p[0] == 0xff && p[1] == 0xff && p[2] == 0xff &&
           p[3] == 0xff && p[4] == 'I';
}

__attribute__((visibility("default")))
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *addr, socklen_t addrlen)
{
    if (!g_s2t) {
        void *f = dlsym(RTLD_NEXT, "sendto");
        if (!f) { *__errno_location() = 2; return -1; }
        g_s2t = f;
    }
    shim_init();
    if (addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) &&
        is_connless_t(buf, len))
        peer_record(addr, addrlen);
    return ((s2t_fn)g_s2t)(fd, buf, len, flags, addr, addrlen);
}

__attribute__((visibility("default")))
ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *addr, socklen_t *addrlen)
{
    ssize_t r;
    if (!g_r2f) {
        void *f = dlsym(RTLD_NEXT, "recvfrom");
        if (!f) { *__errno_location() = 2; return -1; }
        g_r2f = f;
    }
    shim_init();
    r = ((r2f_fn)g_r2f)(fd, buf, len, flags, addr, addrlen);
    if (r > 0 && addr && is_connless_i(buf, r) && peer_known(addr, *addrlen) >= 0) {
        unsigned char tmp[1200];
        u32 nl = shim_transform_i((const unsigned char *)buf, (u32)r,
                                  tmp, (u32)sizeof(tmp));
        if (nl && (size_t)len >= nl) {
            memcpy(buf, tmp, nl);
            slog("shim: 'I' transformed ", g_ver, (long)r);
            return (ssize_t)nl;
        }
    }
    return r;
}

__attribute__((visibility("default")))
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
    if (!g_smg) {
        void *f = dlsym(RTLD_NEXT, "sendmsg");
        if (!f) { *__errno_location() = 2; return -1; }
        g_smg = f;
    }
    shim_init();
    if (msg && msg->msg_name && msg->msg_namelen &&
        msg->msg_iov && msg->msg_iov[0].iov_base &&
        is_connless_t(msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len))
        peer_record((const struct sockaddr *)msg->msg_name, msg->msg_namelen);
    return ((smg_fn)g_smg)(fd, msg, flags);
}

__attribute__((visibility("default")))
ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
    ssize_t r;
    if (!g_rmg) {
        void *f = dlsym(RTLD_NEXT, "recvmsg");
        if (!f) { *__errno_location() = 2; return -1; }
        g_rmg = f;
    }
    shim_init();
    r = ((rmg_fn)g_rmg)(fd, msg, flags);
    if (r > 0 && msg && msg->msg_name && msg->msg_namelen &&
        msg->msg_iov && msg->msg_iov[0].iov_base &&
        is_connless_i(msg->msg_iov[0].iov_base, r) &&
        peer_known((const struct sockaddr *)msg->msg_name, msg->msg_namelen) >= 0) {
        unsigned char tmp[1200];
        u32 nl = shim_transform_i((const unsigned char *)msg->msg_iov[0].iov_base,
                                  (u32)r, tmp, (u32)sizeof(tmp));
        if (nl && msg->msg_iov[0].iov_len >= nl) {
            memcpy(msg->msg_iov[0].iov_base, tmp, nl);
            slog("shim(recvmsg): 'I' transformed ", g_ver, (long)r);
            return (ssize_t)nl;
        }
    }
    return r;
}
