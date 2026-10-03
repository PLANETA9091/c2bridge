/* c2b_spy.c v2 — t39: перехватчик фатального spew движка (диагностический).
 *
 * Проблема: RC=139 = SEGV внутри Plat_ExitProcess после Error(); текст
 * сообщения Error() в stderr/log прогона НЕ попадает (custom spew-handler
 * движка глотает spew при отсутствии консоли).
 *
 * v2 (после инцидента прогона 27.09: SDL позвал Msg до загрузки tier0 ->
 * dlsym(RTLD_NEXT)=NULL -> _exit(99) убил движок на старте):
 *   1) резолв оригинала: dl_iterate_phdr -> база libtier0_client.so +
 *      офсеты dynsym (nm -D 27.09: Error=0xe350, Msg=0xdf70,
 *      Warning=0xe0c0, Plat_ExitProcess=0x12c00); dlsym — фолбэк;
 *   2) БЕЗ exit при ненайденном оригинале: Msg/Warning -> молча вернуть
 *      (сообщение уже в spy.log), Error -> _exit(1) (контракт фатальности),
 *      Plat_ExitProcess -> _exit(code);
 *   3) для Error/Plat_ExitProcess логируется МОДУЛЬ+СМЕЩЕНИЕ вызывающего
 *      (__builtin_return_address -> dlpi_name+off) — точный call-site;
 *   4) анти-спам: максимум 4096 записей Msg/Warning на процесс.
 *
 * Сборка: gcc -shared -fPIC -O2 c2b_spy.c -o c2b_spy64.so -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#define SPY_PATH "/tmp/c2b/spy.log"
#define SPY_MAXLINES 4096

/* офсеты dynsym libtier0_client.so (проверены nm -D на билде владельца) */
#define OFF_ERROR 0xe350u
#define OFF_MSG   0xdf70u
#define OFF_WARN  0xe0c0u
#define OFF_EXIT  0x12c00u

static long g_lines;            /* анти-спам */
static long g_misses;           /* стоп ретраев после 64 неудач */

static int phdr_cb(struct dl_phdr_info *info, size_t sz, void *data)
{
    (void)sz;
    if (info->dlpi_name && strstr(info->dlpi_name, "libtier0_client.so")) {
        *(uintptr_t *)data = info->dlpi_addr;
        return 1;
    }
    return 0;
}

static uintptr_t tier0_base(void)
{
    uintptr_t b = 0;
    dl_iterate_phdr(phdr_cb, &b);
    return b;
}

struct caller_ctx { uintptr_t a; char *out; unsigned cap; };

static int caller_cb(struct dl_phdr_info *info, size_t sz, void *data)
{
    (void)sz;
    struct caller_ctx *ctx = (struct caller_ctx *)data;
    uintptr_t base = info->dlpi_addr;
    uintptr_t end = base;
    int i;
    for (i = 0; i < info->dlpi_phnum; i++)
        if (info->dlpi_phdr[i].p_type == PT_LOAD) {
            uintptr_t e = base + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
            if (e > end) end = e;
        }
    if (ctx->a >= base && ctx->a < end && info->dlpi_name && info->dlpi_name[0]) {
        snprintf(ctx->out, ctx->cap, "%s+0x%lx", info->dlpi_name,
                 (unsigned long)(ctx->a - base));
        return 1;
    }
    return 0;
}

static void caller_mod(void *ra, char *out, unsigned cap)
{
    uintptr_t a = (uintptr_t)ra;
    out[0] = 0;
    if (!a) return;
    struct caller_ctx ctx = { a, out, cap };
    dl_iterate_phdr(caller_cb, &ctx);
}

static void spy_emit(const char *tag, const char *msg, int to_stderr)
{
    char buf[4096];
    int n = snprintf(buf, sizeof buf, "[c2b-spy][%s] %s\n", tag, msg);
    if (n <= 0) return;
    if (to_stderr) (void)!write(2, buf, (size_t)n);
    if (g_lines >= SPY_MAXLINES) return;
    g_lines++;
    int fd = open(SPY_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    if (fd >= 0) { (void)!write(fd, buf, (size_t)n); close(fd); }
}

typedef void (*fn_var)(const char *, ...);

/* резолв: сперва phdr-база+офсет (работает и для RTLD_LOCAL tier0),
 * затем dlsym(RTLD_NEXT); NULL кешируем не более 64 неудач подряд */
static fn_var lookup_var(const char *sym, uintptr_t off, int cache_null)
{
    static fn_var f;
    if (f) return f;
    uintptr_t b = tier0_base();
    if (b) { f = (fn_var)(b + off); return f; }
    if (g_misses < 64) {
        g_misses++;
        fn_var d = (fn_var)dlsym(RTLD_NEXT, sym);
        if (d) { f = d; return d; }
        (void)cache_null;
    }
    return NULL;
}

void Error(const char *fmt, ...)
{
    char msg[3072], cs[256];
    caller_mod(__builtin_return_address(0), cs, sizeof cs);
    va_list ap; va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    char full[3328];
    snprintf(full, sizeof full, "%s (caller=%s)", msg, cs);
    spy_emit("Error", full, 1);
    fn_var real = lookup_var("Error", OFF_ERROR, 0);
    if (real) real("%s", msg);
    else _exit(1);
}

void Warning(const char *fmt, ...)
{
    char msg[3072];
    va_list ap; va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    spy_emit("Warning", msg, 0);
    fn_var real = lookup_var("Warning", OFF_WARN, 0);
    if (real) real("%s", msg);   /* не нашли — сообщение уже в spy.log, молча вернуться */
}

void Msg(const char *fmt, ...)
{
    char msg[3072];
    va_list ap; va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    spy_emit("Msg", msg, 0);
    fn_var real = lookup_var("Msg", OFF_MSG, 0);
    if (real) real("%s", msg);   /* не нашли — молча вернуться (v2: без exit) */
}

void Plat_ExitProcess(int code)
{
    char msg[256], cs[256];
    caller_mod(__builtin_return_address(0), cs, sizeof cs);
    snprintf(msg, sizeof msg, "Plat_ExitProcess(code=%d) caller=%s", code, cs);
    spy_emit("Exit", msg, 1);
    void (*real)(int) = NULL;
    uintptr_t b = tier0_base();
    if (b) real = (void (*)(int))(b + OFF_EXIT);
    else real = (void (*)(int))dlsym(RTLD_NEXT, "Plat_ExitProcess");
    if (real) real(code);
    else _exit(code ? code : 99);
}
