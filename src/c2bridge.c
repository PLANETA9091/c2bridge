/* c2bridge.c — STEP E: каркас транслятора S2->S1 для CS:GO-клиента (Source 1).
 *
 * Механизм:
 *   1. LD_PRELOAD (i386) -> dl_iterate_phdr -> base(engine_client.so)
 *   2. Детур CNetChan::ProcessMessages @ engine+0x528bc0 (push/ret, трамплин)
 *   3. v0 hook = OBSERVER: лог bf_read-стата + hexdump, вызов оригинала.
 *      Транслятор (ренумерация + дроп) готов и покрыт selftest'ом; включение
 *      в живой путь — v1 после подтверждения конверта логами v0.
 *
 * Сборка:
 *   i386 .so (для игры): gcc -m32 -shared -fPIC -nostartfiles -nostdlib
 *                        -fno-stack-protector -DC2B_PRELOAD c2bridge.c -o c2bridge.so
 *   selftest (sandbox):  gcc -DC2B_SELFTEST c2bridge.c -o selftest
 *
 * Проверенные факты (worklog Task 4 + дизасм):
 *   - байты @0x528bc0: 55 89 e5 57 56 53 81 ec 8c 00 00 00 | 0f b6 45 10 ...
 *     граница инструкций после 12 байт (objdump: next = movzx eax,[ebp+0x10])
 *   - конвенция cdecl: стековые аргументы (this@+8, bf_read*@+0xC, flag@+0x10),
 *     подтверждено диспетчером @0x5292d0 (call 528bc0, args через mov [esp+N])
 *   - bf_read CS:GO (i386): m_pDebugName@0, m_bOverflow@4, m_nDataBits@8,
 *     m_nDataBytes@C, m_nInBufWord@10, m_nBitsAvail@14, m_pDataIn@18,
 *     m_iCurBit@1C, m_pBuffer@20, m_pDataEnd@24 — выверено дизасмом 0x528bc0
 *
 * Гипотеза конверта (проверяется v0-логами): сообщения потока =
 * varint type, varint len, payload (byte-aligned). NET 0..7 identity;
 * SVC ренумерация по s2s1_tables.h; S2-only — дроп.
 */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef int            i32;
typedef long long      i64;
typedef unsigned long long u64;
#ifdef __x86_64__
typedef unsigned long  uptr;
#else
typedef unsigned int   uptr;
#endif

#ifdef C2B_SELFTEST
/* ---------- режим selftest: нормальная libc ---------- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
static void c2b_segv(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)uc;
    printf("\n!! SIGSEGV at %p\n", si->si_addr);
    _exit(86);
}
#define C2B_LOGS(s) do { printf("%s", s); } while (0)
#define C2B_LOGH(v) do { printf("0x%x ", (unsigned)(v)); } while (0)
#define C2B_LOGN(v) do { printf("%u ", (unsigned)(v)); } while (0)
#define C2B_LOGD(v) do { printf("%u ", (unsigned)(v)); } while (0)
#else
/* ---------- режим .so: только объявления, резолв через ld.so ---------- */
extern void *mmap(void *addr, u32 len, i32 prot, i32 flags, i32 fd, u32 off);
extern i32   mprotect(void *addr, u32 len, i32 prot);
extern void *memcpy(void *d, const void *s, u32 n);
extern i32   memcmp(const void *a, const void *b, u32 n);
extern void *memset(void *d, i32 c, u32 n);
extern u32   strlen(const char *s);
extern i32   write(i32 fd, const void *buf, u32 n);
extern i32   dl_iterate_phdr(i32 (*cb)(void *info, void *size, void *data), void *data);
extern i32   usleep(u32 usec);
extern i32   pthread_create(void *t, const void *a, void *(*fn)(void *), void *arg);
extern char *getenv(const char *name);
extern i32   strcmp(const char *a, const char *b);   /* t39: GC policy lookup */
extern i32   clock_gettime(i32 clk, void *ts);   /* 41e-m: monotonic ms для темпа INFO-PUSH */
extern i32   __sigsetjmp(void *buf, i32 savemask);   /* 41f-c: SEGV-защита probe */
extern void  siglongjmp(void *buf, i32 val);
extern i32   sigaction(i32 sig, const void *act, void *oldact);
extern i32   sigemptyset(void *set);   /* маска sa_mask */
extern i64   pread(i32 fd, void *buf, uptr n, uptr off);   /* g24 v4.2: ssize_t/size_t/off_t = 64-bit */
extern i32   vsnprintf(char *s, uptr n, const char *fmt, void *va);   /* g34v2: GNS lib-spew hook */

static int g_logfd = 2;

/* R30: line-буфер — один write() на строку. Слив по '\n' или при переполнении.
 * R39/R40 (t35): строка лога до 4096 (пути/дампы длиннее SNM-hist 1КБ) и
 * __thread: у ctor, poll-потока, PM/SNM-хуков и dtor — СВОЙ буфер, нет гонки
 * на общем g_lbuf (доказанные ≥3 потока: rival-счётчик R29). Цена: ~4.1К
 * .tbss на поток, файл .so не растёт. Все боевые сайты заканчиваются '\n' —
 * недофлашенные хвосты чужих потоков теряемы, что эквивалентно старому
 * поведению при крахе потока. */
static __thread char g_lbuf[4096];
static __thread u32  g_lbuf_n;
static void c2b_flush(void)
{
    if (g_lbuf_n) { write(g_logfd, g_lbuf, g_lbuf_n); g_lbuf_n = 0; }
}
static void c2b_out(const char *s, u32 n)
{
    while (n) {
        u32 room = (u32)sizeof(g_lbuf) - g_lbuf_n;
        u32 take = n < room ? n : room;
        memcpy(g_lbuf + g_lbuf_n, s, take);
        g_lbuf_n += take; s += take; n -= take;
        if (g_lbuf_n >= (u32)sizeof(g_lbuf)) { c2b_flush(); continue; }
        if (g_lbuf[g_lbuf_n - 1] == '\n') c2b_flush();
    }
}
static void c2b_log(const char *s) { u32 l = 0; while (s[l]) l++; c2b_out(s, l); }
static void c2b_log_hex(u32 v)
{
    char b[11]; b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 8; i++) {
        u32 nib = (v >> (28 - i * 4)) & 0xF;
        b[2 + i] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
    }
    b[10] = ' '; c2b_out(b, 11);
}
static void c2b_log_dec(u32 v)   /* R37 (t35): десятичная телеметрия (si-строка) */
{
    char b[12]; u32 n = 0;
    do { b[9 - n] = (char)('0' + v % 10); v /= 10; n++; } while (v);
    b[10] = ' '; c2b_out(b + 10 - n, n + 1);
}
#define C2B_LOGS(s) c2b_log(s)
#define C2B_LOGH(v) c2b_log_hex((u32)(v))
#define C2B_LOGN(v) c2b_log_hex((u32)(v))
#define C2B_LOGD(v) c2b_log_dec((u32)(v))
#endif

/* v4.3 (run165): ОБЩИЙ safe-reader — /proc/self/mem pread ЧАНКАМИ 64KB с
 * дозаполнением после дыр. Замена прямых разыменований ПОСЛЕ
 * dl_iterate_phdr/maps-снапшота: модуль может анмапиться (steam client
 * died/reload — run165 a5 steam_state_fatal + SIGSEGV в g9_patch_apply;
 * run164 — в c2b_g24_find_state) между сбором баз и чтением. 0 на
 * невалидных адресах — вызывающие проверки просто не совпадут. */
static u64 c2b_rd64_safe(int fd, uptr *clo, u32 *cn, u8 *buf, uptr a)
{
    u64 v;
    if (a < *clo || a + 8 > *clo + *cn) {
        uptr c = a & ~((uptr)0xFFFF);
        u32 got = 0;
        while (got < 0x10000) {
            u64 rc = (u64)pread(fd, buf + got, 0x10000 - got, c + got);
            if (rc == 0 || rc > 0x7FFFFFFFull) break;   /* EOF/EIO/err */
            got += (u32)rc;
        }
        *clo = c;
        *cn = got;
    }
    if (a < *clo || a + 8 > *clo + *cn) return 0;
    memcpy(&v, buf + (a - *clo), 8);
    return v;
}
/* одноразовый читатель: открыть /proc/self/mem, прочитать u64, закрыть.
 * Для редких чтений (g8/g9 rearm-проверок); g24-скан держит fd сам. */
static u64 c2b_rd_once(uptr a)
{
    extern i32 open(const char *, i32, ...);
    extern i32 close(i32);
    int fd = open("/proc/self/mem", 0 /*O_RDONLY*/);
    uptr clo = 0;
    u32 cn = 0;
    u8 buf[65536];
    u64 v;
    if (fd < 0) return 0;
    v = c2b_rd64_safe(fd, &clo, &cn, buf, a);
    close(fd);
    return v;
}

/* R29: tid первого входа в каждый боевой хук. Inline-asm syscall gettid
 * (x86_64=186, i386=224): никаких зависимостей от libc/libpthread.
 * В живом логе [c2b] PM tid=N / [c2b] SNM tid=N дают ФАКТИЧЕСКУЮ
 * потоковую модель движка (1 общий net-поток или раздельные). */
static u32 c2b_sys_gettid(void)
{
#if defined(__x86_64__)
    u32 r;
    __asm__ volatile ("syscall"
                      : "=a"(r)
                      : "a"((u32)186)
                      : "rcx", "r11", "memory");
    return r;
#elif defined(__i386__)
    u32 r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"((u32)224)
                      : "memory");
    return r;
#else
    return 0;
#endif
}

/* R30: runtime-уровень живого лога (C2B_VERBOSE в .so, читается в c2b_main):
 * 0 = тихо (только старт/ARM/FINI-статистика), 1 = компактно (первые first
 * + каждый every-й), 2 = полный дамп на каждый вызов (как раньше).
 * selftest по умолчанию 2 — поведение тестов не меняется. */
static u32 g_vlevel = 2;
static u32 c2b_vlog_hit(u32 level, u32 seq, u32 first, u32 every)
{
    if (level >= 2) return 1;
    if (level == 0) return 0;
    if (seq <= first) return 1;
    return every && (seq % every) == 0;
}

/* ---------- конфигурация (worklog Task 4/7) ----------
 * цель задаётся по арчу в ветке сигнатуры выше */
/* t39-фикс (coredump 26.09): модуль движка в 64-битном процессе =
 * "engine_client.so" (файл БЕЗ "64"). Прежняя игла x86_64
 * "engine_client64.so" ("фикс" цикла 21) не матчилась НИ РАЗУ — в живых
 * логах нет ни одного ARMED, все счётчики FINI нулевые. Общая подстрока
 * покрывает оба имени; иных модулей с "engine_client" в процессе нет. */
#define ENGINE_NAME         "engine_client"

#ifdef __x86_64__
#ifdef C2B_SELFTEST
/* selftest-заглушка: тот же ПАТТЕРН (frame + 3 push + sub imm32), x86_64 кодировка */
static const u8 C2B_SIG[] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55,
    0x48, 0x81, 0xEC, 0x8C, 0x00, 0x00, 0x00 };
#define C2B_STOLEN 17
#define ENGINE_TARGET_OFF  0x4ace40u
#else
/* БОЕВОЙ пролог CNetChan::ProcessMessages @0x4ace40 в engine_client.so (x86_64,
 * md5 0b508a0961d3e5d3fc04f15f6a362efe, VA==file off):
 *   push rbp; mov rbp,rsp; push r15; mov rsi,r15; push r14; push r13; mov edx,r13d;
 *   push r12; push rbx; mov rdi,rbx; sub $0x288,rsp
 * граница инструкций после 16 байт (0x4ace50 = push r12), сигнатура 28 байт до конца sub. */
static const u8 C2B_SIG[] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x49, 0x89, 0xF7, 0x41, 0x56,
    0x41, 0x55, 0x41, 0x89, 0xD5, 0x41, 0x54, 0x53, 0x48, 0x89, 0xFB,
    0x48, 0x81, 0xEC, 0x88, 0x02, 0x00, 0x00 };
#define C2B_STOLEN 16
#define ENGINE_TARGET_OFF  0x4ace40u
#endif

/* ---------- аплинк: CNetChan::SendNetMsg @0x4a3ea0 (engine_client64.so) ----------
 * RE цикла 21: vtable CNetChan @0xd68968 (_ZTS8CNetChan @0x96db78 -> _ZTI @0xd9bbd0),
 * слот 41 = SendNetMsg @0x4a3ea0 (xref строки 'SendNetMsg %s: stream...' @0x4a404c),
 * контрольные: слот 40 ProcessPacket @0x4af220 (xref @0x4af7ac), слот 47
 * SendDatagram @0x4aa000 (xref @0x4aa9f0) — layout public/inetchannel.h сошёлся 1:1.
 * Пролог: push rbp; mov rsp,rbp; push r15; mov ecx,r15d; push r14; mov edx,r14d;
 *         push r13; mov rsi,r13; ... (граница stolen=16 = до 'mov rsi,r13').
 * Сигнатура 17 байт = stolen + первый байт 'mov rsi,r13' (0x49).
 * Аргументы SysV: rdi=this, rsi=INetMessage&, rdx=bForceReliable, rcx=bVoice. */
static const u8 UPL_SIG[] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x89, 0xCF, 0x41, 0x56,
    0x41, 0x89, 0xD6, 0x41, 0x55, 0x49 };
#define UPL_STOLEN     16
#define UPL_TARGET_OFF 0x4a3ea0u
#define UPL_SIG_LEN    (i32)sizeof(UPL_SIG)
#else
/* реальный пролог ProcessMessages @0x528bc0 (i386), граница после 12 байт */
static const u8 C2B_SIG[] = {
    0x55, 0x89, 0xE5, 0x57, 0x56, 0x53, 0x81, 0xEC, 0x8C, 0x00, 0x00, 0x00,
    0x0F, 0xB6, 0x45, 0x10 };
#define C2B_STOLEN 12
#define ENGINE_TARGET_OFF  0x528bc0u
#endif
#define C2B_SIG_LEN (i32)(i32)sizeof(C2B_SIG)

#ifdef __x86_64__
/* selftest: jmp [rip+0] + imm64 — 6+8=14 байт (push/ret не умеет 64-бит адреса).
 * БОЕВОЙ вариант тот же (нет 5-байтной альтернативы для 64-бит цели). */
#define C2B_PATCH_LEN 14
#else
/* i386: push imm32; ret — 6 байт, абсолютный, CET/SHSTK-безопаснейший */
#define C2B_PATCH_LEN 6
#endif
#define PAGE_MASK     (~(uptr)0xFFFu)   /* арх-независимая маска страницы */

/* ---------- bf_read движка CS:GO, ВЫВЕРЕНО дизасмом ProcessMessages ----------
 * i386 @0x528bc0: +0x04 bool (cmpb 528d66); +0x08 int total; +0x0C int (&3);
 * +0x14 int (вычитается); +0x18/+0x20 ptr-пара (sub, 528cb4); +0x1C щель = iCurBit.
 * x86_64 @0x4ace40 (System V): total +0x0C (cmp/cmovg 4acf97); dataBytes +0x10
 * (size_t, &3 4acf91); bitsAvail +0x1C (вычитается 4acf8d); ptr-пара +0x20/+0x30
 * (sub %rdx,%rsi 4acf74: pDataIn - pBuffer); iCurBit +0x28 (копия 4acfe0).
 * Относительный порядок полей идентичен i386, сдвиг — выравниванием 8. */
#ifdef __x86_64__
typedef struct {
    const char *m_pDebugName;     /* +0x00 (ptr 8) */
    u8         m_bOverflow;       /* +0x08 (bool, movzbl 4ad06c) */
    i32        m_nDataBits;       /* +0x0C (int, total) */
    uptr       m_nDataBytes;      /* +0x10 (size_t, &3) */
    i32        m_nInBufWord;      /* +0x18 (int) */
    i32        m_nBitsAvail;      /* +0x1C (int, вычитается) */
    u32       *m_pDataIn;         /* +0x20 (ptr 8) */
    u32        m_iCurBit;         /* +0x28 (int) */
    u32        m_pad2c;           /* +0x2C */
    u32       *m_pBuffer;         /* +0x30 (ptr 8, NULL-check) */
    u32       *m_pDataEnd;        /* +0x38 (ptr 8) */
} bf_read_t;
#else
typedef struct {
    const char *m_pDebugName;     /* +0x00 (ptr) */
    u8         m_bOverflow;       /* +0x04 (bool) */
    i32        m_nDataBits;       /* +0x08 (int, total) */
    u32        m_nDataBytes;      /* +0x0C (int) */
    i32        m_nInBufWord;      /* +0x10 (int) */
    i32        m_nBitsAvail;      /* +0x14 (int) */
    u32       *m_pDataIn;         /* +0x18 (ptr) */
    u32        m_iCurBit;         /* +0x1C (int) */
    u32       *m_pBuffer;         /* +0x20 (ptr, NULL-check) */
    u32       *m_pDataEnd;        /* +0x24 (ptr) */
} bf_read_t;
#endif

/* ---------- статистика ---------- */
typedef struct {
    u32 calls, msgs_in, msgs_out, dropped, renumbered, unknown, net_pass, um;
} c2b_stats_t;

static c2b_stats_t g_st;
static volatile u32 g_state = 0;   /* 0=idle 1=armed */
#ifndef C2B_SELFTEST
static uptr  g_engine_base = 0;
static volatile u32 g_phdr_seen = 0;  /* t39: модулей в последнем скане */
static volatile u32 g_scan_miss = 0;  /* t39: сканов подряд без движка */
#else
static uptr  g_engine_base = 0;
__attribute__((unused)) static void c2b_touch_base(void) { (void)g_engine_base; }
#endif
static u8   *g_trampoline  = 0;
static u8    g_saved[64];
static void *g_target = 0;

/* второй детур (аплинк): параллельный набор глобалов */
static u8   *g2_trampoline = 0;
static u8    g2_saved[64];
static void *g2_target = 0;
static volatile u32 g2_state = 0;

/* наблюдение аплинка v0: гистограмма типов INetMessage, уходящих в аплинк */
typedef struct {
    u32 calls;        /* все вызовы SendNetMsg */
    u32 bytype[64];   /* счётчик по GetType() */
    u8  first[64];    /* подробных логов на тип не более 3 */
    u32 dump[64];     /* база последнего дампа гистограммы */
    u32 rival;        /* R29: CAS-конфликты trylock (доказательство 2-го потока) */
} c2b_up_stats_t;
static c2b_up_stats_t g_up_st;

/* FINI2-телеметрия (t35): единый каркас (порядок блоков = эталон 5cce9ff4):
 * si{pr mcl mcs mclr mcsr} rt{str ge aov} ba{p s nt} up2{t0 bsz tr} dn2{fc}.
 * Поля заполняются в своих зонах (ServerInfo-парсер, G-4d, аплинк, F4). */
static struct g_fini2 {
    u32 si_pr, si_mcl, si_mcs, si_mclr, si_mcsr; /* R37: заполняет c2b_si_parse */
    u32 rt_str, rt_ge, rt_aov;
    u32 ba_p, ba_s, ba_nt;
    u32 up2_t0, up2_bsz, up2_tr;
    u32 dn2_fc;
} g_fini2;

#include "s2s1_tables.h"
#include "s2s1_um_tables.h"
#include "s2s1_dt_blob.h"
#include "s2s1_gc_policy.h"   /* t39: GC-транзит Фаза 2 (рой audit_t38) */

/* ---------- фаза G-3a: блоб SendTables + синтез ClassInfo ----------
 * S2 svc_ClassInfo(42) не содержит data_table_name -> прямой проход ломает
 * S1-клиент. Вместо этого: (1) льём статический блоб svc_SendTable(9) x275;
 * (2) синтезируем S1 ClassInfo(10): class_id = позиция эмиссии, data_table_name
 * по правилу Cxxx->DTxxx + алиасы оружия/прокси (g_class_alias).
 * Карта s2_id -> s1_id сохраняется для G-4 (PacketEntities).
 * S2 SendTable(41) и FlattenedSerializer(51) уже дропаются в g_s2_svc_drop.
 */

/* ---------- varint ---------- */
/* R34a/R1 (t35): 64-битный накопитель + лимит 10 байт. На проводе отрицательные
 * int32 (svc_PacketEntities.f5 baseline=-1/-5, svc_Sounds entity_index=-1, ...)
 * идут 10-байтовым sign-extended varint (тип поля int32, НЕ sint32/zigzag —
 * FDP-тип 5). Старый ридер (cap 5 байт) возвращал 0 = ошибка формата и ронял
 * весь разбор кадра -> PE уходил в raw pass-through под номером S1 (XF_DIRECT).
 * Возврат: 1..10 = число байт, 0 = обрыв/невалидно (>=10 байт с битом
 * продолжения, либо буфер кончился раньше терминатора). */
static u32 c2b_read_varint64(const u8 *p, u32 avail, u64 *out)
{
    u64 val = 0;
    u32 i = 0;
    while (i < avail && i < 10) {
        u8 b = p[i];
        val |= (u64)(b & 0x7F) << (7 * i);   /* i=9: сдвиг 63, биты >=64 теряются (ок по proto) */
        i++;
        if (!(b & 0x80)) { *out = val; return i; }
    }
    return 0;
}

/* 32-битная обёртка: сигнатура прежняя, все call-site без изменений.
 * Единственное поведенческое отличие: 6..10-байтовые значения теперь парсятся
 * (low-32 = дополнительный код int32 — как в protobuf-рантайме), раньше было
 * `return 0` = ошибка формата. Теги и длины (всегда <=5 байт) не меняются. */
static u32 c2b_read_varint(const u8 *p, u32 avail, u32 *out)
{
    u64 v = 0;
    u32 n = c2b_read_varint64(p, avail, &v);
    if (n) *out = (u32)v;
    return n;
}

static u32 c2b_write_varint(u8 *p, u32 val)
{
    u32 n = 0;
    do {
        u8 b = (u8)(val & 0x7F);
        val >>= 7;
        if (val) b |= 0x80;
        p[n++] = b;
    } while (val);
    return n;
}

/* 64-битная запись (для отрицательных int32: 10-байтовый sign-extended) */
static u32 c2b_write_varint64(u8 *p, u64 val)
{
    u32 n = 0;
    do {
        u8 b = (u8)(val & 0x7F);
        val >>= 7;
        if (val) b |= 0x80;
        p[n++] = b;
    } while (val);
    return n;
}

/* ---------- таблицы ---------- */
static const c2b_msg_map_t *c2b_svc_entry(u32 s2num)
{
    for (u32 i = 0; i < SVC_MAP_COUNT; i++)
        if (g_svc_map[i].s2 == s2num) return &g_svc_map[i];
    return 0;
}

static i32 c2b_in_drop(const u8 *arr, u32 n, u32 v)
{
    for (u32 i = 0; i < n; i++) if (arr[i] == (u8)v) return 1;
    return 0;
}

/* ---------- фаза F: wire-level ренумерация полей protobuf ----------
 * Схемы пар (field_map NEEDS_TRANSCODE) показывают: wire-типы совпадают,
 * меняются ТОЛЬКО номера полей. Значит достаточно перезаписать таги:
 * поле S2 f -> поле S1 fmap[f], поля 0xFF — дроп, значения копируются as-is.
 * Возврат: >=0 длина нового payload, <0 — ошибка формата (не транскодим). */
static void c2b_fwd_copy(u8 *dst, const u8 *src, u32 n)
{
    for (u32 i = 0; i < n; i++) dst[i] = src[i];   /* dst<src: копирование вперёд безопасно */
}

static i32 c2b_renum_payload(const u8 *in, u32 in_len, const unsigned char *fmap,
                             u8 *out, u32 cap, u32 *skipped)
{
    u32 ip = 0, op = 0;
    while (ip < in_len) {
        u32 tag, vlen, c;
        c = c2b_read_varint(in + ip, in_len - ip, &tag); if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7u;
        if (!f) return -1;
        ip += c;
        if (wt == 2) {
            u32 ln;
            c = c2b_read_varint(in + ip, in_len - ip, &ln);
            if (!c || ln > in_len - ip) return -1;
            vlen = c + ln;
        } else if (wt == 0) {
            u32 v; vlen = c2b_read_varint(in + ip, in_len - ip, &v);
            if (!vlen) return -1;
        } else if (wt == 1) vlen = 8;
        else if (wt == 5) vlen = 4;
        else return -1;                       /* WT3/4 (groups) в схемах нет */
        if (vlen > in_len - ip) return -1;
        u8 f1 = (f < 32u) ? fmap[f] : 0xFF;
        if (f1 != 0xFF) {
            u8  t2[8];
            u32 t2n = c2b_write_varint(t2, (u32)((f1 << 3) | wt));
            if (op + t2n + vlen > cap) return -2;
            for (u32 k = 0; k < t2n; k++) out[op++] = t2[k];
            for (u32 k = 0; k < vlen; k++) out[op++] = in[ip + k];
        } else {
            if (skipped) (*skipped)++;
        }
        ip += vlen;
    }
    return (i32)op;
}

/* ---------- фаза G-2: usermsg-мост ----------
 * CS2 шлёт юзермесс плоским wire [N][len][payload] (зоны 100..170 engine,
 * 256..258 P2P, 280..282 ClientUI, 301..389 CS, 400..453 TE — cs2_wire_types.json).
 * S1 ждёт svc_UserMessage(23){1 msg_type int32, 2 msg_data bytes}.
 * Таблица мостов: s2s1_um_tables.h (46 пар; 368/369 — NO_FDP, дроп). */
static i32 c2b_is_um_zone(u32 t)
{
    return (t >= 100 && t <= 170) || (t >= 256 && t <= 258) ||
           (t >= 280 && t <= 282) || (t >= 301 && t <= 389) ||
           (t >= 400 && t <= 453);
}

static const c2b_um_t *c2b_um_entry(u32 wire)
{
    for (u32 i = 0; i < UM_MAP_COUNT; i++)
        if (g_um_map[i].wire == wire) return &g_um_map[i];
    return 0;
}

union f32u { u32 u; float f; };

/* fixed32 (LE) -> float -> int (усечение к нулю; mp_timelimit и ко >= 0) */
static i32 c2b_fbits2i(const u8 *b)
{
    union f32u v;
    v.u = (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
    return (i32)v.f;
}

/* CMsgRGBA{1 r,2 g,3 b,4 a varint} под тагом tag_num (wt2).
 * Source-Color = R|G<<8|B<<16|A<<24 -> LE-байты wire fixed32 = R,G,B,A. */
static i32 c2b_put_rgba(u8 *o, u32 tag_num, const u8 *c)
{
    u8 pl[16]; u32 n = 0, t;
    pl[n++] = 0x08; n += c2b_write_varint(pl + n, c[0]);
    pl[n++] = 0x10; n += c2b_write_varint(pl + n, c[1]);
    pl[n++] = 0x18; n += c2b_write_varint(pl + n, c[2]);
    pl[n++] = 0x20; n += c2b_write_varint(pl + n, c[3]);
    t  = c2b_write_varint(o, (tag_num << 3) | 2);
    t += c2b_write_varint(o + t, n);
    for (u32 k = 0; k < n; k++) o[t + k] = pl[k];
    return (i32)(t + n);
}

/* разбор одного поля (общий с renum формат): на входе ip УЖЕ после тага,
 * возвращает длину ЗНАЧЕНИЯ (для wt2 — вместе с len-префиксом), 0 = ошибка */
static u32 c2b_field_len(const u8 *in, u32 avail, u32 wt)
{
    if (wt == 2) {
        u32 ln, c = c2b_read_varint(in, avail, &ln);
        if (!c || ln > avail - c) return 0;
        return c + ln;
    }
    if (wt == 0) {
        u32 v; u32 c = c2b_read_varint(in, avail, &v);
        return c;
    }
    if (wt == 1) return 8;
    if (wt == 5) return 4;
    return 0;
}

/* 334 CCSUsrMsg_MatchEndConditions: f1..f3 passthru (таг+значение); f4 fixed32-float -> varint-int32 */
static i32 c2b_um_334(const u8 *in, u32 n, u8 *out, u32 cap)
{
    u32 ip = 0, op = 0;
    while (ip < n) {
        u32 tag, c = c2b_read_varint(in + ip, n - ip, &tag);
        if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7u; if (!f) return -1;
        ip += c;
        u32 vl = c2b_field_len(in + ip, n - ip, wt); if (!vl || vl > n - ip) return -1;
        if (f == 4 && wt == 5) {
            if (op + 12 > cap) return -2;
            op += c2b_write_varint(out + op, 4u << 3);
            i32 iv = c2b_fbits2i(in + ip);
            op += c2b_write_varint64(out + op, (u64)(i64)iv);
        } else if (f <= 3 && wt == 0) {
            if (op + c + vl > cap) return -2;
            for (u32 k = 0; k < c; k++) out[op++] = in[ip - c + k];   /* таг */
            for (u32 k = 0; k < vl; k++) out[op++] = in[ip + k];      /* значение */
        }                                        /* прочее — дроп */
        ip += vl;
    }
    return (i32)op;
}

/* 106 CUserMessageFade -> CCSUsrMsg_Fade: f1..f3 passthru; f4 fixed32 -> CMsgRGBA@4 */
static i32 c2b_um_106(const u8 *in, u32 n, u8 *out, u32 cap)
{
    u32 ip = 0, op = 0;
    while (ip < n) {
        u32 tag, c = c2b_read_varint(in + ip, n - ip, &tag);
        if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7u; if (!f) return -1;
        ip += c;
        u32 vl = c2b_field_len(in + ip, n - ip, wt); if (!vl || vl > n - ip) return -1;
        if (f == 4 && wt == 5) {
            if (op + 16 > cap) return -2;
            op += (u32)c2b_put_rgba(out + op, 4, in + ip);
        } else if (f <= 3 && wt == 0) {
            if (op + c + vl > cap) return -2;
            for (u32 k = 0; k < c; k++) out[op++] = in[ip - c + k];   /* таг */
            for (u32 k = 0; k < vl; k++) out[op++] = in[ip + k];      /* значение */
        }
        ip += vl;
    }
    return (i32)op;
}

/* 110 CUserMessageHudMsg -> CCSUsrMsg_HudMsg:
 *   f1 channel passthru; f2 x + f3 y -> pos@2 CMsgVector2D{1 x,2 y fixed32};
 *   f4 -> clr1@3 RGBA; f5 -> clr2@4 RGBA; f6 effect -> @5; f11 text -> @11.
 * (fade_in/out, hold, fx у S2 нет — S1 возьмёт нули.) */
static i32 c2b_um_110(const u8 *in, u32 n, u8 *out, u32 cap)
{
    u32 ip = 0, op = 0;
    u8 xy[8]; i32 have_x = 0, have_y = 0;
    while (ip < n) {
        u32 tag, c = c2b_read_varint(in + ip, n - ip, &tag);
        if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7u; if (!f) return -1;
        ip += c;
        u32 vl = c2b_field_len(in + ip, n - ip, wt); if (!vl || vl > n - ip) return -1;
        if (f == 1 && wt == 0) {
            if (op + c + vl > cap) return -2;
            for (u32 k = 0; k < c; k++) out[op++] = in[ip - c + k];   /* таг */
            for (u32 k = 0; k < vl; k++) out[op++] = in[ip + k];      /* значение */
        } else if (f == 2 && wt == 5) {
            for (u32 k = 0; k < 4; k++) xy[k] = in[ip + k];
            have_x = 1;
        } else if (f == 3 && wt == 5) {
            for (u32 k = 0; k < 4; k++) xy[4 + k] = in[ip + k];
            have_y = 1;
        } else if (f == 4 && wt == 5) {
            if (op + 16 > cap) return -2;
            op += (u32)c2b_put_rgba(out + op, 3, in + ip);
        } else if (f == 5 && wt == 5) {
            if (op + 16 > cap) return -2;
            op += (u32)c2b_put_rgba(out + op, 4, in + ip);
        } else if (f == 6 && wt == 0) {              /* ретаг 6 -> 5 */
            u32 t2 = c2b_write_varint(out + op, 5u << 3);
            if (op + t2 + vl > cap) return -2;
            op += t2;
            for (u32 k = 0; k < vl; k++) out[op++] = in[ip + k];
        } else if (f == 11 && wt == 2) {             /* ретаг 11 -> 11 (as-is) */
            u32 t2 = c2b_write_varint(out + op, (11u << 3) | 2);
            if (op + t2 + vl > cap) return -2;
            op += t2;
            for (u32 k = 0; k < vl; k++) out[op++] = in[ip + k];
        }
        ip += vl;
    }
    if (have_x || have_y) {                          /* pos@2 в конец */
        u8 pl[12]; u32 pn = 0;
        if (have_x) { pl[pn++] = 0x0D; for (u32 k = 0; k < 4; k++) pl[pn++] = xy[k]; }
        if (have_y) { pl[pn++] = 0x15; for (u32 k = 0; k < 4; k++) pl[pn++] = xy[4 + k]; }
        u32 t2  = c2b_write_varint(out + op, (2u << 3) | 2);
        t2 += c2b_write_varint(out + op + t2, pn);
        if (op + t2 + pn > cap) return -2;
        op += t2;
        for (u32 k = 0; k < pn; k++) out[op++] = pl[k];
    }
    return (i32)op;
}

/* сборка svc_UserMessage(23){1 msg_type, 2 data} из S1-payload.
 * payload пишется в скретч out+op+24 (рост ренума <= 1 байт/поле -> запас 64+),
 * затем внутренний+внешний заголовки и сдвиг влево c2b_fwd_copy (dst<src всегда).
 * rc: 0 ок, -1 кривой payload, -2 не хватило cap. */
static i32 c2b_um_wrap(const c2b_um_t *u, const u8 *pl, u32 n, u8 *out, u32 op, u32 cap, u32 *out_op)
{
    u32 pl1 = 0;
    if (op + 24 + n + 64 > cap) return -2;
    u8  *dst  = out + op + 24;
    u32  dcap = cap - op - 24;
    switch (u->xf) {
    case UM_ASIS:
        for (u32 k = 0; k < n; k++) dst[k] = pl[k];
        pl1 = n;
        break;
    case UM_RENUM: {
        i32 r = c2b_renum_payload(pl, n, u->renum->map, dst, dcap, 0);
        if (r < 0) return (r == -2) ? -2 : -1;
        pl1 = (u32)r;
        break; }
    case UM_CONV334: { i32 r = c2b_um_334(pl, n, dst, dcap); if (r < 0) return r; pl1 = (u32)r; break; }
    case UM_CONV106: { i32 r = c2b_um_106(pl, n, dst, dcap); if (r < 0) return r; pl1 = (u32)r; break; }
    case UM_CONV110: { i32 r = c2b_um_110(pl, n, dst, dcap); if (r < 0) return r; pl1 = (u32)r; break; }
    default: return -1;
    }
    u8  ihb[8]; u32 ih = 0;                        /* inner: [08][id][12][len] */
    ihb[ih++] = 0x08;
    ih += c2b_write_varint(ihb + ih, u->s1);
    ihb[ih++] = 0x12;
    ih += c2b_write_varint(ihb + ih, pl1);
    u32 inner = ih + pl1;
    u32 t = c2b_write_varint(out + op, 23u);       /* outer: [23][inner] */
    t += c2b_write_varint(out + op + t, inner);
    for (u32 k = 0; k < ih; k++) out[op + t + k] = ihb[k];   /* inner-заголовок в out */
    c2b_fwd_copy(out + op + t + ih, out + op + 24, pl1);   /* t+ih <= 11 < 24 */
    *out_op = op + t + inner;
    return 0;
}

#define C2B_CLASS_MAP_MAX 1024
static u16 g_class_id_map[C2B_CLASS_MAP_MAX]; /* s2 class_id -> s1 emit index */
static u16 g_class_ser_map[C2B_CLASS_MAP_MAX]; /* s2 class_id -> id сериализатора FSV (G-4) */
static u16 g_class_dt_map[C2B_CLASS_MAP_MAX]; /* s2 class_id -> dt_index корня (G-4) */
static u8 g_class_seen[C2B_CLASS_MAP_MAX];   /* класс реально пришёл в ClassInfo (sentinel) */
static u32 g_class_id_map_n;
static u32 g_cls_emitted;      /* число классов в эмитнутом ClassInfo (ширина class_id S1) */
static u32 g_blob_emits;
static u32 g_dt_misses;  /* классы, чьё DT не найдено в блобе (клиент скипнет) */

static unsigned int c2b_fnv1a(const char *s)
{
    unsigned int h = 0x811c9dc5u;
    while (*s) { h ^= (unsigned char)*s++; h *= 0x01000193u; }
    return h;
}

static const dt_entry *c2b_dt_find(unsigned int h)
{
    u32 i;
    for (i = 0; i < DT_BLOB_TABLES; i++)
        if (g_dt_index[i].name_hash == h) return &g_dt_index[i];
    return 0;
}

static const class_alias *c2b_alias_find(unsigned int h)
{
    u32 i;
    for (i = 0; i < sizeof(g_class_alias) / sizeof(g_class_alias[0]); i++)
        if (g_class_alias[i].name_hash == h) return &g_class_alias[i];
    return 0;
}

/* "CCSPlayer" -> "DT_CSPlayer"; "CWorld" -> "DT_World" */
static u32 c2b_rule_dt(const char *cn, char *out)
{
    u32 n = 0;
    const char *p = cn;
    out[n++] = 'D'; out[n++] = 'T'; out[n++] = '_';
    if (p[0] == 'C' && p[1] >= 'A' && p[1] <= 'Z') p++;
    while (*p && n < 62) out[n++] = *p++;
    out[n] = 0;
    return n;
}

/* ---------- фаза G-3b: парсер S2 svc_FlattenedSerializer(51) ----------
 * Источник G-4 (PacketEntities-декодер): модель сериализаторов/полей CS2.
 * Семантика — демо-референс demoinfocs-golang sendtablescs2 (analysis/g3_design.md §2):
 *   serializers(f1) ссылаются на ОБЩИЕ поля через fields_index (порядковые
 *   номера f3-записей ЭТОГО сообщения); поля шарятся между сериализаторами;
 *   символы (f2) — общий словарь строк сообщения; сериализаторы копятся
 *   МЕЖДУ сообщениями (replace по имени при новой версии).
 * Модель поля: FixedTable (ptr/pointerType/poly) / VariableTable (встроенная
 * структура) / FixedArray ("T[N]", base != char) / VariableArray
 * (CUtlVector/CNetworkUtlVectorBase<>) / Simple.
 * Отличие от Go: поля резолвим после того как ВСЕ сериализаторы сообщения
 * зарегистрированы (2 прохода) — на реальных данных CS:GO эквивалентно
 * (поля ссылаются только на ранее отправленные сериализаторы).
 * Из потока 51 по-прежнему ДРОПАЕТСЯ (S1-схема = статический блоб), парсер
 * строит только рантайм-состояние для G-4. */
#define C2B_FSV_MAX_SER    3072
#define C2B_FSV_MAX_FIELD  8192
#define C2B_FSV_MAX_SYM    4096
#define C2B_FSV_ARENA      (192*1024)
#define C2B_FSV_MAX_IDX    131072   /* суммарные fields_index-ссылки */
#define C2B_FSV_SYM_HASH   8192
#define C2B_FSV_MAX_POLY   4
#define C2B_FSV_SER_NUL    0xFFFFu  /* сериализатор не разрешился */
#define C2B_G4_POLY_SLOTS  16       /* per-entity слоты активных poly-типов (G-4c) */

enum { SM_DROP=0, SM_SIMPLE, SM_FIXEDARR, SM_FIXEDTAB, SM_VARARR, SM_VARTAB };
enum { BT_OTHER=0, BT_F32, BT_QF, BT_U64, BT_VEC3, BT_VEC2, BT_VEC4, BT_QUAT,
       BT_CTR, BT_QANGLE, BT_BOOL, BT_I32, BT_U32, BT_STR, BT_HND, BT_COLOR,
       BT_BIN, BT_COMP, BT_RES };
/* DT_*: битовые декодеры G-4 (параметры — в поле: bits/lo/hi/flags) */
enum { DT_VARINT_U=0, DT_VARINT_S, DT_VARINT_U64, DT_FIXED64, DT_BOOL,
       DT_NOSCALE, DT_COORD, DT_SIMTIME, DT_RUNETIME, DT_QUANT,
       DT_Q_PRECISE, DT_Q_BITS, DT_Q_NOSCALE3, DT_Q_DEFAULT,
       DT_STR, DT_BIN, DT_AMMO, DT_COMP, DT_NORMAL3 };

typedef struct {
    u32 name;     /* arena off varName */
    u32 base;     /* arena off базового типа (до '<' '[' '*') */
    u32 gen_base; /* arena off generic-базы (для VariableArray), 0 = нет */
    u32 node;     /* arena off sendNode (0 = нет/"(root)" — скипается на обходе) */
    u32 enc;      /* arena off encoder (0 = нет) */
    u32 ser_name; /* arena off field_serializer_name (0 = нет) */
    float lo, hi;
    i32 bits;     /* -1 = нет */
    i32 flags;    /* encode_flags, -1 = нет */
    i32 ser_ver;
    u16 model;    /* SM_* */
    u16 base_id;  /* BT_* базового типа */
    u16 gen_id;   /* BT_* generic-базы */
    u16 dec;      /* DT_* (Simple/FixedArray — свой; VariableArray — child) */
    u16 count;    /* фиксированный размер массива */
    u16 pointer;  /* '*' в типе */
    u16 ser_id;   /* разрешиленный id сериализатора (C2B_FSV_SER_NUL = нет) */
    u16 poly_n;   /* число полиморфных альтернатив */
    u16 poly_slot;/* глобальный per-entity слот активного типа (0xFFFF = нет) */
    u16 poly[C2B_FSV_MAX_POLY]; /* id альтернатив (NUL = не разрешился) */
} c2b_fsv_field_t;

typedef struct {
    u32 name;     /* arena off */
    u32 fbase;    /* база пула полей сообщения-владельца */
    u32 idx_off;  /* смещение в g_fsv_idx */
    i32 ver;
    u16 n;        /* число полей */
    u16 id;
} c2b_fsv_ser_t;

static char g_fsv_arena[C2B_FSV_ARENA];
static u32  g_fsv_arena_n = 1;                 /* 0 = NULL-маркер */
static u32  g_fsv_sym_hash[C2B_FSV_SYM_HASH];  /* arena off+1; 0 = пусто */
static u32  g_fsv_msgsym[C2B_FSV_MAX_SYM];     /* ординалы символов ТЕКУЩЕГО сообщения */
static u32  g_fsv_msgsym_n;
static c2b_fsv_field_t g_fsv_field[C2B_FSV_MAX_FIELD];
static u32  g_fsv_field_n;
static c2b_fsv_ser_t   g_fsv_ser[C2B_FSV_MAX_SER];
static u32  g_fsv_ser_n;
static u16  g_fsv_idx[C2B_FSV_MAX_IDX];
static u32  g_fsv_idx_n;
static struct { u32 int_bits, frac_bits, int_mp, frac_mp, normal_bits, angle_bits; } g_fsv_coord;
static u32  g_fsv_msgs, g_fsv_ovf, g_fsv_err, g_fsv_ser_miss;
static u32  g_fsv_max_classes;                 /* из S2 ServerInfo(40) f11 — G-4 */
static u32  g_fsv_poly_next;                   /* глобальный счётчик poly-слотов (G-4c) */
static u32  g_fsv_gen;                         /* поколение FSV — инвалидация кэша классов */

static i32 c2b_streq(const char *a, const char *b)
{
    u32 i = 0;
    while (a[i] && a[i] == b[i]) i++;
    return a[i] == b[i];
}

static unsigned c2b_fnv1a_buf(const u8 *s, u32 n)
{
    unsigned h = 0x811c9dc5u;
    for (u32 i = 0; i < n; i++) { h ^= s[i]; h *= 0x01000193u; }
    return h;
}

/* строка в арену с дедупликацией (символы повторяются между сообщениями) */
static u32 c2b_sym_store(const u8 *s, u32 n)
{
    unsigned h = c2b_fnv1a_buf(s, n);
    u32 slot = (u32)h & (C2B_FSV_SYM_HASH - 1);
    for (u32 probe = 0; probe < 64; probe++) {
        u32 e = g_fsv_sym_hash[(slot + probe) & (C2B_FSV_SYM_HASH - 1)];
        if (!e) break;
        const char *a = g_fsv_arena + (e - 1);
        u32 i = 0;
        while (i < n && a[i] && a[i] == (char)s[i]) i++;
        if (i == n && !a[i]) return e - 1;     /* дубликат */
    }
    if (g_fsv_arena_n + n + 1 > C2B_FSV_ARENA) { g_fsv_ovf++; return 0; }
    u32 off = g_fsv_arena_n;
    for (u32 i = 0; i < n; i++) g_fsv_arena[off + i] = (char)s[i];
    g_fsv_arena[off + n] = 0;
    g_fsv_arena_n += n + 1;
    for (u32 probe = 0; probe < 64; probe++) {
        u32 si = (slot + probe) & (C2B_FSV_SYM_HASH - 1);
        if (!g_fsv_sym_hash[si]) { g_fsv_sym_hash[si] = off + 1; break; }
    }
    return off;
}

#define C2B_SYM_NONE 0xFFFFFFFFu               /* поле-символ ОТСУТСТВУЕТ (0 — валидный ординал!) */
static u32 c2b_sym_lookup(u32 ord)             /* ординал текущего сообщения */
{
    return (ord != C2B_SYM_NONE && ord < g_fsv_msgsym_n) ? g_fsv_msgsym[ord] : 0;
}

static i32 c2b_fsv_ser_by_name_off(u32 off)    /* дедуп => контент == оффсет */
{
    for (u32 i = 0; i < g_fsv_ser_n; i++)
        if (g_fsv_ser[i].name == off) return (i32)i;
    return -1;
}

static i32 c2b_fsv_find_ser(const char *s)
{
    for (u32 i = 0; i < g_fsv_ser_n; i++)
        if (c2b_streq(g_fsv_arena + g_fsv_ser[i].name, s)) return (i32)i;
    return -1;
}

/* регистрация/замена сериализатора по имени (замена = новая версия) */
static i32 c2b_fsv_ser_register(u32 name_off, i32 ver)
{
    i32 ex = c2b_fsv_ser_by_name_off(name_off);
    if (ex >= 0) {
        g_fsv_ser[ex].ver = ver;
        g_fsv_ser[ex].fbase = g_fsv_field_n;   /* база пула ТЕКУЩЕГО сообщения */
        return ex;                              /* idx_off/n ставит вызывающий */
    }
    if (g_fsv_ser_n >= C2B_FSV_MAX_SER) { g_fsv_ovf++; return -1; }
    c2b_fsv_ser_t *S = &g_fsv_ser[g_fsv_ser_n];
    S->name = name_off; S->ver = ver; S->fbase = g_fsv_field_n;
    S->idx_off = 0; S->n = 0; S->id = (u16)g_fsv_ser_n;
    return (i32)g_fsv_ser_n++;
}

/* парсер строки типа: base до '<' '[' '*'; generic внутри < >; '*' -> pointer;
 * [N] -> count (символика -> словарь, число -> atoi, прочее -> 1024) */
static void c2b_fsv_parse_type(u32 t_off, u32 *base, u32 *gen, u16 *ptr, u16 *cnt)
{
    const char *t = g_fsv_arena + t_off;
    u32 b = 0;
    while (t[b] && t[b] != '<' && t[b] != '[' && t[b] != '*') b++;
    *base = c2b_sym_store((const u8 *)t, b);
    *gen = 0; *ptr = 0; *cnt = 0;
    u32 i = b;
    if (t[i] == '<') {                          /* "< X >": generic-база до '<'['*' */
        i++;
        while (t[i] == ' ') i++;
        u32 g = i, gl = 0;
        while (t[g + gl] && t[g + gl] != '<' && t[g + gl] != '[' &&
               t[g + gl] != '*' && t[g + gl] != '>') gl++;
        while (gl > 0 && t[g + gl - 1] == ' ') gl--;
        if (gl) *gen = c2b_sym_store((const u8 *)t + g, gl);
    }
    for (; t[i]; i++) {
        if (t[i] == '*') *ptr = 1;
        else if (t[i] == '[') {
            u32 j = i + 1;
            while (t[j] && t[j] != ']') j++;
            u32 cl = j - (i + 1);
            if (cl == 15 && c2b_streq(t + i + 1, "MAX_ITEM_STOCKS")) *cnt = 8;
            else if (cl == 27 && c2b_streq(t + i + 1, "MAX_ABILITY_DRAFT_ABILITIES")) *cnt = 48;
            else if (cl) {
                u32 v = 0, ok = 1;
                for (u32 k = i + 1; k < j; k++) {
                    if (t[k] >= '0' && t[k] <= '9') v = v * 10 + (u32)(t[k] - '0');
                    else { ok = 0; break; }
                }
                *cnt = (u16)((ok && v) ? v : 1024);
            }
            i = j;
        }
    }
}

static u16 c2b_fsv_base_id(u32 off)
{
    const char *b = off ? g_fsv_arena + off : "";
    if (!*b) return BT_OTHER;
    if (c2b_streq(b, "float32") || c2b_streq(b, "GameTime_t")) return BT_F32;
    if (c2b_streq(b, "CNetworkedQuantizedFloat")) return BT_QF;
    if (c2b_streq(b, "uint64") || c2b_streq(b, "ResourceId_t") ||
        c2b_streq(b, "CStrongHandle")) return BT_U64;
    if (c2b_streq(b, "Vector") || c2b_streq(b, "VectorWS")) return BT_VEC3;
    if (c2b_streq(b, "Vector2D")) return BT_VEC2;
    if (c2b_streq(b, "Vector4D")) return BT_VEC4;
    if (c2b_streq(b, "Quaternion")) return BT_QUAT;
    if (c2b_streq(b, "CTransform")) return BT_CTR;
    if (c2b_streq(b, "QAngle")) return BT_QANGLE;
    if (c2b_streq(b, "bool")) return BT_BOOL;
    if (c2b_streq(b, "int8") || c2b_streq(b, "int16") || c2b_streq(b, "int32") ||
        c2b_streq(b, "HSequence") || c2b_streq(b, "CEntityIndex")) return BT_I32;
    if (c2b_streq(b, "uint8") || c2b_streq(b, "uint16") || c2b_streq(b, "uint32")) return BT_U32;
    if (c2b_streq(b, "char") || c2b_streq(b, "CUtlString") ||
        c2b_streq(b, "CUtlSymbolLarge") || c2b_streq(b, "CGlobalSymbol")) return BT_STR;
    if (c2b_streq(b, "CHandle") || c2b_streq(b, "EHandle") ||
        c2b_streq(b, "CEntityHandle") || c2b_streq(b, "CGameSceneNodeHandle") ||
        c2b_streq(b, "CUtlStringToken") || c2b_streq(b, "AttachmentHandle_t") ||
        c2b_streq(b, "Color")) return BT_HND;
    if (c2b_streq(b, "CUtlBinaryBlock")) return BT_BIN;
    if (c2b_streq(b, "CBodyComponent") || c2b_streq(b, "CPhysicsComponent") ||
        c2b_streq(b, "CLightComponent") || c2b_streq(b, "CRenderComponent") ||
        c2b_streq(b, "CBodyComponentDCGBaseAnimating") ||
        c2b_streq(b, "CBodyComponentBaseAnimating") ||
        c2b_streq(b, "CBodyComponentBaseAnimatingOverlay") ||
        c2b_streq(b, "CBodyComponentBaseModelEntity") ||
        c2b_streq(b, "CBodyComponentSkeletonInstance") ||
        c2b_streq(b, "CBodyComponentPoint")) return BT_COMP;
    return BT_OTHER;
}

static u16 c2b_fsv_comp_dec(u32 enc_off, i32 bits)
{
    const char *enc = enc_off ? g_fsv_arena + enc_off : 0;
    if (enc) {
        if (c2b_streq(enc, "coord"))    return DT_COORD;
        if (c2b_streq(enc, "simtime"))  return DT_SIMTIME;
        if (c2b_streq(enc, "runetime")) return DT_RUNETIME;
    }
    if (bits <= 0 || bits >= 32) return DT_NOSCALE;
    return DT_QUANT;
}

/* выбор декодера: findDecoder/fieldTypeFactories/fieldNameDecoders/fieldTypeDecoders
 * демо-референса. Параметры квантования остаются в поле (G-4). */
static u16 c2b_fsv_decoder_id(const c2b_fsv_field_t *F, u16 base_id)
{
    const char *enc = F->enc ? g_fsv_arena + F->enc : 0;
    /* 1) fieldTypeFactories — приоритет над всем */
    switch (base_id) {
    case BT_F32: case BT_QF:
        return c2b_fsv_comp_dec(F->enc, F->bits);
    case BT_U64:
        return (enc && c2b_streq(enc, "fixed64")) ? DT_FIXED64 : DT_VARINT_U64;
    case BT_VEC3:
        if (enc && c2b_streq(enc, "normal")) return DT_NORMAL3;
        return c2b_fsv_comp_dec(F->enc, F->bits);
    case BT_VEC2: case BT_VEC4: case BT_QUAT: case BT_CTR:
        return c2b_fsv_comp_dec(F->enc, F->bits);
    case BT_QANGLE:
        if (enc && c2b_streq(enc, "qangle_precise")) return DT_Q_PRECISE;
        if (F->bits > 0 && F->bits < 32) return DT_Q_BITS;
        if (F->bits >= 32) return DT_Q_NOSCALE3;
        return DT_Q_DEFAULT;
    default: break;
    }
    /* 2) fieldNameDecoders */
    if (F->name && c2b_streq(g_fsv_arena + F->name, "m_iClip1")) return DT_AMMO;
    /* 3) fieldTypeDecoders */
    switch (base_id) {
    case BT_BOOL: return DT_BOOL;
    case BT_STR:  return DT_STR;
    case BT_BIN:  return DT_BIN;
    case BT_COMP: return DT_COMP;
    case BT_HND:  case BT_COLOR: case BT_U32:
        return DT_VARINT_U;
    case BT_I32:
        return DT_VARINT_S;
    case BT_RES:
        return DT_VARINT_U64;
    default: break;
    }
    return DT_VARINT_U;                                    /* defaultDecoder */
}

/* pointerTypes демо-референса (базовые имена без '*') */
static i32 c2b_fsv_is_ptype(u32 off)
{
    const char *b = g_fsv_arena + off;
    return c2b_streq(b, "CBodyComponent") ||
           c2b_streq(b, "CBodyComponentDCGBaseAnimating") ||
           c2b_streq(b, "CBodyComponentBaseAnimating") ||
           c2b_streq(b, "CBodyComponentBaseAnimatingOverlay") ||
           c2b_streq(b, "CBodyComponentBaseModelEntity") ||
           c2b_streq(b, "CBodyComponentSkeletonInstance") ||
           c2b_streq(b, "CBodyComponentPoint") ||
           c2b_streq(b, "CLightComponent") ||
           c2b_streq(b, "CRenderComponent") ||
           c2b_streq(b, "CPhysicsComponent");
}

static u32 c2b_le_f32bits(const u8 *b)
{
    return (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
}

/* resolve одного f3-поля в пул */
static void c2b_fsv_resolve_field(const u8 *sub, u32 ln, c2b_fsv_field_t *F)
{
    u32 type_sym = C2B_SYM_NONE, name_sym = C2B_SYM_NONE;
    u32 node_sym = C2B_SYM_NONE, enc_sym = C2B_SYM_NONE, ser_sym = C2B_SYM_NONE;
    u32 sp = 0;
    u32 poly_sym[C2B_FSV_MAX_POLY]; u32 poly_n = 0;
    F->base = 0; F->gen_base = 0; F->node = 0; F->enc = 0; F->ser_name = 0;
    F->lo = 0.0f; F->hi = 0.0f; F->bits = -1; F->flags = -1; F->ser_ver = 0;
    F->model = SM_DROP; F->base_id = BT_OTHER; F->gen_id = BT_OTHER; F->dec = 0;
    F->count = 0; F->pointer = 0; F->ser_id = C2B_FSV_SER_NUL; F->poly_n = 0;
    F->poly_slot = 0xFFFFu;
    while (sp < ln) {
        u32 t2, c = c2b_read_varint(sub + sp, ln - sp, &t2);
        if (!c) { g_fsv_err++; return; }
        u32 f2 = t2 >> 3, w2 = t2 & 7;
        sp += c;
        if (w2 == 0) {
            u32 v; c = c2b_read_varint(sub + sp, ln - sp, &v);
            if (!c) { g_fsv_err++; return; }
            sp += c;
            if (f2 == 1) type_sym = v;
            else if (f2 == 2) name_sym = v;
            else if (f2 == 3) F->bits = (i32)v;
            else if (f2 == 6) F->flags = (i32)v;
            else if (f2 == 7) ser_sym = v;
            else if (f2 == 8) F->ser_ver = (i32)v;
            else if (f2 == 9) node_sym = v;
            else if (f2 == 10) enc_sym = v;
        } else if (w2 == 5) {
            if (4 > ln - sp) { g_fsv_err++; return; }
            if (f2 == 4) { union f32u v; v.u = c2b_le_f32bits(sub + sp); F->lo = v.f; }
            else if (f2 == 5) { union f32u v; v.u = c2b_le_f32bits(sub + sp); F->hi = v.f; }
            sp += 4;
        } else if (w2 == 2) {
            u32 l2; c = c2b_read_varint(sub + sp, ln - sp, &l2);
            if (!c || l2 > ln - sp) { g_fsv_err++; return; }
            sp += c;
            if (f2 == 11 && poly_n < C2B_FSV_MAX_POLY) {
                u32 pp = 0;
                while (pp < l2) {
                    u32 t3, c3 = c2b_read_varint(sub + sp + pp, l2 - pp, &t3);
                    if (!c3) break;
                    pp += c3;
                    if ((t3 & 7) == 0) {
                        u32 v3; c3 = c2b_read_varint(sub + sp + pp, l2 - pp, &v3);
                        if (!c3) break;
                        pp += c3;
                        if ((t3 >> 3) == 1 && poly_n < C2B_FSV_MAX_POLY) poly_sym[poly_n++] = v3;
                    } else if ((t3 & 7) == 2) {
                        u32 l3; c3 = c2b_read_varint(sub + sp + pp, l2 - pp, &l3);
                        if (!c3 || l3 > l2 - pp - c3) break;
                        pp += c3 + l3;
                    } else break;
                }
            }
            sp += l2;
        } else { g_fsv_err++; return; }
    }

    F->name = (name_sym != C2B_SYM_NONE) ? c2b_sym_lookup(name_sym) : 0;
    u32 t_off = (type_sym != C2B_SYM_NONE) ? c2b_sym_lookup(type_sym) : 0;
    F->node = (node_sym != C2B_SYM_NONE) ? c2b_sym_lookup(node_sym) : 0;
    F->enc  = (enc_sym != C2B_SYM_NONE)  ? c2b_sym_lookup(enc_sym)  : 0;
    F->ser_name = (ser_sym != C2B_SYM_NONE) ? c2b_sym_lookup(ser_sym) : 0;
    if (t_off) c2b_fsv_parse_type(t_off, &F->base, &F->gen_base, &F->pointer, &F->count);
    F->base_id = c2b_fsv_base_id(F->base);
    F->gen_id  = c2b_fsv_base_id(F->gen_base);

    if (F->ser_name) {
        i32 s = c2b_fsv_ser_by_name_off(F->ser_name);
        F->ser_id = (s >= 0) ? (u16)s : C2B_FSV_SER_NUL;
        if (s < 0) g_fsv_ser_miss++;
    } else F->ser_id = C2B_FSV_SER_NUL;
    F->poly_n = 0;
    for (u32 i = 0; i < poly_n; i++) {
        u32 p_off = c2b_sym_lookup(poly_sym[i]);
        i32 s = p_off ? c2b_fsv_ser_by_name_off(p_off) : -1;
        F->poly[F->poly_n++] = (s >= 0) ? (u16)s : C2B_FSV_SER_NUL;
    }
    if (F->poly_n && g_fsv_poly_next < C2B_G4_POLY_SLOTS)
        F->poly_slot = (u16)g_fsv_poly_next++;   /* глобальный слот (G-4c) */

    /* модель (parser.go setModel) */
    i32 ser_live = (F->ser_name && F->ser_id != C2B_FSV_SER_NUL) || F->poly_n;
    if (ser_live) {
        if (F->pointer || F->poly_n ||
            (F->base && c2b_fsv_is_ptype(F->base)))
            F->model = SM_FIXEDTAB;
        else
            F->model = SM_VARTAB;
    } else if (F->count > 0 && !(F->base && c2b_streq(g_fsv_arena + F->base, "char"))) {
        F->model = SM_FIXEDARR;
    } else if (F->base && (c2b_streq(g_fsv_arena + F->base, "CUtlVector") ||
                           c2b_streq(g_fsv_arena + F->base, "CNetworkUtlVectorBase"))) {
        F->model = SM_VARARR;
    } else {
        F->model = SM_SIMPLE;
    }

    /* декодер: Simple/FixedArray — свой; VariableArray — child по generic-базе */
    if (F->model == SM_SIMPLE || F->model == SM_FIXEDARR)
        F->dec = c2b_fsv_decoder_id(F, F->base_id);
    else if (F->model == SM_VARARR)
        F->dec = c2b_fsv_decoder_id(F, F->gen_id);
    else
        F->dec = DT_VARINT_U;
}

struct c2b_fsv_ud { u32 base; u32 count; };

static i32 c2b_fsv_cb_field(const u8 *sub, u32 ln, u32 ord, void *ud)
{
    struct c2b_fsv_ud *u = (struct c2b_fsv_ud *)ud;
    if (u->base + ord >= C2B_FSV_MAX_FIELD) { g_fsv_ovf++; return 0; }
    c2b_fsv_resolve_field(sub, ln, &g_fsv_field[u->base + ord]);
    u->count = ord + 1;
    return 0;
}

static i32 c2b_fsv_cb_ser(const u8 *sub, u32 ln, u32 ord, void *ud)
{
    (void)ord; (void)ud;
    u32 name_sym = C2B_SYM_NONE, ver = 0;
    u32 idx_off = g_fsv_idx_n, idx_n = 0;
    u32 sp = 0;
    while (sp < ln) {
        u32 t2, c = c2b_read_varint(sub + sp, ln - sp, &t2);
        if (!c) { g_fsv_err++; return -1; }
        u32 f2 = t2 >> 3, w2 = t2 & 7;
        sp += c;
        if (f2 == 3 && w2 == 2) {               /* packed varint-список */
            u32 l2; c = c2b_read_varint(sub + sp, ln - sp, &l2);
            if (!c || l2 > ln - sp) { g_fsv_err++; return -1; }
            sp += c;
            u32 pp = 0;
            while (pp < l2) {
                u32 v; u32 c3 = c2b_read_varint(sub + sp + pp, l2 - pp, &v);
                if (!c3) { g_fsv_err++; return -1; }
                pp += c3;
                if (g_fsv_idx_n < C2B_FSV_MAX_IDX) g_fsv_idx[g_fsv_idx_n++] = (u16)v;
                else g_fsv_ovf++;
                idx_n++;
            }
            sp += l2;                           /* ЗАКРЫТЬ длину packed-блока */
        } else if (f2 == 3 && w2 == 0) {        /* одиночный unpacked */
            u32 v; c = c2b_read_varint(sub + sp, ln - sp, &v);
            if (!c) { g_fsv_err++; return -1; }
            sp += c;
            if (g_fsv_idx_n < C2B_FSV_MAX_IDX) g_fsv_idx[g_fsv_idx_n++] = (u16)v;
            else g_fsv_ovf++;
            idx_n++;
        } else if (w2 == 0) {
            u32 v; c = c2b_read_varint(sub + sp, ln - sp, &v);
            if (!c) { g_fsv_err++; return -1; }
            sp += c;
            if (f2 == 1) name_sym = v;
            else if (f2 == 2) ver = v;
        } else if (w2 == 2) {
            u32 l2; c = c2b_read_varint(sub + sp, ln - sp, &l2);
            if (!c || l2 > ln - sp) { g_fsv_err++; return -1; }
            sp += c + l2;
        } else if (w2 == 1) sp += 8;
        else if (w2 == 5) sp += 4;
        else { g_fsv_err++; return -1; }
    }
    u32 name_off = (name_sym != C2B_SYM_NONE) ? c2b_sym_lookup(name_sym) : 0;
    if (!name_off) { g_fsv_idx_n = idx_off; g_fsv_err++; return 0; }
    i32 sid = c2b_fsv_ser_register(name_off, (i32)ver);
    if (sid < 0) { g_fsv_idx_n = idx_off; return 0; }  /* переполнение: откат */
    g_fsv_ser[sid].idx_off = idx_off;
    g_fsv_ser[sid].n = (u16)idx_n;
    return 0;
}

/* проход по payload FSV: вызов cb для каждого wt2-поля с номером want */
static i32 c2b_fsv_walk(const u8 *pl, u32 n, u32 want, i32 (*cb)(const u8 *sub, u32 ln, u32 ord, void *ud), void *ud)
{
    u32 ip = 0, ord = 0;
    while (ip < n) {
        u32 tag, c = c2b_read_varint(pl + ip, n - ip, &tag);
        if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7;
        ip += c;
        u32 vl = c2b_field_len(pl + ip, n - ip, wt);
        if (!vl || vl > n - ip) return -1;
        if (f == want && wt == 2) {
            u32 l2, c2 = c2b_read_varint(pl + ip, n - ip, &l2);
            if (!c2 || l2 > n - ip - c2) return -1;
            i32 rc = cb(pl + ip + c2, l2, ord++, ud);   /* ДАННЫЕ, не len-байт */
            if (rc) return rc;
        } else if (f == want) {
            ord++;
        }
        ip += vl;
    }
    return 0;
}

/* парс полного сообщения svc_FlattenedSerializer (payload = чистый protobuf) */
static void c2b_fsv_parse(const u8 *pl, u32 n)
{
    u32 msg_field_base = g_fsv_field_n;
    g_fsv_msgs++;

    /* pass A: символы (ординалы сообщения) */
    g_fsv_msgsym_n = 0;
    {
        u32 ip = 0;
        while (ip < n) {
            u32 tag, c = c2b_read_varint(pl + ip, n - ip, &tag);
            if (!c) { g_fsv_err++; return; }
            u32 f = tag >> 3, wt = tag & 7;
            ip += c;
            u32 vl = c2b_field_len(pl + ip, n - ip, wt);
            if (!vl || vl > n - ip) { g_fsv_err++; return; }
            if (f == 2 && wt == 2) {
                u32 l2, c2 = c2b_read_varint(pl + ip, n - ip, &l2);
                if (!c2 || l2 > n - ip - c2) { g_fsv_err++; return; }
                if (g_fsv_msgsym_n < C2B_FSV_MAX_SYM) {
                    g_fsv_msgsym[g_fsv_msgsym_n++] = c2b_sym_store(pl + ip + c2, l2);
                } else g_fsv_ovf++;
            } else if (f == 4 && wt == 2) {     /* ProtoCoordSizeParams (G-4) */
                u32 l2, c2 = c2b_read_varint(pl + ip, n - ip, &l2);
                if (!c2 || l2 > n - ip - c2) { g_fsv_err++; return; }
                u32 sp2 = c2, end2 = c2 + l2;
                while (sp2 < end2) {
                    u32 t2, c3 = c2b_read_varint(pl + ip + sp2, end2 - sp2, &t2);
                    if (!c3) break;
                    sp2 += c3;
                    if ((t2 & 7) != 0) break;
                    u32 v2; c3 = c2b_read_varint(pl + ip + sp2, end2 - sp2, &v2);
                    if (!c3) break;
                    sp2 += c3;
                    switch (t2 >> 3) {
                    case 1: g_fsv_coord.int_bits = v2; break;
                    case 2: g_fsv_coord.frac_bits = v2; break;
                    case 3: g_fsv_coord.int_mp = v2; break;
                    case 4: g_fsv_coord.frac_mp = v2; break;
                    case 5: g_fsv_coord.normal_bits = v2; break;
                    case 6: g_fsv_coord.angle_bits = v2; break;
                    }
                }
            }
            ip += vl;
        }
    }
    /* pass B1: регистрация сериализаторов + пул индексов */
    if (c2b_fsv_walk(pl, n, 1, c2b_fsv_cb_ser, 0) != 0) { g_fsv_err++; return; }
    /* pass B2: resolve всех f3-полей в пул (id = msg_base + ординал) */
    {
        struct c2b_fsv_ud ud; ud.base = msg_field_base; ud.count = 0;
        if (c2b_fsv_walk(pl, n, 3, c2b_fsv_cb_field, &ud) != 0) { g_fsv_err++; return; }
        g_fsv_field_n = msg_field_base + ud.count;
    }
    g_fsv_gen++;                                 /* инвалидация кэша классов (G-4c) */
#ifndef C2B_SELFTEST
    C2B_LOGS("[c2b] FSV msg ser="); C2B_LOGN(g_fsv_ser_n);
    C2B_LOGS("fld="); C2B_LOGN(g_fsv_field_n);
    C2B_LOGS("sym="); C2B_LOGN(g_fsv_msgsym_n);
    C2B_LOGS("idx="); C2B_LOGN(g_fsv_idx_n);
    C2B_LOGS("arena="); C2B_LOGN(g_fsv_arena_n);
    C2B_LOGS("\n");
#endif
}

/* S2 ServerInfo(40) f11 max_classes -> ширина class_id (G-4) */
/* R37: svc_ServerInfo 40->8 — синтез S1-хвоста (protocol/mcl/mcs + csgo + slot).
 * Карта g_renum_40 больше НЕ пропускает S2 f1/f10/f11 — они синтезируются
 * с клампами (эталон 5cce9ff4: g_renum_40 @0x3fc20, append @0x11bf4-0x11d99). */
static u32 g_si_protocol = 13762;  /* S1 PROTOCOL_VERSION (env C2B_S1_PROTOCOL) */
static u32 g_si_v_mcl    = 64;     /* max_clients -> S1 f11 (clamp raw 1..64) */
static u32 g_si_v_mcs    = 512;    /* max_classes -> S1 f12 (clamp raw 238..512) */
static u32 g_si_pr, g_si_mcl_raw, g_si_mcs_raw;      /* FINI2: pr/mclr/mcsr */
static u8  g_si_has_f14;  static u32 g_si_f14_len;   /* S2 f14 game_dir */
static u8  g_si_no_slot;  static u32 g_si_est;       /* per-message (single-thread) */

static u32 c2b_var_len(u32 v) { u32 n = 1; while (v > 0x7F) { v >>= 7; n++; } return n; }

static void c2b_si_parse(const u8 *pl, u32 n)
{
    u32 ip = 0, mcl = 0, mcs = 0, f10 = 0, f11 = 0;
    g_si_has_f14 = 0; g_si_f14_len = 0; g_si_no_slot = 1;   /* дефолт: добавлять */
    while (ip < n) {
        u64 tag; u32 c = c2b_read_varint64(pl + ip, n - ip, &tag);   /* R34-ридер */
        u32 f, wt, vl;
        if (!c) break;                                  /* кривой payload -> дефолты */
        f = (u32)(tag >> 3); wt = (u32)(tag & 7); ip += c;
        vl = c2b_field_len(pl + ip, n - ip, wt);
        if (!vl || vl > n - ip) break;
        if (wt == 0) {
            u64 v; u32 vc = c2b_read_varint64(pl + ip, n - ip, &v);
            if (!vc) break;
            if (f == 1 && g_si_pr == 0) g_si_pr = (u32)v;
            else if (f == 10) { mcl = (u32)v; f10 = 1; }
            else if (f == 11) { mcs = (u32)v; f11 = 1; }
            else if (f == 12) { g_si_no_slot = 0; break; }   /* слот есть — дальше не ходим */
        } else if (wt == 2 && f == 14) {
            g_si_has_f14 = 1; g_si_f14_len = (vl > 5) ? vl - 5 : 0;  /* len из c2b_field_len (таг+varint) */
        }
        ip += vl;
    }
    g_si_mcl_raw = f10 ? mcl : 0;
    g_si_mcs_raw = f11 ? mcs : 0;
    g_si_v_mcl   = f10 ? (mcl ? (mcl < 64 ? mcl : 64) : 1) : 64;      /* 0->1, >64->64 */
    g_si_v_mcs   = f11 ? (mcs < 238 ? 238 : (mcs > 512 ? 512 : mcs)) : 512;
    g_fsv_max_classes = g_si_v_mcs;                    /* R37: кламп вместо raw */
    /* FINI2 si{...}: синтезированный S1 protocol + клампы (mclr/mcsr = S1-only crc, 0) */
    g_fini2.si_pr   = g_si_protocol;
    g_fini2.si_mcl  = g_si_v_mcl;
    g_fini2.si_mcs  = g_si_v_mcs;
    g_fini2.si_mclr = 0;
    g_fini2.si_mcsr = 0;
    g_si_est = 3 + c2b_var_len(g_si_protocol) + c2b_var_len(g_si_v_mcl) +
               c2b_var_len(g_si_v_mcs);
    if (!g_si_has_f14 || g_si_f14_len == 0) g_si_est += 6;   /* 7A 04 "csgo" */
    if (g_si_no_slot)                       g_si_est += 11;  /* 68 FFx9 01 */
}

/* ---------- фаза G-3d: S1 slot-space + словарь S2->S1 ----------
 * Слот-пространство = flatten С1-блоба ТОЧНО по алгоритму движка (референс:
 * analysis/ext/csgo-demoinfo/demofiledump.cpp GatherProps/FlattenDataTable):
 *   - skip INSIDEARRAY(0x100)/EXCLUDE(0x40) (в блобе EXCLUDE нет);
 *   - DPT_DataTable(6): COLLAPSIBLE(0x1000) -> inline (в блобе нет), иначе
 *     gather(sub) аппендится в ФИНАЛ сразу (саб-флэттены РАНЬШЕ собственных
 *     пропов корня — порядок WireImage клиента);
 *   - DPT_Array(5) = ОДИН слот (Array-проп, элемент = props[i-1]);
 *   - priority-сортировка опущена: в блобе все priority=64, CHANGES_OFTEN нет
 *     => identity (появится не-64 -> счётчик s1_pri).
 * Числа (step_g8_s1_flatten.py): 275 корней, 24290 слотов, DT_CSPlayer=717.
 * Словарь S2->S1 (правила v0): (a) direct leaf == varName; (b) sendNode +
 * "[x|y|z]" — S2-компоненты вектора; (c) varName + "[0..2]" — S2 целый Vector
 * против S1-компонент; (d) miss -> лог. Имя листа = varName (канонизация
 * коллизий node.varName на матчинг не влияет — G-4 ходит по ординалам). */
#define C2B_S1_MAX_PROPS 2400
#define C2B_S1_MAX_SLOTS 32000
#define C2B_S1N_ARENA    (64*1024)
#define C2B_S1_MAX_OWN   160    /* own-пропов таблицы на уровень DFS */
#define C2B_S1_MAX_DEPTH 24
#define C2B_S1_WALK_DEPTH 8    /* глубина обхода сериализаторов */

typedef struct {           /* проп S1-таблицы (из блоба) */
    u32 name_off;          /* аренда c2b_s1n */
    u32 dt_name_off;       /* DataTable: dt_name (0 = нет) */
    u16 type, flags, priority, num_elements;
} c2b_s1_prop_t;           /* 16 байт */

typedef struct {           /* слот flatten-пространства класса */
    u32 name_hash;
    u16 dpt;               /* DPT_* (6 не бывает — таблицы раскрываются) */
    u16 num;               /* DPT_Array: num_elements */
    u16 elem_dpt;          /* DPT_Array: dpt элемента, 0xFFFF = нет */
    u16 pad;
} c2b_s1_slot_t;           /* 12 байт */

static c2b_s1_prop_t g_s1_props[C2B_S1_MAX_PROPS];
static u32 g_s1_props_n;
static c2b_s1_slot_t g_s1_slots[C2B_S1_MAX_SLOTS];
static u32 g_s1_slots_n;
static u8  g_s1_prop_dec[DT_BLOB_TABLES];   /* таблица декодирована */
static u32 g_s1_prop_pos[DT_BLOB_TABLES], g_s1_prop_cnt[DT_BLOB_TABLES];
static u32 g_s1_slot_pos[DT_BLOB_TABLES], g_s1_slot_cnt[DT_BLOB_TABLES];
static char g_s1n_arena[C2B_S1N_ARENA];
static u32  g_s1n_n = 1;
static u32  g_s1_pri;                       /* не-64 priority (сортировку ждёт) */
static u32  g_s1_err;                       /* переполнения/битые кадры */

static u32 c2b_s1n_store(const char *s, u32 n)
{
    if (g_s1n_n + n + 1 > C2B_S1N_ARENA) { g_s1_err++; return 0; }
    u32 off = g_s1n_n;
    for (u32 i = 0; i < n; i++) g_s1n_arena[off + i] = s[i];
    g_s1n_arena[off + n] = 0;
    g_s1n_n += n + 1;
    return off;
}

/* разбор кадра svc_SendTable(9) из блоба: пропы -> g_s1_props */
static i32 c2b_s1_decode_tbl(u32 ti)
{
    if (g_s1_prop_dec[ti]) return 0;
    const dt_entry *e = &g_dt_index[ti];
    const u8 *p = g_dt_blob + e->off;
    u32 rem = e->len, tag, ln, c;
    c = c2b_read_varint(p, rem, &tag); if (!c || tag != 9) { g_s1_err++; return -1; }
    p += c; rem -= c;
    c = c2b_read_varint(p, rem, &ln);  if (!c || ln > rem) { g_s1_err++; return -1; }
    p += c; rem -= c;
    u32 start = g_s1_props_n, ip = 0;
    while (ip < ln) {
        u32 t2, v;
        c = c2b_read_varint(p + ip, ln - ip, &t2); if (!c) { g_s1_err++; return -1; }
        ip += c;
        u32 f = t2 >> 3, wt = t2 & 7;
        if (f != 4) {                          /* is_end/name/needs_decoder */
            if (wt == 0) {
                c = c2b_read_varint(p + ip, ln - ip, &v); if (!c) { g_s1_err++; return -1; }
                ip += c;
            } else if (wt == 2) {
                c = c2b_read_varint(p + ip, ln - ip, &v); if (!c || v > ln - ip) { g_s1_err++; return -1; }
                ip += c + v;
            } else { g_s1_err++; return -1; }
            continue;
        }
        if (wt != 2) { g_s1_err++; return -1; }
        c = c2b_read_varint(p + ip, ln - ip, &v); if (!c || v > ln - ip) { g_s1_err++; return -1; }
        ip += c;
        u32 sl = v;
        const u8 *sp = p + ip; ip += sl;
        if (g_s1_props_n >= C2B_S1_MAX_PROPS) { g_s1_err++; return -1; }
        c2b_s1_prop_t *pr = &g_s1_props[g_s1_props_n++];
        pr->name_off = 0; pr->dt_name_off = 0;
        pr->type = 0; pr->flags = 0; pr->priority = 64; pr->num_elements = 0;
        u32 kp = 0;
        while (kp < sl) {
            u32 t3, c3 = c2b_read_varint(sp + kp, sl - kp, &t3);
            if (!c3) { g_s1_err++; return -1; }
            kp += c3;
            u32 f3 = t3 >> 3, w3 = t3 & 7;
            if (w3 == 0) {
                u32 v3; c3 = c2b_read_varint(sp + kp, sl - kp, &v3);
                if (!c3) { g_s1_err++; return -1; }
                kp += c3;
                if (f3 == 1) pr->type = (u16)v3;
                else if (f3 == 3) pr->flags = (u16)v3;
                else if (f3 == 4) pr->priority = (u16)v3;
                else if (f3 == 6) pr->num_elements = (u16)v3;
            } else if (w3 == 2) {
                u32 l3; c3 = c2b_read_varint(sp + kp, sl - kp, &l3);
                if (!c3 || l3 > sl - kp) { g_s1_err++; return -1; }
                kp += c3;
                if (f3 == 2) pr->name_off = c2b_s1n_store((const char *)sp + kp, l3);
                else if (f3 == 5) pr->dt_name_off = c2b_s1n_store((const char *)sp + kp, l3);
                kp += l3;
            } else {                           /* low/high f32 и пр. — скип */
                c3 = c2b_field_len(sp + kp, sl - kp, w3);
                if (!c3) { g_s1_err++; return -1; }
                kp += c3;
            }
        }
    }
    g_s1_prop_dec[ti] = 1;
    g_s1_prop_pos[ti] = start;
    g_s1_prop_cnt[ti] = g_s1_props_n - start;
    return 0;
}

static i32 c2b_s1_emit(u32 pi, u32 ei)
{
    if (g_s1_slots_n >= C2B_S1_MAX_SLOTS) { g_s1_err++; return -1; }
    c2b_s1_prop_t *pp = &g_s1_props[pi];
    c2b_s1_slot_t *s = &g_s1_slots[g_s1_slots_n++];
    s->name_hash = c2b_fnv1a(g_s1n_arena + pp->name_off);
    s->dpt = pp->type;
    s->num = pp->num_elements;
    s->elem_dpt = (ei != 0xFFFFFFFFu) ? g_s1_props[ei].type : 0xFFFFu;
    s->pad = 0;
    return 0;
}

typedef struct { u16 prop; u16 elem; } c2b_s1_tent_t;

static i32 c2b_s1_iterate(u32 ti, i32 depth)
{
    if (depth > C2B_S1_MAX_DEPTH || c2b_s1_decode_tbl(ti) != 0) { g_s1_err++; return -1; }
    c2b_s1_tent_t temp[C2B_S1_MAX_OWN];
    u32 tn = 0, p0 = g_s1_prop_pos[ti], pc = g_s1_prop_cnt[ti];
    for (u32 k = 0; k < pc; k++) {
        c2b_s1_prop_t *pp = &g_s1_props[p0 + k];
        if (pp->flags & 0x100u) continue;               /* INSIDEARRAY */
        if (pp->flags & 0x40u)  { g_s1_pri++; continue; }/* EXCLUDE — нет в блобе */
        if (pp->type == 6) {                            /* DataTable */
            const dt_entry *sub = c2b_dt_find(c2b_fnv1a(g_s1n_arena + pp->dt_name_off));
            if (!sub) { g_s1_err++; continue; }
            u32 sti = (u32)(sub - g_dt_index);
            if (pp->flags & 0x1000u) {                  /* COLLAPSIBLE — inline */
                if (c2b_s1_iterate(sti, depth + 1) != 0) return -1;
            } else {                                    /* саб-флэттен сразу в финал */
                if (c2b_s1_iterate(sti, depth + 1) != 0) return -1;
            }
        } else {
            if (tn >= C2B_S1_MAX_OWN) { g_s1_err++; continue; }
            if (pp->type == 5) {                        /* Array: elem = props[i-1] */
                temp[tn].prop = (u16)k;
                temp[tn].elem = (k > 0 && g_s1_props[p0 + k - 1].flags & 0x100u)
                                ? (u16)(k - 1) : 0xFFFFu;
            } else {
                temp[tn].prop = (u16)k;
                temp[tn].elem = 0xFFFFu;
            }
            tn++;
        }
    }
    for (u32 k = 0; k < tn; k++) {                      /* temp -> финал */
        u32 ei = (temp[k].elem == 0xFFFFu) ? 0xFFFFFFFFu : p0 + temp[k].elem;
        if (c2b_s1_emit(p0 + temp[k].prop, ei) != 0) return -1;
    }
    return 0;
}

/* слоты класса-корня (кэш по позиции dt_index; sentinel pos==0 && cnt==0) */
static i32 c2b_s1_slots_of(u32 ti, u32 *off, u32 *cnt)
{
    if (g_s1_slot_pos[ti] || g_s1_slot_cnt[ti]) {
        *off = g_s1_slot_pos[ti]; *cnt = g_s1_slot_cnt[ti];
        return 0;
    }
    u32 start = g_s1_slots_n;
    if (c2b_s1_iterate(ti, 0) != 0) return -1;
    g_s1_slot_pos[ti] = start;
    g_s1_slot_cnt[ti] = g_s1_slots_n - start;
    *off = start; *cnt = g_s1_slot_cnt[ti];
    return 0;
}

/* матч листа S2 против слотов класса: (a) direct, (b) node+"[xyz]",
 * (c) vn+"[0..2]" (S2-Vector против S1-компонент). comp: -1 = не компонента */
static i32 c2b_slot_match(u32 off, u32 cnt, const char *vn, u32 node_off, i32 *comp)
{
    u32 h = c2b_fnv1a(vn), hits = 0;
    for (u32 i = 0; i < cnt; i++)
        if (g_s1_slots[off + i].name_hash == h) hits++;
    if (hits) { *comp = -1; return (i32)hits; }
    /* (b) node + "[x|y|z]" */
    if (node_off) {
        u32 vl = 0;
        while (vn[vl]) vl++;
        char lc = vl ? vn[vl - 1] : 0;
        i32 ci = (lc == 'x' || lc == 'X') ? 0
               : (lc == 'y' || lc == 'Y') ? 1
               : (lc == 'z' || lc == 'Z') ? 2 : -1;
        if (ci >= 0) {
            const char *nn = g_fsv_arena + node_off;
            char buf[72]; u32 bn = 0;
            while (nn[bn] && bn < 60) { buf[bn] = nn[bn]; bn++; }
            if (bn + 4 < sizeof(buf)) {
                buf[bn++] = '['; buf[bn++] = (char)('0' + ci); buf[bn++] = ']'; buf[bn] = 0;
                u32 h2 = c2b_fnv1a(buf), hits2 = 0;
                for (u32 i = 0; i < cnt; i++)
                    if (g_s1_slots[off + i].name_hash == h2) hits2++;
                if (hits2) { *comp = ci; return (i32)hits2; }
            }
        }
    }
    /* (c) целый S2-Vector против S1 "vn[0..2]" */
    {
        u32 vl = 0;
        while (vn[vl]) vl++;
        if (vl && vl < 60) {
            char buf[72];
            for (u32 i = 0; i < vl; i++) buf[i] = vn[i];
            u32 h0 = 0;
            buf[vl] = '['; buf[vl + 1] = '0'; buf[vl + 2] = ']'; buf[vl + 3] = 0;
            h0 = c2b_fnv1a(buf);
            for (u32 i = 0; i < cnt; i++)
                if (g_s1_slots[off + i].name_hash == h0) { *comp = -2; return 1; }
        }
    }
    return 0;
}

/* покрытие-лог словаря (живая диагностика знакона) */
static u32 g_fmap_cls, g_fmap_paths, g_fmap_hit, g_fmap_vec, g_fmap_amb;
static u32 g_fmap_miss, g_fmap_nofsv, g_fmap_slots_max;
static char g_fmap_misses[12][28];
static u32  g_fmap_miss_n;

static void c2b_fmap_walk_ser(u32 ser_id, u32 off, u32 cnt, i32 depth)
{
    if (depth > C2B_S1_WALK_DEPTH || ser_id == C2B_FSV_SER_NUL ||
        ser_id >= g_fsv_ser_n) return;
    c2b_fsv_ser_t *S = &g_fsv_ser[ser_id];
    for (u32 k = 0; k < S->n; k++) {
        u32 ref = S->fbase + g_fsv_idx[S->idx_off + k];
        if (ref >= g_fsv_field_n) { g_fmap_miss++; continue; }
        c2b_fsv_field_t *F = &g_fsv_field[ref];
        if (F->model == SM_FIXEDTAB || F->model == SM_VARTAB) {
            c2b_fmap_walk_ser(F->ser_id, off, cnt, depth + 1);  /* узел — не слот */
            continue;
        }
        g_fmap_paths++;
        const char *vn = g_fsv_arena + F->name;
        i32 comp = -1;
        i32 mh = c2b_slot_match(off, cnt, vn, F->node, &comp);
        if (mh > 0) {
            g_fmap_hit++;
            if (mh > 1) g_fmap_amb++;
            if (comp >= 0 || comp == -2) g_fmap_vec++;
            continue;
        }
        g_fmap_miss++;
        if (g_fmap_miss_n < 12) {
            u32 i = 0;
            while (vn[i] && i < 27) { g_fmap_misses[g_fmap_miss_n][i] = vn[i]; i++; }
            g_fmap_misses[g_fmap_miss_n][i] = 0;
            g_fmap_miss_n++;
        }
    }
}

static void c2b_fmap_class(const char *cls, const char *dt, i32 ser_id)
{
    if (!g_fsv_ser_n) { g_fmap_nofsv++; return; }
    g_fmap_cls++;
    const dt_entry *e = c2b_dt_find(c2b_fnv1a(dt));
    if (!e) return;                          /* g_dt_misses уже посчитан */
    u32 ti = (u32)(e - g_dt_index), off, cnt;
    if (c2b_s1_slots_of(ti, &off, &cnt) != 0) return;
    if (cnt > g_fmap_slots_max) g_fmap_slots_max = cnt;
    u32 ph = g_fmap_paths, hh = g_fmap_hit, mm = g_fmap_miss;
    g_fmap_miss_n = 0;
    if (ser_id >= 0) c2b_fmap_walk_ser((u32)ser_id, off, cnt, 0);
    C2B_LOGS("[c2b] FMAP cls="); C2B_LOGS(cls);
    C2B_LOGS(" dt="); C2B_LOGS(dt);
    C2B_LOGS(" slots="); C2B_LOGN(cnt);
    C2B_LOGS(" paths="); C2B_LOGN(g_fmap_paths - ph);
    C2B_LOGS(" hit="); C2B_LOGN(g_fmap_hit - hh);
    C2B_LOGS(" vec="); C2B_LOGN(g_fmap_vec);
    C2B_LOGS(" miss="); C2B_LOGN(g_fmap_miss - mm);
    if (g_fmap_miss_n) {
        C2B_LOGS(" top:");
        for (u32 i = 0; i < g_fmap_miss_n && i < 12; i++) {
            C2B_LOGS(" "); C2B_LOGS(g_fmap_misses[i]);
        }
    }
    C2B_LOGS("\n");
}

/* ---------- фаза G-4: PacketEntities — S2 битстрим -> S1 битстрим ----------
 * Декод = точная реплика demoinfocs-golang sendtablescs2 (entity.go/field_path.go/
 * reader.go/field_decoder.go/quantizedfloat.go). Энкод = Valve csgo-demoinfo
 * (demofiledump.cpp ReadPacketEntities/ReadNewEntity/ReadFieldIndex + demofilepropdecode.cpp
 * — S1 wire: [ubitvar idx-delta][leave/enter биты][class classbits][serial 10b]
 * [newWay=1][индексы-дельты, end=0xFFF][значения по DPT_*]).
 * Потоковая перекладина: S2 поле -> словарь G-3d -> S1 слот. Позиция:
 * CBodyComponent.m_cellX + m_vecX -> m_vecOrigin = cell*512 - 16384 + off
 * (entity.go coordFromCell, cellBits=9). Хаффман: s2s1_fphuff.h. */
#include "s2s1_fphuff.h"

static u32 g_g4_pkts, g_g4_out, g_g4_pass, g_g4_err, g_g4_ovf, g_g4_desync;
static u32 g_g4_poly;                     /* активации poly-типов (G-4c) */

typedef struct c2b_g4_ent_s c2b_g4_ent_t; /* per-entity состояние G-4 */
#define C2B_G4_ENT_MAX 4096
struct c2b_g4_ent_s {
    u16 cls;                   /* s2 class_id + 1 (0 = нет) */
    u16 pad;
    u32 cell[3];
    float coff[3];
    u8 cellhave, offhave;
    float org[3];              /* R42: кэш собранной позиции (cell*512-16384+off) */
    u8 orghave;                /* R42: бит ci установлен, когда org[ci] валиден */
    u16 ps[C2B_G4_POLY_SLOTS]; /* активные сериализаторы poly-полей (G-4c; 0xFFFF = нет) */
};
static u32 g_g4_ent_new, g_g4_ent_upd, g_g4_ent_del, g_g4_fields, g_g4_miss;

/* --- бит-ридер LSB-first (reader.go) --- */
typedef struct { const u8 *buf; u32 size, pos; u64 bitval; u32 bitcnt; u32 ovf; } c2b_br_t;

static void c2b_br_init(c2b_br_t *r, const u8 *b, u32 n)
{ r->buf = b; r->size = n; r->pos = 0; r->bitval = 0; r->bitcnt = 0; r->ovf = 0; }

static u32 c2b_br_bits(c2b_br_t *r, u32 n)
{
    if (!n) return 0;
    while (r->bitcnt < n) {
        if (r->pos >= r->size) { r->ovf++; return 0; }
        r->bitval |= (u64)r->buf[r->pos++] << r->bitcnt;
        r->bitcnt += 8;
    }
    u32 x = (u32)(r->bitval & (((u64)1 << n) - 1));
    r->bitval >>= n; r->bitcnt -= n;
    return x;
}

static u32 c2b_br_bit(c2b_br_t *r) { return c2b_br_bits(r, 1); }
static u32 c2b_br_byte(c2b_br_t *r) { return c2b_br_bits(r, 8); }

static u32 c2b_br_varuint32(c2b_br_t *r)
{
    u32 x = 0, s = 0;
    for (;;) {
        u32 b = c2b_br_byte(r);
        x |= (b & 0x7F) << s;
        s += 7;
        if (!(b & 0x80) || s == 35) break;
    }
    return x;
}

static u64 c2b_br_varuint64(c2b_br_t *r)
{
    u64 x = 0; u32 s = 0;
    for (;;) {
        u32 b = c2b_br_byte(r);
        x |= (u64)(b & 0x7F) << s;
        s += 7;
        if (!(b & 0x80) || s >= 64) break;
    }
    return x;
}

static i32 c2b_br_varint32(c2b_br_t *r)          /* zigzag (readVarInt32) */
{
    u32 ux = c2b_br_varuint32(r);
    i32 x = (i32)(ux >> 1);
    return (ux & 1) ? ~x : x;
}

static u32 c2b_br_ubitvar(c2b_br_t *r)           /* 6-битный эскейп (S1==S2) */
{
    u32 ret = c2b_br_bits(r, 6);
    switch (ret & 0x30) {
    case 16: ret = (ret & 15) | (c2b_br_bits(r, 4) << 4); break;
    case 32: ret = (ret & 15) | (c2b_br_bits(r, 8) << 4); break;
    case 48: ret = (ret & 15) | (c2b_br_bits(r, 28) << 4); break;
    }
    return ret;
}

static u32 c2b_br_ubitvar_fp(c2b_br_t *r)        /* fieldpath-кодирование */
{
    if (c2b_br_bit(r)) return c2b_br_bits(r, 2);
    if (c2b_br_bit(r)) return c2b_br_bits(r, 4);
    if (c2b_br_bit(r)) return c2b_br_bits(r, 10);
    if (c2b_br_bit(r)) return c2b_br_bits(r, 17);
    return c2b_br_bits(r, 31);
}

static float c2b_br_coord(c2b_br_t *r)
{
    u32 iv = c2b_br_bits(r, 1), fv = c2b_br_bits(r, 1);
    if (!iv && !fv) return 0.0f;
    u32 neg = c2b_br_bit(r);
    u32 ival = iv ? c2b_br_bits(r, 14) + 1 : 0;
    u32 fval = fv ? c2b_br_bits(r, 5) : 0;
    float v = (float)ival + (float)fval * (1.0f / 32.0f);
    return neg ? -v : v;
}

static float c2b_br_angle(c2b_br_t *r, u32 n)
{ return (float)c2b_br_bits(r, n) * (360.0f / (float)(1u << n)); }

static float c2b_br_normal(c2b_br_t *r)
{
    u32 neg = c2b_br_bit(r);
    float v = (float)c2b_br_bits(r, 11) * (1.0f / 2047.0f);
    return neg ? -v : v;
}

static float c2b_sqrtf(float x)                  /* без libc: bit-hack + Ньютон */
{
    union f32u u; u.f = x;
    if (!(u.u & 0x7FFFFFFFu)) return 0.0f;
    if (u.u & 0x80000000u) return 0.0f;
    u.u = (u.u >> 1) + 0x1FC00000u;
    float y = u.f;
    y = 0.5f * (y + x / y);
    y = 0.5f * (y + x / y);
    y = 0.5f * (y + x / y);
    return y;
}

static void c2b_br_3bitnormal(c2b_br_t *r, float v[3])
{
    v[0] = v[1] = v[2] = 0.0f;
    u32 hx = c2b_br_bit(r), hy = c2b_br_bit(r);
    if (hx) v[0] = c2b_br_normal(r);
    if (hy) v[1] = c2b_br_normal(r);
    u32 negz = c2b_br_bit(r);
    float ps = v[0] * v[0] + v[1] * v[1];
    v[2] = (ps < 1.0f) ? c2b_sqrtf(1.0f - ps) : 0.0f;
    if (negz) v[2] = -v[2];
}

static u32 c2b_f32_to_bits(float f) { union f32u u; u.f = f; return u.u; }
static float c2b_f32_from_bits(u32 b) { union f32u u; u.u = b; return u.f; }

/* --- field path: реплика field_path.go (fp НЕ сбрасывается между путями) --- */
typedef struct { i32 path[7]; i32 last; i32 done; } c2b_fp_t;

static void c2b_fp_reset(c2b_fp_t *fp)
{
    fp->path[0] = -1;
    fp->path[1] = fp->path[2] = fp->path[3] = 0;
    fp->path[4] = fp->path[5] = fp->path[6] = 0;
    fp->last = 0; fp->done = 0;
}

static i32 c2b_fp_ladd(c2b_fp_t *fp, i32 v)
{ if (fp->last < 0 || fp->last > 6) return -1; fp->path[fp->last] += v; return 0; }

static i32 c2b_fp_eadd(c2b_fp_t *fp, i32 i, i32 v)
{ if (i < 0 || i > 6) return -1; fp->path[i] += v; return 0; }

static i32 c2b_fp_push0(c2b_fp_t *fp)            /* last++; path[last]=0 */
{
    if (fp->last + 1 > 6) return -1;
    fp->last++; fp->path[fp->last] = 0; return 0;
}

static i32 c2b_fp_push_set(c2b_fp_t *fp, i32 v)  /* last++; path[last]=v */
{
    if (fp->last + 1 > 6) return -1;
    fp->last++; fp->path[fp->last] = v; return 0;
}

static i32 c2b_fp_push_rel(c2b_fp_t *fp, i32 v)  /* last++; path[last]+=v */
{
    if (fp->last + 1 > 6) return -1;
    fp->last++; fp->path[fp->last] += v; return 0;
}

static i32 c2b_fp_pop(c2b_fp_t *fp, i32 n)
{
    for (i32 i = 0; i < n; i++) {
        if (fp->last < 0) return -1;
        fp->path[fp->last] = 0;
        fp->last--;
    }
    return 0;
}

/* readFieldPaths (field_path.go): читает ВСЕ пути до FieldPathEncodeFinish.
 * fp — персистентное состояние (не сбрасывается между путями), каждый путь —
 * снапшот в paths[] (если paths != 0). Возврат: число путей, <0 — ошибка. */
static i32 c2b_fp_read_all(c2b_br_t *r, c2b_fp_t *fp, c2b_fp_t *paths, u32 max_paths)
{
    u32 pn = 0;
    for (;;) {
        if (r->ovf) return -1;
        i32 node = 0, op = -1;
        for (i32 k = 0; k < 18; k++) {           /* max код 17 бит + guard */
            node = c2b_br_bit(r) ? g_fph_nodes[node].right : g_fph_nodes[node].left;
            if (node < 0 || node >= C2B_FP_MAXNODES) return -1;
            if (g_fph_nodes[node].left < 0) { op = g_fph_nodes[node].op; break; }
        }
        if (op < 0 || op >= C2B_FP_NOPS) return -1;
        switch (op) {
        case 0: if (c2b_fp_ladd(fp, 1)) return -1; break;
        case 1: if (c2b_fp_ladd(fp, 2)) return -1; break;
        case 2: if (c2b_fp_ladd(fp, 3)) return -1; break;
        case 3: if (c2b_fp_ladd(fp, 4)) return -1; break;
        case 4: if (c2b_fp_ladd(fp, (i32)c2b_br_ubitvar_fp(r) + 5)) return -1; break;
        case 5: if (c2b_fp_push0(fp)) return -1; break;
        case 6: { i32 v = (i32)c2b_br_ubitvar_fp(r); if (c2b_fp_push_set(fp, v)) return -1; } break;
        case 7: if (c2b_fp_ladd(fp, 1) || c2b_fp_push0(fp)) return -1; break;
        case 8: { i32 v = (i32)c2b_br_ubitvar_fp(r);
                  if (c2b_fp_ladd(fp, 1) || c2b_fp_push_set(fp, v)) return -1; } break;
        case 9: { i32 v = (i32)c2b_br_ubitvar_fp(r);
                  if (c2b_fp_ladd(fp, v) || c2b_fp_push0(fp)) return -1; } break;
        case 10: { i32 a = (i32)c2b_br_ubitvar_fp(r) + 2, b = (i32)c2b_br_ubitvar_fp(r) + 1;
                   if (c2b_fp_ladd(fp, a) || c2b_fp_push_set(fp, b)) return -1; } break;
        case 11: { i32 a = (i32)c2b_br_bits(r, 3) + 2, b = (i32)c2b_br_bits(r, 3) + 1;
                   if (c2b_fp_ladd(fp, a) || c2b_fp_push_set(fp, b)) return -1; } break;
        case 12: { i32 a = (i32)c2b_br_bits(r, 4) + 2, b = (i32)c2b_br_bits(r, 4) + 1;
                   if (c2b_fp_ladd(fp, a) || c2b_fp_push_set(fp, b)) return -1; } break;
        case 13: { i32 a = (i32)c2b_br_ubitvar_fp(r), b = (i32)c2b_br_ubitvar_fp(r);
                   if (c2b_fp_push_rel(fp, a) || c2b_fp_push_rel(fp, b)) return -1; } break;
        case 14: { i32 a = (i32)c2b_br_bits(r, 5), b = (i32)c2b_br_bits(r, 5);
                   if (c2b_fp_push_set(fp, a) || c2b_fp_push_set(fp, b)) return -1; } break;
        case 15: { i32 a = (i32)c2b_br_ubitvar_fp(r), b = (i32)c2b_br_ubitvar_fp(r),
                       c = (i32)c2b_br_ubitvar_fp(r);
                   if (c2b_fp_push_rel(fp, a) || c2b_fp_push_rel(fp, b) ||
                       c2b_fp_push_rel(fp, c)) return -1; } break;
        case 16: { i32 a = (i32)c2b_br_bits(r, 5), b = (i32)c2b_br_bits(r, 5),
                       c = (i32)c2b_br_bits(r, 5);
                   if (c2b_fp_push_set(fp, a) || c2b_fp_push_set(fp, b) ||
                       c2b_fp_push_set(fp, c)) return -1; } break;
        case 17: { i32 a = (i32)c2b_br_ubitvar_fp(r), b = (i32)c2b_br_ubitvar_fp(r);
                   if (c2b_fp_ladd(fp, 1) || c2b_fp_push_rel(fp, a) ||
                       c2b_fp_push_rel(fp, b)) return -1; } break;
        case 18: { i32 a = (i32)c2b_br_bits(r, 5), b = (i32)c2b_br_bits(r, 5);
                   if (c2b_fp_ladd(fp, 1) || c2b_fp_push_set(fp, a) ||
                       c2b_fp_push_set(fp, b)) return -1; } break;
        case 19: { i32 a = (i32)c2b_br_ubitvar_fp(r), b = (i32)c2b_br_ubitvar_fp(r),
                       c = (i32)c2b_br_ubitvar_fp(r);
                   if (c2b_fp_ladd(fp, 1) || c2b_fp_push_rel(fp, a) ||
                       c2b_fp_push_rel(fp, b) || c2b_fp_push_rel(fp, c)) return -1; } break;
        case 20: { i32 a = (i32)c2b_br_bits(r, 5), b = (i32)c2b_br_bits(r, 5),
                       c = (i32)c2b_br_bits(r, 5);
                   if (c2b_fp_ladd(fp, 1) || c2b_fp_push_set(fp, a) ||
                       c2b_fp_push_set(fp, b) || c2b_fp_push_set(fp, c)) return -1; } break;
        case 21: { i32 a = (i32)c2b_br_ubitvar(r) + 2, b = (i32)c2b_br_ubitvar_fp(r),
                       c = (i32)c2b_br_ubitvar_fp(r);
                   if (c2b_fp_ladd(fp, a) || c2b_fp_push_rel(fp, b) ||
                       c2b_fp_push_rel(fp, c)) return -1; } break;
        case 22: { i32 a = (i32)c2b_br_ubitvar(r) + 2, b = (i32)c2b_br_bits(r, 5),
                       c = (i32)c2b_br_bits(r, 5);
                   if (c2b_fp_ladd(fp, a) || c2b_fp_push_set(fp, b) ||
                       c2b_fp_push_set(fp, c)) return -1; } break;
        case 23: { i32 a = (i32)c2b_br_ubitvar(r) + 2, b = (i32)c2b_br_ubitvar_fp(r),
                       c = (i32)c2b_br_ubitvar_fp(r), d = (i32)c2b_br_ubitvar_fp(r);
                   if (c2b_fp_ladd(fp, a) || c2b_fp_push_rel(fp, b) ||
                       c2b_fp_push_rel(fp, c) || c2b_fp_push_rel(fp, d)) return -1; } break;
        case 24: { i32 a = (i32)c2b_br_ubitvar(r) + 2, b = (i32)c2b_br_bits(r, 5),
                       c = (i32)c2b_br_bits(r, 5), d = (i32)c2b_br_bits(r, 5);
                   if (c2b_fp_ladd(fp, a) || c2b_fp_push_set(fp, b) ||
                       c2b_fp_push_set(fp, c) || c2b_fp_push_set(fp, d)) return -1; } break;
        case 25: { i32 n = (i32)c2b_br_ubitvar(r);
                   if (n < 0 || c2b_fp_ladd(fp, n)) return -1;
                   for (i32 i = 0; i < n; i++)
                       if (c2b_fp_push_rel(fp, (i32)c2b_br_ubitvar_fp(r))) return -1; } break;
        case 26: { for (i32 i = 0; i <= fp->last; i++)
                       if (c2b_br_bit(r) && c2b_fp_eadd(fp, i, c2b_br_varint32(r) + 1)) return -1;
                   i32 n = (i32)c2b_br_ubitvar(r);
                   for (i32 i = 0; i < n; i++)
                       if (c2b_fp_push_rel(fp, (i32)c2b_br_ubitvar_fp(r))) return -1; } break;
        case 27: if (c2b_fp_pop(fp, 1) || c2b_fp_ladd(fp, 1)) return -1; break;
        case 28: { i32 v = (i32)c2b_br_ubitvar_fp(r) + 1;
                   if (c2b_fp_pop(fp, 1) || c2b_fp_ladd(fp, v)) return -1; } break;
        case 29: if (c2b_fp_pop(fp, fp->last) || c2b_fp_ladd(fp, 1)) return -1; break;
        case 30: { i32 v = (i32)c2b_br_ubitvar_fp(r) + 1;
                   if (c2b_fp_pop(fp, fp->last) || c2b_fp_ladd(fp, v)) return -1; } break;
        case 31: { i32 v = (i32)c2b_br_bits(r, 3) + 1;
                   if (c2b_fp_pop(fp, fp->last) || c2b_fp_ladd(fp, v)) return -1; } break;
        case 32: { i32 v = (i32)c2b_br_bits(r, 6) + 1;
                   if (c2b_fp_pop(fp, fp->last) || c2b_fp_ladd(fp, v)) return -1; } break;
        case 33: { i32 n = (i32)c2b_br_ubitvar_fp(r);
                   if (c2b_fp_pop(fp, n) || c2b_fp_ladd(fp, 1)) return -1; } break;
        case 34: { i32 n = (i32)c2b_br_ubitvar_fp(r), v = c2b_br_varint32(r);
                   if (c2b_fp_pop(fp, n) || c2b_fp_ladd(fp, v)) return -1; } break;
        case 35: { i32 n = (i32)c2b_br_ubitvar_fp(r);
                   if (c2b_fp_pop(fp, n)) return -1;
                   for (i32 i = 0; i <= fp->last; i++)
                       if (c2b_br_bit(r) && c2b_fp_eadd(fp, i, c2b_br_varint32(r))) return -1; } break;
        case 36: for (i32 i = 0; i <= fp->last; i++)
                     if (c2b_br_bit(r) && c2b_fp_eadd(fp, i, c2b_br_varint32(r))) return -1;
                 break;
        case 37: { if (fp->last < 1 || fp->last > 6) return -1; fp->path[fp->last - 1]++; } break;
        case 38: for (i32 i = 0; i <= fp->last; i++)
                     if (c2b_br_bit(r) && c2b_fp_eadd(fp, i, (i32)c2b_br_bits(r, 4) - 7)) return -1;
                 break;
        case 39: fp->done = 1; break;
        default: return -1;
        }
        if (fp->done) return (i32)pn;
        if (r->ovf) return -1;
        if (paths) {
            if (pn >= max_paths) return -1;
            paths[pn++] = *fp;                   /* снапшот пути */
        }
    }
}

/* --- quantized float (quantizedfloat.go, полная реплика) --- */
typedef struct { float lo, hi, decmul; u32 bits; u8 has_rd, has_ru, has_ez; } c2b_qf_t;

static float c2b_qf_quantize(const c2b_qf_t *q, float hmul, float val)
{
    if (val < q->lo) return (q->has_ru) ? q->lo : val;
    if (val > q->hi) return (q->has_rd) ? q->hi : val;
    u32 i = (u32)((val - q->lo) * hmul + 0.5f);
    return q->lo + (q->hi - q->lo) * ((float)i * q->decmul);
}

static void c2b_qf_init(c2b_qf_t *q, i32 bits, i32 flags, float lo, float hi)
{
    q->lo = lo; q->hi = hi; q->decmul = 0.0f;
    q->has_rd = q->has_ru = q->has_ez = 0;
    if (bits <= 0 || bits >= 32) { q->bits = 32; return; }    /* NoScale */
    q->bits = (u32)bits;
    u32 RD = 1u, RU = 2u, EZ = 4u, EI = 8u;
    u32 fl = (flags < 0) ? 0u : (u32)flags;
    if (fl) {
        if ((q->lo == 0.0f && (fl & RD)) || (q->hi == 0.0f && (fl & RU))) fl &= ~EZ;
        if (q->lo == 0.0f && (fl & EZ)) { fl |= RD; fl &= ~EZ; }
        if (q->hi == 0.0f && (fl & EZ)) { fl |= RU; fl &= ~EZ; }
        if (q->lo > 0.0f || q->hi < 0.0f) fl &= ~EZ;
        if (fl & EI) fl &= ~(RU | RD | EZ);
    }
    u32 steps = 1u << q->bits;
    if (fl & RD) { float rg = q->hi - q->lo; q->hi -= rg / (float)steps; }
    else if (fl & RU) { float rg = q->hi - q->lo; q->lo += rg / (float)steps; }
    if (fl & EI) {
        float delta = q->hi - q->lo;
        if (delta < 1.0f) delta = 1.0f;
        u32 dl = 0; float d2 = delta;
        while (d2 > 1.0f) { d2 *= 0.5f; dl++; }
        u32 range2 = 1u << dl;
        u32 bc = q->bits;
        while ((1u << bc) <= range2) bc++;
        if (bc > q->bits) { q->bits = bc; steps = 1u << q->bits; }
        float off = (float)range2 / (float)steps;
        q->hi = q->lo + (float)range2 - off;
    }
    {   /* assignMultipliers */
        float range = q->hi - q->lo;
        u32 high = (q->bits == 32) ? 0xFFFFFFFEu : ((1u << q->bits) - 1);
        float hmul = (range <= 0.0f && range >= -0.0f) ? (float)high : (float)high / range;
        if (hmul * range > (float)high) {
            const float muls[5] = { 0.9999f, 0.99f, 0.9f, 0.8f, 0.7f };
            for (i32 i = 0; i < 5; i++) {
                hmul = (float)high / range * muls[i];
                if (!(hmul * range > (float)high)) break;
            }
        }
        q->decmul = 1.0f / (float)(steps - 1);
        /* фильтрация флагов через quantize (реплика) */
        if (fl & RD && c2b_qf_quantize(q, hmul, q->lo) == q->lo) fl &= ~RD;
        if (fl & RU && c2b_qf_quantize(q, hmul, q->hi) == q->hi) fl &= ~RU;
        if (fl & EZ && c2b_qf_quantize(q, hmul, 0.0f) == 0.0f) fl &= ~EZ;
    }
    q->has_rd = (fl & RD) != 0;
    q->has_ru = (fl & RU) != 0;
    q->has_ez = (fl & EZ) != 0;
}

static float c2b_qf_dec(const c2b_qf_t *q, c2b_br_t *r)
{
    if (q->has_rd && c2b_br_bit(r)) return q->lo;
    if (q->has_ru && c2b_br_bit(r)) return q->hi;
    if (q->has_ez && c2b_br_bit(r)) return 0.0f;
    return q->lo + (q->hi - q->lo) * ((float)c2b_br_bits(r, q->bits) * q->decmul);
}

/* --- значение одного компонента по DT_* (field_decoder.go) --- */
static i32 c2b_g4_read_comp(u16 dec, const c2b_fsv_field_t *F, c2b_br_t *r, float *out)
{
    switch (dec) {
    case DT_NOSCALE:  *out = c2b_f32_from_bits(c2b_br_bits(r, 32)); return 0;
    case DT_COORD:    *out = c2b_br_coord(r); return 0;
    case DT_SIMTIME:  *out = (float)c2b_br_varuint32(r) * (1.0f / 64.0f); return 0;
    case DT_RUNETIME: *out = c2b_f32_from_bits(c2b_br_bits(r, 4)); return 0;
    case DT_QUANT: {
        c2b_qf_t q;
        c2b_qf_init(&q, F->bits, F->flags, F->lo, F->hi);
        *out = c2b_qf_dec(&q, r);
        return 0;
    }
    default: return -1;
    }
}

/* QAngle-декодеры: qangle_precise / bits / noscale3 / default */
static i32 c2b_g4_read_qangle(const c2b_fsv_field_t *F, c2b_br_t *r, float v[3])
{
    v[0] = v[1] = v[2] = 0.0f;
    if (F->dec == DT_Q_PRECISE) {
        u32 hx = c2b_br_bit(r), hy = c2b_br_bit(r), hz = c2b_br_bit(r);
        if (hx) v[0] = c2b_br_angle(r, 20) - 180.0f;
        if (hy) v[1] = c2b_br_angle(r, 20) - 180.0f;
        if (hz) v[2] = c2b_br_angle(r, 20) - 180.0f;
        return 0;
    }
    if (F->dec == DT_Q_BITS) {
        u32 n = (u32)(F->bits > 0 ? F->bits : 0);
        v[0] = c2b_br_angle(r, n); v[1] = c2b_br_angle(r, n); v[2] = c2b_br_angle(r, n);
        return 0;
    }
    if (F->dec == DT_Q_NOSCALE3) {
        v[0] = c2b_f32_from_bits(c2b_br_bits(r, 32));
        v[1] = c2b_f32_from_bits(c2b_br_bits(r, 32));
        v[2] = c2b_f32_from_bits(c2b_br_bits(r, 32));
        return 0;
    }
    /* DT_Q_DEFAULT */
    u32 hx = c2b_br_bit(r), hy = c2b_br_bit(r), hz = c2b_br_bit(r);
    if (hx) v[0] = c2b_br_coord(r);
    if (hy) v[1] = c2b_br_coord(r);
    if (hz) v[2] = c2b_br_coord(r);
    return 0;
}

/* --- чтение значения поля (field_decoder.go findDecoder) --- */
enum { GV_SKIP = 0, GV_U64, GV_F1, GV_F2, GV_F3, GV_F4, GV_F6, GV_STR };

typedef struct {
    u64 u;
    float f[6];
    char str[52];
    u32 str_n;
} c2b_val_t;

static i32 c2b_g4_read_val(const c2b_fsv_field_t *F, c2b_br_t *r, c2b_val_t *v)
{
    v->u = 0;
    v->str_n = 0;
    switch (F->dec) {
    case DT_VARINT_U:  v->u = c2b_br_varuint32(r); return GV_U64;
    case DT_VARINT_S:  v->u = (u64)(u32)c2b_br_varint32(r); return GV_U64;
    case DT_VARINT_U64: v->u = c2b_br_varuint64(r); return GV_U64;
    case DT_FIXED64:   v->u = c2b_br_bits(r, 32) | ((u64)c2b_br_bits(r, 32) << 32); return GV_U64;
    case DT_BOOL:      v->u = c2b_br_bit(r); return GV_U64;
    case DT_AMMO:      v->u = (u64)(c2b_br_varuint32(r) - 1); return GV_U64;
    case DT_COMP:      v->u = c2b_br_bit(r); return GV_U64;
    case DT_STR: {
        u32 i = 0;
        while (i < sizeof(v->str) - 1) {
            u32 b = c2b_br_byte(r);
            if (!b || r->ovf) break;
            v->str[i++] = (char)b;
        }
        v->str_n = i;
        return GV_STR;
    }
    case DT_BIN: {
        u32 n = c2b_br_varuint32(r);
        u32 i;
        for (i = 0; i < n; i++) {
            u32 b = c2b_br_byte(r);
            if (i < sizeof(v->str)) v->str[i] = (char)b;
            if (r->ovf) return GV_SKIP;
        }
        v->str_n = (n < sizeof(v->str)) ? n : (u32)sizeof(v->str);
        return GV_STR;
    }
    case DT_NORMAL3:   c2b_br_3bitnormal(r, v->f); return GV_F3;
    case DT_Q_PRECISE: case DT_Q_BITS: case DT_Q_NOSCALE3: case DT_Q_DEFAULT:
        c2b_g4_read_qangle(F, r, v->f);
        return GV_F3;
    default: break;
    }
    /* компонентные базовые типы: каждый компонент — по F->dec */
    u32 n = 0;
    switch (F->base_id) {
    case BT_VEC3: n = 3; break;
    case BT_VEC2: n = 2; break;
    case BT_VEC4: case BT_QUAT: n = 4; break;
    case BT_CTR:  n = 6; break;
    case BT_F32: case BT_QF: n = 1; break;
    default: return GV_SKIP;
    }
    for (u32 i = 0; i < n; i++) {
        float x;
        if (c2b_g4_read_comp(F->dec, F, r, &x) != 0) return GV_SKIP;
        v->f[i] = x;
    }
    switch (n) {
    case 1: return GV_F1;
    case 2: return GV_F2;
    case 3: return GV_F3;
    case 4: return GV_F4;
    default: return GV_F6;
    }
}

/* --- обход сериализатора по пути (getDecoderAndCollection) ---
 * G-4c: под полиморфными FIXEDTAB ходим по per-entity активному типу E->ps. */
enum { LW_MISS = 0, LW_VAL, LW_PTR, LW_VARARR_CNT, LW_VARTAB_CNT };

typedef struct { const c2b_fsv_field_t *F; i32 elem; } c2b_leaf_t;

static u32 c2b_g4_slot_hash(u32 off, u32 cnt, u32 h)
{
    for (u32 i = 0; i < cnt; i++)
        if (g_s1_slots[off + i].name_hash == h) return i;
    return 0xFFFFFFFFu;
}

static i32 c2b_g4_walk(u32 ser_id, const c2b_fp_t *fp, u32 pos, u32 depth,
                       c2b_leaf_t *out, const struct c2b_g4_ent_s *E)
{
    if (ser_id == C2B_FSV_SER_NUL || ser_id >= g_fsv_ser_n) return LW_MISS;
    if (depth > C2B_S1_WALK_DEPTH || pos > 6) return LW_MISS;
    const c2b_fsv_ser_t *S = &g_fsv_ser[ser_id];
    u32 ord = (u32)fp->path[pos];
    if (ord >= S->n) return LW_MISS;
    u32 ref = S->fbase + g_fsv_idx[S->idx_off + ord];
    if (ref >= g_fsv_field_n) return LW_MISS;
    const c2b_fsv_field_t *F = &g_fsv_field[ref];
    switch (F->model) {
    case SM_SIMPLE:
        out->F = F; out->elem = -1;
        return LW_VAL;
    case SM_FIXEDARR:
        if (fp->last < (i32)pos + 1) {           /* bare [f]: Go читает 1 значение */
            out->F = F; out->elem = -2;
            return LW_VAL;
        }
        out->F = F; out->elem = fp->path[pos + 1];
        return LW_VAL;
    case SM_FIXEDTAB:
        if (fp->last == (i32)pos) { out->F = F; return LW_PTR; }
        {
            u32 sid;
            if (F->poly_n) {
                if (!E || F->poly_slot >= C2B_G4_POLY_SLOTS) return LW_MISS;
                sid = E->ps[F->poly_slot];
                if (sid == C2B_FSV_SER_NUL) return LW_MISS;   /* указатель не активирован */
            } else {
                sid = F->ser_id;
                if (sid == C2B_FSV_SER_NUL) return LW_MISS;
            }
            return c2b_g4_walk(sid, fp, pos + 1, depth + 1, out, E);
        }
    case SM_VARARR:
        if (fp->last == (i32)pos + 1) {
            out->F = F; out->elem = fp->path[pos + 1];
            return LW_VAL;
        }
        out->F = F;
        return LW_VARARR_CNT;
    case SM_VARTAB:
        if (fp->last >= (i32)pos + 2)
            return c2b_g4_walk(F->ser_id, fp, pos + 1, depth + 1, out, E);
        out->F = F;
        return LW_VARTAB_CNT;
    default: return LW_MISS;
    }
}

/* --- бит-райтер LSB-first --- */
typedef struct { u8 *buf; u32 cap, pos, bitcnt, ovf; u64 bitval; } c2b_bw_t;

static void c2b_bw_bit(c2b_bw_t *w, u32 b)
{
    w->bitval |= (u64)(b & 1) << w->bitcnt;
    w->bitcnt++;
    if (w->bitcnt == 8) {
        if (w->pos < w->cap) w->buf[w->pos++] = (u8)w->bitval; else w->ovf++;
        w->bitval = 0; w->bitcnt = 0;
    }
}

static void c2b_bw_bits(c2b_bw_t *w, u32 v, u32 n)
{ for (u32 i = 0; i < n; i++) c2b_bw_bit(w, (v >> i) & 1); }

/* R36: инверсия bf_read::ReadUBitVar (S1-клиент) == WriteUBitVar движка.
 * Пороги 16/256/4096, маркеры в битах 4-5 заголовка: 00 direct, 01 +4б, 10 +8б, 11 +28б.
 * БЫЛО: пороги (v>>6)/(v>>10)/(v>>14) = 64/1024/16384 — для дельт 16..63 заголовок
 * читался S1-клиентом как escape (desync потока), 256..1023 и 4096..16383 — тихое
 * усечение старших бит. Сверено с эталоном 5cce9ff4: c2b_g4_ent_header @0x7a50:
 * cmp $0xf / $0xff / $0xfff. */
static void c2b_bw_ubitvar(c2b_bw_t *w, u32 v)   /* инверсия readUBitVar */
{
    if (v < 16)             c2b_bw_bits(w, v, 6);
    else if (v < 256)       { c2b_bw_bits(w, (v & 15) | 16, 6); c2b_bw_bits(w, v >> 4, 4); }
    else if (v < 4096)      { c2b_bw_bits(w, (v & 15) | 32, 6); c2b_bw_bits(w, v >> 4, 8); }
    else                    { c2b_bw_bits(w, (v & 15) | 48, 6); c2b_bw_bits(w, v >> 4, 28); }
}

/* инверсия ReadFieldIndex (newWay, demofiledump.cpp:1008) */
static void c2b_bw_fieldidx(c2b_bw_t *w, u32 d)
{
    if (d == 0) { c2b_bw_bit(w, 1); return; }
    c2b_bw_bit(w, 0);
    if (d < 8) { c2b_bw_bit(w, 1); c2b_bw_bits(w, d, 3); return; }
    c2b_bw_bit(w, 0);
    if (d < 32)       c2b_bw_bits(w, d, 7);
    else if (d < 128) { c2b_bw_bits(w, 0x20u | (d & 0x1Fu), 7); c2b_bw_bits(w, d >> 5, 2); }
    else if (d < 512) { c2b_bw_bits(w, 0x40u | (d & 0x1Fu), 7); c2b_bw_bits(w, d >> 5, 4); }
    else              { c2b_bw_bits(w, 0x60u | (d & 0x1Fu), 7); c2b_bw_bits(w, d >> 5, 7); }
}

static u32 c2b_bw_flush(c2b_bw_t *w)
{
    if (w->bitcnt) {
        if (w->pos < w->cap) w->buf[w->pos++] = (u8)w->bitval; else w->ovf++;
        w->bitval = 0; w->bitcnt = 0;
    }
    return w->pos;
}

/* --- контекст класса + сущности --- */
typedef struct {
    u32 slot_off, slot_cnt;    /* S1 слот-пространство (G-3d) */
    u32 vec_origin;            /* слот m_vecOrigin (0xFFFFFFFF = нет) */
    u32 gen;                   /* поколение FSV при резолве (G-4c) */
    u16 dt_index;              /* корень в g_dt_index */
    u16 ser_id;                /* S2 сериализатор класса */
    u16 state;                 /* 0 = новый, 1 = готов, 2 = без схемы */
    u16 pad;
} c2b_g4_cls_t;

#define C2B_G4_CLASSES C2B_CLASS_MAP_MAX
static c2b_g4_cls_t g_g4_cls[C2B_G4_CLASSES];
static c2b_g4_ent_t g_g4_ent[C2B_G4_ENT_MAX];

static u32 c2b_g4_class_bits(u32 n)             /* log2floor(n)+1 (формула движка) */
{
    u32 b = 0;
    while (n >>= 1) b++;
    return b + 1;
}

/* ленивый контекст класса (слоты из G-3d кэша); инвалидируется новым FSV */
static c2b_g4_cls_t *c2b_g4_cls_ctx(u32 cls2)
{
    if (cls2 >= C2B_G4_CLASSES) return 0;
    c2b_g4_cls_t *C = &g_g4_cls[cls2];
    if (C->gen == g_fsv_gen) {
        if (C->state == 1) return C;
        if (C->state == 2) return 0;
    }
    if (cls2 >= C2B_CLASS_MAP_MAX || !g_class_seen[cls2]) { C->state = 2; return 0; }
    u16 ser = g_class_ser_map[cls2];
    u16 dti = g_class_dt_map[cls2];
    if (ser == C2B_FSV_SER_NUL || dti == 0xFFFFu) {
        C->state = 2;                          /* без DT/FSV — не пробуем снова */
        return 0;
    }
    u32 off, cnt;
    if (c2b_s1_slots_of(dti, &off, &cnt) != 0) {
        C->state = 2;
        return 0;
    }
    C->ser_id = ser;
    C->dt_index = dti;
    C->slot_off = off;
    C->slot_cnt = cnt;
    C->vec_origin = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_vecOrigin"));
    C->state = 1;
    C->gen = g_fsv_gen;
    return C;
}

/* --- стейджинг пропов одной сущности (S1 требует возрастающих индексов) ---
 * 1024 слота: базлайны G-4b стейджат полный класс (DT_CSPlayer=717) */
#define C2B_G4_STG 1024
enum { ST_SCALAR = 0, ST_VEC, ST_STR, ST_ARR };
typedef struct {
    u32 slot;
    u8 kind, fmask;
    u32 arr_base, arr_cnt;
    u32 str_n;
    u64 u;
    float f[3];
    char str[52];
} c2b_g4_stg_t;

static c2b_g4_stg_t g_g4_stg[C2B_G4_STG];
static u32 g_g4_stg_n;
static u64 g_g4_arr[2048];
static u32 g_g4_arr_n;
static u32 g_g4_hit2;

/* R36 (t35): разрядные потолки значений по контексту поля (64/1024/16384).
 * Аномалия = мусор после десинка: клампим там, где семантика диапазона известна.
 * Телеметрия: FINI g4{... ub=N}. */
static u32 g_g4_ub;

#define C2B_UB_CAP_CELL  64u      /* cell (cellBits=9, мир ±16384 -> cell 0..64) */
#define C2B_UB_CAP_IDX   1024u    /* индексы/счётчики VARARR (пул 2048) */
#define C2B_UB_CAP_ITEM  16384u   /* размер item'а baseline (S1 17-бит = 16383) */

static u32 c2b_g4_ub_clamp(u32 v, u32 cap)
{
    if (v > cap) { g_g4_ub++; return cap; }
    return v;
}

static c2b_g4_stg_t *c2b_g4_stage(u32 slot)
{
    for (u32 i = 0; i < g_g4_stg_n; i++)
        if (g_g4_stg[i].slot == slot) return &g_g4_stg[i];
    if (g_g4_stg_n >= C2B_G4_STG) return 0;
    c2b_g4_stg_t *s = &g_g4_stg[g_g4_stg_n++];
    s->slot = slot; s->kind = ST_SCALAR; s->fmask = 0;
    s->arr_base = 0; s->arr_cnt = 0; s->str_n = 0; s->u = 0;
    s->f[0] = s->f[1] = s->f[2] = 0.0f;
    return s;
}

/* позиционное правило: m_cellX/m_vecX -> компонента 0..2, иначе -1 */
static i32 c2b_pos_comp(const char *vn)
{
    if (vn[0] != 'm' || vn[1] != '_') return -1;
    if (vn[2] == 'c' && vn[3] == 'e' && vn[4] == 'l' && vn[5] == 'l' &&
        (vn[6] == 'X' || vn[6] == 'Y' || vn[6] == 'Z') && !vn[7]) {
        return vn[6] - 'X';
    }
    if (vn[2] == 'v' && vn[3] == 'e' && vn[4] == 'c' &&
        (vn[5] == 'X' || vn[5] == 'Y' || vn[5] == 'Z') && !vn[6]) {
        return vn[5] - 'X';
    }
    return -1;
}

static void c2b_g4_pos_update(c2b_g4_ent_t *E, const c2b_g4_cls_t *C, i32 ci)
{
    if (!C || C->vec_origin == 0xFFFFFFFFu) return;
    if (!((E->cellhave >> ci) & 1) || !((E->offhave >> ci) & 1)) return;
    /* R42: per-entity кэш позиции; частичная тройка НЕ эмитится (нули из
     * `: 0.0f` в emit case 2 давали энтити в (0,0,0) при частичных апдейтах). */
    E->org[ci] = (float)E->cell[ci] * 512.0f - 16384.0f + E->coff[ci];
    E->orghave |= (u8)(1u << ci);
    if (E->orghave != 0x07u) return;            /* R42: нет полной тройки — не эмитить */
    c2b_g4_stg_t *s = c2b_g4_stage(C->vec_origin);
    if (!s) return;
    s->kind = ST_VEC;
    s->f[0] = E->org[0]; s->f[1] = E->org[1]; s->f[2] = E->org[2];
    s->fmask = 0x07u;
}

/* резолв листа против слотов класса: 0 direct, 1 node-comp, 2 vec-comp, -1 miss */
static i32 c2b_g4_resolve(const c2b_g4_cls_t *C, const c2b_fsv_field_t *F,
                          i32 *comp, u32 *slot)
{
    const char *vn = g_fsv_arena + F->name;
    u32 s = c2b_g4_slot_hash(C->slot_off, C->slot_cnt, c2b_fnv1a(vn));
    if (s != 0xFFFFFFFFu) { *slot = s; *comp = -1; return 0; }
    if (F->node) {
        const char *nn = g_fsv_arena + F->node;
        u32 vl = 0;
        while (vn[vl]) vl++;
        char lc = vl ? vn[vl - 1] : 0;
        i32 ci = (lc == 'x' || lc == 'X') ? 0 : (lc == 'y' || lc == 'Y') ? 1
               : (lc == 'z' || lc == 'Z') ? 2 : -1;
        if (ci >= 0) {
            char buf[72]; u32 bn = 0;
            while (nn[bn] && bn < 60) { buf[bn] = nn[bn]; bn++; }
            if (bn + 4 < sizeof(buf)) {
                buf[bn++] = '['; buf[bn++] = (char)('0' + ci); buf[bn++] = ']'; buf[bn] = 0;
                s = c2b_g4_slot_hash(C->slot_off, C->slot_cnt, c2b_fnv1a(buf));
                if (s != 0xFFFFFFFFu) { *slot = s; *comp = ci; return 1; }
            }
        }
    }
    {
        u32 vl = 0;
        while (vn[vl] && vl < 60) vl++;
        if (vl && vl < 60) {
            char buf[72];
            for (u32 i = 0; i < vl; i++) buf[i] = vn[i];
            buf[vl] = '['; buf[vl + 1] = '0'; buf[vl + 2] = ']'; buf[vl + 3] = 0;
            s = c2b_g4_slot_hash(C->slot_off, C->slot_cnt, c2b_fnv1a(buf));
            if (s != 0xFFFFFFFFu) { *slot = s; *comp = -2; return 2; }
        }
    }
    return -1;
}

static u32 c2b_g4_slot_named(const c2b_g4_cls_t *C, const char *name)
{
    return c2b_g4_slot_hash(C->slot_off, C->slot_cnt, c2b_fnv1a(name));
}

/* стейджинг одного S2-значения в S1-слоты */
static void c2b_g4_stage_val(c2b_g4_ent_t *E, const c2b_g4_cls_t *C,
                             const c2b_fsv_field_t *F, i32 elem,
                             i32 gvk, const c2b_val_t *v)
{
    const char *vn = g_fsv_arena + F->name;

    if (elem < -1) {                             /* bare FixedArray: биты съедены */
        g_g4_miss++;
        return;
    }

    /* позиционное правило (CBodyComponent.m_cellX/m_vecX) */
    if (elem < 0 && (gvk == GV_U64 || gvk == GV_F1)) {
        i32 ci = c2b_pos_comp(vn);
        if (ci >= 0) {
            if (vn[2] == 'c') {
                /* R36: cell <= 64 (cellBits=9); мусорный cell -> позиция за миром */
                E->cell[ci] = c2b_g4_ub_clamp((u32)v->u, C2B_UB_CAP_CELL);
                E->cellhave |= (u8)(1u << ci);
            }
            else              { E->coff[ci] = v->f[0];   E->offhave |= (u8)(1u << ci); }
            c2b_g4_pos_update(E, C, ci);
            return;
        }
    }

    i32 comp = -1;
    u32 slot = 0xFFFFFFFFu;
    i32 rule = c2b_g4_resolve(C, F, &comp, &slot);
    if (rule < 0) { g_g4_miss++; return; }
    g_g4_hit2++;

    if (rule == 1) {                             /* S1 "node[ci]" — Float-слот */
        c2b_g4_stg_t *s = c2b_g4_stage(slot);
        if (s) { s->kind = ST_SCALAR; s->u = c2b_f32_to_bits(v->f[0]); }
        return;
    }
    if (rule == 2) {                             /* S2 Vector -> S1 vn[0..2] */
        if (gvk != GV_F2 && gvk != GV_F3 && gvk != GV_F4 && gvk != GV_F6) {
            g_g4_miss++;
            return;
        }
        for (i32 i = 0; i < 3; i++) {
            const char *nn = g_fsv_arena + F->name;
            char buf[72]; u32 bn = 0;
            while (nn[bn] && bn < 60) { buf[bn] = nn[bn]; bn++; }
            if (bn + 4 >= sizeof(buf)) break;
            buf[bn++] = '['; buf[bn++] = (char)('0' + i); buf[bn++] = ']'; buf[bn] = 0;
            u32 s2 = c2b_g4_slot_named(C, buf);
            if (s2 == 0xFFFFFFFFu) { g_g4_miss++; continue; }
            c2b_g4_stg_t *s = c2b_g4_stage(s2);
            if (s) { s->kind = ST_SCALAR; s->u = c2b_f32_to_bits(v->f[i]); }
        }
        return;
    }

    /* direct: слот найден по varName */
    if (elem >= 0) {                             /* элемент массива */
        c2b_g4_stg_t *s = c2b_g4_stage(slot);
        if (!s) { g_g4_ovf++; return; }
        u32 e = (u32)elem;
        if (e >= C2B_UB_CAP_IDX) { g_g4_ub++; return; }      /* R36: мусорный индекс */
        if (s->kind != ST_ARR) { s->kind = ST_ARR; s->arr_base = g_g4_arr_n; s->arr_cnt = 0; }
        if (s->arr_base + e >= sizeof(g_g4_arr) / sizeof(g_g4_arr[0])) return;
        /* R43 «резерв=0»: пул не обнуляется между энтити (g_g4_stg_n/g_g4_arr_n
         * сбрасываются как счётчики), в [старый arr_cnt .. elem] лежат значения
         * ЧУЖОГО массива -> S1-дельта уедет. Слот-флагов нет (fmask — VEC),
         * обнуляем только пул значений. */
        g_fini2.rt_aov += (e >= s->arr_cnt) ? (e - s->arr_cnt + 1) : 0;
        for (u32 zi = s->arr_cnt; zi <= e; zi++)
            g_g4_arr[s->arr_base + zi] = 0;
        if (e >= s->arr_cnt) s->arr_cnt = e + 1;
        g_g4_arr[s->arr_base + e] =
            (gvk == GV_F1) ? c2b_f32_to_bits(v->f[0]) : v->u;
        return;
    }
    c2b_g4_stg_t *s = c2b_g4_stage(slot);
    if (!s) { g_g4_ovf++; return; }
    c2b_s1_slot_t *sl = &g_s1_slots[C->slot_off + slot];
    switch (sl->dpt) {
    case 2: case 3: {                            /* Vector / VectorXY */
        if (gvk == GV_F3 || gvk == GV_F4 || gvk == GV_F6) {
            s->kind = ST_VEC;
            s->f[0] = v->f[0]; s->f[1] = v->f[1]; s->f[2] = v->f[2];
            s->fmask = (sl->dpt == 3) ? 0x03u : 0x07u;
        } else if (gvk == GV_F1) {
            s->kind = ST_VEC;
            s->f[0] = v->f[0]; s->fmask |= 0x01u;
        } else {
            g_g4_miss++;
        }
        break;
    }
    case 4: {                                    /* String */
        if (gvk == GV_STR) {
            s->kind = ST_STR;
            s->str_n = v->str_n;
            for (u32 i = 0; i < v->str_n && i < sizeof(s->str); i++) s->str[i] = v->str[i];
        } else {
            g_g4_miss++;
        }
        break;
    }
    case 5: {                                    /* Array: значение = count */
        s->kind = ST_ARR;
        s->arr_base = g_g4_arr_n;
        u32 num = (sl->num ? sl->num : 1);
        g_g4_arr_n += num;                       /* резерв ширины массива */
        if (g_g4_arr_n > sizeof(g_g4_arr) / sizeof(g_g4_arr[0])) { g_g4_ovf++; return; }
        /* R43 «резерв=0»: emit читает ровно cnt слотов; при частичной записи
         * элементов в [written..cnt) лежал мусор чужого массива */
        for (u32 zi = 0; zi < num; zi++) g_g4_arr[s->arr_base + zi] = 0;
        g_fini2.rt_aov += num;
        s->arr_cnt = c2b_g4_ub_clamp((u32)v->u, num);   /* R36/R43: cnt <= num (emit и так клампит) */
        break;
    }
    default: {                                   /* Int/Int64/Float */
        s->kind = ST_SCALAR;
        s->u = (gvk == GV_F1) ? c2b_f32_to_bits(v->f[0]) : v->u;
        break;
    }
    }
}

/* чтение полей одной сущности. Схема wire (entity.go readFields):
 * СНАЧАЛА все huffman-пути единым потоком (до FieldPathEncodeFinish),
 * ПОТОМ значения в порядке путей. paths/max_paths — от вызывающего:
 * 96 для PacketEntities, 512 для базлайнов G-4b. */
#define C2B_G4_PATHS 96
static i32 c2b_g4_ent_fields(c2b_br_t *r, c2b_g4_ent_t *E, const c2b_g4_cls_t *C,
                             c2b_fp_t *paths, u32 max_paths)
{
    c2b_fp_t fp;
    u32 pn = 0;
    c2b_fp_reset(&fp);
    g_g4_stg_n = 0;
    g_g4_arr_n = 0;
    pn = (u32)c2b_fp_read_all(r, &fp, paths, max_paths);
    if (pn > max_paths || r->ovf) return -1;
    for (u32 i = 0; i < pn; i++) {               /* фаза 2: значения */
        const c2b_fp_t *p = &paths[i];
        c2b_leaf_t L;
        i32 lw = c2b_g4_walk(C->ser_id, p, 0, 0, &L, E);
        switch (lw) {
        case LW_PTR: {
            /* G-4c: bool + (если активен и poly) ubitvar-индекс в [own, alts...] */
            u32 act = c2b_br_bit(r);
            if (L.F->poly_n) {
                u32 sel = act ? c2b_br_ubitvar(r) : 0;
                if (act && sel > (u32)L.F->poly_n) g_g4_ub++;   /* R36: аномальный селектор */
                if (L.F->poly_slot < C2B_G4_POLY_SLOTS && E) {
                    u32 sid = C2B_FSV_SER_NUL;
                    if (act) {
                        sid = (sel == 0) ? L.F->ser_id
                            : (sel - 1 < L.F->poly_n) ? L.F->poly[sel - 1]
                                                      : C2B_FSV_SER_NUL;
                        if (sid != C2B_FSV_SER_NUL) g_g4_poly++;
                    }
                    E->ps[L.F->poly_slot] = (u16)sid;   /* активация/деактивация */
                }
            }
            break;
        }
        case LW_VARARR_CNT: {                    /* count VariableArray */
            /* R38: счётчик ВСЕГДА readVarUint32 (референс field.go:144
             * baseDecoder=unsignedDecoder; 218-223: [field] -> baseDecoder+collection,
             * [field,elem] -> childDecoder). Раньше читали child-декодером F->dec:
             * generic != u32/handle (float32->NOSCALE 32b, bool->1b, QUANT->bits,
             * CUtlString->байты) сбивал поток. Прецедент: LW_VARTAB_CNT ниже. */
            c2b_val_t v;
            v.u = c2b_br_varuint32(r);
            v.u = c2b_g4_ub_clamp((u32)v.u, C2B_UB_CAP_IDX);   /* R36/R38: кап 1024 */
            c2b_g4_stage_val(E, C, L.F, -1, GV_U64, &v);
            break;
        }
        case LW_VARTAB_CNT: {                    /* count VariableTable: S1-аналога нет */
            (void)c2b_br_varuint32(r);
            break;
        }
        case LW_VAL: {
            c2b_val_t v;
            i32 gvk = c2b_g4_read_val(L.F, r, &v);
            if (gvk == GV_SKIP) return -1;
            g_g4_fields++;
            c2b_g4_stage_val(E, C, L.F, L.elem, gvk, &v);
            break;
        }
        default:
            g_g4_desync++;
            return -1;                           /* биты значения не знаем -> дроп */
        }
        if (r->ovf) return -1;
    }
    return 0;
}

/* ширина счётчика элементов S1-массива (demofiledump Array_Decode) */
static u32 c2b_g4_arr_bits(u32 n)
{
    u32 b = 1;
    while ((n >>= 1) != 0) b++;
    return b;
}

static void c2b_g4_emit_s1val(c2b_bw_t *w, const c2b_s1_slot_t *sl,
                              const c2b_g4_stg_t *s)
{
    switch (sl->dpt) {
    case 0:                                      /* DPT_Int: 32 бита signed */
        c2b_bw_bits(w, (u32)s->u, 32);
        break;
    case 7: {                                    /* DPT_Int64: sign+low32+high31 */
        i64 v = (i64)s->u;
        u32 neg = (v < 0) ? 1u : 0u;
        u64 m = neg ? (u64)(-v) : (u64)v;
        c2b_bw_bit(w, neg);
        c2b_bw_bits(w, (u32)m, 32);
        c2b_bw_bits(w, (u32)(m >> 32) & 0x7FFFFFFFu, 31);
        break;
    }
    case 1:                                      /* DPT_Float NOSCALE */
        c2b_bw_bits(w, (u32)s->u, 32);
        break;
    case 2: {                                    /* DPT_Vector NOSCALE x3 */
        for (i32 i = 0; i < 3; i++) {
            float fv = ((s->fmask >> i) & 1) ? s->f[i] : 0.0f;
            c2b_bw_bits(w, c2b_f32_to_bits(fv), 32);
        }
        break;
    }
    case 3: {                                    /* DPT_VectorXY x2 */
        for (i32 i = 0; i < 2; i++) {
            float fv = ((s->fmask >> i) & 1) ? s->f[i] : 0.0f;
            c2b_bw_bits(w, c2b_f32_to_bits(fv), 32);
        }
        break;
    }
    case 4: {                                    /* DPT_String: [9 бит len][байты] */
        u32 n = s->str_n;
        if (n > 511) n = 511;
        c2b_bw_bits(w, n, 9);
        for (u32 i = 0; i < n; i++) c2b_bw_bits(w, (u32)(u8)s->str[i], 8);
        break;
    }
    case 5: {                                    /* DPT_Array: [count][элементы] */
        u32 num = sl->num ? sl->num : 1;
        u32 cnt = s->arr_cnt;
        if (cnt > num) cnt = num;
        c2b_bw_bits(w, cnt, c2b_g4_arr_bits(num));
        for (u32 i = 0; i < cnt; i++) {
            u64 ev = 0;
            if (s->arr_base + i < sizeof(g_g4_arr) / sizeof(g_g4_arr[0]))
                ev = g_g4_arr[s->arr_base + i];
            c2b_bw_bits(w, (u32)ev, 32);
        }
        break;
    }
    default:
        g_g4_err++;
        break;
    }
}

/* сортировка стейджа по слоту (вставками) + эмиссия S1-дельт и значений */
static i32 c2b_g4_emit(c2b_bw_t *w, const c2b_g4_cls_t *C)
{
    for (u32 i = 1; i < g_g4_stg_n; i++) {
        c2b_g4_stg_t key = g_g4_stg[i];
        i32 j = (i32)i - 1;
        while (j >= 0 && g_g4_stg[j].slot > key.slot) {
            g_g4_stg[j + 1] = g_g4_stg[j];
            j--;
        }
        g_g4_stg[j + 1] = key;
    }
    c2b_bw_bit(w, 1);                            /* newWay = 1 */
    i32 prev = -1;
    for (u32 i = 0; i < g_g4_stg_n; i++) {
        c2b_bw_fieldidx(w, (u32)(g_g4_stg[i].slot - prev - 1));
        prev = (i32)g_g4_stg[i].slot;
    }
    c2b_bw_bit(w, 0); c2b_bw_bit(w, 0);                   /* вход в 7-битную ветку */
    c2b_bw_bits(w, 0x7Fu, 7); c2b_bw_bits(w, 0x7Fu, 7);   /* end 0xFFF */
    for (u32 i = 0; i < g_g4_stg_n; i++)
        c2b_g4_emit_s1val(w, &g_s1_slots[C->slot_off + g_g4_stg[i].slot], &g_g4_stg[i]);
    return 0;
}

/* бит2: create -> 1 (enter), delta -> 0, leave -> delete-флаг */
static void c2b_g4_ent_header(c2b_bw_t *w, i32 idx, i32 *prev, u32 leave, u32 bit2)
{
    c2b_bw_ubitvar(w, (u32)(idx - *prev - 1));
    *prev = idx;
    c2b_bw_bit(w, leave);
    c2b_bw_bit(w, bit2);
}

/* --- главный вход: S2 CSVCMsg_PacketEntities -> S1 --- */
static u32 g_g4_rem, g_g4_skip, g_g4_nofsv;
static u32 g_g4_ub;          /* R36: кадров PE с f4 update_baseline != 0 (FINI: g4{... ub=}) */
/* t35: расширение телеметрии G-4 (FINI g4{ovf bnn ub dfm ds sr ps nf dm}) */
static u32 g_g4_dfm;        /* R34: delta-frame-miss — дельта на пропущенный кадр */
static u32 g_g4_dfm_pend;   /* R34: 1 = предыдущий кадр PE пропущен мостом */
static u32 g_g4_nf;         /* D1: встречен S2 net#2 (net_File не существует в CS2) */
static u32 g_g4_bnn;        /* PE-кадр без baseline (f5 absent/-1) */
static u32 g_g4_ds;         /* сумма updated_entries по обработанным PE */
static u32 g_g4_sr;         /* raw-pass из-за f13 serialized_entities */
static u32 g_g4_dm;         /* max(updated_entries) */

static i32 c2b_g4_packetentities(const u8 *pl, u32 n, u8 *out, u32 op0, u32 cap,
                                 u32 *out_op)
{
    if (!g_fsv_ser_n || !g_cls_emitted || !g_fsv_max_classes) { g_g4_nofsv++; return -1; }
    static u8 bs[512 * 1024];   /* R46 (t35): 192K -> 512K (пики PE-кадров) */
    static u8 head[96];
    static c2b_fp_t g4_paths[C2B_G4_PATHS];   /* пути перезапускаются на каждую сущность */
    u32 hn = 0, updated = 0, updated_seen = 0, pvs_vis = 0, ser_ent = 0;
    u32 bl = 0xFFFFFFFFu, delta_from = 0;   /* R34: f5 baseline / f6 delta_from */
    const u8 *ent_data = 0;
    u32 ent_n = 0, ip = 0;
    while (ip < n) {
        u32 tag, c = c2b_read_varint(pl + ip, n - ip, &tag);
        if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7, ts = ip;
        ip += c;
        u32 vl;
        if (wt == 0) {
            c = c2b_read_varint(pl + ip, n - ip, &vl);
            if (!c) return -1;
            ip += c;
        } else if (wt == 2) {
            c = c2b_read_varint(pl + ip, n - ip, &vl);
            if (!c || vl > n - ip) return -1;
            ip += c;
        } else if (wt == 5) { if (4 > n - ip) return -1; vl = 4; }
        else if (wt == 1) { if (8 > n - ip) return -1; vl = 8; }
        else return -1;
        /* R34: f4 update_baseline и f5 baseline CS2 НЕ форвардятся — семантика S1
         * иная (f4 у S1 = «записать состояние в instancebaseline», чужое true
         * перезапишет базлайн S1-клиента; f5 CS2 = слот CS2, S1 ждёт -1). */
        if (f >= 1 && f <= 6 && f != 2 && f != 4 && f != 5) {
            u32 tn = (wt == 0) ? (ip - ts) : (ip + vl - ts);  /* wt0: vl = значение */
            if (hn + tn > sizeof(head)) return -2;
            c2b_fwd_copy(head + hn, pl + ts, tn);
            hn += tn;
        }
        if (f == 2 && wt == 0) { updated = vl; updated_seen = 1; }
        if (f == 7 && wt == 2) { ent_data = pl + ip; ent_n = vl; }
        if (f == 16 && wt == 0) pvs_vis = vl;
        if (f == 4 && wt == 0 && vl) g_g4_ub++;   /* R36: update_baseline=1 (эталон 0x1030a) */
        if (f == 5 && wt == 0) bl = vl;          /* R34: CS2 baseline-слот */
        if (f == 6 && wt == 0) delta_from = vl;  /* R34: delta_from для dfm */
        if (f == 13 && wt == 2) ser_ent = 1;
        if (wt != 0) ip += vl;                   /* wt==0: значение уже прочитано */
    }
    if (!updated_seen || !ent_data || !ent_n || ser_ent) {
        g_g4_pass++;
        if (ser_ent) g_g4_sr++;                              /* g4{sr=} */
        if (delta_from) g_g4_dfm_pend = 1;                   /* R34: raw-pass рвёт цепочку */
        return -1;
    }
    g_g4_pkts++;
    if (bl == 0xFFFFFFFFu) g_g4_bnn++;                       /* g4{bnn=}: кадр без baseline */
    g_g4_ds += updated;                                      /* g4{ds=} */
    if (updated > g_g4_dm) g_g4_dm = updated;                /* g4{dm=} */
    if (delta_from) {
        if (g_g4_dfm_pend) { g_g4_dfm++; g_g4_dfm_pend = 0; } /* R34: дельта на пропущенную базу */
    } else {
        g_g4_dfm_pend = 0;                                   /* полный кадр чинит цепочку */
    }

    c2b_br_t br;
    c2b_br_init(&br, ent_data, ent_n);
    c2b_bw_t bw;
    bw.buf = bs; bw.cap = sizeof(bs); bw.pos = 0; bw.bitval = 0; bw.bitcnt = 0; bw.ovf = 0;

    u32 s1_bits = c2b_g4_class_bits(g_cls_emitted);
    u32 s2_bits = c2b_g4_class_bits(g_fsv_max_classes);
    i32 idx = -1, prev = -1;
    u32 emitted = 0;

    for (u32 k = 0; k < updated; k++) {
        u32 d = c2b_br_ubitvar(&br);
        idx = idx + 1 + (i32)d;
        u32 cmd = c2b_br_bits(&br, 2);
        u32 leave = cmd & 1, flag2 = (cmd >> 1) & 1;
        if (idx < 0 || idx >= C2B_G4_ENT_MAX || br.ovf) { g_g4_ovf++; return -3; }
        c2b_g4_ent_t *E = &g_g4_ent[idx];
        if (!leave) {
            if (flag2) {                         /* CREATE (enter PVS) */
                u32 cls2 = c2b_br_bits(&br, s2_bits);
                u32 serial = c2b_br_bits(&br, 17);
                (void)c2b_br_varuint32(&br);
                if (br.ovf) { g_g4_ovf++; return -3; }
                E->cls = (u16)((cls2 < 0xFFFFu) ? cls2 + 1 : 0);
                E->cellhave = E->offhave = 0;
                E->org[0] = E->org[1] = E->org[2] = 0.0f;   /* R42 */
                E->orghave = 0;                             /* R42 */
                for (u32 pi = 0; pi < C2B_G4_POLY_SLOTS; pi++) E->ps[pi] = 0xFFFFu;
                const c2b_g4_cls_t *C = (cls2 < 0xFFFFu) ? c2b_g4_cls_ctx(cls2) : 0;
                if (!C) {                        /* без схемы значения не читаются */
                    g_g4_desync++;               /* -> дроп всего кадра (безопасней) */
                    return -3;
                }
                c2b_g4_ent_header(&bw, idx, &prev, 0, 1);      /* enter */
                c2b_bw_bits(&bw, (cls2 < C2B_CLASS_MAP_MAX) ? g_class_id_map[cls2] : 0, s1_bits);
                c2b_bw_bits(&bw, serial & 0x3FFu, 10);
                if (c2b_g4_ent_fields(&br, E, C, g4_paths, C2B_G4_PATHS) != 0) { g_g4_desync++; return -3; }
                c2b_g4_emit(&bw, C);
                g_g4_ent_new++;
                emitted++;
            } else {                             /* UPDATE */
                if (pvs_vis && (c2b_br_bits(&br, 2) & 1)) { g_g4_skip++; continue; }
                if (!E->cls) {                   /* апдейт без create — десинк неминуем */
                    g_g4_desync++;
                    return -3;
                }
                const c2b_g4_cls_t *C = c2b_g4_cls_ctx(E->cls - 1);
                if (!C) { g_g4_desync++; return -3; }
                c2b_g4_ent_header(&bw, idx, &prev, 0, 0);      /* delta */
                if (c2b_g4_ent_fields(&br, E, C, g4_paths, C2B_G4_PATHS) != 0) { g_g4_desync++; return -3; }
                c2b_g4_emit(&bw, C);
                g_g4_ent_upd++;
                emitted++;
            }
        } else {                                 /* LEAVE (+delete) */
            if (flag2) E->cls = 0;
            E->org[0] = E->org[1] = E->org[2] = 0.0f;       /* R42: без сброса — */
            E->orghave = 0;                                 /*      призрак позиции при reuse idx */
            c2b_g4_ent_header(&bw, idx, &prev, 1, flag2);      /* leave+delete */
            g_g4_ent_del++;
            emitted++;
        }
        if (bw.ovf) { g_g4_ovf++; return -2; }
    }
    g_g4_rem += (br.size - br.pos);              /* непрочитанный хвост (диагностика) */
    u32 bs_n = c2b_bw_flush(&bw);
    if (br.ovf) { g_g4_desync++; return -3; }

    /* сборка S1 proto: head (f1,f3,f6 — f2/f4/f5 вынуты) + f5=-1 + f2 + f7 */
    if (op0 + hn + 16 + 12 + bs_n > cap) return -2;   /* +12: запас под f5=-1 */
    u32 op = op0;
    c2b_fwd_copy(out + op, head, hn);
    op += hn;
    /* R34: f5 baseline всегда -1. int32 -1 на проводе = 10-байтовый varint64;
     * пишем ЯВНО, чтобы S1-клиент видел «базлайн не задан» независимо от
     * [default] в скомпилированном proto (+11 байт на кадр, ~0.7 КБ/с @64tick). */
    op += c2b_write_varint(out + op, (5u << 3) | 0);
    op += c2b_write_varint64(out + op, (u64)(i64)-1);
    op += c2b_write_varint(out + op, (2u << 3) | 0);
    op += c2b_write_varint(out + op, emitted);
    op += c2b_write_varint(out + op, (7u << 3) | 2);
    op += c2b_write_varint(out + op, bs_n);
    c2b_fwd_copy(out + op, bs, bs_n);
    op += bs_n;
    g_g4_out++;
#ifndef C2B_SELFTEST
    /* R30: G4 бьёт каждый тик — первые 8 + каждый 512-й */
    if (c2b_vlog_hit(g_vlevel, g_g4_out, 8, 512)) {
        C2B_LOGS("[c2b] G4 in=");
        C2B_LOGN(updated);
        C2B_LOGS(" out=");
        C2B_LOGN(emitted);
        C2B_LOGS(" new=");
        C2B_LOGN(g_g4_ent_new);
        C2B_LOGS(" upd=");
        C2B_LOGN(g_g4_ent_upd);
        C2B_LOGS(" del=");
        C2B_LOGN(g_g4_ent_del);
        C2B_LOGS(" fld=");
        C2B_LOGN(g_g4_fields);
        C2B_LOGS(" miss=");
        C2B_LOGN(g_g4_miss);
        C2B_LOGS(" bs=");
        C2B_LOGN(bs_n);
        C2B_LOGS("\n");
    }
#endif
    *out_op = op;
    return 0;
}

/* ============================================================ */
/* ---------- фаза G-4b: instanceBaseline (stringtable) ---------
 * S2 svc_CreateStringTable(44) c именем "instancebaseline" (клиент S1
 * лоуверкейсит имена таблиц): userdata каждой строки = S2-базлайн класса
 * (тот же энкод, что payload PacketEntities: huffman-пути + значения —
 * demoinfocs-golang entity.go: e.readFields(baseline_reader)).
 * S1-клиент декодит базлайн той же машиной ReadFieldIndex, что и payload
 * PacketEntities (аргумент: svc_PacketEntities.update_baseline мёржит
 * baseline-ридер с entity-ридером одним ReadFieldIndex; сервер пишет
 * базлайн тем же SendTable_WritePropList) => S1-базлайн = наш c2b_g4_emit
 * БЕЗ entity-заголовка.
 * Фрейминг items (демо-референс parseStringTable, един для S1/S2):
 *   bit incr | bit0: varint32 idx-1 | bit hasKey [bit useHistory
 *   [5b pos][5b size] str | str] | bit hasValue [fixed: uds_bits |
 *   [flags&1: bit compressed] size=varint_bc?ubitvar:17b, байты]
 * Ключи "class_id" (десятичные) транскодятся; пустые/":": cкип.
 * S1-эмиссия: тот же фрейминг, размер = 17 бит (клиент без
 * using_varint_bitcounts — его proto f1..f8, FDP подтверждён), БЕЗ
 * per-item compressed-бита, flags &= ~1.
 * svc_UpdateStringTable(45) для instancebaseline — фаза G-4d: транскод
 * в S1(13) тем же энкодом (c2b_g4d_updatetable), при сбое — дроп. */
static u32 g_g4b_tbl_seen;      /* CreateStringTable счётчик (id таблиц) */
static u32 g_g4b_tbl_id;        /* индекс instancebaseline среди созданных таблиц */
#define C2B_G4B_NO_TBL 0xFFFFFFFFu
static u32 g_g4b_msgs, g_g4b_rows, g_g4b_kept, g_g4b_skip, g_g4b_nocls,
           g_g4b_decerr, g_g4b_ovf, g_g4b_upd_drop, g_g4b_compress;
static u32 g_g4b_bin, g_g4b_bout;
static u32 g_g4b_cls_ovf;            /* R33: дропы кэша cls (index >= CLS_AT) */

static u8 g_g4b_blob[256 * 1024];    /* S1 string_data */
static u8 g_g4b_row[64 * 1024];      /* S1-базлайн одной строки */
static u8 g_g4b_item[128 * 1024];    /* S2-значение строки (после snappy) */
static u8 g_g4b_blb2[1024 * 1024];   /* R46 (t35): 256K -> 1M; весь блоб после snappy */
static c2b_fp_t g_g4b_paths[512];

/* G-4d: свойства таблицы instancebaseline с Create + кэш ключ->класс по индексу
 * (S2-апдейт может прислать item без key — класс берём из кэша Create) */
/* R33: 1024 -> 4096 (S1 class_id 16-бит, аномальные ClassInfo покрыты;
 * цена статики 8 КБ). Раньше при index >1024 кэш молча не писался —
 * теперь дроп считается в g_g4b_cls_ovf и виден в FINI. */
#define C2B_G4B_CLS_AT 4096
#define C2B_G4B_NOCLS  0xFFFFu
static u32 g_g4b_t_fixed, g_g4b_t_udsb, g_g4b_t_flags, g_g4b_t_vbc;
static u16 g_g4b_cls_at[C2B_G4B_CLS_AT];

/* snappy raw-format декомпрессор (preamble varint + literal/copy1/2/4) */
static i32 c2b_snappy_decomp(const u8 *in, u32 n, u8 *out, u32 cap)
{
    u32 ip = 0, op = 0, ulen = 0, c;
    c = c2b_read_varint(in, n, &ulen);
    if (!c || ulen > cap) return -1;
    ip = c;
    while (ip < n) {
        u8 tag = in[ip++];
        u32 t = tag & 3;
        if (t == 0) {                            /* literal */
            u32 ln = (u32)(tag >> 2) + 1;
            if (ln > 60) {
                u32 nb = ln - 60, v = 0;
                if (nb > n - ip) return -1;
                for (u32 i = 0; i < nb; i++) v |= (u32)in[ip + i] << (8 * i);
                ip += nb;
                ln = v + 1;
            }
            if (ln > n - ip || ln > cap - op) return -1;
            for (u32 i = 0; i < ln; i++) out[op + i] = in[ip + i];
            ip += ln; op += ln;
        } else {
            u32 ln, off;
            if (t == 1) {                        /* copy1: 1 байт оффсет */
                if (ip >= n) return -1;
                ln = 4 + ((tag >> 2) & 7);
                off = ((u32)(tag >> 5) << 8) | in[ip];
                ip += 1;
            } else if (t == 2) {                 /* copy2: 2 байта */
                if (2 > n - ip) return -1;
                ln = (u32)(tag >> 2) + 1;
                off = (u32)in[ip] | ((u32)in[ip + 1] << 8);
                ip += 2;
            } else {                             /* copy4: 4 байта */
                if (4 > n - ip) return -1;
                ln = (u32)(tag >> 2) + 1;
                off = (u32)in[ip] | ((u32)in[ip + 1] << 8) |
                      ((u32)in[ip + 2] << 16) | ((u32)in[ip + 3] << 24);
                ip += 4;
            }
            if (!off || off > op || ln > cap - op) return -1;
            for (u32 i = 0; i < ln; i++) { out[op] = out[op - off]; op++; }
        }
    }
    return (op == ulen) ? (i32)op : -1;
}

/* case-insensitive "instancebaseline" */
static i32 c2b_g4b_is_base(const u8 *s, u32 n)
{
    const char *p = "instancebaseline";
    u32 i;
    if (n != 16) return 0;
    for (i = 0; i < 16; i++) {
        char c = (char)s[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c != p[i]) return 0;
    }
    return 1;
}

/* десятичный ключ -> class_id (0..1023), иначе -1 */
static i32 c2b_g4b_key_cls(const char *k)
{
    i32 v = 0;
    if (!*k) return -1;
    for (u32 i = 0; k[i]; i++) {
        if (k[i] < '0' || k[i] > '9') return -1;
        v = v * 10 + (k[i] - '0');
        if (v > 65535) return -1;
    }
    return v;
}

/* R32: S1-ключ строки instancebaseline = десятичный S1 class_id — S1-клиент
 * ищет базлайн по id класса из СИНТЕЗИРОВАННОГО ClassInfo (emit-порядок),
 * а не по S2 id (карта g_class_id_map не identity: тест g4 даёт map[1]=0).
 * Класс вне зарегистрированного диапазона карты -> ключ S2 дословно
 * (строку всё равно скипнет nocls — ключ лишь для диагностики в дампе). */
static void c2b_g4b_s1_key(i32 cls2, const char *ks2, char *out, u32 cap)
{
    if (cls2 >= 0 && (u32)cls2 < g_class_id_map_n && cap >= 8) {
        u32 v = g_class_id_map[cls2];
        char tmp[8]; u32 n = 0;
        do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while (v && n < sizeof(tmp));
        for (u32 i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
        out[n] = 0;
        return;
    }
    u32 i = 0;
    for (; ks2[i] && i < cap - 1; i++) out[i] = ks2[i];
    out[i] = 0;
}

/* varint из битстрима (Go: ReadVarInt32 = 8-битные чанки) */
static u32 c2b_g4b_bit_varint(c2b_br_t *r)
{
    u32 res = 0, b = 0x80;
    for (u32 cnt = 0; (b & 0x80) && cnt < 5; cnt++) {
        b = c2b_br_bits(r, 8);
        res |= (b & 0x7f) << (7 * cnt);
    }
    return res;
}

static void c2b_g4b_wvarint(c2b_bw_t *w, u32 v)
{
    u8 vb[5]; u32 vn = c2b_write_varint(vb, v);
    for (u32 i = 0; i < vn; i++) c2b_bw_bits(w, vb[i], 8);
}

/* null-terminated строка из битстрима (Go readStringLimited, макс 4096) */
static i32 c2b_g4b_bit_str(c2b_br_t *r, char *out, u32 cap)
{
    u32 n = 0;
    for (u32 i = 0; i < 4096; i++) {
        u8 ch = (u8)c2b_br_bits(r, 8);
        if (r->ovf) return -1;
        if (!ch) break;
        if (n + 1 < cap) out[n++] = (char)ch;
    }
    out[n] = 0;
    return (i32)n;
}

/* главный вход: S2 CSVCMsg_CreateStringTable. rc: 0 = эмиссия S1(12),
 * -1 = не instancebaseline (generic-путь), -2 = oom, -3 = дроп. */
static i32 c2b_g4b_stringtable(const u8 *pl, u32 n, u8 *out, u32 op0, u32 cap,
                               u32 *out_op)
{
    const u8 *name = 0; u32 name_n = 0;
    u32 num_entries = 0, fixed = 0, uds = 0, uds_bits = 0, flags = 0,
        compressed = 0, varint_bc = 0;
    const u8 *data = 0; u32 data_n = 0;
    g_g4b_tbl_seen++;

    u32 ip = 0;
    while (ip < n) {
        u32 tag, c = c2b_read_varint(pl + ip, n - ip, &tag);
        if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7;
        ip += c;
        if (wt == 0) {
            u32 v;
            c = c2b_read_varint(pl + ip, n - ip, &v); if (!c) return -1;
            ip += c;
            if (f == 2) num_entries = v;
            else if (f == 3) fixed = v;
            else if (f == 4) uds = v;
            else if (f == 5) uds_bits = v;
            else if (f == 6) flags = v;
            else if (f == 9) compressed = v;
            else if (f == 10) varint_bc = v;
        } else if (wt == 2) {
            u32 ln;
            c = c2b_read_varint(pl + ip, n - ip, &ln); if (!c) return -1;
            ip += c;
            if (ln > n - ip) return -1;
            if (f == 1 && !name) { name = pl + ip; name_n = ln; }
            else if (f == 7 && !data) { data = pl + ip; data_n = ln; }
            ip += ln;
        } else if (wt == 5) { if (4 > n - ip) return -1; ip += 4; }
        else if (wt == 1) { if (8 > n - ip) return -1; ip += 8; }
        else return -1;
    }

    if (!name || !c2b_g4b_is_base(name, name_n)) return -1;
    if (!data || !data_n || !num_entries) return -1;   /* пустая таблица: generic-путь ок */
    g_g4b_tbl_id = g_g4b_tbl_seen - 1;               /* id этой таблицы (порядок создания) */
    g_g4b_t_fixed = fixed; g_g4b_t_udsb = uds_bits;  /* G-4d: свойства для апдейтов */
    g_g4b_t_flags = flags; g_g4b_t_vbc = varint_bc;
    for (u32 ci = 0; ci < C2B_G4B_CLS_AT; ci++) g_g4b_cls_at[ci] = C2B_G4B_NOCLS;
    g_g4b_msgs++;
    g_g4b_bin += data_n;

    const u8 *blob = data; u32 blob_n = data_n;
    if (compressed) {                                /* весь блоб в snappy */
        i32 rn = c2b_snappy_decomp(data, data_n, g_g4b_blb2, sizeof(g_g4b_blb2));
        if (rn < 0) { g_g4b_ovf++; return -3; }
        g_g4b_compress++;
        blob = g_g4b_blb2; blob_n = (u32)rn;
    }

    /* --- парс items (S2 framing) + транскод + сборка S1-блоба --- */
    c2b_br_t r;
    c2b_br_init(&r, blob, blob_n);
    c2b_bw_t w;
    w.buf = g_g4b_blob; w.cap = sizeof(g_g4b_blob);
    w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;

    i32 index = -1;
    i32 prev_idx = -1;                               /* последний ЭМИТНУТЫЙ индекс */
    char keys[32][40];                               /* история ключей (32) */
    u32 keys_n = 0;
    char key[4096];   /* R39 (t35): 48 -> 4096 (длинные ключи stringtable) */

    for (u32 it = 0; it < num_entries && it < 65536; it++) {
        key[0] = 0;
        if (c2b_br_bit(&r)) index++;                 /* incr */
        else index = (i32)c2b_g4b_bit_varint(&r) + 1;
        if (r.ovf) { g_g4b_ovf++; return -3; }

        i32 has_key = (i32)c2b_br_bit(&r);
        if (has_key) {
            if (c2b_br_bit(&r)) {                    /* useHistory */
                u32 pos = c2b_br_bits(&r, 5), size = c2b_br_bits(&r, 5);
                char sub[4096]; u32 kn = 0;   /* R39 (t35): 40 -> 4096 */
                if (pos >= keys_n) {
                    if (c2b_g4b_bit_str(&r, sub, sizeof(sub)) < 0) { g_g4b_ovf++; return -3; }
                    while (sub[kn] && kn < sizeof(key) - 1) { key[kn] = sub[kn]; kn++; }
                    key[kn] = 0;
                } else {
                    const char *h = keys[pos];
                    u32 hl = 0; while (h[hl]) hl++;
                    if (size > hl) {
                        if (c2b_g4b_bit_str(&r, sub, sizeof(sub)) < 0) { g_g4b_ovf++; return -3; }
                        u32 j = 0;
                        while (h[j] && kn < sizeof(key) - 1) key[kn++] = h[j++];
                        j = 0;
                        while (sub[j] && kn < sizeof(key) - 1) key[kn++] = sub[j++];
                        key[kn] = 0;
                    } else {
                        if (c2b_g4b_bit_str(&r, sub, sizeof(sub)) < 0) { g_g4b_ovf++; return -3; }
                        u32 j = 0;
                        while (j < size && kn < sizeof(key) - 1) key[kn++] = h[j++];
                        j = 0;
                        while (sub[j] && kn < sizeof(key) - 1) key[kn++] = sub[j++];
                        key[kn] = 0;
                    }
                }
            } else {
                if (c2b_g4b_bit_str(&r, key, sizeof(key)) < 0) { g_g4b_ovf++; return -3; }
            }
            {                                        /* история (Go: append, trim до 32) */
                if (keys_n == 32) {
                    for (u32 i2 = 0; i2 < 31; i2++)
                        for (u32 j2 = 0; j2 < 40; j2++)
                            keys[i2][j2] = keys[i2 + 1][j2];
                    keys_n = 31;
                }
                u32 j = 0;
                while (key[j] && j < 39) { keys[keys_n][j] = key[j]; j++; }
                keys[keys_n][j] = 0;
                keys_n++;
            }
        }

        i32 has_val = (i32)c2b_br_bit(&r);
        if (!has_val) { g_g4b_rows++; continue; }

        u32 val_bits;
        if (fixed) val_bits = uds_bits;
        else {
            if (flags & 1u && c2b_br_bit(&r)) {
                g_g4b_ovf++; return -3;              /* v0: per-item snappy не встречается */
            }
            val_bits = varint_bc ? (c2b_br_ubitvar(&r) * 8)
                                 : (c2b_br_bits(&r, 17) * 8);
        }
        u32 val_bytes = (val_bits + 7) >> 3;
        if (val_bytes > sizeof(g_g4b_item) || r.ovf) { g_g4b_ovf++; return -3; }
        {
            u32 nb = val_bits >> 3;
            for (u32 i2 = 0; i2 < nb; i2++) g_g4b_item[i2] = (u8)c2b_br_bits(&r, 8);
            if (val_bits & 7) g_g4b_item[nb] = (u8)c2b_br_bits(&r, val_bits & 7);
        }
        g_g4b_rows++;

        /* --- транскод строки: ключ = S2 class_id --- */
        i32 cls2 = c2b_g4b_key_cls(key);
        if (cls2 < 0) { g_g4b_skip++; continue; }    /* пустые/"tick:cls" */
        const c2b_g4_cls_t *C = c2b_g4_cls_ctx((u32)cls2);
        if (!C) { g_g4b_nocls++; continue; }

        c2b_g4_ent_t E;
        E.cls = 0; E.pad = 0;
        E.cell[0] = E.cell[1] = E.cell[2] = 0;
        E.coff[0] = E.coff[1] = E.coff[2] = 0.0f;
        E.cellhave = E.offhave = 0;
        E.orghave = 0;                           /* R42: временная baseline-энтити */
        for (u32 pi = 0; pi < C2B_G4_POLY_SLOTS; pi++) E.ps[pi] = 0xFFFFu;
        c2b_br_t vr;
        c2b_br_init(&vr, g_g4b_item, val_bytes);
        if (c2b_g4_ent_fields(&vr, &E, C, g_g4b_paths, sizeof(g_g4b_paths) / sizeof(g_g4b_paths[0])) != 0) {
            g_g4b_decerr++; continue;
        }

        c2b_bw_t rw;
        rw.buf = g_g4b_row; rw.cap = sizeof(g_g4b_row);
        rw.pos = 0; rw.bitval = 0; rw.bitcnt = 0; rw.ovf = 0;
        c2b_g4_emit(&rw, C);
        u32 rn = c2b_bw_flush(&rw);
        if (rw.ovf) { g_g4b_ovf++; continue; }
        if (rn > 16383) { g_g4b_ovf++; continue; }   /* S1: размер item = 17 бит (MAX_USERDATA) */

        /* --- строка в S1-блоб (S1 framing: размер = 17 бит) --- */
        if (index < 0 || index > 65535) { g_g4b_skip++; continue; }
        if (index == prev_idx + 1) c2b_bw_bit(&w, 1);
        else { c2b_bw_bit(&w, 0); c2b_g4b_wvarint(&w, (u32)index - 1); }
        c2b_bw_bit(&w, 1);                           /* hasKey */
        c2b_bw_bit(&w, 0);                           /* без истории */
        { char k1[16];                               /* R32: ключ = S1 class_id */
          c2b_g4b_s1_key(cls2, key, k1, sizeof(k1));
          u32 kn = 0; while (k1[kn]) kn++;
          for (u32 i2 = 0; i2 <= kn; i2++) c2b_bw_bits(&w, (u32)(u8)k1[i2], 8); }
        c2b_bw_bit(&w, 1);                           /* hasValue */
        c2b_bw_bits(&w, rn, 17);                     /* S1: размер в БАЙТАХ (клиент *8) */
        for (u32 i2 = 0; i2 < rn; i2++) c2b_bw_bits(&w, g_g4b_row[i2], 8);
        g_g4b_kept++;
        g_g4b_bout += rn;
        if (index < C2B_G4B_CLS_AT) g_g4b_cls_at[index] = (u16)cls2;
        else { g_g4b_cls_ovf++;                              /* R33: не молча */
               if (g_g4b_cls_ovf <= 4 || g_vlevel >= 2) {
                   C2B_LOGS("[c2b] g4b cls-at ovf create idx=");
                   C2B_LOGN(index); C2B_LOGS("\n"); } }
        prev_idx = index;
    }
    if (r.ovf || w.ovf) { g_g4b_ovf++; return -3; }
    u32 blob_out = c2b_bw_flush(&w);
    if (w.ovf || blob_out >= sizeof(g_g4b_blob)) { g_g4b_ovf++; return -3; }

    /* --- S1 CSVCMsg_CreateStringTable(12): f1..f8 --- */
    u32 maxent = g_class_id_map_n ? g_class_id_map_n : num_entries;
    u8 hdr[64]; u32 hn = 0;
    hdr[hn++] = (1u << 3) | 2;
    hn += c2b_write_varint(hdr + hn, name_n);
    for (u32 i = 0; i < name_n; i++) hdr[hn++] = name[i];
    hdr[hn++] = (2u << 3); hn += c2b_write_varint(hdr + hn, maxent);
    hdr[hn++] = (3u << 3); hn += c2b_write_varint(hdr + hn, num_entries);
    if (fixed)    { hdr[hn++] = (4u << 3); hn += c2b_write_varint(hdr + hn, fixed); }
    if (uds)      { hdr[hn++] = (5u << 3); hn += c2b_write_varint(hdr + hn, uds); }
    if (uds_bits) { hdr[hn++] = (6u << 3); hn += c2b_write_varint(hdr + hn, uds_bits); }
    if (flags & ~1u) { hdr[hn++] = (7u << 3); hn += c2b_write_varint(hdr + hn, flags & ~1u); }
    hdr[hn++] = (8u << 3) | 2;
    hn += c2b_write_varint(hdr + hn, blob_out);

    if (op0 + hn + 8 + blob_out > cap) return -2;
    u32 op = op0;
    op += c2b_write_varint(out + op, 12);            /* S1 svc_CreateStringTable */
    op += c2b_write_varint(out + op, hn + blob_out);
    c2b_fwd_copy(out + op, hdr, hn); op += hn;
    c2b_fwd_copy(out + op, g_g4b_blob, blob_out); op += blob_out;
    *out_op = op;
    return 0;
}

/* UpdateStringTable: это апдейт instancebaseline? (f1 table_id) */
static i32 c2b_g4b_upd_is_baseline(const u8 *pl, u32 n)
{
    if (g_g4b_tbl_id == C2B_G4B_NO_TBL) { g_fini2.ba_nt++; return 0; }   /* ba{nt}: 45-е до Create */
    u32 ip = 0, tag;
    u32 c = c2b_read_varint(pl, n, &tag);
    if (!c) return 0;
    ip += c;
    if ((tag >> 3) != 1 || (tag & 7) != 0) return 0;
    u32 v;
    c = c2b_read_varint(pl + ip, n - ip, &v);
    if (!c) return 0;
    return (v == g_g4b_tbl_id) ? 1 : 0;
}

/* ============================================================ */
/* ---------- фаза G-4d: svc_UpdateStringTable(45) instancebaseline ----------
 * CS2 CSVCMsg_UpdateStringTable {1 table_id, 2 num_changed, 3 string_data}:
 * string_data = тот же item-фрейминг, что в CreateStringTable; свойства
 * кодирования (fixed/uds_bits/flags/varint_bc) берём из СОХРАНЁННОГО Create
 * (g_g4b_t_*). Значение каждой строки = полный S2-базлайн класса ->
 * c2b_g4_emit -> S1-байты (тот же энкод, что G-4b/PacketEntities).
 * Item без key: класс из кэша g_g4b_cls_at[index] (заполнен на Create).
 * Эмиссия S1 CSVCMsg_UpdateStringTable(13) {1 table_id, 2 num_changed=kept,
 * 3 data} — table_id 1:1 (CreateStringTable проходят все, порядок един).
 * rc: 0 = эмиссия, -1 = не наш/мусорный парс (дроп), -2 = oom, -3 = дроп. */
static u32 g_g4d_msgs, g_g4d_kept, g_g4d_skip, g_g4d_nocls,
           g_g4d_decerr, g_g4d_ovf, g_g4d_bin, g_g4d_bout;

static i32 c2b_g4d_updatetable(const u8 *pl, u32 n, u8 *out, u32 op0, u32 cap,
                               u32 *out_op)
{
    u32 tbl = 0, numc = 0;
    const u8 *data = 0; u32 data_n = 0;
    u32 ip = 0;
    while (ip < n) {
        u32 tag, c = c2b_read_varint(pl + ip, n - ip, &tag);
        if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7;
        ip += c;
        if (wt == 0) {
            u32 v; c = c2b_read_varint(pl + ip, n - ip, &v); if (!c) return -1;
            ip += c;
            if (f == 1) tbl = v; else if (f == 2) numc = v;
        } else if (wt == 2) {
            u32 ln; c = c2b_read_varint(pl + ip, n - ip, &ln); if (!c) return -1;
            ip += c;
            if (ln > n - ip) return -1;
            if (f == 3 && !data) { data = pl + ip; data_n = ln; }
            ip += ln;
        } else if (wt == 5) { if (4 > n - ip) return -1; ip += 4; }
        else if (wt == 1) { if (8 > n - ip) return -1; ip += 8; }
        else return -1;
    }
    if (tbl != g_g4b_tbl_id) return -1;              /* чужая таблица: generic-путь */
    if (!data || !data_n || !numc || numc > 65536) return -1;
    g_g4d_msgs++;
    g_fini2.ba_p++;                                  /* ba{p}: baseline-апдейт разобран */
    g_g4d_bin += data_n;

    const u8 *blob = data; u32 blob_n = data_n;
    /* W-1 (t35): апдейт-блоб приходит СЫРЫМ item-фреймингом: CSVCMsg_UpdateStringTable
     * не несёт флага компрессии (S2 proto f1..f3), whole-blob data_compressed (f9)
     * действует только на Create-блоб, а bit0 таблицы — это per-item compressed-бит
     * (читается ниже в item-цикле по flags&1). Раньше здесь был c2b_snappy_decomp по
     * (t_flags&1): при flags&1=1 сырой блоб «декомпрессировался» и весь апдейт
     * дропался (g4d_ovf). Референс demoinfocs handleUpdateStringTable парсит апдейт
     * без data_compressed. Диз эталона 5cce9ff4: snappy-вызова в G-4d нет. */

    c2b_br_t r;
    c2b_br_init(&r, blob, blob_n);
    c2b_bw_t w;
    w.buf = g_g4b_blob; w.cap = sizeof(g_g4b_blob);
    w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;

    i32 index = -1;
    i32 prev_idx = -1;
    char keys[32][40];
    u32 keys_n = 0;
    char key[4096];   /* R39 (t35): 48 -> 4096 (длинные ключи stringtable) */
    u32 kept = 0;

    for (u32 it = 0; it < numc && it < 65536; it++) {
        key[0] = 0;
        if (c2b_br_bit(&r)) index++;
        else index = (i32)c2b_g4b_bit_varint(&r) + 1;
        if (r.ovf) { g_g4d_ovf++; return -3; }

        i32 has_key = (i32)c2b_br_bit(&r);
        if (has_key) {
            if (c2b_br_bit(&r)) {                    /* useHistory */
                u32 pos = c2b_br_bits(&r, 5), size = c2b_br_bits(&r, 5);
                char sub[4096]; u32 kn = 0;   /* R39 (t35): 40 -> 4096 */
                if (pos >= keys_n) {
                    if (c2b_g4b_bit_str(&r, sub, sizeof(sub)) < 0) { g_g4d_ovf++; return -3; }
                    while (sub[kn] && kn < sizeof(key) - 1) { key[kn] = sub[kn]; kn++; }
                    key[kn] = 0;
                } else {
                    const char *h = keys[pos];
                    u32 hl = 0; while (h[hl]) hl++;
                    if (size > hl) {
                        if (c2b_g4b_bit_str(&r, sub, sizeof(sub)) < 0) { g_g4d_ovf++; return -3; }
                        u32 j = 0;
                        while (h[j] && kn < sizeof(key) - 1) key[kn++] = h[j++];
                        j = 0;
                        while (sub[j] && kn < sizeof(key) - 1) key[kn++] = sub[j++];
                        key[kn] = 0;
                    } else {
                        if (c2b_g4b_bit_str(&r, sub, sizeof(sub)) < 0) { g_g4d_ovf++; return -3; }
                        u32 j = 0;
                        while (j < size && kn < sizeof(key) - 1) key[kn++] = h[j++];
                        j = 0;
                        while (sub[j] && kn < sizeof(key) - 1) key[kn++] = sub[j++];
                        key[kn] = 0;
                    }
                }
            } else {
                if (c2b_g4b_bit_str(&r, key, sizeof(key)) < 0) { g_g4d_ovf++; return -3; }
            }
            {                                        /* история (Go: append, trim до 32) */
                if (keys_n == 32) {
                    for (u32 i2 = 0; i2 < 31; i2++)
                        for (u32 j2 = 0; j2 < 40; j2++)
                            keys[i2][j2] = keys[i2 + 1][j2];
                    keys_n = 31;
                }
                u32 j = 0;
                while (key[j] && j < 39) { keys[keys_n][j] = key[j]; j++; }
                keys[keys_n][j] = 0;
                keys_n++;
            }
        }

        i32 has_val = (i32)c2b_br_bit(&r);
        if (!has_val) continue;                      /* изменение только ключа */

        u32 val_bits;
        if (g_g4b_t_fixed) val_bits = g_g4b_t_udsb;
        else {
            if ((g_g4b_t_flags & 1u) && c2b_br_bit(&r)) {
                g_g4d_ovf++; return -3;              /* per-item snappy: v0 не встречается */
            }
            val_bits = g_g4b_t_vbc ? (c2b_br_ubitvar(&r) * 8)
                                   : (c2b_br_bits(&r, 17) * 8);
        }
        u32 val_bytes = (val_bits + 7) >> 3;
        if (val_bytes > sizeof(g_g4b_item) || r.ovf) { g_g4d_ovf++; return -3; }
        {
            u32 nb = val_bits >> 3;
            for (u32 i2 = 0; i2 < nb; i2++) g_g4b_item[i2] = (u8)c2b_br_bits(&r, 8);
            if (val_bits & 7) g_g4b_item[nb] = (u8)c2b_br_bits(&r, val_bits & 7);
        }

        /* --- класс: ключ или кэш Create --- */
        i32 cls2 = c2b_g4b_key_cls(key);
        if (cls2 < 0 && !has_key && index >= 0 && index < C2B_G4B_CLS_AT &&
            g_g4b_cls_at[index] != C2B_G4B_NOCLS)
            cls2 = (i32)g_g4b_cls_at[index];
        if (cls2 < 0) { g_g4d_skip++; continue; }
        const c2b_g4_cls_t *C = c2b_g4_cls_ctx((u32)cls2);
        if (!C) { g_g4d_nocls++; continue; }

        c2b_g4_ent_t E;
        E.cls = 0; E.pad = 0;
        E.cell[0] = E.cell[1] = E.cell[2] = 0;
        E.coff[0] = E.coff[1] = E.coff[2] = 0.0f;
        E.cellhave = E.offhave = 0;
        E.orghave = 0;                           /* R42: временная baseline-энтити */
        for (u32 pi = 0; pi < C2B_G4_POLY_SLOTS; pi++) E.ps[pi] = 0xFFFFu;
        c2b_br_t vr;
        c2b_br_init(&vr, g_g4b_item, val_bytes);
        if (c2b_g4_ent_fields(&vr, &E, C, g_g4b_paths, sizeof(g_g4b_paths) / sizeof(g_g4b_paths[0])) != 0) {
            g_g4d_decerr++; continue;
        }

        c2b_bw_t rw;
        rw.buf = g_g4b_row; rw.cap = sizeof(g_g4b_row);
        rw.pos = 0; rw.bitval = 0; rw.bitcnt = 0; rw.ovf = 0;
        c2b_g4_emit(&rw, C);
        u32 rn = c2b_bw_flush(&rw);
        if (rw.ovf) { g_g4d_ovf++; continue; }
        if (rn > 16383) { g_g4d_ovf++; continue; }   /* S1: размер item = 17 бит */

        /* --- строка в S1-блоб (S1 framing: размер = 17 бит) --- */
        if (index < 0 || index > 65535) { g_g4d_skip++; continue; }
        if (index == prev_idx + 1) c2b_bw_bit(&w, 1);
        else { c2b_bw_bit(&w, 0); c2b_g4b_wvarint(&w, (u32)index - 1); }
        if (has_key) {
            c2b_bw_bit(&w, 1);                       /* hasKey */
            c2b_bw_bit(&w, 0);                       /* без истории */
            { char k1[16];                           /* R32: ключ = S1 class_id */
              c2b_g4b_s1_key(cls2, key, k1, sizeof(k1));
              u32 kn = 0; while (k1[kn]) kn++;
              for (u32 i2 = 0; i2 <= kn; i2++) c2b_bw_bits(&w, (u32)(u8)k1[i2], 8); }
        } else c2b_bw_bit(&w, 0);                    /* key наследуется клиентом */
        c2b_bw_bit(&w, 1);                           /* hasValue */
        c2b_bw_bits(&w, rn, 17);
        for (u32 i2 = 0; i2 < rn; i2++) c2b_bw_bits(&w, g_g4b_row[i2], 8);
        g_g4d_kept++;
        g_g4d_bout += rn;
        if (index < C2B_G4B_CLS_AT) g_g4b_cls_at[index] = (u16)cls2;
        else { g_g4b_cls_ovf++;                              /* R33: не молча */
               if (g_g4b_cls_ovf <= 4 || g_vlevel >= 2) {
                   C2B_LOGS("[c2b] g4b cls-at ovf update idx=");
                   C2B_LOGN(index); C2B_LOGS("\n"); } }
        prev_idx = index;
        kept++;
    }
    if (r.ovf || w.ovf) { g_g4d_ovf++; return -3; }
    u32 blob_out = c2b_bw_flush(&w);
    if (w.ovf || blob_out >= sizeof(g_g4b_blob)) { g_g4d_ovf++; return -3; }
    if (!kept) return -3;                            /* транскодировать нечего */

    /* --- S1 CSVCMsg_UpdateStringTable(13): f1 table_id, f2 num_changed, f3 data --- */
    u8 hdr[32]; u32 hn = 0;
    hdr[hn++] = (1u << 3); hn += c2b_write_varint(hdr + hn, tbl);
    hdr[hn++] = (2u << 3); hn += c2b_write_varint(hdr + hn, kept);
    hdr[hn++] = (3u << 3) | 2; hn += c2b_write_varint(hdr + hn, blob_out);

    if (op0 + hn + 8 + blob_out > cap) return -2;
    u32 op = op0;
    op += c2b_write_varint(out + op, 13);            /* S1 svc_UpdateStringTable */
    op += c2b_write_varint(out + op, hn + blob_out);
    c2b_fwd_copy(out + op, hdr, hn); op += hn;
    c2b_fwd_copy(out + op, g_g4b_blob, blob_out); op += blob_out;
    g_fini2.ba_s++;                                  /* ba{s}: baseline-апдейт отправлен */
    *out_op = op;
    return 0;
}

static i32 c2b_synth_classinfo(const u8 *pl, u32 n, u8 *out, u32 op, u32 cap,
                               u32 *out_op)

{
    static u8 tmp[96 * 1024];
    u32 tn = 0, emit_idx = 0, ip = 0;

    g_class_id_map_n = 0;
    for (u32 i = 0; i < C2B_CLASS_MAP_MAX; i++) g_class_seen[i] = 0;

    while (ip < n) {
        u32 tag, ln = 0, c, f, wt;
        c = c2b_read_varint(pl + ip, n - ip, &tag); if (!c) return -1;
        ip += c;
        f = tag >> 3; wt = tag & 7;
        if (wt == 0) {
            u32 v;
            c = c2b_read_varint(pl + ip, n - ip, &v); if (!c) return -1;
            ip += c;                        /* f1 create_on_client: игнорируем */
        } else if (wt == 2) {
            c = c2b_read_varint(pl + ip, n - ip, &ln); if (!c) return -1;
            ip += c;
            if (ln > n - ip) return -1;
            if (f == 2) {
                /* S2 class_t { class_id=1, class_name=3 } (dt_name=2 нет) */
                const u8 *sub = pl + ip;
                u32 sp = 0, class_id = 0;
                const u8 *cn = 0; u32 cn_n = 0;
                while (sp < ln) {
                    u32 t2, l2 = 0, c2, f2, w2;
                    c2 = c2b_read_varint(sub + sp, ln - sp, &t2); if (!c2) return -1;
                    sp += c2;
                    f2 = t2 >> 3; w2 = t2 & 7;
                    if (w2 == 0) {
                        u32 v;
                        c2 = c2b_read_varint(sub + sp, ln - sp, &v); if (!c2) return -1;
                        sp += c2;
                        if (f2 == 1) class_id = v;
                    } else if (w2 == 2) {
                        c2 = c2b_read_varint(sub + sp, ln - sp, &l2); if (!c2) return -1;
                        sp += c2;
                        if (l2 > ln - sp) return -1;
                        if (f2 == 3) { cn = sub + sp; cn_n = l2; }
                        sp += l2;
                    } else return -1;
                }
                if (cn && cn_n) {
                    char cbuf[96], dtbuf[80];
                    u32 i, dtn;
                    if (cn_n >= sizeof(cbuf)) cn_n = sizeof(cbuf) - 1;
                    for (i = 0; i < cn_n; i++) cbuf[i] = (char)cn[i];
                    cbuf[cn_n] = 0;

                    if (class_id < C2B_CLASS_MAP_MAX) g_class_seen[class_id] = 1;
                    {
                        const class_alias *al = c2b_alias_find(c2b_fnv1a(cbuf));
                        if (al) {
                            const char *d = al->dt_name;
                            dtn = 0;
                            while (d[dtn] && dtn < sizeof(dtbuf) - 1) {
                                dtbuf[dtn] = d[dtn]; dtn++;
                            }
                            dtbuf[dtn] = 0;
                        } else {
                            dtn = c2b_rule_dt(cbuf, dtbuf);
                        }
                    }

                    {
                        const dt_entry *dte = c2b_dt_find(c2b_fnv1a(dtbuf));
                        if (!dte) g_dt_misses++;
                        if (class_id < C2B_CLASS_MAP_MAX)
                            g_class_dt_map[class_id] = dte ? (u16)(dte - g_dt_index) : 0xFFFFu;
                    }

                    /* G-3b: привязка класса к сериализатору CS2 (для PacketEntities) */
                    {
                        i32 fs = c2b_fsv_find_ser(cbuf);
                        if (class_id < C2B_CLASS_MAP_MAX)
                            g_class_ser_map[class_id] = (fs >= 0) ? (u16)fs : (u16)C2B_FSV_SER_NUL;
                        /* G-3d: покрытие словаря S2->S1 (лог знакона) */
                        if (g_fsv_ser_n) c2b_fmap_class(cbuf, dtbuf, fs);
                        else g_fmap_nofsv++;
                    }

                    if (class_id < C2B_CLASS_MAP_MAX && emit_idx < 0xFFFFu) {
                        g_class_id_map[class_id] = (u16)emit_idx;
                        if (class_id + 1 > g_class_id_map_n)
                            g_class_id_map_n = class_id + 1;
                    }

                    /* inner S1 class_t: f1=class_id, f2=dt_name, f3=class_name */
                    u8 inner[220];
                    u32 in = 0;
                    inner[in++] = 0x08;
                    in += c2b_write_varint(inner + in, emit_idx);
                    inner[in++] = 0x12;
                    in += c2b_write_varint(inner + in, dtn);
                    for (i = 0; i < dtn; i++) inner[in++] = (u8)dtbuf[i];
                    inner[in++] = 0x1A;
                    in += c2b_write_varint(inner + in, cn_n);
                    for (i = 0; i < cn_n; i++) inner[in++] = (u8)cbuf[i];

                    if (tn + 1 + 5 + in > sizeof(tmp)) return -2;
                    tmp[tn++] = 0x12;
                    tn += c2b_write_varint(tmp + tn, in);
                    for (i = 0; i < in; i++) tmp[tn++] = inner[i];
                    emit_idx++;
                }
            }
            ip += ln;
        } else {
            return -1;                      /* фиксированные поля не ждём */
        }
    }

    if (op + DT_BLOB_SIZE + 10 + tn > cap) return -2;
    c2b_fwd_copy(out + op, g_dt_blob, DT_BLOB_SIZE);
    op += DT_BLOB_SIZE;
    op += c2b_write_varint(out + op, 10);   /* S1 svc_ClassInfo */
    op += c2b_write_varint(out + op, tn);
    c2b_fwd_copy(out + op, tmp, tn);
    op += tn;
    g_blob_emits++;
    g_cls_emitted = emit_idx;               /* ширина class_id S1 (G-4) */
    *out_op = op;
    return 0;
}

/* ---------- G-5: VoiceData downlink-транскод ----------
 * CS2 svc_VoiceData(47) -> S1 svc_VoiceData(15).
 *   CS2 CSVCMsg_VoiceData {1 audio=CMsgVoiceAudio{1 format, 2 voice_data,
 *     3 sequence_bytes, 4 section_number, 5 sample_rate, 6
 *     uncompressed_sample_offset, 7 num_packets, 8 packet_offsets packed,
 *     9 voice_level}, 2 client_deprecated, 3 proximity, 4 xuid fx64,
 *     5 audible_mask, 6 tick, 7 passthrough, 8 entity, 9 caster}
 *   -> S1 CSVCMsg_VoiceData {1 client, 2 proximity, 3 xuid fx64,
 *     4 audible_mask, 5 voice_data, 6 caster, 7 format, 8 sequence_bytes,
 *     9 section_number, 10 uncompressed_sample_offset}.
 * Дроп: tick/passthrough/entity (в S1 нет), audio{sample_rate, num_packets,
 * packet_offsets packed, voice_level}. Enum VoiceDataFormat_t: 0/1 совпадают
 * (CS2 OPUS=2 у S1 нет — копируем as-is; S1-клиент трактует неизвестный
 * формат по-своему, фактический голос CS2 = OPUS). Отсутствие поля ->
 * не эмитим (дефолты: CS2 STEAM(0), S1 ENGINE(1) — клиент берёт свой).
 * Нет client_deprecated -> rc=-3 (S1 без источника голоса бесполезен).
 * Эмиссия: [15][len][payload] в out с *out_op. Буфер под локом R29. */
static u32 g_g5_msgs, g_g5_bytes, g_g5_drop;
static u8  g_g5_buf[64 * 1024];

static i32 c2b_g5_voice(const u8 *pl, u32 n, u8 *out, u32 op0, u32 cap, u32 *out_op)
{
    const u8 *aud = 0; u32 audn = 0;
    u32 client = 0, prox = 0, amask = 0, caster = 0;
    u8  has_client = 0, has_prox = 0, has_amask = 0, has_caster = 0;
    u8  xuid[8], has_xuid = 0;
    u32 fmt = 0, seq = 0, sect = 0, uso = 0;
    u8  has_fmt = 0, has_seq = 0, has_sect = 0, has_uso = 0;
    const u8 *vdata = 0; u32 vlen = 0;
    u32 ip = 0, op = 0, olen = 0;

    while (ip < n) {                                 /* верхний уровень */
        u32 tag, c = c2b_read_varint(pl + ip, n - ip, &tag); if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7u;
        ip += c;
        if (wt == 2) {
            u32 ln; c = c2b_read_varint(pl + ip, n - ip, &ln); if (!c) return -1;
            ip += c;
            if (ln > n - ip) return -1;
            if (f == 1) { aud = pl + ip; audn = ln; }    /* audio submsg */
            ip += ln;
        } else if (wt == 1) {
            if (n - ip < 8) return -1;
            if (f == 4) { for (u32 k = 0; k < 8; k++) xuid[k] = pl[ip + k]; has_xuid = 1; }
            ip += 8;
        } else if (wt == 0) {
            u32 v; c = c2b_read_varint(pl + ip, n - ip, &v); if (!c) return -1;
            ip += c;
            if (f == 2)      { client = v; has_client = 1; }
            else if (f == 3) { prox = v; has_prox = 1; }
            else if (f == 5) { amask = v; has_amask = 1; }
            else if (f == 9) { caster = v; has_caster = 1; }
            /* 6 tick, 7 passthrough, 8 entity — дроп (в S1 нет) */
        } else if (wt == 5) {
            if (n - ip < 4) return -1;
            ip += 4;                                     /* unknown fixed32 */
        } else return -1;
    }
    if (aud) {                                       /* CMsgVoiceAudio */
        u32 ap = 0;
        while (ap < audn) {
            u32 tag, c = c2b_read_varint(aud + ap, audn - ap, &tag); if (!c) return -1;
            u32 f = tag >> 3, wt = tag & 7u;
            ap += c;
            if (wt == 2) {
                u32 ln; c = c2b_read_varint(aud + ap, audn - ap, &ln); if (!c) return -1;
                ap += c;
                if (ln > audn - ap) return -1;
                if (f == 2) { vdata = aud + ap; vlen = ln; }  /* voice_data */
                ap += ln;                                /* 8 packet_offsets — скип */
            } else if (wt == 0) {
                u32 v; c = c2b_read_varint(aud + ap, audn - ap, &v); if (!c) return -1;
                ap += c;
                if (f == 1)      { fmt = v; has_fmt = 1; }
                else if (f == 3) { seq = v; has_seq = 1; }
                else if (f == 4) { sect = v; has_sect = 1; }
                else if (f == 6) { uso = v; has_uso = 1; }
                /* 5 sample_rate, 7 num_packets — дроп */
            } else if (wt == 5) {
                if (audn - ap < 4) return -1;
                ap += 4;
            } else return -1;
        }
    }
    if (!vdata || !has_client) { g_g5_drop++; return -3; }

    /* эмиссия S1 payload в g_g5_buf (теги по возрастанию) */
    olen = 0;
    if (olen + 6 > sizeof(g_g5_buf)) return -2;
    g_g5_buf[olen++] = 0x08;                         /* f1 client */
    olen += c2b_write_varint(g_g5_buf + olen, client);
    if (has_prox) {
        if (olen + 6 > sizeof(g_g5_buf)) return -2;
        g_g5_buf[olen++] = 0x10;                     /* f2 proximity */
        olen += c2b_write_varint(g_g5_buf + olen, prox ? 1u : 0u);
    }
    if (has_xuid) {
        if (olen + 9 > sizeof(g_g5_buf)) return -2;
        g_g5_buf[olen++] = 0x19;                     /* f3 xuid fixed64 */
        for (u32 k = 0; k < 8; k++) g_g5_buf[olen + k] = xuid[k];
        olen += 8;
    }
    if (has_amask) {
        if (olen + 6 > sizeof(g_g5_buf)) return -2;
        g_g5_buf[olen++] = 0x20;                     /* f4 audible_mask */
        olen += c2b_write_varint(g_g5_buf + olen, amask);
    }
    if (olen + 6 + vlen > sizeof(g_g5_buf)) return -2;
    g_g5_buf[olen++] = 0x2A;                         /* f5 voice_data */
    olen += c2b_write_varint(g_g5_buf + olen, vlen);
    for (u32 k = 0; k < vlen; k++) g_g5_buf[olen + k] = vdata[k];
    olen += vlen;
    if (has_caster) {
        if (olen + 6 > sizeof(g_g5_buf)) return -2;
        g_g5_buf[olen++] = 0x30;                     /* f6 caster */
        olen += c2b_write_varint(g_g5_buf + olen, caster ? 1u : 0u);
    }
    if (has_fmt) {
        if (olen + 6 > sizeof(g_g5_buf)) return -2;
        g_g5_buf[olen++] = 0x38;                     /* f7 format */
        olen += c2b_write_varint(g_g5_buf + olen, fmt);
    }
    if (has_seq) {
        if (olen + 6 > sizeof(g_g5_buf)) return -2;
        g_g5_buf[olen++] = 0x40;                     /* f8 sequence_bytes */
        olen += c2b_write_varint(g_g5_buf + olen, seq);
    }
    if (has_sect) {
        if (olen + 6 > sizeof(g_g5_buf)) return -2;
        g_g5_buf[olen++] = 0x48;                     /* f9 section_number */
        olen += c2b_write_varint(g_g5_buf + olen, sect);
    }
    if (has_uso) {
        if (olen + 6 > sizeof(g_g5_buf)) return -2;
        g_g5_buf[olen++] = 0x50;                     /* f10 uncompressed_sample_offset */
        olen += c2b_write_varint(g_g5_buf + olen, uso);
    }

    /* конверт [15][len][payload] в out */
    op = op0;
    if (op0 + 2 + 5 + olen > cap) return -2;
    op += c2b_write_varint(out + op, 15);            /* S1 svc_VoiceData */
    op += c2b_write_varint(out + op, olen);
    for (u32 k = 0; k < olen; k++) out[op + k] = g_g5_buf[k];
    op += olen;
    g_g5_msgs++; g_g5_bytes += olen;
    *out_op = op;
    return 0;
}

#define C2B_SND_OSCALE    8.0f
#define C2B_SND_NUM_STUB  0u
#define C2B_SND_MAP_MAX   512

/* --- G-6 (t36/P208) звуковой стейт: декларации ДО R-A-reset (он их сбрасывает) --- */
typedef struct { u32 hash; u16 num; u8 used; } c2b_snd_ent_t;
static c2b_snd_ent_t g_snd_map[C2B_SND_MAP_MAX];   /* TODO(v2): заполнение, спека §3 */
static u32 g_snd_map_n;
static u32 g_synth_sounds, g_synth_snd_drop;       /* счётчики G-6 (НЕ rt.ge) */
static struct { u8 seen, has_org, has_guid, has_seed;
                i32 ox, oy, oz; u32 guid, seed; } g_g6_ge;

/* ===== R-A (t35): сброс tbl/cls-стейта при ПОВТОРНОМ соединении =====
 * Триггер — S2 net#1 (net_Disconnect_Legacy) с последующим ServerInfo(40):
 * разрыв сессии мост видит по net#1, новый signon — по 40 (там же max_classes).
 * Первый 40 холодного старта: стейт статически пуст — только взвод флага.
 * (Спека ra_reset предлагала якорь 51; proto-сверка t35: 51 = ClearAllStringTables
 * и может прийти ПОСЛЕ начала FSV-потока 41 — сброс на разрыв+40 точнее и без гонок.) */
static u32 g_sess_seen;                    /* 0 = signon ещё не приходил (холодный старт) */
static u32 g_sess_disc;                    /* 1 = был net#1 (сессия разорвана) */
static u32 g_sess_resets;                  /* диагностика: число сбросов */

static void c2b_dn_sess_reset(void)
{
    /* G-3b: FSV-стейт */
    g_fsv_arena_n = 1;                                   /* 0 = NULL-маркер */
    memset(g_fsv_sym_hash, 0, sizeof(g_fsv_sym_hash));
    g_fsv_msgsym_n = 0;
    g_fsv_field_n = 0;
    g_fsv_ser_n = 0;
    g_fsv_idx_n = 0;
    memset(&g_fsv_coord, 0, sizeof(g_fsv_coord));
    g_fsv_poly_next = 0;                 /* G-4c: poly-слоты заново (cap 16) */
    /* g_fsv_gen НЕ трогаем: c2b_fsv_parse сразу после сброса инкрементирует
     * — ленивая инвалидация g_g4_cls срабатывает сама. */

    /* G-3a: карта классов s2 -> s1 */
    memset(g_class_id_map, 0, sizeof(g_class_id_map));
    memset(g_class_ser_map, 0, sizeof(g_class_ser_map));
    memset(g_class_dt_map, 0, sizeof(g_class_dt_map));
    memset(g_class_seen, 0, sizeof(g_class_seen));
    g_class_id_map_n = 0;
    g_cls_emitted = 0;                   /* иначе G-4 шлюз открыт со старой шириной */

    /* G-4: контексты классов + per-entity стейт + scratch */
    memset(g_g4_cls, 0, sizeof(g_g4_cls));
    memset(g_g4_ent, 0, sizeof(g_g4_ent));
    g_g4_stg_n = 0;
    g_g4_arr_n = 0;

    /* G-4b/G-4d: instancebaseline */
    g_g4b_tbl_seen = 0;
    g_g4b_tbl_id = C2B_G4B_NO_TBL;       /* 45-апдейты до нового Create -> generic */
    g_g4b_t_fixed = 0; g_g4b_t_udsb = 0;
    g_g4b_t_flags = 0; g_g4b_t_vbc = 0;
    for (u32 ci = 0; ci < C2B_G4B_CLS_AT; ci++) g_g4b_cls_at[ci] = C2B_G4B_NOCLS;

    /* G-6 (t36/audit04): звуковой стейт под сброс — карта мертва (stub),
     * но якорь обязателен к v2-learner; seen гасим на случай pending-синтеза. */
    g_snd_map_n = 0;
    g_g6_ge.seen = 0;

    /* НЕ сбрасывается (осознанно): g_fsv_max_classes — перезапишется этим же 40;
     * DT-словарь/алиасы — компайл-тайм; scratch-буферы; cumулятивная статистика. */
    g_sess_resets++;
#ifndef C2B_SELFTEST
    C2B_LOGS("[c2b] RA sess-reset #"); C2B_LOGN(g_sess_resets);
    C2B_LOGS("\n");
#endif
}

/* ---------- фаза G-6 (t36/P208): SosStartSoundEvent -> синтетический S1 svc_Sounds ----------
 * Транспорт-1 (основной): CS2 wire 208 CMsgSosStartSoundEvent
 *   {1 guid int32, 2 hash fixed32, 3 source_entity_index int32 [def -1],
 *    4 seed int32, 5 packed_params bytes, 6 start_time float} — FDP==proto.
 *   Оригиная в 208 нет -> позиция: (а) кэш G-4 по source_entity_index
 *   (cell*512-16384+coff), (б) без origin (S1 сам возьмёт origin энтити по п7).
 *   packed_params (CParmVec) — v2/TODO. start_time — дроп (в S1 нет).
 * Транспорт-2: 207 GameEvent "sos_start_soundevent" + ключи origin_x/y/z
 *   (val_float wt5 или val_long wt0/wt2-LE), guid/seed (val_long) — имена ключей
 *   TODO сверить живым прогоном; детектор не ломает 207->25 renum.
 * S1: svc_Sounds=17, sounddata_t п1..3 origin SINT32 (ZIGZAG), п7 entity_index,
 *   п11 sound_num, п14 random_seed; unknown п18/п19 S1 пропускает (Task 26) —
 *   эмитим guid в п18. Единицы origin: int(units*8) — C2B_SND_OSCALE, TODO
 *   калибровка живым прогоном (в proto/FDP комментариев нет).
 */
static u16 c2b_snd_num_lookup(u32 hash)
{
    for (u32 i = 0; i < g_snd_map_n && i < C2B_SND_MAP_MAX; i++)
        if (g_snd_map[i].used && g_snd_map[i].hash == hash) return g_snd_map[i].num;
    return (u16)C2B_SND_NUM_STUB;                  /* stub: всегда miss -> 0 */
}

/* origin энтити из кэша G-4 — только при полной тройке cell+coff (R42-гейт) */
static i32 c2b_g4_ent_origin(i32 idx, float o[3])
{
    if (idx < 0 || idx >= C2B_G4_ENT_MAX) return 0;
    const c2b_g4_ent_t *E = &g_g4_ent[idx];
    if (E->cellhave != 0x07u || E->offhave != 0x07u) return 0;
    for (u32 k = 0; k < 3; k++)
        o[k] = (float)E->cell[k] * 512.0f - 16384.0f + E->coff[k];
    return 1;
}

/* эмиссия [17][len]{ п2 sounds{...} }: 1 звук, теги по возрастанию.
 * Ожидающие: has_* гейты полей; origin уже в wire-единицах (zigzag внутри). */
static i32 c2b_g6_emit(u32 guid, u8 has_guid, i32 ox, i32 oy, i32 oz, u8 has_org,
                       i32 ent, u8 has_ent, u32 seed, u8 has_seed, u16 snum,
                       u8 *out, u32 op0, u32 cap, u32 *out_op)
{
    u8  b[48]; u32 n = 0, op = op0, z;
    if (has_org) {
        z = ((u32)ox << 1) ^ (u32)(ox >> 31);      /* sint32 zigzag */
        b[n++] = 0x08; n += c2b_write_varint(b + n, z);        /* п1 origin_x */
        z = ((u32)oy << 1) ^ (u32)(oy >> 31);
        b[n++] = 0x10; n += c2b_write_varint(b + n, z);        /* п2 origin_y */
        z = ((u32)oz << 1) ^ (u32)(oz >> 31);
        b[n++] = 0x18; n += c2b_write_varint(b + n, z);        /* п3 origin_z */
    }
    if (has_ent) { b[n++] = 0x38; n += c2b_write_varint(b + n, (u32)ent); } /* п7 */
    b[n++] = 0x58;                                 /* п11 sound_num: карта/stub */
    n += c2b_write_varint(b + n, snum);
    if (has_seed) { b[n++] = 0x70; n += c2b_write_varint(b + n, seed); }    /* п14 */
    if (has_guid) { b[n++] = 0x90; b[n++] = 0x01;                          /* п18 */
                    n += c2b_write_varint(b + n, guid); }
    {
        u8 vb[3]; u32 vn = c2b_write_varint(vb, n);
        /* t36/audit01: факт-запись = varint(17)=1 + varint(len)=1 (len<=47<128) +
         * 0x12=1 + vn + n = 3+vn+n (запас не завышаем — ложные -2 в узком коридоре) */
        if (op0 + 3 + vn + n > cap) { g_synth_snd_drop++; return -2; }
        op += c2b_write_varint(out + op, 17);      /* S1 svc_Sounds */
        op += c2b_write_varint(out + op, 1 + vn + n);
        out[op++] = 0x12;                          /* п2 sounds */
        for (u32 k = 0; k < vn; k++) out[op++] = vb[k];
        for (u32 k = 0; k < n;  k++) out[op++] = b[k];
    }
    g_synth_sounds++;
    *out_op = op;
    return 0;
}

/* транспорт-1: 208 CMsgSosStartSoundEvent -> svc_Sounds(17). rc: 0/-1 парс/-2 кап */
static i32 c2b_g6_sos208(const u8 *pl, u32 n, u8 *out, u32 op0, u32 cap, u32 *out_op)
{
    u32 guid = 0, hash = 0, seed = 0; u8 has_guid = 0, has_hash = 0, has_seed = 0;
    i32  ent = 0; u8 has_ent = 0;
    u32 ip = 0;
    while (ip < n) {
        u32 tag, c = c2b_read_varint(pl + ip, n - ip, &tag); if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7u;
        ip += c;
        if (wt == 0) {
            u32 v; c = c2b_read_varint(pl + ip, n - ip, &v); if (!c) return -1;
            ip += c;
            if      (f == 1) { guid = v; has_guid = 1; }
            else if (f == 3) { ent = (i32)v; has_ent = ((i32)v >= 0); } /* def -1 */
            else if (f == 4) { seed = v; has_seed = 1; }
        } else if (wt == 5) {                      /* fixed32: п2 hash; п6 f32 дроп */
            if (n - ip < 4) return -1;
            if (f == 2) { hash = (u32)pl[ip] | ((u32)pl[ip+1] << 8) |
                                ((u32)pl[ip+2] << 16) | ((u32)pl[ip+3] << 24);
                          has_hash = 1; }
            ip += 4;
        } else if (wt == 2) {                      /* п5 packed_params — v2 */
            u32 ln; c = c2b_read_varint(pl + ip, n - ip, &ln);
            if (!c || c + ln > n - ip) return -1;  /* t36/audit02: +c в гейте (OOB-read) */
            ip += c + ln;
        } else if (wt == 1) { if (n - ip < 8) return -1; ip += 8; }
        else return -1;
    }
    if (!has_hash && !has_guid) return -1;         /* t36/audit01: пустой 208 — фантомный звук */
    if (has_ent) {                                 /* позиция из кэша G-4 */
        float o[3];
        if (c2b_g4_ent_origin(ent, o)) {
            i32 ov[3];
            ov[0] = (i32)(o[0] * C2B_SND_OSCALE);
            ov[1] = (i32)(o[1] * C2B_SND_OSCALE);
            ov[2] = (i32)(o[2] * C2B_SND_OSCALE);
            return c2b_g6_emit(guid, has_guid, ov[0], ov[1], ov[2], 1, ent, 1,
                               seed, has_seed, c2b_snd_num_lookup(hash),
                               out, op0, cap, out_op);
        }
    }
    return c2b_g6_emit(guid, has_guid, 0, 0, 0, 0, ent, has_ent, seed, has_seed,
                       c2b_snd_num_lookup(hash), out, op0, cap, out_op);
}

/* транспорт-2: 207 GameEvent "sos_start_soundevent" — детектор (не транскод).
 * Результат в g_g6_ge; синтез выполняет вызывающий ПОСЛЕ renum-эмиссии 207->25.
 * t36-ПРАВКА спеки: key_t НЕ имеет поля name (FDP cs2/gameevents.json: 1 type,
 * 2 val_string, 3 val_float, 4 val_long, ...) — ключи анонимны, семантика
 * ПОЗИЦИОННАЯ: val_float №1..3 -> origin_x/y/z, val_long №1..2 -> guid/seed.
 * TODO живая сверка порядка дескриптора (FINI snd{n=} как индикатор). */
static void c2b_g6_ge_peek(const u8 *pl, u32 n)
{
    const u8 *name = 0; u32 name_n = 0, ip = 0;
    g_g6_ge.seen = 0;
    while (ip < n) {                               /* проход 1: event_name */
        u32 tag, c = c2b_read_varint(pl + ip, n - ip, &tag); if (!c) return;
        u32 f = tag >> 3, wt = tag & 7u;
        ip += c;
        if (wt == 2) {
            u32 ln; c = c2b_read_varint(pl + ip, n - ip, &ln);
            if (!c || c + ln > n - ip) return;     /* t36/audit02: +c в гейте */
            ip += c;
            if (f == 1) { name = pl + ip; name_n = ln; }
            ip += ln;
        } else if (wt == 0) {
            u32 v; c = c2b_read_varint(pl + ip, n - ip, &v); if (!c) return;
            ip += c;
        } else if (wt == 5) { if (n - ip < 4) return; ip += 4; }
        else if (wt == 1) { if (n - ip < 8) return; ip += 8; }
        else return;
    }
    if (!name || name_n != 20) return;             /* len("sos_start_soundevent")=20 */
    {
        static const char sos[20] = "sos_start_soundevent";
        for (u32 k = 0; k < 20; k++) if (name[k] != (u8)sos[k]) return;
    }
    g_g6_ge.seen = 1;
    g_g6_ge.has_org = g_g6_ge.has_guid = g_g6_ge.has_seed = 0;
    g_g6_ge.ox = g_g6_ge.oy = g_g6_ge.oz = 0;
    g_g6_ge.guid = g_g6_ge.seed = 0;
    u32 nfl = 0, nlng = 0;                         /* позиционные счётчики ключей */
    ip = 0;                                        /* проход 2: key_t */
    while (ip < n) {
        u32 tag, ln, c = c2b_read_varint(pl + ip, n - ip, &tag); if (!c) return;
        u32 f = tag >> 3, wt = tag & 7u;
        ip += c;
        if (f == 3 && wt == 2) {                   /* key_t{1 type,2 str,3 f32,4 i32} */
            c = c2b_read_varint(pl + ip, n - ip, &ln); if (!c || c + ln > n - ip) return;
            ip += c;
            {
                const u8 *kp = pl + ip; u32 kn = ln, kp2 = 0;
                float kvf = 0.0f; i32 kvl = 0; u8 has_f = 0, has_l = 0;
                while (kp2 < kn) {
                    u32 ktag, kc = c2b_read_varint(kp + kp2, kn - kp2, &ktag);
                    if (!kc) return;
                    u32 kf = ktag >> 3, kwt = ktag & 7u;
                    kp2 += kc;
                    if (kwt == 0) {
                        u32 v; kc = c2b_read_varint(kp + kp2, kn - kp2, &v);
                        if (!kc) return; kp2 += kc;
                        if (kf == 1) { /* ktype: не нужен */ }
                        else if (kf == 4) { kvl = (i32)v; has_l = 1; } /* val_long varint (proto int32) */
                    } else if (kwt == 5) {
                        if (kn - kp2 < 4) return;
                        if (kf == 3) {
                            u32 bits = (u32)kp[kp2] | ((u32)kp[kp2+1] << 8) |
                                       ((u32)kp[kp2+2] << 16) | ((u32)kp[kp2+3] << 24);
                            kvf = c2b_f32_from_bits(bits); has_f = 1;
                        }
                        kp2 += 4;
                    } else if (kwt == 2) {
                        u32 l2; kc = c2b_read_varint(kp + kp2, kn - kp2, &l2);
                        if (!kc || kc + l2 > kn - kp2) return; kp2 += kc;  /* t36/audit02: +kc */
                        if (kf == 4 && l2 == 4) {   /* val_long int32 LE (нестанд., защитно) */
                            kvl = (i32)((u32)kp[kp2] | ((u32)kp[kp2+1] << 8) |
                                        ((u32)kp[kp2+2] << 16) | ((u32)kp[kp2+3] << 24));
                            has_l = 1;
                        }
                        kp2 += l2;
                    } else if (kwt == 1) { if (kn - kp2 < 8) return; kp2 += 8; }
                    else return;
                }
                if (has_f) {                   /* позиция: float №1..3 -> origin_x/y/z */
                    if (!(kvf > -2.0e9f && kvf < 2.0e9f)) kvf = 0.0f; /* t36/audit06: NaN/inf -> 0 (UB-cast) */
                    i32 ov = (i32)(kvf * C2B_SND_OSCALE);
                    if      (nfl == 0) { g_g6_ge.ox = ov; g_g6_ge.has_org = 1; }
                    else if (nfl == 1) { g_g6_ge.oy = ov; g_g6_ge.has_org = 1; }
                    else if (nfl == 2) { g_g6_ge.oz = ov; g_g6_ge.has_org = 1; }
                    nfl++;
                } else if (has_l) {            /* позиция: long №1..2 -> guid/seed */
                    if      (nlng == 0) { g_g6_ge.guid = (u32)kvl; g_g6_ge.has_guid = 1; }
                    else if (nlng == 1) { g_g6_ge.seed = (u32)kvl; g_g6_ge.has_seed = 1; }
                    nlng++;
                }
            }
        } else if (wt == 2) {
            u32 l3; c = c2b_read_varint(pl + ip, n - ip, &l3);
            if (!c || c + l3 > n - ip) return;     /* t36/audit02: +c в гейте */
            ip += c + l3;
        } else if (wt == 0) {
            u32 v3; c = c2b_read_varint(pl + ip, n - ip, &v3); if (!c) return;
            ip += c;
        } else if (wt == 5) { if (n - ip < 4) return; ip += 4; }
        else if (wt == 1) { if (n - ip < 8) return; ip += 8; }
        else return;
    }
}

/* ---------- транслятор потока (v0: ренумерация + дроп, payload as-is) ---------- */
i32 c2b_translate(const u8 *in, u32 in_len, u8 *out, u32 cap, u32 *out_len, c2b_stats_t *st)
{
    u32 ip = 0, op = 0;
    if (st) { st->msgs_in = 0; st->msgs_out = 0; st->dropped = 0;
              st->renumbered = 0; st->unknown = 0; st->net_pass = 0; st->um = 0; }
    while (ip < in_len) {
        u32 type, len, c, t;
        i32 mapped;
        c = c2b_read_varint(in + ip, in_len - ip, &type); if (!c) goto trunc;
        ip += c;
        c = c2b_read_varint(in + ip, in_len - ip, &len);  if (!c) goto trunc;
        ip += c;
        if (len > in_len - ip) goto trunc;
        if (st) st->msgs_in++;
        if (type == 45) g_fini2.rt_str++;                 /* FINI2 rt{str=} */
        else if (type == 205 || type == 207) g_fini2.rt_ge++;  /* FINI2 rt{ge=} */

        /* D1 (t35): net_File есть только в S1 (net_File=2, CNETMsg_File); в CS2
         * NET_Messages id 2 — дыра, сообщения нет (proto+binary FDP). Раньше
         * identity-ветка пропускала S2#2 в S1 как фантомный запрос файла.
         * НЕ добавлять 2 в g_s2_net_drop: identity-ветка срабатывает раньше. */
        if (type == 2) {
            g_g4_nf++;                               /* телеметрия */
            if (g_g4_nf <= 4 || g_vlevel >= 2) {
                C2B_LOGS("[c2b] S2 net#2 dropped (net_File не существует в CS2)\n");
            }
            if (st) st->dropped++;
            ip += len; continue;
        }
        const unsigned char *fmap = 0;
        if (type <= NET_IDENTITY_MAX) {
            mapped = (i32)type;                        /* NET 0..7: identity */
            if (type == 1) g_sess_disc = 1;            /* R-A: net_Disconnect_Legacy */
            if (st) st->net_pass++;
        } else if (c2b_in_drop(g_s2_net_drop, NET_DROP_COUNT, type)) {
            if (st) st->dropped++;
            ip += len; continue;                       /* SpawnGroup*, DebugOverlay */
        } else {
            if (type == 41 || type == 51) {  /* фаза G-3b: FlattenedSerializer (t35-сверка proto: FSV=41;
                                              * 51 = ClearAllStringTables — пустой парс безвреден;
                                              * старая разведка g3_design называла FSV=51 — хук на ОБА) */
                c2b_fsv_parse(in + ip, len);
                if (st) st->dropped++;
                ip += len; continue;
            }
            if (type == 42) {  /* фаза G-3a: S2 ClassInfo -> блоб + синтез */
                u32 nop = op;
                i32 rc = c2b_synth_classinfo(in + ip, len, out, op, cap, &nop);
                if (rc == -1) goto trunc;
                if (rc == -2) goto oom;
                op = nop;
                if (st) { st->msgs_out++; st->renumbered++; }
                ip += len; continue;
            }
            if (type == 55) {  /* фаза G-4: PacketEntities — S2 битстрим -> S1 */
                u32 nop = op + 5;                    /* резерв под конверт [26][len] */
                i32 rc = c2b_g4_packetentities(in + ip, len, out, nop, cap, &nop);
                if (rc == 0) {
                    u32 plen = nop - (op + 5);
                    u32 t = c2b_write_varint(out + op, 26);
                    u32 l = c2b_write_varint(out + op + t, plen);
                    u32 dst = op + t + l;
                    if (dst != op + 5) c2b_fwd_copy(out + dst, out + op + 5, plen);
                    op = dst + plen;
                    if (st) { st->msgs_out++; st->renumbered++; }
                    ip += len; continue;
                }
                if (rc == -2) goto oom;
                if (rc == -3) { if (st) st->dropped++; g_g4_dfm_pend = 1; ip += len; continue; }
                /* rc == -1: нет state — прямой проход (XF_DIRECT) */
            }
            if (type == 44) {  /* фаза G-4b: CreateStringTable — instanceBaseline транскод */
                u32 nop = op;
                i32 rc = c2b_g4b_stringtable(in + ip, len, out, op, cap, &nop);
                if (rc == 0) {
                    op = nop;
                    if (st) { st->msgs_out++; st->renumbered++; }
                    ip += len; continue;
                }
                if (rc == -2) goto oom;
                if (rc == -3) { if (st) st->dropped++; ip += len; continue; }
                /* rc == -1: не instancebaseline — generic XF_RENUM путь ниже */
            }
            if (type == 45 && c2b_g4b_upd_is_baseline(in + ip, len)) {
                /* фаза G-4d: апдейт instancebaseline -> транскод в S1(13) */
                u32 nop = op;
                i32 rc = c2b_g4d_updatetable(in + ip, len, out, op, cap, &nop);
                if (rc == 0) {
                    op = nop;
                    if (st) { st->msgs_out++; st->renumbered++; }
                    ip += len; continue;
                }
                if (rc == -2) goto oom;
                /* -1/-3: парс не удался/транскод пуст — дроп (семантика v0) */
                g_g4b_upd_drop++;
                if (st) st->dropped++;
                ip += len; continue;
            }
            if (type == 47) {  /* фаза G-5: VoiceData — CS2 audio-submsg -> S1 плоские поля */
                u32 nop = op;
                i32 rc = c2b_g5_voice(in + ip, len, out, op, cap, &nop);
                if (rc == 0) {
                    op = nop;
                    if (st) { st->msgs_out++; st->renumbered++; }
                    ip += len; continue;
                }
                if (rc == -2) goto oom;
                /* -1/-3: битый парс / нет client или audio — дроп (семантика v0) */
                if (st) st->dropped++;
                ip += len; continue;
            }
            if (type == 208) {  /* фаза G-6 (t36/P208): SosStartSoundEvent -> svc_Sounds(17) */
                u32 nop = op;
                i32 rc = c2b_g6_sos208(in + ip, len, out, op, cap, &nop);
                if (rc == 0) {
                    op = nop;
                    if (st) { st->msgs_out++; st->renumbered++; }
                    ip += len; continue;
                }
                if (rc == -2) goto oom;
                if (st) st->dropped++;               /* -1: битый payload (v0) */
                ip += len; continue;
            }
            if (type == 207) c2b_g6_ge_peek(in + ip, len);   /* G-6: детектор sos */
            const c2b_msg_map_t *e = c2b_svc_entry(type);
            if (!e) {
                if (c2b_is_um_zone(type)) {
                    /* фаза G-2: юзермесс-зона — мост в svc_UserMessage(23) */
                    const c2b_um_t *u = c2b_um_entry(type);
                    if (!u) {                        /* известная зона, моста нет */
                        if (st) st->dropped++;
                        ip += len; continue;
                    }
                    {
                        u32 nop = op;
                        i32 rc = c2b_um_wrap(u, in + ip, len, out, op, cap, &nop);
                        if (rc == -1) goto trunc;
                        if (rc == -2) goto oom;
                        op = nop;
                    }
                    if (st) { st->msgs_out++; st->um++; st->renumbered++; }
                    ip += len; continue;
                }
                if (c2b_in_drop(g_s2_svc_drop, SVC_DROP_COUNT, type)) {
                    if (st) st->dropped++;             /* FlattenSerializer и ко */
                } else {
                    if (st) st->unknown++;
                }
                ip += len; continue;
            }
            if (e->xf == XF_DROP) {                    /* фаза F: VoiceData и ко */
                if (st) st->dropped++;
                ip += len; continue;
            }
            mapped = (i32)e->s1;
            u32 g_si_est = 0;
            if (type == 40) {                   /* R-A сброс + R37: si-state + синтез-хвост */
                if (g_sess_seen && g_sess_disc) {
                    c2b_dn_sess_reset();
                    g_sess_disc = 0;
                }
                g_sess_seen = 1;
                c2b_si_parse(in + ip, len);
                g_si_est = g_si_est;
            }
        }
        if (type < RENUM_LOOKUP_COUNT && g_renum_lookup[type])
            fmap = g_renum_lookup[type]->map;

        /* payload: renum (таги) или as-is; заголовок занимает <= 2+5 байт,
           под него резервируем 12 байт, renum пишем со сдвигом, потом сдвигаем влево */
        u32 op_hdr = op, npl = len, sk = 0;
        u32 si_tail = (type == 40) ? g_si_est : 0;     /* R37: хвост ТОЛЬКО ServerInfo */
        if (op_hdr + 12 + len + si_tail > cap) goto oom;    /* + хвост R37 */
        if (fmap) {
            i32 rc = c2b_renum_payload(in + ip, len, fmap, out + op_hdr + 12,
                                       cap - op_hdr - 12, &sk);
            if (rc < 0) goto trunc;                    /* кривой payload — обрыв потока */
            npl = (u32)rc + si_tail;                   /* len декларируем с хвостом */
        }
        t  = c2b_write_varint(out + op_hdr, (u32)mapped);
        op = op_hdr + t + c2b_write_varint(out + op_hdr + t, npl);
        if (fmap) {
            c2b_fwd_copy(out + op, out + op_hdr + 12, npl - si_tail);
            op += npl - si_tail;
            if (si_tail) {                               /* R37: append (последний выигрывает) */
                u8 *o2 = out + op;
                if (op + si_tail > cap) goto oom;
                *o2++ = 0x08; o2 += c2b_write_varint(o2, g_si_protocol);
                *o2++ = 0x58; o2 += c2b_write_varint(o2, g_si_v_mcl);
                *o2++ = 0x60; o2 += c2b_write_varint(o2, g_si_v_mcs);
                if (!g_si_has_f14 || g_si_f14_len == 0) {
                    *o2++=0x7A; *o2++=4; *o2++='c'; *o2++='s'; *o2++='g'; *o2++='o';
                }
                if (g_si_no_slot) {
                    *o2++ = 0x68;
                    for (int k2 = 0; k2 < 9; k2++) *o2++ = 0xFF;
                    *o2++ = 0x01;
                }
                op = (u32)(o2 - out);
            }
        } else {
            for (u32 k = 0; k < len; k++) out[op++] = in[ip + k];
        }
        if (st) { st->msgs_out++; if ((u32)mapped != type) st->renumbered++; }
        if (type == 207 && g_g6_ge.seen) {           /* фаза G-6: синтез после GE */
            u32 nop = op;
            i32 rc = c2b_g6_emit(g_g6_ge.guid, g_g6_ge.has_guid,
                                 g_g6_ge.ox, g_g6_ge.oy, g_g6_ge.oz, g_g6_ge.has_org,
                                 0, 0, g_g6_ge.seed, g_g6_ge.has_seed,
                                 (u16)C2B_SND_NUM_STUB, out, op, cap, &nop);
            if (rc == 0) { op = nop; if (st) st->msgs_out++; }
            else if (rc == -2) goto oom;
            g_g6_ge.seen = 0;
        }
        ip += len;
    }
    if (out_len) *out_len = op;
    return 0;
trunc:
    if (out_len) *out_len = op;
    return -1;
oom:
    if (out_len) *out_len = op;
    return -2;
}

/* ================================================================
 * фаза G-5: АПЛИНК (S1 клиент -> S2 сервер)
 * Wire-факты (собраны и перекрёстно проверены):
 *  - S1 аплинк-стрим внутри канала = [varint type][varint len][payload],
 *    зеркально downlink-парсеру (ProcessMessages). UDP-фрейминг не трогаем.
 *  - S1 CLC-номера 8..20 (s1_legacy/netmessages.proto == SteamDatabase/Protobufs
 *    csgo), CS2 CLC 20..36 (схема CS2 + pb.go). NET 0..7 identity в обеих.
 *  - S1 CLC_Move payload {1 backup varint, 2 new varint, 3 data bytes}:
 *    data = битстрим usercmd дельт SDK WriteUsercmd (hl2sdk csgo
 *    game/shared/usercmd.cpp, выверено):
 *      [1|U32 cmd][1|U32 tick][1|f32 va0][1|f32 va1][1|f32 va2]
 *      [1|f32 aim0][1|f32 aim1][1|f32 aim2][1|f32 fwd][1|f32 side][1|f32 up]
 *      [1|U32 buttons][1|U8 impulse]
 *      [1|U11 weaponselect [1|U6 weaponsubtype]]   (MAX_EDICT_BITS=11, const.h)
 *      [1|i16 mousedx][1|i16 mousedy]
 *    Дельта-семантика: бит=0 -> cmd/tick = from+1, остальные поля = from.
 *    random_seed на провод НЕ идёт (ReadUsercmd вычисляет MD5_PseudoRandom).
 *    HeadTracking в CS:GO выключен — бит нет. LSB-first биты (bf_read/bf_write).
 *  - CS2 CLC_Move {3 data bytes, 4 last_command_number} — backup/new из схемы
 *    УДАЛЕНЫ; сервер различает команды по legacy_command_number внутри.
 *    data = N x (varint len + CSGOUserCmdPB): эхо svc_UserCmds(76) несёт полный
 *    CSGOUserCmdPB в CMsgServerUserCmd.data (demoinfocs v6: proto.Unmarshal).
 *  - CSGOUserCmdPB{1 base=CBaseUserCmdPB{1 legacy_command_number, 2 client_tick,
 *    3 buttons_pb=CInButtonStatePB{1 buttonstate1 u64},
 *    4 viewangles=CMsgQAngle{1,2,3 fixed32}, 5 forwardmove, 6 leftmove,
 *    7 upmove fixed32, 8 impulse, 9 weaponselect, 11 mousedx, 12 mousedy}}.
 *    S1 sidemove -> CS2 leftmove БЕЗ инверсии (positive = right в обеих;
 *    флаг C2B_FLIPSIDE — резерв под живую калибровку).
 *    subtick_moves/input_history/move_crc в v1 ПУСТЫЕ (риски R21..R24).
 *  - S1 CLC_VoiceData {1 data, 2 xuid fx64, 3 format, 4 sequence_bytes,
 *    5 section_number, 6 uncompressed_sample_offset} ->
 *    CS2 CLC_VoiceData {1 audio=CMsgVoiceAudio{1 format, 2 voice_data,
 *    3 sequence_bytes, 4 section_number, 6 uncompressed_sample_offset},
 *    2 xuid fx64} — перегруппировка в под-сообщение.
 *  - S1 ClientInfo {1 send_table_crc fx64, 2 server_count, 3 is_hltv,
 *    4 is_replay, 5 friends_id, 6 friends_name, 7 custom_files fx64} ->
 *    CS2 {1,2,3,5,6} — 4/7 дроп (is_replay и custom_files в CS2 нет).
 */

typedef struct {
    u32 cmd_num, tick;
    float va[3], aim[3];
    float fwd, side, up;
    u32 buttons, impulse;
    u32 weap_sel, weap_sub;
    i32 mdx, mdy;
} c2b_s1cmd_t;

static u32 g_up_in, g_up_out, g_up_drop, g_up_unknown, g_up_err;
static u32 g_up_move, g_up_ucmds;              /* сообщ Move и команд всего */
static c2b_s1cmd_t g_up_base;                  /* baseline = последний известный cmd */
static u32 g_up_base_valid;

static void c2b_uplink_reset(void)             /* на новом signon */
{
    memset(&g_up_base, 0, sizeof(g_up_base));
    g_up_base_valid = 0;
}

/* --- S1 битстрим usercmd: чтение дельты (SDK ReadUsercmd, 1:1) --- */
static i32 c2b_up_read_cmd(c2b_br_t *r, const c2b_s1cmd_t *from, c2b_s1cmd_t *o)
{
    *o = *from;
    o->cmd_num = c2b_br_bit(r) ? c2b_br_bits(r, 32) : (from->cmd_num + 1);
    o->tick    = c2b_br_bit(r) ? c2b_br_bits(r, 32) : (from->tick + 1);
    if (g_fini2.up2_t0 == 0) g_fini2.up2_t0 = o->tick;   /* up2{t0}: первый tick сессии */
    for (int i = 0; i < 3; i++)
        if (c2b_br_bit(r)) o->va[i] = c2b_f32_from_bits(c2b_br_bits(r, 32));
    for (int i = 0; i < 3; i++)
        if (c2b_br_bit(r)) o->aim[i] = c2b_f32_from_bits(c2b_br_bits(r, 32));
    if (c2b_br_bit(r)) o->fwd  = c2b_f32_from_bits(c2b_br_bits(r, 32));
    if (c2b_br_bit(r)) o->side = c2b_f32_from_bits(c2b_br_bits(r, 32));
    if (c2b_br_bit(r)) o->up   = c2b_f32_from_bits(c2b_br_bits(r, 32));
    if (c2b_br_bit(r)) o->buttons = c2b_br_bits(r, 32);
    if (c2b_br_bit(r)) o->impulse = c2b_br_bits(r, 8);
    if (c2b_br_bit(r)) {
        o->weap_sel = c2b_br_bits(r, 11);      /* MAX_EDICT_BITS */
        if (c2b_br_bit(r)) o->weap_sub = c2b_br_bits(r, 6);
    }
    {   /* знаковое 16-битное (short) */
        u32 v16;
        if (c2b_br_bit(r)) { v16 = c2b_br_bits(r, 16); o->mdx = (i32)((v16 ^ 0x8000u) - 0x8000u); }
        if (c2b_br_bit(r)) { v16 = c2b_br_bits(r, 16); o->mdy = (i32)((v16 ^ 0x8000u) - 0x8000u); }
    }
    return r->ovf ? -1 : 0;
}

/* --- CSGOUserCmdPB -> байты (полное сообщение, локальная сборка) --- */
static u32 c2b_up_pb_f32(u8 *o, u32 fnum, float v)
{
    u32 b = c2b_f32_to_bits(v);
    o[0] = (u8)((fnum << 3) | 5);
    o[1] = (u8)b; o[2] = (u8)(b >> 8); o[3] = (u8)(b >> 16); o[4] = (u8)(b >> 24);
    return 5;
}

static u32 c2b_varint_len(u32 v)
{
    u8 t[5];
    return c2b_write_varint(t, v);
}

static u32 c2b_up_write_cmd(u8 *o, u32 cap, const c2b_s1cmd_t *c)
{
    u8 base[192], full[224];
    u32 bn = 0;
    base[bn++] = 0x08;                                  /* base.f1 legacy_command_number */
    bn += c2b_write_varint64(base + bn, c->cmd_num);
    base[bn++] = 0x10;                                  /* base.f2 client_tick */
    bn += c2b_write_varint64(base + bn, c->tick);
    {                                                   /* base.f3 buttons_pb */
        u8 bb[16];
        u32 b2 = 0;
        bb[b2++] = 0x08;                                /* f1 buttonstate1 u64 */
        b2 += c2b_write_varint64(bb + b2, c->buttons);
        base[bn++] = 0x1A;
        bn += c2b_write_varint(base + bn, b2);
        for (u32 k = 0; k < b2; k++) base[bn++] = bb[k];
    }
    {                                                   /* base.f4 viewangles (всегда) */
        u8 vb[24];
        u32 v2 = 0;
        for (int i = 0; i < 3; i++)
            v2 += c2b_up_pb_f32(vb + v2, (u32)(i + 1), c->va[i]);
        base[bn++] = 0x22;
        bn += c2b_write_varint(base + bn, v2);
        for (u32 k = 0; k < v2; k++) base[bn++] = vb[k];
    }
    bn += c2b_up_pb_f32(base + bn, 5, c->fwd);          /* base.f5 forwardmove */
    bn += c2b_up_pb_f32(base + bn, 6, c->side);         /* base.f6 leftmove (=S1 sidemove) */
    bn += c2b_up_pb_f32(base + bn, 7, c->up);           /* base.f7 upmove */
    if (c->impulse) {                                   /* base.f8 impulse */
        base[bn++] = 0x40;
        bn += c2b_write_varint64(base + bn, c->impulse);
    }
    if (c->weap_sel) {                                  /* base.f9 weaponselect */
        base[bn++] = 0x48;
        bn += c2b_write_varint64(base + bn, c->weap_sel);
    }
    if (c->mdx) {                                       /* base.f11 mousedx int32 (отриц. = 10Б) */
        base[bn++] = 0x58;
        bn += c2b_write_varint64(base + bn, (u64)(i64)c->mdx);
    }
    if (c->mdy) {                                       /* base.f12 mousedy */
        base[bn++] = 0x60;
        bn += c2b_write_varint64(base + bn, (u64)(i64)c->mdy);
    }
    if (bn >= sizeof(base)) return 0;
    full[0] = 0x0A;                                     /* CSGOUserCmdPB.f1 base */
    u32 n = c2b_write_varint(full + 1, bn);
    if (1 + n + bn > sizeof(full)) return 0;
    c2b_fwd_copy(full + 1 + n, base, bn);
    u32 total = 1 + n + bn;
    if (total > cap) return 0;
    c2b_fwd_copy(o, full, total);
    return total;
}

/* --- S1 CLC_Move -> CS2 payload (пересборка usercmd) ---
 * Контракт: пишет НОВЫЙ payload в plout (cap), *out_n = длина payload.
 * rc: 0 ok, -1 кривой вход/десинк (дроп сообщения), -2 нет места. */
static i32 c2b_up_move(const u8 *pl, u32 pln, u8 *plout, u32 cap, u32 *out_n)
{
    u32 backup = 0, nnew = 0;
    const u8 *data = 0;
    u32 dlen = 0, ip = 0;
    while (ip < pln) {
        u32 tag, c = c2b_read_varint(pl + ip, pln - ip, &tag); if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7u;
        ip += c;
        if (wt == 0) {
            u32 v; c = c2b_read_varint(pl + ip, pln - ip, &v); if (!c) return -1;
            ip += c;
            if (f == 1) backup = v;
            else if (f == 2) nnew = v;
        } else if (wt == 2) {
            u32 ln; c = c2b_read_varint(pl + ip, pln - ip, &ln); if (!c) return -1;
            ip += c;
            if (ln > pln - ip) return -1;
            if (f == 3) { data = pl + ip; dlen = ln; }
            ip += ln;
        } else return -1;
    }
    if (!data) return -1;
    u32 total = backup + nnew;
    if (total > 128) return -1;                         /* демпфер: S1 клампит 64+64 */

    c2b_br_t r;
    c2b_br_init(&r, data, dlen);
    c2b_s1cmd_t from = g_up_base;                       /* локально: откат при ошибке */
    /* блоки пишем с офсета 4 (макс. заголовок payload: 0x1A + varint<=3),
       чтобы финальный сдвиг влево был dst<src (безопасно для fwd_copy).
       Каждый блок = [varint cn][CSGOUserCmdPB]: сообщение пишем в dp+2
       (резерв под 2-байтовую длину), при ln==1 сдвигаем влево, потом
       пишем varint(cn) в dp. */
    u32 dp = 4;
    for (u32 i = 0; i < total; i++) {
        c2b_s1cmd_t cmd;
        if (c2b_up_read_cmd(&r, &from, &cmd) != 0) return -1;
        if (dp + 2 + 224 > cap) return -2;
        u32 cn = c2b_up_write_cmd(plout + dp + 2, cap - dp - 2, &cmd);
        if (!cn) return -2;
        u32 ln = c2b_varint_len(cn);                    /* cn ~<=200 -> ln 1..2 */
        if (ln == 1) c2b_fwd_copy(plout + dp + 1, plout + dp + 2, cn);
        c2b_write_varint(plout + dp, cn);
        dp += ln + cn;
        from = cmd;
        g_up_ucmds++;
    }
    g_up_base = from;
    g_up_base_valid = 1;
    g_up_move++;

    u32 dn = dp - 4;

    /* payload = [0x1A][varint dn][data][f4-хвост]; сдвиг влево на (4-ph),
       хвост пишем ПОСЛЕ сдвига, прямо за данными */
    u32 ph = 1 + c2b_varint_len(dn);
    if (ph > dp) return -1;                             /* не бывает при total>=1 */
    if (ph < 4) c2b_fwd_copy(plout + ph, plout + 4, dn);
    plout[0] = 0x1A;
    c2b_write_varint(plout + 1, dn);
    if (ph + dn + 1 + 5 > cap) return -2;
    plout[ph + dn] = 0x20;
    u32 tl = 1 + c2b_write_varint(plout + ph + dn + 1, from.cmd_num);
    *out_n = ph + dn + tl;
    return 0;
}

/* --- S1 CLC_VoiceData -> CS2 payload (перегруппировка в CMsgVoiceAudio) --- */
/* --- S1 CLC_ListenEvents(12) -> CS2 CMsgSource1LegacyListenEvents(206) (R41, t35):
 * S1 { repeated fixed32 event_mask = 1 } (таг 0x09, wt5, LE-слова)
 * -> CS2 { repeated uint32 eventarraybits = 2 } (таг 0x10, wt0, varint).
 * playerslot(f1 CS2) не эмитим: сервер биндит по net-каналу; флаг на живой прогон. */
static i32 c2b_up_listenevents(const u8 *pl, u32 pln, u8 *plout, u32 cap, u32 *out_n)
{
    u32 n = 0, words = 0, ip = 0;
    while (ip < pln) {
        u32 tag, c = c2b_read_varint(pl + ip, pln - ip, &tag); if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7u;
        ip += c;
        if (f != 1 || (wt != 5 && wt != 1)) return -1; /* event_mask fixed32 (0x0D) или fixed64 (0x09) */
        u32 words_in = (wt == 5) ? 1u : 2u;
        if (pln - ip < words_in * 4) return -1;
        if (n + words_in * 6 > cap) return -2;         /* 0x10 + varint<=5 на слово */
        for (u32 wi = 0; wi < words_in; wi++) {
            u32 v = (u32)pl[ip] | ((u32)pl[ip + 1] << 8) |
                    ((u32)pl[ip + 2] << 16) | ((u32)pl[ip + 3] << 24);
            ip += 4;
            plout[n++] = 0x10;                         /* f2 eventarraybits, wt0 */
            n += c2b_write_varint(plout + n, v);
        }
        words += words_in;
    }
    if (!words) return -1;
    *out_n = n;
    return 0;
}

static i32 c2b_up_voice(const u8 *pl, u32 pln, u8 *plout, u32 cap, u32 *out_n)
{
    const u8 *vdata = 0; u32 vlen = 0;
    u32 xuid_lo = 0, xuid_hi = 0, fmt = 0, seq = 0, sect = 0, uso = 0;
    u8 have_fmt = 0;
    u32 ip = 0;
    while (ip < pln) {
        u32 tag, c = c2b_read_varint(pl + ip, pln - ip, &tag); if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7u;
        ip += c;
        if (wt == 0) {
            u32 v; c = c2b_read_varint(pl + ip, pln - ip, &v); if (!c) return -1;
            ip += c;
            if (f == 3) { fmt = v; have_fmt = 1; }      /* format enum */
            else if (f == 4) seq = v;                   /* sequence_bytes */
            else if (f == 5) sect = v;                  /* section_number */
            else if (f == 6) uso = v;                   /* uncompressed_sample_offset */
        } else if (wt == 1) {
            if (pln - ip < 8) return -1;
            if (f == 2) {                               /* xuid fixed64 */
                u32 lo32, hi32;                         /* memcpy: pl+ip не выровнен */
                memcpy(&lo32, pl + ip, 4); memcpy(&hi32, pl + ip + 4, 4);
                xuid_lo = lo32; xuid_hi = hi32;
            }
            ip += 8;
        } else if (wt == 2) {
            u32 ln; c = c2b_read_varint(pl + ip, pln - ip, &ln); if (!c) return -1;
            ip += c;
            if (ln > pln - ip) return -1;
            if (f == 1) { vdata = pl + ip; vlen = ln; } /* data bytes */
            ip += ln;
        } else return -1;
    }
    if (!vdata) return -1;

    u8 aud[24], aud3[16];
    u32 an = 0, a3 = 0;
    if (have_fmt) {                                     /* CMsgVoiceAudio.f1 format */
        aud[an++] = 0x08;
        an += c2b_write_varint(aud + an, fmt);
    }
    aud[an++] = 0x12;                                   /* f2 voice_data */
    an += c2b_write_varint(aud + an, vlen);
    if (seq)  { aud3[a3++] = 0x18; a3 += c2b_write_varint(aud3 + a3, seq); }
    if (sect) { aud3[a3++] = 0x20; a3 += c2b_write_varint(aud3 + a3, sect); }
    if (uso)  { aud3[a3++] = 0x30; a3 += c2b_write_varint(aud3 + a3, uso); }

    u32 alen = an + vlen + a3;
    u32 need = 1 + c2b_varint_len(alen) + alen + 1 + 8;
    if (need > cap) return -2;

    u32 n2 = 0;
    plout[n2++] = 0x0A;                                 /* CS2 CLC_VoiceData.f1 audio */
    n2 += c2b_write_varint(plout + n2, alen);
    /* part1: format? + 0x12 + len(vdata) */
    c2b_fwd_copy(plout + n2, aud, an); n2 += an;
    /* сами данные голоса */
    c2b_fwd_copy(plout + n2, vdata, vlen); n2 += vlen;
    /* part3: sequence_bytes/section_number/uso — уже в aud после 0x12+len... нет:
       они в aud ПОСЛЕ заголовка; посылаем их отдельно из aud3 */
    c2b_fwd_copy(plout + n2, aud3, a3); n2 += a3;
    plout[n2++] = 0x11;                                 /* f2 xuid fixed64 */
    for (u32 k = 0; k < 4; k++) plout[n2++] = (u8)(xuid_lo >> (8 * k));
    for (u32 k = 0; k < 4; k++) plout[n2++] = (u8)(xuid_hi >> (8 * k));
    *out_n = n2;
    return 0;
}

/* ClientInfo S1->S2: f1->1 f2->2 f3->3 f4(is_replay)->дроп f5->5 f6->6 f7(custom_files)->дроп */
static const unsigned char g_up_fmap_ci[8] = { 0, 1, 2, 3, 0xFF, 5, 6, 0xFF };

/* --- аплинк-транслятор потока: [varint type][varint len][payload] S1 -> S2 --- */
i32 c2b_uplink_translate(const u8 *in, u32 in_len, u8 *out, u32 cap, u32 *out_len)
{
    u32 ip = 0, op = 0;
    while (ip < in_len) {
        u32 type, len, c;
        c = c2b_read_varint(in + ip, in_len - ip, &type); if (!c) goto trunc;
        ip += c;
        c = c2b_read_varint(in + ip, in_len - ip, &len);  if (!c) goto trunc;
        ip += c;
        if (len > in_len - ip) goto trunc;
        g_up_in++;

        u32 newtype = 0xFFFFu;                           /* 0xFFFF = дроп */
        const unsigned char *fmap = 0;
        u32 rebuild = 0;                                 /* 1 = Move, 2 = Voice */

        if (type <= 7)        newtype = type;            /* NET identity */
        else if (type == 8)  { newtype = 20; fmap = g_up_fmap_ci; }  /* ClientInfo */
        else if (type == 9)  { newtype = 21; rebuild = 1; }          /* Move */
        else if (type == 10) { newtype = 22; rebuild = 2; }          /* VoiceData */
        else if (type == 11) newtype = 23;               /* BaselineAck */
        else if (type == 13) newtype = 25;               /* RespondCvarValue */
        else if (type == 15) newtype = 27;               /* LoadingProgress */
        else if (type == 18) newtype = 34;               /* CmdKeyValues */
        else if (type == 20) newtype = 36;               /* HltvReplay */
        else if (type == 12) { newtype = 206; rebuild = 3; }   /* R41: ListenEvents -> S1legacy(206) */
        else if (type == 14 || type == 16 || type == 17) {
            g_up_drop++;                                 /* FileCRC/SplitPlayerConn/ClientMsg */
            ip += len; continue;
        } else {
            g_up_unknown++; g_up_drop++;
            ip += len; continue;
        }

        u32 pn = 0;
        if (rebuild == 1) {
            i32 rc = c2b_up_move(in + ip, len, out + op + 12, cap - op - 12, &pn);
            if (rc == -1) { g_up_err++; ip += len; continue; }   /* дроп сообщения */
            if (rc == -2) goto oom;
        } else if (rebuild == 2) {
            i32 rc = c2b_up_voice(in + ip, len, out + op + 12, cap - op - 12, &pn);
            if (rc == -1) { g_up_err++; ip += len; continue; }
            if (rc == -2) goto oom;
        } else if (rebuild == 3) {
            i32 rc = c2b_up_listenevents(in + ip, len, out + op + 12, cap - op - 12, &pn);
            if (rc == -1) { g_up_err++; ip += len; continue; }   /* битый payload — дроп */
            if (rc == -2) goto oom;
        } else if (fmap) {
            i32 rc = c2b_renum_payload(in + ip, len, fmap, out + op + 12,
                                       cap - op - 12, 0);
            if (rc == -2) goto oom;
            if (rc < 0)  { g_up_err++; ip += len; continue; }
            pn = (u32)rc;
        } else {
            pn = len;                                    /* identity payload */
        }

        if (op + 12 + pn > cap) goto oom;
        u32 t = c2b_write_varint(out + op, newtype);
        u32 l = c2b_write_varint(out + op + t, pn);
        if (pn) {
            if (rebuild || fmap)
                c2b_fwd_copy(out + op + t + l, out + op + 12, pn);   /* dst<src, t+l<=12 */
            else
                c2b_fwd_copy(out + op + t + l, in + ip, len);
        }
        op += t + l + pn;
        g_up_out++;
        ip += len;
    }
    if (out_len) *out_len = op;
    return 0;
trunc:
    if (out_len) *out_len = op;
    return -1;
oom:
    if (out_len) *out_len = op;
    return -2;
}

/* ---------- detour ---------- */
i32 c2b_hook_process_messages(uptr chan, uptr brd, u32 flag); /* fwd */
i32 c2b_hook_sendnetmsg(uptr chan, uptr msg, u32 rel, u32 voice); /* fwd (аплинк) */
#if defined(__x86_64__) && !defined(C2B_SELFTEST)
extern void c2b_hook_thunk(void); /* fwd (тело — в asm-тюнке ниже) */
static void *volatile c2b_trampoline_ptr = 0;
extern void c2b_up_hook_thunk(void); /* fwd (аплинк-тюнк, тело ниже) */
static void *volatile c2b_up_trampoline_ptr = 0;
#endif

static i32 c2b_page_protect(uptr addr, u32 len, u32 prot)
{
    uptr pg  = addr & (uptr)PAGE_MASK;
    uptr end = (addr + len + 0xFFFu) & (uptr)PAGE_MASK;
    return mprotect((void *)pg, (u32)(end - pg), (i32)prot);
}

static void c2b_write_jmp(void *dst, const void *fn)
{
#ifdef __x86_64__
    u8 b[14] = { 0xFF, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    uptr v = (uptr)fn;
    for (int i = 0; i < 8; i++) b[6 + i] = (u8)(v >> (8 * i));
    memcpy(dst, b, C2B_PATCH_LEN);
#else
    u8 b[6] = { 0x68, 0, 0, 0, 0, 0xC3 };   /* push imm32; ret */
    u32 v = (u32)(uptr)fn;
    b[1] = (u8)v; b[2] = (u8)(v >> 8); b[3] = (u8)(v >> 16); b[4] = (u8)(v >> 24);
    memcpy(dst, b, C2B_PATCH_LEN);
#endif
}

typedef i32 (*c2b_fn3_t)(uptr, uptr, u32);
typedef i32 (*c2b_fn4_t)(uptr, uptr, u32, u32);

static i32 c2b_install(uptr target)
{
#ifdef C2B_SELFTEST
    printf("  [i] memcmp@%lx...\n", (unsigned long)target); fflush(stdout);
#endif
    if (memcmp((const void *)target, C2B_SIG, (u32)C2B_SIG_LEN) != 0)
        return -1;                                   /* сигнатура не сошлась */

    if (c2b_page_protect(target, C2B_STOLEN + C2B_PATCH_LEN, 0x07 /*RWX*/) != 0)
        return -2;

#ifdef C2B_SELFTEST
    printf("  [i] mmap trampoline...\n"); fflush(stdout);
#endif
    g_trampoline = (u8 *)mmap(0, 4096, 0x07, 0x22 /*PRIVATE|ANON*/, -1, 0);
    if (g_trampoline == (u8 *)-1) return -3;
#ifdef C2B_SELFTEST
    printf("  [i] tramp=%lx\n", (unsigned long)g_trampoline); fflush(stdout);
#endif

#ifdef C2B_SELFTEST
    printf("  [i] copy g_saved\n"); fflush(stdout);
#endif
    memcpy(g_saved, (const void *)target, C2B_STOLEN + C2B_PATCH_LEN);
#ifdef C2B_SELFTEST
    printf("  [i] fill trampoline\n"); fflush(stdout);
#endif
    memcpy(g_trampoline, (const void *)target, C2B_STOLEN);
#ifdef C2B_SELFTEST
    printf("  [i] jmp back\n"); fflush(stdout);
#endif
    c2b_write_jmp(g_trampoline + C2B_STOLEN, (const u8 *)target + C2B_STOLEN);
#ifdef C2B_SELFTEST
    printf("  [i] patch target\n"); fflush(stdout);
#endif
#if defined(__x86_64__) && !defined(C2B_SELFTEST)
    /* тюнк читает трамплин через глобал — заполнить ДО патча сайта */
    c2b_trampoline_ptr = (void *)g_trampoline;
    c2b_write_jmp((void *)target, (const void *)&c2b_hook_thunk);
#else
    c2b_write_jmp((void *)target, (const void *)&c2b_hook_process_messages);
#endif

    g_target = (void *)target;
    g_state  = 1;
    return 0;
}

__attribute__((unused)) static void c2b_uninstall(void)
{
    if (!g_target) return;
    memcpy(g_target, g_saved, C2B_STOLEN);
    g_target = 0; g_state = 0;
}

/* ---------- второй детур: SendNetMsg (аплинк), та же механика ---------- */
#ifdef __x86_64__
static i32 c2b_install2(uptr target)
{
#ifdef C2B_SELFTEST
    printf("  [i] uplink install @%lx...\n", (unsigned long)target); fflush(stdout);
#endif
    if (memcmp((const void *)target, UPL_SIG, (u32)UPL_SIG_LEN) != 0)
        return -1;                                   /* сигнатура не сошлась */
    if (c2b_page_protect(target, UPL_STOLEN + C2B_PATCH_LEN, 0x07) != 0)
        return -2;
    g2_trampoline = (u8 *)mmap(0, 4096, 0x07, 0x22 /*PRIVATE|ANON*/, -1, 0);
    if (g2_trampoline == (u8 *)-1) { g2_trampoline = 0; return -3; }
    memcpy(g2_saved, (const void *)target, UPL_STOLEN + C2B_PATCH_LEN);
    memcpy(g2_trampoline, (const void *)target, UPL_STOLEN);
    c2b_write_jmp(g2_trampoline + UPL_STOLEN, (const u8 *)target + UPL_STOLEN);
#if defined(__x86_64__) && !defined(C2B_SELFTEST)
    /* тюнк читает трамплин через глобал — заполнить ДО патча сайта */
    c2b_up_trampoline_ptr = (void *)g2_trampoline;
    c2b_write_jmp((void *)target, (const void *)&c2b_up_hook_thunk);
#else
    c2b_write_jmp((void *)target, (const void *)&c2b_hook_sendnetmsg);
#endif
    g2_target = (void *)target;
    g2_state  = 1;
    return 0;
}

__attribute__((unused)) static void c2b_uninstall2(void)
{
    if (!g2_target) return;
    memcpy(g2_target, g2_saved, UPL_STOLEN);
    g2_target = 0; g2_state = 0;
}
#endif /* __x86_64__ */

/* ---------- GC-транзит v1 (Фаза 2): OBSERVER через ISteamGameCoordinator ----------
 * Сырьё: рой audit_t38 (500 юнитов) -> s2s1_gc_policy.h:
 *   S1 196 имён: 149 identity, 10 EE->base, 37 S1-only (кандидат DROP);
 *   S2 664 имён: 149 identity, 514 new-in-S2 (fail-closed DROP), 1 EE.
 * Провод: клиент ходит в GC через ISteamGameCoordinator (steam_api.so;
 * client_client.so импортирует SteamInternal_CreateInterface, CGCClient).
 * v1 БЕЗ патча кода steam_api:
 *   1) dlsym(RTLD_DEFAULT, "SteamAPI_ISteamGameCoordinator") -> obj (NULL до
 *      SteamAPI_Init — опрашиваем из poll-потока);
 *   2) слоты SendMessage/RetrieveMessage верифицируем по flat-экспортам
 *      SteamAPI_ISteamGameCoordinator_{SendMessage,RetrieveMessage}: в теле
 *      компилятор оставляет jmp qword [reg+disp] (FF /4) — disp/8 = слот;
 *   3) копия vtable, 2 слота -> наши обёртки (счётчики + first-sight лог),
 *      obj->vptr = копия (атомарный swap одного указателя, heap — writable).
 * Поведение не меняется: все вызовы уходят в оригиналы (OBSERVER, как v0-хук). */
extern void *dlsym(void *handle, const char *symbol);   /* RTLD_DEFAULT = 0 */

/* run31-ABI-фикс: слоты GC — ВИРТУАЛЬНЫЕ МЕТОДЫ ISteamGameCoordinator:
 *   [3] EGCResults SendMessage(this, unMsgType, pubData, cubData)
 *   [2] EGCResults RetrieveMessage(this, &punMsgType, pubDest, cubDest, &pcubMsgSize)
 * rdi = this. Прежние typedef'ы без self сдвигали ВСЕ аргументы (у pump
 * this вообще отсутствовал) → внутри steamclient.so дерейференс мусорного
 * this → SIGSEGV at 0x100000000 в c2b_poll_thread (run 31, a1/a2/a5). */
typedef i32 (*c2b_gc_send_t)(void *self, u32 msgtype, const void *data, u32 size);
typedef i32 (*c2b_gc_retr_t)(void *self, u32 *msgtype, void *dest, u32 destsz,
                            u32 *retsz);

static u8 g_gc_mode = 1;        /* C2B_GC=0 выключает; дефолт observe */
static u8 g_gc_t_mode = 0;      /* t42v9: C2B_GC_T=1 -> даунлинк-фильтр S2NEW (audit_t38) */
static volatile u32 g_gc_state = 0;
static void *g_gc_obj = 0;
static uptr g_gc_vt_copy[8];
static c2b_gc_send_t g_gc_orig_send = 0;
static c2b_gc_retr_t g_gc_orig_retr = 0;
static u32 g_gc_up_n, g_gc_up_b, g_gc_dn_n, g_gc_dn_b;
static u32 g_gc_dn_drop;        /* t42v9: сообщений S2NEW отфильтровано на даунлинке */
static u32 g_gc_dn_zero;        /* run33: пустые записи очереди (mt=0/rsz=0) — аномалия */
static u8  g_gc_zero_once;      /* run33: разовый лог пустой записи */
/* run33: слоты GC-объекта. RE-факт t42v2 ([2]=retr, [3]=send) снят на
 * steam_api.so 2013 года; современный steamclient.so хостед-раннера дал
 * 16 пустых dn → раскладка под вопросом. Диаг-дамп даст фактическую,
 * env позволяет перевернуть слоты без пересборки. */
static u32 g_gc_slot_send = 3;  /* C2B_GC_SEND_SLOT */
static u32 g_gc_slot_retr = 2;  /* C2B_GC_RETR_SLOT */
static u8  g_gc_diag = 1;       /* run33: дамп vtable при арме; C2B_GC_DIAG=0 выключает */
/* run35: СВОП vptr выключен по умолчанию. Обоснование: реальный класс GC
 * имеет БОЛЬШЕ 8 виртуальных слотов (g_gc_vt_copy[8] их усекает) — после
 * свопа внутренний виртуальный вызов слота >=8 читает за границей массива
 * и прыгает в данные (run 35 a1: SIGSEGV ip==fault==pointer-table адрес
 * внутри steamclient.so, затем каскад отравления тёплого клиента: a2-a4
 * пали на abort libopenal при аудио-init). Хуки игры (перехват GC-вызовов
 * игры) теперь opt-in: C2B_GC_SWAP=1 И ПОЛНАЯ перезапись vtable — позже.
 * Pump'у своп не нужен: он зовёт оригиналы напрямую через g_gc_obj. */
static u8  g_gc_swap = 0;       /* C2B_GC_SWAP=1 включает своп vptr (хуки) */
static u8  g_gc_probe = 0;      /* run37: C2B_GC_PROBE=1 - старая проба GC (битые объекты) */
static u32 g_gc_uniq_n = 0;
#define C2B_GC_UNIQ 24
static struct { u32 id; u32 up; u32 dn; u8 act; } g_gc_uniq[C2B_GC_UNIQ];
/* t42v2: последний код отказа ARM (печатается в GCFINI как GC-ARM-FAIL rc=N).
 * 1 = дефолт (GC-интерфейс клиентом не запрашивался / flat-аксессор отсутствует),
 * 2..6 = отказы v1-пути (аксессор был, но слот/vtable не сошлись),
 * 12 = клиент запросил GC-интерфейс, но получил NULL, 15/16 = отказы v2-ARM. */
static volatile u32 g_gc_last_fail = 1;

/* эталонные объёмы таблиц роя — сломаются при регене с другими материалами */
typedef char c2b_gc_s1_n_chk[(C2B_GC_S1_TAB_N == 196) ? 1 : -1];
typedef char c2b_gc_s2_n_chk[(C2B_GC_S2_TAB_N == 664) ? 1 : -1];

/* wire-id -> запись S1-таблицы (частичный прото: 51 id; иначе 0). IDMAP отсортирован */
__attribute__((unused)) static const c2b_gc_ent_t *c2b_gc_by_id(u32 id)
{
    u32 lo = 0, hi = (u32)C2B_GC_IDMAP_N;
    while (lo < hi) {
        u32 mid = (lo + hi) >> 1;
        if (C2B_GC_IDMAP[mid].id < id) lo = mid + 1;
        else if (C2B_GC_IDMAP[mid].id > id) hi = mid;
        else return &C2B_GC_S1_TAB[C2B_GC_IDMAP[mid].idx];
    }
    return 0;
}

/* t42v9: даунлинк-фильтр (audit_t38 fail-closed): id в S2-таблице с act=S2NEW
 * (new-in-S2, S1-парсер его не знает) -> DROP. id вне таблицы (core-GC:
 * 4004 ClientWelcome, 4006 ClientHello...) и identity -> passthrough.
 * Дроп аплинка S1ONLY отложен: все 37 S1ONLY-имён вне частичного прото
 * (id=0) — вешать фильтр не на что; аплинк S1-клиента легитимен по определению. */
__attribute__((unused)) static i32 c2b_gc_dn_drop(u32 id)
{
    if (!id) return 0;
    for (u32 i = 0; i < (u32)C2B_GC_S2_TAB_N; i++)
        if (C2B_GC_S2_TAB[i].id == id)
            return (C2B_GC_S2_TAB[i].act == C2B_GC_S2NEW) ? 1 : 0;
    return 0;
}

__attribute__((unused)) static i32 c2b_gc_act_by_name(const c2b_gc_ent_t *tab, u32 n,
                                                      const char *name)
{
    for (u32 i = 0; i < n; i++)
        if (strcmp(tab[i].name, name) == 0) return (i32)tab[i].act;
    return -1;
}

/* слот vtable из тела flat-функции: ищем FF /4 (jmp r/m64) в первых 32 байтах */
__attribute__((unused)) static i32 c2b_gc_slot_of(const void *fn)
{
    const u8 *p = (const u8 *)fn;
    for (u32 i = 0; i + 2 <= 32; i++) {
        if (p[i] != 0xFF || (p[i + 1] & 0x38) != 0x20) continue;   /* FF /4: reg=100 */
        u8 mod = (u8)((p[i + 1] >> 6) & 3);
        u8 rm  = (u8)(p[i + 1] & 7);
        if (rm == 4) return -1;                       /* sib — не разбираем */
        if (rm == 5 && mod == 0) return -1;           /* rip-rel — нет */
        if (mod == 0) return 0;                       /* jmp [reg] */
        if (mod == 1) {
            if (i + 3 > 32) return -1;
            return (i32)(signed char)p[i + 2] / 8;  /* sign-ext disp8 */
        }
        if (mod == 2) {
            if (i + 6 > 32) return -1;
            i32 d = 0;
            memcpy(&d, &p[i + 2], 4);
            return d / 8;
        }
        return -1;
    }
    return -1;
}

static const char *c2b_gc_act_str(u8 a)
{
    switch (a) {
    case C2B_GC_IDENTITY: return "identity";
    case C2B_GC_EE_BASE:  return "ee-base";
    case C2B_GC_RENAME:   return "rename";
    case C2B_GC_S1ONLY:   return "s1only";
    case C2B_GC_S2NEW:    return "s2new";
    default:              return "?";
    }
}

/* first-sight лог + уникальный счётчик по id (dir 1=up client->GC, 0=dn GC->client) */
static void c2b_gc_note(u32 dir, u32 rawid, u32 sz)
{
    u32 slot = C2B_GC_UNIQ;
    for (u32 i = 0; i < g_gc_uniq_n; i++)
        if (g_gc_uniq[i].id == rawid) { slot = i; break; }
    if (slot == C2B_GC_UNIQ && g_gc_uniq_n < C2B_GC_UNIQ) {
        slot = g_gc_uniq_n++;
        /* t42v10-fix (поймал selftest gc-hello-B): id НЕ записывался в слот —
         * таблица оставалась из нулей, повторные id аллоцировали новые слоты */
        g_gc_uniq[slot].id = rawid;
        g_gc_uniq[slot].up = 0;
        g_gc_uniq[slot].dn = 0;
        g_gc_uniq[slot].act = 0;
    }
    if (slot != C2B_GC_UNIQ) {
        if (dir) g_gc_uniq[slot].up++; else g_gc_uniq[slot].dn++;
        if (g_gc_uniq[slot].up + g_gc_uniq[slot].dn == 1) {
            const c2b_gc_ent_t *e = c2b_gc_by_id(rawid);
            u8 act = e ? e->act : (u8)255;
            C2B_LOGS("[c2b] GC ");
            C2B_LOGS(dir ? "up " : "dn ");
            C2B_LOGS("id="); C2B_LOGH(rawid);
            C2B_LOGS("sz="); C2B_LOGN(sz);
            C2B_LOGS("name=");
            C2B_LOGS(e ? e->name : "(id вне частичного прото)");
            C2B_LOGS("act="); C2B_LOGS(c2b_gc_act_str(act));
            C2B_LOGS("\n");
            g_gc_uniq[slot].act = act;
        }
    }
}

static i32 c2b_gc_send_h(void *self, u32 msgtype, const void *data, u32 size)
{
    u32 raw = msgtype & 0x7FFFFFFFu;
    /* t42v2: счётчики атомарные — хуки зовутся из чужих потоков (GC-транзит
     * может идти не только из main); GCFINI читает их атомарно же. */
    __atomic_fetch_add(&g_gc_up_n, 1u, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_gc_up_b, size, __ATOMIC_RELAXED);
    c2b_gc_note(1, raw, size);
    return g_gc_orig_send(self, msgtype, data, size);
}

static i32 c2b_gc_retr_h(void *self, u32 *msgtype, void *dest, u32 destsz,
                         u32 *retsz)
{
    /* t42v9: цикл с фильтром S2NEW — отфильтрованное сообщение игра НЕ видит,
     * очередь дренируется дальше (guard 8: аномально длинную серию дропов
     * честно возвращаем как NoMessage). */
    for (u32 guard = 0; guard < 8; guard++) {
        i32 rv = g_gc_orig_retr(self, msgtype, dest, destsz, retsz);
        if (rv != 1 || !msgtype || !retsz) return rv;   /* 2=NoMessage и др. */
        u32 raw = (*msgtype) & 0x7FFFFFFFu;
        if (g_gc_t_mode && c2b_gc_dn_drop(raw)) {
            __atomic_fetch_add(&g_gc_dn_drop, 1u, __ATOMIC_RELAXED);
            C2B_LOGS("[c2b] GC dn DROP s2new id="); C2B_LOGH(raw); C2B_LOGS("\n");
            continue;
        }
        __atomic_fetch_add(&g_gc_dn_n, 1u, __ATOMIC_RELAXED);
        __atomic_fetch_add(&g_gc_dn_b, *retsz, __ATOMIC_RELAXED);
        c2b_gc_note(0, raw, *retsz);
        return rv;
    }
    return 2;                     /* k_EGCResultNoMessage после 8 дропов */
}

/* ---------- run33: диагностический дамп vtable GC-объекта ----------
 * В run 33 (hosted runner, СОВРЕМЕННЫЙ steamclient.so) drain сразу выдал
 * 16 сообщений id=0/sz=0 и заблокировал ClientHello. Похоже, слоты
 * [2]/[3] на этом билде НЕ RetrieveMessage/SendMessage (RE-факт t42v2
 * снят на steam_api.so 2013 года). Дамп (fp + первые 24 байта кода
 * каждого слота 0..7) позволяет офлайн-сверить фактическую раскладку. */
static void c2b_gc_vt_diag(void *obj)
{
    if (!g_gc_diag || !obj) return;
    uptr vt = *(uptr *)obj;
    C2B_LOGS("[c2b] GCDIAG obj="); C2B_LOGH((u32)(uptr)obj);
    C2B_LOGS("vt="); C2B_LOGH((u32)vt); C2B_LOGS("\n");
    if (vt < 0x10000u) return;
    for (u32 k = 0; k < 8; k++) {
        uptr fp = ((uptr *)vt)[k];
        C2B_LOGS("[c2b] GCDIAG s"); C2B_LOGN(k);
        C2B_LOGS("fp="); C2B_LOGH((u32)fp);
        if (fp < 0x10000u) { C2B_LOGS("(nil)\n"); continue; }
        const volatile u8 *p = (const volatile u8 *)fp;
        for (u32 w = 0; w < 6; w++) {   /* 24 байта = 6 u32 (LE, побайтово) */
            u32 word = (u32)p[w * 4] | ((u32)p[w * 4 + 1] << 8) |
                       ((u32)p[w * 4 + 2] << 16) | ((u32)p[w * 4 + 3] << 24);
            C2B_LOGS("w"); C2B_LOGN(w); C2B_LOGH(word);
        }
        C2B_LOGS("\n");
    }
}

/* возвращает 0 = swap сделан; <0 = причина (лог в caller)
 * run37: dlsym(0) не видит libsteam_api.so (движок грузит её RTLD_LOCAL),
 * поэтому аксессоров нет и арм уходил в ПРОБУ с угаданными хэндлами
 * (u=1,p=1) — GetISteamGenericInterface возвращал БИТЫЙ CAdapter:
 * RetrieveMessage отдавал 16 zero-записей (run 33/34), SendMessage прыгал
 * в RTTI-данные (SIGSEGV ip==fault==...e3f848, run 35/37 a1). Фикс:
 * dlopen libsteam_api.so сами и берём ИГРОВЫЕ flat-аксессоры — объект
 * от них построен на реальных хэндлах игры. */
static void *g_gc_apih;
static u8  g_gc_objfail_once;
extern void *dlopen(const char *, i32);   /* run37: объявление до try_install */
#ifndef C2B_RTLD_NOW
#define C2B_RTLD_NOW    2
#define C2B_RTLD_GLOBAL 0x100
#endif
__attribute__((unused)) static i32 c2b_gc_try_install(void)
{
    if (g_gc_state) return 0;
    if (!g_gc_mode) return -100;
    void *(*acc)(void) = (void *(*)(void))dlsym(0, "SteamAPI_ISteamGameCoordinator");
    if (!acc) {
        if (!g_gc_apih) {
            static const char *const cands[] = {
                "libsteam_api.so", "steam_api.so", "steam_api64.so" };
            for (u32 i = 0; i < 3 && !g_gc_apih; i++)
                g_gc_apih = dlopen(cands[i], C2B_RTLD_NOW | C2B_RTLD_GLOBAL);
            if (g_gc_apih)
                C2B_LOGS("[c2b] gc libsteam_api dlopen OK\n");
        }
        if (g_gc_apih) {
            acc = (void *(*)(void))dlsym(g_gc_apih,
                                         "SteamAPI_ISteamGameCoordinator");
            /* run38: dlopen OK, но арм не случился — логируем каждый шаг */
            C2B_LOGS("[c2b] gc acc dlsym=");
            C2B_LOGS(acc ? "hit" : "MISS");
            C2B_LOGS("\n");
        }
        if (!acc) return -1;
    }
    void *obj = acc();
    if (!obj) {
        if (!g_gc_objfail_once) {
            g_gc_objfail_once = 1;
            C2B_LOGS("[c2b] gc acc()=NULL (SteamAPI_Init не завершён или "
                     "адаптер не создаётся)\n");
        }
        return -2;                              /* SteamAPI_Init ещё не был */
    }
    void *fs = dlsym(0, "SteamAPI_ISteamGameCoordinator_SendMessage");
    void *fr = dlsym(0, "SteamAPI_ISteamGameCoordinator_RetrieveMessage");
    if ((!fs || !fr) && g_gc_apih) {
        fs = dlsym(g_gc_apih, "SteamAPI_ISteamGameCoordinator_SendMessage");
        fr = dlsym(g_gc_apih, "SteamAPI_ISteamGameCoordinator_RetrieveMessage");
    }
    if (!fs || !fr) return -3;
    i32 sslot = c2b_gc_slot_of(fs), rslot = c2b_gc_slot_of(fr);
    if (sslot < 0 || rslot < 0 || sslot > 7 || rslot > 7) return -4;
    uptr vt = *(uptr *)obj;
    if (!vt) return -5;
    c2b_gc_send_t osend = (c2b_gc_send_t)((uptr *)vt)[sslot];
    c2b_gc_retr_t oretr = (c2b_gc_retr_t)((uptr *)vt)[rslot];
    if (!osend || !oretr) return -6;
    memcpy(g_gc_vt_copy, (const void *)vt, sizeof(g_gc_vt_copy));
    g_gc_orig_send = osend;
    g_gc_orig_retr = oretr;
    g_gc_vt_copy[sslot] = (uptr)c2b_gc_send_h;
    g_gc_vt_copy[rslot] = (uptr)c2b_gc_retr_h;
    if (g_gc_swap) {
        *(volatile uptr *)obj = (uptr)g_gc_vt_copy;   /* атомарный swap vptr */
    }
    g_gc_obj = obj;
    g_gc_state = 1;
    C2B_LOGS("[c2b] GC-ARMED obj="); C2B_LOGH((u32)(uptr)obj);
    C2B_LOGS("slots send="); C2B_LOGN((u32)sslot);
    C2B_LOGS("retr="); C2B_LOGN((u32)rslot);
    C2B_LOGS("\n");
    c2b_gc_vt_diag(obj);   /* run33: фактическая раскладка слотов в лог */
    return 0;
}

/* ---------- t42v2: ARM по перехвату выдачи GC-интерфейса клиенту ----------
 * RE-факты (t42-рой, восстановлено после отката 2026-09-28T22:28Z):
 *  * vtable клиентского ISteamGameCoordinator: [0..1]=AddRef/Release,
 *    [2]=RetrieveMessage(&punMsgType,pubDest,cubDest,&pcubMsgSize),
 *    [3]=SendMessage(unMsgType,pubData,cubData); rdi=this.
 *  * 9ec638ca (свап слотов + self-хуки) дал первый GC-ARMED, но RC=139:
 *    первый хук-вызов видел недопубликованный vt_copy. 53706c6c = publication-
 *    barrier: слоты-копии и оригиналы публикуются (__atomic_store_n seq_cst)
 *    ДО свопа vptr; счётчики/GCFINI-loads атомарные.
 *  * v1 dlsym-путь мёртв (flat-аксессора в steam_api.so S1 нет) — v2 получает
 *    объект из интерпозиции SteamInternal_{CreateInterface,
 *    FindOrCreateUserInterface} при выдаче версии STEAMGAMECOORDINATOR_*. */
static i32 c2b_gc_arm(void *obj)
{
    if (g_gc_state) return 0;
    if (!g_gc_mode) return -100;
    if (!obj) { g_gc_last_fail = 12; return -12; }
    uptr vt = *(uptr *)obj;
    if (!vt) { g_gc_last_fail = 15; return -15; }
    c2b_gc_retr_t oretr = (c2b_gc_retr_t)((uptr *)vt)[g_gc_slot_retr];
    c2b_gc_send_t osend = (c2b_gc_send_t)((uptr *)vt)[g_gc_slot_send];
    if (!osend || !oretr) { g_gc_last_fail = 16; return -16; }
    g_gc_orig_send = osend;
    g_gc_orig_retr = oretr;
    if (g_gc_swap) {
        /* Opt-in (C2B_GC_SWAP=1): перехват GC-вызовов игры. Требует
         * vtable-копию ПОЛНОГО размера (см. run35-комментарий у g_gc_swap) —
         * с текущей усечённой копией[8] включать НЕЛЬЗЯ. */
        memcpy(g_gc_vt_copy, (const void *)vt, sizeof(g_gc_vt_copy));
        /* publication barrier: содержимое копии ВИДИМО до свопа vptr */
        __atomic_store_n(&g_gc_vt_copy[g_gc_slot_send], (uptr)c2b_gc_send_h,
                         __ATOMIC_SEQ_CST);
        __atomic_store_n(&g_gc_vt_copy[g_gc_slot_retr], (uptr)c2b_gc_retr_h,
                         __ATOMIC_SEQ_CST);
        *(volatile uptr *)obj = (uptr)g_gc_vt_copy;   /* публикация — одним стором */
    }
    g_gc_obj = obj;
    __atomic_store_n(&g_gc_state, 1u, __ATOMIC_SEQ_CST);
    C2B_LOGS("[c2b] GC-ARMED obj="); C2B_LOGH((u32)(uptr)obj);
    C2B_LOGS("slots send="); C2B_LOGN(g_gc_slot_send);
    C2B_LOGS("retr="); C2B_LOGN(g_gc_slot_retr);
    C2B_LOGS(" swap="); C2B_LOGN(g_gc_swap);
    C2B_LOGS("\n");
    c2b_gc_vt_diag(obj);   /* run33: фактическая раскладка слотов в лог */
    return 0;
}

/* ---------- t42v8: ClientHello-craft — разминка GC-канала самим мостом ----------
 * RE-факт (Task 54, t42v7h): GC-ARMED 2/2, но up/dn=0 — игра в menu-idle НЕ шлёт
 * GC-сообщений и НЕ опрашивает очередь (CGCClient молчит).
 * Решение: мост САМ шлёт CMsgClientHello через оригинальный слот SendMessage[3]
 * и САМ дренирует RetrieveMessage[2] — иначе ответы GC копились бы в очереди
 * steamclient вечно (игра их не читает).
 * Провод ISteamGameCoordinator::SendMessage:
 *   unMsgType = 0x80000000 (k_EMsgProtoBufFlag) | 4006 (k_EMsgGCClientHello),
 *   pubData   = тело CMsgClientHello БЕЗ заголовка: field1 engine varint
 *   k_ESESource1=1 -> байты 08 01 (csgo gamecoordinator.proto).
 * Ожидаемый ответ: id=4004 CMsgClientWelcome — первый dn>0 = транзит жив.
 * Счётчики ведём сами (зовём оригиналы, не хуки) теми же атомарками, что и
 * хуки, — GCFINI/uniq-таблица увидят наш трафик как родной. */
static u8 g_hello_mode = 0;            /* C2B_HELLO=1 включает (run33: слоты GC
                                        * под вопросом — слать только по явному флагу,
                                        * пока GCDIAG не подтвердит раскладку) */
static volatile u32 g_hello_state = 0; /* 0=idle 1=tries 2=dn-received 3=exhausted */
static volatile u32 g_hello_sends = 0;

#define C2B_HELLO_MSGID  4006u
#define C2B_HELLO_TRIES  6      /* попыток SendMessage */
/* t42v10: тайминги — рантайм-переменные (selftest гоняет pump на ускорении) */
static u32 g_hello_every = 20;      /* итераций между попытками (10с при тике 500мс) */
static u32 g_hello_pre   = 20;      /* пауза после ARM перед 1-й попыткой (10с) */
static u32 g_hello_tail  = 60;      /* итераций дренирования после первого dn (30с) */
static u32 g_hello_iters = 200;     /* жёсткий потолок цикла (100с) */
static u32 g_hello_tick_us = 500000; /* тик цикла; selftest ускоряет до 1000 */

__attribute__((unused)) static void c2b_gc_hello_pump(void)
{
    u32 st = __atomic_load_n(&g_gc_state, __ATOMIC_SEQ_CST);
    /* run31-фикс: + гейты g_state (t39: движок не встал — GC не трогаем) и
     * g_gc_obj (self для прямых вызовов оригиналов — без него прежний код
     * звал методы без this → SIGSEGV в steamclient.so). run33: слоты
     * send/retr не должны схлопнуться (защита от кривого env). */
    if (!g_hello_mode || !st || !g_state || !g_gc_obj ||
        !g_gc_orig_send || !g_gc_orig_retr ||
        (uptr)g_gc_orig_send == (uptr)g_gc_orig_retr) return;

    static const u8 hello_body[2] = { 0x08, 0x01 };   /* CMsgClientHello{engine=1} */
    const u32 hello_type = 0x80000000u | C2B_HELLO_MSGID;
    static u8 dnbuf[512 * 1024];      /* ClientWelcome бывает большим (инвентарь) */

    u32 sent = 0, since = 0, got_dn_i = 0, got_dn_n = 0;

    for (u32 i = 0; i < g_hello_iters; i++) {
        /* 1) дренаж даунлинка — и до, и после посылок */
        for (u32 d = 0; d < 8; d++) {
            u32 mt = 0, rsz = 0;
            i32 rc = g_gc_orig_retr(g_gc_obj, &mt, dnbuf, (u32)sizeof(dnbuf),
                                    &rsz);
            if (rc != 1) break;                       /* 2=NoMessage и др. */
            u32 raw = mt & 0x7FFFFFFFu;
            if (!raw || !rsz) {
                /* run33: «пустые» записи (mt=0/rsz=0) — на новом steamclient
                 * очередь отдала 16 штук подряд. Это НЕ dn-сообщения: счёт
                 * их как dn навсегда блокировал ClientHello (dn>0 → state=2).
                 * Считаем отдельно, разово логируем, дренаж-тик прекращаем. */
                __atomic_fetch_add(&g_gc_dn_zero, 1u, __ATOMIC_RELAXED);
                if (!g_gc_zero_once) {
                    g_gc_zero_once = 1;
                    C2B_LOGS("[c2b] GC dn ZERO mt="); C2B_LOGH(mt);
                    C2B_LOGS("rsz="); C2B_LOGN(rsz);
                    C2B_LOGS("(не считаем dn — run33-аномалия)\n");
                }
                break;
            }
            __atomic_fetch_add(&g_gc_dn_n, 1u, __ATOMIC_RELAXED);
            __atomic_fetch_add(&g_gc_dn_b, rsz, __ATOMIC_RELAXED);
            c2b_gc_note(0, raw, rsz);
        }
        u32 dn_now = __atomic_load_n(&g_gc_dn_n, __ATOMIC_RELAXED);
        if (dn_now > got_dn_n) {
            got_dn_n = dn_now;
            if (!got_dn_i) {
                got_dn_i = i;
                __atomic_store_n(&g_hello_state, 2u, __ATOMIC_SEQ_CST);
                C2B_LOGS("[c2b] C2B-HELLO dn>0 n="); C2B_LOGN(dn_now); C2B_LOGS("\n");
            }
        }
        if (got_dn_i && i - got_dn_i >= g_hello_tail) break;

        /* 2) попытки ClientHello — ТОЛЬКО до первого dn (t42v10-fix: иначе
         * поздняя посылка затирала state=2 обратно в 1; после dn помогает
         * только дренаж) */
        if (!got_dn_i && sent < C2B_HELLO_TRIES &&
            since >= (sent ? g_hello_every : g_hello_pre)) {
            since = 0;
            sent++;
            __atomic_store_n(&g_hello_sends, sent, __ATOMIC_RELAXED);
            __atomic_store_n(&g_hello_state, 1u, __ATOMIC_SEQ_CST);
            i32 rc = g_gc_orig_send(g_gc_obj, hello_type, hello_body,
                                    (u32)sizeof(hello_body));
            if (rc == 1) {            /* k_EGCResultOK — учтём аплинк сами */
                __atomic_fetch_add(&g_gc_up_n, 1u, __ATOMIC_RELAXED);
                __atomic_fetch_add(&g_gc_up_b, (u32)sizeof(hello_body), __ATOMIC_RELAXED);
                c2b_gc_note(1, C2B_HELLO_MSGID, (u32)sizeof(hello_body));
            }
            C2B_LOGS("[c2b] C2B-HELLO send #"); C2B_LOGN(sent);
            C2B_LOGS("type=0x8000FA6 len=2 rc="); C2B_LOGD((u32)rc); C2B_LOGS("\n");
        } else if (sent >= C2B_HELLO_TRIES && since >= g_hello_every * 2) {
            break;                    /* 20с тишины после последней попытки */
        }
        since++;
        usleep(g_hello_tick_us);
    }
    if (!got_dn_i && sent >= C2B_HELLO_TRIES)
        __atomic_store_n(&g_hello_state, 3u, __ATOMIC_SEQ_CST);
    C2B_LOGS("[c2b] C2B-HELLO done state=");
    C2B_LOGD(__atomic_load_n(&g_hello_state, __ATOMIC_SEQ_CST));
    C2B_LOGS("sends="); C2B_LOGN(__atomic_load_n(&g_hello_sends, __ATOMIC_RELAXED));
    C2B_LOGS("dn="); C2B_LOGD(__atomic_load_n(&g_gc_dn_n, __ATOMIC_RELAXED));
    C2B_LOGS("\n");
}

static const char C2B_GC_VERPFX[] = "STEAMGAMECOORDINATOR_INTERFACE_VERSION";
static u8 c2b_gc_is_gcver(const char *v)
{
    for (u32 i = 0; C2B_GC_VERPFX[i]; i++)
        if (v[i] != C2B_GC_VERPFX[i]) return 0;
    return 1;
}

static void c2b_print_gcfini(void)
{
    u32 st = __atomic_load_n(&g_gc_state, __ATOMIC_SEQ_CST);
    if (!st && g_gc_mode && g_state) {
        /* t42v2: движок жил, GC так и не встал — машинный код причины */
        C2B_LOGS("[c2b] GC-ARM-FAIL rc="); C2B_LOGD(g_gc_last_fail); C2B_LOGS("\n");
    }
    C2B_LOGS("[c2b] GCFINI mode="); C2B_LOGS(st ? "observe" : (g_gc_mode ? "unarmed" : "off"));
    C2B_LOGS(" up="); C2B_LOGD(__atomic_load_n(&g_gc_up_n, __ATOMIC_RELAXED));
    C2B_LOGS(" dn="); C2B_LOGD(__atomic_load_n(&g_gc_dn_n, __ATOMIC_RELAXED));
    C2B_LOGS(" uniq="); C2B_LOGD(g_gc_uniq_n);
    C2B_LOGS(" t="); C2B_LOGN(g_gc_t_mode);
    C2B_LOGS(" dn_drop="); C2B_LOGD(__atomic_load_n(&g_gc_dn_drop, __ATOMIC_RELAXED));
    C2B_LOGS(" zero="); C2B_LOGD(__atomic_load_n(&g_gc_dn_zero, __ATOMIC_RELAXED));
    /* t42v8: итог ClientHello-craft (state 2 = dn-ответ получен) */
    C2B_LOGS(" hello="); C2B_LOGD(__atomic_load_n(&g_hello_state, __ATOMIC_RELAXED));
    C2B_LOGS("/"); C2B_LOGN(__atomic_load_n(&g_hello_sends, __ATOMIC_RELAXED));
    C2B_LOGS("\n");
}

/* ---------- аплинк v1: forged INetMessage + dispatcher ----------
 * RE-факты (engine_client64.so md5 0b508a09, step_g5c_netmsgpb_re.py):
 *  * m_Protobuf = this+0x8 (CNetMessage = только vptr; Move W2B @0x286720,
 *    Voice W2B @0x3a5da0 — оба lea 0x8(%rdi));
 *  * GetType = слот 8, КОНСТАНТА в коде (m_nMsgType-члена нет) -> in-place
 *    renum невозможен, только подмена объекта (forged);
 *  * SendNetMsg @0x4a3ea0 дергает у msg только слот 7 (IsReliable) и слот 6
 *    (WriteToBuffer); тип на провод пишет САМ WriteToBuffer сообщения:
 *    [varint32 type][varint32 size][protobuf bytes] (63f900 = bf_write::
 *    WriteVarInt32, 0x80-continuation; 63fe50 = чистый калькулятор длины);
 *  * хелперы-прямые вызовы: 1ef9f0 = protobuf ByteSizeLong(pb),
 *    1f4410 = SerializeWithCachedSizesToArray(pb, dst), 641840 =
 *    bf_write::WriteBytes(buf, data, len) — бит-позиция в buf любая;
 *  * якорь идентичности бинарника: пролог Move W2B @0x286720, 19 байт.
 * Схема v1: dispatcher сериализует исходный msg, прогоняет
 * c2b_uplink_translate (renum/дроп/пересборка Move/Voice/CI) и вызывает orig
 * с forged-объектом, чей WriteToBuffer пишет ГОТОВЫЙ CS2-поток байтами. */
static volatile uptr g2e_bytesize_p, g2e_serialize_p, g2e_writebytes_p;
static i32 g_up_mode = 0;                    /* 0=observe, 1=translate (C2B_UPLINK=1) */
static u32 g2_busy = 0;

typedef u32 (*c2b_e_bytesize_t)(uptr pb);
typedef void *(*c2b_e_serialize_t)(uptr pb, void *dst);
typedef i32 (*c2b_e_writebytes_t)(uptr buf, const void *data, u32 len);

#define C2B_UP_SIN_CAP  (64u * 1024u)
#define C2B_UP_SOUT_CAP (96u * 1024u)
static u8 g_up_sbuf[C2B_UP_SIN_CAP];         /* protobuf-байты исходного msg */
static u8 g_up_sframe[C2B_UP_SIN_CAP + 16];  /* [varint t][varint n][payload] */
static u8 g_up_sout[C2B_UP_SOUT_CAP];        /* CS2-поток от транслятора */

struct c2b_forge_t { uptr vt; i32 t; u32 rel; u32 len; const u8 *data; };

static void c2b_fg_dtor(uptr a, u32 b) { (void)a; (void)b; }
static void c2b_fg_set2(uptr a, uptr b) { (void)a; (void)b; }
static i32 c2b_fg_ret0(uptr a, uptr b, u32 c, u32 d) { (void)a;(void)b;(void)c;(void)d; return 0; }
static i32 c2b_fg_ret1(uptr a, uptr b, u32 c, u32 d) { (void)a;(void)b;(void)c;(void)d; return 1; }
static i32 c2b_fg_w2b(uptr self, uptr buf)
{
    struct c2b_forge_t *f = (struct c2b_forge_t *)self;
    if (!f->data || !f->len) return 1;       /* пустой поток = нечего писать */
    c2b_e_writebytes_t wb = (c2b_e_writebytes_t)(const void *)g2e_writebytes_p;
    if (!wb) return 0;
    return wb(buf, f->data, f->len);
}
static i32 c2b_fg_isrel(void *self) { return (i32)((struct c2b_forge_t *)self)->rel; }
static i32 c2b_fg_gettype(void *self) { return ((struct c2b_forge_t *)self)->t; }
static u32 c2b_fg_getsize(void *self) { return ((struct c2b_forge_t *)self)->len; }
static const char *c2b_fg_getname(void *self) { (void)self; return "C2BForge"; }
static const char *c2b_fg_tostr(void *self) { (void)self; return "c2b forged netmsg"; }

static const uptr g_fg_vt[14] = {
    (uptr)c2b_fg_dtor,      /* 0  ~INetMessage */
    (uptr)c2b_fg_dtor,      /* 1  ~INetMessage (deleting) */
    (uptr)c2b_fg_set2,      /* 2  SetNetChannel */
    (uptr)c2b_fg_set2,      /* 3  SetReliable */
    (uptr)c2b_fg_ret1,      /* 4  Process */
    (uptr)c2b_fg_ret0,      /* 5  ReadFromBuffer */
    (uptr)c2b_fg_w2b,       /* 6  WriteToBuffer -> [varint t][varint len][payload] */
    (uptr)c2b_fg_isrel,     /* 7  IsReliable */
    (uptr)c2b_fg_gettype,   /* 8  GetType */
    (uptr)c2b_fg_ret0,      /* 9  GetGroup */
    (uptr)c2b_fg_getname,   /* 10 GetName */
    (uptr)c2b_fg_ret0,      /* 11 GetNetChannel */
    (uptr)c2b_fg_tostr,     /* 12 ToString */
    (uptr)c2b_fg_getsize    /* 13 GetSize */
};

/* гистограмма v0 (бывший c2b_up_obs64, вызывается из dispatch) */
static void c2b_up_obs_note(i32 t, void *msg, u32 rel, u32 voi)
{
    if (t < 0 || t >= 64 || !msg) return;
    g_up_st.bytype[t]++;
    if (g_up_st.first[t] < 3) {
        g_up_st.first[t]++;
        uptr vt = *(uptr *)msg;
        const char *(*gn)(void *) = (const char *(*)(void *)) *(uptr *)(vt + 10 * sizeof(uptr));
        C2B_LOGS("[c2b] SNM t="); C2B_LOGN((u32)t);
        C2B_LOGS("name="); C2B_LOGS(gn ? gn(msg) : "?");
        C2B_LOGS("rel="); C2B_LOGN(rel);
        C2B_LOGS("vo=");  C2B_LOGN(voi);
        C2B_LOGS("\n");
    }
    if ((g_up_st.calls & 0x1FFF) == 0) {
        C2B_LOGS("[c2b] SNM hist:");
        for (u32 k = 0; k < 64; k++)
            if (g_up_st.bytype[k] != g_up_st.dump[k]) {
                C2B_LOGN(k); C2B_LOGS(":");
                C2B_LOGN(g_up_st.bytype[k] - g_up_st.dump[k]); C2B_LOGS(" ");
                g_up_st.dump[k] = g_up_st.bytype[k];
            }
        C2B_LOGS("\n");
    }
}

/* диспетчер аплинка: вызывается из c2b_up_hook_thunk (боевой) и из
 * selftest'а напрямую. Возвращает rv, который движок увидит из SendNetMsg. */
u64 c2b_up_dispatch(const void *blk)
{
    const uptr *b = (const uptr *)blk;
    uptr chan = b[4], msg = b[3];
    u32  rel_a = (u32)b[2], voice = (u32)b[1];
    c2b_fn4_t orig = (c2b_fn4_t)(const void *)g2_trampoline;

    g_up_st.calls++;
    {   /* R29: tid первого входа (гонка на флаге безвредна — двойной лог) */
        static u32 s_tid_seen = 0;
        if (!s_tid_seen) {
            s_tid_seen = 1;
            C2B_LOGS("[c2b] SNM tid="); C2B_LOGN(c2b_sys_gettid());
            C2B_LOGS("\n");
        }
    }
    if (!g_up_mode || !msg || !orig)
        return (u64)(u32)orig(chan, msg, rel_a, voice);

    uptr vt = *(uptr *)msg;
    i32 t = -1;
    if (vt) {
        i32 (*gt)(void *) = (i32 (*)(void *)) *(uptr *)(vt + 8 * sizeof(uptr));
        t = gt ? gt((void *)msg) : -1;
    }
    c2b_up_obs_note(t, (void *)msg, rel_a, voice);
    if (t < 0 || !vt)
        return (u64)(u32)orig(chan, msg, rel_a, voice);

    /* R29: CAS-trylock. Под локом: g_up_sbuf/sframe/sout + forged-объект.
 * Конкурентный SendNetMsg из другого потока / реентрантность -> passthrough
 * ИСХОДНОГО msg (zero-block). rival>0 в живом логе = 2-й поток отправки. */
    if (__atomic_exchange_n(&g2_busy, 1u, __ATOMIC_ACQ_REL) != 0u) {
        g_up_st.rival++;
        return (u64)(u32)orig(chan, msg, rel_a, voice);
    }
    u32 done = 0;
    i32 rv = 1;
    {
        c2b_e_bytesize_t  bsz = (c2b_e_bytesize_t)(const void *)g2e_bytesize_p;
        c2b_e_serialize_t ser = (c2b_e_serialize_t)(const void *)g2e_serialize_p;
        u32 n = (bsz && ser) ? bsz(msg + 8) : 0;
        if (n > 0 && n <= C2B_UP_SIN_CAP && ser) {
            ser(msg + 8, g_up_sbuf);
            u32 sl = 0;
            sl += c2b_write_varint(g_up_sframe + sl, (u32)t);
            sl += c2b_write_varint(g_up_sframe + sl, n);
            memcpy(g_up_sframe + sl, g_up_sbuf, n);
            sl += n;
            u32 olen = 0;
            i32 rc = c2b_uplink_translate(g_up_sframe, sl, g_up_sout,
                                          sizeof(g_up_sout), &olen);
            if (rc == 0 && olen == 0) {          /* дроп по карте */
                __atomic_store_n(&g2_busy, 0u, __ATOMIC_RELEASE);
                return 1;                        /* фейк-ОК движку */
            }
            if (rc == 0 && olen > 0) {
                g_fini2.up2_bsz += olen * 8;     /* up2{bsz}: сумма битов исходящих */
                g_fini2.up2_tr++;                /* up2{tr}: число транскодов */
                u32 ot = 0xFFFFFFFFu;
                c2b_read_varint(g_up_sout, olen < 5 ? olen : 5, &ot);
                i32 (*isrel)(void *) = (i32 (*)(void *)) *(uptr *)(vt + 7 * sizeof(uptr));
                u32 orel = isrel ? (u32)isrel((void *)msg) : rel_a;
                struct c2b_forge_t f;
                f.vt = (uptr)g_fg_vt;
                f.t = (ot == 0xFFFFFFFFu) ? t : (i32)ot;
                f.rel = orel ? 1u : 0u;
                f.len = olen;
                f.data = g_up_sout;
                rv = orig(chan, (uptr)(void *)&f, rel_a, voice);
                done = 1;
            }
            /* rc != 0 (trunc/капа) — не ожидается на 1 сообщении: passthrough */
        }
    }
    __atomic_store_n(&g2_busy, 0u, __ATOMIC_RELEASE);
    if (!done) rv = orig(chan, msg, rel_a, voice);
    return (u64)(u32)rv;
}

/* ---------- hook: v0 OBSERVER ---------- */
#if defined(__x86_64__) && !defined(C2B_SELFTEST)
/* Боевой x86_64 (SysV): this=rdi, bf_read=rsi, flag=dl. Stolen-байты (16) включают
 * mov %rsi,%r15 и mov %edx,%r13d — C-хук затрёт rsi/rdi/rdx до вызова трамплина,
 * поэтому вход — asm-тюнк: сохранить volatile, лог через C, восстановить и хвостом
 * jmp в трамплин (эпилог оригинала сам снимет фрейм и вернёт управление движку;
 * rv в v0 не логируем — вернётся напрямую движку). */
void c2b_obs64(const void *blk)
{
    const uptr *b    = (const uptr *)blk;
    uptr        self = b[4];                 /* [blk+0x20] = rdi (this) */
    bf_read_t  *br   = (bf_read_t *)b[3];    /* [blk+0x18] = rsi */
    u32         flag = (u32)b[2];            /* [blk+0x10] = rdx */
    (void)self; (void)flag;
    g_st.calls++;
    /* R30: дамп первых 8 вызовов + каждый 1024-й; head-hex только первые 4
     * (level 2 = как раньше, на каждый вызов). */
    if (c2b_vlog_hit(g_vlevel, g_st.calls, 8, 1024)) {
        C2B_LOGS("[c2b] PM this="); C2B_LOGH((u32)self);
        C2B_LOGS("bf=");   C2B_LOGH((u32)(uptr)br);
        C2B_LOGS("flag="); C2B_LOGN(flag);
        C2B_LOGS("bytes="); C2B_LOGN((u32)br->m_nDataBytes);
        C2B_LOGS("bits=");  C2B_LOGN((u32)br->m_nDataBits);
        C2B_LOGS("cur=");   C2B_LOGN(br->m_iCurBit);
        C2B_LOGS("ovf=");   C2B_LOGN(br->m_bOverflow ? 1u : 0u);
        C2B_LOGS("\n");
        if ((g_vlevel >= 2 || g_st.calls <= 4) &&
            br->m_pBuffer && br->m_nDataBytes) {
            C2B_LOGS("[c2b] head:");
            const u8 *d = (const u8 *)br->m_pBuffer;
            for (u32 i = 0; i < 24 && i < br->m_nDataBytes; i++) C2B_LOGH(d[i]);
            C2B_LOGS("\n");
        }
    }
}


__asm__(
".text\n"
".globl c2b_hook_thunk\n"
".type  c2b_hook_thunk,@function\n"
"c2b_hook_thunk:\n"          /* вход: rsp%16==8, [rsp]=ret-адрес движка */
"  endbr64\n"
"  sub  $0x50,%rsp\n"        /* блок 80 байт; rsp%16==0 */
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  mov  %rbp,0x48(%rsp)\n"
"  mov  %rsp,%rdi\n"
"  call c2b_obs64\n"         /* на входе в C rsp%16==8 (ret сверху) */
"  mov  0x48(%rsp),%rbp\n"
"  mov  0x40(%rsp),%r11\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x00(%rsp),%rax\n"
"  add  $0x50,%rsp\n"        /* rsp%16==8, ret-адрес движка сверху */
"  jmp  *c2b_trampoline_ptr(%rip)\n"
".size c2b_hook_thunk, .-c2b_hook_thunk\n"
".previous\n"
);
extern void c2b_hook_thunk(void);

/* ---------- hook: аплинк v1 (тюнк) ----------
 * SendNetMsg(this=rdi CNetChan*, msg=rsi INetMessage&, rel=rdx, voice=rcx).
 * Тюнк сохраняет volatile+rbp, вызывает c2b_up_dispatch(blk) (сам решает:
 * passthrough / дроп / подмена forged-объекта с вызовом трамплина) и
 * ВОЗВРАЩАЕТ его rv движку через ret (rsp выровнен по ABI до call). */
__asm__(
".text\n"
".globl c2b_up_hook_thunk\n"
".type  c2b_up_hook_thunk,@function\n"
"c2b_up_hook_thunk:\n"          /* вход: rsp%16==8, [rsp]=ret-адрес движка */
"  endbr64\n"
"  sub  $0x58,%rsp\n"          /* 88: rsp%16 -> 0 (call C по ABI) */
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  mov  %rbp,0x48(%rsp)\n"
"  mov  %rsp,%rdi\n"
"  call c2b_up_dispatch\n"     /* rv в rax */
"  mov  0x48(%rsp),%rbp\n"
"  add  $0x58,%rsp\n"
"  ret\n"                      /* снимаем ret-адрес движка, rv уже в rax */
".size c2b_up_hook_thunk, .-c2b_up_hook_thunk\n"
".previous\n"
);
extern void c2b_up_hook_thunk(void);
#endif /* боевой x86_64 */

i32 c2b_hook_sendnetmsg(uptr chan, uptr msg_i, u32 rel, u32 voice)
{
    c2b_fn4_t orig = (c2b_fn4_t)(const void *)g2_trampoline;
    g_up_st.calls++;
    (void)chan; (void)msg_i; (void)rel; (void)voice;
    /* v1 (C2B_MODE=rewrite): renum/дроп/пересборка CLC_Move до вызова orig.
       v0: сообщение не трогаем. */
    return orig(chan, msg_i, rel, voice);
}

/* ---------- downlink v1: ProcessMessages -> c2b_translate -> свой bf_read -> orig
 * Гейт: g_dn_mode (C2B_DOWNLINK=1 -> translate, иначе observe-passthrough).
 * Безопасность: любой сбой (trunc/oom/overflow/cur!=0/нет буфера/reentrancy)
 * -> passthrough ИСХОДНОГО потока движку. Статический буфер 256 КБ
 * (= NET_MAX_PAYLOAD S1), u32-массив -> выравнивание под bf_read.
 * Геометрия bf_read копируется из исходного (движок уже проинициализировал),
 * относительный сдвиг m_pDataIn-m_pBuffer сохраняется: конвенция prefetch
 * (DataIn=Buffer или Buffer+1) не угадывается, но и не важна. */
typedef struct {
    u32 calls, ok, pass, trunc, oom, bytes_in, bytes_out;
    u32 rival;   /* R29: CAS-конфликты trylock (доказательство 2-го потока) */
    u32 n_void;  /* t36/audit05: пустой перевод rc==0&&olen==0 (эталон void=; fail-closed) */
    u32 max_in, max_out; /* R31: пики размеров блока за прогон — запас до
                          * C2B_DN_CAP (256КБ) виден в FINI без гистограмм */
} c2b_dn_stats_t;
static volatile u32   g_dn_mode = 0;
static u32            g_dn_busy = 0;
static c2b_dn_stats_t g_dn_stats;
#define C2B_DN_CAP (1024u * 1024u)   /* R46 (t35): 256K -> 1M (пики G-4b/G-4d; 256K = старый NET_MAX_PAYLOAD S1) */
static u32 g_dn_buf[C2B_DN_CAP / 4];

i32 c2b_hook_process_messages(uptr chan, uptr brd_i, u32 flag)
{
    c2b_fn3_t  orig = (c2b_fn3_t)(const void *)g_trampoline;
    bf_read_t *br   = (bf_read_t *)(uptr)brd_i;

    g_st.calls++;
    g_dn_stats.calls++;
    {   /* R29: tid первого входа (гонка на флаге безвредна — двойной лог) */
        static u32 s_tid_seen = 0;
        if (!s_tid_seen) {
            s_tid_seen = 1;
            C2B_LOGS("[c2b] PM tid="); C2B_LOGN(c2b_sys_gettid());
            C2B_LOGS("\n");
        }
    }
    if (c2b_vlog_hit(g_vlevel, g_dn_stats.calls, 8, 1024)) {
        C2B_LOGS("[c2b] PM chan=");  C2B_LOGH(chan);
        C2B_LOGS("bf=");     C2B_LOGH(brd_i);
        C2B_LOGS("flag=");   C2B_LOGH(flag);
        C2B_LOGS("bytes=");  C2B_LOGN(br ? br->m_nDataBytes : 0);
        C2B_LOGS("bits=");   C2B_LOGN(br ? (u32)br->m_nDataBits : 0);
        C2B_LOGS("cur=");    C2B_LOGN(br ? br->m_iCurBit : 0);
        C2B_LOGS("ovf=");    C2B_LOGN((br && br->m_bOverflow) ? 1u : 0u);
        C2B_LOGS("\n");
        if ((g_vlevel >= 2 || g_dn_stats.calls <= 4) &&
            br && br->m_pBuffer && br->m_nDataBytes) {
            C2B_LOGS("[c2b] head:");
            const u8 *d = (const u8 *)br->m_pBuffer;
            for (u32 i = 0; i < 24 && i < br->m_nDataBytes; i++) C2B_LOGH(d[i]);
            C2B_LOGS("\n");
        }
    }
    if (g_dn_mode && br && br->m_pBuffer && !br->m_bOverflow &&
        br->m_iCurBit == 0 && br->m_nDataBytes && br->m_nDataBytes <= C2B_DN_CAP) {
        u8  *inb = (u8 *)br->m_pBuffer;
        u32  il  = (u32)br->m_nDataBytes;
        u32  olen = 0;
        /* R29: CAS-trylock ДО c2b_translate. Под локом: g_dn_buf + вся арена
         * FSV/G4b/G4d (два канала => два ProcessMessages => иначе гонка).
 * Конкурентный захват/реентрантность -> passthrough (zero-block, без спина).
 * rival>0 в живом логе = факт 2-го net-потока движка. */
        if (__atomic_exchange_n(&g_dn_busy, 1u, __ATOMIC_ACQ_REL) == 0u) {
        i32  rc  = c2b_translate(inb, il, (u8 *)g_dn_buf, C2B_DN_CAP, &olen, &g_st);
        if (rc == 0 && olen) {
            u32 din_off = (u32)(br->m_pDataIn - br->m_pBuffer);
            bf_read_t nb = *br;
            nb.m_pBuffer    = g_dn_buf;
            nb.m_pDataIn    = g_dn_buf + din_off;
            nb.m_pDataEnd   = (u32 *)((u8 *)g_dn_buf + olen);
            nb.m_nDataBytes = olen;
            nb.m_nDataBits  = olen << 3;
            nb.m_iCurBit    = 0;
            nb.m_bOverflow  = 0;
            nb.m_nBitsAvail = 32;
            nb.m_nInBufWord = g_dn_buf[0];
            g_dn_stats.ok++;
            g_dn_stats.bytes_in  += il;
            g_dn_stats.bytes_out += olen;
            if (il > g_dn_stats.max_in)     g_dn_stats.max_in = il;
            if (olen > g_dn_stats.max_out)  g_dn_stats.max_out = olen;
            /* R30: ok<=16 или каждый 512-й успех; остальное в FINI-статистике */
            if (c2b_vlog_hit(g_vlevel, g_dn_stats.ok, 16, 512)) {
                C2B_LOGS("[c2b] DN tr in="); C2B_LOGN(il);
                C2B_LOGS("out="); C2B_LOGN(olen);
                C2B_LOGS("m=");   C2B_LOGN(g_st.msgs_in);
                C2B_LOGS("/");    C2B_LOGN(g_st.msgs_out);
                C2B_LOGS("d=");   C2B_LOGN(g_st.dropped);
                C2B_LOGS("\n");
            }
            { i32 rv = orig(chan, (uptr)&nb, flag);
              __atomic_store_n(&g_dn_busy, 0u, __ATOMIC_RELEASE);
              return rv; }
        }
        if (rc == 0) {
            /* t36/audit05 (HIGH): пустой перевод (rc==0, olen==0) — ВСЕ сообщения
             * кадра дропнуты легитимно. Этиалонный счётчик void=; отдаём движку
             * ПУСТОЙ буфер (семантика F4) — passthrough исходного S2 кормил бы
             * движок сырыми CS2-id (ренум-хаос). */
            g_dn_stats.n_void++;
            bf_read_t nbv = *br;
            nbv.m_pBuffer    = g_dn_buf;
            nbv.m_pDataIn    = g_dn_buf;
            nbv.m_pDataEnd   = g_dn_buf;        /* 0 байт */
            nbv.m_nDataBytes = 0;
            nbv.m_nDataBits  = 0;
            nbv.m_iCurBit    = 0;
            nbv.m_bOverflow  = 0;
            nbv.m_nBitsAvail = 32;
            nbv.m_nInBufWord = 0;
            __atomic_store_n(&g_dn_busy, 0u, __ATOMIC_RELEASE);
            return orig(chan, (uptr)&nbv, flag);
        }
        if (rc == -2) {
            /* oom: passthrough исходника (диагностика потолка C2B_DN_CAP) —
             * осознанно вне F4; счётчик oom виден в FINI */
            g_dn_stats.oom++;
        } else if (rc == -1) {
            /* F4 (t35) fail-closed: кривой S2-поток движку НЕ отдаётся.
             * Дроп = движку уходит ПУСТОЙ буфер (0 сообщений) через orig —
             * честный rv, инварианты канала целы, мусора нет. */
            g_fini2.dn2_fc++;
            if (g_fini2.dn2_fc <= 8 || g_vlevel >= 2) {
                C2B_LOGS("[c2b] dn2 fc drop msg=");
                C2B_LOGN(g_st.msgs_in);
                C2B_LOGS("rc=");
                C2B_LOGH((u32)rc);
                C2B_LOGS("\n");
            }
            bf_read_t nbfc = *br;
            nbfc.m_pBuffer    = g_dn_buf;
            nbfc.m_pDataIn    = g_dn_buf;
            nbfc.m_pDataEnd   = g_dn_buf;        /* 0 байт */
            nbfc.m_nDataBytes = 0;
            nbfc.m_nDataBits  = 0;
            nbfc.m_iCurBit    = 0;
            nbfc.m_bOverflow  = 0;
            nbfc.m_nBitsAvail = 32;
            nbfc.m_nInBufWord = 0;
            __atomic_store_n(&g_dn_busy, 0u, __ATOMIC_RELEASE);
            return orig(chan, (uptr)&nbfc, flag);  /* НЕ исходный brd_i */
        } else {
            g_dn_stats.trunc++;
        }
        __atomic_store_n(&g_dn_busy, 0u, __ATOMIC_RELEASE);
        } else {
            g_dn_stats.rival++;      /* фактическое доказательство 2-го потока */
        }
    }
    g_dn_stats.pass++;
    /* R30: pass<=4 или каждый 1024-й; полный счётчик в FINI */
    if (c2b_vlog_hit(g_vlevel, g_dn_stats.pass, 4, 1024))
        C2B_LOGS("[c2b] DN passthrough\n");
    return orig(chan, brd_i, flag);
}

/* ============================================================ */
/* ---------- 41e-a: connectionless-слой v1 (сбор живых данных + passthrough) ----------
 *
 * Диагноз 41e: getchallenge/connect идут МИМО детур ProcessMessages/SendNetMsg
 * напрямую наружу -> CS2-сервер молча дропает сырой S1-хендшейк -> «connection
 * error after 30 retries». v1: перехват libc sendto/recvfrom (LD_PRELOAD ставит
 * нас в глобальный скоуп раньше libc), классификация 0xFFFFFFFF-датаграмм,
 * счётчики clu/clr + однострочный hexdump первых 32 connless-пакетов (или всех
 * при C2B_CL_VERBOSE=1) -> live-данные для connect-трансляции v2. Пакеты НЕ
 * модифицируются (passthrough).
 *
 * Границы v1:
 *   - хукаются только sendto/recvfrom (sendmsg/recvmmsg/writev — не в v1);
 *   - фильтр по семейству (AF_INET/AF_INET6) + префиксу FF FF FF FF; SO_TYPE
 *     не проверяем (0xFFFFFFFF в TCP-потоке этого процесса не бывает);
 *   - фильтры всегда возвращают PASSTHROUGH (каркас DROP/REWRITE для v2);
 *   - счётчики телеметрические (без атомиков: гонка = потерянный инкремент).
 * Рекурсия исключена: собственный путь — только C2B_LOGx (write в лог), сетевых
 * вызовов в трассировке нет. */

#ifdef C2B_SELFTEST
/* libc-заголовки выше уже дали size_t/ssize_t; socklen_t среди них нет —
 * совместимый с glibc тип. <sys/socket.h> по-прежнему не подключаем. */
typedef unsigned int socklen_t;
#else
/* -nostdlib: типы свои; ABI x86_64: ssize_t=long, size_t=unsigned long,
 * socklen_t=unsigned int (на i386 размеры совпадают с glibc). */
typedef long           ssize_t;
typedef unsigned long  size_t;
typedef unsigned int   socklen_t;
#endif

/* g32: типы хуков + ленивые резолвы — безусловно (нужны и selftest-хукам,
 * и .so-ветке; стоят ПОСЛЕ блока типов выше). ВАЖНО: struct sockaddr
 * объявляется НА ФАЙЛОВОМ СКОУПЕ ДО typedef — впервые-в-parameter-list
 * тип скоупится в прототип и не совпадает с файловым (урок сборки g32). */
struct sockaddr;
typedef ssize_t (*c2b_sendto_fn)(int, const void *, size_t, int,
                                 const struct sockaddr *, socklen_t);
typedef ssize_t (*c2b_recvfrom_fn)(int, void *, size_t, int,
                                   struct sockaddr *, socklen_t *);
/* 43f-g40: ABI-копия glibc msghdr/iovec (x86-64) для хука sendmsg —
 * GNS-путь nChunks!=1 шлёт через sendmsg (PLT 0xd9dfc0 @0x1fcd1ee). */
struct c2b_iovec { void *iov_base; size_t iov_len; };
struct c2b_msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct c2b_iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};
typedef ssize_t (*c2b_sendmsg_fn)(int, const struct c2b_msghdr *, int);

/* ленивый резолв реальных функций: 0=ещё не пробовали, 1=не нашли (dlsym
 * вернул NULL), иначе адрес. Гонка первого вызова безвредна: оба потока
 * пишут одно и то же значение (x86: выровненный сторов атомарен). */
static void *g_clp_sendto;
static void *g_clp_recvfrom;
static void *g_clp_fouif;       /* SteamInternal_FindOrCreateUserInterface (g32a) */

/* ABI-совместимое с glibc описание (netpacket-адрес приходит из движка) */
struct sockaddr { unsigned short sa_family; char sa_data[14]; };
#define C2B_AF_INET   2
#define C2B_AF_INET6  10

#define C2B_CL_DUMP_MAX  96    /* байт payload в hexdump (однострочный) */
#define C2B_CL_LOG_FIRST 32    /* первые N connless-пакетов логируем всегда */

/* классы uplink (по payload после 4-байтного префикса) */
#define C2B_CLQ_NONE       0   /* не connless */
#define C2B_CLQ_CHALLENGE  1   /* "getchallenge" */
#define C2B_CLQ_CONNECT    2   /* "connect ..." */
#define C2B_CLQ_RCON       3   /* "rcon ..." */
#define C2B_CLQ_OTHER      4   /* прочее (A2S-запросы 'T'/'W', ... ) */
#define C2B_CLQ_QCONNECT   5   /* "qconnect0x%08X" — запрос челленджа S1 CS:GO legacy
                                * (41e-b: строка @0x937239, CL_SendConnectPacket @0x24aa20;
                                * классического "getchallenge" в бинаре НЕТ) */
#define C2B_CLQ_JOIN       6   /* 'j'+14-символов: JOIN-запрос (ферма run 65: движок
                                * шлёт 'j' после real-'A' с "connect0x"-строкой) */

/* классы downlink (по первому байту payload; грубая таблица Source) */
#define C2B_CLR_NONE       0   /* не connless */
#define C2B_CLR_CHALLENGE  1   /* 'A' S2C_CHALLENGE (+ challenge#) */
#define C2B_CLR_REJECT     2   /* 'B' S2C_CONNREJECT / '9' S2C_REJECT_* */
#define C2B_CLR_SINFO      3   /* 'C' S2C_SERVERINFO */
#define C2B_CLR_INFO       4   /* 'm'/'O'/'I' A2S-ответы */
#define C2B_CLR_OTHER      5   /* прочее (живые данные v1 уточнят таблицу) */

/* решения фильтра (v2: REWRITE под connect-трансляцию) */
#define C2B_CL_PASSTHROUGH 0
#define C2B_CL_DROP        1
#define C2B_CL_REWRITE     2   /* зарезервировано, в v1 не возвращается */

/* счётчики (FINI: clu{...} clr{...}) */
static u32 g_cl_s_total, g_cl_s_cl, g_cl_s_gc, g_cl_s_qc, g_cl_s_cn, g_cl_s_rc, g_cl_s_ot, g_cl_s_drop;
static u32 g_cl_s_jn;
static u32 g_cl_r_total, g_cl_r_cl, g_cl_r_ch, g_cl_r_rj, g_cl_r_si, g_cl_r_in, g_cl_r_ot, g_cl_r_drop;
static u32 g_cl_log_n;         /* сколько connless уже прошло через trace (1-based) */
static u32 g_cl_verbose;       /* C2B_CL_VERBOSE=1 (читается в c2b_main) */

static i32 c2b_cl_is_connless(const u8 *p, u32 n)
{
    return (n >= 4 && p[0] == 0xFF && p[1] == 0xFF && p[2] == 0xFF && p[3] == 0xFF) ? 1 : 0;
}

/* префиксный матч с границей длины (payload может кончиться раньше строки) */
static i32 c2b_cl_pfx(const u8 *p, u32 n, const char *s)
{
    u32 i = 0;
    while (s[i]) {
        if (i >= n || p[i] != (u8)s[i]) return 0;
        i++;
    }
    return 1;
}

static i32 c2b_cl_class_up(const u8 *p, u32 n)
{
    if (!c2b_cl_is_connless(p, n)) return C2B_CLQ_NONE;
    p += 4; n -= 4;
    if (c2b_cl_pfx(p, n, "getchallenge")) return C2B_CLQ_CHALLENGE;
    if (c2b_cl_pfx(p, n, "qconnect0x"))   return C2B_CLQ_QCONNECT;
    if (n >= 1 && p[0] == 'k')            return C2B_CLQ_CONNECT;  /* CS:GO 'k'-connect! */
    if (n >= 1 && p[0] == 'j')            return C2B_CLQ_JOIN;     /* 'j'+token join */
    if (c2b_cl_pfx(p, n, "connect"))      return C2B_CLQ_CONNECT;
    if (c2b_cl_pfx(p, n, "rcon"))         return C2B_CLQ_RCON;
    return C2B_CLQ_OTHER;
}

static i32 c2b_cl_class_dn(const u8 *p, u32 n)
{
    if (!c2b_cl_is_connless(p, n)) return C2B_CLR_NONE;
    p += 4; n -= 4;
    if (!n) return C2B_CLR_OTHER;              /* голый префикс без ответа */
    switch (p[0]) {
    case 'A': return C2B_CLR_CHALLENGE;
    case 'B': return C2B_CLR_REJECT;
    case '9': return C2B_CLR_REJECT;
    case 'C': return C2B_CLR_SINFO;
    case 'm': case 'O': case 'I': return C2B_CLR_INFO;
    default:  return C2B_CLR_OTHER;
    }
}

static const char *c2b_cl_up_name(i32 c)
{
    switch (c) {
    case C2B_CLQ_CHALLENGE: return "getchallenge";
    case C2B_CLQ_QCONNECT:  return "qconnect";
    case C2B_CLQ_JOIN:      return "join";
    case C2B_CLQ_CONNECT:   return "connect";
    case C2B_CLQ_RCON:      return "rcon";
    case C2B_CLQ_OTHER:     return "other";
    default:                return "none";
    }
}

static const char *c2b_cl_dn_name(i32 c)
{
    switch (c) {
    case C2B_CLR_CHALLENGE: return "challenge";
    case C2B_CLR_REJECT:    return "reject";
    case C2B_CLR_SINFO:     return "sinfo";
    case C2B_CLR_INFO:      return "info";
    case C2B_CLR_OTHER:     return "other";
    default:                return "none";
    }
}

/* 41e-a: passthrough v1. Каркас решений для v2:
 *   uplink  getchallenge -> passthrough (ответ сервера живой);
 *   uplink  connect      -> v2: REWRITE (S2-формат из живых дампов v1);
 *   downlink 'A'/'C'/'9' -> passthrough; v2: REWRITE под ожидания S1-движка. */
static i32 c2b_cl_filter_uplink(const u8 *p, u32 n)
{
    switch (c2b_cl_class_up(p, n)) {
    case C2B_CLQ_CHALLENGE: return C2B_CL_PASSTHROUGH;
    case C2B_CLQ_CONNECT:   return C2B_CL_PASSTHROUGH;   /* v2: C2B_CL_REWRITE */
    case C2B_CLQ_RCON:      return C2B_CL_PASSTHROUGH;
    case C2B_CLQ_OTHER:     return C2B_CL_PASSTHROUGH;
    default:                return C2B_CL_PASSTHROUGH;
    }
}

static i32 c2b_cl_filter_downlink(const u8 *p, u32 n)
{
    switch (c2b_cl_class_dn(p, n)) {
    case C2B_CLR_CHALLENGE: return C2B_CL_PASSTHROUGH;
    case C2B_CLR_REJECT:    return C2B_CL_PASSTHROUGH;
    case C2B_CLR_SINFO:     return C2B_CL_PASSTHROUGH;
    case C2B_CLR_INFO:      return C2B_CL_PASSTHROUGH;
    case C2B_CLR_OTHER:     return C2B_CL_PASSTHROUGH;
    default:                return C2B_CL_PASSTHROUGH;
    }
}

/* однострочный hex+ascii: "ff ff .. | ...getchalleng.." (непечатное -> '.').
 * Возвращает длину строки без NUL; out всегда NUL-терминирован. */
static u32 c2b_cl_hexline(const u8 *p, u32 n, char *out, u32 cap)
{
    static const char hx[] = "0123456789abcdef";
    u32 o = 0, i;
    if (n > C2B_CL_DUMP_MAX) n = C2B_CL_DUMP_MAX;
    for (i = 0; i < n && o + 3 < cap; i++) {       /* "xx " на байт */
        out[o++] = hx[p[i] >> 4];
        out[o++] = hx[p[i] & 15];
        out[o++] = ' ';
    }
    if (o + 2 < cap) { out[o++] = '|'; out[o++] = ' '; }
    for (i = 0; i < n && o + 1 < cap; i++) {
        u8 c = p[i];
        out[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    out[o < cap ? o : cap - 1] = 0;
    return o < cap ? o : cap - 1;
}

/* счётчики классов + лог: первые C2B_CL_LOG_FIRST пакетов всегда, дальше
 * только при C2B_CL_VERBOSE=1. Только C2B_LOGx — сетевых вызовов нет. */
static void c2b_cl_trace(i32 up, const u8 *p, u32 n, i32 act)
{
    i32 cls;
    if (up) {
        cls = c2b_cl_class_up(p, n);
        if (cls == C2B_CLQ_CHALLENGE)      g_cl_s_gc++;
        else if (cls == C2B_CLQ_QCONNECT)  g_cl_s_qc++;
        else if (cls == C2B_CLQ_JOIN)      g_cl_s_jn++;
        else if (cls == C2B_CLQ_CONNECT)   g_cl_s_cn++;
        else if (cls == C2B_CLQ_RCON)      g_cl_s_rc++;
        else                               g_cl_s_ot++;
    } else {
        cls = c2b_cl_class_dn(p, n);
        if (cls == C2B_CLR_CHALLENGE)      g_cl_r_ch++;
        else if (cls == C2B_CLR_REJECT)    g_cl_r_rj++;
        else if (cls == C2B_CLR_SINFO)     g_cl_r_si++;
        else if (cls == C2B_CLR_INFO)      g_cl_r_in++;
        else                               g_cl_r_ot++;
    }
    u32 idx = ++g_cl_log_n;
    if (!g_cl_verbose && idx > C2B_CL_LOG_FIRST) return;
    char ln[C2B_CL_DUMP_MAX * 3 + C2B_CL_DUMP_MAX + 8];   /* 288 + 2 + 96 + NUL */
    c2b_cl_hexline(p, n, ln, (u32)sizeof(ln));
    C2B_LOGS("[c2b] CL "); C2B_LOGS(up ? "up" : "dn");
    C2B_LOGS(" #"); C2B_LOGN(idx);
    C2B_LOGS(" len="); C2B_LOGN(n);
    C2B_LOGS(" "); C2B_LOGS(up ? c2b_cl_up_name(cls) : c2b_cl_dn_name(cls));
    C2B_LOGS(" act="); C2B_LOGN((u32)act);
    C2B_LOGS(" | "); C2B_LOGS(ln); C2B_LOGS("\n");
}

extern i32 *__errno_location(void);   /* libc TLS-errno; errno.h не тянем */

/* ---------- 41e-c: CL v2 phase A — S1 qconnect -> S2 GNS challenge ----------
 * Эмпирика 2026-10-04 против ЖИВОГО CS2 152.233.19.133:28022 (CYBERSHOKE 5x5):
 *   сервер игнорирует S1 qconnect/getchallenge (S1-поток ему нечем понять),
 *   но ОТВЕЧАЕТ по GNS-проводу (GameNetworkingSockets, Valve — совпадает
 *   байт-в-байт, k_nCurrentProtocolVersion=13):
 *     ChallengeRequest = 0x20 [u16 pb_len][pb][pad] >= 512Б, pb =
 *       CMsgSteamSockets_UDP_ChallengeRequest {1: fixed32 connection_id (!=0),
 *        3: fixed64 my_timestamp, 4: varint protocol_version=13}
 *     ChallengeReply   = 0x21 [pb] {1: fixed32 connection_id (эхо),
 *       2: fixed64 challenge, 3: fixed64 your_timestamp (эхо), 4: varint 13}
 *   (проверено живьём из песочницы: 0x21 с нашим conn_id/ts и challenge
 *   0xe22fccfec1f5470c и др.)
 *   ConnectRequest = 0x22 [pb] БЕЗ crypt/cert сервер МОЛЧА роняет (проверено
 *   3 варианта: с length-заголовком, чистый, с crypt-без-подписи) — фаза B
 *   (x25519 + cert + auth ticket) вне scope phase A.
 *   Challenge привязан к адресу источника (SipHash) и живёт ~4s -> шлём
 *   ChallengeRequest С ТОГО ЖЕ fd, ответ принимаем только на нём же.
 * Перевод phase A (kill-switch C2B_CL_V2=1, по умолчанию OFF):
 *   uplink   qconnect0x…    -> подавить, послать S2 ChallengeRequest (тот fd)
 *   downlink 0x21 (на fd)   -> движку S1 S2C_CHALLENGE: ff ff ff ff 'A'+le32
 *   uplink   connect <ch>…  -> капчер (hexdump + счётчик) и ДРОП (фаза B
 *                              построит из него ConnectRequest с crypt)
 */
static u32 g_clv2_enable;        /* C2B_CL_V2=1 */
static u32 g_clv2_conn_id;       /* cid последнего ChallengeRequest */
static i32 g_clv2_fd = -1;       /* fd, с которым связан обмен */
static u64 g_clv2_ch64;          /* challenge сервера */
static u32 g_clv2_ch32;          /* что отдали движку в 'A' */
static u32 g_clv2_sent_req, g_clv2_got_ch, g_clv2_cap_connect, g_clv2_badreply;
static u32 g_clv2_fwdk, g_clv2_fwd_k;   /* g30: 'k'->target raw-forward exp */
static u32 g_clv2_fmt;           /* C2B_CLV2_FMT: вариант формата 'A'-ответа */
static u32 g_clv2_qc_val;        /* хвост qconnect0x%08X от движка (эхо-кандидат) */
static u32 g_clv2_phase;         /* 0=idle 1='A' 2=ждём reply для 'i' 3='i' доставлен
                                  * 4=ждём reply для reserve-'A' 5=reserve-'A' доставлен */
static u64 g_clv2_phase_ms;      /* мгновение смены фазы (ms монотонные) */
static u8 g_clv2_dst[16];        /* адрес CS2-цели (из qconnect), сырые байты */
static socklen_t g_clv2_dstlen;
static u32 g_clv2_k;             /* C2B_CLV2_K: длина филлера перед строкой (поиск N) */
static u32 g_clv2_baits;         /* C2B_CLV2_BAITS=1: фазы 2/4/6 ('i'/reserve-'A'/'B').
                                  * ПО УМОЛЧАНИЮ ВЫКЛ: run 80 показал, что байты,
                                  * посланные через 1.5с после fmt9-'A', клоббят
                                  * развивающуюся реакцию движка (ферма между
                                  * пушами всегда держит consume_gap) */
static char g_a2s_ver[24] = "1.38.0.4"; /* C2B_A2S_VERSION — версия бандла */
static u32 g_clv2_bhex;          /* C2B_CLV2_BHEX: хвост 'b' 0=AAAAAAAA 1=challenge 2=qc_val */
/* ---------- 41f-g31: S2 0x22 ConnectRequest из моста (фаза B, перевод) ----------
 * Факты (worklog + run168/170): S1 'k' на wire цели ПОЛНОСТЬЮ (513B, snaplen-80
 * в pcap был артефактом захвата, incl=128) — сервер МОЛЧИТ; 0x20->0x21 работает
 * (cid-эхо, СВЕЖИЙ challenge на каждый cid, replies парами); 0x22 без crypt/cert
 * сервер роняет молча (3 варианта 2026-10-04 — НО фрейминг тех проб не
 * документирован; g31 шлёт канонический фрейминг как у работающего 0x20).
 * g31: C2B_CLV2_CR=1 bare {1 cid,3 ch,4 ts,5 pv=13,8 steamid}
 *      C2B_CLV2_CR=2 + f7 crypt = CMsgSteamDatagramSessionCryptInfoSigned
 *        {1: key_info = CMsgSteamDatagramSessionCryptInfo {1: key_type=1
 *         CURVE25519, 2: key_data = наш x25519 pubkey (RFC 7748, ключ НАШ —
 *         пригоден для ECDH, если сервер ответит 0x23)}, signature НЕТ (нет
 *         серта — серверный IP_AllowWithoutAuth? эксперимент)}
 * Вердикт-лог: любой 0x23/0x24/0x25 на g_clv2_fd -> hexline (0x23 ConnectOK =
 * ДЖЕКПОТ; 0x24 Closed = причина = точный оставшийся gap; тишина = нужен
 * подписной серт -> следующий трек: реальный cert+crypt движка). */
static u32 g_clv2_cr;            /* C2B_CLV2_CR: 0=off 1=bare 2=+crypt */
static u32 g_clv2_cr_sent;       /* сколько 0x22 ушло */
static u64 g_clv2_cr_last_ms;    /* темп: не чаще 1/250ms */
static u32 g_clv2_cr_pending;    /* 1 = послали 0x20 с 'k'-капчера, ждём 0x21 -> 0x22 */
static u64 g_clv2_sid64;         /* legacy_client_steam_id (из 'k' или C2B_CLV2_SID) */
static u8 g_clv2_cr_priv[32];    /* x25519 priv (variant 2) */
static u8 g_clv2_cr_pub[32];     /* x25519 pub */
struct c2b_clv2_chrec { u32 cid; u32 valid; u64 ch, ts, ms; };
static struct c2b_clv2_chrec g_clv2_chrec[4];   /* кольцо свежих ChallengeReply */
static u32 g_clv2_chrec_i;
/* 41f-d: длина ПОСЛЕДНЕГО 'A'-пейлоада, отданного движку через recvfrom-хук.
 * RE 'B'-хендлера (0x25a8b0, engine 34a96ae): чеки B[0x1c]==snap[0x1c]∈{1..3},
 * B[0x18]==0&&snap[0x18]==0, B.u64[0x0c]==snap.u64[0x0c], B.u32[0x14]==snap[0x14]
 * — это ЗАГОЛОВОК netpacket (netadr from@0x00 + метаданные 0x0c..0x1f), который
 * движок строит сам из реального recv. Единственное управляемое отличие между
 * датаграммами 'A' и 'B' — РАЗМЕР (recvfrom return): 'A' шёл len=59/40, 'B'
 * возвращался len=14 → u64@0x0c (скорее всего size) не сходился → молчаливый
 * фейл. Фикс: паддить 'B' нулями до длины последнего 'A' (хвост битов парсер
 * не читает). */
static u32 g_clv2_last_A_len;
/* 41e-m: INFO-PUSH — ферма пушит 'I'-блоб в сокеты движка UNSOLICITED и
 * движок ЕГО ПОТРЕБЛЯЕТ (run 72: CL dn #f4-8 «info» = ACK в консоли +
 * прогресс флоу). Движок сам A2S НЕ шлёт (ни в ферме, ни в мосту),
 * клиент на цель UDP не ходит (run 90: relay q=0) — значит мост обязан
 * сам доставить info в recvfrom движка. */
static u8 g_ipush_buf[160];      /* собранный 'I'-блоб */
static u32 g_ipush_len;          /* 0 = не собран */
static u32 g_ipush_left;         /* сколько раз осталось вытолкнуть */
static u64 g_ipush_last_ms;      /* темп: не чаще 2с */
static u8 g_ipush_abuf[128];     /* 41e-o: буфер fmt9-'A' для чередования A/I */
static u8 g_a2s_peer[16];        /* sockaddr, куда движок послал A2S 'T' */
static socklen_t g_a2s_peerlen;
static u32 g_a2s_seen_t;         /* 'T' замечен — peer валиден */

/* ---------- 41f-a: AUTH-TICKET CAPTURE (SteamUser022) ----------
 * Run 62 lesson: 'k'-connect требует Steam auth session ticket. Run 93:
 * движок потребляет 'A'/info/'i'/'j'/reserve/'B' но 'k' НЕ СТРОИТ и уходит
 * в LanSearch; в libc-хуках тикет-путь не виден. Фаза B (б): капчурим
 * ISteamUser* в FUv-интерцепторе (SteamUser022 заведомо проходит через
 * SteamInternal_FindOrCreateUserInterface) и ВЫЗЫВАЕМ GetAuthSessionTicket
 * сами — доказательство, что тикет-путь жив из процесса движка, плюс
 * капчуренный тикет = ингредиент для S2 ConnectRequest (0x22).
 * Модель vtable ISteamUser (v020-022): 0=GetHSteamUser 1=BLoggedOn
 * 2=GetSteamID(u64 в RAX) ... 11=GetAuthSessionTicket(void*,int,u32*,
 * const SteamNetworkingIdentity*). В x86-64 SysV лишний регистровый арг
 * безвреден, поэтому 4-арг вызов безопасен и для 3-арг-имплантаций.
 * SANITY перед тикетом: GetSteamID обязан вернуть 0x01100001xxxxxxxx
 * (universe/public + account) — иначе индекс-модель неверна и тикет НЕ
 * зовём (защита от вызова мусора). */
static void *g_steamuser_obj;    /* ISteamUser*, капчурится в FUv */
static int g_steamuser_user;     /* g32: HSteamUser из того же FOUIF-вызова */
static void *g_steamnetsock_obj; /* g32: ISteamNetworkingSockets*, капчур в FUv */
static u32  g_steamuser_seen;    /* капчур случился */
static u32  g_ticket_calls;      /* вызовов GetAuthSessionTicket */
static u32  g_ticket_ok;         /* с ненулевым handle */
static u32  g_ticket_len;        /* длина последнего тикета */
static u8   g_ticket_buf[2048];  /* последний тикет (полный, до 2048Б) */

/* ---------- 41f-f: GNS-СПЬЮ через ISteamNetworkingUtils ----------
 * Run 99 (6492195): тикет добыт (slot 13, 252Б, наш steamid внутри), GNS-серт
 * есть, SDR OK — но движок по-прежнему аборитит GNS-хендшейк с целью между
 * ChallengeReply(0x21) и ConnectRequest(0x22) (retry с новым connection_id,
 * 0x22 НИКОГДА не летит). +sdr_spew_level 7 spew не дал (конвар не路由ит в
 * condebug-консоль). Решение: капчурим ISteamNetworkingUtils в FUv и
 * САМИ ставим debug-callback: SetDebugOutputFunction(5 = Verbose, our_cb)
 * — vt[1] в ISteamNetworkingUtils003/004 (vt[0]=GetTimestamp безобиден).
 * ГНС начнёт спьюить ВСЕ решения стейт-машины (в т.ч. причину аборта
 * ChallengeReply->ConnectRequest) прямо в наш лог. */
static void *g_steamnetutils_obj;   /* ISteamNetworkingUtils*, FUv */
static u32  g_steamnetutils_seen;
static volatile u32 g_gns_spew_n;   /* 41f-g7e: живость спью (все копии) */

static void c2b_gns_spew(i32 lvl, const char *msg)
{
    u32 n = 0;
    if (!msg) return;
    g_gns_spew_n++;   /* 41f-g7e: счётчик живости (безопасно: потерянные инкременты ок) */
    while (msg[n] && n < 4096u) n++;
    C2B_LOGS("[c2b] GNS["); C2B_LOGN((u32)lvl); C2B_LOGS("] ");
    C2B_LOGS(msg);
    if (n && msg[n - 1] != '\n') C2B_LOGS("\n");
}

/* 41f-g34v2: хук ЛИБЕЙНОГО спью-канала GNS. RE run178: 0x1fce3a0 — тонкая
 * обёртка (вариадик-сейв) -> call *0x2c6dcd0; сеттер 0x1fce440 пишет ПАРУ
 * (level @0x2c6dcc8, fn @0x2c6dcd0). Дефолтный fn = стёамовский логгер
 * (невидим нам). Сигнатура вызова: fn(rdi=level, rsi=1, rdx=0, rcx=0,
 * r8=fmt, r9=va_list). Наш хук vsnprintf-ит и пишет в лог. */
static void c2b_gns_libspew_hook(u32 a, u32 b, void *c, void *d,
                                 const char *fmt, void *va)
{
    char buf[1024];
    i32 n;
    (void)b; (void)c; (void)d;
    if (!fmt) return;
    g_gns_spew_n++;
    n = vsnprintf(buf, sizeof(buf) - 2, fmt, va);
    if (n < 0) return;
    if (n > 1000) n = 1000;
    if (buf[n - 1] != '\n') { buf[n] = '\n'; buf[n + 1] = 0; }
    C2B_LOGS("[c2b] GNSLIB["); C2B_LOGN(a); C2B_LOGS("] ");
    C2B_LOGS(buf);
}

static i32 c2b_ver_pfx(const char *ver, const char *pfx)
{
    u32 i = 0;
    if (!ver) return 0;
    while (pfx[i]) {
        if (ver[i] != pfx[i]) return 0;
        i++;
    }
    return 1;
}

/* ---------- 41f-c: SEGV-защита probe-вызовов vtable ----------
 * Run 96 (60807ef): vt[11] НЕ GetAuthSessionTicket в ISteamUser022 бандла —
 * gdb: c2b_auth_thread -> steamclient.so x3 -> __memcpy_avx SEGV (импл
 * интерпретировал аргументы иначе и писал в мусорный указатель; модель
 * верна до индекса 2 — BLoggedOn/GetSteamID вернули sane значения, значит
 * между GetSteamID и voice-блоком вставлены методы). Фикс: probe
 * последовательности индексов под временной SIGSEGV-ловушкой
 * (__sigsetjmp/siglongjmp): крашнутый вызов не роняет процесс, логируем
 * индекс и переходим к следующему. Стартовый индекс = C2B_AUTH_VTIDX
 * (харнесс декодирует точный слот из wrapper'а SteamAPI_ISteamUser_*
 * libsteam_api.so, если найдёт её на раннере; дефолт 11).
 * В selftest-сборке (настоящие libc-хедеры) блок стабится. */
#ifndef C2B_SELFTEST
struct c2b_sigaction {          /* glibc x86-64 layout */
    uptr handler;               /* sa_handler / sa_sigaction (union @0) */
    u8   mask[128];             /* sa_mask (sigset_t) */
    u32  flags;                 /* sa_flags; SA_SIGINFO = 4 */
    uptr restorer;              /* sa_restorer */
};
static u8  g_probe_jb[512] __attribute__((aligned(16)));
static u8  g_probe_active;

static void c2b_probe_segv(i32 sig, void *si, void *uc)
{
    (void)sig; (void)si; (void)uc;
    if (g_probe_active) {
        g_probe_active = 0;
        siglongjmp(g_probe_jb, 1);
    }
    /* не наш контекст: возврат = refault-спин (run134/135 SIGKILL-клон).
     * Восстанавливаем SIG_DFL и возвращаемся — повторныи фолт убьёт процесс
     * ШТАТНО (core/dmesg), с честным ip==fault. */
    {
        struct c2b_sigaction dfl;
        u32 t;
        for (t = 0; t < sizeof(dfl); t++) ((u8 *)&dfl)[t] = 0;
        dfl.handler = 0;                       /* SIG_DFL */
        dfl.flags = 0;
        sigemptyset(dfl.mask);
        sigaction(11, &dfl, (void *)0);
    }
}

static u32 g_auth_vtidx = 13;    /* C2B_AUTH_VTIDX: стартовый слот probe.
 * 41f-e: run 97 эмпирика — 14=BeginAuthSession(h=1 InvalidTicket), 15/16=void
 * (stale rax), 17=UserHasLicenseForApp(h=2); 11=DecompressVoice (memcpy-SEGV
 * run 96). SDK-нумерация ISteamUser: 13 = GetAuthSessionTicket. */

static void c2b_auth_ticket_probe(void)
{
    u64 sid_self = ((u64 (*)(void *))(*(void ***)g_steamuser_obj)[2])(g_steamuser_obj);
    u8 ident[16];
    u32 t4, att;
    struct c2b_sigaction sa, oldsa;
    u8 have_old;
    for (t4 = 0; t4 < sizeof(ident); t4++) ident[t4] = 0;
    ident[0] = 3;                                  /* k_ESteamNetworkingIdentityType_SteamID */
    for (t4 = 0; t4 < 8; t4++) ident[8 + t4] = (u8)(sid_self >> (8 * t4));
    for (t4 = 0; t4 < sizeof(sa); t4++) ((u8 *)&sa)[t4] = 0;
    for (t4 = 0; t4 < sizeof(oldsa); t4++) ((u8 *)&oldsa)[t4] = 0;
    sa.handler = (uptr)c2b_probe_segv;
    sa.flags = 4;                                  /* SA_SIGINFO */
    sigemptyset(sa.mask);
    have_old = (sigaction(11, &sa, &oldsa) == 0);  /* SIGSEGV = 11 */
    for (att = 0; att < 4 && g_ticket_ok == 0; att++) {
        u32 idx = g_auth_vtidx + att;
        u32 tlen = 0, h;
        if (att) usleep(5000000);
        tlen = 0;
        g_probe_active = 1;
        if (__sigsetjmp(g_probe_jb, 1) == 0) {
            h = ((u32 (*)(void *, void *, i32, u32 *, void *))(*(void ***)g_steamuser_obj)[idx])(
                g_steamuser_obj, g_ticket_buf, (i32)sizeof(g_ticket_buf),
                &tlen, ident);
            g_probe_active = 0;
        } else {
            g_probe_active = 0;
            C2B_LOGS("[c2b] AUTH: slot "); C2B_LOGN(idx);
            C2B_LOGS(" segv — not GetAuthSessionTicket\n");
            usleep(5000000);                       /* дать имплу отпустить локи */
            continue;
        }
        g_ticket_calls++;
        C2B_LOGS("[c2b] AUTH: slot "); C2B_LOGN(idx);
        C2B_LOGS("GetAuthSessionTicket h="); C2B_LOGN(h);
        C2B_LOGS(" len="); C2B_LOGN(tlen);
        if (h && tlen && tlen <= sizeof(g_ticket_buf)) {
            char ln[C2B_CL_DUMP_MAX * 3 + C2B_CL_DUMP_MAX + 8];
            u32 rep;
            g_ticket_ok++;
            g_ticket_len = tlen;
            c2b_cl_hexline(g_ticket_buf, tlen, ln, (u32)sizeof(ln));
            C2B_LOGS(" ticket "); C2B_LOGS(ln); C2B_LOGS("\n");
            for (rep = 0; rep < 2 && g_ticket_ok < 3; rep++) {
                usleep(10000000);
                tlen = 0;
                g_probe_active = 1;
                if (__sigsetjmp(g_probe_jb, 1) == 0) {
                    h = ((u32 (*)(void *, void *, i32, u32 *, void *))(*(void ***)g_steamuser_obj)[idx])(
                        g_steamuser_obj, g_ticket_buf,
                        (i32)sizeof(g_ticket_buf), &tlen, ident);
                    g_probe_active = 0;
                } else {
                    g_probe_active = 0;
                    break;
                }
                g_ticket_calls++;
                C2B_LOGS("[c2b] AUTH: slot "); C2B_LOGN(idx);
                C2B_LOGS("repeat h="); C2B_LOGN(h);
                C2B_LOGS(" len="); C2B_LOGN(tlen);
                if (h && tlen && tlen <= sizeof(g_ticket_buf)) {
                    g_ticket_ok++;
                    g_ticket_len = tlen;
                    c2b_cl_hexline(g_ticket_buf, tlen, ln, (u32)sizeof(ln));
                    C2B_LOGS(" ticket "); C2B_LOGS(ln); C2B_LOGS("\n");
                } else {
                    C2B_LOGS("\n");
                }
            }
        } else {
            C2B_LOGS("\n");
            /* 41f-e: len=0 — дампим первые 16 Б буфера: вдруг импл тикет
             * записал, а pcbTicket не тронул (модель вызова угадана не до
             * конца) — hex покажет запись без счётчика. */
            {
                char ln16[64];
                c2b_cl_hexline(g_ticket_buf, 16, ln16, (u32)sizeof(ln16));
                C2B_LOGS(" buf16 "); C2B_LOGS(ln16); C2B_LOGS("\n");
            }
            usleep(5000000);
        }
    }
    if (have_old) sigaction(11, &oldsa, (void *)0);
}
#else
static u32 g_auth_vtidx = 13;
static void c2b_auth_ticket_probe(void) { (void)g_auth_vtidx; }
#endif  /* C2B_SELFTEST */

#ifndef C2B_SELFTEST
/* 41f-g: установка спью БЕЗ FUv — движок берёт NetworkingUtils через прямой
 * C-экспорт (run 100: FUv не увидел НИ ОДНОГО запроса SteamNetworkingUtils*).
 * Стоим сами: dlsym SteamAPI_SteamNetworkingUtils_v004/v003 или
 * SteamNetworkingUtils_LibV4 (стендэлон-аксессор, вернёт синглтон), затем
 * SEGV-защищённо vt[1] = SetDebugOutputFunction(5, cb). */
/* 41f-g5: состояние найденных GNS-копий (инсталл + пере-арм) */
static void *g_gns_u[2];        /* utils-объекты копий (0=standalone/FUv, 1=steamclient) */
static void *g_gns_flat[2];     /* flat SetDebugOutputFunction на копию */
static void *g_gns_cfg[2];      /* flat SetConfigValue на копию */
static u8    g_gns_u2_done;     /* копия#2 разрешена (найдена или совпадает с #1) */

/* 41f-g5: dl_iterate_phdr -> ТОЧНОЕ имя уже загруженного steamclient.so.
 * Run 104: bare dlopen("steamclient.so") не взял — либа вне путей поиска.
 * Имя из link_map (каким его загрузил steam_api — обычно полный путь)
 * годится как ключ dlopen: загруженная копия НЕ перезагружается. */
struct c2b_g5_phdr {
    uptr        dlpi_addr;
    const char *dlpi_name;
    const void *dlpi_phdr;
    u16         dlpi_phnum;
};
struct c2b_g5_ctx { char *out; u32 cap; u8 found; };

static i32 c2b_g5_phdr_cb(void *info_v, void *size_v, void *data_v)
{
    struct c2b_g5_phdr *pi = (struct c2b_g5_phdr *)info_v;
    struct c2b_g5_ctx *cx = (struct c2b_g5_ctx *)data_v;
    const char *nm, *sfx = "steamclient.so";
    u32 nl, sl = 0, j, q;
    (void)size_v;
    if (!pi || !pi->dlpi_name) return 0;
    nm = pi->dlpi_name;
    nl = 0; while (nm[nl]) nl++;
    while (sfx[sl]) sl++;
    if (nl < sl) return 0;
    for (j = 0; j < sl && nm[nl - sl + j] == sfx[j]; j++) {}
    if (j != sl) return 0;
    for (q = 0; nm[q] && q < cx->cap - 1; q++) cx->out[q] = nm[q];
    cx->out[q] = 0;
    cx->found = 1;
    return 1;
}

static void *c2b_dlopen_loaded_steamclient(void)
{
    static char g5_nm[512];
    struct c2b_g5_ctx cx;
    cx.out = g5_nm; cx.cap = (u32)sizeof(g5_nm); cx.found = 0;
    g5_nm[0] = 0;
    dl_iterate_phdr(c2b_g5_phdr_cb, &cx);
    if (!cx.found) return (void *)0;
    C2B_LOGS("[c2b] GNS: phdr steamclient path="); C2B_LOGS(g5_nm); C2B_LOGS("\n");
    return dlopen(g5_nm, C2B_RTLD_NOW | C2B_RTLD_GLOBAL);
}

/* 41f-g5: применить спью(6) к ОДНОЙ копии GNS (SEGV-защищённо).
 * 41f-g6: запись SetConfigValue(29)=1 УДАЛЕНА: runtime-верификация run 105
 * показала, что ключ 29 в этом билде = SDRClient_ForceRelayCluster (String!).
 * Запись Int32 туда отравила SDR-клиент: "Network config has no POPs" во
 * ВСЕХ попытках (SDR-конфиг застрял в Attempting) — регрессия run 105.
 * Настоящие индексы даёт проба c2b_g5_probe_configs (0..200). */
static void c2b_g5_apply(void *u, void *flat_spew, void *flat_cfg,
                         const char *tag, u8 verbose)
{
    if (!u) return;
    if (flat_spew) {
        g_probe_active = 1;
        if (__sigsetjmp(g_probe_jb, 1) == 0) {
            ((void (*)(void *, i32, void *))flat_spew)(u, 6, (void *)c2b_gns_spew);
            g_probe_active = 0;
            if (verbose) { C2B_LOGS("[c2b] GNS: spew(6) "); C2B_LOGS(tag);
                           C2B_LOGS(" OK\n"); }
        } else {
            g_probe_active = 0;
            if (verbose) { C2B_LOGS("[c2b] GNS: spew "); C2B_LOGS(tag);
                           C2B_LOGS(" segv\n"); }
        }
    }
}

/* 41f-g6: RUNTIME-ПРОБА таблицы конфигов 0..200 через GetConfigValueInfo
 * (run 105: имя ключа 29 получили из рантайма — индексы билда отличаются от
 * публичного SDK). Лог: name(type). Попутно КАЖДОМУ LogLevel_* ставим 6
 * (Debug/Verbose) — спью run 105 показал только Warning'и, пер-топик уровни
 * гейтят остальное; полный спью покажет end-причину аборта 0x21->0x22. */
/* 41f-g6: локальный префикс-чек (c2b_sthas объявлен ниже по файлу) */
static u8 c2b_g5_pfx(const char *s, const char *pfx)
{
    u32 i = 0;
    if (!s) return 0;
    while (pfx[i]) {
        if (s[i] != pfx[i]) return 0;
        i++;
    }
    return 1;
}

static void c2b_g5_probe_configs(void *u, void *flat_cfg)
{
    void *nfo = dlsym((void *)0, "SteamAPI_ISteamNetworkingUtils_GetConfigValueInfo");
    i32 k;
    if (!nfo || !u) return;
    for (k = 0; k <= 200; k++) {
        i32 dt = 0, sc = 0;
        const char *nm;
        g_probe_active = 1;
        if (__sigsetjmp(g_probe_jb, 1) != 0) {
            g_probe_active = 0;
            continue;
        }
        nm = ((const char * (*)(void *, i32, void *, void *))nfo)(u, k, &dt, &sc);
        g_probe_active = 0;
        if (!nm || !nm[0]) continue;
        C2B_LOGS("[c2b] GNS cfg "); C2B_LOGN((u32)k); C2B_LOGS("= ");
        {   char nb[64]; u32 q = 0;
            while (nm[q] && q < 60) { nb[q] = nm[q]; q++; }
            nb[q] = 0; C2B_LOGS(nb);
        }
        C2B_LOGS(" dt="); C2B_LOGN((u32)dt); C2B_LOGS("\n");
        /* LogLevel_* -> уровень 6 глобально (полный спью стейт-машины) */
        if (flat_cfg && dt == 1 && c2b_g5_pfx(nm, "LogLevel_")) {
            i32 six = 6;
            g_probe_active = 1;
            if (__sigsetjmp(g_probe_jb, 1) == 0) {
                ((void (*)(void *, i32, i32, uptr, i32, const void *))flat_cfg)(
                    u, k, 1, (uptr)0, 1, (const void *)&six);
                ((void (*)(void *, i32, i32, uptr, i32, const void *))flat_cfg)(
                    u, k, 0, (uptr)0, 1, (const void *)&six);
                g_probe_active = 0;
                C2B_LOGS("[c2b] GNS cfg LogLevel set 6 ok\n");
            } else {
                g_probe_active = 0;
            }
        }
    }
}

/* 41f-g5: разрешение копии#2 (внутренний GNS steamclient.so) */
static void c2b_g5_resolve_copy2(void)
{
    void *sch = dlopen("steamclient.so", C2B_RTLD_NOW | C2B_RTLD_GLOBAL);
    void *acc2, *f2, *c2, *u2;
    if (!sch) sch = c2b_dlopen_loaded_steamclient();
    if (!sch) return;
    f2 = dlsym(sch, "SteamAPI_ISteamNetworkingUtils_SetDebugOutputFunction");
    c2 = dlsym(sch, "SteamAPI_ISteamNetworkingUtils_SetConfigValue");
    acc2 = dlsym(sch, "SteamNetworkingUtils_LibV4");
    if (!acc2) {
        C2B_LOGS("[c2b] GNS: copy#2 no LibV4 accessor\n");
        g_gns_u2_done = 1;
        return;
    }
    u2 = ((void *(*)(void))acc2)();
    if (!u2) { C2B_LOGS("[c2b] GNS: copy#2 acc2 null\n"); return; }
    if (u2 == g_gns_u[0]) {
        C2B_LOGS("[c2b] GNS: copy#2 same singleton as copy#1\n");
        g_gns_u2_done = 1;
        return;
    }
    g_gns_u[1] = u2; g_gns_flat[1] = f2; g_gns_cfg[1] = c2;
    g_gns_u2_done = 1;
    C2B_LOGS("[c2b] GNS: copy#2 resolved u2="); C2B_LOGH((u32)(uptr)u2);
    C2B_LOGS("flat="); C2B_LOGN(f2 != 0);
    C2B_LOGS("cfg="); C2B_LOGN(c2 != 0);
    C2B_LOGS("\n");
}

static void c2b_gns_spew_install(void)
{
    static const char *syms[] = { "SteamAPI_SteamNetworkingUtils_v004",
                                  "SteamAPI_SteamNetworkingUtils_v003",
                                  "SteamAPI_SteamNetworkingUtils_v002",
                                  "SteamNetworkingUtils_LibV4", 0 };
    static const char *libs[] = { "libsteamnetworkingsockets.so",
                                  "steamclient.so", 0 };
    void *u = 0;
    u32 k, try;
    /* run 101: на старте auth-потока steamclient/GNS ещё НЕ загружены ->
     * dlsym(RTLD_DEFAULT) пуст. Ретраим до ~120с, попутно dlopen-им
     * кандидатов (steamclient уже загружен движком -> просто refcount). */
    for (try = 0; try < 60 && !u; try++) {
        for (k = 0; syms[k] && !u; k++) {
            void *fn = dlsym((void *)0, syms[k]);   /* RTLD_DEFAULT */
            if (fn) u = ((void *(*)(void))fn)();
            if (u) {
                C2B_LOGS("[c2b] GNS: utils via "); C2B_LOGS(syms[k]);
                C2B_LOGS(" ptr="); C2B_LOGH((u32)(uptr)u); C2B_LOGS("\n");
            }
        }
        if (!u && (try == 0 || try == 10)) {
            u32 l;
            for (l = 0; libs[l]; l++)
                dlopen(libs[l], C2B_RTLD_NOW | C2B_RTLD_GLOBAL);
        }
        if (!u) usleep(2000000);
    }
    if (!u && g_steamnetutils_obj) u = g_steamnetutils_obj;   /* FUv-фоллбэк */
    if (!u) {
        C2B_LOGS("[c2b] GNS: utils iface not found after retries\n");
        return;
    }
    /* 41f-g5: копия#1 — тот объект, что нашли (standalone или FUv) + копия#2
     * через phdr-резолв; верифицируем ключ 29 по имени. */
    {
        struct c2b_sigaction saf, oldf;
        u32 kf;
        for (kf = 0; kf < sizeof(saf); kf++) ((u8 *)&saf)[kf] = 0;
        for (kf = 0; kf < sizeof(oldf); kf++) ((u8 *)&oldf)[kf] = 0;
        saf.handler = (uptr)c2b_probe_segv;
        saf.flags = 4;
        sigemptyset(saf.mask);
        if (sigaction(11, &saf, &oldf) == 0) {
            void *flat = dlsym((void *)0, "SteamAPI_ISteamNetworkingUtils_SetDebugOutputFunction");
            void *cfg  = dlsym((void *)0, "SteamAPI_ISteamNetworkingUtils_SetConfigValue");
            g_gns_u[0] = u; g_gns_flat[0] = flat; g_gns_cfg[0] = cfg;
            if (flat || cfg) {
                C2B_LOGS("[c2b] GNS: copy#1 apply flat="); C2B_LOGN(flat != 0);
                C2B_LOGS("cfg="); C2B_LOGN(cfg != 0); C2B_LOGS("\n");
                c2b_g5_probe_configs(u, cfg);
                c2b_g5_apply(u, flat, cfg, "copy#1", 1);
                c2b_g5_resolve_copy2();
                if (g_gns_u[1])
                    c2b_g5_apply(g_gns_u[1], g_gns_flat[1], g_gns_cfg[1],
                                 "copy#2(steamclient)", 1);
                sigaction(11, &oldf, (void *)0);
                return;
            }
            sigaction(11, &oldf, (void *)0);
        }
    }
    {
        /* flat-экспортов нет вообще — старый vt[1] фоллбэк (run 102: segv,
         * но других опций нет) */
        struct c2b_sigaction sa3, old3;
        u32 k3;
        for (k3 = 0; k3 < sizeof(sa3); k3++) ((u8 *)&sa3)[k3] = 0;
        for (k3 = 0; k3 < sizeof(old3); k3++) ((u8 *)&old3)[k3] = 0;
        sa3.handler = (uptr)c2b_probe_segv;
        sa3.flags = 4;
        sigemptyset(sa3.mask);
        if (sigaction(11, &sa3, &old3) == 0) {
            g_probe_active = 1;
            if (__sigsetjmp(g_probe_jb, 1) == 0) {
                ((void (*)(void *, i32, void *))(*(void ***)u)[1])(u, 5,
                                                    (void *)c2b_gns_spew);
                g_probe_active = 0;
                C2B_LOGS("[c2b] GNS: SetDebugOutputFunction(5,cb) installed\n");
            } else {
                g_probe_active = 0;
                C2B_LOGS("[c2b] GNS: vt[1] segv — spew not installed\n");
            }
            sigaction(11, &old3, (void *)0);
        }
    }
}

/* 41f-g7: доходим до steamclient-внутреннего GNS (копия#2) через ISteamClient.
 * run 105/106 факты: спью copy#1 (LibV4-синглтон) показывает ТОЛЬКО пинги
 * (LogLevel=6 включён — вывода по коннектам НЕТ), а 0x20/0x21 к цели в pcap
 * идут -> коннекты делает ДРУГОЙ GNS: steamclient-внутренний (строки GNS есть
 * в steamclient.so, из экспортов только CreateInterface; libsteamnetworkingsockets
 * в бандле MISSING — движок берёт сокеты через ISteamClient). Путь:
 * g_iclient_obj (SteamClient020, захвачен в хуке) -> CreateSteamPipe ->
 * ConnectToGlobalUser -> GetISteamUser (верификация по GetSteamID) ->
 * GetISteamNetworkingUtils(pipe, ver) -> vt[0]=GetTimestamp-чек ->
 * SetDebugOutputFunction(vt[1], 6, cb). Пробы ТОЛЬКО с НАШИМИ pipe/user:
 * разрушительные индексы портят наши хэндлы, не движковые. */
static void *g_iclient_obj;   /* fwd — реальное определение в хуке ниже */

static void c2b_g7_vt_spew(void *uo, i32 lvl, void *fn)
{
    ((void (**)(void *, i32, void *))(*(void ***)uo))[1](uo, lvl, fn);
}

static void c2b_g7_client_utils(void)
{
    void *cl = g_iclient_obj;
    void **vt;
    uptr pipe = 0, user = 0;
    u64 sid = 0;
    u32 k;
    struct c2b_sigaction sa, oldsa;
    u32 kf;
    /* 41f-g10: СКАН ОПАСЕН — детерминированно убивает процесс (run 111, 114:
     * vt[1] на кандидате u=2 = не-SEGV краш/minidump, guard не спас; в run 114
     * погибли ВСЕ попытки на одном месте, g8-патч ни разу не применился).
     * Цели скана (спью+конфиг внутреннего GNS) перекрыты хирургией: g8 (слот
     * debug-callback base+0x2d1e1b0) и g9 (IP_AllowWithoutAuth entry+0x30).
     * Тело сохранено для архивных целей — не вызывать без острой нужды. */
    return;
    if (!cl) {
        C2B_LOGS("[c2b] GNS g7: no IClient obj\n");
        return;
    }
    for (kf = 0; kf < sizeof(sa); kf++) ((u8 *)&sa)[kf] = 0;
    for (kf = 0; kf < sizeof(oldsa); kf++) ((u8 *)&oldsa)[kf] = 0;
    sa.handler = (uptr)c2b_probe_segv;
    sa.flags = 4;
    sigemptyset(sa.mask);
    if (sigaction(11, &sa, &oldsa) != 0) return;
    vt = *(void ***)cl;
    /* CreateSteamPipe = vt[0] */
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) == 0) {
        pipe = ((uptr (*)(void *))vt[0])(cl);
        g_probe_active = 0;
    } else g_probe_active = 0;
    if (!pipe || pipe > 0x100000) {
        C2B_LOGS("[c2b] GNS g7: CreateSteamPipe bad\n");
        sigaction(11, &oldsa, (void *)0);
        return;
    }
    C2B_LOGS("[c2b] GNS g7: pipe="); C2B_LOGN((u32)pipe); C2B_LOGS("\n");
    /* Кандидаты user: vt[3] GetHSteamUserCurrent (движковый, без аргументов),
     * vt[4] ConnectToGlobalUser(pipe), vt[5] CreateLocalUser(&pipe2, 1).
     * Верификация каждого — через GetISteamUser(vt[7]) -> GetSteamID. */
    {
        uptr cand[4];
        u32 nc = 0, ci;
        uptr cur = 0, guser = 0, luser = 0, pipe2 = pipe;
        g_probe_active = 1;
        if (__sigsetjmp(g_probe_jb, 1) == 0) {
            cur = ((uptr (*)(void *))vt[3])(cl);
            g_probe_active = 0;
        } else g_probe_active = 0;
        C2B_LOGS("[c2b] GNS g7: cur user="); C2B_LOGN((u32)cur); C2B_LOGS("\n");
        g_probe_active = 1;
        if (__sigsetjmp(g_probe_jb, 1) == 0) {
            guser = ((uptr (*)(void *, uptr))vt[4])(cl, pipe);
            g_probe_active = 0;
        } else g_probe_active = 0;
        C2B_LOGS("[c2b] GNS g7: global user="); C2B_LOGN((u32)guser);
        C2B_LOGS("\n");
        g_probe_active = 1;
        if (__sigsetjmp(g_probe_jb, 1) == 0) {
            luser = ((uptr (*)(void *, uptr *, uptr))vt[5])(cl, &pipe2, 1);
            g_probe_active = 0;
        } else g_probe_active = 0;
        C2B_LOGS("[c2b] GNS g7: local user="); C2B_LOGN((u32)luser);
        C2B_LOGS(" pipe2="); C2B_LOGN((u32)pipe2); C2B_LOGS("\n");
        if (guser && guser <= 0x100000) cand[nc++] = guser;
        if (cur && cur <= 0x100000) cand[nc++] = cur;
        if (luser && luser <= 0x100000) cand[nc++] = luser;
        /* верификация: user+pipe -> ISteamUser -> GetSteamID */
        for (ci = 0; ci < nc && !user; ci++) {
            void *uobj = 0;
            u64 s2 = 0;
            g_probe_active = 1;
            if (__sigsetjmp(g_probe_jb, 1) == 0) {
                uobj = ((void *(*)(void *, uptr, uptr, const char *))vt[7])(
                    cl, cand[ci], pipe, "SteamUser022");
                if (uobj) s2 = ((u64 (*)(void *))(*(void ***)uobj)[2])(uobj);
                g_probe_active = 0;
            } else g_probe_active = 0;
            C2B_LOGS("[c2b] GNS g7: user cand "); C2B_LOGN((u32)cand[ci]);
            C2B_LOGS(" sid=0x"); C2B_LOGH((u32)(s2 >> 32));
            C2B_LOGH((u32)s2); C2B_LOGS("\n");
            if ((s2 >> 56) == 0x01) user = cand[ci];
        }
        if (!user)
            C2B_LOGS("[c2b] GNS g7: no verified user (продолжаем — utils не нужен user)\n");
    }
    /* GetISteamNetworkingUtils: перебор индексов и форм вызова.
     * Форма A: (pipe, ver) — run 109: не нашла (геттер, видимо, 3-арговый).
     * Форма B: (user, pipe, ver) c user из {1,2,0} — SDK-порядок старших
     * версий ISteamClient. Верификация объекта = vt[0] микросекунды
     * (~1.77e15). Все не-null возвраты логируем (видно почти-попадания). */
    {
        static const char *vers[] = { "SteamNetworkingUtils004",
                                      "SteamNetworkingUtils003", 0 };
        static const uptr ucand[3] = { 1, 2, 0 };
        u32 v, uci;
        for (v = 0; vers[v]; v++) {
            for (k = 4; k <= 30; k++) {
                u32 try3;
                for (try3 = 0; try3 < 2; try3++) {
                    u32 nu = try3 ? 3 : 1;
                    for (uci = 0; uci < nu; uci++) {
                        void *uo = 0;
                        u64 ts = 0;
                        g_probe_active = 1;
                        if (__sigsetjmp(g_probe_jb, 1) == 0) {
                            if (try3)
                                uo = ((void *(*)(void *, uptr, uptr,
                                     const char *))vt[k])(cl, ucand[uci],
                                     pipe, vers[v]);
                            else
                                uo = ((void *(*)(void *, uptr,
                                     const char *))vt[k])(cl, pipe, vers[v]);
                            g_probe_active = 0;
                        } else { g_probe_active = 0; continue; }
                        if (!uo) continue;
                        g_probe_active = 1;
                        if (__sigsetjmp(g_probe_jb, 1) == 0) {
                            ts = ((u64 (*)(void *))(*(void ***)uo)[0])(uo);
                            g_probe_active = 0;
                        } else { g_probe_active = 0; continue; }
                        C2B_LOGS("[c2b] GNS g7: vt["); C2B_LOGN(k);
                        C2B_LOGS(try3 ? "] 3arg u=" : "] 2arg u=");
                        C2B_LOGN(try3 ? (u32)ucand[uci] : 0);
                        C2B_LOGS("obj="); C2B_LOGH((u32)(uptr)uo);
                        C2B_LOGS("ts_hi="); C2B_LOGN((u32)(ts >> 32));
                        C2B_LOGS("\n");
                        /* 41f-g7e: run 110 показал, что геттеры vt[12..30]
                         * возвращают КАШИРОВАННЫЙ объект под данным ver
                         * (разный на user), ts_hi=0x7f0f — эпоха не 1970.
                         * Ставим спью в КАЖДЫЙ найденный объект (vt[1],
                         * SEGV-защита); живость меряет g_gns_spew_n. */
                        g_probe_active = 1;
                        if (__sigsetjmp(g_probe_jb, 1) == 0) {
                            c2b_g7_vt_spew(uo, 6, (void *)c2b_gns_spew);
                            g_probe_active = 0;
                            C2B_LOGS("[c2b] GNS g7: spew(6) installed on candidate u=");
                            C2B_LOGN(try3 ? (u32)ucand[uci] : 0);
                            C2B_LOGS("\n");
                            g_gns_u[1] = uo;
                            g_gns_flat[1] = (void *)c2b_g7_vt_spew;
                            g_gns_cfg[1] = 0;
                            g_gns_u2_done = 1;
                        } else {
                            g_probe_active = 0;
                            C2B_LOGS("[c2b] GNS g7: candidate vt[1] segv\n");
                        }
                    }
                }
            }
        }
    }
    C2B_LOGS("[c2b] GNS g7: scan done\n");
    /* 41f-g7e: меряем живость — если спью-кандидат настоящий, за 6с придут
     * строки (пинги идут постоянно); счётчик инкрементится из любого потока */
    {
        u32 before = g_gns_spew_n;
        usleep(6000000);
        C2B_LOGS("[c2b] GNS g7: spew lines in 6s = ");
        C2B_LOGN(g_gns_spew_n - before); C2B_LOGS("\n");
    }
    sigaction(11, &oldsa, (void *)0);
}

/* 41f-g5: пере-арм-петля. Run 103/104: flat setter встал, строк НОЛЬ —
 * гипотеза (а): движок/стартап ставит СВОЙ callback ПОСЛЕ нашего инсталла,
 * наш затирается. Решение: каждые 5с в течение 5 минут пере-устанавливаем
 * callback и конфиг (последним остаёмся МЫ) + доз-resолв копии#2 (steamclient
 * мог загрузиться позже). Повторная установка того же значения безобидна. */
/* 41f-g8: ХИРУРГИЧЕСКИЙ пач внутреннего GNS steamclient.so.
 * run 111: vtable-скан IClient опасен (кандидат vt[1] на чужом интерфейсе
 * роняет процесс). Вместо вызовов — ПРЯМАЯ ЗАПИСЬ указателя callback'а.
 * RE steamclient.so (run105/bins/steamclient.so__d975c5.so, диз /tmp/sc.asm):
 * spew-ядро 0x26fc0b0 (chain: 0x26fcb60 -> 0x26fca50 -> 0x26fc0b0) читает
 * глобал 0x2d1e1b0 и зовёт call *%rax при ненулевом; аргументы на вызове =
 * (level i32, msg ptr) — сигнатура совпадает с c2b_gns_spew(lvl, msg).
 * RVA 0x2d1e1b0 валиден для билда linux64 d975c5 (ровно тот, что грузит
 * движок — phdr run 105: /home/runner/.local/share/Steam/linux64/steamclient.so).
 * Слот в .data — обычная запись; перед записью логируем старое значение
 * (0 = колбэк нет). */
static volatile void **g_g8_slot;
static u8 g_g8_armed;

static i32 c2b_g8_phdr_cb(void *info_v, void *size_v, void *data_v)
{
    struct c2b_g5_phdr *pi = (struct c2b_g5_phdr *)info_v;
    uptr *out = (uptr *)data_v;
    const char *nm, *sfx = "steamclient.so";
    u32 nl, sl = 0, j;
    (void)size_v;
    if (!pi || !pi->dlpi_name) return 0;
    nm = pi->dlpi_name;
    nl = 0; while (nm[nl]) nl++;
    while (sfx[sl]) sl++;
    if (nl < sl) return 0;
    for (j = 0; j < sl && nm[nl - sl + j] == sfx[j]; j++) {}
    if (j != sl) return 0;
    *out = pi->dlpi_addr;   /* load bias найденной копии */
    return 0;               /* продолжаем — берём последнюю замапленную */
}

static void c2b_g8_patch_apply(void)
{
    uptr base = 0;
    volatile void **slot;
    uptr old;
    dl_iterate_phdr(c2b_g8_phdr_cb, &base);
    if (!base) {
        C2B_LOGS("[c2b] GNS g8: steamclient.so not mapped\n");
        return;
    }
    slot = (volatile void **)(base + 0x2d1e1b0);
    /* v4.3: чтение слота через /proc/self/mem (steam client может
     * анмапиться между phdr-итерацией и чтением — run165 SIGSEGV класс); */
    old = c2b_rd_once((uptr)slot);
    if (old == (uptr)c2b_gns_spew) { g_g8_armed = 1; return; }
    if (!old) return;   /* модуль исчез — не патчим */
    *slot = (const volatile void *)c2b_gns_spew;
    g_g8_slot = slot;
    g_g8_armed = 1;
    C2B_LOGS("[c2b] GNS g8: slot patched base+0x2d1e1b0 old=");
    C2B_LOGH((u32)old); C2B_LOGS("\n");
}

static void c2b_g8_patch_verify(void)
{
    /* через 6с проверяем живость: внутренний GNS пингует POPs постоянно */
    u32 before = g_gns_spew_n;
    usleep(6000000);
    C2B_LOGS("[c2b] GNS g8: spew lines in 6s after patch = ");
    C2B_LOGN(g_gns_spew_n - before);
    C2B_LOGS("\n");
}

/* 41f-g9: IP_AllowWithoutAuth (enum 0x17=23, dt Int32) — вероятный gate аборта
 * 0x21->0x22: у клиентского GNS нет серта (identity), соединение абортирует
 * ConnectRequest, пока флаг 0. Run 106 runtime-проба: "cfg 0x17 =
 * IP_AllowWithoutAuth dt=1" (совпадает с публичным SDK 23). RE offline
 * (run105/bins): таблица конфигов = linked list, register fn (d975c5:0x1ef3a70)
 * пишет entry{+0x00 enum, +0x08 name, +0x10 scope, +0x14 dt, +0x18 cfg_off,
 * +0x20 next}, значение INLINE в entry+0x30 (ctor: movq $0x0); walker
 * (d975c5:0x1ef3af0, fallback=NULL) строит global-структуру как
 * cfg_global[entry->off] = &entry+0x30 => запись 1 в entry+0x30 пробрасывается
 * во ВСЕ конфиг-структуры без явных оверрайдов (connection -> socket ->
 * global цепочка указателей).
 * Entry RVA на билд (ctor lea/mov-паттерн + mov $0x17,%esi верифицирован):
 *   d975c5 (64Б): entry 0x2cb8060, name 0xd1e1b7, cfg_off 0x108 (r9d)
 *   5b08b7 (64Б): entry 0x32113e0, name 0xe0b6da, cfg_off 0xb0
 * (6820f9/8629c2 = 32Б копии, наш процесс 64Б — не матчатся сиг-чеком.)
 * Сиг-чек перед записью: enum==0x17 && name==base+name_rva && off==cfg_off &&
 * val==0. Выровненная 4-байтная запись — атомарна на x86; .data страница RW. */
struct c2b_g9_build {
    const char *tag;
    uptr entry_rva;
    uptr name_rva;
    i32  cfg_off;
};
static const struct c2b_g9_build c2b_g9_builds[2] = {
    { "d975c5", 0x2cb8060ull, 0xd1e1b7ull, 0x108 },
    { "5b08b7", 0x32113e0ull, 0xe0b6daull, 0xb0  },
};
struct c2b_g9_ctx { uptr base[8]; u32 n; };

static i32 c2b_g9_phdr_cb(void *info_v, void *size_v, void *data_v)
{
    struct c2b_g5_phdr *pi = (struct c2b_g5_phdr *)info_v;
    struct c2b_g9_ctx *cx = (struct c2b_g9_ctx *)data_v;
    const char *nm, *sfx = "steamclient.so";
    u32 nl, sl = 0, j;
    (void)size_v;
    if (!pi || !pi->dlpi_name) return 0;
    nm = pi->dlpi_name;
    nl = 0; while (nm[nl]) nl++;
    while (sfx[sl]) sl++;
    if (nl < sl) return 0;
    for (j = 0; j < sl && nm[nl - sl + j] == sfx[j]; j++) {}
    if (j != sl) return 0;
    if (cx->n < 8) cx->base[cx->n++] = pi->dlpi_addr;
    return 0;
}

static void c2b_g9_patch_one(uptr base, const struct c2b_g9_build *b)
{
    uptr entry = base + b->entry_rva;
    volatile u32 *val;
    u32 enumv, cfgv, valv;
    /* v4.3: все чеки через /proc/self/mem (run165: SIGSEGV здесь —
     * steamclient.so исчез между dl_iterate_phdr и разыменованиями);
     * 0-чтения просто не совпадут с сигнатурой */
    enumv = (u32)c2b_rd_once(entry);
    if (enumv != 0x17) return;                                    /* enum  */
    {   u64 nameq = c2b_rd_once(entry + 8);
        if (nameq != (u64)(uptr)(base + b->name_rva)) return; /* имя ptr */
    }
    cfgv = (u32)c2b_rd_once(entry + 0x18);
    if ((i32)cfgv != b->cfg_off) return;                          /* off   */
    val = (volatile u32 *)(entry + 0x30);
    valv = (u32)c2b_rd_once(entry + 0x30);
    if (valv != 0) return;      /* 1 = уже наш; прочее = чужой оверрайд */
    *val = 1;
    C2B_LOGS("[c2b] GNS g9: IP_AllowWithoutAuth 0->1 build "); C2B_LOGS(b->tag);
    C2B_LOGS("entry="); C2B_LOGH((u32)b->entry_rva); C2B_LOGS("\n");
}

static void c2b_g9_patch_apply(void)
{
    struct c2b_g9_ctx cx;
    u32 i, b;
    static u8 said_no;
    cx.n = 0;
    dl_iterate_phdr(c2b_g9_phdr_cb, &cx);
    if (!cx.n) {
        if (!said_no) { C2B_LOGS("[c2b] GNS g9: no steamclient.so mapped\n"); said_no = 1; }
        return;
    }
    for (i = 0; i < cx.n; i++)
        for (b = 0; b < 2; b++)
            c2b_g9_patch_one(cx.base[i], &c2b_g9_builds[b]);
}

/* 41f-g9: плоский set cfg23=1 через copy#1 — ТОЛЬКО после рантайм-верификации
 * имени ключа (урок run 105: enum 29 оказался строкой SDRClient_ForceRelay-
 * Cluster). Scope Global=0, как у LogLevel из g6. Идемпотентно. */
static void c2b_g9_flat_set(void)
{
    void *nfo = dlsym((void *)0, "SteamAPI_ISteamNetworkingUtils_GetConfigValueInfo");
    static u8 done;
    i32 dt = 0, sc = 0;
    const char *nm;
    if (done || !g_gns_u[0] || !g_gns_cfg[0] || !nfo) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    nm = ((const char * (*)(void *, i32, void *, void *))nfo)(g_gns_u[0], 23, &dt, &sc);
    g_probe_active = 0;
    if (!nm || !c2b_g5_pfx(nm, "IP_AllowWithoutAuth") || dt != 1) {
        C2B_LOGS("[c2b] GNS g9: cfg23 mismatch dt="); C2B_LOGN((u32)dt); C2B_LOGS("\n");
        done = 1;   /* не ретраим: имя не то — таблица не та, чинить нечем */
        return;
    }
    {   i32 one = 1;
        ((void (*)(void *, i32, i32, uptr, i32, const void *))g_gns_cfg[0])(
            g_gns_u[0], 23, 1, (uptr)0, 1, (const void *)&one);
    }
    done = 1;
    C2B_LOGS("[c2b] GNS g9: flat set cfg23 IP_AllowWithoutAuth=1 ok\n");
}

/* ---------- 41f-g11: транспортная выводка ConnectRequest (observer) ----------
 * RE run116 (диз sc.asm, билд d975c5) + pcap a3/a4:
 *  - 0x22 строится (крипто-гейты пройдены, "crypt not ready" НЕТ), но до
 *    UDP-сокета НЕ доходит: в pcap 0x20->0x21 идут, 0x22 — нет, при этом
 *    POP-пинги уходят сотнями пакетов (sendto-путь жив).
 *  - сайт отправки 0x1fd622a: call *(%rax), где rcx=*(wrap+0x10) (транспорт),
 *    rdi=*(xport+0x20) (внутр. объект), rsi=1, rdx=&{buf,len} (16Б сегмент),
 *    r8d=-1. ГЕЙТ перед ним: 0x1fd61f0 je 0x1fd651e — при NULL-транспорте
 *    печатается warning "Attemt to send packet, but socket has been closed!"
 *    (@0xcc1ae8, id 0x545) через СПЬЮ-канал — в спью run116 ОТСУТСТВУЕТ =>
 *    транспорт НЕ NULL, пакет уходит ВНУТРЬ транспортного объекта.
 *  - CConnectionTransportIPV4 в билде НЕ существует (только SDR/P2P) =>
 *    транспорт скорее всего SDR-очередь (роут к POP не установлен).
 *  - нижний уровень: UDP-обёртка 0x1fcd110 (fd@obj+0x1c==-1 -> abort;
 *    sendmsg 0x1fcd1ee / sendto 0x1fcd3f4; сегменты 16Б).
 * Инструментация (строго observer, логика не меняется):
 *  g11a: пач 0x1fd61f0 (14Б = je 6Б + mov 5Б + lea[0..2]) -> c2b_g11_xport_
 *        thunk: лог (xport, inner, vtable[0] RVA, conn-счётчики 0x9e8/0xa00),
 *        затем реплика cmpq/je/mov/lea -> jmp 0x1fd6200 (не-NULL) либо
 *        0x1fd651e (NULL).
 *  g11b: детур входа 0x1fcd110 (29Б пролога) -> c2b_g11_udp_thunk: лог
 *        (fd, nseg, дамп сегментов, дамп dest-объекта), затем jmp трамплин
 *        (копия 29Б + jmp 0x1fcd12d).
 * Ожидаемый сигнал: g11a даст RVA vtable[0] (константа — сравним с
 * 0x1fcd110-регионом в анализе), g11b — вызывается ли UDP-слой вообще. */

#define C2B_G11_UDP_RVA   0x1fcd110ull
#define C2B_G11_UDP_CONT  0x1fcd12dull   /* после 29Б пролога */
#define C2B_G11_SITE_RVA  0x1fd61f0ull
#define C2B_G11_CONT_RVA  0x1fd6200ull   /* mov $-1,%r8d */
#define C2B_G11_NULL_RVA  0x1fd651eull   /* warning "Attemt to send..." */
/* g11d (раунд 1337): BSendPacketGather = vtable[0] внутреннего сокета
 * (CRawUDPSocketImpl, RE vtable 0x2bd38c8/[0]=0x1fc7c80). Сигнатура совпадает
 * с call-site 0x1fd622a: (self, nChunks, pChunks, adr, efDontRoute).
 * Точки ТИХОГО ДРОПА до sendto (все молча возвращают успех):
 *  1) *(u32*)0x2cbb900 — ВНИМАНИЕ (RE run181): это счётчик ИНИЦИАЛИЗАЦИИ
 *     низкоуровневого GNS (BSteamNetworkingSocketsLowLevelAddRef), НЕ трогать
 *     (стор 1 -> s_hEpoll=-1 -> epoll_ctl EBADF -> h=0); в BSendPacketGather
 *     он же читается как sockcnt (0x1fc7cb5), но при живом AddRef > 0;
 *  2) FakeRateLimit_Send_Rate (int, entry 0x2cb8ae0+0x40) > 0 -> лимит-ветка;
 *  3) FakePacketLoss_Send (float, 0x2cb8f00+0x40) 0<f<1e9 -> ролл лосса;
 *  4) FakePacketLag_Send (0x2cb8e40+0x40) / FakePacketReorder_Send
 *     (0x2cb8d80+0x40) — отложенная постановка в lagger (0x1fc7f40 -> 0x1fcd530
 *     очередь) вместо прямой отправки.
 * cfg-имена верифицированы по RTTI-регистрации (esi=2..6, 0x29..0x2c @0x1efceea):
 * enum 2=FakePacketLoss_Send 3=FakePacketLoss_Recv 4=FakePacketLag_Send
 * 5=FakePacketLag_Recv 6=FakePacketReorder_Send 0x2a=FakeRateLimit_Send_Rate.
 * Детур входа 0x1fc7c80 (14Б до rip-relative lea @0x1fc7c8e): реплика 6 инснов
 * в тунке, jmp на 0x1fc7c8e — lea остаётся валидной (оригинальный rip).
 * Транзитные вызовы: g11u (0x1fcd110) покрыт отдельно — пара g11d-есть/
 * g11u-нет = дроп внутри gather; g11d/g11u оба есть = пакет ушёл в sendto. */
#define C2B_G11_GATHER_RVA  0x1fc7c80ull
#define C2B_G11_GATHER_CONT 0x1fc7c8eull   /* lea rip-rel спью-имени */
/* g11e: CPacketLaggerSend::vtable[5] = 0x1fcd4e0 — «отправить лагированный
 * пакет сейчас» (вызывается из дрена очереди lagger'а). RE 1337: ВСЕ пакеты
 * через BSendPacketGather ставятся в очередь CPacketLagger::LagPacket
 * (0x1fcd530: fd==-1/obj+0x28==0 -> warning 0x2f2 "Tried to lag a packet on a
 * socket that has already been closed..."; MTU 0x514), реальный sendto — из
 * дрена: vtable[5] -> 0x1fcd110. Если очередь НЕ дренируется — пакеты висят
 * вечно (кандидат на барьер 0x22). Цепь сигналов: g11d (enqueue) -> g11e
 * (drain per-packet) -> g11u (socket write). g11d есть + g11e НЕТ = lagger
 * не дренируется -> g12: форс-дрен/байпас. Пролог 24Б без rip-relative,
 * cont = 0x1fcd4f8. */
#define C2B_G11_LAG_RVA     0x1fcd4e0ull
#define C2B_G11_LAG_CONT    0x1fcd4f8ull
/* g11f (раунд 1407): ТИХИЙ ГЕЙТ обработчика ChallengeReply @0x1fd5f68:
 * cmpl $0x1,0x1b40(%rbp); jne 0x1fd5f3c (эпилог, БЕЗ warning) — если
 * conn+0x1b40 != 1, обработка 0x21 и отправка 0x22 молча пропускаются.
 * Ран118: сервер ОТВЕЧАЕТ 0x21 (a1:7, a3:4, a4:2), спью чист, g11x молчит
 * => единственный невидимый выход = этот гейт (или функ не вызывается).
 * conn+0x1b40: пишется ТОЛЬКО нулём в конторе (15d0083 movups), статических
 * записей 1/3 НЕ найдено — семантика неизвестна (вопрос к логу). Пролог 14Б:
 * cmpl(7) + jne(2) + первые 5Б mov 0x180(%rbp),%eax (шестой байт — сирота).
 * Репликация: cmpl, jne->0x1fd5f3c, mov; cont = 0x1fd5f77 (mov %rsi,%r15). */
#define C2B_G11_GATE_RVA    0x1fd5f68ull
#define C2B_G11_GATE_CONT   0x1fd5f77ull
#define C2B_G11_GATE_BAIL   0x1fd5f3cull

static const u8 c2b_g11_sig_gate[14] = {
    0x83, 0xBD, 0x40, 0x1B, 0x00, 0x00, 0x01,  /* cmpl $0x1,0x1b40(%rbp) — БЫЛО 0xBB (%rbx): опечатка раунда 1407, вскрыта в run122 (bins/steamclient.so__d975c5.so) */
    0x75, 0xCB,                                 /* jne 0x1fd5f3c */
    0x8B, 0x85, 0x80, 0x01, 0x00                /* mov 0x180(%rbp),%eax (5/6) */
};

static const u8 c2b_g11_sig_lag[24] = {
    0x48, 0x8D, 0x4E, 0x28,          /* lea 0x28(%rsi),%rcx */
    0x48, 0x83, 0xEC, 0x18,          /* sub $0x18,%rsp */
    0x48, 0x63, 0x46, 0x18,          /* movslq 0x18(%rsi),%rax */
    0x44, 0x0F, 0xB6, 0x46, 0x41,    /* movzbl 0x41(%rsi),%r8d */
    0x48, 0x89, 0xE2,                /* mov %rsp,%rdx */
    0x48, 0x8B, 0x7E, 0x48           /* mov 0x48(%rsi),%rdi */
};

static const u8 c2b_g11_sig_gather[14] = {
    0x41, 0x57,             /* push %r15 */
    0x41, 0x56,             /* push %r14 */
    0x49, 0x89, 0xCE,       /* mov %rcx,%r14 */
    0x41, 0x55,             /* push %r13 */
    0x49, 0x89, 0xFD,       /* mov %rdi,%r13 */
    0x41, 0x54              /* push %r12 (байты 12-13; инсн обрывается джампом) */
};

static const u8 c2b_g11_sig_site[14] = {
    0x0F, 0x84, 0x28, 0x03, 0x00, 0x00,   /* je 1fd651e */
    0x49, 0x8B, 0x44, 0x24, 0x08,         /* mov 0x8(%r12),%rax */
    0x48, 0x8D, 0x54                      /* lea 0x10(%rsp),%rdx (3/5) */
};
static const u8 c2b_g11_sig_udp[29] = {
    0x41, 0x57, 0x41, 0x56, 0x41, 0x55,   /* push r15/r14/r13 */
    0x49, 0x89, 0xCD,                     /* mov %rcx,%r13 */
    0x41, 0x54, 0x49, 0x89, 0xFC,         /* push r12; mov %rdi,%r12 */
    0x55, 0x48, 0x89, 0xD5,               /* push rbp; mov %rdx,%rbp */
    0x53, 0x48, 0x63, 0xDE,               /* push rbx; movslq %esi,%ebx */
    0x48, 0x81, 0xEC, 0x38, 0x02, 0x00, 0x00  /* sub $0x238,%rsp */
};

static uptr g_g11_base;                 /* load bias steamclient.so */
static volatile u32 g_g11_nx;           /* анти-спам xport-логгера */
static volatile u32 g_g11_nu;           /* анти-спам udp-логгера */
static volatile u32 g_g11_ng;           /* анти-спам gather-логгера */
static volatile u32 g_g11_nl;           /* анти-спам lagger-drain-логгера */
static volatile u32 g_g11_nf;           /* анти-спам gate-логгера */
static void *volatile c2b_g11_gate_cont = 0;
static void *volatile c2b_g11_gate_bail = 0;
static volatile u64 c2b_g11_cont_addr, c2b_g11_null_addr;
/* void *volatile (НЕ volatile void*): gcc удаляет unused static без
 * volatile-объекта, а тюнк ссылается на символ из asm (урок сборки g11) */
static void *volatile c2b_g11_udp_tramp = 0;
static void *volatile c2b_g11_gather_cont = 0;
static void *volatile c2b_g11_lag_cont = 0;
static u8 *g_g11_udp_tramp_mem;
/* 41f-g32: relay капчуренного 0x22 (гейт C2B_GNS_RELAY) + драйвер-флаги */
static u32 g_gns_relay;                 /* C2B_GNS_RELAY=1 */
static u32 g_gns_relay_sent;            /* сколько 0x22 ушло через relay */
static u8  g_gns_connect_target[24];    /* C2B_GNS_CONNECT=ip:port (ascii) */
static u32 g_gns_connect_go;            /* драйвер вооружён */
static u8  g_gns_dst[16];               /* g32: sockaddr_in цели (из env) */
static socklen_t g_gns_dstlen;          /* 0 = не собран */

/* 41f-g32a: fwd decl — драйвер определяется ниже, зовётся из auth-потока */
static void c2b_g32_drive(void);
static void *c2b_g32_thread(void *arg);

void c2b_g11_xport_log(uptr wrap, uptr orsp)
{
    uptr xport, inner, vt0, conn;
    u32 n;
    if (!g_g11_base) return;
    n = ++g_g11_nx;
    if (n > 24 && (n & 0x3F) != 1) return;   /* первые 24, далее 1/64 */
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    xport = *(volatile uptr *)(wrap + 0x10);
    C2B_LOGS("[c2b] g11x try: xport=");
    if (!xport) {
        C2B_LOGS("0 (NULL -> 'Attemt to send' path)\n");
        g_probe_active = 0;
        return;
    }
    C2B_LOGH((u32)(xport - g_g11_base));
    inner = *(volatile uptr *)(xport + 0x20);
    C2B_LOGS(" inner=");
    C2B_LOGH((u32)(inner > g_g11_base ? inner - g_g11_base : 0));
    vt0 = inner ? *(volatile uptr *)inner : 0;
    C2B_LOGS(" vt0_rva=");
    C2B_LOGH((u32)(vt0 > g_g11_base ? vt0 - g_g11_base : 0));
    conn = *(volatile uptr *)(wrap + 8);
    if (conn) {
        C2B_LOGS(" conn msgs=");
        C2B_LOGN(*(volatile u32 *)(conn + 0x9e8));
        C2B_LOGS(" bytes=");
        C2B_LOGN(*(volatile u32 *)(conn + 0xa00));
    }
    /* 41f-g32: СЕГМЕНТ-КАПЧЕР — at orsp (rsp@0x1fd61f0): +0x10 = {ptr,len}
    * единственного 16Б сегмента (disasm: mov %r13,0x10(%rsp); mov %rbp,0x18(%rsp);
    * lea 0x10(%rsp),%rdx @0x1fd61fb). Это СЫРОЙ пакет 0x22 (cert+crypt движка!).
    * fd = *(inner+0x1c) — CRawUDPSocketImpl (вериф. cmpl $-1,0x1c(%rdi) @0x1fcd140). */
    {
        uptr sptr = orsp ? *(volatile uptr *)(orsp + 0x10) : 0;
        uptr slen = orsp ? *(volatile uptr *)(orsp + 0x18) : 0;
        i32  fd   = inner ? *(volatile i32 *)(inner + 0x1c) : -2;
        u32  k;
        C2B_LOGS(" fd="); C2B_LOGN((u32)fd);
        C2B_LOGS(" seg.len="); C2B_LOGN((u32)slen);
        if (sptr && slen >= 16 && slen <= 1500) {
            C2B_LOGS(" seg[96B]=");
            for (k = 0; k < 96 && (uptr)k < slen; k++)
                C2B_LOGH(*(volatile u8 *)(sptr + k));
            C2B_LOGS(" p0="); C2B_LOGH(*(volatile u8 *)sptr);
            /* 41f-g32 RELAY: послать капчуренный 0x22 САМИМИ — fd движка
             * (source addr = биндинг challenge!), dst = g_clv2_dst (цель).
             * Гейт C2B_GNS_RELAY=1 (двойная отправка безвредна: сервер
             * уже молчит на транспортный путь). */
            if (g_gns_relay && fd > 0 && fd < 1024 && g_clp_sendto) {
                /* dst: СОБСТВЕННЫЙ sockaddr_in g32 (из env, собран драйвером)
                 * -> fallback g_clv2_dst (CLV2-капчер). fd движка держит
                 * биндинг challenge; Env-цель = та же, что и challenge. */
                const void *rd = (g_gns_dstlen >= 6) ? (const void *)g_gns_dst
                                                     : (const void *)g_clv2_dst;
                socklen_t rl = (g_gns_dstlen >= 6) ? g_gns_dstlen : g_clv2_dstlen;
                if (rl >= 6 && *(volatile u8 *)sptr == 0x22) {
                    ((c2b_sendto_fn)g_clp_sendto)(fd, (const void *)sptr,
                                                  (u32)slen, 0, rd, rl);
                    g_gns_relay_sent++;
                    C2B_LOGS(" RELAYED#"); C2B_LOGN(g_gns_relay_sent);
                }
            }
        }
    }
    C2B_LOGS("\n");
    g_probe_active = 0;
}

void c2b_g11_udp_log(uptr obj, uptr nseg, uptr segs, uptr dest)
{
    i32 fd;
    u32 n;
    if (!g_g11_base) return;
    n = ++g_g11_nu;
    if (n > 40 && (n & 0x3F) != 1) return;   /* первые 40, далее 1/64 */
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    fd = obj ? *(volatile i32 *)(obj + 0x1c) : -2;
    C2B_LOGS("[c2b] g11u: fd=");
    C2B_LOGN((u32)fd);
    C2B_LOGS(" nseg=");
    C2B_LOGN((u32)nseg);
    C2B_LOGS(" dest[20B]=");
    if (dest) {
        u32 i;
        for (i = 0; i < 20; i += 4)
            C2B_LOGH(*(volatile u32 *)(dest + i));
    } else {
        C2B_LOGH(0);
    }
    C2B_LOGS(" segs[16B]=");
    if (segs) {
        u32 i;
        for (i = 0; i < 16; i += 4)
            C2B_LOGH(*(volatile u32 *)(segs + i));
    } else {
        C2B_LOGH(0);
    }
    C2B_LOGS("\n");
    g_probe_active = 0;
}

void c2b_g11_gather_log(uptr self, uptr nseg, uptr segs, uptr adr, uptr efd)
{
    u32 n, sockcnt, ratelim, loss, lag, reorder;
    u32 total = 0, k;
    if (!g_g11_base) return;
    n = ++g_g11_ng;
    if (n > 24 && (n & 0x3F) != 1) return;   /* первые 24, далее 1/64 */
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    sockcnt = *(volatile u32 *)(g_g11_base + 0x2cbb900);
    ratelim = *(volatile u32 *)(g_g11_base + 0x2cb8ae0 + 0x40);
    loss    = *(volatile u32 *)(g_g11_base + 0x2cb8f00 + 0x40);
    lag     = *(volatile u32 *)(g_g11_base + 0x2cb8e40 + 0x40);
    reorder = *(volatile u32 *)(g_g11_base + 0x2cb8d80 + 0x40);
    C2B_LOGS("[c2b] g11d gather: self=");
    C2B_LOGH((u32)(self > g_g11_base ? self - g_g11_base : 0));
    C2B_LOGS(" nseg="); C2B_LOGN((u32)nseg);
    C2B_LOGS(" efd="); C2B_LOGN((u32)(i32)efd);
    C2B_LOGS(" sockcnt="); C2B_LOGN(sockcnt);
    C2B_LOGS(" ratelimit="); C2B_LOGN(ratelim);
    C2B_LOGS(" loss="); C2B_LOGH(loss);
    C2B_LOGS(" lag="); C2B_LOGN(lag);
    C2B_LOGS(" reorder="); C2B_LOGH(reorder);
    if (segs && nseg && nseg < 64) {
        for (k = 0; k < nseg; k++)
            total += *(volatile u32 *)(segs + 16 * k);
        C2B_LOGS(" total="); C2B_LOGN(total);
    }
    C2B_LOGS(" adr[16B]=");
    if (adr) {
        for (k = 0; k < 16; k += 4)
            C2B_LOGH(*(volatile u32 *)(adr + k));
    } else {
        C2B_LOGH(0);
    }
    C2B_LOGS("\n");
    g_probe_active = 0;
}

void c2b_g11_gate_log(uptr conn, uptr msg)
{
    u32 n, k;
    if (!g_g11_base) return;
    n = ++g_g11_nf;
    if (n > 24 && (n & 0x3F) != 1) return;   /* первые 24, далее 1/64 */
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g11f gate: conn=");
    C2B_LOGH((u32)(conn > g_g11_base ? conn - g_g11_base : 0));
    if (conn) {
        C2B_LOGS(" b40="); C2B_LOGN(*(volatile u32 *)(conn + 0x1b40));
        C2B_LOGS(" b44="); C2B_LOGN(*(volatile u32 *)(conn + 0x1b44));
        C2B_LOGS(" id180="); C2B_LOGN(*(volatile u32 *)(conn + 0x180));
        C2B_LOGS(" f158="); C2B_LOGN((u32)*(volatile u8 *)(conn + 0x158));
        C2B_LOGS(" cr1848="); C2B_LOGN((u32)*(volatile u8 *)(conn + 0x1848));
        C2B_LOGS(" cr1870="); C2B_LOGN((u32)*(volatile u8 *)(conn + 0x1870));
    }
    if (msg) {
        C2B_LOGS(" msg[8B]=");
        for (k = 0x20; k < 0x28; k += 4)
            C2B_LOGH(*(volatile u32 *)(msg + k));
    }
    C2B_LOGS("\n");
    g_probe_active = 0;
}

void c2b_g11_lag_log(uptr self, uptr pkt)
{
    u32 n, k;
    if (!g_g11_base) return;
    n = ++g_g11_nl;
    if (n > 24 && (n & 0x3F) != 1) return;   /* первые 24, далее 1/64 */
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g11e lagdrain: self=");
    C2B_LOGH((u32)(self > g_g11_base ? self - g_g11_base : 0));
    if (pkt) {
        C2B_LOGS(" len="); C2B_LOGN(*(volatile u32 *)(pkt + 0x18));
        C2B_LOGS(" tos="); C2B_LOGN((u32)*(volatile u8 *)(pkt + 0x41));
        C2B_LOGS(" sock=");
        C2B_LOGH((u32)(*(volatile uptr *)(pkt + 0x48) > g_g11_base
                          ? *(volatile uptr *)(pkt + 0x48) - g_g11_base : 0));
        C2B_LOGS(" dest[16B]=");
        for (k = 0; k < 16; k += 4)
            C2B_LOGH(*(volatile u32 *)(pkt + 0x28 + k));
    }
    C2B_LOGS("\n");
    g_probe_active = 0;
}

__asm__(
".text\n"
".globl c2b_g11_xport_thunk\n"
".type  c2b_g11_xport_thunk,@function\n"
"c2b_g11_xport_thunk:\n"    /* вход: rsp=rsp@0x1fd61f0 (jmp-пач); r12 жив */
"  endbr64\n"
"  push %rax\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %rsi\n"
"  push %rdi\n"
"  push %r8\n"
"  push %r9\n"
"  push %r10\n"
"  push %r11\n"
"  push %rbx\n"             /* 10 push = 80Б */
"  mov  %rsp,%r10\n"
"  sub  $0x8,%rsp\n"
"  and  $0xfffffffffffffff0,%rsp\n"
"  mov  %r10,0x00(%rsp)\n"  /* якорь rsp в памяти (call его не тронет) */
"  mov  %r12,%rdi\n"
"  mov  %r10,%rsi\n"        /* g32: arg2 = rsp@0x1fd61f0 (сегменты на +0x10/+0x18) */
"  call c2b_g11_xport_log\n"
"  mov  0x00(%rsp),%r10\n"
"  mov  %r10,%rsp\n"
"  pop  %rbx\n"
"  pop  %r11\n"
"  pop  %r10\n"
"  pop  %r9\n"
"  pop  %r8\n"
"  pop  %rdi\n"
"  pop  %rsi\n"
"  pop  %rdx\n"
"  pop  %rcx\n"
"  pop  %rax\n"
/* реплика затёртого (je зависел от cmpq @0x1fd61e0 — cmpq повторяем) */
"  cmpq $0x0,0x10(%r12)\n"
"  jne  11f\n"
"  mov  c2b_g11_null_addr(%rip),%r11\n"
"  jmp  *%r11\n"
"11:\n"
"  mov  0x8(%r12),%rax\n"
"  lea  0x10(%rsp),%rdx\n"
"  mov  c2b_g11_cont_addr(%rip),%r11\n"
"  jmp  *%r11\n"
".size c2b_g11_xport_thunk, .-c2b_g11_xport_thunk\n"
".globl c2b_g11_udp_thunk\n"
".type  c2b_g11_udp_thunk,@function\n"
"c2b_g11_udp_thunk:\n"      /* вход: rsp%16==8, rdi=obj rsi=nseg rdx=segs rcx=dest */
"  endbr64\n"
"  sub  $0x58,%rsp\n"       /* 88; rsp%16==0 */
"  mov  %rax,0x00(%rsp)\n"
"  mov  %r8, 0x08(%rsp)\n"
"  mov  %r9, 0x10(%rsp)\n"
"  mov  %r10,0x18(%rsp)\n"
"  mov  %r11,0x20(%rsp)\n"
"  mov  %rcx,0x28(%rsp)\n"
"  mov  %rdx,0x30(%rsp)\n"
"  mov  %rsi,0x38(%rsp)\n"
"  mov  %rdi,0x40(%rsp)\n"
"  mov  0x40(%rsp),%rdi\n"
"  mov  0x38(%rsp),%rsi\n"
"  mov  0x30(%rsp),%rdx\n"
"  mov  0x28(%rsp),%rcx\n"
"  call c2b_g11_udp_log\n"
/* 43f-g39 (BUGFIX, run183): ВОССТАНОВИТЬ арг-реги! Пролог 0x1fcd110
 * читает rcx->r13, rdi->r12, rdx->rbp, esi->rbx (49 89 cd/49 89 fc/
 * 48 89 d5/48 63 de) и делает test ebx,ebx; jle -> assert "nChunks > 0"
 * (0x1fcd408, line 415 socketthread.cpp). Логгер (C) затирает
 * rdi/rsi/rdx/rcx; без рестора пролог жил мусором: assert + мини-дамп +
 * смерть клиента в КАЖДОЙ попытке (run183 a1-a4), pcap пуст (sendto
 * с мусорными rbp/r13 падал). g11d/g11e тунки ресторят ПОЛНЫЙ набор —
 * только g11u терял четыре регистра. */
"  mov  0x28(%rsp),%rcx\n"
"  mov  0x30(%rsp),%rdx\n"
"  mov  0x38(%rsp),%rsi\n"
"  mov  0x40(%rsp),%rdi\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%r8\n"
"  mov  0x10(%rsp),%r9\n"
"  mov  0x18(%rsp),%r10\n"
"  mov  0x20(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g11_udp_tramp(%rip)\n"
".size c2b_g11_udp_thunk, .-c2b_g11_udp_thunk\n"
".globl c2b_g11_gather_thunk\n"
".type  c2b_g11_gather_thunk,@function\n"
"c2b_g11_gather_thunk:\n" /* вход: rsp%16==8; args: rdi=self rsi=nseg rdx=segs rcx=adr r8d=efd */
"  endbr64\n"
"  sub  $0x68,%rsp\n"      /* 104; rsp%16==0 */
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  call c2b_g11_gather_log\n" /* args уже в регах */
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x68,%rsp\n"
/* реплика 14Б пролога (0x1fc7c80..0x1fc7c8d), затем jmp на lea */
"  push %r15\n"
"  push %r14\n"
"  mov  %rcx,%r14\n"
"  push %r13\n"
"  mov  %rdi,%r13\n"
"  push %r12\n"
"  mov  c2b_g11_gather_cont(%rip),%r11\n"
"  jmp  *%r11\n"
".size c2b_g11_gather_thunk, .-c2b_g11_gather_thunk\n"
".globl c2b_g11_lag_thunk\n"
".type  c2b_g11_lag_thunk,@function\n"
"c2b_g11_lag_thunk:\n" /* вход: rsp%16==8; rdi=self rsi=pkt */
"  endbr64\n"
"  sub  $0x68,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  call c2b_g11_lag_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x68,%rsp\n"
/* реплика 24Б пролога 0x1fcd4e0 */
"  lea  0x28(%rsi),%rcx\n"
"  sub  $0x18,%rsp\n"
"  movslq 0x18(%rsi),%rax\n"
"  movzbl 0x41(%rsi),%r8d\n"
"  mov  %rsp,%rdx\n"
"  mov  0x48(%rsi),%rdi\n"
"  mov  c2b_g11_lag_cont(%rip),%r11\n"
"  jmp  *%r11\n"
".size c2b_g11_lag_thunk, .-c2b_g11_lag_thunk\n"
".globl c2b_g11_gate_thunk\n"
".type  c2b_g11_gate_thunk,@function\n"
"c2b_g11_gate_thunk:\n" /* вход: rsp%16==8 (call в функ); rbp=conn rsi=msg; rdx/rbx живы */
"  endbr64\n"
"  sub  $0x68,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  mov  %rbp,0x48(%rsp)\n"
"  mov  %rbp,%rdi\n"          /* arg1=conn */
"  mov  0x18(%rsp),%rsi\n"    /* arg2=msg */
"  call c2b_g11_gate_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  mov  0x48(%rsp),%rbp\n"
"  add  $0x68,%rsp\n"
/* реплика 14Б: cmpl $1,0x1b40(%rbp); jne bail; mov 0x180(%rbp),%eax */
"  cmpl $0x1,0x1b40(%rbp)\n"
"  jne  12f\n"
"  mov  0x180(%rbp),%eax\n"
"  mov  c2b_g11_gate_cont(%rip),%r11\n"
"  jmp  *%r11\n"
"12:\n"
"  mov  c2b_g11_gate_bail(%rip),%r11\n"
"  jmp  *%r11\n"
".size c2b_g11_gate_thunk, .-c2b_g11_gate_thunk\n"
".previous\n"
);
extern void c2b_g11_xport_thunk(void);
extern void c2b_g11_udp_thunk(void);
extern void c2b_g11_gather_thunk(void);
extern void c2b_g11_lag_thunk(void);
extern void c2b_g11_gate_thunk(void);

static void c2b_g11_apply(void)
{
    static u8 done;
    uptr base = 0, site, udp, tr, gather, lag, gate;
    if (done) return;
    dl_iterate_phdr(c2b_g8_phdr_cb, &base);   /* тот же фильтр steamclient.so */
    if (!base) return;
    site = base + C2B_G11_SITE_RVA;
    udp  = base + C2B_G11_UDP_RVA;
    if (memcmp((const void *)site, c2b_g11_sig_site, sizeof c2b_g11_sig_site) != 0) {
        C2B_LOGS("[c2b] g11: site sig mismatch\n"); done = 1; return;
    }
    if (memcmp((const void *)udp, c2b_g11_sig_udp, sizeof c2b_g11_sig_udp) != 0) {
        C2B_LOGS("[c2b] g11: udp sig mismatch\n"); done = 1; return;
    }
    /* g11d: BSendPacketGather (сиг-чек до установки g_g11_base — не критично,
     * но логгер требует base, ставим заранее вместе с cont) */
    gather = base + C2B_G11_GATHER_RVA;
    if (memcmp((const void *)gather, c2b_g11_sig_gather, sizeof c2b_g11_sig_gather) != 0) {
        C2B_LOGS("[c2b] g11: gather sig mismatch\n"); done = 1; return;
    }
    /* g11a: сайт транспорта */
    if (c2b_page_protect(site, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_g11_cont_addr = base + C2B_G11_CONT_RVA;   /* ДО пача сайта */
    c2b_g11_null_addr = base + C2B_G11_NULL_RVA;
    g_g11_base = base;                              /* ДО пача сайта */
    c2b_write_jmp((void *)site, (const void *)&c2b_g11_xport_thunk);
    /* 43f-g37 (RE run181, scripts/re_epoll_site*.py): СТОР в 0x2cbb900
     * УДАЛЁН навсегда. Этот глобал — НЕ "счётчик raw-UDP-сокетов" для
     * g11d-барьера, а СЧЁТЧИК ИНИЦИАЛИЗАЦИИ низкоуровневого слоя
     * (BSteamNetworkingSocketsLowLevelAddRef @0x1fca760: guard-mov @0x1fca784
     * читает его; !=0 -> ВЕСЬ init пропущен: wake-socketpair + ГЛОБАЛЬНЫЙ
     * epoll_create1 (s_hEpoll @0x2c6dcb8) НЕ создаются; ==0 -> полный init).
     * Наш стор 1 -> при Connect AddRef скипал init -> s_hEpoll = -1 ->
     * epoll_ctl(-1, ADD, sock) -> EBADF 0x9 -> "Cannot create IPv4 connection.
     * epoll_ctl failed, error 0x9" -> h=0 (runs 172-181). С реальным refcount
     * AddRef сам создаёт epoll при первом коннекте — барьер <=0 в
     * BSendPacketGather проходит естественно. */
    /* g11b: udp-обёртка (трамплин = копия пролога + jmp-хвост) */
    tr = (uptr)mmap(0, 4096, 0x07, 0x22 /*PRIVATE|ANON*/, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g11_udp_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)udp, sizeof c2b_g11_sig_udp);
    c2b_write_jmp((void *)(tr + sizeof c2b_g11_sig_udp),
                  (const void *)(udp + sizeof c2b_g11_sig_udp));
    c2b_g11_udp_tramp = (const volatile void *)tr;  /* ДО пача udp */
    if (c2b_page_protect(udp, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)udp, (const void *)&c2b_g11_udp_thunk);
    /* g11d: вход BSendPacketGather — чистая asm-репликация пролога в тунке,
     * cont = 0x1fc7c8e (lea rip-rel валидна в оригинальном положении) */
    c2b_g11_gather_cont = (const volatile void *)(base + C2B_G11_GATHER_CONT);
    if (c2b_page_protect(gather, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)gather, (const void *)&c2b_g11_gather_thunk);
    /* g11e: дрен lagger'а (per-packet send) */
    lag = base + C2B_G11_LAG_RVA;
    if (memcmp((const void *)lag, c2b_g11_sig_lag, sizeof c2b_g11_sig_lag) != 0) {
        C2B_LOGS("[c2b] g11: lag sig mismatch\n"); done = 1; return;
    }
    c2b_g11_lag_cont = (const volatile void *)(base + C2B_G11_LAG_CONT);
    if (c2b_page_protect(lag, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)lag, (const void *)&c2b_g11_lag_thunk);
    /* g11f: тихий гейт обработчика ChallengeReply */
    gate = base + C2B_G11_GATE_RVA;
    if (memcmp((const void *)gate, c2b_g11_sig_gate, sizeof c2b_g11_sig_gate) != 0) {
        C2B_LOGS("[c2b] g11: gate sig mismatch\n"); done = 1; return;
    }
    c2b_g11_gate_cont = (const volatile void *)(base + C2B_G11_GATE_CONT);
    c2b_g11_gate_bail = (const volatile void *)(base + C2B_G11_GATE_BAIL);
    if (c2b_page_protect(gate, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)gate, (const void *)&c2b_g11_gate_thunk);
    done = 1;
    C2B_LOGS("[c2b] g11: armed site+udp+gather+lag+gate base=");
    C2B_LOGH((u32)base); C2B_LOGS("\n");
}

/* ---------- 41f-g12: state-machine probes (observer) ----------
 * RE round 1437 (sc.asm d975c5):
 *  - conn+0x1b40 = ESteamNetworkingConnectionState (m_eConnState),
 *    +0x1b44 = m_eConnStateOld, +0x1b48 = m_usecWhenEnteredConnState.
 *    Доказательство: единственная статическая запись b40/b48 — SetState
 *    @0x1f76390 (this=rdi, esi=eNewState, rdx=usecNow): mov %ebx,0x1b40
 *    @0x1f763dd, mov %r13,0x1b48 @0x1f763e3; спец-ветки -1/-2/-3 и запись
 *    old-state @0x1f764bd/0x1f76414 = семантика ESteamNetworkingConnectionState
 *    (0 None, 1 Connecting, 2 FindingRoute, 3 Connected, 4 ClosedByPeer,
 *    5 ProblemDetectedLocally, -1 Linger, -2 FinWait, -3 Dead).
 *  - Гейт ChallengeReply @0x1fd5f68 требует state==1 (Connecting).
 *  - InitiateConnection @0x1f799c0 (rdi=this, rsi=usecNow, rdx=errMsg):
 *    state!=0 -> assert-spew через 26fcb60 (line 0xcca, строка @d6c790);
 *    виртуальный vtable+0x58 (слот 11) обязан вернуть true;
 *    conn+0x34==0 -> snprintf(d45390) + spew (line 0xcd9) + ВЫХОД БЕЗ
 *    SetState(1) (0x1f79b08 -> ret 0) — НЕВИДИМЫЙ отказ в Connecting;
 *    успех: SetState(1) @0x1f79a72 (второй сайт esi=1: 0x1f82f5c Think-retry).
 *  - ConnectTo @0x1fd14xx: holder{vt 2bd3b08, disp 0x1fd65e0} -> create
 *    (1fcb2f0) -> BInitConnect 0x1f83240 (rdi=conn, rsi=usecNow, edx=int,
 *    rcx=ptr, r8=errMsg; фейлы: state!=0, +0x30!=0, identity-несовпадение,
 *    GetIdentity vslot21) -> если true -> InitiateConnection @0x1fd16e9.
 * Зонды (детур входа; трамплин = сырая копия пролога + jmp cont):
 *  g12s: SetState 0x1f76390; пролог 16Б ТОЧНЫЙ (байты сверены с бинарем
 *        из run122: 4156 4155 4989d5 31d2 4154 55 4889fd 53; в sc.asm
 *        xor %edx,%edx @0x1f76397 был неверно прочитан как push %r12),
 *        cont 0x1f763a0. Лог: conn-rva, old, new(esi), usec, g30, g34, f158. Ловит КАЖДЫЙ переход состояния ЛЮБОГО коннекта.
 *  g12i: InitiateConnection 0x1f799c0; пролог 20Б точный, cont 0x1f799d4.
 *        Лог: conn-rva, state, g30, g34, f158, a1(usec).
 * Матрица решения (вместе с g11f run122):
 *  g12i есть + g12s new=1 тот же conn -> стейт-машина ОК, барьер дальше
 *  g12i есть, g12s(1) НЕТ -> блокировка внутри (vslot11 / +0x34==0 / assert)
 *  g12i НЕТ -> ConnectTo не вызывался вообще (верхний слой) */
#define C2B_G12_STATE_RVA  0x1f76390ull
#define C2B_G12_STATE_CONT 0x1f763a0ull
#define C2B_G12_INIT_RVA   0x1f799c0ull
#define C2B_G12_INIT_CONT  0x1f799d4ull

static const u8 c2b_g12_sig_init[20] = {
    0x41, 0x56,                   /* push %r14 */
    0x41, 0x55,                   /* push %r13 */
    0x49, 0x89, 0xD5,             /* mov %rdx,%r13 */
    0x41, 0x54,                   /* push %r12 */
    0x55,                         /* push %rbp */
    0x48, 0x89, 0xFD,             /* mov %rdi,%rbp */
    0x53,                         /* push %rbx */
    0x8B, 0x97, 0x40, 0x1B, 0x00, 0x00  /* mov 0x1b40(%rdi),%edx */
};
/* g12s: ТОЧНЫЙ пролог (сырье сверено с bins/steamclient.so__d975c5.so
 * из артефакта run122: @0x1f76397 = 31 D2 (xor %edx,%edx) — в sc.asm я
 * прочёл это как push %r12; маска wildcard больше не нужна) */
static const u8 c2b_g12_pat_state[16] = {
    0x41, 0x56,                   /* push %r14 */
    0x41, 0x55,                   /* push %r13 */
    0x49, 0x89, 0xD5,             /* mov %rdx,%r13 */
    0x31, 0xD2,                   /* xor %edx,%edx */
    0x41, 0x54,                   /* push %r12 */
    0x55,                         /* push %rbp */
    0x48, 0x89, 0xFD,             /* mov %rdi,%rbp */
    0x53                          /* push %rbx */
};
static const u8 c2b_g12_msk_state[16] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

static volatile u32 g_g11_ns;   /* анти-спам state-логгера */
static volatile u32 g_g11_ni;   /* анти-спам init-логгера */
static void *volatile c2b_g12s_tramp = 0;
static void *volatile c2b_g12i_tramp = 0;
static u8 *g_g12s_tramp_mem, *g_g12i_tramp_mem;

void c2b_g12s_log(uptr conn, uptr newstate, uptr usec)
{
    u32 n;
    if (!g_g11_base || !conn) return;
    n = ++g_g11_ns;
    if (n > 32 && (n & 0x0F) != 1) return;   /* первые 32, далее 1/16 */
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g12s state: conn=");
    C2B_LOGH((u32)(conn > g_g11_base ? conn - g_g11_base : 0));
    C2B_LOGS(" old="); C2B_LOGN(*(volatile u32 *)(conn + 0x1b40));
    C2B_LOGS(" new="); C2B_LOGN((u32)newstate);
    C2B_LOGS(" usec="); C2B_LOGH((u32)(usec >> 32)); C2B_LOGH((u32)usec);
    C2B_LOGS(" g30="); C2B_LOGN(*(volatile u32 *)(conn + 0x30));
    C2B_LOGS(" g34="); C2B_LOGN(*(volatile u32 *)(conn + 0x34));
    C2B_LOGS(" f158="); C2B_LOGN((u32)*(volatile u8 *)(conn + 0x158));
    C2B_LOGS("\n");
    g_probe_active = 0;
}

void c2b_g12i_log(uptr conn, uptr a1, uptr a2)
{
    u32 n;
    (void)a2;
    if (!g_g11_base || !conn) return;
    n = ++g_g11_ni;
    if (n > 32 && (n & 0x0F) != 1) return;
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g12i init: conn=");
    C2B_LOGH((u32)(conn > g_g11_base ? conn - g_g11_base : 0));
    C2B_LOGS(" st="); C2B_LOGN(*(volatile u32 *)(conn + 0x1b40));
    C2B_LOGS(" g30="); C2B_LOGN(*(volatile u32 *)(conn + 0x30));
    C2B_LOGS(" g34="); C2B_LOGN(*(volatile u32 *)(conn + 0x34));
    C2B_LOGS(" f158="); C2B_LOGN((u32)*(volatile u8 *)(conn + 0x158));
    C2B_LOGS(" a1="); C2B_LOGH((u32)(a1 >> 32)); C2B_LOGH((u32)a1);
    C2B_LOGS("\n");
    g_probe_active = 0;
}

__asm__(
".text\n"
".globl c2b_g12s_thunk\n"
".type  c2b_g12s_thunk,@function\n"
"c2b_g12s_thunk:\n"   /* вход: rsp%16==8; rdi=this esi=new rdx=usec */
"  endbr64\n"
"  sub  $0x58,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  call c2b_g12s_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g12s_tramp(%rip)\n"
".size c2b_g12s_thunk, .-c2b_g12s_thunk\n"
".globl c2b_g12i_thunk\n"
".type  c2b_g12i_thunk,@function\n"
"c2b_g12i_thunk:\n"   /* вход: rsp%16==8; rdi=this rsi=usec rdx=errMsg */
"  endbr64\n"
"  sub  $0x58,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  call c2b_g12i_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g12i_tramp(%rip)\n"
".size c2b_g12i_thunk, .-c2b_g12i_thunk\n"
".previous\n"
);
extern void c2b_g12s_thunk(void);
extern void c2b_g12i_thunk(void);

/* ---------- 41f-g13: диспетчер connectionless-пакетов ДВИЖКА (engine_client.so)
 *
 * ProcessConnectionlessPacket 0x259df0 (CClientState primary vt+0x68, base
 * 0xd78bb8; xref-clientstate.md): вход this=rdi (state), packet=rsi.
 * Пролог 19Б ТОЧНЫЙ (55 4889e5 4157 4989ff 4156 4155 4154 53 4889f3 — сверено
 * objdump с /tmp/engine-re/engine_client.so 34a96ae BuildID e9f63d98;
 * все инструкции позиционно-независимые), cont 0x259e03.
 * Лог: type-байт (bitbuf data@pkt+0x38, bitpos@pkt+0x50), hdr[0x00..0x1f]
 * (32Б — СНЕПОК-ФОРМАТ 'B'-чеков), data[0..7], state-rva.
 * ЦЕЛЬ: слепая зона xref-clientstate.md — что recv-путь кладёт в hdr для 'A'
 * и 'B' (чеки B: hdr[0x1c]==snap[0x50c]∈1..3, hdr[0x18]==-snap[0x508] (оба!=0),
 * u64@0x0c==snap, u32@0x14==snap) + доходит ли 'B' до диспатчера вообще.
 * Матрица решения:
 *  'A' и 'B' есть -> сравнить B.hdr c A.hdr локально -> точный фейл-чек
 *  'A' есть, 'B' НЕТ -> 'B' не доходит (recv-фильтр/порт/сокет/порядок фаз)
 *  ничего НЕТ -> диспатчер не тот / state[0x1a0] фильтр раньше (vt не тот)   */
#define C2B_G13_CLP_RVA  0x259df0ull
#define C2B_G13_CLP_CONT 0x259e03ull

/* 26B = 19B пролог + sub $0xa58,%rsp (специфичный кадр 0xa58 — малый шанс
 * ложного совпадения в монолите; тот же исходник, что engine_client.so
 * 34a96ae, собран в составе csgo_linux64 — байты функции должны совпасть) */
#define C2B_G13_SIG_N 26
static const u8 c2b_g13_pat_clp[26] = {
    0x55,                         /* push %rbp */
    0x48, 0x89, 0xE5,             /* mov %rsp,%rbp */
    0x41, 0x57,                   /* push %r15 */
    0x49, 0x89, 0xFF,             /* mov %rdi,%r15 */
    0x41, 0x56,                   /* push %r14 */
    0x41, 0x55,                   /* push %r13 */
    0x41, 0x54,                   /* push %r12 */
    0x53,                         /* push %rbx */
    0x48, 0x89, 0xF3,             /* mov %rsi,%rbx */
    0x48, 0x81, 0xEC, 0x58, 0x0A, 0x00, 0x00  /* sub $0xa58,%rsp */
};
static void *volatile c2b_g13_tramp = 0;
static u8 *g_g13_tramp_mem;
static volatile u32 g_g13_n;
static uptr g_g13_base;           /* (резерв) */

/* минимальная копия dl_phdr_info (glibc ABI стабилен: addr@0, name@8,
 * phdr@16, phnum@24) — полный struct объявлен ниже по файлу */
struct c2b_g13_phdr_min { uptr addr; const char *name; const void *phdr; u16 phnum; };
struct c2b_g13_phdr64 {          /* Elf64_Phdr (только нужное) */
    u32 type; u32 flags;
    u64 off, vaddr, paddr, filesz, memsz, align;
};
struct c2b_g13_ranges { uptr lo[128], hi[128]; u32 n; };  /* run142: 128+ модулей,
    cap 16 ЗАПОЛНЯЛСЯ ДО engine (загрузка #7-8) -> "pattern not found" в 141/142 */
static i32 c2b_g13_exec_phdr_cb(void *info_v, void *size_v, void *data_v)
{
    struct c2b_g13_phdr_min *info = (struct c2b_g13_phdr_min *)info_v;
    struct c2b_g13_ranges *r = (struct c2b_g13_ranges *)data_v;
    (void)size_v;
    if (!info->phdr || !info->phnum) return 0;
    {
        u16 i;
        for (i = 0; i < info->phnum && r->n < 128; i++) {
            const struct c2b_g13_phdr64 *ph =
                (const struct c2b_g13_phdr64 *)((const u8 *)info->phdr +
                                                (uptr)i * sizeof(*ph));
            if (ph->type == 1 && (ph->flags & 1) && ph->filesz > 0x1000 &&
                ph->filesz < ((uptr)1 << 28)) {
                r->lo[r->n] = info->addr + (uptr)ph->vaddr;
                r->hi[r->n] = r->lo[r->n] + (uptr)ph->filesz;
                r->n++;
            }
        }
    }
    return 0;
}

void c2b_g13_log(uptr state, uptr pkt)
{
    u32 n, i;
    uptr data;
    if (!pkt || !g_g13_base) return;
    n = ++g_g13_n;
    if (n > 24 && (n & 0x3F) != 1) return;
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g13 clp: t=");
    data = *(volatile uptr *)(pkt + 0x38);
    if (data) {
        u32 bp = *(volatile u32 *)(pkt + 0x50);
        C2B_LOGH(*(volatile const u8 *)(data + (bp >> 3)));
        C2B_LOGS(" bp="); C2B_LOGN(bp);
    } else {
        C2B_LOGS("-");
    }
    C2B_LOGS(" st=");
    C2B_LOGH((u32)(state >> 32)); C2B_LOGH((u32)state);
    C2B_LOGS(" hdr=");
    for (i = 0; i < 32; i++)
        C2B_LOGH(*(volatile const u8 *)(pkt + i));
    if (data) {
        C2B_LOGS(" d0=");
        for (i = 0; i < 8; i++)
            C2B_LOGH(*(volatile const u8 *)(data + i));
    }
    C2B_LOGS("\n");
    g_probe_active = 0;
}

__asm__(
".text\n"
".globl c2b_g13_thunk\n"
".type  c2b_g13_thunk,@function\n"
"c2b_g13_thunk:\n"   /* вход: rsp%16==8; rdi=state rsi=pkt */
"  endbr64\n"
"  sub  $0x58,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  call c2b_g13_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g13_tramp(%rip)\n"
".size c2b_g13_thunk, .-c2b_g13_thunk\n"
".previous\n"
);
extern void c2b_g13_thunk(void);

/* Самолокализация диспатчера (26B паттерн) по ВСЕМ модулям процесса:
 * dl_iterate_phdr -> PT_LOAD+PF_X сегменты каждого модуля (безопасные
 * границы) -> скан. Арм ТОЛЬКО при ровно одном совпадении на процесс.
 * Возврат: 0 = нашли ровно 1 (*tgt), 1 = 0 или >1 (диагностика в логе). */
static i32 c2b_g13_selfscan(uptr *tgt)
{
    struct c2b_g13_ranges rg;
    u32 hits = 0, i;
    rg.n = 0;
    dl_iterate_phdr(c2b_g13_exec_phdr_cb, &rg);
    if (!rg.n) { C2B_LOGS("[c2b] g13: no exec ranges\n"); return 1; }
    for (i = 0; i < rg.n; i++) {
        const u8 *p = (const u8 *)rg.lo[i];
        const u8 *end = (const u8 *)rg.hi[i] - C2B_G13_SIG_N;
        for (; p <= end; p++) {
            if (p[0] == 0x55 && p[1] == 0x48 && p[2] == 0x89 && p[3] == 0xE5 &&
                p[4] == 0x41 && p[6] == 0x49 &&
                memcmp(p, c2b_g13_pat_clp, C2B_G13_SIG_N) == 0) {
                if (hits < 4) {
                    C2B_LOGS("[c2b] g13: hit @");
                    C2B_LOGH((u32)((uptr)p >> 32));
                    C2B_LOGH((u32)(uptr)p);
                    C2B_LOGS("\n");
                }
                if (hits == 0) *tgt = (uptr)p;
                hits++;
                if (hits >= 2) return 1;   /* неуникален — вслепую не армим */
            }
        }
    }
    if (!hits) C2B_LOGS("[c2b] g13: pattern not found in any module\n");
    return hits != 1;
}

static void c2b_g13_apply(void)
{
    static u8 done;
    uptr base, tgt = 0, tr;
    if (done) return;
    /* 1) быстрый путь: известная база движка + RVA (uplink sig уже доказал
     *    совпадение рантайм-движка с 34a96ae) */
    base = g_engine_base;
    if (base) {
        tgt = base + C2B_G13_CLP_RVA;
        if (memcmp((const void *)tgt, c2b_g13_pat_clp, C2B_G13_SIG_N) == 0)
            goto arm;
        C2B_LOGS("[c2b] g13: rva mismatch -> selfscan\n");
    }
    /* 2) общий путь: скан всех модулей (run124: в ряде попыток движок
     *    вообще не резолвится legacy-сканом; модуль может грузиться поздно).
     *    «Не найдено» — НЕ терминально: ретрай до ~40 итераций rearm-цикла
     *    (~3.5 мин), потом сдаться с диагностикой. */
    if (c2b_g13_selfscan(&tgt) != 0) {
        static u32 tries;
        u32 miss = 0;
        if (++tries <= 40) return;         /* ретрай в следующей итерации */
        miss = 1;
        (void)miss;
        done = 1;
        return;
    }
arm:
    tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g13_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)tgt, C2B_G13_SIG_N);
    c2b_write_jmp((void *)(tr + C2B_G13_SIG_N),
                  (const void *)(tgt + C2B_G13_SIG_N));
    c2b_g13_tramp = (const volatile void *)tr;
    if (c2b_page_protect(tgt, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)tgt, (const void *)&c2b_g13_thunk);
    done = 1;
    C2B_LOGS("[c2b] g13: armed clp @");
    C2B_LOGH((u32)(tgt >> 32)); C2B_LOGH((u32)tgt);
    C2B_LOGS("\n");
}

/* ---------- 41f-g16: ЖИВОЙ путь датаграмм движка (evidence run 127 / g15) ----
 * g15 (run127): живой recvfrom-сайт = engine_client.so+0x4d63a1 (HOT h=100),
 * send-сайт = +0x4d0934. Статика (34a96ae, engine.asm):
 *  - 0x4d63a1 = точка сразу ПОСЛЕ call recvfrom@plt (0x4d639c) в насосе
 *    0x4d61d0: recv-ТРЕД (обёртка-тело 0x4d70b0 -> CreateSimpleThread @0x4d0f3a,
 *    init с socketpair), буфер = sockobj+4 (sockobj{u32 len; u8 buf[0x100010]}),
 *    from = rbp-0x70. После приёма датаграмма копируется в аккумулятор и
 *    ПУШИТСЯ в lock-free очередь (node 0x2a3, Alloc @0x4d661d) — консьюмер
 *    на другом треде, его парсер пока неизвестен.
 *  - 0x4d08c0 = send-обёртка (rdi=sock, esi=fd, rdx=data, ecx=len, r9=netadr;
 *    NetAdrToSockaddr @0x65ec40 -> sendto@plt @0x4d092f). ЕЮ движок шлёт ВСЁ
 *    исходящее UDP: 'j' после 'A', LanSearch, getchallenge.
 *  - Семейство 0x259df0 (g13) извне входит ТОЛЬКО через entry (2 vtable-wrappers,
 *    0x25de04/0x2c9545) — и после арма НЕ ОГОРАЕТ при живых bait'ах (run126),
 *    т.е. живой парсер connectionless — ДРУГОЙ код. g16 даёт его адреса:
 *   a) g16a = entry-детур send-обёртки 0x4d08c0: рет0 вызывающего = САЙТ
 *      РЕАКЦИИ ('j'-отправитель = 'A'-парсер; LanSearch-эмиттер отдельно).
 *   b) g16b = пост-recvfrom детур 0x4d63a1: дамп КАЖДОЙ входящей датаграммы
 *      (len, from, data[0..11]) — что реально доезжает до насоса.
 * Патч 14Б (jmp [rip+0]); крадём до границы инструкций: g16a 16Б (0x4d08c0..cf,
 * все позиционно-независимые), cont 0x4d08d0; g16b 15Б (0x4d63a1..af, ВКЛЮЧАЯ
 * jle rel32 — в трамплине rel32 ПЕРЕСЧИТЫВАЕТСЯ на 0x4d6a50!), cont 0x4d63b0.
 * Сигнатуры сверены оффлайн с 34a96ae (BuildID e9f63d98). */
#define C2B_G16_SEND_RVA  0x4d08c0ull
#define C2B_G16_SEND_CONT 0x4d08d0ull
#define C2B_G16_RECV_RVA  0x4d63a1ull
#define C2B_G16_RECV_CONT 0x4d63b0ull
#define C2B_G16_JLE_TGT   0x4d6a50ull
static const u8 c2b_g16a_sig[16] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x49, 0x89, 0xD7,
    0x41, 0x56, 0x41, 0x55, 0x41, 0x89, 0xCD };
static const u8 c2b_g16b_sig[15] = {
    0x85, 0xC0, 0x48, 0x89, 0x85, 0x98, 0xFE, 0xFF, 0xFF,
    0x0F, 0x8E, 0xA0, 0x06, 0x00, 0x00 };
static u8 *g_g16a_tramp_mem;
static u8 *g_g16b_tramp_mem;
__attribute__((used)) static void *volatile c2b_g16a_tramp;
__attribute__((used)) static void *volatile c2b_g16b_tramp;

/* уникальные ret0-сайты (стиль g15): LanSearch-спам не вытеснит редкие
 * 'j'-реакции из лога — логируем КАЖДЫЙ новый сайт, hot-метки 100/10000 */
struct c2b_g16_site { uptr ra; u32 hits; };
static struct c2b_g16_site g_g16a_tab[8];
static u32 g_g16a_n;
static u32 g_g16a_ev;

void c2b_g16a_log(uptr ret0, uptr dataptr, u32 len)
{
    u32 i, h = 1;
    for (i = 0; i < g_g16a_n && i < 8; i++) {
        if (g_g16a_tab[i].ra == ret0) {
            h = ++g_g16a_tab[i].hits;
            if (h != 100 && h != 10000) return;
            if (g_probe_active) return;
            g_probe_active = 1;
            if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
            C2B_LOGS("[c2b] g16 send hot ra=");
            C2B_LOGH((u32)(ret0 >> 32)); C2B_LOGH((u32)ret0);
            C2B_LOGS("h="); C2B_LOGN(h); C2B_LOGS("\n");
            g_probe_active = 0;
            return;
        }
    }
    if (g_g16a_n < 8) {
        g_g16a_tab[g_g16a_n].ra = ret0;
        g_g16a_tab[g_g16a_n].hits = 1;
        g_g16a_n++;
    } else if (g_g16a_ev < 24) {
        /* вытеснение минимального (init-сайты уходят, hot остаётся) */
        u32 mi = 0;
        for (i = 1; i < 8; i++)
            if (g_g16a_tab[i].hits < g_g16a_tab[mi].hits) mi = i;
        g_g16a_ev++;
        g_g16a_tab[mi].ra = ret0;
        g_g16a_tab[mi].hits = 1;
    } else {
        return;   /* зоопарк одноразовых — молча */
    }
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g16 send: ra=");
    C2B_LOGH((u32)(ret0 >> 32)); C2B_LOGH((u32)ret0);
    if (g_engine_base && ret0 > g_engine_base &&
        ret0 - g_engine_base < 0x8000000ull) {
        C2B_LOGS("rva="); C2B_LOGH((u32)(ret0 - g_engine_base));
    }
    if (dataptr && len) {
        C2B_LOGS("d=");
        for (i = 0; i < 8 && i < len; i++)
            C2B_LOGH(*(volatile const u8 *)(dataptr + i));
    }
    C2B_LOGS("len="); C2B_LOGN(len); C2B_LOGS("\n");
    g_probe_active = 0;
}

void c2b_g16b_log(uptr rlen, uptr frame)
{
    static volatile u32 n;
    static volatile u32 cl;   /* connectionless-помеченные */
    u32 i, cnt;
    uptr sp;
    const u8 *data, *from;
    if (!frame) return;
    cnt = ++n;
    /* первые 24 — всё подряд (калибровка шума); дальше ТОЛЬКО
     * connectionless-помеченные (ffffffff + печатный тип) — редкие 'A'/'B'
     * bait'ы не теряются в broadcast-шуме */
    if (cnt > 24) {
        sp = *(volatile uptr *)(frame - 0x140);
        data = sp ? (const u8 *)(sp + 4) : (const u8 *)0;
        if (!data || (i32)rlen < 5) return;
        if (*(volatile const u32 *)data != 0xffffffffu) return;
        {
            u8 t = *(volatile const u8 *)(data + 4);
            if (t < 0x21 || t > 0x7e) return;
        }
        if (++cl > 40 && (cl & 0x0F) != 1) return;
    }
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g16 recv: len=");
    C2B_LOGN((u32)(i32)rlen);
    from = (const u8 *)(frame - 0x70);      /* sockaddr_in: fam2 port2 ip4 */
    C2B_LOGS("from=");
    for (i = 0; i < 8; i++) C2B_LOGH(from[i]);
    sp = *(volatile uptr *)(frame - 0x140);  /* sockobj */
    data = sp ? (const u8 *)(sp + 4) : (const u8 *)0;
    if (data && (i32)rlen > 0) {
        C2B_LOGS("d=");
        for (i = 0; i < 12 && (u32)i < (u32)rlen; i++)
            C2B_LOGH(data[i]);
    }
    C2B_LOGS("\n");
    g_probe_active = 0;
}

__asm__(
".text\n"
".globl c2b_g16a_thunk\n"
".type  c2b_g16a_thunk,@function\n"
"c2b_g16a_thunk:\n"   /* вход: rsp%16==8; r10/r11/rax мертвы до записи */
"  endbr64\n"
"  mov  (%rsp),%r10\n"          /* ret0 = вызывающий обёртки */
"  sub  $0x58,%rsp\n"
"  mov  %r10,0x00(%rsp)\n"
"  mov  %rdi,0x08(%rsp)\n"
"  mov  %rsi,0x10(%rsp)\n"
"  mov  %rdx,0x18(%rsp)\n"
"  mov  %rcx,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %rax,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  mov  %r10,%rdi\n"            /* arg1 = ret0 */
"  mov  %rdx,%rsi\n"            /* arg2 = data ptr */
"  mov  %rcx,%rdx\n"            /* arg3 = len (ecx) */
"  call c2b_g16a_log\n"
"  mov  0x00(%rsp),%r10\n"
"  mov  0x08(%rsp),%rdi\n"
"  mov  0x10(%rsp),%rsi\n"
"  mov  0x18(%rsp),%rdx\n"
"  mov  0x20(%rsp),%rcx\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%rax\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g16a_tramp(%rip)\n"
".size c2b_g16a_thunk, .-c2b_g16a_thunk\n"
".globl c2b_g16b_thunk\n"
".type  c2b_g16b_thunk,@function\n"
"c2b_g16b_thunk:\n"   /* вход сразу после recvfrom: rax=len, rbp=кадр насоса */
"  endbr64\n"
"  sub  $0x58,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rbp,0x08(%rsp)\n"
"  mov  %rdi,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdx,0x20(%rsp)\n"
"  mov  %rcx,0x28(%rsp)\n"
"  mov  %r8, 0x30(%rsp)\n"
"  mov  %r9, 0x38(%rsp)\n"
"  mov  %r10,0x40(%rsp)\n"
"  mov  %r11,0x48(%rsp)\n"
"  mov  %rax,%rdi\n"            /* arg1 = recvfrom rc */
"  mov  %rbp,%rsi\n"            /* arg2 = кадр насоса */
"  call c2b_g16b_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rbp\n"
"  mov  0x10(%rsp),%rdi\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdx\n"
"  mov  0x28(%rsp),%rcx\n"
"  mov  0x30(%rsp),%r8\n"
"  mov  0x38(%rsp),%r9\n"
"  mov  0x40(%rsp),%r10\n"
"  mov  0x48(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g16b_tramp(%rip)\n" /* tramp: test+mov+jle(фикс rel32) -> cont */
".size c2b_g16b_thunk, .-c2b_g16b_thunk\n"
".previous\n"
);
extern void c2b_g16a_thunk(void);
extern void c2b_g16b_thunk(void);

static void c2b_g16_apply(void)
{
    static u8 done;
    uptr base, sa, ra, tr;
    if (done) return;
    base = g_engine_base;
    if (!base) return;               /* движок ещё не_resolved — ретрай */
    sa = base + C2B_G16_SEND_RVA;
    if (memcmp((const void *)sa, c2b_g16a_sig, sizeof c2b_g16a_sig) != 0) {
        C2B_LOGS("[c2b] g16: send sig mismatch\n"); done = 1; return;
    }
    ra = base + C2B_G16_RECV_RVA;
    if (memcmp((const void *)ra, c2b_g16b_sig, sizeof c2b_g16b_sig) != 0) {
        C2B_LOGS("[c2b] g16: recv sig mismatch\n"); done = 1; return;
    }
    /* g16a tramp: 16Б украденных + jmp cont */
    tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g16a_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)sa, sizeof c2b_g16a_sig);
    c2b_write_jmp((void *)(tr + sizeof c2b_g16a_sig),
                  (const void *)(base + C2B_G16_SEND_CONT));
    c2b_g16a_tramp = (const volatile void *)tr;
    if (c2b_page_protect(sa, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)sa, (const void *)&c2b_g16a_thunk);
    /* g16b tramp: 9Б (test+mov) + jle С ПЕРЕСЧИТОМ rel32 -> jmp cont */
    tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g16b_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)ra, 9);
    {
        u8 jl[6];
        i32 rel = (i32)((base + C2B_G16_JLE_TGT) - (tr + 9 + 6));
        jl[0] = 0x0F; jl[1] = 0x8E;
        jl[2] = (u8)(u32)rel;         jl[3] = (u8)((u32)rel >> 8);
        jl[4] = (u8)((u32)rel >> 16); jl[5] = (u8)((u32)rel >> 24);
        memcpy((void *)(tr + 9), jl, 6);
    }
    c2b_write_jmp((void *)(tr + 15), (const void *)(base + C2B_G16_RECV_CONT));
    c2b_g16b_tramp = (const volatile void *)tr;
    if (c2b_page_protect(ra, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)ra, (const void *)&c2b_g16b_thunk);
    done = 1;
    C2B_LOGS("[c2b] g16: armed send+recv base=");
    C2B_LOGH((u32)base); C2B_LOGS("\n");
}

/* ---------- 41f-g17: вердикт connectionless-фильтра (evidence run129) -------
 * Run129: 'A'-bait (ff ff ff ff 'A' ch32, from 152.233.19.133:28022) И 'I'-info
 * ДОХОДЯТ до pump-recvfrom (g16b), но движок НЕ реагирует (нет 'j', фазы не
 * идут, getchallenge НЕ повторяется). Статика: connectionless-ветка насоса
 * 0x4d6b80 строит объект {netadr@0, field8@8, ...} и зовёт ФИЛЬТР 0x390d80;
 * его вердикт (al): TRUE -> test/jne 0x4d64fb = ENQUEUE в очередь (консьюмер
 * на гл. треде = живой парсер), FALSE -> jmp 0x4d6360 = СИЛЫЙ ДРОП (обратно в
 * recv). Фильтр: obj+0x1c!=0 -> сразу 1; иначе мьютекс + матчер 0x38e830
 * (Plat_FloatTime + проход списка зарегистрированных соединений, typeinfo
 * 0x224f30) — ПРЕЙМ-ПОДОЗРЕВАЕМЫЙ БАРЬЕР: baits могут дропаться из-за
 * "нет активного соединения с адресом" -> объясняет нули g13 (семейство
 * 0x259df0 зовётся консьюмером очереди, куда baits не доходят) и молчание.
 * g17a = entry-детур фильтра 0x390d80 (крадём 20Б до 0x390d94, все
 * позиционно-независимые): дамп obj[0..31] (netadr+поля) на входе.
 * g17b = патч точки вердикта 0x4d6bea (ровно 14Б: test %r13b + jne + jmp,
 * ОБА rel32 в трамплине пересчитаны: jne->0x4d64fb, jmp->0x4d6360): лог
 * вердикта r13b + obj. Сигнатуры сверены оффлайн с 34a96ae. */
#define C2B_G17_FILT_RVA  0x390d80ull
#define C2B_G17_FILT_CONT 0x390d94ull
#define C2B_G17_VERD_RVA  0x4d6beaull
#define C2B_G17_VERD_CONT 0x4d6bf8ull
#define C2B_G17_JNE_TGT   0x4d64fbull
#define C2B_G17_JMP_TGT   0x4d6360ull
static const u8 c2b_g17a_sig[20] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55,
    0x41, 0x54, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x8B, 0x4F, 0x1C };
static const u8 c2b_g17b_sig[14] = {
    0x45, 0x84, 0xED, 0x0F, 0x85, 0x08, 0xF9, 0xFF, 0xFF,
    0xE9, 0x68, 0xF7, 0xFF, 0xFF };
static u8 *g_g17a_tramp_mem;
static u8 *g_g17b_tramp_mem;
__attribute__((used)) static void *volatile c2b_g17a_tramp;
__attribute__((used)) static void *volatile c2b_g17b_tramp;

void c2b_g17a_log(uptr obj)
{
    static volatile u32 n;
    u32 i, cnt;
    if (!obj) return;
    cnt = ++n;
    if (cnt > 24 && (cnt & 0x3F) != 1) return;
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g17 filt-in: ");
    for (i = 0; i < 32; i++)
        C2B_LOGH(*(volatile const u8 *)(obj + i));
    C2B_LOGS("\n");
    g_probe_active = 0;
}

void c2b_g17b_log(uptr verdict, uptr obj)
{
    static volatile u32 n;
    u32 i, cnt;
    if (!obj) return;
    cnt = ++n;
    if (cnt > 24 && (cnt & 0x3F) != 1) return;
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g17 verdict: ");
    C2B_LOGN((u32)(verdict & 0xff));
    C2B_LOGS("obj=");
    for (i = 0; i < 32; i++)
        C2B_LOGH(*(volatile const u8 *)(obj + i));
    C2B_LOGS("\n");
    g_probe_active = 0;
}

__asm__(
".text\n"
".globl c2b_g17a_thunk\n"
".type  c2b_g17a_thunk,@function\n"
"c2b_g17a_thunk:\n"   /* вход: rdi=obj; rdi протаскиваем в логгер как есть */
"  endbr64\n"
"  sub  $0x58,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %r8, 0x20(%rsp)\n"
"  mov  %r9, 0x28(%rsp)\n"
"  mov  %r10,0x30(%rsp)\n"
"  mov  %r11,0x38(%rsp)\n"
"  call c2b_g17a_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%r8\n"
"  mov  0x28(%rsp),%r9\n"
"  mov  0x30(%rsp),%r10\n"
"  mov  0x38(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g17a_tramp(%rip)\n"
".size c2b_g17a_thunk, .-c2b_g17a_thunk\n"
".globl c2b_g17b_thunk\n"
".type  c2b_g17b_thunk,@function\n"
"c2b_g17b_thunk:\n"   /* вход: r13b=вердикт, rbx=obj; callee-saved не трогаем */
"  endbr64\n"
"  sub  $0x58,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rdi,0x18(%rsp)\n"
"  mov  %rsi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  mov  %r13d,%edi\n"
"  mov  %rbx,%rsi\n"
"  call c2b_g17b_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rdi\n"
"  mov  0x20(%rsp),%rsi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g17b_tramp(%rip)\n"
".size c2b_g17b_thunk, .-c2b_g17b_thunk\n"
".previous\n"
);
extern void c2b_g17a_thunk(void);
extern void c2b_g17b_thunk(void);

static void c2b_g17_apply(void)
{
    static u8 done;
    uptr base, fa, va, tr;
    if (done) return;
    base = g_engine_base;
    if (!base) return;
    fa = base + C2B_G17_FILT_RVA;
    if (memcmp((const void *)fa, c2b_g17a_sig, sizeof c2b_g17a_sig) != 0) {
        C2B_LOGS("[c2b] g17: filt sig mismatch\n"); done = 1; return;
    }
    va = base + C2B_G17_VERD_RVA;
    if (memcmp((const void *)va, c2b_g17b_sig, sizeof c2b_g17b_sig) != 0) {
        C2B_LOGS("[c2b] g17: verdict sig mismatch\n"); done = 1; return;
    }
    /* g17a tramp: 20Б украденных + jmp cont */
    tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g17a_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)fa, sizeof c2b_g17a_sig);
    c2b_write_jmp((void *)(tr + sizeof c2b_g17a_sig),
                  (const void *)(base + C2B_G17_FILT_CONT));
    c2b_g17a_tramp = (const volatile void *)tr;
    if (c2b_page_protect(fa, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)fa, (const void *)&c2b_g17a_thunk);
    /* g17b tramp: test(3Б) + jne(6Б, rel32->0x4d64fb) + jmp(5Б, rel32->0x4d6360)
     * + write_jmp cont */
    tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g17b_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)va, 3);
    {
        u8 br[6];
        i32 rel;
        rel = (i32)((base + C2B_G17_JNE_TGT) - (tr + 3 + 6));
        br[0] = 0x0F; br[1] = 0x85;
        br[2] = (u8)(u32)rel;         br[3] = (u8)((u32)rel >> 8);
        br[4] = (u8)((u32)rel >> 16); br[5] = (u8)((u32)rel >> 24);
        memcpy((void *)(tr + 3), br, 6);
        rel = (i32)((base + C2B_G17_JMP_TGT) - (tr + 9 + 5));
        br[0] = 0xE9;
        br[1] = (u8)(u32)rel;         br[2] = (u8)((u32)rel >> 8);
        br[3] = (u8)((u32)rel >> 16); br[4] = (u8)((u32)rel >> 24);
        memcpy((void *)(tr + 9), br, 5);
    }
    c2b_write_jmp((void *)(tr + 14), (const void *)(base + C2B_G17_VERD_CONT));
    c2b_g17b_tramp = (const volatile void *)tr;
    if (c2b_page_protect(va, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)va, (const void *)&c2b_g17b_thunk);
    done = 1;
    C2B_LOGS("[c2b] g17: armed filt+verdict base=");
    C2B_LOGH((u32)base); C2B_LOGS("\n");
}

/* ---------- 41f-g18: поиск консьюмера через захват освободителя нод --------
 * Run130: 'A'-bait verdict=1 -> ENQUEUED, но консьюмер не зовёт 0x259df0 и
 * движок молчит. Статический поиск консьюмера провалился: TSQueue —
 * header-only шаблон, pop-код инлайнится ПОМОДУЛЬНО (0x4d49c0 зовут только
 * shutdown-пути насоса 0x4d6a7b/0x4d6fee) — консьюмер может жить в другом
 * модуле бандла со своей инлайн-копией. РЕШАЮЩАЯ РАНТАЙМ-ПРОБА: поймать,
 * КТО освобождает датаграммные ноды.
 * g18a: пост-Alloc детур в насосе 0x4d6620 (rax = сырая нода от IMemAlloc
 * Alloc; крадём 17Б: test/je[rel32 ФИКС -> 0x4d6e8a]/lea 0x17(%rax),%r13/
 * and ~0xF,%r13, cont 0x4d6631) — в кольцо (8 слотов) пишется ВЫРОВНЕННЫЙ
 * указатель ноды (rax+0x17)&~0xF — именно его потом освобождают.
 * g18b: патч слота Free в vtable аллокатора: obj = *(*(base+0xdf6e50))
 * (g_pMemAlloc = GOT-слот на IMemAlloc**, два разыменования — насос
 * 0x4d7013/создание 0x4d0e2d); vt = *obj; слот vt+0x10 = Free (насос зовёт
 * с rdi=this, rsi=ptr). Слoт ХРАНИТ УКАЗАТЕЛЬ НА ФУНКЦИЮ — трaмплин не
 * нужен: пишем туда адрес g18b-thunk, thunk логирует ret0 (только если rsi
 * совпал с кольцом нод) и хвостовым jmp зовёт сохранённый оригинал.
 * ret0 при освобождении НАШЕЙ ноды = адрес ВНУТРИ КОНСЬЮМЕРА. */
#define C2B_G18_NODEALLOC_RVA  0x4d6620ull
#define C2B_G18_NODEALLOC_CONT 0x4d6631ull
#define C2B_G18_JE_TGT         0x4d6e8aull
#define C2B_G18_GPTR_RVA       0xdf6e50ull   /* g_pMemAlloc (IMemAlloc**) */
#define C2B_G18_FREE_SLOT      0x10ull
static const u8 c2b_g18a_sig[17] = {
    0x48, 0x85, 0xC0, 0x0F, 0x84, 0x61, 0x08, 0x00, 0x00,
    0x4C, 0x8D, 0x68, 0x17, 0x49, 0x83, 0xE5, 0xF0 };
static u8 *g_g18a_tramp_mem;
__attribute__((used)) static void *volatile c2b_g18a_tramp;
__attribute__((used)) static uptr volatile c2b_g18_orig_free;
#define C2B_G18_RING 64   /* 8 было мало: LanSearch-эхо вытесняло bait-ноду до free */
static uptr volatile g_g18_nodes[C2B_G18_RING];
static uptr volatile g_g18_raw[C2B_G18_RING];   /* 2307: и СЫРЫЕ указатели Alloc */
static u32 volatile g_g18_node_idx;
/* 2307: таблица уникальных САЙТОВ свободных вызовов (не попавших в кольцо).
 * Тайна runs 138/139: 1-4 allocs в кольце, консьюмер жив ('A'->'j'), но 0
 * ring-matched frees. Кто вообще зовёт Free через патченный слот? Таблица
 * отвечает: каждый новый ret0 логируется ОДИН раз; при полной таблице —
 * 1/64 семплирование (канал открытия новых сайтов). ЖЁСТКИЕ ОГРАНИЧЕНИЯ
 * (урок run133): БЕЗ deref ptr, БЕЗ loader-вызовов, БЕЗ блокировок —
 * только волатильные статики; гонки бенигны (дубль строки допустим). */
#define C2B_G18_SITES 32
static uptr volatile g_g18_sites[C2B_G18_SITES];
static u32 volatile g_g18_site_cnt;   /* 1/64 семпл при полной таблице */
static u32 volatile g_g18_site_logs;  /* шапка семплов: не более 64 строк */
/* run140 УРОК: 65 строк free-site УШЛИ в интервал 417-487 (между патчем
 * слота и первым bait) — бюджет таблицы/семплов выгорел ДО окна наживки.
 * ФИКС: реарм канала сайтов при КАЖДОМ node-alloc (насос выделил ноду =
 * bait-поток активен): таблица чистится, счётчики в 0. Гонки бенигны. */
static void c2b_g18_site_rearm(void)
{
    u32 i;
    for (i = 0; i < C2B_G18_SITES; i++) g_g18_sites[i] = 0;
    g_g18_site_cnt = 0;
    g_g18_site_logs = 0;
}
/* run133 УРОК: атрибуция через dl_iterate_phdr ВНУТРИ Free (слот патчится на
 * ВСЁ-ПРОЦЕССНЫЙ аллокатор!) совпала с нулевыми Alloc и SIGSEGV консьюмера —
 * атрибуция УБРАНА из hot-пути (ответ уже получен: matchmaking_client.so
 * +0x2a029). Слот Free = самыи горячии путь в процессе — только кольцо и лог. */

void c2b_g18a_log(uptr raw_node)
{
    static volatile u32 n;
    u32 cnt;
    if (!raw_node) return;
    /* насос выравнивает: (rax+0x17) & ~0xF — свободят именно выровненный */
    g_g18_nodes[g_g18_node_idx % C2B_G18_RING] = (raw_node + 0x17) & ~(uptr)0xF;
    g_g18_raw[g_g18_node_idx % C2B_G18_RING] = raw_node;   /* 2307: и сырый */
    g_g18_node_idx++;
    c2b_g18_site_rearm();   /* окно сайтов переоткрывается после каждой ноды */
    cnt = ++n;
    if (cnt > 4) return;
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g18 node-alloc: ");
    C2B_LOGH((u32)(raw_node >> 32)); C2B_LOGH((u32)raw_node);
    C2B_LOGS("\n");
    g_probe_active = 0;
}

void c2b_g18b_log(uptr ret0, uptr ptr)
{
    static volatile u32 n;
    u32 i, j, cnt;
    if (!ptr) return;                          /* Free(NULL): кольцо нулевое -> false match (run133) */
    for (i = 0; i < C2B_G18_RING; i++)
        if (g_g18_nodes[i] == ptr) break;
    if (i >= C2B_G18_RING)
        for (i = 0; i < C2B_G18_RING; i++)     /* 2307: и сырое значение Alloc */
            if (g_g18_raw[i] == ptr) break;
    if (i >= C2B_G18_RING) {
        /* 2307: не наша нода — сайт свободного вызова. Первый sighting
         * логируем, повторные молчат; полная таблица -> 1/64 семпл. */
        for (j = 0; j < C2B_G18_SITES; j++)
            if (g_g18_sites[j] == ret0) return;
        for (j = 0; j < C2B_G18_SITES; j++)
            if (g_g18_sites[j] == 0) { g_g18_sites[j] = ret0; break; }
        if (j >= C2B_G18_SITES) {
            cnt = ++g_g18_site_cnt;
            if ((cnt & 0x3F) != 1 || g_g18_site_logs > 64) return;
            g_g18_site_logs++;
        }
        C2B_LOGS("[c2b] g18 free-site: ra=");
        C2B_LOGH((u32)(ret0 >> 32)); C2B_LOGH((u32)ret0);
        if (g_engine_base && ret0 > g_engine_base &&
            ret0 - g_engine_base < 0x8000000ull) {
            C2B_LOGS("rva="); C2B_LOGH((u32)(ret0 - g_engine_base));
        }
        C2B_LOGS(" ptr=");
        C2B_LOGH((u32)(ptr >> 32)); C2B_LOGH((u32)ptr);
        C2B_LOGS("\n");
        return;
    }
    cnt = ++n;
    if (cnt > 8 && (cnt & 0x1F) != 1) return;
    /* БЕЗ sigsetjmp-гарда: гарды живут только пока стоит хендлер auth-пробой,
     * а слот Free патчится с РАННЕГО арма — фолт тут = мгновенная смерть.
     * Здесь только чтение кольца и лог — фолт невозможен.
     * 41f-g19-перенос: раз г19-сайт (0x2e1ad5) ЛЕТАЛЕН (run133: краш сразу
     * после первого исполнения; run132 без него — чисто), дамп ноды делаем
     * ЗДЕСЬ: ptr в кольце = нода насоса (Fork1 0x47=71Б), читаем 32Б полей
     * (+0=sockobj, +8=payload ptr, +0x10=len, +0x18/+0x1c=netadr) — риск
     * page-end только для 0x27-канальных нод, и то 9Б в тот же heap-чанк. */
    C2B_LOGS("[c2b] g18 free-node: ra=");
    C2B_LOGH((u32)(ret0 >> 32)); C2B_LOGH((u32)ret0);
    if (g_engine_base && ret0 > g_engine_base &&
        ret0 - g_engine_base < 0x8000000ull) {
        C2B_LOGS("rva="); C2B_LOGH((u32)(ret0 - g_engine_base));
    }
    C2B_LOGS(" node=");
    C2B_LOGH((u32)(ptr >> 32)); C2B_LOGH((u32)ptr);
    for (i = 0; i < 8; i++)                        /* 32Б полей ноды */
        C2B_LOGH(((const volatile u32 *)ptr)[i]);
    C2B_LOGS("\n");
}

__asm__(
".text\n"
".globl c2b_g18a_thunk\n"
".type  c2b_g18a_thunk,@function\n"
"c2b_g18a_thunk:\n"   /* вход: rax = сырая нода от Alloc; ВХОД mid-function rsp%16==0 */
"  endbr64\n"
"  sub  $0x60,%rsp\n"   /* 0x60%16==0: logger entry rsp%16==8 (ABI); 0x58 давал 0 = UB/movaps */
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  mov  %rax,%rdi\n"
"  call c2b_g18a_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x60,%rsp\n"
"  jmp  *c2b_g18a_tramp(%rip)\n"
".size c2b_g18a_thunk, .-c2b_g18a_thunk\n"
".globl c2b_g18b_thunk\n"
".type  c2b_g18b_thunk,@function\n"
"c2b_g18b_thunk:\n"   /* вход: rdi=this(аллокатор), rsi=освобождаемый ptr */
"  endbr64\n"
"  mov  (%rsp),%r10\n"          /* ret0 = вызывающий Free */
"  sub  $0x58,%rsp\n"
"  mov  %r10,0x00(%rsp)\n"
"  mov  %rdi,0x08(%rsp)\n"
"  mov  %rsi,0x10(%rsp)\n"
"  mov  %rdx,0x18(%rsp)\n"
"  mov  %rcx,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %rax,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  mov  %r10,%rdi\n"            /* arg1 = ret0 */
"  call c2b_g18b_log\n"         /* arg2 = rsi (ptr) уже на месте */
"  mov  0x00(%rsp),%r10\n"
"  mov  0x08(%rsp),%rdi\n"
"  mov  0x10(%rsp),%rsi\n"
"  mov  0x18(%rsp),%rdx\n"
"  mov  0x20(%rsp),%rcx\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%rax\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g18_orig_free(%rip)\n"  /* хвостовой вызов оригинального Free */
".size c2b_g18b_thunk, .-c2b_g18b_thunk\n"
".previous\n"
);
extern void c2b_g18a_thunk(void);
extern void c2b_g18b_thunk(void);

/* 2307: РАЗОВАЯ карта модулей в момент арма (КОНТЕКСТ ИНИЦИАЛИЗАЦИИ потока
 * rearm — НЕ hot-путь Free; урок run133 не нарушен). Цель: узнать on-disk
 * путь matchmaking_client.so (второй сайт освобождения нод, +0x2a029) для
 * heist-фикса — run140: find по ~steaam/~local/Steam/~/csgo-lite /tmp его
 * НЕ НАШЁЛ (heist-map только steamclient-копии). */
static i32 c2b_g18_modmap_cb(void *info_v, void *size_v, void *data_v)
{
    struct c2b_g5_phdr *pi = (struct c2b_g5_phdr *)info_v;
    u32 *cnt = (u32 *)data_v;
    const char *nm;
    (void)size_v;
    if (!pi || !pi->dlpi_name) return 0;
    nm = pi->dlpi_name;
    if (!nm[0]) return 0;                        /* главный exe — пропустить */
    if (++(*cnt) > 192) return 1;                /* run141: 48 ОБРЕЗАЛО до X11/GL; 128: matchmaking
                                                    ВСЁ ЕЩЁ за cap (грузится после panorama) -> 192 */
    C2B_LOGS("[c2b] g18 modmap: ");
    C2B_LOGH((u32)(pi->dlpi_addr >> 32)); C2B_LOGH((u32)pi->dlpi_addr);
    C2B_LOGS(" ");
    {
        u32 nl = 0;
        while (nm[nl] && nl < 128) nl++;         /* до 128 символов пути */
        c2b_out(nm, nl);
    }
    C2B_LOGS("\n");
    return 0;
}

static void c2b_g18_modmap_dump(void)
{
    static u32 modmap_cnt;
    modmap_cnt = 0;
    C2B_LOGS("[c2b] g18 modmap begin\n");
    dl_iterate_phdr(c2b_g18_modmap_cb, &modmap_cnt);
    C2B_LOGS("[c2b] g18 modmap end\n");
}

static void c2b_g18_apply(void)
{
    static u8 done_a, done_b;
    uptr base, na, tr, pp, obj, vt, slot;
    if (done_a && done_b) return;
    base = g_engine_base;
    if (!base) return;
    if (!done_a) {
        na = base + C2B_G18_NODEALLOC_RVA;
        if (memcmp((const void *)na, c2b_g18a_sig, sizeof c2b_g18a_sig) != 0) {
            C2B_LOGS("[c2b] g18: nodealloc sig mismatch\n"); done_a = 1; return;
        }
        tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
        if (tr == (uptr)-1) { done_a = 1; return; }
        g_g18a_tramp_mem = (u8 *)tr;
        memcpy((void *)tr, (const void *)na, 3);          /* test %rax,%rax */
        {
            u8 br[6];
            i32 rel = (i32)((base + C2B_G18_JE_TGT) - (tr + 3 + 6));
            br[0] = 0x0F; br[1] = 0x84;
            br[2] = (u8)(u32)rel;         br[3] = (u8)((u32)rel >> 8);
            br[4] = (u8)((u32)rel >> 16); br[5] = (u8)((u32)rel >> 24);
            memcpy((void *)(tr + 3), br, 6);              /* je ФИКС */
        }
        memcpy((void *)(tr + 9), (const void *)(na + 9), 8); /* lea+and */
        c2b_write_jmp((void *)(tr + 17),
                      (const void *)(base + C2B_G18_NODEALLOC_CONT));
        c2b_g18a_tramp = (const volatile void *)tr;
        if (c2b_page_protect(na, C2B_PATCH_LEN, 0x07) != 0) { done_a = 1; return; }
        c2b_write_jmp((void *)na, (const void *)&c2b_g18a_thunk);
        done_a = 1;
        C2B_LOGS("[c2b] g18: nodealloc armed\n");
    }
    if (!done_b) {
        pp = *(volatile uptr *)(base + C2B_G18_GPTR_RVA);
        obj = pp ? *(volatile uptr *)pp : 0;
        vt  = obj ? *(volatile uptr *)obj : 0;
        if (!pp || !obj || !vt) return;               /* аллокатор ещё не готов — ретрай */
        slot = vt + C2B_G18_FREE_SLOT;
        c2b_g18_orig_free = *(volatile uptr *)slot;
        if (!c2b_g18_orig_free) { C2B_LOGS("[c2b] g18: free slot 0\n"); done_b = 1; return; }
        if (c2b_page_protect(slot, 8, 0x07) != 0) { done_b = 1; return; }
        *(volatile uptr *)slot = (uptr)&c2b_g18b_thunk;
        done_b = 1;
        C2B_LOGS("[c2b] g18: free slot patched obj=");
        C2B_LOGH((u32)obj); C2B_LOGS(" vt=");
        C2B_LOGH((u32)vt); C2B_LOGS(" orig=");
        C2B_LOGH((u32)c2b_g18_orig_free); C2B_LOGS("\n");
        c2b_g18_modmap_dump();   /* разово, контекст арма — путь matchmaking_client.so */
    }
}

/* ---------- 41f-g19: дамп полезной нагрузки у свободителя нод ----------
 * Run132 (362b3b1, после rel32-фикса): ПОЛНАЯ цепочка CLV2 до фазы 6 —
 * 'A' -> retry -> 'i' -> 'j' JOIN -> RESERVE-'A' -> 'B' accept доставлен
 * в насос (g16 recv: len=0x28 ffffffff 'B' ex=0xaaaaaaaa) — и консьюмер
 * молчит (нет 'k'). Барьер = обработка 'B' В КОНСЬЮМЕРЕ. Консьюмер найден
 * g18: доминирующий сайт освобождения нод engine+0x2e1ade. Статика
 * (engine.asm 34a96ae): 2e1ad5..2e1ae2 = mov (%rax),%rdi (3Б) /
 * mov (%rdi),%rax (3Б) / call *0x10(%rax) (3Б, Free: rdi=аллокатор,
 * rsi=r13=нода) / jmp 0x2e193b (5Б, цикл) — РОВНО 14Б = C2B_PATCH_LEN,
 * вход только fall-through (2e1acb выше), целей jmp ВНУТРЬ нет (проверено
 * по engine.asm; ВАЖНО: патч от 2e1adb налёг бы на 6 лишних байт и убил
 * блок 2e1ae8 — живая цель jne 2e186e). Естественное продолжение = ЦЕЛЬ
 * jmp 0x2e193b. Все 11Б инструкций до jmp — PIC (копируем как есть; call
 * зовёт ПАТЧЕННЫЙ слот Free -> g18b-thunk остаётся жив, ret0 для этого
 * сайта станет адресом трамплина — ожидаемо, сайт уже доказан). Один
 * rel32-фикс: (base + 0x2e193b) - (tr + 14). Thunk логирует rsi (ноду)
 * ДО освобождения: 64Б ноды + 32Б по *(node+8) (кандидат-obj) = ЧТО
 * консьюмер обработал ('A' vs 'B' на ОДНОМ сайте!). */
#define C2B_G19_FREESITE_RVA  0x2e1ad5ull
#define C2B_G19_FREESITE_CONT 0x2e193bull
static const u8 c2b_g19a_sig[14] = {
    0x48, 0x8B, 0x38, 0x48, 0x8B, 0x07, 0xFF, 0x50,
    0x10, 0xE9, 0x58, 0xFE, 0xFF, 0xFF };
static u8 *g_g19a_tramp_mem;
__attribute__((used)) static void *volatile c2b_g19a_tramp;

void c2b_g19a_log(uptr node)
{
    static volatile u32 n;
    u32 i, cnt;
    u32 ring = 0;
    if (!node) return;
    for (i = 0; i < C2B_G18_RING; i++)
        if (g_g18_nodes[i] == node) { ring = 1; break; }
    cnt = ++n;
    if (cnt > 12 && (cnt & 0x07) != 1) return;
    /* БЕЗ sigsetjmp-гарда и БЕЗ разыменования *(node+8): гарды мертвы вне
     * auth-окна (ранний арм), unsafe-дереф = смерть консьюмера. 64Б ноды
     * достаточно: там ptr/len/netadr — корреляция с g16b-дампами по len. */
    C2B_LOGS("[c2b] g19 free-dump: node=");
    C2B_LOGH((u32)(node >> 32)); C2B_LOGH((u32)node);
    C2B_LOGS("ring="); C2B_LOGN(ring);
    for (i = 0; i < 16; i++)                     /* 64Б ноды */
        C2B_LOGH(((const volatile u32 *)node)[i]);
    C2B_LOGS("\n");
}

__asm__(
".text\n"
".globl c2b_g19a_thunk\n"
".type  c2b_g19a_thunk,@function\n"
"c2b_g19a_thunk:\n"   /* вход: rsi=нода, rax=g_pMemAlloc**; mid-function rsp%16==0 */
"  endbr64\n"
"  sub  $0x60,%rsp\n"   /* 0x60: logger entry rsp%16==8 (ABI); 0x58 давал misalign */
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  mov  %rsi,%rdi\n"
"  call c2b_g19a_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x60,%rsp\n"
"  jmp  *c2b_g19a_tramp(%rip)\n"
".size c2b_g19a_thunk, .-c2b_g19a_thunk\n"
".previous\n"
);
extern void c2b_g19a_thunk(void);

static void c2b_g19_apply(void)
{
    static u8 done;
    uptr base, na, tr;
    if (done) return;
    base = g_engine_base;
    if (!base) return;
    na = base + C2B_G19_FREESITE_RVA;
    if (memcmp((const void *)na, c2b_g19a_sig, sizeof c2b_g19a_sig) != 0) {
        C2B_LOGS("[c2b] g19: freesite sig mismatch\n"); done = 1; return;
    }
    tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g19a_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)na, 11);  /* mov/mov/call — PIC как есть */
    {
        u8 br[5];
        i32 rel = (i32)((base + C2B_G19_FREESITE_CONT) - (tr + 14));
        br[0] = 0xE9;
        br[1] = (u8)(u32)rel;         br[2] = (u8)((u32)rel >> 8);
        br[3] = (u8)((u32)rel >> 16); br[4] = (u8)((u32)rel >> 24);
        memcpy((void *)(tr + 11), br, 5);      /* jmp 0x2e193b — ФИКС с базой */
    }
    c2b_g19a_tramp = (const volatile void *)tr;
    if (c2b_page_protect(na, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)na, (const void *)&c2b_g19a_thunk);
    done = 1;
    C2B_LOGS("[c2b] g19: consumer-free armed base=");
    C2B_LOGH((u32)base); C2B_LOGS("\n");
}

/* ---------- 41f-g21: ЭМПИРИЧЕСКИЙ ВАЛИДАТОР 'A'-accept (проба vt+0x200) ---
 * ФАКТ runs 138-142: g13 (0x259df0) armится, но НЕ ФУРЫЧИТ (0 строк "g13
 * clp") при живых g16/g17/g18 — живой консьюмер НЕ зовёт диспатчер
 * 0x259df0 (инлайнен в консьюмере или в другом модуле). НО vt+0x200
 * (0x2491f0, 'A'-accept продолжение) и vt+0x170 (0x24a760, FullConnect)
 * — ВИРТУАЛЬНЫЕ вызовы через vtable стейта: инлайнинг диспатчера их не
 * убивает (девиртуализация требует ДОКАЗАТЬ конкретный тип; xref прямо
 * видел call *0x200(%rax) из 'A'-хендлера).
 * g21a: 0x2491f0 gate = cmpq $0,0x430(%rdi); push rbp; mov %rsp,%rbp;
 *       je ret-путь (pop rbp; ret @0x249208); fall-through: pop rbp; jmp
 *       0x2490f0. Stolen 12Б БЕЗ ветвлений; патч 14Б накрывает je на
 *       сайте (je достижим ТОЛЬКО с 0x2491fc — внутрь никто не jmp-ит).
 *       Трамплин ВОССТАНАВЛИВАЕТ управление: je rel32 -> локальный
 *       retpath (pop rbp; ret — возврат исходному зовущему), fall-
 *       through: pop rbp; АБСОЛЮТНЫЙ jmp -> 0x2490f0 ЭТОГО ЖЕ модуля
 *       (= site-0x100, позиционная связь, rel32-дальность не нужна).
 * g21b: 0x2490f0 полный путь — 19Б PIC-пролога (push rbp; mov $-1,%ecx;
 *       mov $0x2d8,%edx; mov %rsp,%rbp; push %r13; mov %esi,%r13d), на
 *       случай прямого зова полного пути мимо gate. Трамплин = stolen +
 *       abs-jmp cont.
 * ЛОГ (решает слепую зону hdr): cstate=u32@0x1a0, gate=u64@0x430,
 * chal=u32@0x4d8, proto=u32@0x4dc, val=u32@0x4e0, snap=32Б @0x4f0..0x50f
 * — СНЕПШОТ 'A'-hdr, с которым сверяются чеки 'B' 2-5 (xref). Эмпирика
 * скажет: netadr@0x00+нули (чеки 2/3 НЕВОЗМОЖНЫ через wire -> нужен
 * другой ход) vs распарсенные поля (chal@0x18, proto@0x1c -> считаем
 * точные байты 'B'-бейта).
 * g22: FullConnect 0x24a760 (vt+0x170) — детектор 'B'-успеха: лог
 * cstate + pkthdr 32Б + data-птр. До слома барьера ожидаем 0 событий.
 * Арм: sig-verify на g_engine_base+RVA (копия g16/g17/g18 — ОНА живая,
 * их строки фурычат); при мисматче hexdump 16Б фактических байт ОДИН
 * РАЗ + ретрай до 40 итераций (диагноз дрейфа бандла, mystery g13
 * run141/142). Мисматч НЕ ретраится вечно: rearm-цикл сам конечен. */
#define C2B_G21_GATE_RVA 0x2491f0ull
#define C2B_G21_PATH_RVA 0x2490f0ull
#define C2B_G22_FC_RVA   0x24a760ull
static const u8 c2b_g21a_sig[12] = {
    0x48, 0x83, 0xBF, 0x30, 0x04, 0x00, 0x00, 0x00,   /* cmpq $0,0x430(%rdi) */
    0x55, 0x48, 0x89, 0xE5 };                          /* push rbp; mov rsp,rbp */
static const u8 c2b_g21b_sig[19] = {
    0x55, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, 0xD8, 0x02, 0x00, 0x00,
    0x48, 0x89, 0xE5, 0x41, 0x55, 0x41, 0x89, 0xF5 };
static const u8 c2b_g22_sig[21] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
    0x49, 0x89, 0xFC, 0x53, 0x48, 0x89, 0xF3, 0x48, 0x83, 0xEC, 0x60 };
static u8 *g_g21a_tramp_mem, *g_g21b_tramp_mem, *g_g22_tramp_mem;
__attribute__((used)) static void *volatile c2b_g21a_tramp;
__attribute__((used)) static void *volatile c2b_g21b_tramp;
__attribute__((used)) static void *volatile c2b_g22_tramp;

void c2b_g21_log(uptr state, uptr tag)
{
    static volatile u32 n;
    u32 i, cnt;
    u64 g;
    if (!state) return;
    cnt = ++n;
    if (cnt > 24 && (cnt & 0x3F) != 1) return;
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g21 acc t=");
    C2B_LOGN((u32)tag);
    C2B_LOGS("st=");
    C2B_LOGH((u32)(state >> 32)); C2B_LOGH((u32)state);
    C2B_LOGS("cstate=");
    C2B_LOGH(*(volatile const u32 *)(state + 0x1a0));
    g = *(volatile const u64 *)(state + 0x430);
    C2B_LOGS("gate=");
    C2B_LOGH((u32)g); C2B_LOGH((u32)(g >> 32));
    C2B_LOGS("chal=");
    C2B_LOGH(*(volatile const u32 *)(state + 0x4d8));
    C2B_LOGS("proto=");
    C2B_LOGH(*(volatile const u32 *)(state + 0x4dc));
    C2B_LOGS("val=");
    C2B_LOGH(*(volatile const u32 *)(state + 0x4e0));
    C2B_LOGS("snap=");
    for (i = 0; i < 32; i++)
        C2B_LOGH(*(volatile const u8 *)(state + 0x4f0 + i));
    C2B_LOGS("\n");
    g_probe_active = 0;
}

void c2b_g22_log(uptr state, uptr pkt)
{
    static volatile u32 n;
    u32 i, cnt;
    uptr data;
    if (!state) return;
    cnt = ++n;
    if (cnt > 24 && (cnt & 0x3F) != 1) return;
    if (g_probe_active) return;
    g_probe_active = 1;
    if (__sigsetjmp(g_probe_jb, 1) != 0) { g_probe_active = 0; return; }
    C2B_LOGS("[c2b] g22 fc st=");
    C2B_LOGH((u32)(state >> 32)); C2B_LOGH((u32)state);
    C2B_LOGS("cstate=");
    C2B_LOGH(*(volatile const u32 *)(state + 0x1a0));
    C2B_LOGS("pkthdr=");
    if (pkt) {
        for (i = 0; i < 32; i++)
            C2B_LOGH(*(volatile const u8 *)(pkt + i));
        data = *(volatile uptr *)(pkt + 0x38);
        C2B_LOGS("d0=");
        if (data) {
            for (i = 0; i < 8; i++)
                C2B_LOGH(*(volatile const u8 *)(data + i));
        } else {
            C2B_LOGS("-");
        }
    } else {
        C2B_LOGS("-");
    }
    C2B_LOGS("\n");
    g_probe_active = 0;
}

__asm__(
".text\n"
".globl c2b_g21a_thunk\n"
".type  c2b_g21a_thunk,@function\n"
"c2b_g21a_thunk:\n"   /* вход: rsp%16==8; rdi=state; тег 1 (gate) */
"  endbr64\n"
"  sub  $0x58,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  mov  $1,%esi\n"
"  call c2b_g21_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g21a_tramp(%rip)\n"
".size c2b_g21a_thunk, .-c2b_g21a_thunk\n"
".globl c2b_g21b_thunk\n"
".type  c2b_g21b_thunk,@function\n"
"c2b_g21b_thunk:\n"   /* вход: rsp%16==8; rdi=state; тег 2 (полный путь) */
"  endbr64\n"
"  sub  $0x58,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  mov  $2,%esi\n"
"  call c2b_g21_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g21b_tramp(%rip)\n"
".size c2b_g21b_thunk, .-c2b_g21b_thunk\n"
".globl c2b_g22_thunk\n"
".type  c2b_g22_thunk,@function\n"
"c2b_g22_thunk:\n"   /* вход: rsp%16==8; rdi=state rsi=pkt — протаскиваем */
"  endbr64\n"
"  sub  $0x58,%rsp\n"
"  mov  %rax,0x00(%rsp)\n"
"  mov  %rcx,0x08(%rsp)\n"
"  mov  %rdx,0x10(%rsp)\n"
"  mov  %rsi,0x18(%rsp)\n"
"  mov  %rdi,0x20(%rsp)\n"
"  mov  %r8, 0x28(%rsp)\n"
"  mov  %r9, 0x30(%rsp)\n"
"  mov  %r10,0x38(%rsp)\n"
"  mov  %r11,0x40(%rsp)\n"
"  call c2b_g22_log\n"
"  mov  0x00(%rsp),%rax\n"
"  mov  0x08(%rsp),%rcx\n"
"  mov  0x10(%rsp),%rdx\n"
"  mov  0x18(%rsp),%rsi\n"
"  mov  0x20(%rsp),%rdi\n"
"  mov  0x28(%rsp),%r8\n"
"  mov  0x30(%rsp),%r9\n"
"  mov  0x38(%rsp),%r10\n"
"  mov  0x40(%rsp),%r11\n"
"  add  $0x58,%rsp\n"
"  jmp  *c2b_g22_tramp(%rip)\n"
".size c2b_g22_thunk, .-c2b_g22_thunk\n"
".previous\n"
);
extern void c2b_g21a_thunk(void);
extern void c2b_g21b_thunk(void);
extern void c2b_g22_thunk(void);

static void c2b_g21_apply(void)
{
    static u8 done, dump_shown;
    static u32 tries;
    uptr base, ga, tr;
    if (done) return;
    base = g_engine_base;
    if (!base) return;                       /* движок ещё не резолвнут — ретрай */
    ga = base + C2B_G21_GATE_RVA;
    if (memcmp((const void *)ga, c2b_g21a_sig, sizeof c2b_g21a_sig) != 0) {
        if (!dump_shown) {                   /* ОДИН раз: дрейф бандла/базы в лоб */
            u32 i;
            dump_shown = 1;
            C2B_LOGS("[c2b] g21: gate sig mismatch @base+rva 0x2491f0, bytes:");
            for (i = 0; i < 16; i++)
                C2B_LOGH(*(volatile const u8 *)(ga + i));
            C2B_LOGS("\n");
        }
        if (++tries >= 40) { C2B_LOGS("[c2b] g21: gate sig gone, giving up\n"); done = 1; }
        return;
    }
    /* gate-трамплин: 12Б stolen + je rel32 -> retpath + pop rbp + abs-jmp
     * -> 0x2490f0 этого модуля (site-0x100) + retpath (pop rbp; ret) */
    tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g21a_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)ga, sizeof c2b_g21a_sig);
    {
        u8 br[6];
        i32 rel;
        rel = (i32)(33 - 18);                /* retpath_off - (12+6) = 15 */
        br[0] = 0x0F; br[1] = 0x84;
        br[2] = (u8)(u32)rel;         br[3] = (u8)((u32)rel >> 8);
        br[4] = (u8)((u32)rel >> 16); br[5] = (u8)((u32)rel >> 24);
        memcpy((void *)(tr + 12), br, 6);
    }
    *(volatile u8 *)(tr + 18) = 0x5D;        /* fall-through: pop %rbp */
    c2b_write_jmp((void *)(tr + 19), (const void *)(ga - 0x100));
    *(volatile u8 *)(tr + 33) = 0x5D;        /* retpath: pop %rbp */
    *(volatile u8 *)(tr + 34) = 0xC3;        /* ret -> исходному зовущему */
    c2b_g21a_tramp = (const volatile void *)tr;
    if (c2b_page_protect(ga, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)ga, (const void *)&c2b_g21a_thunk);
    /* полный путь 0x2490f0: stolen 19Б + abs-jmp cont (мисматч НЕ фатален —
     * гейт главный) */
    {
        uptr pa = base + C2B_G21_PATH_RVA;
        if (memcmp((const void *)pa, c2b_g21b_sig, sizeof c2b_g21b_sig) == 0) {
            tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
            if (tr != (uptr)-1) {
                g_g21b_tramp_mem = (u8 *)tr;
                memcpy((void *)tr, (const void *)pa, sizeof c2b_g21b_sig);
                c2b_write_jmp((void *)(tr + sizeof c2b_g21b_sig),
                              (const void *)(pa + sizeof c2b_g21b_sig));
                c2b_g21b_tramp = (const volatile void *)tr;
                if (c2b_page_protect(pa, C2B_PATCH_LEN, 0x07) == 0)
                    c2b_write_jmp((void *)pa, (const void *)&c2b_g21b_thunk);
            }
        } else {
            C2B_LOGS("[c2b] g21: path sig mismatch (non-fatal)\n");
        }
    }
    done = 1;
    C2B_LOGS("[c2b] g21: armed gate+path base=");
    C2B_LOGH((u32)base); C2B_LOGS("\n");
}

static void c2b_g22_apply(void)
{
    static u8 done, dump_shown;
    static u32 tries;
    uptr base, fa, tr;
    if (done) return;
    base = g_engine_base;
    if (!base) return;
    fa = base + C2B_G22_FC_RVA;
    if (memcmp((const void *)fa, c2b_g22_sig, sizeof c2b_g22_sig) != 0) {
        if (!dump_shown) {
            u32 i;
            dump_shown = 1;
            C2B_LOGS("[c2b] g22: fc sig mismatch @base+rva 0x24a760, bytes:");
            for (i = 0; i < 16; i++)
                C2B_LOGH(*(volatile const u8 *)(fa + i));
            C2B_LOGS("\n");
        }
        if (++tries >= 40) { C2B_LOGS("[c2b] g22: fc sig gone, giving up\n"); done = 1; }
        return;
    }
    tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g22_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)fa, sizeof c2b_g22_sig);
    c2b_write_jmp((void *)(tr + sizeof c2b_g22_sig),
                  (const void *)(fa + sizeof c2b_g22_sig));
    c2b_g22_tramp = (const volatile void *)tr;
    if (c2b_page_protect(fa, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)fa, (const void *)&c2b_g22_thunk);
    done = 1;
    C2B_LOGS("[c2b] g22: armed fullconnect base=");
    C2B_LOGH((u32)base); C2B_LOGS("\n");
}

/* ---------- 41f-g24: СНАП-ВОТЧЕР стейта (zero-detour evidence) ------------
 * run143 (87a9448): g21 gate+path ARMены ДО цепочки (a2/a3 healthy: 12
 * реальных 'A' type=0x41, 23-25 verdict=1, phase6 x2, 'B'-бейты на wire)
 * и НЕ СРАБОТАЛИ (0 acc) — entry-детур ловит ЛЮБОГО зовущего (vtable ИЛИ
 * прямой call), значит 0x2491f0 не вызывает НИКТО. Гипотезы: (A) очередь
 * connectionless вообще не выгребается; (B) консьюмер выгребает и
 * обрабатывает 'A' СВОЕЙ инлайн-копией хендлера (снапшот в state+0x4f0
 * пишется, но вирт. зова accept нет). РАЗЛИЧАЕМ ПАССИВНО: state
 * CClientState — глобал движка; инстанс опознаётся парой vptr (primary
 * 0xd78bb8 @+0, вторичный 0xd78de8 @+8 — xref ctor 0x256890). Сканируем
 * RW-сегменты ДВИГАТЕЛЯ на пару -> адрес(а) стейта -> поллинг 250мс:
 * cstate=u32@0x1a0 ('A'-чек 1: должен быть 1 — если !=1, ГЛАВНЫЙ барьер
 * НАЙДЕН: чек 1 рубит пакет до снапшота), gate=u64@0x430,
 * netchan=u64@0x128 (FullConnect пишет !=0 = 'B'-успех независимо от
 * g22!), chal/proto/val @0x4d8/0x4dc/0x4e0, snap 32Б @0x4f0..0x50f.
 * Лог на каждое изменение (cap 64, дальше 1/64). Snap-change при
 * cstate==1 = инлайн-хендлер жив -> те же 'B'-формулы, что у g21. */
#define C2B_G24_VPTR1 0xd78bb8ull
#define C2B_G24_VPTR2 0xd78de8ull
static uptr g_g24_state[4];
static u32 g_g24_nstate;
/* ---------- g26/g28: 'k'-build unlock (RE run161 engine_client.so) --------
 * ОФЛАЙН-RE bins run161 (engine_client.so__2cd041, НЕ strip, RVA = живым:
 * gate-сиг 48 83 bf 30 04 00 00 00 @0x2491f0 совпал байт-в-байт):
 *  SendConnectPacket = vt+0x198 -> 0x24aa20 (первая строка:
 *  COM_TimestampedLog("SendConnectPacket")). Пишет BF: 'k', auth-proto
 *  (state+0x8dc4), proto, chal, name, pwd, потом тикет-зону (0x478 blob,
 *  0x510/0x514/0x520/0x530) и шлёт (0x248010). САМ движок строит 'k'.
 *  ТРИ внутри-функции чека рубят его ДО первого байта:
 *   (a) @0x24aa76: snap[0x1c] (state+0x50c) == 0 -> je 0x24b071 fail;
 *   (b) @0x24aa96: netadr cmp state+0x148 vs snap (0x248330) -> je 0x24b2c7;
 *   (c) @0x24aae3: state->0x8dc4 (auth-proto) == 0 -> je 0x24b065 fail.
 *  ПОСТАВЩИК флагов (0x4c0 connect-in-progress + 0x8dc4) — ветка
 *  "connect"-КОМАНДЫ диспетчера (@0x25cf38: cmpl $1,0x1a0 -> cstate==1 ->
 *  movb $1,0x4c0 @0x25cf46; mov %r14d,0x8dc4 @0x25cf99) — но диспетчер
 *  0x259df0 в живом пути НЕ зовётся (g13-детур молчит), а 'A'-парс чалль
 *  ПИШЕТ (run157/162 эмпирика) — т.е. живой консьюмер обрабатывает 'A'
 *  своей копией, не доходя до ветки флагов. Pump 0x24b520 (vt+0x198 зовёт
 *  при 0x4c0!=0) тоже мёртв для живого пути (зовут только dispatch-ер и
 *  pwd-handler). ИТОГ: все недостающие флаги — В ПАМЯТИ СТЕЙТА, которой
 *  g24 владеет. g26: пишем snap[0x1c]=1, 0x8dc4=3 (если 0) -> чеки (a)/(c)
 *  проходя. g28: СОВЕРШАЕМ вызов vt+0x198 сами (сигнатура из pump-а
 *  @0x24b56b: rdi=state, rsi=&snap(0x4f0), edx=chal, ecx=proto, r8=val
 *  u64, r9d=u8@0x4c1): тикет-путь исполняет сам движок. Рефрактерность
 *  2с, кап 10, C2B_G28=0 выкл. (b) не трогаем: na-зона логируется в
 *  dumpone, адрес сравнения — решающие данные следующего ранa.
 * ---- g29 (RE 0907, /tmp/engine.asm): КОРЕНЬ [I:0:0]:0 ----
 *  Identity-строитель 0x248010 (вызывается из SendConnectPacket @0x24aebc
 *  c arg4=snap=state+0x4f0; рump 0x24b56e передаёт ТОТ ЖЕ объект):
 *   [snap+0x1c]!=0 -> ветки SteamID/пустого identity; ==0 -> ЧИСТЫЙ путь:
 *   ip=bswap(u32@[snap+4]) через 65ec30, port=rol8(u16@[snap+8]) через
 *   65ec10 — CNetAdr СТАРОГО класса {type@0, ip BE @+4, port BE @+8}
 *   (семейство 65eb70 IsLoopback(ip==127.0.0.1@+4) / 65eb80 type==1 /
 *   65eb90 Clear / 65ebc0 SetIP4 / 65ebe0 SetIP(bswap@+4) / 65ebf0
 *   SetType@0 / 65ec00 GetType / 65ec20 GetIP / 65ec30 GetIP_host).
 *   ЖИВОЙ приёмник пишет NEW-style {type=3@0, pad=0, ip@8, port BE @0xc,
 *   0@0x10..0x1f} -> старые чтения: ip=bswap(u32@+4)=0, port=u16@+8=
 *   первые 2 байта ip -> identity [I:0:0]:0 ЭМПИРИКА ОБЪЯСНЕНА.
 *  ОТПРАВКА (send-layer 0x4bae20, Warning @0x4bb618):
 *   [netadr+0x1c]!=0 -> ad-hoc маршрут -> нет steam net connection ->
 *   "Can't send ad-hoc to address %s" -> DROP (10:10 корреляция с g28);
 *   ==0 -> IsLoopback/IsType1 проверки -> 4b7da0(fd,buf,len,snap,..):
 *   GetType(snap)!=0 -> PLAIN-UDP OOB send -> "UDP -> %s: sz=%d OOB" —
 *   НА ПРОВОДЕ. g26 писал snap[0x1c]=1 -> САМ вгонял в ad-hoc drop!
 *  ЧЕК (b) при snap[0x1c]==0 НЕ падает: 0x248330 @0x248376 test eax;
 *   je 0x2483b0 — alt-путь: 65e930(snap, el+0x48, 0) = netadr== старого
 *   класса (type@0, port u16@+8, ip u32@+4). СОВПАДЕНИЕ требует OLD-
 *   зеркал в ОБОИХ объектах: snap {ip BE @st+0x4f4, port BE @st+0x4f8}
 *   и el {ip BE @el+0x4c, port BE @el+0x50} — источники: NEW-копия
 *   приёмника (ip bytes @st+0x4f8, port BE @st+0x4fc).
 *  ИТОГ g29: snap[0x1c]->0 (НЕ 1!), OLD-зеркала ip/port в snap+el,
 *  auth-proto=3 (старое g26), g28 без изменений -> чеки a/b/c проходят,
 *  identity=IPv4(цель:28022), отправка по 4b7da0 = UDP OOB НА ПРОВОДЕ.
 *  C2B_G29=0 — откат к старой стратегии (snap[0x1c]=1 + выравнивание
 *  g26v2 под primary-путь чека (b)). */
static u32 g_g28_sends;
static u32 g_g28_last_it;
static u32 g_g28_en = 1;
static u32 g_g29_en = 1;
/* v3 (run144/145 post-mortem: g24 v1/v2 = dl_iterate_phdr КАЖДЫЕ 5с по 2мин +
 * rescan каждые 64с -> КОНКУРЕНЦИЯ за loader-lock с auth-тредом, чей rearm
 * (g8/g9/g13/modmap) ТОЖЕ зовёт dl_iterate_phdr: run144 a2 backtrace = auth
 * ЗАСТРЯЛ в c2b_g9_patch_apply->dl_iterate_phdr навсегда (движок жив, все
 * наши треды молчат, "GNS g9" — последняя строка; 2/2 g24-ранов умерли,
 * без g24 — живы). V3: dl_iterate_phdr ПОЛНОСТЬЮ УБРАН — модули/диапазоны
 * читаем из /proc/self/maps (файл, ноль блокировок), тяжёлый скан ТОЛЬКО
 * 2 раза за попытку (t+3мин и t+10мин), между сканами — дешёвый poll уже
 * найденных адресов (250мс, чистые чтения).
 * Каналы: (B) vptr-пара 0xd78bb8/0xd78de8 (ctor 0x256890 верифицирован
 * дизасмом), (A) accept-слоты qword==base+0x2491f0 (vtable ptrs в W-памяти;
 * run145 нашёл 3: статик primary + ДВЕ рантайм-копии — живой стейт на КУЧЕ,
 * vptr на копию!), (C) контент-след 'A'-парса (cstate==1 && proto==3 &&
 * chal!=0, vptr-в-движок). Диапазоны: RW engine_client.so + АНОНИМНЫЕ RW
 * (куча!) + [h[heap]; каждый <=256МБ, суммарно <=768МБ. */
struct c2b_g24_range { uptr lo, hi; };
struct c2b_g24_rset { struct c2b_g24_range r[512]; u32 n; u32 p0, p1; u64 total; };
static u32 c2b_g24_hex32(const char *p, uptr *out)
{
    uptr v = 0;
    u32 k;
    for (k = 0; k < 16; k++) {
        u32 c = (u32)(u8)p[k];
        u32 d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        v = (v << 4) | d;
    }
    *out = v;
    return k;
}
static void c2b_g24_add_range(struct c2b_g24_rset *rs, uptr lo, uptr hi)
{
    u32 i, dup = 0;
    u64 sz = hi - lo;
    if (sz < 0x1000 || sz > ((uptr)4096 << 20)) return;  /* v3.6: 1GB cap
        SKIPPAL главный arena движка (>1GB зарезерв) — run145 видел его
        phdr-сканом без капа; скан 4ГБ ~2-4с, 2 скана/попытка — ок */
    if (rs->total + sz > ((uptr)6144 << 20)) return;
    for (i = 0; i < rs->n; i++)
        if (rs->r[i].lo == lo) { dup = 1; break; }
    if (dup || rs->n >= 512) return;
    rs->r[rs->n].lo = lo;
    rs->r[rs->n].hi = hi;
    rs->n++;
    rs->total += sz;
}
static u32 c2b_g24_add_range_t(struct c2b_g24_rset *rs, uptr lo, uptr hi, u32 pass);
static void c2b_g24_collect_ranges(struct c2b_g24_rset *rs)
{
    static const char *p24 = "/proc/self/maps";
    extern i32 open(const char *, i32, ...);
    extern i64 read(i32, void *, u64);
    extern i32 close(i32);
    static char mb[2 * 1024 * 1024];    /* v3.3: 256KB ОБРЕЗАЛ maps ПО АДРЕСУ:
     * файл отсортирован по адресу, движок живёт на ВЫСОКИХ адресах
     * (0x7fxx-xxxx-xxxx) и попадал ЗА срез -> engRW=0/слоты=0. Читаем до EOF. */
    i32 fd = open(p24, 0);
    i64 n = 0;
    char *p, *end;
    rs->n = 0;
    rs->total = 0;
    if (fd < 0) return;
    for (;;) {
        i64 r = read(fd, mb + n, (i64)sizeof(mb) - 1 - n);
        if (r <= 0) break;
        n += r;
        if (n >= (i64)sizeof(mb) - 1) break;
    }
    close(fd);
    if (n <= 0) return;
    mb[n] = 0;
    p = mb;
    end = mb + n;
    /* v3.4: ДВЕ ПРОХОДКИ — диапазоны движка собираются ПЕРВЫМИ (кап 48
     * однажды уже съели анонимные низкие регионы ДО движка — точь-в-точь
     * баг g13-selfscan-cap 16); вторая проходка — анонимные/[heap]. */
    u32 pass, want_eng;
    for (pass = 0; pass < 2; pass++) {
      want_eng = (pass == 0);
      p = mb;
      while (p < end && rs->n < 512) {  /* v3.8: 96 опять съелось мелкими; 512x16Б=8КБ */
        /* format: lo-hi perms offset dev inode [path]\n */
        uptr lo = 0, hi = 0;
        u32 k;
        char perms[8];
        const char *path = 0;
        u32 pathlen = 0;
        k = c2b_g24_hex32(p, &lo);
        if (k == 0 || p[k] != '-') break;
        p += k + 1;
        k = c2b_g24_hex32(p, &hi);
        if (k == 0) break;
        p += k;
        if (p >= end) break;
        {
            u32 j = 0;
            while (p < end && *p == ' ') p++;
            while (p < end && *p != ' ' && j < 7) perms[j++] = *p++;
            perms[j] = 0;
            while (p < end && *p != '\n') {
                if (*p == '/' || (*p == '[' && path == 0)) {
                    if (path == 0) path = p;
                }
                p++;
            }
            if (path) {
                /* pathlen = от начала пути до '\n' (q-прогон возвращал 0
                 * ВСЕГДА: он останавливается на пробеле ПЕРЕД путём ->
                 * pathlen==0 -> eng-фильтр никогда не матчил -> v3/v3.1
                 * сканировали ТОЛЬКО анонимные диапазоны!) */
                pathlen = (u32)(p - path);
            }
            if (p < end) p++;
        }
        /* v3.7: pass 0 (окно движка) теперь принимает ЛЮБОЙ читаемый регион:
         * VTABLES живут в .data.rel.ro, который после релокаций RELRO
         * переводится в r--p — RW-only фильтр исключал ровно те страницы,
         * где лежат статик-primary vtable и слоты accept! run145 видел их
         * phdr-сканом (флаг W у PT_LOAD не отражает runtime-RELRO).
         * pass 1 (куча) остаётся rw-only. */
        if (want_eng) { if (perms[0] != 'r') continue; }
        else { if (perms[0] != 'r' || perms[1] != 'w') continue; }
        {
            /* v3.5: pass 0 = ВСЁ, что пересекает окно [base, base+1GB):
             * file-backed RW движка + anon-продолжения bss + арены с
             * рантайм-копиями vtable (+223MB) — путь не важен; прошлый
             * фильтр по пути ловил 18 мелких фрагментов и ТЕРЯЛ главный
             * регион (224МБ). pass 1 = анонимные/[heap] (куча). */
            u32 anon = 0, inwin;
            inwin = (lo < g_engine_base + 0x40000000ull) &&
                    (hi > g_engine_base);
            if (pathlen == 0) anon = 1;                     /* anon RW = heap */
            else if (pathlen >= 6 && path[0] == '[' &&
                     path[1] == 'h' && path[2] == 'e') anon = 1;
            if (want_eng) { if (!inwin) continue; }
            else        { if (!anon) continue; }
        }
        if ((hi - lo) > ((uptr)4096 << 20)) {          /* v3.6 diag */
            static u32 nbig;
            if (nbig++ < 8) {
                C2B_LOGS("[c2b] g24: huge skip sz=");
                C2B_LOGH((u32)((hi - lo) >> 32)); C2B_LOGH((u32)(hi - lo));
                C2B_LOGS("\n");
            }
        }
        c2b_g24_add_range_t(rs, lo, hi, pass);
      }
    }
}
static u32 c2b_g24_add_range_t(struct c2b_g24_rset *rs, uptr lo, uptr hi, u32 pass)
{
    u32 before = rs->n;
    c2b_g24_add_range(rs, lo, hi);
    if (rs->n > before) { if (pass == 0) rs->p0++; else rs->p1++; }
    return rs->n > before;
}
static u32 c2b_g24_add_state(uptr p)
{
    u32 j;
    if (g_g24_nstate >= 4) return 0;
    for (j = 0; j < g_g24_nstate; j++)
        if (g_g24_state[j] == p) return 0;
    g_g24_state[g_g24_nstate++] = p;
    return 1;
}
/* v4.2: chunked reader ВЫШЕ (c2b_rd64_safe, общий с g8/g9) — здесь только
 * макрос доступа со своим fd/кэшем на скан. */
static void c2b_g24_find_state(void)
{
    struct c2b_g24_rset rs;
    u32 i, found = 0;
    uptr p;
    /* v4.2 (run164 a2): SIGSEGV в c2b_g24_find_state — прямые
     * разыменования *(volatile uptr*)p по ranges из maps-СНАПШОТА гонятся
     * с concurrent munmap движка (панорама/asset loading маппит/анмапит
     * постоянно); ресканы каждые ~45с (nstate=3<4) -> рано или поздно
     * chunk исчезает между collect_ranges и сканом -> CRASH (run164 a2,
     * ~8-я минута, весь прогон убит). ФИКС: чтение ЧАНКАМИ 64KB через
     * /proc/self/mem pread — unmapped chunk = EIO -> skip, ноль крашей;
     * 2.4GB скан = ~37k pread + ин-буферное чтение (скорость ок).
     * Чтение 0 на невалидных адресах просто не совпадёт с константами. */
    int mfd;
    uptr clo = 0;
    u32 cn = 0;
    u8 cbuf[65536];
extern i32 open(const char *, i32, ...);
extern i32 close(i32);
#define C2B_G24_RD64(a) (c2b_rd64_safe(mfd, &clo, &cn, cbuf, (a)))
    if (g_g24_nstate >= 4 || !g_engine_base) return;
    mfd = open("/proc/self/mem", 0 /*O_RDONLY*/);
    if (mfd < 0) return;
    c2b_g24_collect_ranges(&rs);
    if (!rs.n) { close(mfd); return; }
    /* канал B: vptr-пара (0xd78bb8@0 + 0xd78de8@8) */
    for (i = 0; i < rs.n && g_g24_nstate < 4; i++) {
        for (p = rs.r[i].lo; p + 16 <= rs.r[i].hi && g_g24_nstate < 4; p += 8) {
            if (C2B_G24_RD64(p) == g_engine_base + C2B_G24_VPTR1 &&
                C2B_G24_RD64(p + 8) == g_engine_base + C2B_G24_VPTR2) {
                if (c2b_g24_add_state(p)) found++;
            }
        }
    }
    /* канал A: живые слоты accept -> vtbase=V-0x200 -> инстансы с vptr==vtbase */
    for (i = 0; i < rs.n && g_g24_nstate < 4; i++) {
        for (p = rs.r[i].lo; p + 8 <= rs.r[i].hi && g_g24_nstate < 4; p += 8) {
            uptr v = C2B_G24_RD64(p);
            if (v == g_engine_base + C2B_G21_GATE_RVA) {
                uptr vtbase = p - 0x200;
                u32 k;
                C2B_LOGS("[c2b] g24: accept-slot @");
                C2B_LOGH((u32)(p >> 32)); C2B_LOGH((u32)p);
                C2B_LOGS("vtbase=");
                C2B_LOGH((u32)(vtbase >> 32)); C2B_LOGH((u32)vtbase);
                C2B_LOGS("\n");
                for (k = 0; k < rs.n && g_g24_nstate < 4; k++) {
                    uptr q;
                    for (q = rs.r[k].lo; q + 8 <= rs.r[k].hi && g_g24_nstate < 4; q += 8)
                        if (C2B_G24_RD64(q) == vtbase && c2b_g24_add_state(q))
                            found++;
                }
            }
        }
    }
    /* канал C: контент-скан (cstate==1, proto==3, chal!=0) + vptr в движке */
    for (i = 0; i < rs.n && g_g24_nstate < 4; i++) {
        for (p = rs.r[i].lo; p + 0x520 <= rs.r[i].hi && g_g24_nstate < 4; p += 8) {
            uptr vp;
            if ((u32)C2B_G24_RD64(p + 0x1a0) != 1) continue;
            if ((u32)C2B_G24_RD64(p + 0x4dc) != 3) continue;
            if ((u32)C2B_G24_RD64(p + 0x4d8) == 0) continue;
            vp = C2B_G24_RD64(p);
            if (vp < g_engine_base || vp >= g_engine_base + 0x4000000) continue;
            if (c2b_g24_add_state(p)) found++;
        }
    }
    close(mfd);
    C2B_LOGS("[c2b] g24: state scan ranges=");
    C2B_LOGN(rs.n);
    C2B_LOGS("tot=");
    C2B_LOGH((u32)(rs.total >> 32)); C2B_LOGH((u32)rs.total);
    C2B_LOGS("p0=");
    C2B_LOGN(rs.p0);
    C2B_LOGS("p1=");
    C2B_LOGN(rs.p1);
    C2B_LOGH((u32)(rs.total >> 32)); C2B_LOGH((u32)rs.total);
    C2B_LOGS("n=");
    C2B_LOGN(g_g24_nstate);
    C2B_LOGS("new=");
    C2B_LOGN(found);
    for (i = 0; i < g_g24_nstate; i++) {
        C2B_LOGS(" @");
        C2B_LOGH((u32)(g_g24_state[i] >> 32)); C2B_LOGH((u32)g_g24_state[i]);
    }
    C2B_LOGS("\n");
#undef C2B_G24_RD64
}
static void c2b_g24_dumpone(u32 i, u32 cs)
{
    uptr st = g_g24_state[i];
    u32 k;
    u64 nc, g;
    C2B_LOGS("[c2b] g24 i=");
    C2B_LOGN(i);
    C2B_LOGS("st=");
    C2B_LOGH((u32)(st >> 32)); C2B_LOGH((u32)st);
    C2B_LOGS("cstate=");
    C2B_LOGH(cs);
    nc = *(volatile const u64 *)(st + 0x128);
    C2B_LOGS("netchan=");
    C2B_LOGH((u32)nc); C2B_LOGH((u32)(nc >> 32));
    g = *(volatile const u64 *)(st + 0x430);
    C2B_LOGS("gate=");
    C2B_LOGH((u32)g); C2B_LOGH((u32)(g >> 32));
    C2B_LOGS("chal=");
    C2B_LOGH(*(volatile const u32 *)(st + 0x4d8));
    C2B_LOGS("proto=");
    C2B_LOGH(*(volatile const u32 *)(st + 0x4dc));
    C2B_LOGS("val=");
    C2B_LOGH(*(volatile const u32 *)(st + 0x4e0));
    C2B_LOGS("snap=");
    for (k = 0; k < 32; k++)
        C2B_LOGH(*(volatile const u8 *)(st + 0x4f0 + k));
    /* g27 diag: флаги/поля 'k'-пути (RE run161): s1c=snap[0x1c] (чек (a)),
     * c0/c1/c5=0x4c0/0x4c1/0x4c5 (connect-in-progress, арг, флаги),
     * e8=0x4e8 (pump-гейт), ap=0x8dc4 (auth-proto, чек (c)), tkt=0x478
     * (тикет-блоб ptr), na=0x148 16Б (netadr для cmp (b) со snap) */
    C2B_LOGS("s1c=");
    C2B_LOGH(*(volatile const u32 *)(st + 0x50c));
    C2B_LOGS("c0=");
    C2B_LOGH(*(volatile const u8 *)(st + 0x4c0));
    C2B_LOGS("c1=");
    C2B_LOGH(*(volatile const u8 *)(st + 0x4c1));
    C2B_LOGS("c5=");
    C2B_LOGH(*(volatile const u8 *)(st + 0x4c5));
    {   u64 e8 = *(volatile const u64 *)(st + 0x4e8);
        u64 tk = *(volatile const u64 *)(st + 0x478);
        u32 kk;
        C2B_LOGS("e8=");
        C2B_LOGH((u32)(e8 >> 32)); C2B_LOGH((u32)e8);
        C2B_LOGS("ap=");
        C2B_LOGH(*(volatile const u32 *)(st + 0x8dc4));
        C2B_LOGS("tkt=");
        C2B_LOGH((u32)(tk >> 32)); C2B_LOGH((u32)tk);
        C2B_LOGS("na=");
        for (kk = 0; kk < 16; kk++)
            C2B_LOGH(*(volatile const u8 *)(st + 0x148 + kk));
        /* nc= первый элемент реестра каналов 0x148: {ptr@0, cnt@0x10} el 0x68:
         * el+0x48 netadr, el+0x54 u64, el+0x5c u32, el+0x60 u32, el+0x64 u32 —
         * ПОЛНЫЙ набор полей match-а 0x248330 (чек (b) SendConnectPacket) */
        {   uptr arr = *(volatile const uptr *)(st + 0x148);
            u32 cnt = *(volatile const u32 *)(st + 0x158);
            C2B_LOGS("nc=");
            C2B_LOGH((u32)(arr >> 32)); C2B_LOGH((u32)arr);
            C2B_LOGS("cnt=");
            C2B_LOGN(cnt);
            if (arr && cnt) {
                for (kk = 0; kk < 32; kk++)
                    C2B_LOGH(*(volatile const u8 *)(arr + 0x48 + kk));
            }
        }
    }
    C2B_LOGS("\n");
}
static void *c2b_g24_thread(void *arg)
{
    u32 it, i, logged = 0;
    u32 last_c[4];
    u64 last_h[4];
    (void)arg;
    {   const char *e = getenv("C2B_G28");
        if (e && e[0] == '0') { g_g28_en = 0;
            C2B_LOGS("[c2b] g28: disabled by env\n"); }
    }
    {   const char *e = getenv("C2B_G29");
        if (e && e[0] == '0') { g_g29_en = 0;
            C2B_LOGS("[c2b] g29: disabled by env\n"); }
    }
    for (it = 0; it < 600 && !g_engine_base; it++) usleep(1000000);
    for (i = 0; i < 4; i++) { last_c[i] = 0xffffffffu; last_h[i] = 0; }
    /* v3.9.1: скан #1 через 45с после базы (движок встал, стейт создан,
     * ЦЕПОЧКА стартует ~минуту-две спустя — скан должен УСПЕТЬ ДО неё:
     * run160: скан t+2мин опоздал, a2 отработала цепочку без сканов);
     * далее +75с если пусто; ин-полл ресканы каждые ~64с (кап 10) добивают */
    for (it = 0; it < 45; it++) usleep(1000000);
    c2b_g24_find_state();
    for (it = 0; it < 75 && !g_g24_nstate; it++) usleep(1000000);
    if (!g_g24_nstate) c2b_g24_find_state();
    for (i = 0; i < g_g24_nstate; i++) {             /* базовая линия */
        u32 cs = *(volatile const u32 *)(g_g24_state[i] + 0x1a0);
        last_c[i] = cs;
        last_h[i] = 0;                               /* форс первого chg-лога */
        c2b_g24_dumpone(i, cs);
    }
    {   u32 scans = 2;
        for (it = 0; it < 4800; it++) {              /* 20 мин по 250мс */
            if (g_g24_nstate < 4 && scans < 10 && (it & 0xB7) == 0xB7) {
                c2b_g24_find_state();                /* ~каждые 45с пока 0 */
                scans++;
            }
        for (i = 0; i < g_g24_nstate; i++) {
            uptr st = g_g24_state[i];
            u32 cs = *(volatile const u32 *)(st + 0x1a0);
            u32 chal = *(volatile const u32 *)(st + 0x4d8);
            u32 proto = *(volatile const u32 *)(st + 0x4dc);
            u64 h;
            u32 k;
            h = (u64)cs * 1000003u;
            h ^= *(volatile const u64 *)(st + 0x128);
            h = h * 1000003u + chal;
            h = h * 1000003u + proto;
            h = h * 1000003u + *(volatile const u32 *)(st + 0x4e0);
            for (k = 0; k < 4; k++)
                h = h * 1000003u + *(volatile const u64 *)(st + 0x4f0 + k * 8);
            h = h * 1000003u + *(volatile const u32 *)(st + 0x50c);
            h = h * 1000003u + *(volatile const u32 *)(st + 0x8dc4);
            /* g26: пред-чеки SendConnectPacket — snap[0x1c] и auth-proto
             * в норме ставит мёртвая для живого пути ветка "connect"-
             * команды диспетчера; чиним в памяти.
             * v2 (run164): 'k' НЕ ушёл — чек (b) 0x248330 это НЕ netadr-cmp,
             * а ПОИСК КАНАЛА: {arr@0x148, cnt@0x158}, элементы 0x68, матч:
             * el->0x64==snap[0x1c]∈{1..3}, snap[0x18]==0&&el->0x60==0,
             * el->0x54(u64)==snap.u64[0x0c], el->0x5c==snap[0x14].
             * ('B'-формулы из RE: "B" = элемент канала, НЕ пакет!)
             * Стратегия: ищем элемент с 0x64∈{1..3} -> ВЫРАВНИВАЕМ snap под
             * него (snap - наш скретч; el->0x54 -> snap[0x0c..0x13] НЕ рвёт
             * адрес: порт = младшие байты 0x54, у живого канала они равны
             * порту цели). Нет такого элемента -> хирургия элемента[0]:
             * 0x64=1, 0x60=0, 0x54=snap.u64[0x0c], 0x5c=snap[0x14]. */
            if (chal != 0 && proto == 3) {
                u32 s1c = *(volatile u32 *)(st + 0x50c);
                u32 ap = *(volatile u32 *)(st + 0x8dc4);
                uptr arr = *(volatile const uptr *)(st + 0x148);
                u32 cnt = *(volatile const u32 *)(st + 0x158);
                if (s1c != (g_g29_en ? 0u : 1u)) {
                    *(volatile u32 *)(st + 0x50c) = (g_g29_en ? 0u : 1u);
                    C2B_LOGS(g_g29_en ? "[c2b] g29: snap[0x1c]->0 st="
                                      : "[c2b] g26: snap[0x1c]->1 st=");
                    C2B_LOGH((u32)st); C2B_LOGS("\n");
                }
                if (ap == 0) {
                    *(volatile u32 *)(st + 0x8dc4) = 3;
                    C2B_LOGS("[c2b] g26: auth-proto 0->3 st=");
                    C2B_LOGH((u32)st); C2B_LOGS("\n");
                }
                if (arr && cnt) {
                    if (!g_g29_en) {
                        /* ---- СТАРАЯ СТРАТЕГИЯ g26v2 (откат): snap[0x1c]=1
                         * + выравнивание snap под элемент (primary-путь
                         * чека (b): el->0x64==snap[0x1c]∈{1..3} и т.д.) */
                        u32 ei, matched = 0;
                        for (ei = 0; ei < cnt && ei < 8 && !matched; ei++) {
                            uptr el = arr + (uptr)ei * 0x68;
                            u32 e64 = *(volatile const u32 *)(el + 0x64);
                            if (e64 >= 1 && e64 <= 3) {
                                u32 e60 = *(volatile const u32 *)(el + 0x60);
                                u64 e54 = *(volatile const u64 *)(el + 0x54);
                                u32 e5c = *(volatile const u32 *)(el + 0x5c);
                                matched = 1;
                                if (s1c != e64) {
                                    *(volatile u32 *)(st + 0x50c) = e64;
                                    C2B_LOGS("[c2b] g26v2: snap[0x1c]->el64 el=");
                                    C2B_LOGH((u32)el);
                                    C2B_LOGS("v=");
                                    C2B_LOGH(e64); C2B_LOGS("\n");
                                }
                                if (e60 != 0) {
                                    *(volatile u32 *)(el + 0x60) = 0;
                                    C2B_LOGS("[c2b] g26v2: el->0x60 ->0 el=");
                                    C2B_LOGH((u32)el); C2B_LOGS("\n");
                                }
                                {   u64 s0c = *(volatile const u64 *)(st + 0x4fc);
                                    if (s0c != e54) {
                                        *(volatile u64 *)(st + 0x4fc) = e54;
                                        C2B_LOGS("[c2b] g26v2: snap[0x0c..0x13]->el54 v=");
                                        C2B_LOGH((u32)(e54 >> 32));
                                        C2B_LOGH((u32)e54); C2B_LOGS("\n");
                                    }
                                    if (*(volatile const u32 *)(st + 0x504) != e5c) {
                                        *(volatile u32 *)(st + 0x504) = e5c;
                                        C2B_LOGS("[c2b] g26v2: snap[0x14]->el5c v=");
                                        C2B_LOGH(e5c); C2B_LOGS("\n");
                                    }
                                }
                                C2B_LOGS("[c2b] g26v2: channel match built el=");
                                C2B_LOGH((u32)el);
                                C2B_LOGS("e64=");
                                C2B_LOGH(e64);
                                C2B_LOGS("\n");
                            }
                        }
                        if (!matched) {   /* хирургия элемента[0] под snap */
                            uptr el = arr;
                            C2B_LOGS("[c2b] g26v2: no el64 1..3, surgery el=");
                            C2B_LOGH((u32)el);
                            C2B_LOGS("e64=");
                            C2B_LOGH(*(volatile const u32 *)(el + 0x64));
                            C2B_LOGS("e60=");
                            C2B_LOGH(*(volatile const u32 *)(el + 0x60));
                            C2B_LOGS("\n");
                            *(volatile u32 *)(el + 0x64) = 1;
                            *(volatile u32 *)(el + 0x60) = 0;
                            *(volatile u64 *)(el + 0x54) =
                                *(volatile const u64 *)(st + 0x4fc);
                            *(volatile u32 *)(el + 0x5c) =
                                *(volatile const u32 *)(st + 0x504);
                            *(volatile u32 *)(st + 0x50c) = 1;
                        }
                    } else {
                        /* ---- g29: OLD-зеркала netadr в ОБЕ стороны ----
                         * snap[0x1c]=0 -> чек (b) по alt-пути 0x2483b0:
                         * 65e930(snap, el+0x48, 0) — netadr== старого
                         * класса {type@0, ip BE @+4, port BE @+8}.
                         * Источники — NEW-копия приёмника: ip bytes
                         * @st+0x4f8, port BE @st+0x4fc. Пишем в snap
                         * (+0x4f4/+0x4f8) и el (+0x4c/+0x50) ОДИНАКОВЫЕ
                         * OLD-значения -> 65e930=true, identity строится
                         * ЧИСТЫМ путём (65ec30/65ec10) = IPv4(цель). */
                        uptr el = arr;
                        u32 ei;
                        for (ei = 0; ei < cnt && ei < 8; ei++) {
                            uptr e = arr + (uptr)ei * 0x68;
                            if (*(volatile const u32 *)(e + 0x48) == 3) {
                                el = e; break;
                            }
                        }
                        {   u32 ipb = *(volatile const u32 *)(st + 0x4f8);
                            u16 ptb = *(volatile const u16 *)(st + 0x4fc);
                            if (ipb != 0 && ptb != 0) {
                                if (*(volatile const u32 *)(st + 0x4f4) != ipb) {
                                    *(volatile u32 *)(st + 0x4f4) = ipb;
                                    C2B_LOGS("[c2b] g29: snap.ip<-recv st=");
                                    C2B_LOGH((u32)st);
                                    C2B_LOGS("v=");
                                    C2B_LOGH(ipb); C2B_LOGS("\n");
                                }
                                if (*(volatile const u16 *)(st + 0x4f8) != ptb) {
                                    *(volatile u16 *)(st + 0x4f8) = ptb;
                                    C2B_LOGS("[c2b] g29: snap.port<-recv v=");
                                    C2B_LOGH(ptb); C2B_LOGS("\n");
                                }
                                if (*(volatile const u32 *)(el + 0x4c) != ipb) {
                                    *(volatile u32 *)(el + 0x4c) = ipb;
                                    C2B_LOGS("[c2b] g29: el.ip el=");
                                    C2B_LOGH((u32)el);
                                    C2B_LOGS("v=");
                                    C2B_LOGH(ipb); C2B_LOGS("\n");
                                }
                                if (*(volatile const u16 *)(el + 0x50) != ptb) {
                                    *(volatile u16 *)(el + 0x50) = ptb;
                                    C2B_LOGS("[c2b] g29: el.port v=");
                                    C2B_LOGH(ptb); C2B_LOGS("\n");
                                }
                                C2B_LOGS("[c2b] g29: old-mirrors built el=");
                                C2B_LOGH((u32)el);
                                C2B_LOGS("ip=");
                                C2B_LOGH(ipb);
                                C2B_LOGS("pt=");
                                C2B_LOGH(ptb);
                                C2B_LOGS("\n");
                            }
                        }
                    }
                }
                /* g28: прямой вызов vt+0x198 SendConnectPacket(state,&snap,
                 * chal,proto,val,u8@0x4c1) — рефрактерность 2с (8 итераций),
                 * кап 10; тикет-зону исполняет сам движок */
                if (g_g28_en && g_g28_sends < 10 &&
                    (u32)(it - g_g28_last_it) >= 8) {
                    uptr vt = *(volatile const uptr *)st;
                    uptr fn = vt ? *(volatile const uptr *)(vt + 0x198) : 0;
                    g_g28_last_it = it;
                    if (fn && g_engine_base &&
                        fn - g_engine_base < 0x4000000ull) {
                        C2B_LOGS("[c2b] g28: scp call #");
                        C2B_LOGN(g_g28_sends + 1);
                        C2B_LOGS("fn=");
                        C2B_LOGH((u32)(fn >> 32)); C2B_LOGH((u32)fn);
                        C2B_LOGS("chal=");
                        C2B_LOGH(chal);
                        C2B_LOGS("proto=");
                        C2B_LOGH(proto);
                        C2B_LOGS("\n");
                        ((void (*)(uptr, const void *, u32, u32, u64, u32))fn)(
                            st, (const void *)(st + 0x4f0), chal, proto,
                            *(volatile const u64 *)(st + 0x4e0),
                            *(volatile const u8 *)(st + 0x4c1));
                        g_g28_sends++;
                        C2B_LOGS("[c2b] g28: scp returned\n");
                    } else {
                        C2B_LOGS("[c2b] g28: fn rejected vt=");
                        C2B_LOGH((u32)(vt >> 32)); C2B_LOGH((u32)vt);
                        C2B_LOGS("fn=");
                        C2B_LOGH((u32)(fn >> 32)); C2B_LOGH((u32)fn);
                        C2B_LOGS("\n");
                    }
                }
            }
            /* v3.9: cstate!=0 = подключающееся окно (может быть короче 250мс
             * опроса) — логируем КАЖДУЮ итерацию пока подключается: траектория
             * cstate + snap В МОМЕНТ 'A' — решающие данные.
             * v4.1 (run164): фильтр мусорных инстансов (стек/указательные зоны
             * с мусорным proto) — они жгут кап 512 ПОСТРОЧНО (указатели меняются
             * каждый опрос); реальные стейты всегда proto==3 ('A'-парс). */
            if (cs != 0 && proto == 3 && logged < 512) {
                last_c[i] = cs;
                last_h[i] = h;
                logged++;
                c2b_g24_dumpone(i, cs);
            } else if (cs != last_c[i] || h != last_h[i]) {
                last_c[i] = cs;
                last_h[i] = h;
                logged++;
                if (logged <= 64 || (logged & 0x3F) == 1) c2b_g24_dumpone(i, cs);
            }
        }
        usleep(250000);
        }
    }
    C2B_LOGS("[c2b] g24: watch done changes=");
    C2B_LOGN(logged);
    C2B_LOGS("\n");
    return 0;
}

static void c2b_g12_apply(void)
{
    static u8 done;
    uptr base, st, in, tr;
    if (done) return;
    base = g_g11_base;
    if (!base) return;
    st = base + C2B_G12_STATE_RVA;
    in = base + C2B_G12_INIT_RVA;
    {   const u8 *p = (const u8 *)st;
        u32 i;
        for (i = 0; i < 16; i++)
            if (c2b_g12_msk_state[i] && p[i] != c2b_g12_pat_state[i]) {
                C2B_LOGS("[c2b] g12: state sig mismatch\n"); done = 1; return;
            }
    }
    if (memcmp((const void *)in, c2b_g12_sig_init, sizeof c2b_g12_sig_init) != 0) {
        C2B_LOGS("[c2b] g12: init sig mismatch\n"); done = 1; return;
    }
    /* g12i: трамплин 20Б + jmp 0x1f799d4 */
    tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g12i_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)in, sizeof c2b_g12_sig_init);
    c2b_write_jmp((void *)(tr + sizeof c2b_g12_sig_init),
                  (const void *)(in + sizeof c2b_g12_sig_init));
    c2b_g12i_tramp = (const volatile void *)tr;
    if (c2b_page_protect(in, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)in, (const void *)&c2b_g12i_thunk);
    /* g12s: трамплин 16Б + jmp 0x1f763a0 */
    tr = (uptr)mmap(0, 4096, 0x07, 0x22, -1, 0);
    if (tr == (uptr)-1) { done = 1; return; }
    g_g12s_tramp_mem = (u8 *)tr;
    memcpy((void *)tr, (const void *)st, 16);
    c2b_write_jmp((void *)(tr + 16), (const void *)(st + 16));
    c2b_g12s_tramp = (const volatile void *)tr;
    if (c2b_page_protect(st, C2B_PATCH_LEN, 0x07) != 0) { done = 1; return; }
    c2b_write_jmp((void *)st, (const void *)&c2b_g12s_thunk);
    done = 1;
    C2B_LOGS("[c2b] g12: armed state+init base=");
    C2B_LOGH((u32)base); C2B_LOGS("\n");
}

static void c2b_gns_spew_rearm(void)
{
    u32 it, c, applied = 0;
    c2b_g8_patch_apply();   /* 41f-g8: пач слота независимо от copy#1 */
    c2b_g9_patch_apply();   /* 41f-g9: IP_AllowWithoutAuth=1 во все копии */
    c2b_g9_flat_set();      /* 41f-g9: flat set через copy#1 */
    c2b_g11_apply();        /* 41f-g11: транспортная выводка ConnectRequest */
    c2b_g12_apply();        /* 41f-g12: зонды стейт-машины (SetState/InitConn) */
    c2b_g13_apply();        /* 41f-g13: диспетчер connectionless движка (слепая зона hdr) */
    c2b_g16_apply();        /* 41f-g16: живой путь датаграмм (send-обёртка + пост-recvfrom) */
    c2b_g17_apply();        /* 41f-g17: вердикт connectionless-фильтра (enqueue vs drop) */
    c2b_g18_apply();        /* 41f-g18: поиск консьюмера (кольцо нод + слот Free) */
    c2b_g21_apply();        /* 41f-g21: 'A'-accept валидатор (gate+path, vt+0x200) */
    c2b_g22_apply();        /* 41f-g22: FullConnect детектор (vt+0x170, 'B'-успех) */
    /* c2b_g19_apply();  41f-g19 BISECT run137: disabled - run135/136 connect-flow death suspect (0x2e1ad5 in the connect path) */
    if (!g_gns_u[0]) return;
    for (it = 0; it < 60; it++) {
        if (!g_gns_u2_done) c2b_g5_resolve_copy2();
        for (c = 0; c < 2; c++) {
            if (g_gns_u[c]) {
                c2b_g5_apply(g_gns_u[c], g_gns_flat[c], g_gns_cfg[c],
                             c ? "copy#2" : "copy#1", 0);
                applied++;
            }
        }
        if (g_g8_slot) *g_g8_slot = (const volatile void *)c2b_gns_spew;
        c2b_g9_patch_apply();   /* 41f-g9: re-assert (поздние копии/гонки) */
        c2b_g9_flat_set();      /* 41f-g9: copy#1 мог появиться позже */
        c2b_g11_apply();        /* 41f-g11: одноразово (done-флаг внутри) */
        c2b_g12_apply();        /* 41f-g12: одноразово (done-флаг внутри) */
        c2b_g13_apply();        /* 41f-g13: одноразово (done-флаг внутри) */
        c2b_g16_apply();        /* 41f-g16: одноразово (done-флаг внутри) */
        c2b_g17_apply();        /* 41f-g17: одноразово (done-флаг внутри) */
        c2b_g18_apply();        /* 41f-g18: одноразово (done-флаги внутри) */
        c2b_g21_apply();        /* 41f-g21: одноразово (done-флаги внутри) */
        c2b_g22_apply();        /* 41f-g22: одноразово (done-флаги внутри) */
        /* c2b_g19_apply();  41f-g19 BISECT run137: disabled */
        usleep(5000000);
    }
    C2B_LOGS("[c2b] GNS: rearm done applied="); C2B_LOGN(applied);
    C2B_LOGS("u2done="); C2B_LOGN(g_gns_u2_done); C2B_LOGS("\n");
}

/* 41f-g20: РАННИЙ арм движковых зондов. Run134 урок: bait-цепочка CLV2
 * уходит ЦЕЛИКОМ до арма (auth-тред ждёт steamuser до 150с, а baits идут
 * сразу; в a2 g18/g19 armed на строке 830 ПОСЛЕ phase6 на 810 — дампы
 * 'A'/'B' потеряны). Отдельный тред: как только g_engine_base известен
 * (legacy-скан, очень рано), гоняем g13/g16/g17/g18/g19 каждую секунду до
 * 4 мин. Арм ДО начала bait-цепочки = дампы гарантированы. Применения
 * идемпотентны (done-флаги), гонка с rearm-тредом benign (те же байты). */
static void *c2b_early_arm_thread(void *arg)
{
    u32 it;
    (void)arg;
    /* Хендлер ставим ПЕРМАНЕНТНО ДО первого арма: гарды логгеров мертвы вне
     * auth-окна (ранний арм g20), а чужие фолты c2b_probe_segv теперь честно
     * убивает (SIG_DFL-чейн) — refault-спин/SIGKILL-клон невозможен. */
    {
        struct c2b_sigaction sa;
        u32 t;
        for (t = 0; t < sizeof(sa); t++) ((u8 *)&sa)[t] = 0;
        sa.handler = (uptr)c2b_probe_segv;
        sa.flags = 4;                          /* SA_SIGINFO */
        sigemptyset(sa.mask);
        sigaction(11, &sa, (void *)0);
    }
    C2B_LOGS("[c2b] EARLY: engine-probe arm thread start\n");
    for (it = 0; it < 240; it++) {
        c2b_g13_apply();
        c2b_g16_apply();
        c2b_g17_apply();
        c2b_g18_apply();
        /* c2b_g19_apply();  41f-g19 BISECT run137: disabled */
        usleep(1000000);
    }
    C2B_LOGS("[c2b] EARLY: arm loop exit\n");
    return 0;
}
#else
static void c2b_gns_spew_install(void) { }   /* selftest: стаб */
static void c2b_gns_spew_rearm(void) { }     /* selftest: стаб */
static void c2b_g7_client_utils(void) { }    /* selftest: стаб */
static void *c2b_early_arm_thread(void *arg) { (void)arg; return 0; }  /* стаб */
#endif  /* C2B_SELFTEST */

static void *c2b_auth_thread(void *arg)
{
    u32 i, att;
    (void)arg;
    /* ждём капчур до 150с (движок грузит steam_api уже после меню-обвяза) */
    for (i = 0; i < 150 && !g_steamuser_obj; i++) usleep(1000000);
    if (!g_steamuser_obj) {
        C2B_LOGS("[c2b] AUTH: SteamUser never appeared\n");
        return 0;
    }
#ifndef C2B_SELFTEST
    c2b_gns_spew_install();  /* 41f-g: ПОСЛЕ капчура — steamclient уже загружен */
#endif
    void **vt = *(void ***)g_steamuser_obj;
    u32 sane = 1;
    for (i = 0; i < 16; i++)
        if (!vt[i]) { sane = 0; break; }
    C2B_LOGS("[c2b] AUTH: SteamUser ptr="); C2B_LOGH((u32)(uptr)g_steamuser_obj);
    C2B_LOGS("vt sane="); C2B_LOGN(sane); C2B_LOGS("\n");
    if (!sane) return 0;
    {   /* BLoggedOn (vt[1]) */
        i32 logged = ((i32 (*)(void *))vt[1])(g_steamuser_obj);
        C2B_LOGS("[c2b] AUTH: BLoggedOn="); C2B_LOGN((u32)(logged != 0));
        C2B_LOGS("\n");
    }
    {   /* GetSteamID (vt[2], u64 в RAX) — sanity модели vtable */
        u64 sid = ((u64 (*)(void *))vt[2])(g_steamuser_obj);
        C2B_LOGS("[c2b] AUTH: GetSteamID=0x"); C2B_LOGH((u32)(sid >> 32));
        C2B_LOGH((u32)sid); C2B_LOGS("\n");
        if ((sid >> 56) != 0x01) {
            C2B_LOGS("[c2b] AUTH: steamid implausible — vtable model wrong, ticket skipped\n");
            return 0;
        }
    }
    c2b_auth_ticket_probe();
    C2B_LOGS("[c2b] AUTH: done calls="); C2B_LOGN(g_ticket_calls);
    C2B_LOGS(" ok="); C2B_LOGN(g_ticket_ok);
    C2B_LOGS("\n");
    /* 41f-g32a: спавн ДО spew_rearm — rearm НЕ возвращает поток (60x5s цикл;
     * v3-урок: спавн после него недостижим). Драйвер-поток сам ждёт ничего:
     * SteamUser уже капчурен (проба тикета выше), env-флаги стоят (init). */
#ifndef C2B_SELFTEST
    {
        void *t32 = 0;
        if (pthread_create(&t32, (const void *)0, c2b_g32_thread,
                           (void *)0) == 0)
            C2B_LOGS("[c2b] g32: driver thread started\n");
        else
            C2B_LOGS("[c2b] g32: pthread_create failed\n");
    }
#endif
    c2b_gns_spew_rearm();   /* 41f-g5/g8/g9: пин спью+конфига (блокирует поток) */
    c2b_g7_client_utils();   /* 41f-g10: ЗАГЛУШЕН (убивал процесс до rearm) */
    return 0;
}

#ifndef C2B_SELFTEST
/* g32a-обёртка для pthread: spew_rearm держит auth-поток в 60x5s цикле
 * (run173: драйвер ПОСЛЕ rearm недостижим — попытка кончается раньше) */
static void *c2b_g32_thread(void *arg)
{
    (void)arg;
    c2b_g32_drive();
    return 0;
}

/* ================= 41f-g32a: GNS ConnectByIPAddress-драйвер =================
 * Цель — заставить steamclient-овский GNS СОЗДАТЬ реальное соединение к
 * CS2-цели: его 0x20/0x21 обмен + ПОСТРОЕННЫЙ 0x22 (его cert+crypt, подпись
 * живая) капчурится g11a-тунком (сегмент-дамп) и РЕЛЕится мостом
 * (C2B_GNS_RELAY=1) с fd движка (биндинг challenge по адресу сохранён).
 * Путь: SteamInternal_FindOrCreateUserInterface(g_steamuser_user,
 * "SteamNetworkingSockets006" | 009) -> vt[1] ConnectByIPAddress(iface,
 * &SteamNetworkingIPAddr{a.b.c.d,0..,port}, 0, NULL). SEGV-гвард g7. */
static void c2b_g32_drive(void)
{
    u32 a[4], pr = 0;
    u16 port = 0;
    u8 addr[20];
    u32 k;
    void *clp;
    struct c2b_sigaction sa, oldsa;
    if (!g_gns_connect_go || !g_clp_fouif || !g_steamuser_seen) {
        C2B_LOGS("[c2b] g32: not armed (env/ifactory/user missing)\n");
        return;
    }
    /* 41f-g33: открыть ГЛОБАЛЬНЫЙ спью-гейт GNS (steamclient+0x2c6dcc8).
     * RE run177: это глобальный уровень спью (гейты cmpl $4/$5/$6 по всему
     * коннект-коду); дефолт <=1 РЕЖЕТ verbose-спью включая ПРИЧИНУ отказа
     * BInitConnect (0x1fd13d0 ->errMsg -> 0x1fce3a0(level2) скипается на
     * 0x1ef4312: cmpl $1; jle). Ждём базу от g11_apply (спавн ДО rearm —
     * гонка на старте) и пишем 6. FD: тот же лог через g8-колбек. */
    {
        u32 wt;
        for (wt = 0; wt < 600 && !g_g11_base; wt++) usleep(100000);
        if (g_g11_base) {
            *(volatile u32 *)(g_g11_base + 0x2c6dcc8ull) = 6;
            C2B_LOGS("[c2b] g33: global spew gate 0x2c6dcc8 -> 6\n");
            /* 41f-g34: ПРИНУДИТЬ спью отказа ConnectByIPAddress —
             * 0x1ef431c: 7e 16 (jle, скипает spew "Cannot create IPv4
             * connection. %s" при гейте <=1) -> 90 90 (nop nop): errMsg
             * из стека ПЕЧАТАЕТСЯ всегда. Гейт g33 выше уже открыт,
             * но спью не шёл — вероятен второй фильтр ниже по потоку;
             * патч 2 байт убирает саму ветку. Сиг-чек 7e 16 обязателен. */
            {
                volatile u8 *p34 = (volatile u8 *)(g_g11_base + 0x1ef431cull);
                u8 b0 = *p34, b1 = *(p34 + 1);
                C2B_LOGS("[c2b] g34: sig@0x1ef431c=");
                C2B_LOGH(b0); C2B_LOGH(b1);
                if (b0 == 0x7e && b1 == 0x16) {
                    if (c2b_page_protect((uptr)p34, 2, 0x07) == 0) {
                        *p34 = 0x90; *(p34 + 1) = 0x90;
                        C2B_LOGS(" -> noped (spew forced)\n");
                    } else {
                        C2B_LOGS(" -> mprotect failed\n");
                    }
                } else {
                    C2B_LOGS(" -> sig mismatch, skip\n");
                }
            }
            /* 41f-g34v2: подменить ЛИБЕЙНЫЙ спью-фн (0x2c6dcd0, .data RW).
             * Дефолт = стёамовский логгер (невидим); наш хук vsnprintf-ит
             * fmt+va в лог. Это канал ВСЕГО establish-спью GNS. */
            {
                void *volatile *slot = (void *volatile *)(g_g11_base + 0x2c6dcd0ull);
                void *oldfn = *slot;
                *slot = (void *)&c2b_gns_libspew_hook;
                C2B_LOGS("[c2b] g34v2: libspew fn 0x2c6dcd0 old=");
                C2B_LOGH((u32)(uptr)oldfn);
                C2B_LOGS(" -> hook\n");
            }
            /* 43f-g41b: пропустить КАНОНИЧЕСКУЮ mapped-форму через классификатор.
             * 0x1ef41c2: cmp $0x1,%eax (83 f8 01); jle 0x1ef42d0 — ret=3
             * (mapped-v4, не fake) падал в опшенс-путь -> h=0. Меняем
             * imm8 01 -> 03 (1 байт): принимаются 1 (raw, старое поведение)
             * и 3 (канон, новый путь). ret=2 (fake-range) нам не встречается
             * (цель не 169.254.248.0/22). Сиг-чек обязателен. */
            {
                volatile u8 *p41 = (volatile u8 *)(g_g11_base + 0x1ef41c2ull);
                C2B_LOGS("[c2b] g41: sig@0x1ef41c2=");
                C2B_LOGH(p41[0]); C2B_LOGH(p41[1]); C2B_LOGH(p41[2]); C2B_LOGH(p41[3]);
                if (p41[0] == 0x83 && p41[1] == 0xf8 && p41[2] == 0x01 && p41[3] == 0x0f) {
                    if (c2b_page_protect((uptr)p41, 4, 0x07) == 0) {
                        p41[2] = 0x03;
                        C2B_LOGS(" -> patched (accept mapped-v4)\n");
                    } else {
                        C2B_LOGS(" -> mprotect failed\n");
                    }
                } else {
                    C2B_LOGS(" -> sig mismatch, skip\n");
                }
            }
            /* 43f-g38 (RE run181): состояние НИЗКОУРОВНЕВОГО инита перед
             * Connect — refcount 0x2cbb900, s_hEpoll 0x2c6dcb8, wake-fd
             * 0x2c6dcbc/0x2c6dcc0. Здоровая картина: refcount>=1 (наш
             * коннект уже AddRef'нулся? НЕТ — читаем ДО Connect, так что
             * 0, если движок сам низкоуровневый слой не поднимал) и
             * s_hEpoll=-1 ДО коннекта — норма; ключевой маркер — что
             * ПОСЛЕ коннекта (см. дублируемый лог ниже). */
            {
                volatile u32 *refc = (volatile u32 *)(g_g11_base + 0x2cbb900ull);
                volatile i32 *pep = (volatile i32 *)(g_g11_base + 0x2c6dcb8ull);
                volatile i32 *prd = (volatile i32 *)(g_g11_base + 0x2c6dcbcull);
                volatile i32 *pwr = (volatile i32 *)(g_g11_base + 0x2c6dcc0ull);
                C2B_LOGS("[c2b] g38: pre-connect lowlevel refcnt=");
                C2B_LOGN(*refc);
                C2B_LOGS(" s_hEpoll="); C2B_LOGN((u32)*pep);
                C2B_LOGS(" wakeR="); C2B_LOGN((u32)*prd);
                C2B_LOGS(" wakeW="); C2B_LOGN((u32)*pwr);
                C2B_LOGS("\n");
            }
        } else {
            C2B_LOGS("[c2b] g33: no g11 base in 60s - spew gate skipped\n");
        }
    }
    /* 41f-g36: диагностика fd-бюджета В МОМЕНТ коннекта: lowest-free-fd
     * (open("/dev/null") даёт наименьший свободный номер) + epoll-проба. */
    {
        extern i32 open(const char *, i32, ...);
        extern i32 close(i32);
        extern i32 epoll_create1(i32);
        i32 fdp = open("/dev/null", 0 /*O_RDONLY*/);
        i32 ep = epoll_create1(0);
        C2B_LOGS("[c2b] g36: lowest-free-fd=");
        C2B_LOGN((u32)(fdp < 0 ? 99999u : (u32)fdp));
        C2B_LOGS(" epoll_create1=");
        C2B_LOGN((u32)(ep < 0 ? 99999u : (u32)ep));
        if (ep >= 0) close(ep);
        if (fdp >= 0) close(fdp);
        C2B_LOGS("\n");
    }
    /* парс "a.b.c.d:port" из g_gns_connect_target */
    {
        const char *s = (const char *)g_gns_connect_target;
        u32 i = 0;
        for (k = 0; k < 4; k++) {
            u32 v = 0;
            while (s[i] >= '0' && s[i] <= '9') { v = v * 10 + (u32)(s[i] - '0'); i++; }
            a[k] = v & 255u;
            if (k < 3 && s[i] == '.') i++;
        }
        if (s[i] == ':') {
            i++;
            while (s[i] >= '0' && s[i] <= '9') { port = (u16)(port * 10 + (u16)(s[i] - '0')); i++; }
        }
        pr = (a[0] | a[1] | a[2] | a[3]) ? 1u : 0u;
    }
    if (!pr || !port) {
        C2B_LOGS("[c2b] g32: bad C2B_GNS_CONNECT value\n");
        return;
    }
    /* g32 v2: БЕЗ ожидания g_clv2_dstlen (run172: 240s-ждатель пережил
     * попытку — драйвер не дошёл до Connect). Релей использует СОБСТВЕННЫЙ
     * sockaddr_in из env (g_gns_dst), капчер работает всегда. */
    {
        for (k = 0; k < 16; k++) g_gns_dst[k] = 0;
        g_gns_dst[0] = 2;                              /* AF_INET (LE) */
        g_gns_dst[2] = (u8)(port >> 8);                /* sin_port BE */
        g_gns_dst[3] = (u8)(port & 0xff);
        g_gns_dst[4] = (u8)a[0]; g_gns_dst[5] = (u8)a[1];
        g_gns_dst[6] = (u8)a[2]; g_gns_dst[7] = (u8)a[3];
        g_gns_dstlen = 16;
        C2B_LOGS("[c2b] g32: relay dst built 02 00 ");
        C2B_LOGH(g_gns_dst[2]); C2B_LOGH(g_gns_dst[3]);
        C2B_LOGH(g_gns_dst[4]); C2B_LOGH(g_gns_dst[5]);
        C2B_LOGH(g_gns_dst[6]); C2B_LOGH(g_gns_dst[7]);
        C2B_LOGS("\n");
    }
    for (k = 0; k < sizeof(addr); k++) addr[k] = 0;
    /* 43f-g41 (RE run185): КАНОНИЧЕСКАЯ IPv4-MAPPED форма! Конвертер
     * sockaddr (0x22487a0: family=AF_INET6 прематчится, затем джамп-таблица
     * по TYPE @obj+0x14) для raw-формы {ip@0-3, нули, port@16} даёт
     * type=IPv6 -> sockaddr_in6 ::98e9:1385 -> sendto ENETUNREACH (0x65,
     * g40: ret=-1, семейство !=2, dst=0) — пакеты НЕ идут на провод.
     * Канон: байты 0-9=0, 10-11=ff ff (IsIPv4!), 12-15=ip, port@16 ->
     * тип=IPv4 -> AF_INET -> пакеты идут. ПРИМЕЧАНИЕ: классификатор
     * 0x1fed370 для канона вернёт 3 (>=mapped-v4) — патчим сравнение
     * вызывающего (см. g41b ниже), чтобы коннект-путь принял форму 3. */
    addr[10] = 0xff; addr[11] = 0xff;
    addr[12] = (u8)a[0]; addr[13] = (u8)a[1];
    addr[14] = (u8)a[2]; addr[15] = (u8)a[3];
    addr[16] = (u8)(port & 0xff); addr[17] = (u8)(port >> 8);   /* m_port LE (host=x86) */
    {
        static const char *const vers[2] = {
            "SteamNetworkingSockets006", "SteamNetworkingSockets009" };
        u32 vi;
        for (k = 0; k < sizeof(sa); k++) ((u8 *)&sa)[k] = 0;
        for (k = 0; k < sizeof(oldsa); k++) ((u8 *)&oldsa)[k] = 0;
        sa.handler = (uptr)c2b_probe_segv;
        sa.flags = 4;
        sigemptyset(sa.mask);
        if (sigaction(11, &sa, &oldsa) != 0) return;
        clp = g_clp_fouif;
        for (vi = 0; vi < 2; vi++) {
            void *iface = 0;
            uptr h = 0;
            void **vt;
            g_probe_active = 1;
            if (__sigsetjmp(g_probe_jb, 1) == 0) {
                iface = ((void *(*)(int, const char *))clp)(
                    g_steamuser_user, vers[vi]);
                g_probe_active = 0;
            } else {
                g_probe_active = 0;
                C2B_LOGS("[c2b] g32: factory SEGV ver=");
                C2B_LOGS(vers[vi]); C2B_LOGS("\n");
                continue;
            }
            if (!iface) {
                C2B_LOGS("[c2b] g32: no iface ver=");
                C2B_LOGS(vers[vi]); C2B_LOGS("\n");
                continue;
            }
            C2B_LOGS("[c2b] g32: iface ver="); C2B_LOGS(vers[vi]);
            C2B_LOGS(" ok\n");
            vt = *(void ***)iface;
            g_probe_active = 1;
            if (__sigsetjmp(g_probe_jb, 1) == 0) {
                h = ((uptr (*)(void *, void *, i32, void *))vt[1])(
                    iface, addr, 0, (void *)0);
                g_probe_active = 0;
            } else {
                g_probe_active = 0;
                C2B_LOGS("[c2b] g32: ConnectByIPAddress SEGV\n");
                break;
            }
            C2B_LOGS("[c2b] g32: ConnectByIPAddress h="); C2B_LOGN((u32)h);
            C2B_LOGS("\n");
            /* 43f-g38b: состояние НИЗКОУРОВНЕВОГО слоя ПОСЛЕ коннекта:
             * если AddRef отработал с полным инитом, s_hEpoll != -1 и
             * refcnt вырос; s_hEpoll=-1 при живом refcnt = init был
             * СКИПНУТ (чужой стор в 0x2cbb900 — см. g37) */
            if (g_g11_base) {
                volatile u32 *refc = (volatile u32 *)(g_g11_base + 0x2cbb900ull);
                volatile i32 *pep = (volatile i32 *)(g_g11_base + 0x2c6dcb8ull);
                C2B_LOGS("[c2b] g38: post-connect lowlevel refcnt=");
                C2B_LOGN(*refc);
                C2B_LOGS(" s_hEpoll="); C2B_LOGN((u32)*pep);
                C2B_LOGS("\n");
            }
            break;   /* первая сработавшая версия */
        }
        sigaction(11, &oldsa, (void *)0);
    }
}
#endif  /* C2B_SELFTEST (g32a-драйвер: real-build only) */

/* xorshift32; сид = адрес стека (ASLR) — conn_id требует уникальности, не крипто */
static u32 c2b_clv2_rand32(void)
{
    static u32 s;
    if (!s) {
        s = (u32)(uptr)(void *)&s ^ 0xC2B1E3D9u;
        if (!s) s = 0xA5F00D42u;
    }
    s ^= s << 13; s ^= s >> 17; s ^= s << 5;
    return s;
}

/* S2 ChallengeRequest: [0x20][u16 pb_len][pb][pad] = ровно 512 байт */
static u32 c2b_clv2_build_chalreq(u8 *out)
{
    u8 pb[32]; u32 n = 0, i;
    u32 cid = c2b_clv2_rand32() | 1u;          /* cid=0 сервер отвергает */
    u64 ts;
    g_clv2_conn_id = cid;
    pb[n++] = 0x0d;                            /* f1 fixed32 connection_id */
    pb[n++] = (u8)(cid); pb[n++] = (u8)(cid >> 8);
    pb[n++] = (u8)(cid >> 16); pb[n++] = (u8)(cid >> 24);
    pb[n++] = 0x19;                            /* f3 fixed64 my_timestamp */
    ts = ((u64)c2b_clv2_rand32() << 32) ^ (u64)c2b_clv2_rand32();
    for (i = 0; i < 8; i++) pb[n++] = (u8)(ts >> (8 * i));
    pb[n++] = 0x20; pb[n++] = 0x0d;            /* f4 varint protocol_version=13 */
    out[0] = 0x20;                             /* k_ESteamNetworkingUDPMsg_ChallengeRequest */
    out[1] = (u8)n; out[2] = (u8)(n >> 8);
    for (i = 0; i < n; i++) out[3 + i] = pb[i];
    for (i = 3 + n; i < 512; i++) out[i] = 0;  /* GNS min padded packet 512 */
    return 512;
}

/* 0x21 ChallengeReply -> challenge64; требует эхо connection_id == expect.
 * g31: ts_out (опционально) = эхо НАШЕГО my_timestamp (f3 fixed64) —
 * он же уходит обратно в 0x22 f4, сервер по нему считает RTT. */
static i32 c2b_clv2_parse_chalreply(const u8 *p, u32 n, u32 expect_cid, u64 *ch,
                                    u64 *ts_out)
{
    u32 i = 1;                                 /* p[0] == 0x21 */
    i32 got = 0;
    u64 v = 0, tv = 0;
    if (n < 9 || p[0] != 0x21) return 0;
    while (i < n) {
        u8 tag = p[i++];
        u32 f = (u32)(tag >> 3), wt = tag & 7;
        if (wt == 1) {
            u64 x = 0; i32 k;
            if (i + 8 > n) return 0;
            for (k = 7; k >= 0; k--) x = (x << 8) | (u64)p[i + k];
            if (f == 2) { v = x; got = 1; }
            if (f == 3) tv = x;
            i += 8;
        } else if (wt == 5) {
            if (i + 4 > n) return 0;
            if (f == 1) {
                u32 cid = (u32)p[i] | ((u32)p[i+1] << 8) |
                          ((u32)p[i+2] << 16) | ((u32)p[i+3] << 24);
                if (cid != expect_cid) return 0;   /* не наш обмен */
            }
            i += 4;
        } else if (wt == 0) {
            while (i < n && p[i] & 0x80) i++;
            i++;
        } else if (wt == 2) {
            u32 ln = 0, sh = 0;
            while (i < n) {
                u8 b = p[i++]; ln |= (u32)(b & 0x7f) << sh;
                if (!(b & 0x80)) break;
                sh += 7;
            }
            i += ln;
        } else {
            return 0;
        }
    }
    if (!got) return 0;
    *ch = v;
    if (ts_out) *ts_out = tv;
    return 1;
}

/* ================= 41f-g31: X25519 (RFC 7748) + 0x22 ConnectRequest =================
 * Чистый C, без bignum-библиотек: поле 2^255-19 в 5 limb'ах по 51 бит (u128
 * аккумуляторы). Нужен ТОЛЬКО один скаляр-базу (генерим keypair для f7 crypt).
 * Векторы RFC 7748 §5.2/§6.1 проверяются в selftest (C2B_SELFTEST). */
typedef unsigned __int128 c2b_u128;

#define C2B_M51 0x7FFFFFFFFFFFFULL   /* 2^51 - 1 */

/* limb-загрузка: 51-битные окна из 256-бит LE-целого (bit-based, без UB) */
static void c2b_f51_load(u64 r[5], const u8 *b)
{
    u32 i, k;
    for (i = 0; i < 5; i++) {
        u64 acc = 0;
        u32 bitpos = 51 * i, byt = bitpos >> 3, sh = bitpos & 7;
        for (k = 0; k < 8; k++)
            if (byt + k < 32) acc |= (u64)b[byt + k] << (8 * k);
        r[i] = (acc >> sh) & C2B_M51;
    }
}

/* limb-выгрузка: биты 0..254 -> 32B LE (вход должен быть канонически приведён) */
static void c2b_f51_store(u8 out[32], const u64 t[5])
{
    u32 bit;
    for (bit = 0; bit < 32; bit++) out[bit] = 0;
    for (bit = 0; bit < 255; bit++) {
        u64 b = (t[bit / 51] >> (bit % 51)) & 1u;
        if (b) out[bit >> 3] |= (u8)(1u << (bit & 7));
    }
}

static void c2b_f51_carry(u64 t[5])
{
    u64 c;
    c = t[0] >> 51; t[0] &= C2B_M51; t[1] += c;
    c = t[1] >> 51; t[1] &= C2B_M51; t[2] += c;
    c = t[2] >> 51; t[2] &= C2B_M51; t[3] += c;
    c = t[3] >> 51; t[3] &= C2B_M51; t[4] += c;
    c = t[4] >> 51; t[4] &= C2B_M51;
    t[0] += c * 19;                    /* 2^255 = 19 (mod p) */
    c = t[0] >> 51; t[0] &= C2B_M51; t[1] += c;
}

/* schoolbook 5x5 с фолдингом старших limb'ов *19 (donna-c64, входы < 2^54) */
static void c2b_f51_mul(u64 d[5], const u64 a[5], const u64 b[5])
{
    c2b_u128 r0, r1, r2, r3, r4;
    u64 t[5];
    c2b_u128 c;
    r0 = (c2b_u128)a[0] * b[0] + 19 * ((c2b_u128)a[1] * b[4] + (c2b_u128)a[2] * b[3] +
                                       (c2b_u128)a[3] * b[2] + (c2b_u128)a[4] * b[1]);
    r1 = (c2b_u128)a[0] * b[1] + (c2b_u128)a[1] * b[0] +
         19 * ((c2b_u128)a[2] * b[4] + (c2b_u128)a[3] * b[3] + (c2b_u128)a[4] * b[2]);
    r2 = (c2b_u128)a[0] * b[2] + (c2b_u128)a[1] * b[1] + (c2b_u128)a[2] * b[0] +
         19 * ((c2b_u128)a[3] * b[4] + (c2b_u128)a[4] * b[3]);
    r3 = (c2b_u128)a[0] * b[3] + (c2b_u128)a[1] * b[2] + (c2b_u128)a[2] * b[1] +
         (c2b_u128)a[3] * b[0] + 19 * ((c2b_u128)a[4] * b[4]);
    r4 = (c2b_u128)a[0] * b[4] + (c2b_u128)a[1] * b[3] + (c2b_u128)a[2] * b[2] +
         (c2b_u128)a[3] * b[1] + (c2b_u128)a[4] * b[0];
    /* сборка limb'ов: t[k] = hi(r[k-1]) + lo(r[k]); ПОЛНЫЙ коэффициент при
     * 2^255 = hi(r4) + ((hi(r3)+lo(r4)) >> 51) — фолдится *19 в t[0] */
    t[0] = (u64)r0 & C2B_M51;
    t[1] = (u64)(r0 >> 51) + (u64)(r1 & C2B_M51);
    t[2] = (u64)(r1 >> 51) + (u64)(r2 & C2B_M51);
    t[3] = (u64)(r2 >> 51) + (u64)(r3 & C2B_M51);
    t[4] = (u64)(r3 >> 51) + (u64)(r4 & C2B_M51);
    c = (c2b_u128)((t[4] >> 51) + (u64)(r4 >> 51));
    t[4] &= C2B_M51;
    t[0] += (u64)c * 19;
    c = t[0] >> 51; t[0] &= C2B_M51; t[1] += (u64)c;
    c = t[1] >> 51; t[1] &= C2B_M51; t[2] += (u64)c;
    c = t[2] >> 51; t[2] &= C2B_M51; t[3] += (u64)c;
    c = t[3] >> 51; t[3] &= C2B_M51; t[4] += (u64)c;
    c = t[4] >> 51; t[4] &= C2B_M51;
    t[0] += (u64)c * 19;
    c = t[0] >> 51; t[0] &= C2B_M51; t[1] += (u64)c;
    d[0] = t[0]; d[1] = t[1]; d[2] = t[2]; d[3] = t[3]; d[4] = t[4];
}

static void c2b_f51_sqr(u64 d[5], const u64 a[5]) { c2b_f51_mul(d, a, a); }

static void c2b_f51_add(u64 d[5], const u64 a[5], const u64 b[5])
{
    u32 i;
    for (i = 0; i < 5; i++) d[i] = a[i] + b[i];
    c2b_f51_carry(d);
}

/* a - b mod p (без ветвлений по секрету: прибавляем 2p; входы < 2^53) */
static void c2b_f51_sub(u64 d[5], const u64 a[5], const u64 b[5])
{
    static const u64 two_p[5] = {
        0xFFFFFFFFFFFDAULL * 1ULL, 0xFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFEULL,
        0xFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFEULL
    };
    u32 i;
    for (i = 0; i < 5; i++) d[i] = a[i] + two_p[i] - b[i];
    c2b_f51_carry(d);
}

static void c2b_f51_cswap(u32 sw, u64 a[5], u64 b[5])
{
    u64 m = (u64)0 - (u64)(sw & 1u);
    u32 i;
    for (i = 0; i < 5; i++) {
        u64 t = m & (a[i] ^ b[i]);
        a[i] ^= t; b[i] ^= t;
    }
}

/* X25519: out = scalar * u (RFC 7748 ladder, 255 итераций) */
static void c2b_x25519(u8 out[32], const u8 scalar[32], const u8 uin[32])
{
    u8 e[32];
    u64 x1[5], x2[5], z2[5], x3[5], z3[5];
    u64 a[5], aa[5], b[5], bb[5], ee[5], c[5], d[5], da[5], cb[5], t0[5], t1[5];
    static const u64 a24[5] = { 121665, 0, 0, 0, 0 };
    u32 i, pos, swap = 0;
    for (i = 0; i < 32; i++) e[i] = scalar[i];
    e[0] &= 248; e[31] &= 127; e[31] |= 64;
    c2b_f51_load(x1, uin);
    x1[4] &= C2B_M51;                  /* MSB (bit 255) off */
    x2[0] = 1; z2[0] = 0;
    for (i = 1; i < 5; i++) { x2[i] = 0; z2[i] = 0; }
    for (i = 0; i < 5; i++) x3[i] = x1[i];   /* RFC: x_3 = u (!), z_3 = 1 */
    z3[0] = 1;
    for (i = 1; i < 5; i++) z3[i] = 0;
    for (pos = 254; ; pos--) {
        u32 bt = (u32)((e[pos >> 3] >> (pos & 7)) & 1u);
        swap ^= bt;
        c2b_f51_cswap(swap, x2, x3);
        c2b_f51_cswap(swap, z2, z3);
        swap = bt;
        c2b_f51_add(a, x2, z2);        /* A = x2 + z2 */
        c2b_f51_sqr(aa, a);            /* AA = A^2 */
        c2b_f51_sub(b, x2, z2);        /* B = x2 - z2 */
        c2b_f51_sqr(bb, b);            /* BB = B^2 */
        c2b_f51_sub(ee, aa, bb);       /* E = AA - BB */
        c2b_f51_add(c, x3, z3);        /* C = x3 + z3 */
        c2b_f51_sub(d, x3, z3);        /* D = x3 - z3 */
        c2b_f51_mul(da, d, a);         /* DA = D * A */
        c2b_f51_mul(cb, c, b);         /* CB = C * B */
        c2b_f51_add(t0, da, cb);
        c2b_f51_sqr(x3, t0);           /* x3 = (DA + CB)^2 */
        c2b_f51_sub(t1, da, cb);
        c2b_f51_sqr(t1, t1);
        c2b_f51_mul(z3, x1, t1);       /* z3 = x1 * (DA - CB)^2 */
        c2b_f51_mul(x2, aa, bb);       /* x2 = AA * BB */
        c2b_f51_mul(t0, ee, a24);      /* 121665 * E */
        c2b_f51_add(t0, t0, aa);
        c2b_f51_mul(z2, ee, t0);       /* z2 = E * (AA + a24 * E) */
        if (pos == 0) break;
    }
    c2b_f51_cswap(swap, x2, x3);
    c2b_f51_cswap(swap, z2, z3);
    /* out = x2 * z2^(p-2): инверсия square-and-multiply по битам порядка */
    {
        u64 zinv[5], zz[5];
        u32 bit;
        static const u8 pm2[32] = {    /* p-2 = 2^255 - 21, LE */
            0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
        };
        u8 eb[32];
        for (i = 0; i < 32; i++) eb[i] = pm2[i];
        /* инверсия: z^(p-2) square-and-multiply, биты СТАРШИМ-ВПЕРЁД
         * (LSB-first с фиксированной базой считал z^reverse(p-2)!) */
        zinv[0] = 1; for (i = 1; i < 5; i++) zinv[i] = 0;
        for (bit = 254; ; bit--) {
            c2b_f51_sqr(zinv, zinv);
            if ((eb[bit >> 3] >> (bit & 7)) & 1u) {
                c2b_f51_mul(zinv, zinv, z2);
            }
            if (bit == 0) break;
        }
        c2b_f51_mul(zz, x2, zinv);
        /* каноническое приведение: carry пока limb4 не упадёт, затем -p если >= p */
        {
            u64 t[5];
            u32 guard;
            for (i = 0; i < 5; i++) t[i] = zz[i];
            for (guard = 0; guard < 4; guard++) {
                u32 over = 0;
                for (i = 0; i < 5; i++) if (t[i] >> 51) over = 1;
                if (!over) break;
                c2b_f51_carry(t);
            }
            /* t < 2p: вычитаем p, если t >= p (t>=p <=> t0+19 >= 2^51 при t1..4 полных) */
            {
                static const u64 pp[5] = {
                    0x7FFFFFFFFFFEDULL, 0x7FFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFULL,
                    0x7FFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFULL
                };
                i64 borrow = 0;
                u64 res[5];
                for (i = 0; i < 5; i++) {
                    i64 d2 = (i64)t[i] - (i64)pp[i] - borrow;
                    if (d2 < 0) { res[i] = (u64)(d2 + 0x8000000000000LL); borrow = 1; }
                    else { res[i] = (u64)d2; borrow = 0; }
                }
                if (!borrow) for (i = 0; i < 5; i++) t[i] = res[i];
            }
            c2b_f51_store(out, t);
        }
    }
}

/* ---------- 41e-d: формат 'A'-ответа движку — МАТРИЦА ЭКСПЕРИМЕНТОВ ----------
 * Run 45: наш 9Б ответ (41+le32) движок отверг («Invalid challenge packet.»,
 * req=1 — движок перестаёт qconnect-ить после невалидного 'A'). Голый 41
 * тоже невалиден (Valve issue 1436). Движок живёт ОДНУ попытку → формат
 * выбирается env C2B_CLV2_FMT и харнесс гоняет 5 вариантов на 5 попыток:
 *   0: 41 le32(ch32)                       — бинарный (базовый, run 45)
 *   1: 41 "0x%08X" NUL                     — ASCII, симметрично qconnect0x…
 *   2: 41 le32(ch32) le32(17)              — бинарный + int protocol
 *   3: 41 le32(qc_echo) le32(ch32)         — эхо значения из qconnect + challenge
 *   4: 41 "0x%08X" le32(17)                — ASCII + int protocol
 * Успех = движок продолжил: либо снова qconnect с новым значением, либо
 * S1 connect (капчерится CLV2-интерпозером, cn-счётчик). */
static u32 c2b_clv2_build_chalreply(u8 *out, u32 cap, u32 fmt, u32 qc_val, u32 ch32)
{
    u32 n = 0;
    if (cap < 24) return 0;
    out[n++] = 0xff; out[n++] = 0xff; out[n++] = 0xff; out[n++] = 0xff;
    out[n++] = 'A';
    switch (fmt) {
    case 1: {                              /* ASCII "0x%08X" */
        static const char hx[] = "0123456789ABCDEF";
        u32 i;
        out[n++] = '0'; out[n++] = 'x';
        for (i = 0; i < 8; i++) out[n++] = hx[(ch32 >> (28 - 4 * i)) & 15];
        out[n++] = 0;
        break;
    }
    case 2:                                /* le32 challenge + le32 protocol(17) */
        out[n++] = (u8)(ch32); out[n++] = (u8)(ch32 >> 8);
        out[n++] = (u8)(ch32 >> 16); out[n++] = (u8)(ch32 >> 24);
        out[n++] = 17; out[n++] = 0; out[n++] = 0; out[n++] = 0;
        break;
    case 3:                                /* le32 echo(qc) + le32 challenge */
        out[n++] = (u8)(qc_val); out[n++] = (u8)(qc_val >> 8);
        out[n++] = (u8)(qc_val >> 16); out[n++] = (u8)(qc_val >> 24);
        out[n++] = (u8)(ch32); out[n++] = (u8)(ch32 >> 8);
        out[n++] = (u8)(ch32 >> 16); out[n++] = (u8)(ch32 >> 24);
        break;
    case 4: {                              /* ASCII + le32 protocol(17) */
        static const char hx[] = "0123456789ABCDEF";
        u32 i;
        out[n++] = '0'; out[n++] = 'x';
        for (i = 0; i < 8; i++) out[n++] = hx[(ch32 >> (28 - 4 * i)) & 15];
        out[n++] = 0;
        out[n++] = 17; out[n++] = 0; out[n++] = 0; out[n++] = 0;
        break;
    }
    case 5: {                              /* 41e-e: RE-derived, value=32 бита */
        /* Парсер кейса 'A' (0x25a9e8): le32 challenge -> le32 authproto=3
         * (keysize u16=0) -> 32-битное значение (645be0) -> u8 flag ->
         * ReadString -> strstr(str,"reserve") обязателен -> успех =
         * vtable+0x200(this, challenge). Run 48: 64-битный fill дал
         * пустую строку (readString стартовал на нуле) => read = 32 бита. */
        u32 i;
        out[n++] = (u8)(ch32); out[n++] = (u8)(ch32 >> 8);
        out[n++] = (u8)(ch32 >> 16); out[n++] = (u8)(ch32 >> 24);
        out[n++] = 3; out[n++] = 0; out[n++] = 0; out[n++] = 0;   /* authproto=3 */
        out[n++] = 0; out[n++] = 0;                               /* keysize=0 */
        for (i = 0; i < 4; i++) out[n++] = 0;                     /* u32 value */
        out[n++] = 0;                                             /* flag */
        out[n++] = 'r'; out[n++] = 'e'; out[n++] = 's'; out[n++] = 'e';
        out[n++] = 'r'; out[n++] = 'v'; out[n++] = 'e'; out[n++] = 0;
        break;
    }
    case 6: {                              /* вариант с 64-битным значением (A/B) */
        u32 i;
        out[n++] = (u8)(ch32); out[n++] = (u8)(ch32 >> 8);
        out[n++] = (u8)(ch32 >> 16); out[n++] = (u8)(ch32 >> 24);
        out[n++] = 3; out[n++] = 0; out[n++] = 0; out[n++] = 0;
        out[n++] = 0; out[n++] = 0;
        for (i = 0; i < 8; i++) out[n++] = 0;                     /* u64 value */
        out[n++] = 0;                                             /* flag */
        out[n++] = 'r'; out[n++] = 'e'; out[n++] = 's'; out[n++] = 'e';
        out[n++] = 'r'; out[n++] = 'v'; out[n++] = 'e'; out[n++] = 0;
        break;
    }
    case 7: {                              /* 41e-f: поиск смещения строки (C2B_CLV2_K) */
        /* движок читает: chal32 proto32 keysize16 [645be0: N байт] flag8 string.
         * Успех = строка начинается ровно на 'r' => k == N+1. Перебираем k. */
        u32 i;
        out[n++] = (u8)(ch32); out[n++] = (u8)(ch32 >> 8);
        out[n++] = (u8)(ch32 >> 16); out[n++] = (u8)(ch32 >> 24);
        out[n++] = 3; out[n++] = 0; out[n++] = 0; out[n++] = 0;
        out[n++] = 0; out[n++] = 0;
        for (i = 0; i < g_clv2_k; i++) out[n++] = 0;              /* филлер k */
        out[n++] = 'r'; out[n++] = 'e'; out[n++] = 's'; out[n++] = 'e';
        out[n++] = 'r'; out[n++] = 'v'; out[n++] = 'e'; out[n++] = 0;
        break;
    }
    case 9: {                              /* 41e-h: REAL-legacy 'A' (ферма run 65-73!) */
        /* Байт-в-байт структура живого CS:GO-legacy сервера (46.174.52.230 и
         * др., снято 2026-10-06): 'A' + le32(chal) + le32(3) + u16(0) +
         * le32(value=STEAMID-LOW32 ЦЕЛИ!) + u8(0) + 00 30 01 01 +
         * "connect0x<ЭХО qc_val>\0" + "96\0" + нулевой паддинг:
         * ПОЛЕЗНАЯ НАГРУЗКА (после ffffffff-префикса) до 55 байт =
         * 59 на проводе. Run 80 bug: паддинг считали С префиксом
         * (итого 55 = payload 51) — на 4 байта короче фермы v13+.
         * Строка содержит "connect" -> движок идёт в connect-ветку
         * (+0x4c0=1, +0x8dc4="96\0\0"), доходит до LOADING->INGAME и шлёт
         * 'j' (join) — ферма это доказала живьём (run 68/72). */
        static const u8 CS2_SID_LOW[4] = {0x07, 0x0a, 0xee, 0x00}; /* 0x00ee0a07 */
        static const u8 MYSTERY[4] = {0x00, 0x30, 0x01, 0x01};
        u32 i;
        if (cap < 60) return 0;
        out[n++] = (u8)(ch32); out[n++] = (u8)(ch32 >> 8);
        out[n++] = (u8)(ch32 >> 16); out[n++] = (u8)(ch32 >> 24);
        out[n++] = 3; out[n++] = 0; out[n++] = 0; out[n++] = 0;   /* authproto=3 */
        out[n++] = 0; out[n++] = 0;                               /* keysize=0 */
        for (i = 0; i < 4; i++) out[n++] = CS2_SID_LOW[i];        /* value */
        out[n++] = 0;                                             /* flag */
        for (i = 0; i < 4; i++) out[n++] = MYSTERY[i];
        /* строка: "connect0x%08X\0" — ЭХО токена из qconnect движка */
        {
            static const char pfx[] = "connect0x";
            static const char hx[] = "0123456789ABCDEF";
            u32 v = g_clv2_qc_val, j;
            for (j = 0; j < 9; j++) out[n++] = (u8)pfx[j];
            for (j = 0; j < 8; j++) out[n++] = (u8)hx[(v >> (28 - 4 * j)) & 15];
            out[n++] = 0;
        }
        out[n++] = '9'; out[n++] = '6'; out[n++] = 0;  /* "96\0" */
        while (n < 59) out[n++] = 0;   /* payload до 55 (итого 59, байт-в-байт ферма) */
        break;
    }
    case 8: {                              /* 41e-g: N-агностик — хвост = (reserve)*9 NUL */
        /* Любой суффикс повторного "reserve" содержит целое "reserve"
         * (период 7 = длина слова), поэтому ReadString, начавшись с ЛЮБОГО
         * смещения (11+N для любого N), находит strstr("reserve").
         * flag-байт при N≠4 ненулевой -> идёт через гейт 482410
         * (CommandLine: !-insecure !-tools && VAC-флаг = true на раннере)
         * -> тот же string-флоу (25c8dd -> 25ab88). */
        u32 i;
        out[n++] = (u8)(ch32); out[n++] = (u8)(ch32 >> 8);
        out[n++] = (u8)(ch32 >> 16); out[n++] = (u8)(ch32 >> 24);
        out[n++] = 3; out[n++] = 0; out[n++] = 0; out[n++] = 0;   /* authproto=3 */
        out[n++] = 0; out[n++] = 0;                               /* keysize=0 */
        for (i = 0; i < 9 * 7; i++) {                             /* (reserve)*9 */
            static const char w[] = "reserve";
            out[n++] = (u8)w[i % 7];
        }
        out[n++] = 0;
        break;
    }
    default:                               /* 0: le32 challenge (run 45 baseline) */
        out[n++] = (u8)(ch32); out[n++] = (u8)(ch32 >> 8);
        out[n++] = (u8)(ch32 >> 16); out[n++] = (u8)(ch32 >> 24);
        break;
    }
    return n;
}

#define C2B_CL_RTLD_NEXT ((void *)-1L)

/* 41e-m: monotonic ms (CLOCK_MONOTONIC=1) — темп INFO-PUSH */
static u64 c2b_mono_ms(void)
{
#ifdef C2B_SELFTEST
    struct timespec ts;                  /* selftest: <time.h> */
    if (clock_gettime(1, &ts) != 0) return 0;
    return (u64)ts.tv_sec * 1000ull + (u64)ts.tv_nsec / 1000000ull;
#else
    /* .so без time.h: ABI timespec = {i64 sec; i64 nsec} (x86_64) */
    struct { i64 sec; i64 nsec; } ts;
    if (clock_gettime(1, &ts) != 0) return 0;
    return (u64)ts.sec * 1000ull + (u64)ts.nsec / 1000000ull;
#endif
}

/* ================= 41f-g31: протокол 0x22 ConnectRequest ================= */

/* нестрогая запись КАЖДОГО 0x21 (без expect-чека — сервер шлёт парами и по
 * нескольким cid): кольцо (cid, ch, ts, ms) для выбора СВЕЖЕГО challenge.
 * Окно жизни challenge ~4s (SipHash по адресу источника). */
static void c2b_clv2_note_reply(const u8 *p, u32 n)
{
    u32 i = 1, cid = 0;
    u64 ch = 0, ts = 0;
    if (n < 9 || p[0] != 0x21) return;
    while (i < n) {
        u8 tag = p[i++];
        u32 f = (u32)(tag >> 3), wt = tag & 7;
        if (wt == 1) {
            u64 x = 0; i32 k;
            if (i + 8 > n) return;
            for (k = 7; k >= 0; k--) x = (x << 8) | (u64)p[i + k];
            if (f == 2) ch = x;
            if (f == 3) ts = x;
            i += 8;
        } else if (wt == 5) {
            if (i + 4 > n) return;
            if (f == 1)
                cid = (u32)p[i] | ((u32)p[i+1] << 8) |
                      ((u32)p[i+2] << 16) | ((u32)p[i+3] << 24);
            i += 4;
        } else if (wt == 0) {
            while (i < n && p[i] & 0x80) i++;
            i++;
        } else if (wt == 2) {
            u32 ln = 0, sh = 0;
            while (i < n) {
                u8 b = p[i++]; ln |= (u32)(b & 0x7f) << sh;
                if (!(b & 0x80)) break;
                sh += 7;
            }
            i += ln;
        } else {
            return;
        }
    }
    if (!cid || !ch) return;
    {
        struct c2b_clv2_chrec *r = &g_clv2_chrec[g_clv2_chrec_i];
        r->cid = cid; r->ch = ch; r->ts = ts;
        r->ms = c2b_mono_ms(); r->valid = 1;
        g_clv2_chrec_i = (g_clv2_chrec_i + 1) & 3u;
    }
}

/* свежайший challenge (моложе 3500ms); при наличии — наружу (cid, ch, ts) */
static i32 c2b_clv2_pick_fresh(u32 *cid, u64 *ch, u64 *ts)
{
    u32 i;
    u64 now = c2b_mono_ms();
    struct c2b_clv2_chrec *best = 0;
    for (i = 0; i < 4; i++) {
        struct c2b_clv2_chrec *r = &g_clv2_chrec[i];
        if (!r->valid || !r->ch) continue;
        if (now < r->ms || now - r->ms > 3500u) continue;   /* просрочен/часы */
        if (!best || (i64)(r->ms - best->ms) > 0) best = r;
    }
    if (!best) return 0;
    *cid = best->cid; *ch = best->ch; *ts = best->ts;
    return 1;
}

/* g31-вариант 2: keypair x25519 (клэмп по RFC; сид — xorshift от стека).
 * Готовость — ФЛАГ (не pub[0]!=0: первый байт ключа легитимно бывает 0 —
 * урон CI 180, флак 1/256). */
static u32 g_clv2_cr_have;
static void c2b_clv2_cr_keygen(void)
{
    u32 i;
    if (g_clv2_cr_have) return;                  /* уже сгенерён */
    for (i = 0; i < 32; i += 4) {
        u32 r = c2b_clv2_rand32();
        g_clv2_cr_priv[i]     = (u8)r;
        g_clv2_cr_priv[i + 1] = (u8)(r >> 8);
        g_clv2_cr_priv[i + 2] = (u8)(r >> 16);
        g_clv2_cr_priv[i + 3] = (u8)(r >> 24);
    }
    g_clv2_cr_priv[0] &= 248; g_clv2_cr_priv[31] &= 127; g_clv2_cr_priv[31] |= 64;
    {
        u8 base9[32];
        u32 j;
        for (j = 0; j < 32; j++) base9[j] = 0;
        base9[0] = 9;                            /* u-координата базовой точки */
        c2b_x25519(g_clv2_cr_pub, g_clv2_cr_priv, base9);
    }
    g_clv2_cr_have = 1;
}

/* [0x22][u16 pb_len LE][pb][zero-pad] = ровно 512 байт; вариант >= 2 добавляет
 * f7 crypt (SessionCryptInfoSigned без signature: key_info{key_type=1,
 * key_data=наш pub32}). Содержимое pb:
 *   f1 fixed32 cid | f3 fixed64 challenge | f4 fixed64 my_timestamp |
 *   f5 varint 13   | [f7 bytes crypt]     | f8 fixed64 legacy_client_steam_id */
static u32 c2b_clv2_build_connreq(u8 *out, u32 variant, u32 cid, u64 ch, u64 ts)
{
    u8 pb[128];
    u32 n = 0, i;
    if (variant >= 2) c2b_clv2_cr_keygen();
    pb[n++] = 0x0d;                              /* f1 fixed32 connection_id */
    pb[n++] = (u8)cid; pb[n++] = (u8)(cid >> 8);
    pb[n++] = (u8)(cid >> 16); pb[n++] = (u8)(cid >> 24);
    pb[n++] = 0x19;                              /* f3 fixed64 challenge */
    for (i = 0; i < 8; i++) pb[n++] = (u8)(ch >> (8 * i));
    pb[n++] = 0x21;                              /* f4 fixed64 my_timestamp */
    for (i = 0; i < 8; i++) pb[n++] = (u8)(ts >> (8 * i));
    pb[n++] = 0x28; pb[n++] = 0x0d;              /* f5 varint protocol_version=13 */
    if (variant >= 2) {
        /* f7 crypt: SessionCryptInfoSigned{1: key_info{1: 1(CURVE25519),
         * 2: pub32}}; key_info = 08 01 12 20 <32B> = 36B; crypt =
         * 0a 24 <36B> = 38B; f7 = 3a 26 <38B>. Итого 8 + 32 байта. */
        static const u8 hdr[8] = { 0x3a, 38, 0x0a, 36, 0x08, 0x01, 0x12, 32 };
        u32 k;
        for (k = 0; k < 8; k++) pb[n++] = hdr[k];
        for (k = 0; k < 32; k++) pb[n++] = g_clv2_cr_pub[k];
    }
    if (g_clv2_sid64) {
        pb[n++] = 0x41;                          /* f8 fixed64 legacy_client_steam_id */
        for (i = 0; i < 8; i++) pb[n++] = (u8)(g_clv2_sid64 >> (8 * i));
    }
    out[0] = 0x22;                               /* k_ESteamNetworkingUDPMsg_ConnectRequest */
    out[1] = (u8)n; out[2] = (u8)(n >> 8);
    for (i = 0; i < n; i++) out[3 + i] = pb[i];
    for (i = 3 + n; i < 512; i++) out[i] = 0;
    return 512;
}

/* отправить 0x22 (по свежему challenge) на da/dl через fd; 1 = ушло */
static i32 c2b_clv2_send_connreq(int fd, u32 variant, i32 flags,
                                 const void *da, socklen_t dl, const char *why)
{
    u32 cid; u64 ch, ts;
    u8 out[512];
    u64 now = c2b_mono_ms();
    if (!g_clv2_cr) return 0;
    if (now && g_clv2_cr_last_ms && now - g_clv2_cr_last_ms < 250u) return 0;
    if (!c2b_clv2_pick_fresh(&cid, &ch, &ts)) return 0;
    (void)c2b_clv2_build_connreq(out, variant, cid, ch, ts);
    ((c2b_sendto_fn)g_clp_sendto)(fd, out, 512, flags, da, dl);
    g_clv2_cr_last_ms = now;
    g_clv2_cr_sent++;
    C2B_LOGS("[c2b] CLV2 0x22 ConnectRequest->target #");
    C2B_LOGN(g_clv2_cr_sent);
    C2B_LOGS(" v="); C2B_LOGN(variant);
    C2B_LOGS(" cid="); C2B_LOGH(cid);
    C2B_LOGS(" ch="); C2B_LOGH((u32)(ch >> 32)); C2B_LOGH((u32)ch);
    C2B_LOGS(" sid="); C2B_LOGH((u32)(g_clv2_sid64 >> 32)); C2B_LOGH((u32)g_clv2_sid64);
    C2B_LOGS(" why="); C2B_LOGS(why);
    C2B_LOGS("\n");
    return 1;
}

/* legacy_client_steam_id из капчуренного S1 'k': САМАЯ длинная ASCII-цифровая
 * строка >= 8 цифр = account id (sys-id protobuf-поля; run168: "687168219").
 * SteamID64 = 0x0110000100000000 | account. */
static void c2b_clv2_note_sid(const u8 *p, u32 n)
{
    u32 best = 0, bs = 0, i = 0;
    u64 acct = 0;
    if (g_clv2_sid64) return;                    /* уже распарсен/env задан */
    while (i < n) {
        if (p[i] >= '0' && p[i] <= '9') {
            u32 j = i;
            while (j < n && p[j] >= '0' && p[j] <= '9') j++;
            if (j - i > best && j - i >= 8) { best = j - i; bs = i; }
            i = j;
        } else {
            i++;
        }
    }
    if (!best) return;
    for (i = 0; i < best; i++) acct = acct * 10 + (u64)(p[bs + i] - '0');
    g_clv2_sid64 = 0x0110000100000000ULL | (acct & 0xFFFFFFFFULL);
}

/* 41e-m: собрать ферма-формата 'I'-блоб (byte-паритет с fake_s1_server.py
 * sinfo_blob; run 72 CL dn #f4-8: движок ПОТРЕБЛЯЕТ unsolicited 'I'):
 * 'I' prot(0x11) "c2b-bridge\0" "de_dust2\0" "csgo\0"
 * "Counter-Strike: Global Offensive\0" le16(730) 0/24/0 'd' 'l' 0 0
 * <версия бандла>\0 — БЕЗ EDF. Hostname = маркер попадания: ACK в консоли
 * должен напечатать c2b-bridge. */
static u32 c2b_clv2_build_infoblob(u8 *out, u32 cap)
{
    static const char HOST[] = "c2b-bridge";
    static const char MAP[]  = "de_dust2";
    static const char DIR[]  = "csgo";
    static const char GAME[] = "Counter-Strike: Global Offensive";
    u32 n = 0, i;
    if (cap < 128) return 0;
    out[n++] = 0xff; out[n++] = 0xff; out[n++] = 0xff; out[n++] = 0xff;
    out[n++] = 'I';
    out[n++] = 0x11;                                     /* protocol 17 */
    for (i = 0; i < sizeof(HOST); i++) out[n++] = (u8)HOST[i];
    for (i = 0; i < sizeof(MAP); i++)  out[n++] = (u8)MAP[i];
    for (i = 0; i < sizeof(DIR); i++)  out[n++] = (u8)DIR[i];
    for (i = 0; i < sizeof(GAME); i++) out[n++] = (u8)GAME[i];
    out[n++] = 0xda; out[n++] = 0x02;                    /* appid 730 */
    out[n++] = 0;    out[n++] = 24;   out[n++] = 0;      /* players/max/bots */
    out[n++] = 'd';  out[n++] = 'l';                     /* dedicated/linux */
    out[n++] = 0;    out[n++] = 0;                       /* public/VAC off */
    for (i = 0; g_a2s_ver[i] != 0; i++) out[n++] = (u8)g_a2s_ver[i];
    out[n++] = 0;                                        /* версия\0 */
    return n;
}

/* ---------- 41e-j: трансформ A2S_INFO 'I'-ответа цели для движка ----------
 * RUN 70/71 lessons фермы (fake_s1_server.py): продолжение connect-потока
 * требует serverinfo БЕЗ EDF-хвоста, с appid u16=730 (appid владельца
 * клиента) и версией БАНДЛА. Реальный CS2-сервер (run 83) шлёт EDF +
 * версию 1.41.8.8 -> движок делает тихий abort на
 * INGAME->MAINMENU без 'j'. Формат парсится как в ферме:
 *   'I' prot(1) name\0 map\0 folder\0 game\0 appid(2) players max bots
 *   type env vis vac [первая NUL-строка после vac = версия] [EDF — СРЕЗАЕМ]
 * Возвращаем новую длину; 0 = отдать как есть. */
static u32 c2b_a2s_transform_i(const u8 *in, u32 n, u8 *out, u32 cap)
{
    u32 i, j, apid, olen;
    if (n < 40 || n > 1400 || cap < n + 32) return 0;
    if (in[0] != 0xff || in[1] != 0xff || in[2] != 0xff || in[3] != 0xff)
        return 0;
    if (in[4] != 'I') return 0;
    i = 6;                                       /* после ffff(4)+'I'(1)+prot(1) */
    for (j = 0; j < 4; j++) {                    /* name, map, folder, game */
        u32 sl = 0;
        while (i < n && in[i] != 0) {
            i++;
            if (++sl > 256) return 0;            /* строка не кончается */
        }
        if (i >= n) return 0;
        i++;                                     /* NUL */
    }
    if (i + 2 + 7 > n) return 0;
    apid = i;                                    /* здесь appid u16 */
    i += 2 + 7;                                  /* players/max/bots/type/env/vis/vac */
    if (i >= n) return 0;
    {
        u32 vend = i;                            /* первая NUL-строка = версия */
        while (vend < n && in[vend] != 0) {
            vend++;
            if (vend - i > 32) return 0;
        }
        if (vend >= n) return 0;
    }
    olen = 0;
    out[olen++] = 0xff; out[olen++] = 0xff; out[olen++] = 0xff; out[olen++] = 0xff;
    for (i = 4; i < apid; i++) out[olen++] = in[i];      /* 'I'+prot+4 строки */
    out[olen++] = 0xda; out[olen++] = 0x02;              /* appid = 730 */
    for (i = apid + 2; i < apid + 2 + 7; i++) out[olen++] = in[i]; /* 7 байт */
    for (i = 0; g_a2s_ver[i] != 0; i++) out[olen++] = (u8)g_a2s_ver[i];
    out[olen++] = 0;                                     /* версия\0, EDF нет */
    return olen;
}


/* ленивый резолв реальных функций: адреса живут выше (g31-секция). */

/* 41f-g15: LIVE recv-loop consumer finder. Run126: g13 доказал, что
 * диспетчер 0x259df0 (engine 34a96ae) НЕ участвует в живом пути потребления
 * 'A'/'B' (армился в активной фазе — ноль срабатываний), а pcap показал,
 * что весь UDP-поток движок<->цель медиится shim'ом (в wire НОЛЬ пакетов от
 * движка напрямую). Значит живой потребитель connectionless-пакетов —
 * ДРУГАЯ функция (возможно в другом модуле lite-бандла). Вместо слепого RE:
 * shim-хук recvfrom/sendto видит ТОЧНЫЙ call-site живого потребителя —
 * __builtin_return_address(0) вызывающего. Логируем новые уникальные адреса
 * с атрибуцией модуль/RVA (dl_iterate_phdr, PT_LOAD containment), частотные
 * hot-метки (100/10000) показывают, какой из сайтов — net-цикл. Дизасм
 * вокруг RVA -> где type-switch 'A'/'B' -> g16 дамп уже на живом потребителе.
 * Гонки таблицы между потоками безвредны (стиль g_clp_* кэшей).
 * Собственные минимальные копии dl_phdr_info/Elf64_Phdr (glibc ABI стабилен:
 * addr@0, name@8, phdr@16, phnum@24; Phdr: type@0,flags@4,vaddr@0x10,
 * memsz@0x28) — g13-структуры живут внутри #ifndef C2B_SELFTEST. */
struct c2b_g15_phdr_min { uptr addr; const char *name; const void *phdr; u16 phnum; };
struct c2b_g15_phdr64 { u32 type; u32 flags; u64 off, vaddr, paddr, filesz, memsz, align; };
/* extern-декларация в selftest-ветке отсутствует (строка ~69 вне её) —
 * повторяем идентичную (легальна в C) */
extern i32 dl_iterate_phdr(i32 (*cb)(void *info, void *size, void *data), void *data);
struct c2b_g15_site { uptr ra; u32 hits; };
static struct c2b_g15_site g_g15_tab[16];
static u32 g_g15_n;
static u32 g_g15_other;

struct c2b_g15_find { uptr a; const char *nm; uptr base; u8 found; };

static i32 c2b_g15_mod_cb(void *info_v, void *size_v, void *data_v)
{
    struct c2b_g15_phdr_min *info = (struct c2b_g15_phdr_min *)info_v;
    struct c2b_g15_find *f = (struct c2b_g15_find *)data_v;
    u16 i;
    (void)size_v;
    if (!info->phdr || !info->phnum) return 0;
    for (i = 0; i < info->phnum; i++) {
        const struct c2b_g15_phdr64 *ph = (const struct c2b_g15_phdr64 *)
            ((const u8 *)info->phdr + (uptr)i * sizeof(*ph));
        if (ph->type != 1) continue;
        if (f->a >= info->addr + (uptr)ph->vaddr &&
            f->a < info->addr + (uptr)ph->vaddr + (uptr)ph->memsz) {
            f->nm = info->name;
            f->base = info->addr;
            f->found = 1;
            return 1;
        }
    }
    return 0;
}

static void c2b_g15_note(uptr ra, const char *tag)
{
    u32 i;
    for (i = 0; i < g_g15_n && i < 16; i++) {
        if (g_g15_tab[i].ra == ra) {
            u32 h = ++g_g15_tab[i].hits;
            if (h == 100 || h == 10000) {
                C2B_LOGS("[c2b] g15 "); C2B_LOGS(tag);
                C2B_LOGS("hot ra="); C2B_LOGH((u32)(ra >> 32));
                C2B_LOGH((u32)ra);
                C2B_LOGS("h="); C2B_LOGN(h); C2B_LOGS("\n");
            }
            return;
        }
    }
    if (g_g15_n < 16) {
        struct c2b_g15_find f;
        const char *nm;
        g_g15_tab[g_g15_n].ra = ra;
        g_g15_tab[g_g15_n].hits = 1;
        g_g15_n++;
        f.a = ra; f.nm = 0; f.base = 0; f.found = 0;
        dl_iterate_phdr(c2b_g15_mod_cb, &f);
        C2B_LOGS("[c2b] g15 "); C2B_LOGS(tag);
        C2B_LOGS("new ra="); C2B_LOGH((u32)(ra >> 32)); C2B_LOGH((u32)ra);
        C2B_LOGS("mod=");
        if (f.found) {
            nm = f.nm;
            if (!nm || !nm[0]) nm = "[main]";
            C2B_LOGS(nm);
            C2B_LOGS(" rva="); C2B_LOGH((u32)(ra - f.base));
        } else {
            C2B_LOGS("? ");
        }
        C2B_LOGS("\n");
        return;
    }
    /* таблица полна: вытесняем слот с минимумом hits (init-сайты уходят,
     * hot net-loop остаётся); после 24 вытеснений — только счётчик,
     * чтобы неловой зоопарк одноразовых сайтов не спамил лог */
    if (g_g15_other < 24) {
        u32 mi = 0;
        for (i = 1; i < 16; i++)
            if (g_g15_tab[i].hits < g_g15_tab[mi].hits) mi = i;
        C2B_LOGS("[c2b] g15 "); C2B_LOGS(tag);
        C2B_LOGS("evict ra="); C2B_LOGH((u32)(g_g15_tab[mi].ra >> 32));
        C2B_LOGH((u32)g_g15_tab[mi].ra);
        C2B_LOGS("h="); C2B_LOGN(g_g15_tab[mi].hits);
        C2B_LOGS("-> new ra="); C2B_LOGH((u32)(ra >> 32)); C2B_LOGH((u32)ra);
        C2B_LOGS("\n");
        g_g15_tab[mi].ra = ra;
        g_g15_tab[mi].hits = 1;
    }
    g_g15_other++;
}

/* libc-совместимые сигнатуры; visibility default обязателен: файл собирается
 * с -fvisibility=hidden, а перехват работает только с глобальным символом. */

/* 43f-g40 (run184): ДИАГНОСТИКА СУДЬБЫ ПАКЕТА GNS. Факты: ConnectByIPAddress
 * h!=0 (g37), соединение ЖИВО (AuthStatus OK, ретрансмиты ConnectRequest
 * каждые ~2с через 0x1fcd110 -> sendto@plt 0x1fcd3f4, nChunks==1 путь),
 * НО pcap ЧИСТ (0 датаграмм к цели) — sendto выполняется и МОЛЧА НЕ ИДЁТ
 * на провод. sendto@plt steamclient резолвится в ЭТОТ хук (LD_PRELOAD
 * первый в глобальном скоупе), значит каждое отправление проходит здесь:
 * логируем fd/len/dst/ret/errno всех "интересных" отправок (len>=400 —
 * 512Б ConnectRequest'ы GNS — или dst = цель C2B_GNS_CONNECT). Решение
 * принимаем по ret/errno: -1+EPERM/EPERM/EBADF/EAFNOSUPPORT = ядро
 * отвергло; ret==len = ушло (тогда вопрос к pcap); хук не увидел =
 * raw-syscall путь. */
static u32 g_g40_n;
static void c2b_g40_sdt_note(i32 fd, u32 len, const void *addr, ssize_t r)
{
#ifndef C2B_SELFTEST
    const u8 *p = (const u8 *)addr;
    const struct sockaddr *sa = (const struct sockaddr *)addr;
    u32 ip0 = 0;
    i32 e;
    if (!g_gns_connect_go) return;
    g_g40_n++;
    if (g_g40_n > 48 && (g_g40_n & 0x1F) != 1) return;
    if (p && len >= 8) {
        ip0 = ((u32)p[4] << 24) | ((u32)p[5] << 16) | ((u32)p[6] << 8) | (u32)p[7];
    }
    /* фильтр: длинные пакеты (GNS 512Б) ИЛИ отправки на цель env */
    if (len < 400) {
        u32 tip;
        if (!p || sa->sa_family != 2 || g_gns_dstlen < 8) return;
        tip = ((u32)g_gns_dst[4] << 24) | ((u32)g_gns_dst[5] << 16) |
              ((u32)g_gns_dst[6] << 8) | (u32)g_gns_dst[7];
        if (ip0 != tip) return;
    }
    e = *__errno_location();
    C2B_LOGS("[c2b] g40 sdt: fd="); C2B_LOGN((u32)fd);
    C2B_LOGS(" len="); C2B_LOGN(len);
    C2B_LOGS(" dst=");
    if (p && sa->sa_family == 2) {
        C2B_LOGN((u32)p[4]); C2B_LOGS("."); C2B_LOGN((u32)p[5]); C2B_LOGS(".");
        C2B_LOGN((u32)p[6]); C2B_LOGS("."); C2B_LOGN((u32)p[7]);
        C2B_LOGS(":"); C2B_LOGN(((u32)p[2] << 8) | (u32)p[3]);
    } else {
        C2B_LOGH(ip0);
    }
    C2B_LOGS(" ret="); C2B_LOGN((u32)(i64)r);
    C2B_LOGS(" errno="); C2B_LOGN((u32)e);
    C2B_LOGS("\n");
#else
    (void)fd; (void)len; (void)addr; (void)r;
#endif
}

__attribute__((visibility("default")))
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *addr, socklen_t addrlen)
{
    c2b_g15_note((uptr)__builtin_return_address(0), "s");
    if (!g_clp_sendto) {
        void *f = dlsym(C2B_CL_RTLD_NEXT, "sendto");
        if (!f) f = (void *)1;
        g_clp_sendto = f;
    }
    if ((uptr)g_clp_sendto == 1) {          /* passthrough невозможен — как libc */
        *__errno_location() = 2;            /* ENOENT */
        return -1;
    }
    if (addr && (addr->sa_family == C2B_AF_INET || addr->sa_family == C2B_AF_INET6)) {
        g_cl_s_total++;
        const u8 *p = (const u8 *)buf;
        if (c2b_cl_is_connless(p, (u32)len)) {
            g_cl_s_cl++;
            i32 cls = c2b_cl_class_up(p, (u32)len);
            /* 41e-j: A2S_INFO 'T'-запрос движка — запоминаем peer, чтобы
             * трансформить 'I'-ответ с него (сам 'T' идёт на сервер без
             * изменений: челлендж-танец движок отрабатывает с реальным
             * сервером, меняем только финальный 'I'). */
            if (g_clv2_enable && (u32)len > 6 && p[4] == 'T') {
                if (addr && addrlen && addrlen <= 16) {
                    u8 *d = (u8 *)&g_a2s_peer[0];
                    u32 i2;
                    const u8 *s2 = (const u8 *)addr;
                    for (i2 = 0; i2 < (u32)addrlen; i2++) d[i2] = s2[i2];
                    g_a2s_peerlen = addrlen;
                    if (!g_a2s_seen_t) {
                        g_a2s_seen_t = 1;
                        C2B_LOGS("[c2b] A2S 'T' query seen -> will transform 'I' replies (ver=");
                        C2B_LOGS(g_a2s_ver);
                        C2B_LOGS(")\n");
                    }
                }
            }
            if (g_clv2_enable && cls == C2B_CLQ_QCONNECT) {
                /* CLV2 phase A: qconnect -> S2 ChallengeRequest (тот же fd:
                 * challenge привязан к источнику и живёт ~4s).
                 * Хвост "qconnect0x%08X" — текущее значение challenge движка
                 * (эхо-кандидат для fmt3); парсим hex после "qconnect0x". */
                u8 out[512];
                u32 hv = 0;
                u32 k;
                for (k = 12; k + 8 <= (u32)len; k++) {      /* после "qconnect0x" */
                    u8 c = p[k];
                    u32 d;
                    if (c >= '0' && c <= '9') d = (u32)(c - '0');
                    else if (c >= 'a' && c <= 'f') d = (u32)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') d = (u32)(c - 'A' + 10);
                    else break;
                    hv = (hv << 4) | d;
                }
                g_clv2_qc_val = hv;
                g_clv2_phase = 0;               /* новая попытка — фаза с нуля */
                /* 41e-m: arm INFO-PUSH — после доставки 'A' мост начнёт
                 * выталкивать ферма-блоб 'I' в recvfrom движка (run 72:
                 * движок потребляет unsolicited info) */
                if (!g_ipush_len)
                    g_ipush_len = c2b_clv2_build_infoblob(
                        g_ipush_buf, (u32)sizeof(g_ipush_buf));
                g_ipush_left = 10;
                if (addr && addrlen && addrlen <= 16) {
                    u8 *d = (u8 *)&g_clv2_dst;
                    u32 i2;
                    const u8 *s2 = (const u8 *)addr;
                    for (i2 = 0; i2 < (u32)addrlen; i2++) d[i2] = s2[i2];
                    g_clv2_dstlen = addrlen;
                }
                (void)c2b_clv2_build_chalreq(out);
                g_clv2_fd = fd;
                g_clv2_sent_req++;
                C2B_LOGS("[c2b] CLV2 qconnect->S2 ChallengeRequest #");
                C2B_LOGN(g_clv2_sent_req);
                C2B_LOGS(" cid="); C2B_LOGH(g_clv2_conn_id);
                C2B_LOGS(" qc="); C2B_LOGH(g_clv2_qc_val);
                C2B_LOGS(" fmt="); C2B_LOGN(g_clv2_fmt);
                C2B_LOGS("\n");
                ((c2b_sendto_fn)g_clp_sendto)(fd, out, 512, flags, addr, addrlen);
                return (ssize_t)len;               /* движку обычный rc */
            }
            if (g_clv2_enable && cls == C2B_CLQ_JOIN) {
                /* 'j' в ЛЮБОЙ фазе — логируем (ключевое наблюдение: живой
                 * fmt9-'A' должен сам вести движок в LOADING->INGAME и 'j'). */
                C2B_LOGS("[c2b] CLV2 engine 'j' JOIN seen (phase=");
                C2B_LOGN(g_clv2_phase);
                C2B_LOGS(")\n");
            }
            if (g_clv2_enable && g_clv2_baits && cls == C2B_CLQ_JOIN &&
                g_clv2_phase == 3) {
                /* фаза 4 (C2B_CLV2_BAITS=1): движок прислал 'j' (JOIN,
                 * pending reserve set?) -> третий ChallengeRequest; его reply
                 * подменяем на RESERVE-'A' (fmt5-структура: строка "reserve")
                 * -> OnReserveAccepted с pending-резервом должен выпустить
                 * reserve-confirm ('n'). */
                u8 out2[512];
                g_clv2_phase = 4;
                g_clv2_conn_id = (g_clv2_conn_id ^ 0x5eed0002u) | 1u;
                (void)c2b_clv2_build_chalreq(out2);
                C2B_LOGS("[c2b] CLV2 phase4: JOIN seen -> 3rd ChallengeRequest (cid=");
                C2B_LOGH(g_clv2_conn_id);
                C2B_LOGS(")\n");
                ((c2b_sendto_fn)g_clp_sendto)(g_clv2_fd, out2, 512, flags,
                                              addr, addrlen);
                return (ssize_t)len;
            }
            if (g_clv2_enable && cls == C2B_CLQ_CONNECT) {
                /* CLV2 phase A: S1 connect капчерим и ДРОПАЕМ (без перевода
                 * его нельзя слать в CS2; фаза B построит ConnectRequest).
                 * g30 (run168 PROBE): 'k' ТЕПЕРЬ ДОХОДИТ СЮДА ЦЕЛЫМ (g28+g29
                 * сломали адхок-дроп движка — 10 капчурей/attempt, 0x201
                 * байт, chal+имя+прото). РЕШАЮЩИЙ ЭКСПЕРИМЕНТ:
                 * C2B_CLV2_FWDK=1 — форвард СЫРОГО S1 'k' в РЕАЛЬНУЮ ЦЕЛЬ
                 * (g_clv2_dst из qconnect; fd = движковый — порт-источник
                 * всего потока). Ответ цели ('B'/reject/тишина) = данные
                 * для фазы B. Дампим и dst движка (identity-конверсия!). */
                char ln[C2B_CL_DUMP_MAX * 3 + C2B_CL_DUMP_MAX + 8];
                c2b_cl_hexline(p, (u32)len, ln, (u32)sizeof(ln));
                g_clv2_cap_connect++;
                C2B_LOGS("[c2b] CLV2 S1 connect captured #");
                C2B_LOGN(g_clv2_cap_connect);
                C2B_LOGS(" len="); C2B_LOGN((u32)len);
                if (addr && addrlen && addrlen <= 16) {
                    const u8 *ad = (const u8 *)addr;
                    u32 k2;
                    C2B_LOGS(" dst=");
                    for (k2 = 0; k2 < (u32)addrlen; k2++) C2B_LOGH(ad[k2]);
                }
                C2B_LOGS(" | "); C2B_LOGS(ln); C2B_LOGS("\n");
                if (g_clv2_fwdk) {
                    /* run169 (fbe6689): fwdk=1 ON, 10 captures, dst= ПРАВИЛЬНЫЙ
                     * (AF_INET 28022 152.233.19.133!), но fwd НЕ стрелял —
                     * g_clv2_dstlen=0: qconnect'овский addr >16Б скипнулся.
                     * ФИКС: приоритет — САМ addr капчура (engine's own sendto
                     * dst = цель по построению), g_clv2_dst как fallback. */
                    const void *da = 0;
                    u32 dl = 0;
                    if (addr && addrlen && addrlen <= 28) {
                        da = addr; dl = (u32)addrlen;
                    } else if (g_clv2_dstlen >= 6) {
                        da = (const void *)g_clv2_dst; dl = g_clv2_dstlen;
                    }
                    if (da && dl) {
                        ((c2b_sendto_fn)g_clp_sendto)(fd, p, (u32)len, flags,
                                                      da, dl);
                        g_clv2_fwd_k++;
                        C2B_LOGS("[c2b] CLV2 'k'->target fwd #");
                        C2B_LOGN(g_clv2_fwd_k);
                        C2B_LOGS(" len=");
                        C2B_LOGN((u32)len);
                        C2B_LOGS("\n");
                    }
                }
                if (g_clv2_cr) {
                    /* g31: перевод — S2 0x22 ConnectRequest из капчуренного 'k'.
                     * steamid = самая длинная цифра-строка 'k' (sys-id). Затем:
                     * свежий challenge (<=3.5s) есть -> 0x22 СРАЗУ (тот же fd,
                     * addr капчура = цель); нет -> 0x20 сейчас + pending (0x22
                     * уйдёт по reply в recvfrom-хуке). */
                    c2b_clv2_note_sid(p, (u32)len);
                    {
                        const void *da2 = 0;
                        socklen_t dl2 = 0;
                        if (addr && addrlen && addrlen <= 28) {
                            da2 = addr; dl2 = (socklen_t)addrlen;
                        } else if (g_clv2_dstlen >= 6) {
                            da2 = (const void *)g_clv2_dst; dl2 = g_clv2_dstlen;
                        }
                        if (da2 && dl2) {
                            if (!c2b_clv2_send_connreq(fd, g_clv2_cr, flags,
                                                       da2, dl2, "k-capture")) {
                                u8 out2[512];
                                u32 cid2 = (c2b_clv2_rand32() | 1u);
                                g_clv2_conn_id = cid2;
                                (void)c2b_clv2_build_chalreq(out2);
                                ((c2b_sendto_fn)g_clp_sendto)(fd, out2, 512,
                                                              flags, da2, dl2);
                                g_clv2_cr_pending = 1;
                                C2B_LOGS("[c2b] CLV2 0x22 arm: no fresh ch -> 0x20 sent (cid=");
                                C2B_LOGH(cid2);
                                C2B_LOGS(", 0x22 on reply)\n");
                            }
                        }
                    }
                }
                return (ssize_t)len;               /* дроп без отправки */
            }
            i32 act = c2b_cl_filter_uplink(p, (u32)len);
            c2b_cl_trace(1, p, (u32)len, act);
            if (act == C2B_CL_DROP) return (ssize_t)len;   /* v2: дроп без отправки */
        }
    }
    /* 43f-g40: diag всех passthrough-отправок (см. комментарий выше) */
    {
        ssize_t r = ((c2b_sendto_fn)g_clp_sendto)(fd, buf, len, flags, addr, addrlen);
        c2b_g40_sdt_note(fd, (u32)len, addr, r);
        return r;
    }
}

/* 43f-g40: sendmsg-хук — passthrough + тот же diag (путь nChunks!=1 GNS).
 * msghdr — НАША ABI-копия (совместима с glibc x86-64); dest из msg_name. */
static void *g_clp_sendmsg;
__attribute__((visibility("default")))
ssize_t sendmsg(int fd, const struct c2b_msghdr *msg, int flags)
{
    if (!g_clp_sendmsg) {
        void *f = dlsym(C2B_CL_RTLD_NEXT, "sendmsg");
        if (!f) f = (void *)1;
        g_clp_sendmsg = f;
    }
    if ((uptr)g_clp_sendmsg == 1) {
        *__errno_location() = 2;            /* ENOENT */
        return -1;
    }
    {
        ssize_t r = ((c2b_sendmsg_fn)g_clp_sendmsg)(fd, msg, flags);
        u32 tot = 0;
        if (msg && msg->msg_iov && msg->msg_iovlen && msg->msg_iovlen < 64) {
            u32 k;
            for (k = 0; k < (u32)msg->msg_iovlen; k++)
                tot += (u32)msg->msg_iov[k].iov_len;
        }
        c2b_g40_sdt_note(fd, tot ? tot : 1u, msg ? msg->msg_name : 0, r);
        return r;
    }
}

__attribute__((visibility("default")))
ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *addr, socklen_t *addrlen)
{
    c2b_g15_note((uptr)__builtin_return_address(0), "r");
    if (!g_clp_recvfrom) {
        void *f = dlsym(C2B_CL_RTLD_NEXT, "recvfrom");
        if (!f) f = (void *)1;
        g_clp_recvfrom = f;
    }
    if ((uptr)g_clp_recvfrom == 1) {
        *__errno_location() = 2;            /* ENOENT */
        return -1;
    }
    /* реальный приём ПЕРВЫМ: v1 — чистый наблюдатель, движку всё отдаётся */
    ssize_t r = ((c2b_recvfrom_fn)g_clp_recvfrom)(fd, buf, len, flags, addr, addrlen);
    /* 41e-m: INFO-PUSH — на EAGAIN любого UDP-сокета движка выталкиваем
     * ферма-блоб 'I' (source = цель qconnect). Ферма пушила info во ВСЕ
     * порты движка и движок потреблял (run 72); A2S-запроса движок не
     * делает, клиент UDP на цель не шлёт (run 90 relay q=0) — другой
     * путь доставки info не существует. */
    if (r < 0 && g_clv2_enable && g_ipush_len && g_ipush_left &&
        *__errno_location() == 11 /* EAGAIN */ && buf && addr && addrlen &&
        *addrlen >= g_clv2_dstlen && g_clv2_dstlen &&
        (addr->sa_family == C2B_AF_INET || addr->sa_family == C2B_AF_INET6)) {
        u64 now_ms = c2b_mono_ms();
        if (g_clv2_phase >= 1 && now_ms - g_ipush_last_ms >= 2000) {
            u32 i4;
            u8 *q = (u8 *)buf;
            u8 *d = (u8 *)addr;
            const u8 *s2 = (const u8 *)&g_clv2_dst[0];
            /* 41e-o: ЧЕРЕДОВАНИЕ A/I — ферма пушит 'A' МНОГОКРАТНО (run 72:
             * CL dn #1-7 = 7 'A' ответов в одной попытке, каждые 2-10с),
             * движок потребляет каждый и заново проходит connect-ветку;
             * мост до сих пор отдавал 'A' один раз. Чётный ход = 'I'-блоб,
             * нечётный = свежий fmt9-'A' с ТЕМ ЖЕ ch32/qc_val. */
            u8 *blob = g_ipush_buf;
            u32 blen = g_ipush_len;
            if ((g_ipush_left & 1u) == 0u) {           /* нечётный ход: 'A' */
                blen = c2b_clv2_build_chalreply(g_ipush_abuf,
                                                (u32)sizeof(g_ipush_abuf),
                                                g_clv2_fmt, g_clv2_qc_val,
                                                g_clv2_ch32);
                if (!blen) blen = g_ipush_len;         /* буфер мал — info */
                else blob = g_ipush_abuf;
            }
            for (i4 = 0; i4 < blen; i4++) q[i4] = blob[i4];
            for (i4 = 0; i4 < g_clv2_dstlen; i4++) d[i4] = s2[i4];
            *addrlen = g_clv2_dstlen;
            g_ipush_last_ms = now_ms;
            g_ipush_left--;
            if (blob == g_ipush_abuf) g_clv2_last_A_len = blen; /* 41f-d */
            C2B_LOGS("[c2b] ");
            C2B_LOGS(blob == g_ipush_abuf ? "A pushed to engine (left=" :
                                            "INFO pushed to engine (left=");
            C2B_LOGN(g_ipush_left);
            C2B_LOGS(" len="); C2B_LOGN(blen);
            if (blob != g_ipush_abuf) { C2B_LOGS(" ver="); C2B_LOGS(g_a2s_ver); }
            C2B_LOGS("\n");
            return (ssize_t)blen;
        }
    }
    if (r > 0 && addr &&
        (addr->sa_family == C2B_AF_INET || addr->sa_family == C2B_AF_INET6)) {
        g_cl_r_total++;
        const u8 *p = (const u8 *)buf;
        /* 41f-g31: фиксация ВСЕХ 0x21 (кольцо для СВЕЖЕГО challenge) +
         * pending-триггер (reply на наш 0x20 с 'k'-капчера -> 0x22 немедленно)
         * + ВЕРДИКТ-лог 0x23..0x26 (0x23 ConnectOK = джекпот; 0x24 Closed =
         * причина = точный оставшийся gap; 0x25 NoConnection). */
        if (g_clv2_enable && fd == g_clv2_fd && (u32)r >= 9 && p[0] == 0x21) {
            c2b_clv2_note_reply(p, (u32)r);
            if (g_clv2_cr && g_clv2_cr_pending) {
                g_clv2_cr_pending = 0;
                if (addr && *addrlen && *addrlen <= 28)
                    c2b_clv2_send_connreq(fd, g_clv2_cr, 0, addr,
                                          *addrlen, "pending");
            }
        }
        if (g_clv2_enable && fd == g_clv2_fd && (u32)r >= 1 &&
            p[0] >= 0x23 && p[0] <= 0x26) {
            char ln[C2B_CL_DUMP_MAX * 3 + C2B_CL_DUMP_MAX + 8];
            u32 dl2 = (u32)r;
            if (dl2 > 96) dl2 = 96;
            c2b_cl_hexline(p, dl2, ln, (u32)sizeof(ln));
            C2B_LOGS("[c2b] CLV2 S2 verdict 0x");
            C2B_LOGH((u32)p[0]);
            C2B_LOGS(p[0] == 0x23 ? " (ConnectOK!!) " :
                     p[0] == 0x24 ? " (ConnectionClosed) " :
                     p[0] == 0x25 ? " (NoConnection) " : " ");
            C2B_LOGN((u32)r);
            C2B_LOGS(" | "); C2B_LOGS(ln); C2B_LOGS("\n");
        }
        if (g_clv2_enable && fd == g_clv2_fd && (u32)r >= 9 && p[0] == 0x21) {
            /* CLV2 phase A: S2 ChallengeReply -> движку S1 'A'+challenge32 */
            u64 ch = 0, ch_ts = 0;
            (void)ch_ts;
            if (c2b_clv2_parse_chalreply(p, (u32)r, g_clv2_conn_id, &ch, &ch_ts)) {
                u8 *q = (u8 *)buf;
                u32 rl;
                g_clv2_ch64 = ch;
                g_clv2_ch32 = (u32)ch;
                g_clv2_got_ch++;
                if (g_clv2_phase == 6) {
                    /* фаза 6: четвёртый ChallengeReply -> 'B'+'.+8hex (accept).
                     * RE 'b'-хендлера (0x25a8b0, engine_client 34a96ae): после
                     * header-проверок движок bit-читает байт — обязан быть '.'
                     * (0x2e) — затем 8 байт, парсит sscanf("%08X") и требует
                     * НЕНУЛЕВОЙ результат, при успехе зовёт vtable+0x170(this,
                     * packet). Варианты хвоста (C2B_CLV2_BHEX): 0="AAAAAAAA"
                     * (ран 80-93), 1=hex challenge из 'A', 2=hex qc_val
                     * (эхо qconnect0x). Дифференцирует реакцию движка. */
                    if ((u32)len >= 14) {
                        u32 hx;
                        q[0] = 0xff; q[1] = 0xff; q[2] = 0xff; q[3] = 0xff;
                        q[4] = 'B'; q[5] = '.';
                        hx = (g_clv2_bhex == 1) ? g_clv2_ch32 :
                                             ((g_clv2_bhex == 2) ? g_clv2_qc_val : 0xAAAAAAAAu);
                        if (!hx) hx = 0xAAAAAAAAu;      /* sscanf требует nonzero */
                        {
                            static const char hxk[] = "0123456789ABCDEF";
                            u32 sh;
                            for (sh = 0; sh < 8; sh++)
                                q[6 + sh] = (u8)hxk[(hx >> (28 - sh * 4)) & 0xF];
                        }
                        C2B_LOGS("[c2b] CLV2 phase6: ChallengeReply -> 'B' accept hex=");
                        C2B_LOGN(hx);
                        /* 41f-d: паддим 'B' нулями до длины последнего 'A',
                         * чтобы метаданные размера в netpacket-заголовке
                         * совпали со снапшотом (эхо-чеки u64@0x0c/u32@0x14). */
                        {
                            u32 pl = g_clv2_last_A_len;
                            u32 i6;
                            if (pl < 14) pl = 14;
                            if (pl > (u32)len) pl = (u32)len;
                            for (i6 = 14; i6 < pl; i6++) q[i6] = 0;
                            C2B_LOGS(" pad="); C2B_LOGN(pl);
                            C2B_LOGS(" lastA="); C2B_LOGN(g_clv2_last_A_len);
                            return (ssize_t)pl;
                        }
                    }
                    return r;
                }
                if (g_clv2_phase == 4) {
                    /* фаза 4: третий ChallengeReply -> RESERVE-'A' (fmt5):
                     * 'A' + chal + proto3 + ks0 + value(steamid-low) + flag0 +
                     * "reserve\0" — строка содержит "reserve" ->
                     * OnReserveAccepted; с pending-резервом (после 'j')
                     * должен выйти reserve-confirm. */
                    if ((u32)len >= 32) {
                        u32 i3;
                        u8 mys[4] = {0x07, 0x0a, 0xee, 0x00}; /* steamid-low */
                        q[0] = 0xff; q[1] = 0xff; q[2] = 0xff; q[3] = 0xff;
                        q[4] = 'A';
                        q[5] = (u8)(g_clv2_ch32); q[6] = (u8)(g_clv2_ch32 >> 8);
                        q[7] = (u8)(g_clv2_ch32 >> 16); q[8] = (u8)(g_clv2_ch32 >> 24);
                        q[9] = 3; q[10] = 0; q[11] = 0; q[12] = 0;   /* proto=3 */
                        q[13] = 0; q[14] = 0;                        /* keysize=0 */
                        for (i3 = 0; i3 < 4; i3++) q[15 + i3] = mys[i3];
                        q[19] = 0;                                    /* flag */
                        /* строка "reserve\0" с 20-го байта */
                        q[20] = 'r'; q[21] = 'e'; q[22] = 's'; q[23] = 'e';
                        q[24] = 'r'; q[25] = 'v'; q[26] = 'e'; q[27] = 0;
                        for (i3 = 28; i3 < 40; i3++) q[i3] = 0;
                        g_clv2_last_A_len = 40;      /* 41f-d: 'B' паддим до этого */
                        g_clv2_phase = 5;
                        C2B_LOGS("[c2b] CLV2 phase4: ChallengeReply -> RESERVE-'A' (OnReserveAccepted bait)\n");
                        return 40;
                    }
                    return r;
                }
                if (g_clv2_phase == 2) {
                    /* фаза 2: второй ChallengeReply подменяем на 'i'-промпт
                     * (ферма run 65: 'i'+8A -> движок отвечает 'j'+token 3/3) */
                    if ((u32)len >= 13) {
                        q[0] = 0xff; q[1] = 0xff; q[2] = 0xff; q[3] = 0xff;
                        q[4] = 'i';
                        q[5] = 'A'; q[6] = 'A'; q[7] = 'A'; q[8] = 'A';
                        q[9] = 'A'; q[10] = 'A'; q[11] = 'A'; q[12] = 'A';
                        g_clv2_phase = 3;
                        C2B_LOGS("[c2b] CLV2 phase2: ChallengeReply -> 'i' prompt (join bait)\n");
                        return 13;
                    }
                    return r;
                }
                g_clv2_phase = 1;
                /* fmt7: k задаётся env (по попытке) — счётчики не живут
                 * между попытками (каждая = новый процесс движка). */
                rl = c2b_clv2_build_chalreply(q, (u32)len, g_clv2_fmt,
                                              g_clv2_qc_val, g_clv2_ch32);
                if (!rl) return r;                 /* не хватило буфера — отдаём как есть */
                g_clv2_last_A_len = rl;            /* 41f-d: трек длины для 'B'-пада */
                C2B_LOGS("[c2b] CLV2 S2 ChallengeReply #");
                C2B_LOGN(g_clv2_got_ch);
                C2B_LOGS(" ch64="); C2B_LOGH((u32)(ch >> 32)); C2B_LOGH((u32)ch);
                C2B_LOGS("-> engine 'A' fmt="); C2B_LOGN(g_clv2_fmt);
                C2B_LOGS(" k="); C2B_LOGN(g_clv2_k);
                C2B_LOGS(" len="); C2B_LOGN(rl);
                C2B_LOGS("\n");
                return (ssize_t)rl;
            }
            g_clv2_badreply++;
        }
        if (c2b_cl_is_connless(p, (u32)r)) {
            g_cl_r_cl++;
            /* 41e-j: 'I'-ответ от A2S-peer (цели connect) — трансформ под
             * бандл (no-EDF, appid=730, версия бандла), run 70/71 lessons */
            if (g_clv2_enable && g_a2s_seen_t && addr && (u32)r > 10 &&
                p[4] == 'I' && (u32)*addrlen == (u32)g_a2s_peerlen &&
                memcmp(addr, g_a2s_peer, g_a2s_peerlen) == 0) {
                u8 tmp[1200];
                u32 nl = c2b_a2s_transform_i(p, (u32)r, tmp,
                                             (u32)sizeof(tmp));
                if (nl && (u32)len >= nl) {
                    u32 ti;
                    u8 *q = (u8 *)buf;
                    for (ti = 0; ti < nl; ti++) q[ti] = tmp[ti];
                    C2B_LOGS("[c2b] A2S 'I' transformed: no-EDF appid=730 ver=");
                    C2B_LOGS(g_a2s_ver);
                    C2B_LOGS(" ("); C2B_LOGN((u32)r); C2B_LOGS("->");
                    C2B_LOGN(nl); C2B_LOGS("B)\n");
                    r = (ssize_t)nl;
                    p = (const u8 *)buf;
                }
            }
            i32 act = c2b_cl_filter_downlink(p, (u32)r);
            c2b_cl_trace(0, p, (u32)r, act);
            if (act == C2B_CL_DROP) return 0;   /* v2: движку нулевая датаграмма */
        }
    }
    return r;
}

/* ---------- t42v2→t42v3: интерпозиция выдачи GC-интерфейса ----------
 * t42v3 FIX: v2 отравлял кэш сентинелом (void*)1 при неудаче dlsym(RTLD_NEXT)
 * — ранний вызов движка до подмапления провайдера -> вызов адреса 0x1 ->
 * SIGSEGV на старте (dmesg 2026-09-29: segfault at 1 ip ...0001). Теперь:
 * кэш = только успех; ретрай на каждом вызове; фолбэк dlopen sonames;
 * полный фиаско -> NULL + GC-STALL в лог (движок живёт no-API веткой). */
extern void *dlopen(const char *, i32);
#define C2B_RTLD_NOW    2
#define C2B_RTLD_GLOBAL 0x100
/* RE-факт: client_client.so импортирует SteamInternal_CreateInterface
 * (шапка GC-секции). LD_PRELOAD: наш символ биндится раньше steam_api,
 * реальный резолвим через RTLD_NEXT (t42v3: кэш = только успех, ретрай).
 * Версийная строка GC — STEAMGAMECOORDINATOR_
 * INTERFACE_VERSION*: на выдаче клиенту захватываем объект и сразу ARM.
 * Все остальные интерфейсы — чистый passthrough. */
static void *g_clp_ciface;
static void *g_clp_fouif;

/* t42v7d: fwd — определения ниже по файлу */
static i32  c2b_sthas(const char *h, const char *nd);
static void *g_iclient_obj;

__attribute__((visibility("default")))
void *SteamInternal_CreateInterface(const char *ver)
{
    /* t42v4: диагностика — лог первых 24 верси-строк (клиент анти-тампер:
     * строки расшифровываются в рантайме, grep по бинарям пуст) */
    static u32 vlog_n = 24;
    if (vlog_n && ver) {
        vlog_n--;
        C2B_LOGS("[c2b] CIv "); C2B_LOGS(ver); C2B_LOGS("\n");
    }
    if (!g_clp_ciface) {
        g_clp_ciface = dlsym(C2B_CL_RTLD_NEXT, "SteamInternal_CreateInterface");
        if (!g_clp_ciface) {
            static const char *const cands[] = {
                "steam_api.so", "libsteam_api.so", "steam_api64.so" };
            for (u32 i = 0; i < 3 && !g_clp_ciface; i++) {
                void *h = dlopen(cands[i], C2B_RTLD_NOW | C2B_RTLD_GLOBAL);
                if (h) g_clp_ciface =
                    dlsym(C2B_CL_RTLD_NEXT, "SteamInternal_CreateInterface");
            }
        }
    }
    if (!g_clp_ciface) {
        static u8 stall_once;
        if (!stall_once) {
            stall_once = 1;
            C2B_LOGS("[c2b] GC-STALL CreateInterface ver=");
            C2B_LOGS(ver ? ver : "(null)");
            C2B_LOGS("\n");
        }
        return 0;
    }
    void *r = ((void *(*)(const char *))g_clp_ciface)(ver);
    {
        /* t42v7e: локальный префикс-чек (не тянет c2b_sthas из .so-only) */
        static const char scPfx[] = "SteamClient";
        u8 isSC = 0;
        if (ver) {
            u32 j = 0;
            while (scPfx[j] && ver[j] == scPfx[j]) j++;
            isSC = (scPfx[j] == 0);
        }
        if (isSC && g_iclient_obj != r) {
            g_iclient_obj = r;
            C2B_LOGS("[c2b] IClient obj "); C2B_LOGS(ver ? ver : "?");
            C2B_LOGH((u32)(uptr)r); C2B_LOGS("\n");
        }
    }
    if (ver && c2b_gc_is_gcver(ver)) {
        C2B_LOGS("[c2b] GC req CreateInterface rv="); C2B_LOGH((u32)(uptr)r);
        C2B_LOGS("\n");
        c2b_gc_arm(r);
    }
    return r;
}

__attribute__((visibility("default")))
void *SteamInternal_FindOrCreateUserInterface(int user, const char *ver)
{
    (void)user;
    /* t42v7e: дедуп версий — не глотать поздние вызовы (GC приходит позже
     * повторов контекста); 64 уникальных строк достаточно */
    {
        static char seen[64][48];
        static u32  seen_n;
        static u8   seen_full;
        if (ver) {
            u8 dup = 0;
            for (u32 k = 0; k < seen_n && !dup; k++) {
                u32 m = 0;
                while (seen[k][m] && seen[k][m] == ver[m]) m++;
                if (seen[k][m] == ver[m]) dup = 1;
            }
            if (!dup && (!seen_full || seen_n < 64)) {
                u32 idx = seen_full ? 0 : (seen_n % 64);
                if (!seen_full && seen_n == 64) seen_full = 1;
                u32 l = 0;
                while (ver[l] && l < 47) { seen[idx][l] = ver[l]; l++; }
                seen[idx][l] = 0;
                C2B_LOGS("[c2b] FUv "); C2B_LOGS(ver); C2B_LOGS("\n");
            }
        }
    }
    if (!g_clp_fouif) {
        g_clp_fouif = dlsym(C2B_CL_RTLD_NEXT, "SteamInternal_FindOrCreateUserInterface");
        if (!g_clp_fouif) {
            static const char *const cands[] = {
                "steam_api.so", "libsteam_api.so", "steam_api64.so" };
            for (u32 i = 0; i < 3 && !g_clp_fouif; i++) {
                void *h = dlopen(cands[i], C2B_RTLD_NOW | C2B_RTLD_GLOBAL);
                if (h) g_clp_fouif =
                    dlsym(C2B_CL_RTLD_NEXT, "SteamInternal_FindOrCreateUserInterface");
            }
        }
    }
    if (!g_clp_fouif) {
        static u8 stall_once;
        if (!stall_once) {
            stall_once = 1;
            C2B_LOGS("[c2b] GC-STALL FindOrCreateUser ver=");
            C2B_LOGS(ver ? ver : "(null)");
            C2B_LOGS("\n");
        }
        return 0;
    }
    void *r = ((void *(*)(int, const char *))g_clp_fouif)(user, ver);
    /* 41f-a: капчур ISteamUser* (SteamUser0/22) для auth-воркера */
    if (r && !g_steamuser_seen && c2b_ver_pfx(ver, "SteamUser0")) {
        g_steamuser_obj = r;
        g_steamuser_seen = 1;
        g_steamuser_user = user;
        C2B_LOGS("[c2b] AUTH: SteamUser captured\n");
    }
    /* 41f-g32: капчур ISteamNetworkingSockets* (та же фабрика, что и SteamUser)
     * для драйвера ConnectByIPAddress — трек (A): реальный cert+crypt движка. */
    if (r && !g_steamnetsock_obj && c2b_ver_pfx(ver, "SteamNetworkingSockets")) {
        g_steamnetsock_obj = r;
        C2B_LOGS("[c2b] g32: SteamNetworkingSockets iface captured (ver=");
        C2B_LOGS(ver ? ver : "?");
        C2B_LOGS(")\n");
    }
    /* 41f-f: капчур ISteamNetworkingUtils + спью-callback (vt[1],
     * SEGV-защита как в 41f-c; vt[0] = GetTimestamp — безобиден).
     * В selftest-сборке probe-глобалы не существуют — только капчур. */
    if (r && !g_steamnetutils_seen && c2b_ver_pfx(ver, "SteamNetworkingUtils")) {
        g_steamnetutils_obj = r;
        g_steamnetutils_seen = 1;
        C2B_LOGS("[c2b] GNS: NetworkingUtils captured\n");
#ifndef C2B_SELFTEST
        {
            struct c2b_sigaction sa2, old2;
            u32 k2;
            for (k2 = 0; k2 < sizeof(sa2); k2++) ((u8 *)&sa2)[k2] = 0;
            for (k2 = 0; k2 < sizeof(old2); k2++) ((u8 *)&old2)[k2] = 0;
            sa2.handler = (uptr)c2b_probe_segv;
            sa2.flags = 4;
            sigemptyset(sa2.mask);
            if (sigaction(11, &sa2, &old2) == 0) {
                for (k2 = 0; k2 < 2; k2++) {
                    g_probe_active = 1;
                    if (__sigsetjmp(g_probe_jb, 1) == 0) {
                        ((void (*)(void *, i32, void *))
                            (*(void ***)g_steamnetutils_obj)[k2])(
                            g_steamnetutils_obj, 5, (void *)c2b_gns_spew);
                        g_probe_active = 0;
                        C2B_LOGS("[c2b] GNS: vt["); C2B_LOGN(k2);
                        C2B_LOGS("] called (spew cb installed if setter)\n");
                    } else {
                        g_probe_active = 0;
                        C2B_LOGS("[c2b] GNS: vt["); C2B_LOGN(k2);
                        C2B_LOGS("] segv\n");
                        break;
                    }
                }
                sigaction(11, &old2, (void *)0);
            }
        }
#endif  /* C2B_SELFTEST */
    }
    if (ver && c2b_gc_is_gcver(ver)) {
        C2B_LOGS("[c2b] GC req FindOrCreateUser rv="); C2B_LOGH((u32)(uptr)r);
        C2B_LOGS("\n");
        c2b_gc_arm(r);
    }
    return r;
}

/* ---------- t42v4: генеральный путь выдачи интерфейсов ----------
 * RE-факт: libsteam_api.so экспортирует SteamAPI_ISteamClient_GetISteam
 * GenericInterface (проверено nm 2026-09-30). CGCClient получает GC через
 * ISteamClient::GetISteamGeneric с расшифрованной анти-тампером строкой.
 * Хук: лог версии (первые 24) + ARM на STEAMGAMECOORDINATOR_*. */
__attribute__((visibility("default")))
void *SteamAPI_ISteamClient_GetISteamGenericInterface(void *self, int hUser,
                                                      int hPipe, const char *ver)
{
    (void)self;
    static void *g_clp_gis;
    static u32 vlog_n = 24;
    if (vlog_n && ver) {
        vlog_n--;
        C2B_LOGS("[c2b] GIv "); C2B_LOGS(ver); C2B_LOGS("\n");
    }
    if (!g_clp_gis) {
        g_clp_gis = dlsym(C2B_CL_RTLD_NEXT, "SteamAPI_ISteamClient_GetISteamGenericInterface");
        if (!g_clp_gis) {
            static const char *const cands[] = {
                "steam_api.so", "libsteam_api.so", "steam_api64.so" };
            for (u32 i = 0; i < 3 && !g_clp_gis; i++) {
                void *h = dlopen(cands[i], C2B_RTLD_NOW | C2B_RTLD_GLOBAL);
                if (h) g_clp_gis = dlsym(C2B_CL_RTLD_NEXT,
                    "SteamAPI_ISteamClient_GetISteamGenericInterface");
            }
        }
    }
    if (!g_clp_gis) {
        static u8 stall_once;
        if (!stall_once) {
            stall_once = 1;
            C2B_LOGS("[c2b] GC-STALL GetISteamGeneric ver=");
            C2B_LOGS(ver ? ver : "(null)");
            C2B_LOGS("\n");
        }
        return 0;
    }
    void *r = ((void *(*)(void *, int, int, const char *))g_clp_gis)(
        self, hUser, hPipe, ver);
    if (ver && c2b_gc_is_gcver(ver)) {
        C2B_LOGS("[c2b] GC req GetISteamGeneric rv="); C2B_LOGH((u32)(uptr)r);
        C2B_LOGS("\n");
        c2b_gc_arm(r);
    }
    return r;
}

/* ============================================================ */
#ifndef C2B_SELFTEST
/* ---------- режим .so: поиск движка и установка ---------- */
struct phdr_impl {
#ifdef __x86_64__
    u64         dlpi_addr;     /* Elf64_Addr, load bias */
#else
    u32         dlpi_addr;     /* Elf32_Addr */
#endif
    const char *dlpi_name;
    const void *dlpi_phdr;
    u16         dlpi_phnum;
};

static uptr g_main_base;               /* t42v6: база главного exe */
static u8   g_main_exe_csgo;           /* exe содержит csgo_linux64 */

static u32 c2b_stlen(const char *s) { u32 k = 0; while (s[k]) k++; return k; }
static i32 c2b_sthas(const char *h, const char *nd)
{
    u32 nl = c2b_stlen(nd);
    if (!nl) return 1;
    for (u32 i = 0; h[i]; i++) {
        u32 j = 0;
        while (nd[j] && h[i + j] == nd[j]) j++;
        if (j == nl) return 1;
    }
    return 0;
}

static void c2b_check_exe(void)
{
    if (g_main_exe_csgo) return;
    extern i64 readlink(const char *, char *, u64);
    char buf[512];
    i64 r = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (r <= 0) return;
    buf[r] = 0;
    if (c2b_sthas(buf, "csgo_linux64")) g_main_exe_csgo = 1;
}

static i32 c2b_phdr_cb(void *info_v, void *size_v, void *data_v)
{
    struct phdr_impl *info = (struct phdr_impl *)info_v;
    (void)size_v; (void)data_v;
    if (!info->dlpi_name) return 0;
    g_phdr_seen++;
    /* t42v6: главный exe (имя пустое) — кандидат в «движок» */
    if (!info->dlpi_name[0] && !g_main_base) g_main_base = (uptr)info->dlpi_addr;
    /* t42v5c: дамп первых 16 имён модулей — почему не видим engine? */
    {
        static u32 dbg_n = 16;
        if (dbg_n) {
            dbg_n--;
            C2B_LOGS("[c2b] phdrmod ");
            C2B_LOGS(info->dlpi_name[0] ? info->dlpi_name : "(main)");
            C2B_LOGS("\n");
        }
    }
    /* contains "engine_client" (t39: оба имени файла) */
    const char *n = info->dlpi_name;
    for (u32 i = 0; n[i]; i++) {
        u32 j = 0;
        while (ENGINE_NAME[j] && n[i + j] == ENGINE_NAME[j]) j++;
        if (!ENGINE_NAME[j]) {
            g_engine_base = (uptr)info->dlpi_addr;
            return 1;
        }
    }
    return 0;
}

static i32 c2b_try_install(void)
{
    if (!g_engine_base) {
        g_phdr_seen = 0;
        dl_iterate_phdr(c2b_phdr_cb, 0);
        if (!g_engine_base) {
            /* t42v6: движок монолитный — fallback на главный exe */
            c2b_check_exe();
            if (g_main_exe_csgo && g_main_base) {
                g_engine_base = g_main_base;
                C2B_LOGS("[c2b] engine fallback=main-exe ");
                C2B_LOGH((u32)g_engine_base); C2B_LOGS("\n");
            } else {
                g_scan_miss++;
                if (g_scan_miss == 4) {          /* t39: разовая диагностика иглы */
                    C2B_LOGS("[c2b] phdr: движок не найден за 4 скана, модулей=");
                    C2B_LOGN(g_phdr_seen);
                    C2B_LOGS("\n");
                }
                return -10;
            }
        }
        C2B_LOGS("[c2b] engine base "); C2B_LOGH(g_engine_base); C2B_LOGS("\n");
    }
#ifdef __x86_64__
    if (!g2e_bytesize_p) {
        /* якорь идентичности: пролог CCLCMsg_Move::WriteToBuffer @0x286720 (19Б) */
        static const u8 w2bsig[19] = { 0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56,
                                       0x49, 0x89, 0xFE, 0x41, 0x55, 0x41, 0x54, 0x4C,
                                       0x8D, 0x67, 0x08 };
        if (memcmp((const void *)(g_engine_base + (uptr)0x286720u),
                   w2bsig, sizeof(w2bsig)) != 0) {
            C2B_LOGS("[c2b] WARN: MoveW2B sig mismatch — uplink helpers off\n");
        } else {
            g2e_bytesize_p   = g_engine_base + (uptr)0x1EF9F0u;  /* protobuf ByteSizeLong */
            g2e_serialize_p  = g_engine_base + (uptr)0x1F4410u;  /* SerializeToArray */
            g2e_writebytes_p = g_engine_base + (uptr)0x0641840u; /* bf_write::WriteBytes */
            C2B_LOGS("[c2b] uplink helpers OK (bsz/ser/wbytes)\n");
        }
    }
#endif
    i32 r = 0;
    if (!g_state) {
        r = c2b_install(g_engine_base + (uptr)ENGINE_TARGET_OFF);
        if (r == 0) C2B_LOGS("[c2b] ARMED: ProcessMessages detoured\n");
        else {
            /* t42v6: разово показать код отказа (сигнатура/страница) */
            static u8 sigfail_once;
            if (!sigfail_once) {
                sigfail_once = 1;
                C2B_LOGS("[c2b] install rc="); C2B_LOGD((u32)(-r));
                C2B_LOGS(" at off="); C2B_LOGH(ENGINE_TARGET_OFF);
                C2B_LOGS("\n");
            }
        }
    }
#ifdef __x86_64__
    if (!g2_state) {
        i32 r2 = c2b_install2(g_engine_base + (uptr)UPL_TARGET_OFF);
        if (r2 == 0) C2B_LOGS("[c2b] ARMED2: SendNetMsg detoured\n");
        else if (r == 0) r = r2;
    }
#endif
    /* 0 = все детуры данного арча встали */
    return (g_state && !r) ? 0 : (r ? r : -11);
}

/* ---------- t42v7: перехват выдачи GC через ISteamClient ----------
 * RE-факты (t42v5b/c прогоны): client_client.so НЕ грузится (64-битный путь
 * монолитен), engine_client.so импортирует ТОЛЬКО SteamInternal_ContextInit
 * (CreateInterface внутри libsteam_api, -Bsymbolic — интерпозиция глуха).
 * Путь: GOT-патч ContextInit-слота engine_client.so -> наш хук получает
 * контекст-структуру игры; в ctx[0] живёт ISteamClient*; его vtable слот
 * 0x60 (стаб SteamAPI_ISteamClient_GetISteamGenericInterface: mov(%rdi),rax;
 * mov 0x60(%rax),rax; jmp *rax — снято objdump 2026-09-30) свапаем на хук,
 * который на STEAMGAMECOORDINATOR_* звает c2b_gc_arm (publish-barrier t42v2). */
static void *g_ctxinit_real;
static void *g_ctx_ptr;                /* контекст игры (гипотеза: ctx=data[1]) */
static u32   g_ctxinit_seen;
static u8    g_vt_done;
static void *g_gislot_orig;
static void *g_gethuser_p;             /* t42v7g: SteamAPI_GetHSteamUser* */
static void *g_gethpipe_p;             /* t42v7g: SteamAPI_GetHSteamPipe* */

static void (*g_orig_ctx_cb)(void *);
static u32 g_huser, g_hpipe;           /* t42v7f: хэндлы из ctx[2]/[3] */
static void c2b_ctx_cb_w(void *ctx)
{
    /* t42v7b: контекст приходит АРГУМЕНТОМ коллбека (раскладка data={pFn,флаг}) */
    if (ctx && !g_ctx_ptr) {
        g_ctx_ptr = ctx;
        C2B_LOGS("[c2b] ctxcb ctx="); C2B_LOGH((u32)(uptr)ctx);
        for (u32 k = 0; k < 4; k++) {
            C2B_LOGS(" ["); C2B_LOGN(k); C2B_LOGS("]=");
            C2B_LOGH((u32)(*(uptr *)((uptr)ctx + k * 8)));
        }
        C2B_LOGS("\n");
        /* t42v7f: кандидаты хэндлов user/pipe */
        g_huser = (u32)(*(uptr *)((uptr)ctx + 16));
        g_hpipe = (u32)(*(uptr *)((uptr)ctx + 24));
    }
    if (g_orig_ctx_cb) g_orig_ctx_cb(ctx);
}

static void *c2b_ctxinit_h(void *data)
{
    if (!g_ctxinit_real) {
        g_ctxinit_real = dlsym(C2B_CL_RTLD_NEXT, "SteamInternal_ContextInit");
        if (!g_ctxinit_real) {
            static const char *const cands[] = {
                "steam_api.so", "libsteam_api.so", "steam_api64.so" };
            for (u32 i = 0; i < 3 && !g_ctxinit_real; i++) {
                void *h = dlopen(cands[i], C2B_RTLD_NOW | C2B_RTLD_GLOBAL);
                if (h) g_ctxinit_real =
                    dlsym(C2B_CL_RTLD_NEXT, "SteamInternal_ContextInit");
            }
        }
    }
    if (!g_ctxinit_real) return 0;
    if (data && !g_orig_ctx_cb) {
        uptr d0 = *(uptr *)data;
        uptr d1 = *(uptr *)((uptr)data + 8);
        C2B_LOGS("[c2b] CtxInit data="); C2B_LOGH((u32)(uptr)data);
        C2B_LOGS(" [0]="); C2B_LOGH((u32)d0);
        C2B_LOGS(" [1]="); C2B_LOGH((u32)d1);
        C2B_LOGS("\n");
        /* t42v7b: подменяем коллбек — контекст придёт аргументом */
        g_orig_ctx_cb = (void (*)(void *))d0;
        if (g_orig_ctx_cb)
            *(uptr *)data = (uptr)c2b_ctx_cb_w;
    }
    void *r = ((void *(*)(void *))g_ctxinit_real)(data);
    return r;
}

static void *c2b_gislot_h(void *self, int hu, int hp, const char *ver)
{
    void *r = ((void *(*)(void *, int, int, const char *))g_gislot_orig)(
        self, hu, hp, ver);
    if (ver && c2b_gc_is_gcver(ver)) {
        C2B_LOGS("[c2b] GC req IClient rv="); C2B_LOGH((u32)(uptr)r);
        C2B_LOGS("\n");
        c2b_gc_arm(r);
    }
    return r;
}

static void *g_iclient_obj;            /* t42v7d: объект ISteamClient из CIv */

static void c2b_vt_tick(void)
{
    if (g_vt_done) return;
    /* t42v7d: приоритет — объект из CreateInterface(SteamClient*),
     * фолбэк — контекст из CtxInit-коллбека */
    uptr ic = g_iclient_obj ? (uptr)g_iclient_obj : (g_ctx_ptr ? *(uptr *)g_ctx_ptr : 0);
    if (!ic) return;
    uptr vt = *(uptr *)ic;
    if (vt < 0x10000u) return;
    uptr slot = vt + 0x60;
    g_gislot_orig = *(void **)slot;
    if (!g_gislot_orig || g_gislot_orig == (void *)c2b_gislot_h) {
        g_vt_done = 1;
        return;
    }
    if (c2b_page_protect(slot, 8, 0x07) != 0) return;
    *(volatile uptr *)slot = (uptr)c2b_gislot_h;
    g_vt_done = 1;
    C2B_LOGS("[c2b] IClient vt+0x60 hooked orig=");
    C2B_LOGH((u32)(uptr)g_gislot_orig);
    C2B_LOGS("\n");

    /* t42v7f/g: ПРОАКТИВНЫЙ ARM — сами запрашиваем GC-интерфейс у steamclient.
     * Игровой объект — синглтон на (user,версию): свап слотов [2]/[3] ловит
     * и игровой RetrieveMessage/SendMessage. Хэндлы — РЕАЛЬНЫЕ (через
     * захваченные SteamAPI_GetHSteamUser/Pipe), фолбэк — ctx[2]/[3]. */
    if (!g_gc_state && g_gislot_orig && g_gc_probe) {
        /* run37: ПРОБА ВЫКЛЮЧЕНА ПО УМОЛЧАНИЮ. Вызов GetISteamGenericInterface
         * с угаданными (u,p) создаёт БИТЫЙ CAdapter: retr -> 16 zero-записей,
         * send -> SIGSEGV в RTTI (run 35/37). Арм теперь только через
         * игровые flat-аксессоры (c2b_gc_try_install) или через выдачу
         * интерфейса САМОЙ игре (интерпозеры ниже). C2B_GC_PROBE=1 —
         * вернуть старое поведение для отладки. */
        static const char *const gvers[] = {
            "STEAMGAMECOORDINATOR_INTERFACE_VERSION001",
            "STEAMGAMECOORDINATOR_INTERFACE_VERSION002",
            "STEAMGAMECOORDINATOR_INTERFACE_VERSION003",
            "SteamGameCoordinator001" };
        int hu = (int)g_huser, hp = (int)g_hpipe;
        if (g_gethuser_p)  hu = ((int (*)(void))g_gethuser_p)();
        if (g_gethpipe_p)  hp = ((int (*)(void))g_gethpipe_p)();
        C2B_LOGS("[c2b] GC handles u="); C2B_LOGN((u32)hu);
        C2B_LOGS("p="); C2B_LOGN((u32)hp); C2B_LOGS("\n");
        /* t42v7h: матрица user{0,hu} × версии — коллбеки игры зовут FOU(0,ver) */
        int users[2]; users[0] = 0; users[1] = hu;
        for (u32 u = 0; u < 2 && !g_gc_state; u++)
        for (u32 i = 0; i < 4 && !g_gc_state; i++) {
            void *obj = ((void *(*)(void *, int, int, const char *))g_gislot_orig)(
                (void *)ic, users[u], hp, gvers[i]);
            if (obj) {
                C2B_LOGS("[c2b] GC probe HIT u="); C2B_LOGN((u32)users[u]);
                C2B_LOGS(" "); C2B_LOGS(gvers[i]);
                C2B_LOGH((u32)(uptr)obj); C2B_LOGS("\n");
                c2b_gc_arm(obj);
            } else if (u == 1) {
                C2B_LOGS("[c2b] GC probe u=1 "); C2B_LOGS(gvers[i] + 28);
                C2B_LOGS("=0\n");
            }
        }
    }
}

/* ---------- t42v5: GOT-патчер выдачи steam-интерфейсов ----------
 * RE-факт (прогон t42v4 91bf54f2, 2026-09-30): client_client.so резолвит
 * SteamInternal_* через СВОЙ DT_NEEDED (libsteam_api.so) — локальный скоуп
 * dlopen-модуля старше глобального, preload-интерпозинг НЕ биндится
 * (0 вызовов CIv/FUv/GIv за 120с в главном меню).
 * Решение: в poll-потоке сканируем релокации JUMP_SLOT/GLOB_DAT модулей
 * *client* и перезаписываем слоты на хуки моста (оригинал хук зовёт через
 * RTLD_NEXT + dlopen-фолбэк — t42v3). Анти-тампер шифрует строки, но имена
 * символов в .dynsym открыты. */
static u8 c2b_got_done;                    /* 1 = целевой модуль пропатчен */
static u32 g_got_patch_n;                  /* счётчик пропатченных слотов */
#ifdef __x86_64__
typedef struct { u64 tag; u64 val; } c2b_dyn_t;
typedef struct { u64 off; u64 info; i64 add; } c2b_rela_t;
typedef struct { u32 nm; u8 info; u8 oth; u16 shn; u64 val; u64 sz; } c2b_sym_t;

static u32 c2b_got_len(const char *s) { u32 k = 0; while (s[k]) k++; return k; }
static i32 c2b_got_eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return (*a == *b); }

static void c2b_got_patch_range(uptr base, uptr rela, u64 sz, uptr symtab,
                                uptr strtab)
{
    u32 n = (u32)(sz / sizeof(c2b_rela_t));
    for (u32 i = 0; i < n; i++) {
        const c2b_rela_t *r =
            (const c2b_rela_t *)(rela + (uptr)i * sizeof(c2b_rela_t));
        u32 type = (u32)(r->info & 0xFFFFFFFFu);
        if (type != 6 /*GLOB_DAT*/ && type != 7 /*JUMP_SLOT*/) continue;
        u32 si = (u32)(r->info >> 32);
        if (!si) continue;
        const c2b_sym_t *s =
            (const c2b_sym_t *)(symtab + (uptr)si * sizeof(c2b_sym_t));
        const char *nm = (const char *)(strtab + s->nm);
        void *hook = 0; const char *hnm = 0;
        if (c2b_got_eq(nm, "SteamInternal_CreateInterface")) {
            hook = (void *)&SteamInternal_CreateInterface; hnm = nm;
        } else if (c2b_got_eq(nm,
                   "SteamAPI_ISteamClient_GetISteamGenericInterface")) {
            hook = (void *)&SteamAPI_ISteamClient_GetISteamGenericInterface;
            hnm = nm;
        } else if (c2b_got_eq(nm, "SteamInternal_ContextInit")) {
            /* t42v7: перехват контекста игры */
            hook = (void *)&c2b_ctxinit_h; hnm = nm;
        } else if (c2b_got_eq(nm, "SteamInternal_FindOrCreateUserInterface")) {
            /* t42v7c: ГЛАВНЫЙ путь — коллбеки контекста зовут её через PLT
             * (objdump 0x22AE00: lea ver; xor edi; call FOU@plt; mov rax->ctx) */
            hook = (void *)&SteamInternal_FindOrCreateUserInterface; hnm = nm;
        } else if (c2b_got_eq(nm, "SteamAPI_GetHSteamUser") && !g_gethuser_p) {
            /* t42v7g: capture-only — реальные хэндлы для GC-пробы */
            g_gethuser_p = (void *)(*(uptr *)(base + r->off));
            continue;
        } else if (c2b_got_eq(nm, "SteamAPI_GetHSteamPipe") && !g_gethpipe_p) {
            g_gethpipe_p = (void *)(*(uptr *)(base + r->off));
            continue;
        }
        if (!hook) continue;
        uptr slot = base + r->off;
        if (*(volatile uptr *)slot == (uptr)hook) { c2b_got_done = 1; continue; }
        if (c2b_page_protect(slot, 8, 0x07 /*RWX*/) != 0) continue;
        *(volatile uptr *)slot = (uptr)hook;
        g_got_patch_n++;
        C2B_LOGS("[c2b] GOT-patch "); C2B_LOGS(hnm); C2B_LOGS("\n");
    }
}

static i32 c2b_got_cb(void *info_v, void *szv, void *dv)
{
    struct phdr_impl *info = (struct phdr_impl *)info_v;
    (void)szv; (void)dv;
    const char *n = info->dlpi_name;
    if (!n || !n[0]) return 0;
    u32 is_client = 0;
    for (u32 i = 0; n[i]; i++) {
        u32 j = 0;
        const char *pat = "client";
        while (pat[j] && n[i + j] == pat[j]) j++;
        if (!pat[j]) { is_client = 1; break; }
    }
    if (!is_client) return 0;
    const u8 *ph = (const u8 *)info->dlpi_phdr;
    uptr dynv = 0;
    for (u16 k = 0; k < info->dlpi_phnum; k++, ph += 56) {
        if (*(const u32 *)(ph) == 2 /*PT_DYNAMIC*/) {
            dynv = info->dlpi_addr + *(const u64 *)(ph + 16); break;
        }
    }
    /* t42v5b: отладка сканера — только целевой client_client.so (до 8 строк) */
    {
        static u32 dbg_n = 8;
        u32 is_tgt = 0;
        for (u32 i = 0; n[i]; i++) {
            u32 j = 0;
            const char *pat = "client_client";
            while (pat[j] && n[i + j] == pat[j]) j++;
            if (!pat[j]) { is_tgt = 1; break; }
        }
        if (is_tgt && dbg_n) {
            dbg_n--;
            C2B_LOGS("[c2b] GOTscan base="); C2B_LOGH((u32)info->dlpi_addr);
            C2B_LOGS(" dyn="); C2B_LOGH((u32)dynv);
            C2B_LOGS(" phnum="); C2B_LOGN(info->dlpi_phnum);
            C2B_LOGS(" "); C2B_LOGS(n); C2B_LOGS("\n");
        }
    }
    if (!dynv) return 0;
    uptr strtab = 0, symtab = 0, rela = 0, jmprel = 0;
    u64 relasz = 0, pltrelsz = 0;
    const c2b_dyn_t *d = (const c2b_dyn_t *)dynv;
    for (u32 k = 0; k < 4096 && d[k].tag; k++) {
        switch (d[k].tag) {
        case 5:  strtab = d[k].val; break;   /* DT_STRTAB */
        case 6:  symtab = d[k].val; break;   /* DT_SYMTAB */
        case 7:  rela = d[k].val; break;     /* DT_RELA */
        case 8:  relasz = d[k].val; break;   /* DT_RELASZ */
        case 2:  pltrelsz = d[k].val; break; /* DT_PLTRELSZ */
        case 23: jmprel = d[k].val; break;   /* DT_JMPREL */
        }
    }
    if (!symtab || !strtab) return 0;
    /* ld.so абсолютизирует d_ptr; страховка на относительные значения */
    if (strtab < info->dlpi_addr) strtab += info->dlpi_addr;
    if (symtab < info->dlpi_addr) symtab += info->dlpi_addr;
    if (rela && rela < info->dlpi_addr) rela += info->dlpi_addr;
    if (jmprel && jmprel < info->dlpi_addr) jmprel += info->dlpi_addr;
    if (rela && relasz)
        c2b_got_patch_range(info->dlpi_addr, rela, relasz, symtab, strtab);
    if (jmprel && pltrelsz)
        c2b_got_patch_range(info->dlpi_addr, jmprel, pltrelsz, symtab, strtab);
    {
        static u32 dbg2_n = 8;
        u32 is_tgt2 = 0;
        for (u32 i = 0; n[i]; i++) {
            u32 j = 0;
            const char *pat = "client_client";
            while (pat[j] && n[i + j] == pat[j]) j++;
            if (!pat[j]) { is_tgt2 = 1; break; }
        }
        if (is_tgt2 && dbg2_n) {
            dbg2_n--;
            C2B_LOGS("[c2b] GOTscan relocs st="); C2B_LOGH((u32)strtab);
            C2B_LOGS(" sy="); C2B_LOGH((u32)symtab);
            C2B_LOGS(" ra="); C2B_LOGH((u32)rela);
            C2B_LOGS("+"); C2B_LOGN((u32)relasz);
            C2B_LOGS(" jr="); C2B_LOGH((u32)jmprel);
            C2B_LOGS("+"); C2B_LOGN((u32)pltrelsz);
            C2B_LOGS("\n");
        }
    }
    return 0;
}

static void c2b_got_tick(void)
{
    /* t42v7d: сканируем ВСЕГДА — слотов несколько, идемпотентно (slot==hook
     * пропускается); ранняя остановка оставляла CreateInterface непропатченным */
    dl_iterate_phdr(c2b_got_cb, 0);
}
#else
static void c2b_got_tick(void) {}
#endif /* __x86_64__ */

static void *c2b_poll_thread(void *arg)
{
    (void)arg;
    {   /* t43v1: crash-bisect gate — C2B_DISABLE_PATCH=1 makes the bridge a
         * PASSIVE preload (no GOT-patch, no detours, no vtable swap, no GC).
         * e2e-cloud smoke matrix (run 21/22 post-mortem): observe mode still
         * armed ContextInit GOT-patch + ProcessMessages/SendNetMsg detours;
         * the engine then SEGVs at protobuf RepeatedPtrFieldBase::Add inside
         * libvideo.so right after a SUCCESSFUL SteamAPI_Init. Attempt-level
         * env bisect: a3 = patch disabled, a4 = no preload at all. */
        /* run-57 fix: CL_VERBOSE must be read BEFORE the passive return —
         * passive farm mode needs the unlimited connless trace too. */
        const char *ve = getenv("C2B_CL_VERBOSE");
        if (ve && ve[0] == '1') {
            g_cl_verbose = 1;
            C2B_LOGS("[c2b] cl verbose=1 (passive; dump ALL connless)\n");
        }
        const char *np = getenv("C2B_DISABLE_PATCH");
        if (np && np[0] == '1') {
            C2B_LOGS("[c2b] C2B_DISABLE_PATCH=1 -> passive preload (no GOT-patch/detours/vt/GC)\n");
            return 0;
        }
    }
    for (int i = 0; i < 600; i++) {               /* до ~5 минут */
        /* t42v6: на 20-й секунде — разовый дамп модулей из /proc/self/maps */
        if (i == 40) {
            extern i32  open(const char *, i32, ...);
            extern i64  read(i32, void *, u64);
            extern i32  close(i32);
            static char mb[32768];
            i32 fd = open("/proc/self/maps", 0 /*O_RDONLY*/);
            if (fd >= 0) {
                i64 n = read(fd, mb, sizeof(mb) - 1);
                close(fd);
                if (n > 0) {
                    mb[n] = 0;
                    u32 lines = 0;
                    char *p = mb;
                    while (p < mb + n && lines < 40) {
                        char *e = p;
                        while (e < mb + n && *e != '\n') e++;
                        char sav = *e; *e = 0;
                        if (c2b_sthas(p, ".so") || c2b_sthas(p, "csgo_linux64")) {
                            C2B_LOGS("[c2b] maps ");
                            C2B_LOGS(p);
                            C2B_LOGS("\n");
                            lines++;
                        }
                        *e = sav;
                        p = (sav == '\n') ? e + 1 : e;
                    }
                }
            }
        }
        c2b_got_tick();                           /* t42v5: GOT-патчер */
        if (c2b_try_install() == 0) break;
        usleep(500000);
    }
    /* t42v5/v7: тик до пропатчивания GOT И установки vtable-слота */
    {
        int i;
        for (i = 0; i < 600; i++) {
            c2b_got_tick();
            c2b_vt_tick();                         /* t42v7: свап слота IClient */
            if (g_vt_done) break;
            usleep(500000);
        }
        C2B_LOGS("[c2b] GOT total="); C2B_LOGN(g_got_patch_n);
        C2B_LOGS(" vt="); C2B_LOGN(g_vt_done);
        C2B_LOGS("\n");
    }
    if (g_clv2_baits) {
    /* CLV2 фаза 2 (C2B_CLV2_BAITS=1): ждём доставки 'A' (recvfrom-хук ставит
     * phase=1) + ТРИ раунда INFO-PUSH (41e-m: движок сначала потребляет info —
     * ферма run 72: 'i'-промпт стрелял ПОСЛЕ info, и движок отвечал 'j'
     * через 0.13с), затем стреляем вторым ChallengeRequest — его reply
     * подменяется на 'i'-промпт (bait для 'j' движка). */
        int i;
        for (i = 0; i < 1200; i++) {              /* до 10 мин */
            if (g_clv2_phase == 1 && i >= 3 && g_ipush_left <= 7) {
                u8 out2[512];
                g_clv2_conn_id = (g_clv2_conn_id ^ 0x5eed0001u) | 1u;
                (void)c2b_clv2_build_chalreq(out2);
                if (g_clv2_fd >= 0 && g_clv2_dstlen &&
                    g_clp_sendto && (uptr)g_clp_sendto != 1) {
                    ((c2b_sendto_fn)g_clp_sendto)(g_clv2_fd, out2, 512, 0,
                                                  (struct sockaddr *)g_clv2_dst,
                                                  g_clv2_dstlen);
                }
                g_clv2_phase = 2;
                C2B_LOGS("[c2b] CLV2 phase2: 2nd ChallengeRequest sent (cid=");
                C2B_LOGH(g_clv2_conn_id);
                C2B_LOGS(")\n");
                break;
            }
            if (g_clv2_phase >= 2) break;         /* уже за фазой 2/3/4/5 */
            usleep(500000);
        }
    }
    if (g_clv2_baits) {
    /* CLV2 фаза 6 (C2B_CLV2_BAITS=1): после reserve-'A' (фаза 5) — четвёртый
     * challenge, reply подменяем на 'B'+'.+8A (connection accept). Если движок
     * примет — пошлёт 'k'-connect (капчур в sendto-хуке!). */
        int i;
        u8 got5 = 0;
        for (i = 0; i < 120; i++) {               /* до 60с */
            if (g_clv2_phase == 5) { got5 = 1; break; }
            usleep(500000);
        }
        if (got5) {
            for (i = 0; i < 6; i++) {             /* ждём фазу 5 установку */
                if (g_clv2_phase == 5) break;
                usleep(500000);
            }
            usleep(3000000);                      /* 3с на OnReserveAccepted */
            u8 out3[512];
            g_clv2_conn_id = (g_clv2_conn_id ^ 0x5eed0003u) | 1u;
            (void)c2b_clv2_build_chalreq(out3);
            if (g_clv2_fd >= 0 && g_clv2_dstlen &&
                g_clp_sendto && (uptr)g_clp_sendto != 1) {
                ((c2b_sendto_fn)g_clp_sendto)(g_clv2_fd, out3, 512, 0,
                                              (struct sockaddr *)g_clv2_dst,
                                              g_clv2_dstlen);
            }
            g_clv2_phase = 6;
            C2B_LOGS("[c2b] CLV2 phase6: 4th ChallengeRequest (B-accept bait)\n");
        }
    }
    /* конец гейта C2B_CLV2_BAITS (фазы 2/4/6) */
    /* t39-фикс: GC-опрос ТОЛЬКО после ARMED движка (ProcessMessages уже
     * идёт = SteamAPI_Init главного потока давно завершён). Прежде GC-цикл
     * мог дёрнуть accessor SteamAPI_ISteamGameCoordinator() ПОСРЕДИ
     * SteamAPI_Init — гонка на интерфейс-реестре steamclient. Если движок
     * не встал — GC не трогаем вовсе (GCFINI скажет unarmed). */
    if (g_gc_mode && g_state) {
        for (int i = 0; i < 600; i++) {
            i32 grc = c2b_gc_try_install();
            if (grc == 0) break;
            if (grc != -1) g_gc_last_fail = (u32)(-grc);   /* -1 = аксессора нет (норма для S1) */
            usleep(500000);
        }
        if (!g_gc_state)
            C2B_LOGS("[c2b] GC poll expired — interface never appeared\n");
    }
    /* t42v8: ClientHello-craft — самим разбудить GC-канал (при отсутствии
     * ARM pump тихо выйдет по g_gc_state==0) */
    c2b_gc_hello_pump();
    return 0;
}

i32 c2b_main(void)
{
    /* 41f-g36: nofile в САМЫЙ ранний момент (ctor, LD_PRELOAD — до любого
     * fd-давления движка). run179/180: 'epoll_ctl failed, error 0x9' в GNS
     * ConnectByIPAddress = fd-бюджет (дефолт 1024): socket() EMFILE -> fd=-1
     * -> epoll_ctl EBADF. Поднимаем soft до min(hard, 65535); структур
     * rlimit не тянем: {u64 cur, u64 max} (x86-64 ABI), RLIMIT_NOFILE=7. */
    {
        extern i32 getrlimit(i32 res, void *rlim);
        extern i32 setrlimit(i32 res, const void *rlim);
        struct { u64 cur, max; } rl;
        if (getrlimit(7, &rl) == 0) {
            u64 want = (rl.max < 65535ull) ? rl.max : 65535ull;
            C2B_LOGS("[c2b] g36: nofile cur="); C2B_LOGN((u32)rl.cur);
            C2B_LOGS(" max="); C2B_LOGN((u32)rl.max);
            if (rl.cur < want) {
                rl.cur = want;
                C2B_LOGS(setrlimit(7, &rl) == 0 ? " -> raised" : " -> setrlimit FAILED");
            } else {
                C2B_LOGS(" -> ok");
            }
            C2B_LOGS("\n");
        }
    }
    {   /* R30: уровень живого лога: 0=тихо, 1=компактно (по умолчанию),
         * 2=полный дамп на каждый вызов. g_vlevel==2 после статики (selftest),
         * в .so принудительно опускаем до 1 и даём env поднять обратно. */
        g_vlevel = 1;
        const char *e = getenv("C2B_VERBOSE");
        if (e && (e[1] == 0) && e[0] >= '0' && e[0] <= '2')
            g_vlevel = (u32)(e[0] - '0');
        C2B_LOGS("[c2b] verbose level="); C2B_LOGN(g_vlevel); C2B_LOGS("\n");
    }
    {   /* аплинк v1: 0=observe (по умолчанию), 1=translate */
        const char *e = getenv("C2B_UPLINK");
        if (e && e[0] == '1') {
            g_up_mode = 1;
            C2B_LOGS("[c2b] uplink mode=translate\n");
        } else {
            C2B_LOGS("[c2b] uplink mode=observe\n");
        }
    }
    {   /* downlink v1: 0=observe (по умолчанию), 1=translate */
        const char *e = getenv("C2B_DOWNLINK");
        if (e && e[0] == '1') {
            g_dn_mode = 1;
            C2B_LOGS("[c2b] downlink mode=translate\n");
        } else {
            C2B_LOGS("[c2b] downlink mode=observe\n");
        }
    }
    {   /* t39: GC-транзит Фаза 2 — observe по умолчанию; C2B_GC=0 выключает */
        const char *e = getenv("C2B_GC");
        if (e && e[0] == '0') {
            g_gc_mode = 0;
            C2B_LOGS("[c2b] gc mode=off\n");
        } else {
            C2B_LOGS("[c2b] gc mode=observe\n");
        }
    }
    {   /* t42v9: даунлинк-фильтр S2NEW (audit_t38 fail-closed); C2B_GC_T=1 включает */
        const char *e = getenv("C2B_GC_T");
        if (e && e[0] == '1') {
            g_gc_t_mode = 1;
            C2B_LOGS("[c2b] gc translate=dn-drop-s2new\n");
        } else {
            C2B_LOGS("[c2b] gc translate=observe\n");
        }
    }
    {   /* t42v8: ClientHello-craft; run33: только по явному C2B_HELLO=1
         * (слоты GC на новом steamclient не подтверждены — см. GCDIAG) */
        const char *e = getenv("C2B_HELLO");
        if (e && e[0] == '1') {
            g_hello_mode = 1;
            C2B_LOGS("[c2b] hello mode=craft (env)\n");
        } else {
            C2B_LOGS("[c2b] hello mode=off\n");
        }
    }
    {   /* run33: оверрайд слотов GC-объекта (одна цифра 0..7) */
        const char *e = getenv("C2B_GC_SEND_SLOT");
        if (e && e[0] >= '0' && e[0] <= '7' && e[1] == 0) {
            g_gc_slot_send = (u32)(e[0] - '0');
            C2B_LOGS("[c2b] gc send slot="); C2B_LOGN(g_gc_slot_send); C2B_LOGS("\n");
        }
        e = getenv("C2B_GC_RETR_SLOT");
        if (e && e[0] >= '0' && e[0] <= '7' && e[1] == 0) {
            g_gc_slot_retr = (u32)(e[0] - '0');
            C2B_LOGS("[c2b] gc retr slot="); C2B_LOGN(g_gc_slot_retr); C2B_LOGS("\n");
        }
        e = getenv("C2B_GC_DIAG");
        if (e && e[0] == '0') {
            g_gc_diag = 0;
            C2B_LOGS("[c2b] gc diag=off\n");
        }
        e = getenv("C2B_GC_SWAP");
        if (e && e[0] == '1') {
            g_gc_swap = 1;
            C2B_LOGS("[c2b] gc swap=on (hooks; ОПАСНО — усечённая vt_copy, run35)\n");
        } else {
            C2B_LOGS("[c2b] gc swap=off (pump зовёт оригиналы напрямую)\n");
        }
        e = getenv("C2B_GC_PROBE");
        if (e && e[0] == '1') {
            g_gc_probe = 1;
            C2B_LOGS("[c2b] gc probe=on (ОПАСНО — битые CAdapter, run37)\n");
        } else {
            C2B_LOGS("[c2b] gc probe=off (арм только через flat-аксессоры игры)\n");
        }
    }
    {   /* R37: протокол в S1 ServerInfo (дефолт 13762; под конкретный бинарь клиента — env) */
        const char *e = getenv("C2B_S1_PROTOCOL");
        if (e && e[0] >= '0' && e[0] <= '9') {
            u32 v = 0; int k;
            for (k = 0; k < 9 && e[k] >= '0' && e[k] <= '9'; k++) v = v * 10 + (u32)(e[k] - '0');
            if (v > 0) {
                g_si_protocol = v;
                C2B_LOGS("[c2b] si protocol="); C2B_LOGH(g_si_protocol); C2B_LOGS("\n");
            }
        }
    }
#ifndef C2B_SELFTEST
    /* 41f-g32: C2B_GNS_CONNECT=ip:port | C2B_GNS_RELAY=1 | C2B_GNS_UDPCNT=1
     * (вне гейта C2B_CL_V2: драйвер GNS-connect независим от CLV2) */
    {
        const char *e2 = getenv("C2B_GNS_CONNECT");
        if (e2 && e2[0]) {
            u32 k3;
            for (k3 = 0; e2[k3] && k3 < sizeof(g_gns_connect_target) - 1; k3++)
                g_gns_connect_target[k3] = (u8)e2[k3];
            g_gns_connect_target[k3] = 0;
            g_gns_connect_go = 1;
            C2B_LOGS("[c2b] g32: connect driver armed -> ");
            C2B_LOGS((const char *)g_gns_connect_target);
            C2B_LOGS("\n");
        }
        e2 = getenv("C2B_GNS_RELAY");
        if (e2 && e2[0] == '1') {
            g_gns_relay = 1;
            C2B_LOGS("[c2b] g32: relay=1 (captured 0x22 -> engine fd -> target)\n");
        }
    }
#endif  /* C2B_SELFTEST (g32-env: статики в real-build регионе) */
    {   /* 41e-a: connectionless-слой v1; C2B_CL_VERBOSE=1 -> hexdump каждого
         * connless-пакета (иначе первые 32; см. блок 41e-a выше) */
        const char *e = getenv("C2B_CL_VERBOSE");
        if (e && e[0] == '1') {
            g_cl_verbose = 1;
            C2B_LOGS("[c2b] cl verbose=1 (dump ALL connless)\n");
        } else {
            C2B_LOGS("[c2b] cl mode=passthrough (first 32 dumped)\n");
        }
    }
    {   /* 41e-c: CL v2 phase A — S2 GNS challenge-обмен (full-харнесс) */
        const char *e = getenv("C2B_CL_V2");
        if (e && e[0] == '1') {
            g_clv2_enable = 1;
            C2B_LOGS("[c2b] clv2=1 (qconnect->S2 ChallengeRequest, 'A'+challenge -> engine)\n");
            {   const char *e2 = getenv("C2B_CLV2_FWDK");
                if (e2 && e2[0] == '1') {
                    g_clv2_fwdk = 1;
                    C2B_LOGS("[c2b] clv2 fwdk=1 ('k'->target raw-forward ON)\n");
                }
            }
            {   /* 41f-g31: C2B_CLV2_CR=1 bare | =2 +crypt(x25519); SID override */
                const char *e2 = getenv("C2B_CLV2_CR");
                if (e2 && (e2[0] == '1' || e2[0] == '2')) {
                    g_clv2_cr = (u32)(e2[0] - '0');
                    C2B_LOGS("[c2b] clv2 cr=");
                    C2B_LOGN(g_clv2_cr);
                    C2B_LOGS(g_clv2_cr == 2 ? " (0x22 +crypt x25519)\n" : " (0x22 bare)\n");
                }
                e2 = getenv("C2B_CLV2_SID");
                if (e2 && e2[0]) {
                    u64 v = 0;
                    if (e2[0] == '0' && (e2[1] == 'x' || e2[1] == 'X')) {
                        u32 k3;
                        for (k3 = 2; e2[k3]; k3++) {
                            u8 c = (u8)e2[k3];
                            u32 d;
                            if (c >= '0' && c <= '9') d = (u32)(c - '0');
                            else if (c >= 'a' && c <= 'f') d = (u32)(c - 'a' + 10);
                            else if (c >= 'A' && c <= 'F') d = (u32)(c - 'A' + 10);
                            else break;
                            v = (v << 4) | (u64)d;
                        }
                    } else {
                        u32 k3;
                        for (k3 = 0; e2[k3] >= '0' && e2[k3] <= '9'; k3++)
                            v = v * 10 + (u64)(e2[k3] - '0');
                    }
                    if (v) {
                        g_clv2_sid64 = v;
                        C2B_LOGS("[c2b] clv2 sid=0x");
                        C2B_LOGH((u32)(v >> 32)); C2B_LOGH((u32)v);
                        C2B_LOGS(" (env override)\n");
                    }
                }
            }
            e = getenv("C2B_CLV2_FMT");
            if (e && e[0] >= '0' && e[0] <= '9') {
                g_clv2_fmt = (u32)(e[0] - '0');
                C2B_LOGS("[c2b] clv2 fmt="); C2B_LOGN(g_clv2_fmt);
                C2B_LOGS(" (0=le32 1=ascii0x 2=le32+proto 3=echo+le32 4=ascii+proto 5=RE-u32 6=RE-u64 7=K-search)\n");
            }
            e = getenv("C2B_CLV2_K");
            if (e && e[0] >= '0' && e[0] <= '9') {
                g_clv2_k = (u32)(e[0] - '0');
                C2B_LOGS("[c2b] clv2 K="); C2B_LOGN(g_clv2_k);
                C2B_LOGS("\n");
            }
            e = getenv("C2B_CLV2_BAITS");
            if (e && e[0] == '1') {
                g_clv2_baits = 1;
                C2B_LOGS("[c2b] clv2 baits=1 (фазы 2/4/6: 'i'/reserve-'A'/'B')\n");
            } else {
                C2B_LOGS("[c2b] clv2 baits=0 (чистый fmt9-'A', без клоббера)\n");
            }
            e = getenv("C2B_CLV2_BHEX");
            if (e && e[0] >= '0' && e[0] <= '2') {
                g_clv2_bhex = (u32)(e[0] - '0');
                C2B_LOGS("[c2b] clv2 bhex="); C2B_LOGN(g_clv2_bhex);
                C2B_LOGS(" (0=AAAAAAAA 1=challenge 2=qc_val)\n");
            }
            e = getenv("C2B_A2S_VERSION");
            if (e && e[0]) {
                u32 ai;
                for (ai = 0; e[ai] && ai < sizeof(g_a2s_ver) - 1; ai++)
                    g_a2s_ver[ai] = e[ai];
                g_a2s_ver[ai] = 0;
            }
        }
    }
    /* 41f-a: auth-воркер (ждёт FUv-капчур SteamUser022, зовёт GetAuthSessionTicket).
     * Стартуем ДО try_install в обоих путях (ARMED и poll) — поток сам ждёт
     * капчур до 150с и безопасен при его отсутствии. */
    {
        void *auth_tid = 0;
        const char *e = getenv("C2B_AUTH_VTIDX");
        if (e && e[0] >= '0' && e[0] <= '9') {
            u32 v = 0;
            while (*e >= '0' && *e <= '9') { v = v * 10 + (u32)(*e - '0'); e++; }
            if (v > 0 && v < 64) g_auth_vtidx = v;
        }
        C2B_LOGS("[c2b] AUTH: vtidx probe start="); C2B_LOGN(g_auth_vtidx);
        C2B_LOGS("\n");
        pthread_create(&auth_tid, 0, c2b_auth_thread, 0);
    }
    /* 41f-g20 BISECT run138: early-arm DISABLED - run135/136/137 showed early
     * arming kills the connect flow regardless of the probe subset (run137:
     * g19a off, allocs returned, chain still dead). run132's mid-flow arming
     * (rearm loop) is the proven config. Re-introduce early arms one probe at
     * a time in later rounds. */
    i32 r;
#ifndef C2B_SELFTEST
    {   /* 41f-g24: снап-вотчер стейта — пассивные чтения, свой тред */
        void *t24 = 0;
        pthread_create(&t24, 0, c2b_g24_thread, 0);
    }
#endif
    r = c2b_try_install();
    if (r == 0) {
        C2B_LOGS("[c2b] ARMED: detours in place\n");
        return 0;
    }
    /* движок ещё не загружен — фоновый опрос */
    void *tid = 0;
    pthread_create(&tid, 0, c2b_poll_thread, 0);
    C2B_LOGS("[c2b] poll thread started\n");
    return 0;
}

/* ld.so вызывает DT_INIT_ARRAY у .so автоматически даже с -nostartfiles */
__attribute__((constructor(101)))
static void c2b_ctor(void) { c2b_main(); }

/* R30: финальная статистика при выгрузке .so (выход движка). Одна строка,
 * независимо от g_vlevel — парсится step_f1 после живого прогона. При
 * _exit() движка деструктор может не вызваться — best effort. */
/* t35: FINI/FINI2 — одна строка на блок (формат = эталон 5cce9ff4:
 * hex 0x%08x, двойные пробелы между полями, один пробел перед }) */
static void c2b_print_fini(void)
{
    C2B_LOGS("[c2b] FINI calls="); C2B_LOGN(g_dn_stats.calls);
    C2B_LOGS(" dn{ok=");   C2B_LOGN(g_dn_stats.ok);
    C2B_LOGS(" pass=");    C2B_LOGN(g_dn_stats.pass);
    C2B_LOGS(" rival=");   C2B_LOGN(g_dn_stats.rival);
    C2B_LOGS(" oom=");     C2B_LOGN(g_dn_stats.oom);
    C2B_LOGS(" trunc=");   C2B_LOGN(g_dn_stats.trunc);
    C2B_LOGS(" bin=");     C2B_LOGN(g_dn_stats.bytes_in);
    C2B_LOGS(" bout=");    C2B_LOGN(g_dn_stats.bytes_out);
    C2B_LOGS(" mxi=");     C2B_LOGN(g_dn_stats.max_in);
    C2B_LOGS(" mox=");     C2B_LOGN(g_dn_stats.max_out);
    C2B_LOGS(" void=");    C2B_LOGN(g_dn_stats.n_void);   /* t36/audit05: эталон dn{... void} */
    C2B_LOGS("} g4{ovf="); C2B_LOGN(g_g4b_cls_ovf);   /* R33: дропы кэша cls */
    C2B_LOGS(" bnn=");     C2B_LOGN(g_g4_bnn);
    C2B_LOGS(" ub=");      C2B_LOGN(g_g4_ub);         /* R36: update_baseline != 0 */
    C2B_LOGS(" dfm=");     C2B_LOGN(g_g4_dfm);
    C2B_LOGS(" ds=");      C2B_LOGN(g_g4_ds);
    C2B_LOGS(" sr=");      C2B_LOGN(g_g4_sr);
    C2B_LOGS(" ps=");      C2B_LOGN(g_g4_pass);      /* raw-pass кадров PE (эталон pass) */
    C2B_LOGS(" nf=");      C2B_LOGN(g_g4_nofsv);
    C2B_LOGS(" dm=");      C2B_LOGN(g_g4_dm);
    C2B_LOGS("} gb{m=");   C2B_LOGN(g_g4b_msgs);
    C2B_LOGS(" k=");       C2B_LOGN(g_g4b_kept);
    C2B_LOGS(" sk=");      C2B_LOGN(g_g4b_skip);
    C2B_LOGS(" nc=");      C2B_LOGN(g_g4b_nocls);
    C2B_LOGS(" ov=");      C2B_LOGN(g_g4b_ovf);
    C2B_LOGS(" ud=");      C2B_LOGN(g_g4b_upd_drop);
    C2B_LOGS(" c51=");     C2B_LOGN(g_g4b_compress);
    C2B_LOGS(" dc=");      C2B_LOGN(g_g4b_decerr);
    C2B_LOGS("} snd{n=");  C2B_LOGN(g_synth_sounds);   /* фаза G-6 (t36/P208) */
    C2B_LOGS(" drop=");    C2B_LOGN(g_synth_snd_drop);
    C2B_LOGS("} up{calls="); C2B_LOGN(g_up_st.calls);
    C2B_LOGS(" rival=");   C2B_LOGN(g_up_st.rival);
    C2B_LOGS("} clu{s=");  C2B_LOGN(g_cl_s_total);   /* 41e-a: connectionless v1 */
    C2B_LOGS(" cl=");      C2B_LOGN(g_cl_s_cl);
    C2B_LOGS(" gc=");      C2B_LOGN(g_cl_s_gc);
    C2B_LOGS(" qc=");      C2B_LOGN(g_cl_s_qc);
    C2B_LOGS(" cn=");      C2B_LOGN(g_cl_s_cn);
    C2B_LOGS(" rc=");      C2B_LOGN(g_cl_s_rc);
    C2B_LOGS(" ot=");      C2B_LOGN(g_cl_s_ot);
    C2B_LOGS(" dr=");      C2B_LOGN(g_cl_s_drop);
    C2B_LOGS("} clr{r=");  C2B_LOGN(g_cl_r_total);
    C2B_LOGS(" cl=");      C2B_LOGN(g_cl_r_cl);
    C2B_LOGS(" ch=");      C2B_LOGN(g_cl_r_ch);
    C2B_LOGS(" rj=");      C2B_LOGN(g_cl_r_rj);
    C2B_LOGS(" si=");      C2B_LOGN(g_cl_r_si);
    C2B_LOGS(" in=");      C2B_LOGN(g_cl_r_in);
    C2B_LOGS(" ot=");      C2B_LOGN(g_cl_r_ot);
    C2B_LOGS(" dr=");      C2B_LOGN(g_cl_r_drop);
    C2B_LOGS("} clv2{req="); C2B_LOGN(g_clv2_sent_req);   /* 41e-c: S2 challenge */
    C2B_LOGS(" ch=");      C2B_LOGN(g_clv2_got_ch);
    C2B_LOGS(" cn=");      C2B_LOGN(g_clv2_cap_connect);
    C2B_LOGS(" bad=");     C2B_LOGN(g_clv2_badreply);
    C2B_LOGS("}\n");
}

static void c2b_print_fini2(void)
{
    C2B_LOGS("[c2b] FINI2 si{pr="); C2B_LOGH(g_si_pr);
    C2B_LOGS(" mcl=");  C2B_LOGH(g_si_v_mcl);      /* записанное в S1 */
    C2B_LOGS(" mcs=");  C2B_LOGH(g_si_v_mcs);
    C2B_LOGS(" mclr="); C2B_LOGH(g_si_mcl_raw);    /* raw S2 */
    C2B_LOGS(" mcsr="); C2B_LOGH(g_si_mcs_raw);
    C2B_LOGS("} rt{str="); C2B_LOGN(g_fini2.rt_str);
    C2B_LOGS(" ge=");   C2B_LOGN(g_fini2.rt_ge);
    C2B_LOGS(" aov=");  C2B_LOGN(g_fini2.rt_aov);
    C2B_LOGS("} ba{p=");  C2B_LOGN(g_fini2.ba_p);
    C2B_LOGS(" s=");    C2B_LOGN(g_fini2.ba_s);
    C2B_LOGS(" nt=");   C2B_LOGN(g_fini2.ba_nt);
    C2B_LOGS("} up2{t0=");  C2B_LOGN(g_fini2.up2_t0);
    C2B_LOGS(" bsz=");  C2B_LOGN(g_fini2.up2_bsz);
    C2B_LOGS(" tr=");   C2B_LOGN(g_fini2.up2_tr);
    C2B_LOGS("} dn2{fc="); C2B_LOGN(g_fini2.dn2_fc);
    C2B_LOGS("}\n");
}

__attribute__((destructor(101)))
static void c2b_dtor(void)
{
    c2b_print_fini();
    c2b_print_fini2();      /* до c2b_flush */
    c2b_print_gcfini();     /* t39: GC-транзит — отдельная строка, формат FINI не тронут */
    c2b_flush();
}

#else
/* ============================================================ */
/* ---------- selftest (x86_64 sandbox / любой x86-хост) ---------- */

#if defined(__x86_64__)
__asm__(
".text\n"
".globl c2b_stub\n"
".type  c2b_stub,@function\n"
"c2b_stub:\n"                     /* пролог = C2B_SIG (17 байт) */
"  push %rbp\n"
"  mov  %rsp,%rbp\n"
"  push %r15\n"
"  push %r14\n"
"  push %r13\n"
"  sub  $0x8c,%rsp\n"             /* <- граница stolen-байт здесь */
"  mov  c2b_stub_in_a(%rip),%eax\n"
"  add  c2b_stub_in_b(%rip),%eax\n"
"  add  c2b_stub_in_c(%rip),%eax\n"
"  mov  %eax,c2b_stub_result(%rip)\n"
"  lea  -0x18(%rbp),%rsp\n"
"  pop  %r13\n"
"  pop  %r14\n"
"  pop  %r15\n"
"  pop  %rbp\n"
"  ret\n"
".globl c2b_stub_result\n"
".data\n"
"c2b_stub_result: .long 0\n"
"c2b_stub_in_a:   .long 0\n"
"c2b_stub_in_b:   .long 0\n"
"c2b_stub_in_c:   .long 0\n"
".text\n"
);
#else
__asm__(
".text\n"
".globl c2b_stub\n"
".type  c2b_stub,@function\n"
"c2b_stub:\n"                     /* пролог = C2B_SIG (12 байт) */
"  push %ebp\n"
"  mov  %esp,%ebp\n"
"  push %edi\n"
"  push %esi\n"
"  push %ebx\n"
"  sub  $0x8c,%esp\n"             /* <- граница stolen-байт здесь */
"  mov  c2b_stub_in_a,%eax\n"
"  add  c2b_stub_in_b,%eax\n"
"  add  c2b_stub_in_c,%eax\n"
"  mov  %eax,c2b_stub_result\n"
"  lea  -0xc(%ebp),%esp\n"     /* вершина сохранённых ebx,esi,edi */
"  pop  %ebx\n"
"  pop  %esi\n"
"  pop  %edi\n"
"  pop  %ebp\n"
"  ret\n"
".globl c2b_stub_result\n"
".data\n"
"c2b_stub_result: .long 0\n"
"c2b_stub_in_a:   .long 0\n"
"c2b_stub_in_b:   .long 0\n"
"c2b_stub_in_c:   .long 0\n"
".text\n"
);
#endif

extern i32 c2b_stub(i32, i32, i32);
extern i32 c2b_stub_result;
extern i32 c2b_stub_in_a, c2b_stub_in_b, c2b_stub_in_c;

#if defined(__x86_64__)
/* аплинк-заглушка: пролог = UPL_SIG (17 байт), stolen=16 (до 'mov %rsi,%r13').
 * Тело: result = edi + r14d + r15d — r14d/r15d пишутся stolen-байтами из
 * edx/ecx, edi проходит через хук нетронутым: проверяет полный круг
 * регистров через детур (в selftest — прямой C-хук + trampoline). */
__asm__(
".text\n"
".globl c2b_stub2\n"
".type  c2b_stub2,@function\n"
"c2b_stub2:\n"                    /* пролог = UPL_SIG (17 байт) */
"  push %rbp\n"
"  mov  %rsp,%rbp\n"
"  push %r15\n"
"  mov  %ecx,%r15d\n"
"  push %r14\n"
"  mov  %edx,%r14d\n"
"  push %r13\n"
"  mov  %rsi,%r13\n"              /* <- граница stolen-байт выше */
"  push %r12\n"
"  push %rbx\n"
"  sub  $0x18,%rsp\n"
"  mov  %edi,%eax\n"
"  add  %r14d,%eax\n"
"  add  %r15d,%eax\n"
"  mov  %eax,c2b_stub2_result(%rip)\n"
"  add  $0x18,%rsp\n"
"  pop  %rbx\n"
"  pop  %r12\n"
"  pop  %r13\n"
"  pop  %r14\n"
"  pop  %r15\n"
"  pop  %rbp\n"
"  ret\n"
".globl c2b_stub2_result\n"
".data\n"
"c2b_stub2_result: .long 0\n"
".text\n"
);
extern i32 c2b_stub2(uptr, void *, i32, i32);
extern i32 c2b_stub2_result;
#endif /* x86_64 */

static int fails = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("  OK   %s\n", name); \
    else { printf("  FAIL %s\n", name); fails++; } \
} while (0)

static void test_varint(void)
{
    u8 b[8]; u32 v = 0, n;
    printf("[t] varint\n");
    u32 cases[] = { 0, 1, 40, 127, 128, 300, 16383, 16384, 0xFFFFFFFFu };
    for (u32 i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        n = c2b_write_varint(b, cases[i]);
        c2b_read_varint(b, n, &v);
        if (!(v == cases[i] && n > 0)) {
            printf("  FAIL varint %u\n", cases[i]); fails++;
        }
    }
    printf("  OK   varint roundtrip x9\n");
}

static void test_translate(void)
{
    /* синтетический S2-поток (фаза F):
       40(ServerInfo XF_RENUM): п1=2001, п4=0, п10=24, п11=64, п6=3, п12=0,
                                 п15="d2", п17="host"
                                 -> S1 8: renum(f5=0,f7=3,f13=0,f16="d2",f19="host")
                                    + R37-хвост: f1=13762, f11=24, f12=238, f15="csgo"
                                    (S2 п1/п10/п11 из passthrough УДАЛЕНЫ — синтез)
       41(FlattenedSerializer)  -> DROP
       48(Print,"hi")           -> 16 DIRECT
       8(net_SpawnGroup_Load)   -> DROP
       4(net_Tick XF_RENUM): п1=100, п9=5 -> S1 4: п1=100, п7=5
       47(VoiceData XF_DROP)    -> DROP (фаза F)
       77(NextMsgPredicted)     -> DROP
    */
    u8 in[96], out[96]; u32 olen = 0, ip = 0;
    u8 si[32]; u32 sp = 0;
    si[sp++]=0x08; sp+=c2b_write_varint(si+sp, 2001);       /* S2 п1 protocol */
    si[sp++]=0x20; si[sp++]=0x00;                            /* S2 п4 is_hltv -> S1 п5 */
    si[sp++]=0x50; si[sp++]=24;                              /* S2 п10 max_clients=24 -> S1 п11 (R37) */
    si[sp++]=0x58; si[sp++]=64;                              /* S2 п11 max_classes=64 -> S1 п12 (R37) */
    si[sp++]=0x30; si[sp++]=3;                               /* S2 п6  c_os=3 -> S1 п7 (R37) */
    si[sp++]=0x60; si[sp++]=0;                               /* S2 п12 player_slot=0 -> S1 п13 (R37) */
    si[sp++]=0x7A; si[sp++]=2; si[sp++]='d'; si[sp++]='2';   /* S2 п15 map_name -> S1 п16 */
    si[sp++]=0x8A; si[sp++]=0x01; si[sp++]=4;                /* S2 п17 host_name -> S1 п19 */
    si[sp++]='h'; si[sp++]='o'; si[sp++]='s'; si[sp++]='t';
    ip += c2b_write_varint(in + ip, 40); ip += c2b_write_varint(in + ip, sp);
    for (u32 k = 0; k < sp; k++) in[ip++] = si[k];

    ip += c2b_write_varint(in + ip, 41); ip += c2b_write_varint(in + ip, 1); in[ip++] = 0x01;
    ip += c2b_write_varint(in + ip, 48); ip += c2b_write_varint(in + ip, 2);
    in[ip++] = 'h'; in[ip++] = 'i';
    ip += c2b_write_varint(in + ip, 8);  ip += c2b_write_varint(in + ip, 1); in[ip++] = 0x02;

    u8 ti[8]; u32 tp = 0;
    ti[tp++]=0x08; ti[tp++]=0x64;          /* S2 п1 tick=100 */
    ti[tp++]=0x48; ti[tp++]=0x05;          /* S2 п9 hltv_flags=5 -> S1 п7 */
    ip += c2b_write_varint(in + ip, 4);  ip += c2b_write_varint(in + ip, tp);
    for (u32 k = 0; k < tp; k++) in[ip++] = ti[k];

    ip += c2b_write_varint(in + ip, 47); ip += c2b_write_varint(in + ip, 1); in[ip++] = 0x07;
    ip += c2b_write_varint(in + ip, 77); ip += c2b_write_varint(in + ip, 1); in[ip++] = 0x03;

    printf("[t] translate+renum (in=%u bytes)\n", ip);
    i32 r = c2b_translate(in, ip, out, sizeof(out), &olen, &g_st);

    CHECK(r == 0, "translate rc==0");
    CHECK(g_st.msgs_in == 7, "msgs_in==7");
    CHECK(g_st.msgs_out == 3, "msgs_out==3");
    CHECK(g_st.dropped == 4, "dropped==4");
    CHECK(g_st.renumbered == 2, "renumbered==2 (40->8, 48->16)");
    CHECK(g_st.net_pass == 1, "net_pass==1");

    /* ожидаемый выход: 8(renum) | 16(direct) | 4(renum) */
    u8 exp[64]; u32 ep = 0;
    /* R37-синтез (агент2, диз эталона): п1/f10/f11 НЕ passthrough — синтезируются:
     * protocol=13762, mcl=24 (raw), mcs=238 (кламп 238..512), game_dir "csgo" (f14 нет),
     * слот есть в S2 (f12) — 10Б -1 не дописывается. Порядок полей = порядок входа. */
    ep += c2b_write_varint(exp + ep, 8); ep += c2b_write_varint(exp + ep, 32);
    exp[ep++]=0x28; exp[ep++]=0x00;                          /* п5 <- S2 п4 */
    exp[ep++]=0x38; exp[ep++]=3;                             /* п7  <- S2 п6 */
    exp[ep++]=0x68; exp[ep++]=0;                             /* п13 <- S2 п12 */
    exp[ep++]=0x82; exp[ep++]=0x01; exp[ep++]=2;             /* п16 "d2" */
    exp[ep++]='d'; exp[ep++]='2';
    exp[ep++]=0x9A; exp[ep++]=0x01; exp[ep++]=4;             /* п19 "host" */
    exp[ep++]='h'; exp[ep++]='o'; exp[ep++]='s'; exp[ep++]='t';
    exp[ep++]=0x08; exp[ep++]=0xC2; exp[ep++]=0x6B;          /* синтез п1 protocol=13762 */
    exp[ep++]=0x58; exp[ep++]=24;                            /* синтез п11 mcl=24 */
    exp[ep++]=0x60; exp[ep++]=0xEE; exp[ep++]=0x01;          /* синтез п12 mcs=238 */
    exp[ep++]=0x7A; exp[ep++]=4;                             /* синтез п15 "csgo" */
    exp[ep++]='c'; exp[ep++]='s'; exp[ep++]='g'; exp[ep++]='o';
    ep += c2b_write_varint(exp + ep, 16); ep += c2b_write_varint(exp + ep, 2);
    exp[ep++]='h'; exp[ep++]='i';
    ep += c2b_write_varint(exp + ep, 4); ep += c2b_write_varint(exp + ep, 4);
    exp[ep++]=0x08; exp[ep++]=0x64; exp[ep++]=0x38; exp[ep++]=0x05;
    CHECK(olen == ep && memcmp(out, exp, ep) == 0, "output bytes exact");
    /* R37: si-парсинг из потока выше (raw-значения + клампы) */
    CHECK(g_si_pr == 2001, "si: protocol raw");
    CHECK(g_si_mcl_raw == 24 && g_fini2.si_mcl == 24, "si: max_clients raw/кламп");
    CHECK(g_si_mcs_raw == 64, "si: max_classes raw (кламп 238..512 не задет? 64<238 -> g_si_v_mcs=238)");
    CHECK(g_fini2.si_mcs == 238, "si: max_classes кламп снизу до 238 (эталон-семантика)");
    CHECK(g_fini2.si_mclr == 0 && g_fini2.si_mcsr == 0, "si: S1-only crc = 0");
    CHECK(g_si_no_slot == 0, "si: player_slot присутствует в S2-потоке");

    /* renum_payload: дроп неизвестных полей и wt1(fixed64) */
    u8 p2[32], q2[32]; u32 p2n = 0, sk = 0;
    p2[p2n++]=0x08; p2[p2n++]=0x2A;                 /* п1 varint 42 -> 0xFF (дроп; R37-синтез) */
    p2[p2n++]=0x11; for (int k=0;k<8;k++) p2[p2n++]=(u8)k;  /* п2 fixed64 (wt1) -> п2 */
    p2[p2n++]=0x28; p2[p2n++]=0x63;                 /* п5 varint 99 -> 0xFF (дроп) */
    i32 rn = c2b_renum_payload(p2, p2n, g_renum_40.map, q2, sizeof(q2), &sk);
    CHECK(rn == 9, "renum_payload len");     /* только п2 fixed64(1+8); п1/п5 дроп */
    CHECK(sk == 2, "renum_payload skipped==2");
    CHECK(q2[0]==0x11, "renum_payload tags ok (п1 дропнут)");
}

/* фаза G-1: GameEvent-мост (wire 205/207 из EBaseGameEvents, доказано
 * шаблонами CNetMessagePB в cs2_client.so). key_t 1..8 у пары идентичны,
 * top-level: 1->1, 2->2, 3->3, 4(server_tick)=ДРОП, 5(passthrough)->4. */
static void test_translate_ge(void)
{
    u8 in[160], out[160]; u32 olen = 0, ip = 0;

    /* 207 GameEvent: имя, id, один ключ, server_tick (дроп), passthrough */
    u8 ge[64]; u32 gp = 0;
    ge[gp++]=0x0A; ge[gp++]=9;
    ge[gp++]='r'; ge[gp++]='o'; ge[gp++]='u'; ge[gp++]='n'; ge[gp++]='d';
    ge[gp++]='_'; ge[gp++]='e'; ge[gp++]='n'; ge[gp++]='d';
    ge[gp++]=0x10; ge[gp++]=9;                                  /* п2 eventid=9 */
    ge[gp++]=0x1A; ge[gp++]=6;                                   /* п3 keys{...} */
    ge[gp++]=0x08; ge[gp++]=1;                                   /*   key: type=1 */
    ge[gp++]=0x12; ge[gp++]=2; ge[gp++]='c'; ge[gp++]='t';       /*   val_string="ct" */
    ge[gp++]=0x20; ge[gp++]=0xE8; ge[gp++]=0x07;                 /* п4 server_tick=1000 -> ДРОП */
    ge[gp++]=0x28; ge[gp++]=0x4D;                                /* п5 passthrough=77 -> S1 п4 */
    ip += c2b_write_varint(in + ip, 207); ip += c2b_write_varint(in + ip, gp);
    for (u32 k = 0; k < gp; k++) in[ip++] = ge[k];

    /* 205 GameEventList: descriptor{ eventid, name, keys{type,name} } — payload байт-в-байт */
    u8 gl[64]; u32 q = 0;
    gl[q++]=0x0A; gl[q++]=28;                                    /* п1 descriptors{...} */
    gl[q++]=0x08; gl[q++]=7;                                     /*   eventid=7 */
    gl[q++]=0x12; gl[q++]=12;                                    /*   name="player_death" */
    gl[q++]='p';gl[q++]='l';gl[q++]='a';gl[q++]='y';gl[q++]='e';gl[q++]='r';
    gl[q++]='_';gl[q++]='d';gl[q++]='e';gl[q++]='a';gl[q++]='t';gl[q++]='h';
    gl[q++]=0x1A; gl[q++]=10;                                   /*   keys{...} */
    gl[q++]=0x08; gl[q++]=1;                                     /*     type=1 */
    gl[q++]=0x12; gl[q++]=6;                                     /*     name="userid" */
    gl[q++]='u';gl[q++]='s';gl[q++]='e';gl[q++]='r';gl[q++]='i';gl[q++]='d';
    ip += c2b_write_varint(in + ip, 205); ip += c2b_write_varint(in + ip, q);
    for (u32 k = 0; k < q; k++) in[ip++] = gl[k];

    ip += c2b_write_varint(in + ip, 208); ip += c2b_write_varint(in + ip, 1); in[ip++] = 0xAA; /* SOS -> дроп */
    ip += c2b_write_varint(in + ip, 117); ip += c2b_write_varint(in + ip, 1); in[ip++] = 0x55; /* SayText -> мост G-2 */
    ip += c2b_write_varint(in + ip, 16);  ip += c2b_write_varint(in + ip, 1); in[ip++] = 0x01; /* bi_Rebroadcast -> дроп */

    printf("[t] translate GE-мост (in=%u bytes)\n", ip);
    i32 r = c2b_translate(in, ip, out, sizeof(out), &olen, &g_st);
    CHECK(r == 0, "ge: translate rc==0");
    CHECK(g_st.msgs_in == 5, "ge: msgs_in==5");
    CHECK(g_st.msgs_out == 3, "ge: msgs_out==3 (25,30,+um 23)");
    CHECK(g_st.dropped == 2, "ge: dropped==2 (208,16)");
    CHECK(g_st.unknown == 0, "ge: unknown==0 (117 больше не unknown — G-2 мост)");
    CHECK(g_st.um == 1, "ge: um==1 (117->svc 23)");
    CHECK(g_st.renumbered == 3, "ge: renumbered==3 (205->30, 207->25, 117->23)");

    /* ожидаемые байты: [25][23] payload-207-без-server_tick | [30][30] payload-205
     *                | [23][5] 08 05 12 01 55 (SayText->svc_UserMessage{1:5,2:0x55}) */
    u8 exp[80]; u32 ep = 0;
    ep += c2b_write_varint(exp + ep, 25); ep += c2b_write_varint(exp + ep, 23);
    exp[ep++]=0x0A; exp[ep++]=9;
    exp[ep++]='r'; exp[ep++]='o'; exp[ep++]='u'; exp[ep++]='n'; exp[ep++]='d';
    exp[ep++]='_'; exp[ep++]='e'; exp[ep++]='n'; exp[ep++]='d';
    exp[ep++]=0x10; exp[ep++]=9;
    exp[ep++]=0x1A; exp[ep++]=6; exp[ep++]=0x08; exp[ep++]=1;
    exp[ep++]=0x12; exp[ep++]=2; exp[ep++]='c'; exp[ep++]='t';
    exp[ep++]=0x20; exp[ep++]=0x4D;                             /* passthrough теперь п4 */
    ep += c2b_write_varint(exp + ep, 30); ep += c2b_write_varint(exp + ep, 30);
    for (u32 k = 0; k < 30; k++) exp[ep++] = gl[k];
    ep += c2b_write_varint(exp + ep, 23); ep += c2b_write_varint(exp + ep, 5);
    exp[ep++]=0x08; exp[ep++]=5; exp[ep++]=0x12; exp[ep++]=1; exp[ep++]=0x55;
    CHECK(olen == ep, "ge: out len");
    CHECK(olen == ep && memcmp(out, exp, ep) == 0, "ge: output bytes exact");
    if (olen != ep || memcmp(out, exp, ep) != 0) {
        printf("   got  (%u):", olen); for (u32 k = 0; k < olen && k < 80; k++) printf(" %02X", out[k]);
        printf("\n   want (%u):", ep); for (u32 k = 0; k < ep && k < 80; k++) printf(" %02X", exp[k]);
        printf("\n");
    }
}

/* фаза G-2: usermsg-мост — плоский wire -> svc_UserMessage(23){1 msg_type,2 data}.
 * Покрывает: ASIS (117/124 через renum — см. ниже), RENUM с repeated-merge (118),
 * RENUM дроп (130), CONV334 (float->int), CONV106 (fixed32->CMsgRGBA),
 * CONV110 (vec2+rgba+ретаги), дроп непарных зон (113 engine, 400 TE). */
/* фаза G-6 (t36/P208): фикстуры 208 и 207-sos -> валидный S1 svc_Sounds (симметричный ридер) */
static void test_translate_sos(void)
{
    u8 in[128], out[192]; u32 olen = 0, ip = 0;
    u32 s_before = g_synth_sounds;

    /* A: wire 208: guid=1000, hash=0x44332211, ent=7 (кэша G-4 нет -> origin нет),
     *    seed=3, start_time=1.0 */
    {
        u8 p[24]; u32 pp = 0;
        p[pp++]=0x08; p[pp++]=0xE8; p[pp++]=0x07;                 /* п1 guid */
        p[pp++]=0x15; p[pp++]=0x11; p[pp++]=0x22; p[pp++]=0x33; p[pp++]=0x44;
        p[pp++]=0x18; p[pp++]=0x07;                               /* п3 ent=7 */
        p[pp++]=0x20; p[pp++]=0x03;                               /* п4 seed */
        p[pp++]=0x35; p[pp++]=0x00; p[pp++]=0x00; p[pp++]=0x80; p[pp++]=0x3F;
        ip += c2b_write_varint(in + ip, 208); ip += c2b_write_varint(in + ip, pp);
        for (u32 k = 0; k < pp; k++) in[ip++] = p[k];
    }
    i32 r = c2b_translate(in, ip, out, sizeof(out), &olen, &g_st);
    CHECK(r == 0, "sos: translate rc==0");
    CHECK(g_st.msgs_in == 1 && g_st.msgs_out == 1, "sos: 208 -> 1 msg");
    CHECK(g_synth_sounds == s_before + 1, "sos: g_synth_sounds");

    /* симметричный ридер: [17][len]{ п2 sounds{...} } */
    {
        u32 q = 0, mt = 0, ml = 0;
        q += c2b_read_varint(out + q, olen, &mt);
        q += c2b_read_varint(out + q, olen - q, &ml);
        CHECK(mt == 17 && q + ml == olen, "sosA: конверт [17][len]");
        u32 ent = 0xFFFF, num = 0xFFFF, seed = 0xFFFF, guid = 0xFFFF, tag;
        while (q < olen) {
            u32 cq = c2b_read_varint(out + q, olen - q, &tag); q += cq;
            u32 f = tag >> 3, wt = tag & 7u;
            if (f == 2 && wt == 2) {
                u32 sl; q += c2b_read_varint(out + q, olen - q, &sl);
                u32 sq = q + sl;
                while (q < sq) {
                    u32 iq; iq = c2b_read_varint(out + q, sq - q, &tag); q += iq;
                    u32 iF = tag >> 3, iW = tag & 7u;
                    u32 v; iq = c2b_read_varint(out + q, sq - q, &v); q += iq;
                    if      (iF == 7  && iW == 0) ent  = v;
                    else if (iF == 11 && iW == 0) num  = v;
                    else if (iF == 14 && iW == 0) seed = v;
                    else if (iF == 18 && iW == 0) guid = v;
                }
            } else { CHECK(0, "sosA: неожиданное поле конверта (t36/audit08)"); return; }
        }
        CHECK(ent == 7,  "sosA: entity_index==7");
        CHECK(num == 0,  "sosA: sound_num==0 (stub)");
        CHECK(seed == 3, "sosA: random_seed==3");
        CHECK(guid == 1000, "sosA: guid==1000 (п18, S1 skip unknown)");
    }

    /* B: 207 GameEvent sos_start_soundevent, origin 1.5/-2.25/8.0 (float keys),
     *    guid=100 (val_long varint-кодировка wt0 — t36-расширение) */
    ip = 0; s_before = g_synth_sounds;
    {
        u8 ge[96]; u32 gp = 0;
        static const char nm[20] = "sos_start_soundevent";
        ge[gp++]=0x0A; ge[gp++]=20;
        for (u32 k = 0; k < 20; k++) ge[gp++] = (u8)nm[k];
        ge[gp++]=0x10; ge[gp++]=100;                              /* eventid */
        ge[gp++]=0x1A; ge[gp++]=7; ge[gp++]=0x08; ge[gp++]=2;     /* origin_x=1.5 */
        ge[gp++]=0x1D; ge[gp++]=0x00; ge[gp++]=0x00; ge[gp++]=0xC0; ge[gp++]=0x3F;
        ge[gp++]=0x1A; ge[gp++]=7; ge[gp++]=0x08; ge[gp++]=2;     /* origin_y=-2.25 */
        ge[gp++]=0x1D; ge[gp++]=0x00; ge[gp++]=0x00; ge[gp++]=0x10; ge[gp++]=0xC0;
        ge[gp++]=0x1A; ge[gp++]=7; ge[gp++]=0x08; ge[gp++]=2;     /* origin_z=8.0 */
        ge[gp++]=0x1D; ge[gp++]=0x00; ge[gp++]=0x00; ge[gp++]=0x00; ge[gp++]=0x41;
        ge[gp++]=0x1A; ge[gp++]=10; ge[gp++]=0x08; ge[gp++]=2;    /* guid key: type=2 */
        ge[gp++]=0x12; ge[gp++]=4; ge[gp++]='g'; ge[gp++]='u';
        ge[gp++]='i'; ge[gp++]='d';                               /*   name="guid" */
        ge[gp++]=0x20; ge[gp++]=100;                              /*   val_long=100 (wt0) */
        ge[gp++]=0x20; ge[gp++]=0xE9; ge[gp++]=0x06;              /* server_tick дроп */
        ip += c2b_write_varint(in + ip, 207); ip += c2b_write_varint(in + ip, gp);
        for (u32 k = 0; k < gp; k++) in[ip++] = ge[k];
    }
    r = c2b_translate(in, ip, out, sizeof(out), &olen, &g_st);
    CHECK(r == 0, "sosB: translate rc==0");
    CHECK(g_st.msgs_in == 1 && g_st.msgs_out == 2, "sosB: 207 -> 25 + synth 17");
    CHECK(g_synth_sounds == s_before + 1, "sosB: g_synth_sounds");
    {
        u32 q = 0, mt, tag; i32 ox = 0, oy = 0, oz = 0; u32 num = 0xFFFF, gd = 0xFFFF;
        q += c2b_read_varint(out + q, olen, &mt);                 /* 25 (renum 207) */
        CHECK(mt == 25, "sosB: первое msg == 25");
        q += c2b_read_varint(out + q, olen - q, &tag); q += tag;  /* скип payload */
        u32 c1 = c2b_read_varint(out + q, olen - q, &mt); q += c1;
        u32 c2 = c2b_read_varint(out + q, olen - q, &tag); q += c2;
        CHECK(mt == 17 && tag == olen - q, "sosB: второй msg == [17][len]");
        q += c2b_read_varint(out + q, tag, &tag);                 /* п2 tag */
        { u32 sl; q += c2b_read_varint(out + q, tag, &sl); }
        u32 sq = olen;
        while (q < sq) {
            u32 iq; iq = c2b_read_varint(out + q, sq - q, &tag); q += iq;
            u32 f = tag >> 3, v; iq = c2b_read_varint(out + q, sq - q, &v); q += iq;
            i32 d = (i32)((v >> 1) ^ (-(i32)(v & 1)));            /* unzigzag */
            if      (f == 1)  ox = d;
            else if (f == 2)  oy = d;
            else if (f == 3)  oz = d;
            else if (f == 11) num = v;
            else if (f == 18) gd = v;
        }
        CHECK(ox == 12 && oy == -18 && oz == 64, "sosB: origin zigzag 12/-18/64");
        CHECK(num == 0, "sosB: sound_num==0 (stub)");
        CHECK(gd == 100, "sosB: guid==100 (val_long wt0)");
    }
}

static void test_translate_um(void)
{
    u8 in[256], out[256]; u32 olen = 0, ip = 0;

    /* 118 SayText2 RENUM (repeated-merge): entityindex/chat/messagename/param1..4/
     * textallchat -> S1: ent_idx/chat/msg_name/params(repeated x4)/textallchat */
    u8 s2[64]; u32 sp = 0;
    s2[sp++]=0x08; s2[sp++]=7;                                   /* п1 entityindex=7 */
    s2[sp++]=0x10; s2[sp++]=1;                                   /* п2 chat=1 */
    s2[sp++]=0x1A; s2[sp++]=5;                                   /* п3 messagename */
    s2[sp++]='h'; s2[sp++]='e'; s2[sp++]='l'; s2[sp++]='l'; s2[sp++]='o';
    s2[sp++]=0x22; s2[sp++]=1; s2[sp++]='a';                     /* п4 param1 -> S1 п4 */
    s2[sp++]=0x2A; s2[sp++]=1; s2[sp++]='b';                     /* п5 param2 -> S1 п4 */
    s2[sp++]=0x32; s2[sp++]=1; s2[sp++]='c';                     /* п6 param3 -> S1 п4 */
    s2[sp++]=0x3A; s2[sp++]=1; s2[sp++]='d';                     /* п7 param4 -> S1 п4 */
    s2[sp++]=0x40; s2[sp++]=0;                                   /* п8 textallchat -> S1 п5 */
    ip += c2b_write_varint(in + ip, 118); ip += c2b_write_varint(in + ip, sp);
    for (u32 k = 0; k < sp; k++) in[ip++] = s2[k];

    /* 334 MatchEndConditions: fraglimit=10, mp_maxrounds=30, mp_winlimit=20,
     * mp_timelimit=float 5.0 (0x40A00000 -> LE 00 00 A0 40) -> varint 5 */
    u8 m[16]; u32 mp = 0;
    m[mp++]=0x08; m[mp++]=10; m[mp++]=0x10; m[mp++]=30; m[mp++]=0x18; m[mp++]=20;
    m[mp++]=0x25; m[mp++]=0x00; m[mp++]=0x00; m[mp++]=0xA0; m[mp++]=0x40;
    ip += c2b_write_varint(in + ip, 334); ip += c2b_write_varint(in + ip, mp);
    for (u32 k = 0; k < mp; k++) in[ip++] = m[k];

    /* 110 HudMsg: channel=2, x=1.5 (00 00 C0 3F), y=0.5 (00 00 00 3F),
     * color1=0x11223344 (LE 44 33 22 11 -> R=44 G=33 B=22 A=11), effect=1, text="txt" */
    u8 h[48]; u32 hp = 0;
    h[hp++]=0x08; h[hp++]=2;                                     /* п1 channel */
    h[hp++]=0x15; h[hp++]=0x00; h[hp++]=0x00; h[hp++]=0xC0; h[hp++]=0x3F;  /* п2 x */
    h[hp++]=0x1D; h[hp++]=0x00; h[hp++]=0x00; h[hp++]=0x00; h[hp++]=0x3F;  /* п3 y */
    h[hp++]=0x25; h[hp++]=0x44; h[hp++]=0x33; h[hp++]=0x22; h[hp++]=0x11;  /* п4 color1 */
    h[hp++]=0x30; h[hp++]=1;                                     /* п6 effect */
    h[hp++]=0x5A; h[hp++]=3; h[hp++]='t'; h[hp++]='x'; h[hp++]='t';        /* п11 text */
    ip += c2b_write_varint(in + ip, 110); ip += c2b_write_varint(in + ip, hp);
    for (u32 k = 0; k < hp; k++) in[ip++] = h[k];

    /* 130 SendAudio RENUM: soundname="radio" KEEP, stop=1 -> дроп */
    u8 a[16]; u32 ap = 0;
    a[ap++]=0x0A; a[ap++]=5; a[ap++]='r'; a[ap++]='a'; a[ap++]='d'; a[ap++]='i'; a[ap++]='o';
    a[ap++]=0x10; a[ap++]=1;
    ip += c2b_write_varint(in + ip, 130); ip += c2b_write_varint(in + ip, ap);
    for (u32 k = 0; k < ap; k++) in[ip++] = a[k];

    /* непарные: 113 (ColoredText, engine-зона без моста) и 400 (TE-зона) -> дроп */
    ip += c2b_write_varint(in + ip, 113); ip += c2b_write_varint(in + ip, 1); in[ip++] = 0x01;
    ip += c2b_write_varint(in + ip, 400); ip += c2b_write_varint(in + ip, 1); in[ip++] = 0x02;

    printf("[t] translate UM-мост (in=%u bytes)\n", ip);
    i32 r = c2b_translate(in, ip, out, sizeof(out), &olen, &g_st);
    CHECK(r == 0, "um: translate rc==0");
    CHECK(g_st.msgs_in == 6, "um: msgs_in==6");
    CHECK(g_st.msgs_out == 4, "um: msgs_out==4 (все в svc 23)");
    CHECK(g_st.um == 4, "um: um==4");
    CHECK(g_st.dropped == 2, "um: dropped==2 (113, 400)");
    CHECK(g_st.unknown == 0, "um: unknown==0");
    CHECK(g_st.renumbered == 4, "um: renumbered==4 (все 118/334/110/130 -> 23)");

    /* побайтовый ожидаемый выход */
    u8 exp[192]; u32 ep = 0;
    /* 118 -> 23: S1 payload {1:7, 2:1, 3:"hello", 4:"a", 4:"b", 4:"c", 4:"d", 5:0} */
    u8 e6[32]; u32 q6 = 0;
    e6[q6++]=0x08; e6[q6++]=7; e6[q6++]=0x10; e6[q6++]=1;
    e6[q6++]=0x1A; e6[q6++]=5; e6[q6++]='h'; e6[q6++]='e'; e6[q6++]='l'; e6[q6++]='l'; e6[q6++]='o';
    e6[q6++]=0x22; e6[q6++]=1; e6[q6++]='a';
    e6[q6++]=0x22; e6[q6++]=1; e6[q6++]='b';
    e6[q6++]=0x22; e6[q6++]=1; e6[q6++]='c';
    e6[q6++]=0x22; e6[q6++]=1; e6[q6++]='d';
    e6[q6++]=0x28; e6[q6++]=0;
    ep += c2b_write_varint(exp + ep, 23); ep += c2b_write_varint(exp + ep, 1 + 1 + 1 + 1 + q6);
    exp[ep++]=0x08; exp[ep++]=6; exp[ep++]=0x12; exp[ep++]=(u8)q6;
    for (u32 k = 0; k < q6; k++) exp[ep++] = e6[k];
    /* 334 -> 23: {1:10, 2:30, 3:20, 4:5} (payload 8 байт) */
    ep += c2b_write_varint(exp + ep, 23); ep += c2b_write_varint(exp + ep, 4 + 8);
    exp[ep++]=0x08; exp[ep++]=34; exp[ep++]=0x12; exp[ep++]=8;
    exp[ep++]=0x08; exp[ep++]=10; exp[ep++]=0x10; exp[ep++]=30;
    exp[ep++]=0x18; exp[ep++]=20; exp[ep++]=0x20; exp[ep++]=5;
    /* 110 -> 23: {1:2, 3:RGBA(44,33,22,11), 5:1, 11:"txt", 2:{1:1.5,2:0.5}}
     * (конвертер эмитит pos@2 в конце payload — порядок полей в protobuf не важен) */
    u8 e110[48]; u32 q1 = 0;
    e110[q1++]=0x08; e110[q1++]=2;
    e110[q1++]=0x1A; e110[q1++]=8;   /* clr1 CMsgRGBA{1:0x44,2:0x33,3:0x22,4:0x11} */
    e110[q1++]=0x08; e110[q1++]=0x44; e110[q1++]=0x10; e110[q1++]=0x33;
    e110[q1++]=0x18; e110[q1++]=0x22; e110[q1++]=0x20; e110[q1++]=0x11;
    e110[q1++]=0x28; e110[q1++]=1;   /* effect */
    e110[q1++]=0x5A; e110[q1++]=3; e110[q1++]='t'; e110[q1++]='x'; e110[q1++]='t';
    e110[q1++]=0x12; e110[q1++]=10;  /* pos CMsgVector2D{1:1.5,2:0.5} */
    e110[q1++]=0x0D; e110[q1++]=0x00; e110[q1++]=0x00; e110[q1++]=0xC0; e110[q1++]=0x3F;
    e110[q1++]=0x15; e110[q1++]=0x00; e110[q1++]=0x00; e110[q1++]=0x00; e110[q1++]=0x3F;
    ep += c2b_write_varint(exp + ep, 23); ep += c2b_write_varint(exp + ep, 4 + q1);
    exp[ep++]=0x08; exp[ep++]=8; exp[ep++]=0x12; exp[ep++]=(u8)q1;
    for (u32 k = 0; k < q1; k++) exp[ep++] = e110[k];
    /* 130 -> 23: {1:"radio"} */
    ep += c2b_write_varint(exp + ep, 23); ep += c2b_write_varint(exp + ep, 4 + 7);
    exp[ep++]=0x08; exp[ep++]=17; exp[ep++]=0x12; exp[ep++]=7;
    exp[ep++]=0x0A; exp[ep++]=5; exp[ep++]='r'; exp[ep++]='a'; exp[ep++]='d'; exp[ep++]='i'; exp[ep++]='o';
    CHECK(olen == ep, "um: out len");
    CHECK(olen == ep && memcmp(out, exp, ep) == 0, "um: output bytes exact");
    if (olen != ep || memcmp(out, exp, ep) != 0) {
        printf("   got  (%u):", olen); for (u32 k = 0; k < olen && k < 100; k++) printf(" %02X", out[k]);
        printf("\n   want (%u):", ep); for (u32 k = 0; k < ep && k < 100; k++) printf(" %02X", exp[k]);
        printf("\n");
    }
}


/* ---------- тест: S2 ClassInfo -> блоб SendTables + синтез (фаза G-3a) ---------- */
static u8 g_ci_out[256 * 1024];

static u32 ci_build_class(u8 *b, u32 id, const char *name)
{
    u32 n = 0, i = 0;
    u32 nl = 0;
    while (name[nl]) nl++;
    b[n++] = 0x08; n += c2b_write_varint(b + n, id);          /* f1 class_id */
    b[n++] = 0x1A; n += c2b_write_varint(b + n, nl);          /* f3 class_name */
    for (i = 0; i < nl; i++) b[n++] = (u8)name[i];
    return n;
}

static void test_translate_classinfo(void)
{
    u8 in[512]; u32 olen = 0, ip = 0, n = 0;
    printf("[t] translate_classinfo (G-3a)\n");

    /* payload S2 ClassInfo: 4 класса + класс без имени (последний скипается) */
    u8 c1[64], c2b[64], c3[64], c4[64], c5[64];
    u32 l1 = ci_build_class(c1, 0, "CCSPlayer");
    u32 l2 = ci_build_class(c2b, 1, "CAK47");
    u32 l3 = ci_build_class(c3, 2, "CCSGameRulesProxy");
    u32 l4 = ci_build_class(c4, 3, "CWorld");
    u32 l5 = ci_build_class(c5, 4, "CNoSuchClassEver");
    struct { const u8 *p; u32 l; } cls[] = { {c1,l1}, {c2b,l2}, {c3,l3}, {c4,l4}, {c5,l5} };
    u8 empty_cls[4]; u32 el = 0;
    empty_cls[el++] = 0x08; el += c2b_write_varint(empty_cls + el, 5); /* только id, без имени */

    for (u32 i = 0; i < 5; i++) {
        in[n++] = 0x12; n += c2b_write_varint(in + n, cls[i].l);
        for (u32 k = 0; k < cls[i].l; k++) in[n++] = cls[i].p[k];
    }
    in[n++] = 0x12; n += c2b_write_varint(in + n, el);
    for (u32 k = 0; k < el; k++) in[n++] = empty_cls[k];

    /* фрейм S2 svc_ClassInfo(42) */
    u8 msg[600]; u32 mn = 0;
    mn += c2b_write_varint(msg + mn, 42);
    mn += c2b_write_varint(msg + mn, n);
    for (u32 k = 0; k < n; k++) msg[mn++] = in[k];

    c2b_stats_t st; u32 before_miss = g_dt_misses;
    i32 r = c2b_translate(msg, mn, g_ci_out, sizeof(g_ci_out), &olen, &st);
    CHECK(r == 0, "classinfo: translate rc==0");
    CHECK(st.msgs_in == 1 && st.msgs_out == 1 && st.renumbered == 1,
          "classinfo: stats 1->1");

    /* обход блоба: DT_BLOB_TABLES кадров, все id==9 */
    u32 i = 0, cnt = 0, id = 0, len = 0, c;
    while (i < DT_BLOB_SIZE) {
        c = c2b_read_varint(g_ci_out + i, DT_BLOB_SIZE - i, &id);
        if (!c) break; i += c;
        c = c2b_read_varint(g_ci_out + i, DT_BLOB_SIZE - i, &len);
        if (!c) break; i += c;
        if (id != 9) break;
        if (len > DT_BLOB_SIZE - i) break;
        i += len; cnt++;
    }
    CHECK(cnt == DT_BLOB_TABLES && i == DT_BLOB_SIZE,
          "classinfo: 275 SendTable-кадров");

    /* S1 ClassInfo(10) сразу за блобом */
    u32 ci = i;
    c = c2b_read_varint(g_ci_out + ci, olen - ci, &id); ci += c;
    c = c2b_read_varint(g_ci_out + ci, olen - ci, &len); ci += c;
    CHECK(id == 10, "classinfo: S1 svc_ClassInfo(10)");
    CHECK(ci + len == olen, "classinfo: длина payload");
    /* классы: 5 записей (безымянный скипнут), id 0..4, dt-имена */
    const char *want_dt[5] = { "DT_CSPlayer", "DT_WeaponAK47",
                               "DT_CSGameRulesProxy", "DT_World",
                               "DT_NoSuchClassEver" };
    const char *want_cn[5] = { "CCSPlayer", "CAK47", "CCSGameRulesProxy",
                               "CWorld", "CNoSuchClassEver" };
    u32 ok_cls = 1, j = 0, idx = 0;
    while (j < len) {
        u32 t, l;
        c = c2b_read_varint(g_ci_out + ci + j, len - j, &t); if (!c) { ok_cls = 0; break; }
        j += c;
        if ((t & 7) != 2) { j++; continue; }
        c = c2b_read_varint(g_ci_out + ci + j, len - j, &l); if (!c) { ok_cls = 0; break; }
        j += c;
        /* sub: f1 varint, f2 str dt, f3 str cn */
        u32 sp2 = 0; const u8 *sb = g_ci_out + ci + j;
        u32 gid = 0xFFFFFFFFu; char gdt[80] = {0}, gcn[80] = {0};
        while (sp2 < l) {
            u32 t2, l2;
            c = c2b_read_varint(sb + sp2, l - sp2, &t2); if (!c) { ok_cls = 0; break; }
            sp2 += c;
            if ((t2 & 7) == 0) {
                u32 v; c = c2b_read_varint(sb + sp2, l - sp2, &v);
                if (!c) { ok_cls = 0; break; }
                sp2 += c;
                if ((t2 >> 3) == 1) gid = v;
            } else if ((t2 & 7) == 2) {
                c = c2b_read_varint(sb + sp2, l - sp2, &l2);
                if (!c || l2 > l - sp2) { ok_cls = 0; break; }
                sp2 += c;
                if ((t2 >> 3) == 2) { for (u32 q = 0; q < l2 && q < 79; q++) gdt[q] = (char)sb[sp2 + q]; }
                if ((t2 >> 3) == 3) { for (u32 q = 0; q < l2 && q < 79; q++) gcn[q] = (char)sb[sp2 + q]; }
                sp2 += l2;
            } else { ok_cls = 0; break; }
        }
        j += l;
        if (idx >= 5 || gid != idx ||
            strcmp(gdt, want_dt[idx]) != 0 ||
            strcmp(gcn, want_cn[idx]) != 0) { ok_cls = 0; break; }
        idx++;
    }
    CHECK(ok_cls && idx == 5, "classinfo: 5 классов, id/dt/name побайтно");
    CHECK(g_class_id_map_n == 5 && g_class_id_map[1] == 1 && g_class_id_map[4] == 4,
          "classinfo: карта s2->s1 id");
    CHECK(g_dt_misses == before_miss + 1, "classinfo: dt-промах учтён (fake-класс)");
    CHECK(g_blob_emits >= 1, "classinfo: счётчик эмиссий блоба");
    printf("  [i] dt_misses=%u class_map_n=%u\n", g_dt_misses, g_class_id_map_n);
}

/* ---------- тест: парсер FlattenedSerializer (фаза G-3b) ---------- */
static u32 fsv_sym(u8 *b, const char *s)
{
    u32 n = 0, l = 0;
    while (s[l]) l++;
    b[n++] = (2u << 3) | 2;
    n += c2b_write_varint(b + n, l);
    for (u32 i = 0; i < l; i++) b[n++] = (u8)s[i];
    return n;
}

static u32 fsv_ser(u8 *b, u32 name_sym, u32 ver, const u32 *idx, u32 n)
{
    u8 tmp[256], sub[640]; u32 t = 0, s = 0;
    for (u32 i = 0; i < n; i++) t += c2b_write_varint(tmp + t, idx[i]);
    sub[s++] = (1u << 3); s += c2b_write_varint(sub + s, name_sym);
    sub[s++] = (2u << 3); s += c2b_write_varint(sub + s, ver);
    sub[s++] = (3u << 3) | 2;
    s += c2b_write_varint(sub + s, t);
    for (u32 i = 0; i < t; i++) sub[s++] = tmp[i];
    u32 o = c2b_write_varint(b, (1u << 3) | 2);
    o += c2b_write_varint(b + o, s);
    for (u32 i = 0; i < s; i++) b[o++] = sub[i];
    return o;
}

typedef struct {
    u32 type_sym, name_sym;
    i32 bits;            /* -1 = нет */
    u32 enc_sym;         /* 0 = нет (var_encoder_sym — ОРДИНАЛ символа) */
    u32 ser_name_sym;    /* 0 = нет */
    const u8 *lo_hi;     /* 0 = нет: 8 байт LE (lo,hi) fixed32 */
    u32 poly_sym1;       /* 0 = нет: одна poly-альтернатива (G-4c тест) */
} fsv_fld_spec_t;

static u32 fsv_field(u8 *b, const fsv_fld_spec_t *sp)
{
    u8 sub[256]; u32 s = 0;
    sub[s++] = (1u << 3); s += c2b_write_varint(sub + s, sp->type_sym);
    sub[s++] = (2u << 3); s += c2b_write_varint(sub + s, sp->name_sym);
    if (sp->bits >= 0) { sub[s++] = (3u << 3); s += c2b_write_varint(sub + s, (u32)sp->bits); }
    if (sp->lo_hi) {
        sub[s++] = (4u << 3) | 5; for (u32 i = 0; i < 4; i++) sub[s++] = sp->lo_hi[i];
        sub[s++] = (5u << 3) | 5; for (u32 i = 4; i < 8; i++) sub[s++] = sp->lo_hi[i];
    }
    if (sp->ser_name_sym) { sub[s++] = (7u << 3); s += c2b_write_varint(sub + s, sp->ser_name_sym); }
    if (sp->enc_sym) { sub[s++] = (10u << 3); s += c2b_write_varint(sub + s, sp->enc_sym); }
    if (sp->poly_sym1) {
        u8 pb[16]; u32 pn2 = 0;
        pb[pn2++] = (1u << 3); pn2 += c2b_write_varint(pb + pn2, sp->poly_sym1);
        sub[s++] = (11u << 3) | 2; s += c2b_write_varint(sub + s, pn2);
        for (u32 i = 0; i < pn2; i++) sub[s++] = pb[i];
    }
    u32 o = c2b_write_varint(b, (3u << 3) | 2);
    o += c2b_write_varint(b + o, s);
    for (u32 i = 0; i < s; i++) b[o++] = sub[i];
    return o;
}

static void test_fsv(void)
{
    printf("[t] fsv_parse (G-3b)\n");
    u8 m[1024]; u32 n = 0;

    /* символы сообщения 1 (порядок = ординал) */
    const char *syms[] = {
        "CCSPlayer", "CBodyComponent", "m_angRotation", "QAngle",
        "m_vecVelocity", "Vector", "coord", "m_nHealth", "int32",
        "m_hModel", "CStrongHandle< InfoForResourceTypeCModel >", "fixed64",
        "m_pBodyComponent", "CBodyComponent*", "m_szClan", "char[16]",
        "m_iAmmo", "CNetworkUtlVectorBase< CHandle< CBaseCombatWeapon > >",
        "m_iClip1", "m_flPoseParameter", "float32",
        "CNetworkedQuantizedFloat", "m_flQuant" };
    for (u32 i = 0; i < sizeof(syms) / sizeof(syms[0]); i++)
        n += fsv_sym(m + n, syms[i]);

    /* coord-параметры (f4) */
    {
        u8 cp[16]; u32 c = 0;
        cp[c++] = (1u << 3); c += c2b_write_varint(cp + c, 14);
        cp[c++] = (2u << 3); c += c2b_write_varint(cp + c, 5);
        cp[c++] = (6u << 3); c += c2b_write_varint(cp + c, 11);
        m[n++] = (4u << 3) | 2; n += c2b_write_varint(m + n, c);
        for (u32 i = 0; i < c; i++) m[n++] = cp[i];
    }

    /* поля (ординалы 0..9) */
    static const u8 lohi01[8] = { 0,0,0,0, 0,0,0x80,0x3F };  /* lo=0, hi=1.0 */
    fsv_fld_spec_t flds[10] = {
        { 3,  2,  -1, 0,     0, 0 },         /* 0 m_angRotation QAngle */
        { 5,  4,  -1, 6,     0, 0 },         /* 1 m_vecVelocity Vector/enc=coord(sym6) */
        { 8,  7,  -1, 0,     0, 0 },         /* 2 m_nHealth int32 */
        { 10, 9,  -1, 11,    0, 0 },         /* 3 m_hModel CStrongHandle/enc=fixed64(sym11) */
        { 13, 12, -1, 0,     1, 0 },         /* 4 m_pBodyComponent CBodyComponent* */
        { 15, 14, -1, 0,     0, 0 },         /* 5 m_szClan char[16] */
        { 17, 16, -1, 0,     0, 0 },         /* 6 m_iAmmo CNetworkUtlVectorBase */
        { 8,  18, -1, 0,     0, 0 },         /* 7 m_iClip1 int32 */
        { 20, 19, 11, 0,     0, lohi01 },    /* 8 m_flPoseParameter float quant */
        { 21, 22, 8,  0,     0, 0 },         /* 9 m_flQuant CNetworkedQuantizedFloat */
    };
    for (u32 i = 0; i < 10; i++) n += fsv_field(m + n, &flds[i]);

    /* сериализаторы: CBodyComponent, CCSPlayer(9 полей), замена CBodyComponent v5 */
    u32 iv[] = { 0 };
    u32 i1[9]; for (u32 i = 0; i < 9; i++) i1[i] = i + 1;  /* ординалы 1..9 (0 — поле CBodyComponent) */
    n += fsv_ser(m + n, 1, 0, iv, 1);
    n += fsv_ser(m + n, 0, 0, i1, 9);
    n += fsv_ser(m + n, 1, 5, iv, 1);

    u32 msg1_field_base = g_fsv_field_n;
    c2b_fsv_parse(m, n);
    CHECK(g_fsv_err == 1, "fsv: err==1 (garbage-41 из test_translate; FSV-хук теперь и на 41)");
    CHECK(g_fsv_msgs >= 1, "fsv: msg counted");
    CHECK(g_fsv_ser_n == 2, "fsv: 2 сериализатора (replace по имени)");
    CHECK(g_fsv_msgsym_n == 23, "fsv: 23 символа");
    CHECK(g_fsv_coord.int_bits == 14 && g_fsv_coord.angle_bits == 11,
          "fsv: coord-параметры сохранены");
    CHECK(c2b_fsv_find_ser("CCSPlayer") == 1, "fsv: find CCSPlayer==1");
    CHECK(c2b_fsv_find_ser("CBodyComponent") == 0, "fsv: find CBodyComponent==0");
    CHECK(g_fsv_ser[0].ver == 5 && g_fsv_ser[0].n == 1, "fsv: CBodyComponent заменён на v5");
    CHECK(g_fsv_ser[1].ver == 0 && g_fsv_ser[1].n == 9, "fsv: CCSPlayer v0 n=9");

    /* обход полей CCSPlayer через fields_index -> пул */
    const c2b_fsv_ser_t *S = &g_fsv_ser[1];
    u32 pid[9];
    for (u32 i = 0; i < 9; i++)
        pid[i] = S->fbase + g_fsv_idx[S->idx_off + i];
    CHECK(pid[0] == msg1_field_base + 1, "fsv: ref[0] -> pool ordinal 1");
    for (u32 i = 1; i < 9; i++)
        CHECK(pid[i] == pid[0] + i, "fsv: refs монотонны");

    const c2b_fsv_field_t *F;
    F = &g_fsv_field[pid[0]];
    CHECK(F->model == SM_SIMPLE && F->dec == DT_COORD && F->base_id == BT_VEC3,
          "fsv: m_vecVelocity = Simple/COORD/Vec3");
    F = &g_fsv_field[pid[1]];
    CHECK(F->model == SM_SIMPLE && F->dec == DT_VARINT_S, "fsv: m_nHealth = Simple/VARINT_S");
    F = &g_fsv_field[pid[2]];
    CHECK(F->base_id == BT_U64 && F->dec == DT_FIXED64 && F->pointer == 0,
          "fsv: m_hModel = U64/FIXED64 (CStrongHandle)");
    F = &g_fsv_field[pid[3]];
    CHECK(F->model == SM_FIXEDTAB && F->pointer == 1 &&
          F->ser_id == 0 && F->ser_name != 0,
          "fsv: m_pBodyComponent = FixedTable(ser CBodyComponent)");
    F = &g_fsv_field[pid[4]];
    CHECK(F->base_id == BT_STR && F->count == 16 && F->model == SM_SIMPLE &&
          F->dec == DT_STR,
          "fsv: m_szClan char[16] = Simple/STR (base char -> не FixedArray)");
    F = &g_fsv_field[pid[5]];
    CHECK(F->model == SM_VARARR && F->gen_id == BT_HND && F->dec == DT_VARINT_U,
          "fsv: m_iAmmo = VariableArray(CHandle)");
    F = &g_fsv_field[pid[6]];
    CHECK(F->dec == DT_AMMO, "fsv: m_iClip1 = AMMO (fieldNameDecoders)");
    F = &g_fsv_field[pid[7]];
    CHECK(F->dec == DT_QUANT && F->bits == 11, "fsv: m_flPoseParameter = QUANT(11)");
    F = &g_fsv_field[pid[8]];
    CHECK(F->dec == DT_QUANT && F->base_id == BT_QF, "fsv: m_flQuant = QUANT (CNetworkedQuantizedFloat)");

    /* CBodyComponent v5: ссылка на ordinal 0 */
    F = &g_fsv_field[g_fsv_ser[0].fbase + g_fsv_idx[g_fsv_ser[0].idx_off]];
    CHECK(F->model == SM_SIMPLE && F->dec == DT_Q_DEFAULT && F->base_id == BT_QANGLE,
          "fsv: m_angRotation = Simple/QANGLE_DEFAULT");

    /* сообщение 2: CCSPlayer v2, свой словарь символов и поле */
    u8 m2[256]; u32 n2 = 0;
    n2 += fsv_sym(m2 + n2, "CCSPlayer");
    n2 += fsv_sym(m2 + n2, "m_nHealth");
    n2 += fsv_sym(m2 + n2, "int32");
    fsv_fld_spec_t f2s = { 2, 1, -1, 0, 0, 0 };
    n2 += fsv_field(m2 + n2, &f2s);
    n2 += fsv_ser(m2 + n2, 0, 2, iv, 1);
    u32 msg2_field_base = g_fsv_field_n;
    c2b_fsv_parse(m2, n2);
    CHECK(g_fsv_err == 1, "fsv2: err==1 (garbage-41 из test_translate; FSV-хук теперь и на 41)");
    CHECK(g_fsv_ser_n == 2, "fsv2: число сериализаторов прежнее");
    CHECK(g_fsv_ser[1].ver == 2 && g_fsv_ser[1].n == 1, "fsv2: CCSPlayer -> v2, 1 поле");
    CHECK(g_fsv_ser[1].fbase == msg2_field_base, "fsv2: база пула = новое сообщение");
    F = &g_fsv_field[g_fsv_ser[1].fbase + g_fsv_idx[g_fsv_ser[1].idx_off]];
    CHECK(F->dec == DT_VARINT_S && F->name != 0 &&
          c2b_streq(g_fsv_arena + F->name, "m_nHealth"),
          "fsv2: поле v2 резолвится в новом пуле");

    /* уровень translate: кадр 51 -> парс+дроп; кадр 40 -> max_classes */
    u8 in[64], out[64]; u32 olen = 0, ip = 0;
    u8 tiny[16]; u32 tn = 0;
    tn += fsv_sym(tiny + tn, "XSer");
    u32 i3 = 7;
    tn += fsv_ser(tiny + tn, 0, 0, &i3, 1);
    ip += c2b_write_varint(in + ip, 51); ip += c2b_write_varint(in + ip, tn);
    for (u32 k = 0; k < tn; k++) in[ip++] = tiny[k];
    u8 si[8]; u32 sn = 0;
    si[sn++] = (11u << 3); sn += c2b_write_varint(si + sn, 64);
    ip += c2b_write_varint(in + ip, 40); ip += c2b_write_varint(in + ip, sn);
    for (u32 k = 0; k < sn; k++) in[ip++] = si[k];

    u32 fsv_before = g_fsv_msgs;
    i32 r = c2b_translate(in, ip, out, sizeof(out), &olen, &g_st);
    CHECK(r == 0, "fsv: translate rc==0");
    CHECK(g_fsv_msgs == fsv_before + 1, "fsv: translate парсит 51");
    CHECK(g_st.dropped == 1, "fsv: 51 из потока дропнут");
    CHECK(g_fsv_max_classes == 238, "fsv: ServerInfo f11 -> max_classes (R37 кламп 238..512)");
    CHECK(c2b_fsv_find_ser("XSer") >= 0, "fsv: XSer зарегистрирован через translate");
}

/* ---------- тест: PacketEntities S2->S1 (фаза G-4) ---------- */

/* S2-энкодер синтетики: huffman-код op (MSB-first = порядок чтения декодером) */
static void g4e_huff(c2b_bw_t *w, u32 op)
{
    u32 code = g_fph_codes[op].code, len = g_fph_codes[op].len;
    for (u32 i = 0; i < len; i++)
        c2b_bw_bit(w, (code >> (len - 1 - i)) & 1);
}

/* инверсия c2b_br_ubitvar_fp (payload опов PlusN/PushN/...) */
static void g4e_uvfp(c2b_bw_t *w, u32 v)
{
    if (v < 4) { c2b_bw_bit(w, 1); c2b_bw_bits(w, v, 2); }
    else if (v < 16) { c2b_bw_bit(w, 0); c2b_bw_bit(w, 1); c2b_bw_bits(w, v, 4); }
    else if (v < 1024) { c2b_bw_bit(w, 0); c2b_bw_bit(w, 0); c2b_bw_bit(w, 1); c2b_bw_bits(w, v, 10); }
    else { c2b_bw_bit(w, 0); c2b_bw_bit(w, 0); c2b_bw_bit(w, 0); c2b_bw_bit(w, 1); c2b_bw_bits(w, v, 17); }
}

static void g4e_coord(c2b_bw_t *w, float v)
{
    u32 neg = v < 0.0f;
    float a = neg ? -v : v;
    u32 iv = (u32)a, fv = (u32)((a - (float)iv) * 32.0f + 0.5f);
    c2b_bw_bit(w, iv ? 1 : 0);
    c2b_bw_bit(w, fv ? 1 : 0);
    if (!iv && !fv) return;
    c2b_bw_bit(w, neg);
    if (iv) c2b_bw_bits(w, iv - 1, 14);
    if (fv) c2b_bw_bits(w, fv, 5);
}

static void g4e_varu(c2b_bw_t *w, u32 v)
{
    u8 vb[5]; u32 vn = c2b_write_varint(vb, v);
    for (u32 i = 0; i < vn; i++) c2b_bw_bits(w, vb[i], 8);
}

/* зеркало состояния путей энкодера */
typedef struct { i32 path[7]; i32 last; } g4e_fp_t;

static void g4e_fp_reset(g4e_fp_t *fp)
{
    fp->path[0] = -1;
    fp->path[1] = fp->path[2] = fp->path[3] = 0;
    fp->path[4] = fp->path[5] = fp->path[6] = 0;
    fp->last = 0;
}

/* доводим путь до [p0] / [p0,p1] через PlusOne/Push/PopAllButOnePlusOne */
static void g4e_target0(c2b_bw_t *w, g4e_fp_t *fp, i32 p0)
{
    while (fp->last > 0) { g4e_huff(w, 27); fp->last--; fp->path[fp->last]++; }
    while (fp->path[0] < p0) { g4e_huff(w, 0); fp->path[0]++; }
}

/* push на уровень с заданным значением: op6 (left_inc=0) / op8 (=1) —
 * ОДИН снапшот, без промежуточного пути (каждый снапшот требует значения!) */
static void g4e_push(c2b_bw_t *w, g4e_fp_t *fp, i32 left_inc, i32 v)
{
    if (left_inc) { g4e_huff(w, 8); fp->path[fp->last]++; }
    else          { g4e_huff(w, 6); }
    fp->last++;
    fp->path[fp->last] = v;
    g4e_uvfp(w, (u32)v);
}

static void test_g4(void)
{
    printf("[t] packetentities S2->S1 (G-4)\n");

    /* --- 1. FSV-схема: CBodyComponentS1 (cell+vec) + CCSPlayer --- */
    u8 m[1024]; u32 n = 0;
    const char *syms[] = {
        "CCSPlayer",                                 /* 0  */
        "CBodyComponentS1",                          /* 1  */
        "m_cellX", "uint32",                         /* 2,3 */
        "m_cellY",                                   /* 4  */
        "m_cellZ",                                   /* 5  */
        "m_vecX", "float32", "coord",                /* 6,7,8 */
        "m_vecY",                                    /* 9  */
        "m_vecZ",                                    /* 10 */
        "m_iHealth", "int32",                        /* 11,12 */
        "m_vecVelocity", "Vector",                   /* 13,14 */
        "m_hMyWeapons",
        "CNetworkUtlVectorBase< CHandle< CBaseCombatWeapon > >",  /* 15,16 */
        "m_szClan", "char",                          /* 17,18 */
        "m_flPoseParameter", "float32[4]",           /* 19,20 */
        "m_iClip1",                                  /* 21 */
        "m_pBody", "CBodyComponentS1*",              /* 22,23 */
    };
    for (u32 i = 0; i < sizeof(syms) / sizeof(syms[0]); i++)
        n += fsv_sym(m + n, syms[i]);

    fsv_fld_spec_t flds[13] = {
        { 3,  2,  -1, 0, 0, 0 },    /* 0  m_cellX uint32 -> VARINT_U */
        { 3,  4,  -1, 0, 0, 0 },    /* 1  m_cellY */
        { 3,  5,  -1, 0, 0, 0 },    /* 2  m_cellZ */
        { 7,  6,  -1, 8, 0, 0 },    /* 3  m_vecX float32/coord -> COORD */
        { 7,  9,  -1, 8, 0, 0 },    /* 4  m_vecY */
        { 7,  10, -1, 8, 0, 0 },    /* 5  m_vecZ */
        { 12, 11, -1, 0, 0, 0 },    /* 6  m_iHealth int32 -> VARINT_S */
        { 14, 13, -1, 0, 0, 0 },    /* 7  m_vecVelocity Vector -> NOSCALE x3 */
        { 16, 15, -1, 0, 0, 0 },    /* 8  m_hMyWeapons CUtlVector -> VARARR */
        { 18, 17, -1, 0, 0, 0 },    /* 9  m_szClan char -> STR */
        { 20, 19, -1, 0, 0, 0 },    /* 10 m_flPoseParameter float32[4] -> FIXEDARR */
        { 12, 21, -1, 0, 0, 0 },    /* 11 m_iClip1 int32 -> AMMO */
        { 23, 22, -1, 0, 1, 0 },    /* 12 m_pBody CBodyComponentS1* -> FIXEDTAB */
    };
    for (u32 i = 0; i < 13; i++) n += fsv_field(m + n, &flds[i]);

    u32 ivc[6] = { 0, 1, 2, 3, 4, 5 };               /* CBodyCompS1: cell/vec */
    u32 ivp[7] = { 12, 6, 7, 8, 9, 10, 11 };         /* CCSPlayer */
    n += fsv_ser(m + n, 1, 0, ivc, 6);
    n += fsv_ser(m + n, 0, 0, ivp, 7);
    c2b_fsv_parse(m, n);
    CHECK(g_fsv_err == 1, "g4: fsv err==1 (garbage-41 из test_translate; FSV-хук теперь и на 41)");
    i32 serC = c2b_fsv_find_ser("CCSPlayer");
    i32 serB = c2b_fsv_find_ser("CBodyComponentS1");
    CHECK(serC >= 0 && serB >= 0, "g4: сериализаторы зарегистрированы");
    CHECK(g_fsv_ser[serC].n == 7 && g_fsv_ser[serB].n == 6, "g4: n полей ser");
    CHECK(g_fsv_field[g_fsv_ser[serB].fbase + g_fsv_idx[g_fsv_ser[serB].idx_off + 3]].dec == DT_COORD,
          "g4: m_vecX = COORD");

    /* --- 2. ширина class_id S2 --- */
    g_fsv_max_classes = 64;

    /* --- 3. S2 ClassInfo -> синтез (класс 1 = CCSPlayer) --- */
    {
        static u8 ci_in[64], ci_out[256 * 1024];
        u32 cn = 0;
        cn += c2b_write_varint(ci_in + cn, (1u << 3) | 0);   /* f1 create_on_client */
        cn += c2b_write_varint(ci_in + cn, 1);
        u8 inner[64]; u32 inn = 0;
        inner[inn++] = (1u << 3); inn += c2b_write_varint(inner + inn, 1);
        const char *nm = "CCSPlayer";
        u32 l = 0; while (nm[l]) l++;
        inner[inn++] = (3u << 3) | 2; inn += c2b_write_varint(inner + inn, l);
        for (u32 i = 0; i < l; i++) inner[inn++] = (u8)nm[i];
        cn += c2b_write_varint(ci_in + cn, (2u << 3) | 2);
        cn += c2b_write_varint(ci_in + cn, inn);
        for (u32 i = 0; i < inn; i++) ci_in[cn++] = inner[i];

        u8 in[80]; u32 il = 0;
        il += c2b_write_varint(in + il, 42);
        il += c2b_write_varint(in + il, cn);
        for (u32 i = 0; i < cn; i++) in[il++] = ci_in[i];
        u32 olen = 0;
        i32 rc = c2b_translate(in, il, ci_out, sizeof(ci_out), &olen, &g_st);
        CHECK(rc == 0, "g4: classinfo translate rc==0");
        CHECK(g_cls_emitted == 1 && g_class_id_map[1] == 0,
              "g4: класс 1 -> emit 0, g_cls_emitted=1");
        CHECK(g_class_dt_map[1] != 0xFFFFu, "g4: класс 1 -> DT_CSPlayer");
        CHECK(g_class_ser_map[1] == (u16)serC, "g4: класс 1 -> ser CCSPlayer");
    }

    /* --- 4. слоты DT_CSPlayer --- */
    u32 slot_health = 0xFFFFFFFFu, slot_mhp = 0xFFFFFFFFu, slot_org = 0xFFFFFFFFu;
    u32 slot_vel0 = 0xFFFFFFFFu, slot_clan = 0xFFFFFFFFu, slot_pose = 0xFFFFFFFFu;
    {
        const dt_entry *dte = c2b_dt_find(c2b_fnv1a("DT_CSPlayer"));
        CHECK(dte != 0, "g4: DT_CSPlayer в блобе");
        u32 off = 0, cnt = 0;
        CHECK(c2b_s1_slots_of((u32)(dte - g_dt_index), &off, &cnt) == 0 && cnt == 717,
              "g4: слоты DT_CSPlayer = 717");
        slot_health = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_iHealth"));
        slot_mhp    = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_hMyWeapons"));
        slot_org    = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_vecOrigin"));
        slot_vel0   = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_vecVelocity[0]"));
        slot_clan   = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_szClan"));
        slot_pose   = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_flPoseParameter"));
        printf("  [i] slots: health=%u mhp=%u org=%u vel0=%u clan=%u pose=%u\n",
               slot_health, slot_mhp, slot_org, slot_vel0, slot_clan, slot_pose);
        CHECK(slot_health != 0xFFFFFFFFu && slot_org != 0xFFFFFFFFu &&
              slot_mhp != 0xFFFFFFFFu && slot_vel0 != 0xFFFFFFFFu,
              "g4: ключевые слоты найдены");
    }

    /* --- 5. S2-битстрим: create(4), update(4), leave(4) --- */
    static u8 ent[8192];
    c2b_bw_t w;
    w.buf = ent; w.cap = sizeof(ent); w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
    g4e_fp_t fp;

    /* entity 4 CREATE: cmd=2, class=1, serial=0x2A.
     * ФАЗА 1: все пути; ФАЗА 2: все значения (порядок путей). */
    c2b_bw_ubitvar(&w, 4);
    c2b_bw_bits(&w, 2, 2);
    c2b_bw_bits(&w, 1, c2b_g4_class_bits(64));       /* 7 бит */
    c2b_bw_bits(&w, 0x2A, 17);
    g4e_varu(&w, 0);                                 /* extra varuint32 = 0 */
    g4e_fp_reset(&fp);
    /* пути: [0] [0,0..5] [1] [2] [3] [3,0..2] [4] [5,1] [6] finish */
    g4e_target0(&w, &fp, 0);                         /* [0] m_pBody */
    g4e_push(&w, &fp, 0, 0);                         /* [0,0] m_cellX */
    for (i32 i = 1; i < 6; i++) { g4e_huff(&w, 0); fp.path[1]++; }   /* [0,1..5] */
    g4e_huff(&w, 29); fp.last--; fp.path[0]++;       /* [1] m_iHealth */
    g4e_huff(&w, 0); fp.path[0]++;                   /* [2] m_vecVelocity */
    g4e_huff(&w, 0); fp.path[0]++;                   /* [3] m_hMyWeapons */
    g4e_push(&w, &fp, 0, 0);                         /* [3,0] */
    for (i32 i = 1; i < 3; i++) { g4e_huff(&w, 0); fp.path[1]++; }   /* [3,1..2] */
    g4e_huff(&w, 29); fp.last--; fp.path[0]++;       /* [4] m_szClan */
    g4e_push(&w, &fp, 1, 1);                         /* [5,1] m_flPoseParameter[1] */
    g4e_huff(&w, 29); fp.last--; fp.path[0]++;       /* [6] m_iClip1 */
    g4e_huff(&w, 39);                                /* finish */
    /* значения по порядку путей */
    c2b_bw_bit(&w, 1);                               /* [0] pointer active */
    g4e_varu(&w, 100); g4e_varu(&w, 100); g4e_varu(&w, 100);      /* cell XYZ */
    g4e_coord(&w, 3.5f); g4e_coord(&w, -3.25f); g4e_coord(&w, 10.0f);  /* vec XYZ */
    g4e_varu(&w, 1337u << 1);                        /* [1] zigzag */
    c2b_bw_bits(&w, c2b_f32_to_bits(1.0f), 32);
    c2b_bw_bits(&w, c2b_f32_to_bits(-2.0f), 32);
    c2b_bw_bits(&w, c2b_f32_to_bits(0.25f), 32);     /* [2] velocity */
    g4e_varu(&w, 3);                                 /* [3] count */
    g4e_varu(&w, 0x1234u); g4e_varu(&w, 0x5678u); g4e_varu(&w, 0x9ABCu);
    c2b_bw_bits(&w, 'G', 8); c2b_bw_bits(&w, 'G', 8); c2b_bw_bits(&w, 0, 8);  /* [4] */
    c2b_bw_bits(&w, c2b_f32_to_bits(0.5f), 32);      /* [5,1] */
    g4e_varu(&w, 31);                                /* [6] m_iClip1 (wire) */

    /* entity 9 CREATE (второй в пакете, дельта 4): health=500 */
    c2b_bw_ubitvar(&w, 4);
    c2b_bw_bits(&w, 2, 2);
    c2b_bw_bits(&w, 1, c2b_g4_class_bits(64));
    c2b_bw_bits(&w, 0x2B, 17);
    g4e_varu(&w, 0);
    g4e_fp_reset(&fp);
    g4e_huff(&w, 0); fp.path[0] = 0;                 /* [0] */
    g4e_huff(&w, 0); fp.path[0] = 1;                 /* [1] */
    g4e_huff(&w, 39);
    c2b_bw_bit(&w, 1);                               /* [0] pointer bool */
    g4e_varu(&w, 500u << 1);                         /* [1] health */
    u32 ent_n1 = c2b_bw_flush(&w);
    CHECK(w.ovf == 0, "g4: S2-энкодер (msg1) без оверфлоу");

    /* === msg1 proto (собираем ДО перезаписи буфера msg2) === */
    static u8 in1[16384]; u32 il1 = 0;
    {
        u8 pe[16384]; u32 pn = 0;
        pe[pn++] = (1u << 3); pn += c2b_write_varint(pe + pn, 64);
        pe[pn++] = (2u << 3); pn += c2b_write_varint(pe + pn, 2);
        pe[pn++] = (3u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (7u << 3) | 2; pn += c2b_write_varint(pe + pn, ent_n1);
        for (u32 i = 0; i < ent_n1; i++) pe[pn++] = ent[i];
        il1 += c2b_write_varint(in1 + il1, 55);
        il1 += c2b_write_varint(in1 + il1, pn);
        for (u32 i = 0; i < pn; i++) in1[il1++] = pe[i];
    }

    /* === сообщение 2: update 4 (d=4), leave 9 (d=4) === */
    w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
    /* entity 4 UPDATE */
    c2b_bw_ubitvar(&w, 4);
    c2b_bw_bits(&w, 0, 2);
    g4e_fp_reset(&fp);
    g4e_huff(&w, 0); fp.path[0] = 0;                 /* [0] */
    g4e_huff(&w, 0); fp.path[0] = 1;                 /* [1] */
    g4e_huff(&w, 0); fp.path[0] = 2;                 /* [2] */
    g4e_huff(&w, 39);
    c2b_bw_bit(&w, 1);                               /* [0] pointer bool */
    g4e_varu(&w, 1000u << 1);                        /* [1] health */
    c2b_bw_bits(&w, c2b_f32_to_bits(4.5f), 32);      /* [2] velocity */
    c2b_bw_bits(&w, c2b_f32_to_bits(-4.5f), 32);
    c2b_bw_bits(&w, c2b_f32_to_bits(0.0f), 32);
    /* entity 9 LEAVE (без delete) */
    c2b_bw_ubitvar(&w, 4);
    c2b_bw_bits(&w, 1, 2);
    u32 ent_n = c2b_bw_flush(&w);
    CHECK(w.ovf == 0, "g4: S2-энкодер (msg2) без оверфлоу");



    /* === msg2 proto: f2 updated=2 === */
    u8 pe2[16384]; u32 pn2 = 0;
    pe2[pn2++] = (1u << 3); pn2 += c2b_write_varint(pe2 + pn2, 64);
    pe2[pn2++] = (2u << 3); pn2 += c2b_write_varint(pe2 + pn2, 2);
    pe2[pn2++] = (3u << 3); pn2 += c2b_write_varint(pe2 + pn2, 1);
    pe2[pn2++] = (7u << 3) | 2; pn2 += c2b_write_varint(pe2 + pn2, ent_n);
    for (u32 i = 0; i < ent_n; i++) pe2[pn2++] = ent[i];
    u8 in2[16384]; u32 il2 = 0;
    il2 += c2b_write_varint(in2 + il2, 55);
    il2 += c2b_write_varint(in2 + il2, pn2);
    for (u32 i = 0; i < pn2; i++) in2[il2++] = pe2[i];

    /* === прогон msg1: 2 create === */
    static u8 out1[256 * 1024];
    u32 olen1 = 0;
    u32 miss_before = g_g4_miss;
    i32 rc1 = c2b_translate(in1, il1, out1, sizeof(out1), &olen1, &g_st);
    CHECK(rc1 == 0, "g4: translate PE msg1 rc==0");
    CHECK(g_g4_out == 1 && g_g4_ent_new == 2,
          "g4: msg1: out=1 new=2");

    /* === прогон msg2: update + leave === */
    static u8 out2[256 * 1024];
    u32 olen2 = 0;
    i32 rc2 = c2b_translate(in2, il2, out2, sizeof(out2), &olen2, &g_st);
    CHECK(rc2 == 0, "g4: translate PE msg2 rc==0");
    CHECK(g_g4_out == 2 && g_g4_ent_upd == 1 && g_g4_ent_del == 1,
          "g4: msg2: out=2 upd=1 del=1");
    CHECK(g_g4_miss - miss_before >= 1, "g4: m_iClip1 -> miss (нет в DT_CSPlayer)");

    /* --- разбор S1-выхлопа msg2 (update+leave) --- */
    CHECK(olen2 > 2 && out2[0] == 26, "g4: S1 svc_PacketEntities(26) первый байт");
    u32 o = 1, s1len = 0;
    o += c2b_read_varint(out2 + o, olen2 - o, &s1len);
    CHECK(o + s1len == olen2, "g4: длина payload сходится");
    u32 f1v = 0, f2v = 0, f3v = 0;
    const u8 *f7 = 0; u32 f7n = 0;
    u32 p = o;
    while (p < o + s1len) {
        u32 tag, c = c2b_read_varint(out2 + p, o + s1len - p, &tag);
        if (!c) break;
        p += c;
        u32 fid = tag >> 3, wt = tag & 7;
        if (wt == 0) { u32 v; c = c2b_read_varint(out2 + p, o + s1len - p, &v); p += c;
                       if (fid == 1) f1v = v; if (fid == 2) f2v = v; if (fid == 3) f3v = v; }
        else if (wt == 2) { u32 l; c = c2b_read_varint(out2 + p, o + s1len - p, &l); p += c;
                            if (fid == 7) { f7 = out2 + p; f7n = l; } p += l; }
        else break;
    }
    CHECK(f1v == 64 && f2v == 2 && f3v == 1, "g4: msg2 f1/f2/f3 = 64/2/1");
    CHECK(f7 && f7n > 0, "g4: msg2 entity_data присутствует");

    c2b_br_t r;
    c2b_br_init(&r, f7, f7n);
    u32 s1bits = c2b_g4_class_bits(g_cls_emitted);

    /* entity 4 UPDATE */
    u32 d1 = c2b_br_ubitvar(&r);
    u32 lv1 = c2b_br_bit(&r), en1 = c2b_br_bit(&r);
    CHECK(d1 == 4 && lv1 == 0 && en1 == 0, "g4: ent4 delta-апдейт (idx 4)");
    CHECK(c2b_br_bit(&r) == 1, "g4: upd newWay=1");
    i32 prev2 = -1;
    u32 gi[8], gin = 0;
    for (;;) {
        i32 ix;
        if (c2b_br_bit(&r)) ix = prev2 + 1;
        else if (c2b_br_bit(&r)) ix = prev2 + 1 + (i32)c2b_br_bits(&r, 3);
        else {
            u32 ret = c2b_br_bits(&r, 7);
            switch (ret & 96u) {
            case 32: ret = (ret & ~96u) | (c2b_br_bits(&r, 2) << 5); break;
            case 64: ret = (ret & ~96u) | (c2b_br_bits(&r, 4) << 5); break;
            case 96: ret = (ret & ~96u) | (c2b_br_bits(&r, 7) << 5); break;
            }
            if (ret == 0xFFF) { ix = -1; break; }
            ix = prev2 + 1 + (i32)ret;
        }
        if (ix < 0) break;
        prev2 = ix;
        if (gin < 8) gi[gin++] = (u32)ix;
    }
    CHECK(gin == 4, "g4: upd: 4 слота (vel0..2 + health)");
    int ok_ui = 1;
    ok_ui &= (gi[0] == slot_vel0 && gi[1] == slot_vel0 + 1 && gi[2] == slot_vel0 + 2);
    ok_ui &= (gi[3] == slot_health);
    CHECK(ok_ui, "g4: upd слоты = vel0..2+health по возрастанию");
    {
        float a = c2b_f32_from_bits(c2b_br_bits(&r, 32));
        float b = c2b_f32_from_bits(c2b_br_bits(&r, 32));
        float cc = c2b_f32_from_bits(c2b_br_bits(&r, 32));
        CHECK(a == 4.5f && b == -4.5f && cc == 0.0f, "g4: upd velocity 4.5/-4.5/0");
        u32 v = c2b_br_bits(&r, 32);
        CHECK(v == 1000, "g4: upd m_iHealth=1000");
    }
    /* entity 9 LEAVE */
    u32 d2 = c2b_br_ubitvar(&r);
    u32 lv2 = c2b_br_bit(&r);
    u32 del2 = lv2 ? c2b_br_bit(&r) : 9;
    CHECK(d2 == 4 && lv2 == 1 && del2 == 0, "g4: ent9 leave (idx 9), без delete");
    CHECK(r.ovf == 0, "g4: S1-ридер без оверфлоу");

    /* --- разбор msg1 (create 4: полный набор слотов) --- */
    CHECK(olen1 > 2 && out1[0] == 26, "g4: msg1 S1 svc(26)");
    u32 o1 = 1, s1len1 = 0;
    o1 += c2b_read_varint(out1 + o1, olen1 - o1, &s1len1);
    const u8 *f7a = 0; u32 f7an = 0;
    u32 f2a = 0;
    u32 p1 = o1;
    while (p1 < o1 + s1len1) {
        u32 tag, c = c2b_read_varint(out1 + p1, o1 + s1len1 - p1, &tag);
        if (!c) break;
        p1 += c;
        u32 fid = tag >> 3, wt = tag & 7;
        if (wt == 0) { u32 v; c = c2b_read_varint(out1 + p1, o1 + s1len1 - p1, &v); p1 += c;
                       if (fid == 2) f2a = v; }
        else if (wt == 2) { u32 l; c = c2b_read_varint(out1 + p1, o1 + s1len1 - p1, &l); p1 += c;
                            if (fid == 7) { f7a = out1 + p1; f7an = l; } p1 += l; }
        else break;
    }
    CHECK(f2a == 2 && f7a && f7an > 0, "g4: msg1 f2=2, entity_data есть");
    c2b_br_t r1;
    c2b_br_init(&r1, f7a, f7an);
    /* create 4 */
    u32 da = c2b_br_ubitvar(&r1);
    u32 lva = c2b_br_bit(&r1), ena = c2b_br_bit(&r1);
    CHECK(da == 4 && lva == 0 && ena == 1, "g4: msg1 ent4 enter");
    u32 clsa = c2b_br_bits(&r1, s1bits);
    u32 sera = c2b_br_bits(&r1, 10);
    CHECK(clsa == 0 && sera == (0x2A & 0x3FF), "g4: msg1 class=0 serial");
    CHECK(c2b_br_bit(&r1) == 1, "g4: msg1 newWay=1");
    i32 prevA = -1;
    u32 got[32], gn = 0;
    for (;;) {
        i32 ix;
        if (c2b_br_bit(&r1)) ix = prevA + 1;
        else if (c2b_br_bit(&r1)) ix = prevA + 1 + (i32)c2b_br_bits(&r1, 3);
        else {
            u32 ret = c2b_br_bits(&r1, 7);
            switch (ret & 96u) {
            case 32: ret = (ret & ~96u) | (c2b_br_bits(&r1, 2) << 5); break;
            case 64: ret = (ret & ~96u) | (c2b_br_bits(&r1, 4) << 5); break;
            case 96: ret = (ret & ~96u) | (c2b_br_bits(&r1, 7) << 5); break;
            }
            if (ret == 0xFFF) { ix = -1; break; }
            ix = prevA + 1 + (i32)ret;
        }
        if (ix < 0) break;
        prevA = ix;
        if (gn < 32) got[gn++] = (u32)ix;
    }
    u32 cand[8], cn2 = 0;
    cand[cn2++] = slot_health; cand[cn2++] = slot_mhp; cand[cn2++] = slot_clan;
    cand[cn2++] = slot_pose;   cand[cn2++] = slot_org; cand[cn2++] = slot_vel0;
    cand[cn2++] = slot_vel0 + 1; cand[cn2++] = slot_vel0 + 2;
    u32 want[8], wn = 0;
    for (u32 i = 0; i < cn2; i++) {
        if (cand[i] == 0xFFFFFFFFu) continue;
        u32 j;
        for (j = 0; j < wn && want[j] != cand[i]; j++) {}
        if (j == wn) want[wn++] = cand[i];
    }
    for (u32 i = 0; i < wn; i++)
        for (u32 j = i + 1; j < wn; j++)
            if (want[j] < want[i]) { u32 t = want[i]; want[i] = want[j]; want[j] = t; }
    CHECK(gn == wn, "g4: msg1 число слотов create");
    int ok_idx = (gn == wn);
    for (u32 i = 0; i < wn && ok_idx; i++) ok_idx = (got[i] == want[i]);
    CHECK(ok_idx, "g4: msg1 индексы слотов совпали");
    int ok_vals = 1;
    {
        const dt_entry *dte = c2b_dt_find(c2b_fnv1a("DT_CSPlayer"));
        u32 off = 0, cnt = 0;
        c2b_s1_slots_of((u32)(dte - g_dt_index), &off, &cnt);
        for (u32 i = 0; i < gn; i++) {
            c2b_s1_slot_t *sl = &g_s1_slots[off + got[i]];
            if (got[i] == slot_health) {
                u32 hv = c2b_br_bits(&r1, 32);
                ok_vals &= (hv == 1337);
            } else if (got[i] == slot_mhp) {
                u32 cnt2 = c2b_br_bits(&r1, c2b_g4_arr_bits(sl->num));
                ok_vals &= (cnt2 == 3);
                ok_vals &= (c2b_br_bits(&r1, 32) == 0x1234);
                ok_vals &= (c2b_br_bits(&r1, 32) == 0x5678);
                ok_vals &= (c2b_br_bits(&r1, 32) == 0x9ABC);
            } else if (got[i] == slot_org) {
                float x = c2b_f32_from_bits(c2b_br_bits(&r1, 32));
                float y = c2b_f32_from_bits(c2b_br_bits(&r1, 32));
                float z = c2b_f32_from_bits(c2b_br_bits(&r1, 32));
                /* R36: fixture cell=100 > C2B_UB_CAP_CELL(64) -> кламп в 64:
                 * 64*512-16384+off = 16384+off = 16387.5 / 16380.75 / 16394.0 */
                ok_vals &= (x == 16387.5f && y == 16380.75f && z == 16394.0f);
            } else if (got[i] == slot_vel0) {
                ok_vals &= (c2b_f32_from_bits(c2b_br_bits(&r1, 32)) == 1.0f);
            } else if (got[i] == slot_vel0 + 1) {
                ok_vals &= (c2b_f32_from_bits(c2b_br_bits(&r1, 32)) == -2.0f);
            } else if (got[i] == slot_vel0 + 2) {
                ok_vals &= (c2b_f32_from_bits(c2b_br_bits(&r1, 32)) == 0.25f);
            } else if (got[i] == slot_clan && sl->dpt == 4) {
                u32 l = c2b_br_bits(&r1, 9);
                ok_vals &= (l == 2);
                ok_vals &= (c2b_br_bits(&r1, 8) == 'G' && c2b_br_bits(&r1, 8) == 'G');
            } else if (got[i] == slot_pose && sl->dpt == 5) {
                u32 cnt2 = c2b_br_bits(&r1, c2b_g4_arr_bits(sl->num));
                ok_vals &= (cnt2 == 2);
                ok_vals &= (c2b_f32_from_bits(c2b_br_bits(&r1, 32)) == 0.0f);
                ok_vals &= (c2b_f32_from_bits(c2b_br_bits(&r1, 32)) == 0.5f);
            } else {
                ok_vals = 0;
            }
        }
    }
    CHECK(ok_vals, "g4: msg1 значения слотов верны (позиция/здоровье/оружие/клан/позы)");
    /* create 9 в msg1: health=500 */
    {
        u32 db = c2b_br_ubitvar(&r1);
        u32 lvb = c2b_br_bit(&r1), enb = c2b_br_bit(&r1);
        CHECK(db == 4 && lvb == 0 && enb == 1, "g4: msg1 ent9 enter (idx 9)");
        c2b_br_bits(&r1, s1bits);                    /* class */
        c2b_br_bits(&r1, 10);                        /* serial */
        CHECK(c2b_br_bit(&r1) == 1, "g4: msg1 ent9 newWay");
        /* слоты: [0] pointer bool -> нет; [1] health */
        i32 pv = -1, ix9 = 0;
        u32 g9[4], n9 = 0;
        for (;;) {
            if (c2b_br_bit(&r1)) ix9 = pv + 1;
            else if (c2b_br_bit(&r1)) ix9 = pv + 1 + (i32)c2b_br_bits(&r1, 3);
            else {
                u32 ret = c2b_br_bits(&r1, 7);
                switch (ret & 96u) {
                case 32: ret = (ret & ~96u) | (c2b_br_bits(&r1, 2) << 5); break;
                case 64: ret = (ret & ~96u) | (c2b_br_bits(&r1, 4) << 5); break;
                case 96: ret = (ret & ~96u) | (c2b_br_bits(&r1, 7) << 5); break;
                }
                if (ret == 0xFFF) { ix9 = -1; break; }
                ix9 = pv + 1 + (i32)ret;
            }
            if (ix9 < 0) break;
            pv = ix9;
            if (n9 < 4) g9[n9++] = (u32)ix9;
        }
        CHECK(n9 == 1 && g9[0] == slot_health, "g4: msg1 ent9: 1 слот health");
        CHECK(c2b_br_bits(&r1, 32) == 500, "g4: msg1 ent9 health=500");
    }
    CHECK(r1.ovf == 0, "g4: msg1 ридер без оверфлоу");
    printf("  [i] g4: pkts=%u out=%u fields=%u miss=%u desync=%u rem=%u\n",
           g_g4_pkts, g_g4_out, g_g4_fields, g_g4_miss, g_g4_desync, g_g4_rem);
}

/* ---------- фаза G-4b: selftest ---------- */
static void tst_wstr(c2b_bw_t *w, const char *s)
{
    u32 i = 0;
    for (;;) {
        c2b_bw_bits(w, (u32)(u8)s[i], 8);
        if (!s[i]) break;
        i++;
    }
}

/* ---------- t35: новые тесты R34/D1/FINI2/R45 ---------- */
static void test_r34(void)
{
    printf("[t] r34: varint64 + PE f5 wire (10Б) + dfm-счётчики\n");
    u8 neg1[10]; memset(neg1, 0xFF, 9); neg1[9] = 0x01;
    u32 v32 = 0;
    CHECK(c2b_read_varint(neg1, 10, &v32) == 10 && v32 == 0xFFFFFFFFu,
          "r34: baseline=-1 (10Б) читается как 0xFFFFFFFF");
    u64 v64 = 0;
    CHECK(c2b_read_varint64(neg1, 10, &v64) == 10 && v64 == 0xFFFFFFFFFFFFFFFFull,
          "r34: varint64 -1 точен");
    u8 f5[12]; u32 fn = 0;
    fn += c2b_write_varint(f5 + fn, (5u << 3) | 0);
    fn += c2b_write_varint64(f5 + fn, (u64)(i64)-1);
    static const u8 f5_exp[11] = { 0x28, 0xFF,0xFF,0xFF,0xFF,0xFF,
                                   0xFF,0xFF,0xFF,0xFF,0x01 };
    CHECK(fn == 11 && memcmp(f5, f5_exp, 11) == 0, "r34: f5=-1 wire = 28 FF x9 01");
    u8 bad[12]; memset(bad, 0xFF, 11); bad[11] = 0x00;
    u64 bv = 0xAAAA;
    CHECK(c2b_read_varint64(bad, sizeof(bad), &bv) == 0 && bv == 0xAAAA,
          "r34: 11-байтовая последовательность отвергнута");
    u64 nv = 0xAAAA;
    CHECK(c2b_read_varint64(neg1, 9, &nv) == 0 && nv == 0xAAAA,
          "r34: обрыв по avail (9<10) — 0");
    /* скан тагов после 10-байтового значения не сорвётся (регресс hang) */
    u8 st16[20]; u32 sn = 0, pp = 0, tag = 0, vv = 0, c;
    sn += c2b_write_varint(st16 + sn, (5u << 3) | 0);
    sn += c2b_write_varint64(st16 + sn, (u64)(i64)-1);
    sn += c2b_write_varint(st16 + sn, (6u << 3) | 0);
    sn += c2b_write_varint(st16 + sn, 777);
    c = c2b_read_varint(st16 + pp, sn - pp, &tag); pp += c;
    c = c2b_read_varint(st16 + pp, sn - pp, &vv);  pp += c;
    CHECK(tag == (5u << 3) && vv == 0xFFFFFFFFu && pp < sn, "r34: скан после 10Б значения жив");
    g_g4_dfm = 0; g_g4_dfm_pend = 0;
    CHECK(g_g4_dfm == 0 && g_g4_dfm_pend == 0, "r34: dfm-счётчики доступны/сброшены");
}

static void test_d1_netfile(void)
{
    printf("[t] d1: S2 net#2 (дыра net_File) дропается\n");
    u8 inf[16]; u32 ilf = 0;
    ilf += c2b_write_varint(inf + ilf, 2);
    ilf += c2b_write_varint(inf + ilf, 2);
    inf[ilf++] = (1u << 3); inf[ilf++] = 7;      /* мусор, похожий на transfer_id */
    u32 drf = g_st.dropped, nf0 = g_g4_nf;
    static u8 outf[64]; u32 olf = 0;
    i32 rcf = c2b_translate(inf, ilf, outf, sizeof(outf), &olf, &g_st);
    CHECK(rcf == 0 && olf == 0, "d1: S2 net#2 дропнут (на провод ничего)");
    CHECK(g_st.dropped == drf + 1, "d1: st->dropped++");
    CHECK(g_g4_nf == nf0 + 1, "d1: счётчик net#2 инкрементирован");
}

/* T35-гап «fph 24% weight» (применено t36): 40 op'ов field-path Huffman, 24 с w>0
 * (сумма 97220). Selftest-энкодер покрывал 6/24 опов (68.4% веса; вторая ступень
 * PlusTwo/Three/Four/Pack6Bits ~24% веса не гонялась вовсе). Здесь: roundtrip ВСЕХ
 * 40 кодов (g_fph_codes -> c2b_fp_read_all) от базы [2,5] = 100% веса. */
static void test_fph_weight(void)
{
    printf("[t] fph: roundtrip 40 опов (24 взвешенных, вес 97220)\n");
    static const u16 W[40] = { 36271,10334,1375,646,4128,35,3,521,2942,560,471,
        10530,251,0,0,0,0,0,0,0,0,0,0,0,0,0,310,2,0,1837,149,300,634,0,0,1,76,271,99,25474 };
    u32 tw = 0, nw = 0;
    for (u32 i = 0; i < 40; i++) { tw += W[i]; if (W[i]) nw++; }
    CHECK(nw == 24 && tw == 97220, "fph: 24 op'а с весом, суммарный вес 97220");
    CHECK(g_fph_codes[0].code == 0x0u && g_fph_codes[0].len == 1 &&
          g_fph_codes[39].code == 0x2u && g_fph_codes[39].len == 2,
          "fph: PlusOne='0'(1 бит), Finish='10'(2 бита)");
    CHECK(g_fph_codes[11].code == 0xFu && g_fph_codes[11].len == 4 &&
          g_fph_codes[1].code == 0xEu && g_fph_codes[1].len == 4 &&
          g_fph_codes[3].code == 0xDFu && g_fph_codes[3].len == 8,
          "fph: Pack6Bits=1111(4), PlusTwo=1110(4), PlusFour=11011111(8)");
    /* ожидаемые пути от базы [2,5] (last=1) по реплике field_path.go */
    static const struct { u8 op; i32 e[5]; u8 el; } T[40] = {
        { 0, {2,6,0,0,0}, 1 }, { 1, {2,7,0,0,0}, 1 }, { 2, {2,8,0,0,0}, 1 },
        { 3, {2,9,0,0,0}, 1 }, { 4, {2,10,0,0,0}, 1 }, { 5, {2,5,0,0,0}, 2 },
        { 6, {2,5,0,0,0}, 2 }, { 7, {2,6,0,0,0}, 2 }, { 8, {2,6,0,0,0}, 2 },
        { 9, {2,5,0,0,0}, 2 }, { 10,{2,7,1,0,0}, 2 }, { 11,{2,7,1,0,0}, 2 },
        { 12,{2,7,1,0,0}, 2 }, { 13,{2,5,0,0,0}, 3 }, { 14,{2,5,0,0,0}, 3 },
        { 15,{2,5,0,0,0}, 4 }, { 16,{2,5,0,0,0}, 4 }, { 17,{2,6,0,0,0}, 3 },
        { 18,{2,6,0,0,0}, 3 }, { 19,{2,6,0,0,0}, 4 }, { 20,{2,6,0,0,0}, 4 },
        { 21,{2,7,0,0,0}, 3 }, { 22,{2,7,0,0,0}, 3 }, { 23,{2,7,0,0,0}, 4 },
        { 24,{2,7,0,0,0}, 4 }, { 25,{2,5,0,0,0}, 1 }, { 26,{2,5,0,0,0}, 1 },
        { 27,{3,0,0,0,0}, 0 }, { 28,{3,0,0,0,0}, 0 }, { 29,{3,0,0,0,0}, 0 },
        { 30,{3,0,0,0,0}, 0 }, { 31,{3,0,0,0,0}, 0 }, { 32,{3,0,0,0,0}, 0 },
        { 33,{3,0,0,0,0}, 0 }, { 34,{5,0,0,0,0}, 0 }, { 35,{2,0,0,0,0}, 0 },
        { 36,{2,5,0,0,0}, 1 }, { 37,{3,5,0,0,0}, 1 }, { 38,{2,5,0,0,0}, 1 },
        { 39,{2,5,0,0,0}, 1 }
    };
    u32 good = 0;
    for (u32 op = 0; op < 40; op++) {
        static u8 b[64];
        c2b_bw_t w; w.buf = b; w.cap = sizeof(b);
        w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
        /* база [2,5]: reset path[0]=-1 -> 3x PlusOne -> [2]; op6 PushSet(5) -> [2,5] */
        g4e_huff(&w, 0); g4e_huff(&w, 0); g4e_huff(&w, 0);
        g4e_huff(&w, 6); g4e_uvfp(&w, 5);
        g4e_huff(&w, op);                    /* КОД опа (t36-фикс фрагмента спеки) */
        switch (op) {                        /* операнды (инверсия ридера c2b_fp_read_all) */
        case 4: case 6: case 8: case 9: case 28: case 30:
            g4e_uvfp(&w, 0); break;
        case 33: g4e_uvfp(&w, 1); break;                     /* n=1 */
        case 34: g4e_uvfp(&w, 1);                            /* n=1 + varint32 */
                 c2b_bw_bits(&w, 0x06, 8); break;            /* varint32 zigzag(3)=6 */
        case 35: g4e_uvfp(&w, 1);                            /* n=1 + маркер ур.0 */
                 c2b_bw_bit(&w, 0); break;
        case 10: case 13: case 17:
            g4e_uvfp(&w, 0); g4e_uvfp(&w, 0); break;
        case 11: c2b_bw_bits(&w, 0, 3); c2b_bw_bits(&w, 0, 3); break;
        case 12: c2b_bw_bits(&w, 0, 4); c2b_bw_bits(&w, 0, 4); break;
        case 18: c2b_bw_bits(&w, 0, 5); c2b_bw_bits(&w, 0, 5); break;  /* t36-фикс: ридер читает 5 бит */
        case 14: c2b_bw_bits(&w, 0, 5); c2b_bw_bits(&w, 0, 5); break;
        case 15: case 19:
            g4e_uvfp(&w, 0); g4e_uvfp(&w, 0); g4e_uvfp(&w, 0); break;
        case 16: case 20:
            c2b_bw_bits(&w, 0, 5); c2b_bw_bits(&w, 0, 5); c2b_bw_bits(&w, 0, 5); break;
        case 21: case 22:
            c2b_bw_ubitvar(&w, 0);           /* n (6-бит эскейп), ladd(n+2) */
            if (op == 21) { g4e_uvfp(&w, 0); g4e_uvfp(&w, 0); }
            else { c2b_bw_bits(&w, 0, 5); c2b_bw_bits(&w, 0, 5); } break;
        case 23: case 24:
            c2b_bw_ubitvar(&w, 0);
            if (op == 23) { g4e_uvfp(&w, 0); g4e_uvfp(&w, 0); g4e_uvfp(&w, 0); }
            else { c2b_bw_bits(&w, 0, 5); c2b_bw_bits(&w, 0, 5); c2b_bw_bits(&w, 0, 5); } break;
        case 25: c2b_bw_ubitvar(&w, 0); break;               /* PushN: n=0 */
        case 26: c2b_bw_bit(&w, 0); c2b_bw_bit(&w, 0);       /* маркеры ур.0,1 */
                 c2b_bw_ubitvar(&w, 0); break;               /* n=0 */
        case 31: c2b_bw_bits(&w, 0, 3); break;
        case 32: c2b_bw_bits(&w, 0, 6); break;
        case 36: case 38:                                    /* NonTopo: маркеры ур.0,1 */
                 c2b_bw_bit(&w, 0); c2b_bw_bit(&w, 0); break;
        default: break;
        }
        g4e_huff(&w, 39);
        u32 nb = c2b_bw_flush(&w);
        c2b_br_t r; c2b_br_init(&r, b, nb);
        c2b_fp_t fp; c2b_fp_reset(&fp);
        i32 pn = c2b_fp_read_all(&r, &fp, 0, 0);
        int ok = (pn == 0 && !r.ovf && !w.ovf);
        for (u32 k = 0; ok && k <= (u32)T[op].el; k++) ok = (fp.path[k] == T[op].e[k]);
        ok = ok && (fp.last == T[op].el);
        char nm[40];
        snprintf(nm, sizeof(nm), "fph: op %u roundtrip -> путь/last", op);
        CHECK(ok, nm);
        if (ok) good++;
    }
    CHECK(good == 40, "fph: 40/40 опов, покрытие веса 100% (97220/97220)");
}

static void test_fini2(void)
{
    printf("[t] fini2: формат FINI/FINI2 (контракт эталона 5cce9ff4)\n");
    /* t36/audit05: полный контракт эталона 5cce9ff4 (+расширения R33/gb, G-6/snd) */
    static const char fini_labels[] =
        " dn{ok= pass= rival= oom= trunc= bin= bout= mxi= mox= void= }"
        " g4{ovf= bnn= ub= dfm= ds= sr= ps= nf= dm= }"
        " gb{m= k= sk= nc= ov= ud= c51= dc= }"
        " snd{n= drop= }"
        " up{calls= rival= }"
        " si{pr= mcl= mcs= mclr= mcsr= } rt{str= ge= aov= }"
        " ba{p= s= nt= } up2{t0= bsz= tr= } dn2{fc= }"
        " clu{s= cl= gc= qc= cn= rc= ot= dr=} clr{r= cl= ch= rj= si= in= ot= dr=}";   /* 41e-a */
    CHECK(strstr(fini_labels, "dn{") != 0, "fini: строка содержит блок dn{");
    CHECK(strstr(fini_labels, "void=") != 0, "fini: эталонное поле void= (t36/audit05)");
    CHECK(strstr(fini_labels, "up{calls=") != 0, "fini: строка содержит up{calls=");
    CHECK(strstr(fini_labels, "gb{") != 0, "fini: строка содержит блок gb{");
    CHECK(strstr(fini_labels, "snd{n=") != 0, "fini: строка содержит snd{n= (G-6)");
    CHECK(strstr(fini_labels, "dn2{fc=") != 0, "fini: строка содержит dn2{fc=}");
    CHECK(strstr(fini_labels, "clu{s=") != 0, "fini: строка содержит clu{ (41e-a)");
    CHECK(strstr(fini_labels, "clr{r=") != 0, "fini: строка содержит clr{ (41e-a)");
    CHECK(g_g4b_msgs > 0 && g_g4b_kept > 0, "fini: g4b-счётчики после фикстур > 0");
    /* в selftest C2B_LOGx = printf: дублируем печать (тела принтеров в live-зоне);
     * t36/audit05: дубликат приведён к полному live-формату (LOGH для si-полей) */
    C2B_LOGS("[c2b] FINI calls="); C2B_LOGN(g_dn_stats.calls);
    C2B_LOGS(" dn{ok=");   C2B_LOGN(g_dn_stats.ok);
    C2B_LOGS(" void=");    C2B_LOGN(g_dn_stats.n_void);   /* ключевые dn-поля */
    C2B_LOGS("} g4{ovf="); C2B_LOGN(g_g4b_cls_ovf);
    C2B_LOGS("} gb{m=");   C2B_LOGN(g_g4b_msgs);
    C2B_LOGS("} snd{n=");  C2B_LOGN(g_synth_sounds);   /* G-6 */
    C2B_LOGS("} up{calls="); C2B_LOGN(g_up_st.calls);
    C2B_LOGS("} clu{s=");  C2B_LOGN(g_cl_s_total);   /* 41e-a: ключевые cl-поля */
    C2B_LOGS(" cl=");      C2B_LOGN(g_cl_s_cl);
    C2B_LOGS("} clr{r=");  C2B_LOGN(g_cl_r_total);
    C2B_LOGS(" ch=");      C2B_LOGN(g_cl_r_ch);
    C2B_LOGS("}\n");
    C2B_LOGS("[c2b] FINI2 si{pr="); C2B_LOGH(g_fini2.si_pr);   /* live=LOGH (hex) */
    C2B_LOGS("} rt{str="); C2B_LOGN(g_fini2.rt_str);
    C2B_LOGS("} ba{p=");   C2B_LOGN(g_fini2.ba_p);
    C2B_LOGS("} up2{t0="); C2B_LOGN(g_fini2.up2_t0);
    C2B_LOGS("} dn2{fc="); C2B_LOGN(g_fini2.dn2_fc);
    C2B_LOGS("}\n");
    printf("\n");
    CHECK(g_fini2.ba_p >= 0, "fini: печать FINI/FINI2 без краха");
}

static void test_r45_alias(void)
{
    printf("[t] r45: алиасы классов C_* -> DT_* (109 шт, массив 210)\n");
    CHECK(sizeof(g_class_alias) / sizeof(g_class_alias[0]) == 210,
          "r45: g_class_alias размер 210 (101+109)");
    const class_alias *a1 = c2b_alias_find(c2b_fnv1a("C_CSPlayerPawn"));
    CHECK(a1 != 0 && a1->dt_name != 0 && strcmp(a1->dt_name, "DT_CSPlayer") == 0,
          "r45: C_CSPlayerPawn -> DT_CSPlayer");
    const class_alias *a2 = c2b_alias_find(c2b_fnv1a("C_PlantedC4"));
    CHECK(a2 != 0 && strcmp(a2->dt_name, "DT_PlantedC4") == 0,
          "r45: C_PlantedC4 -> DT_PlantedC4");
    const class_alias *a3 = c2b_alias_find(c2b_fnv1a("C_DefinitelyNotAClass"));
    CHECK(a3 == 0, "r45: неизвестное имя не резолвится");
    /* каждая цель обязана существовать в S1-словаре */
    u32 miss = 0;
    for (u32 i = 0; i < sizeof(g_class_alias) / sizeof(g_class_alias[0]); i++) {
        if (!c2b_dt_find(c2b_fnv1a(g_class_alias[i].dt_name))) miss++;
    }
    CHECK(miss == 0, "r45: все DT-цели алиасов есть в g_dt_index");
}

static void test_g4b(void)
{
    printf("[t] instanceBaseline stringtable (G-4b)\n");

    /* --- 1. snappy декомпрессор --- */
    {
        /* literal-only */
        const u8 v1[] = { 0x10, 0x3C, 'H','e','l','l','o','H','e','l','l','o','H','e','l','l','o','!' };
        u8 o1[64]; u32 o1n = 0xFFFFFFFFu;
        i32 rc = c2b_snappy_decomp(v1, sizeof(v1), o1, sizeof(o1));
        CHECK(rc == 16, "g4b: snappy literal rc==16");
        if (rc == 16) {
            o1n = (u32)rc;
            o1[o1n] = 0;
            CHECK(memcmp(o1, "HelloHelloHello!", 16) == 0, "g4b: snappy literal текст");
        }
        /* literal + copy2 overlap: "ABC" + 9 байт с оффсетом 3 */
        const u8 v2[] = { 0x0C, 0x08, 'A','B','C', 0x22, 0x03, 0x00 };
        u8 o2[32];
        rc = c2b_snappy_decomp(v2, sizeof(v2), o2, sizeof(o2));
        CHECK(rc == 12, "g4b: snappy copy2 rc==12");
        if (rc == 12) CHECK(memcmp(o2, "ABCABCABCABC", 12) == 0, "g4b: snappy copy2 текст");
        /* literal + copy1 (ln=5, off=3): "ABCABCAB" */
        const u8 v3[] = { 0x08, 0x08, 'A','B','C', 0x05, 0x03 };
        u8 o3[32];
        rc = c2b_snappy_decomp(v3, sizeof(v3), o3, sizeof(o3));
        CHECK(rc == 8, "g4b: snappy copy1 rc==8");
        if (rc == 8) CHECK(memcmp(o3, "ABCABCAB", 8) == 0, "g4b: snappy copy1 текст");
        /* 2-байтовая длина литерала: 200 байт (тег 61<<2 = 0xF4) */
        u8 v4[5 + 200]; u32 v4n = 0;
        v4[v4n++] = 0xC8; v4[v4n++] = 0x01;          /* varint 200 */
        v4[v4n++] = 0xF4;                            /* tag 61<<2: 2 байта длины */
        v4[v4n++] = 0xC7; v4[v4n++] = 0x00;          /* 199 -> len 200 */
        for (u32 i = 0; i < 200; i++) v4[v4n++] = (u8)(i & 0xFF);
        u8 o4[256];
        rc = c2b_snappy_decomp(v4, v4n, o4, sizeof(o4));
        CHECK(rc == 200, "g4b: snappy длинный литерал rc==200");
        if (rc == 200) {
            int ok = 1;
            for (u32 i = 0; i < 200; i++) ok &= (o4[i] == (u8)(i & 0xFF));
            CHECK(ok, "g4b: snappy длинный литерал текст");
        }
        /* кривые: copy с off=0, обрыв */
        const u8 vb[] = { 0x08, 0x08, 'A','B','C', 0x22, 0x00, 0x00 };
        CHECK(c2b_snappy_decomp(vb, sizeof(vb), o2, sizeof(o2)) < 0, "g4b: snappy off=0 -> err");
        CHECK(c2b_snappy_decomp(v1, 2, o1, sizeof(o1)) < 0, "g4b: snappy обрыв -> err");
    }

    /* --- 2. подготовка: класс 1 = CCSPlayer уже зарегистрирован в test_g4 --- */
    CHECK(g_cls_emitted >= 1 && g_class_dt_map[1] != 0xFFFFu,
          "g4b: класс 1 зарегистрирован (наследие test_g4)");
    /* R32: unit-проверка транскода ключа (карта после test_g4: map[1]=0) */
    {
        char kx[16];
        c2b_g4b_s1_key(1, "1", kx, sizeof(kx));
        CHECK(kx[0] == '0' && kx[1] == 0, "g4b: ключ 1 -> S1 \"0\" по карте");
        c2b_g4b_s1_key(4, "4", kx, sizeof(kx));
        CHECK(kx[0] == '4' && kx[1] == 0, "g4b: identity-класс ключ сохранён");
        c2b_g4b_s1_key(999, "999", kx, sizeof(kx));   /* 999 >= map_n */
        CHECK(kx[0] == '9' && kx[1] == '9' && kx[2] == '9' && kx[3] == 0,
              "g4b: вне карты ключ S2 дословно");
        c2b_g4b_s1_key(-1, "123:456", kx, sizeof(kx));
        CHECK(kx[0] == '1' && kx[3] == ':' && kx[7] == 0,
              "g4b: cls<0 -> ключ S2 дословно");
    }
    u32 tbl_before = g_g4b_tbl_seen;

    /* --- 3. S2-базлайн класса 1: [0] ptr=0, [1] health, [2] vel, [3] weapons n=0, [4] clan --- */
    static u8 blp[4096];
    c2b_bw_t bw2;
    bw2.buf = blp; bw2.cap = sizeof(blp); bw2.pos = 0; bw2.bitval = 0; bw2.bitcnt = 0; bw2.ovf = 0;
    g4e_fp_t fp;
    g4e_fp_reset(&fp);
    g4e_huff(&bw2, 0); fp.path[0]++;                 /* [0] m_pBody */
    g4e_huff(&bw2, 0); fp.path[0]++;                 /* [1] m_iHealth */
    g4e_huff(&bw2, 0); fp.path[0]++;                 /* [2] m_vecVelocity */
    g4e_huff(&bw2, 0); fp.path[0]++;                 /* [3] m_hMyWeapons */
    g4e_huff(&bw2, 0); fp.path[0]++;                 /* [4] m_szClan */
    g4e_huff(&bw2, 39);                              /* finish */
    c2b_bw_bit(&bw2, 0);                             /* [0] pointer inactive */
    g4e_varu(&bw2, 1337u << 1);                      /* [1] health (zigzag) */
    c2b_bw_bits(&bw2, c2b_f32_to_bits(1.0f), 32);    /* [2] velocity */
    c2b_bw_bits(&bw2, c2b_f32_to_bits(-2.0f), 32);
    c2b_bw_bits(&bw2, c2b_f32_to_bits(0.25f), 32);
    g4e_varu(&bw2, 0);                               /* [3] weapons count=0 */
    c2b_bw_bits(&bw2, 'G', 8); c2b_bw_bits(&bw2, 'G', 8); c2b_bw_bits(&bw2, 0, 8); /* [4] */
    u32 blp_n = c2b_bw_flush(&bw2);
    CHECK(bw2.ovf == 0, "g4b: S2-энкодер базлайна без оверфлоу");

    /* --- 4. S2-блоб: 3 строки (idx0 key"1", idx1 key"123:456", idx5 key"7") --- */
    static u8 blb[8192];
    c2b_bw_t wb;
    wb.buf = blb; wb.cap = sizeof(blb); wb.pos = 0; wb.bitval = 0; wb.bitcnt = 0; wb.ovf = 0;
    /* item0 */
    c2b_bw_bit(&wb, 1);                              /* incr -> idx0 */
    c2b_bw_bit(&wb, 1); c2b_bw_bit(&wb, 0); tst_wstr(&wb, "1");
    c2b_bw_bit(&wb, 1);                              /* hasValue */
    c2b_bw_bits(&wb, blp_n, 17);                     /* размер в байтах (клиент *8) */
    for (u32 i = 0; i < blp_n; i++) c2b_bw_bits(&wb, blp[i], 8);
    /* item1: неклассовый ключ */
    c2b_bw_bit(&wb, 1);                              /* incr -> idx1 */
    c2b_bw_bit(&wb, 1); c2b_bw_bit(&wb, 0); tst_wstr(&wb, "123:456");
    c2b_bw_bit(&wb, 1);
    c2b_bw_bits(&wb, 1, 17);
    c2b_bw_bits(&wb, 'X', 8);
    /* item2: явный индекс 5, незарегистрированный класс */
    c2b_bw_bit(&wb, 0); c2b_g4b_wvarint(&wb, 4);     /* idx = 4+1 = 5 */
    c2b_bw_bit(&wb, 1); c2b_bw_bit(&wb, 0); tst_wstr(&wb, "999");
    c2b_bw_bit(&wb, 1);
    c2b_bw_bits(&wb, 1, 17);
    c2b_bw_bits(&wb, 'Y', 8);
    u32 blb_n = c2b_bw_flush(&wb);
    CHECK(wb.ovf == 0, "g4b: S2-блоб без оверфлоу");

    /* --- 5. сообщение CreateStringTable(44) --- */
    u8 cst[9216]; u32 cn = 0;
    cst[cn++] = (1u << 3) | 2; cst[cn++] = 16;
    memcpy(cst + cn, "instanceBaseline", 16); cn += 16;
    cst[cn++] = (2u << 3); cn += c2b_write_varint(cst + cn, 3);   /* num_entries */
    cst[cn++] = (7u << 3) | 2; cn += c2b_write_varint(cst + cn, blb_n);
    for (u32 i = 0; i < blb_n; i++) cst[cn++] = blb[i];

    u8 inb[10240]; u32 il = 0;
    il += c2b_write_varint(inb + il, 44);
    il += c2b_write_varint(inb + il, cn);
    for (u32 i = 0; i < cn; i++) inb[il++] = cst[i];

    static u8 outb[512 * 1024];
    u32 olen = 0;
    i32 rc = c2b_translate(inb, il, outb, sizeof(outb), &olen, &g_st);
    CHECK(rc == 0, "g4b: translate rc==0");
    CHECK(olen > 2 && outb[0] == 12, "g4b: S1 svc_CreateStringTable(12)");
    CHECK(g_g4b_msgs == 1 && g_g4b_kept == 1 && g_g4b_skip == 1 && g_g4b_nocls == 1,
          "g4b: счётчики msgs/kept/skip/nocls");

    /* --- 6. разбор S1-сообщения: f1..f3, f8 --- */
    u32 o6 = 1, s1len6 = 0;
    o6 += c2b_read_varint(outb + o6, olen - o6, &s1len6);
    CHECK(o6 + s1len6 == olen, "g4b: длина payload сходится");
    const u8 *nmf = 0; u32 nmf_n = 0, maxent = 0, nent = 0;
    const u8 *b8 = 0; u32 b8n = 0;
    u32 p6 = o6;
    while (p6 < o6 + s1len6) {
        u32 tag, c = c2b_read_varint(outb + p6, o6 + s1len6 - p6, &tag);
        if (!c) break;
        p6 += c;
        u32 fid = tag >> 3, wt = tag & 7;
        if (wt == 0) { u32 v; c = c2b_read_varint(outb + p6, o6 + s1len6 - p6, &v); p6 += c;
                       if (fid == 2) maxent = v; if (fid == 3) nent = v; }
        else if (wt == 2) { u32 l; c = c2b_read_varint(outb + p6, o6 + s1len6 - p6, &l); p6 += c;
                            if (fid == 1) { nmf = outb + p6; nmf_n = l; }
                            if (fid == 8) { b8 = outb + p6; b8n = l; } p6 += l; }
        else break;
    }
    CHECK(nmf && nmf_n == 16 && memcmp(nmf, "instanceBaseline", 16) == 0,
          "g4b: f1 name сохранён");
    CHECK(maxent == g_class_id_map_n, "g4b: f2 max_entries синтезирован");
    CHECK(nent == 3, "g4b: f3 num_entries = 3");
    CHECK(b8 && b8n > 0, "g4b: f8 string_data есть");

    /* --- 7. разбор S1-блоба: ровно 1 строка (idx0, key "1") --- */
    c2b_br_t br1;
    c2b_br_init(&br1, b8, b8n);
    CHECK(c2b_br_bit(&br1) == 1, "g4b: S1 item0 incr (idx0)");
    CHECK(c2b_br_bit(&br1) == 1, "g4b: S1 item0 hasKey");
    CHECK(c2b_br_bit(&br1) == 0, "g4b: S1 item0 без истории");
    char k1[40];
    CHECK(c2b_g4b_bit_str(&br1, k1, sizeof(k1)) == 1 && k1[0] == '0' && k1[1] == 0,
          "g4b: S1 key = \"0\" (S1 class_id по карте, R32)");
    CHECK(c2b_br_bit(&br1) == 1, "g4b: S1 item0 hasValue");
    u32 sz17 = c2b_br_bits(&br1, 17);
    u32 pl_n = sz17;
    CHECK(pl_n > 0 && pl_n < 4096, "g4b: S1 размер item (17 бит, байты)");
    static u8 plb[4096];
    for (u32 i = 0; i < pl_n; i++) plb[i] = (u8)c2b_br_bits(&br1, 8);
    CHECK(br1.ovf == 0, "g4b: S1-ридер блоба без оверфлоу (строк больше нет)");

    /* --- 8. декод S1-базлайна: newWay, слоты, значения --- */
    c2b_br_t rb;
    c2b_br_init(&rb, plb, pl_n);
    CHECK(c2b_br_bit(&rb) == 1, "g4b: newWay=1");
    i32 prev8 = -1;
    u32 got8[16]; u32 gn8 = 0;
    for (;;) {
        i32 ix;
        if (c2b_br_bit(&rb)) ix = prev8 + 1;
        else if (c2b_br_bit(&rb)) ix = prev8 + 1 + (i32)c2b_br_bits(&rb, 3);
        else {
            u32 ret = c2b_br_bits(&rb, 7);
            switch (ret & 96u) {
            case 32: ret = (ret & ~96u) | (c2b_br_bits(&rb, 2) << 5); break;
            case 64: ret = (ret & ~96u) | (c2b_br_bits(&rb, 4) << 5); break;
            case 96: ret = (ret & ~96u) | (c2b_br_bits(&rb, 7) << 5); break;
            }
            if (ret == 0xFFF) { ix = -1; break; }
            ix = prev8 + 1 + (i32)ret;
        }
        if (ix < 0) break;
        prev8 = ix;
        if (gn8 < 16) got8[gn8++] = (u32)ix;
    }
    u32 slot_health = 0xFFFFFFFFu, slot_mhp = 0xFFFFFFFFu, slot_clan = 0xFFFFFFFFu,
        slot_vel0 = 0xFFFFFFFFu;
    u32 sl_mhp_bits = 1;
    {
        const dt_entry *dte = c2b_dt_find(c2b_fnv1a("DT_CSPlayer"));
        u32 off = 0, cnt = 0;
        c2b_s1_slots_of((u32)(dte - g_dt_index), &off, &cnt);
        slot_health = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_iHealth"));
        slot_mhp    = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_hMyWeapons"));
        slot_clan   = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_szClan"));
        slot_vel0   = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_vecVelocity[0]"));
        sl_mhp_bits = c2b_g4_arr_bits(g_s1_slots[off + slot_mhp].num);
    }
    u32 cand8[5], wn8 = 0;
    /* m_szClan НЕТ в DT_CSPlayer (спроектированный miss — см. test_g4) */
    cand8[wn8++] = slot_health; cand8[wn8++] = slot_mhp;
    cand8[wn8++] = slot_vel0; cand8[wn8++] = slot_vel0 + 1; cand8[wn8++] = slot_vel0 + 2;
    for (u32 i = 0; i < wn8; i++)
        for (u32 j = i + 1; j < wn8; j++)
            if (cand8[j] < cand8[i]) { u32 t = cand8[i]; cand8[i] = cand8[j]; cand8[j] = t; }
    CHECK(gn8 == wn8, "g4b: 5 слотов в базлайне");
    int ok8 = (gn8 == wn8);
    for (u32 i = 0; i < wn8 && ok8; i++) ok8 = (got8[i] == cand8[i]);
    CHECK(ok8, "g4b: слоты базлайна по возрастанию");
    {
        u32 hv = 0xFFFFFFFFu, mv = 0xFFFFFFFFu;
        float vx = 0, vy = 0, vz = 0;
        for (u32 i = 0; i < gn8; i++) {
            if (got8[i] == slot_health) hv = c2b_br_bits(&rb, 32);
            else if (got8[i] == slot_mhp) mv = c2b_br_bits(&rb, sl_mhp_bits);
            else if (got8[i] == slot_vel0) vx = c2b_f32_from_bits(c2b_br_bits(&rb, 32));
            else if (got8[i] == slot_vel0 + 1) vy = c2b_f32_from_bits(c2b_br_bits(&rb, 32));
            else if (got8[i] == slot_vel0 + 2) vz = c2b_f32_from_bits(c2b_br_bits(&rb, 32));
        }
        CHECK(hv == 1337, "g4b: health=1337");
        CHECK(mv == 0, "g4b: weapons count=0");
        CHECK(vx == 1.0f && vy == -2.0f && vz == 0.25f, "g4b: velocity 1/-2/0.25");
        CHECK(rb.ovf == 0, "g4b: S1-декодер без оверфлоу");
    }

    /* --- 9. UpdateStringTable: baseline-апдейт дропается, чужой проходит --- */
    {
        u8 up[32]; u32 un = 0;
        up[un++] = (1u << 3); un += c2b_write_varint(up + un, tbl_before);  /* наш id */
        u8 inu[64]; u32 ilu = 0;
        ilu += c2b_write_varint(inu + ilu, 45);
        ilu += c2b_write_varint(inu + ilu, un);
        for (u32 i = 0; i < un; i++) inu[ilu++] = up[i];
        u32 drop_before = g_g4b_upd_drop;
        static u8 outu[256]; u32 olu = 0;
        i32 rcu = c2b_translate(inu, ilu, outu, sizeof(outu), &olu, &g_st);
        CHECK(rcu == 0 && olu == 0, "g4b: baseline-Update дропнут (пустой выход)");
        CHECK(g_g4b_upd_drop == drop_before + 1, "g4b: счётчик upd_drop");

        u8 up2[32]; u32 un2 = 0;
        up2[un2++] = (1u << 3); un2 += c2b_write_varint(up2 + un2, tbl_before + 1);
        up2[un2++] = (2u << 3); un2 += c2b_write_varint(up2 + un2, 1);      /* num_changed */
        u8 inu2[64]; u32 ilu2 = 0;
        ilu2 += c2b_write_varint(inu2 + ilu2, 45);
        ilu2 += c2b_write_varint(inu2 + ilu2, un2);
        for (u32 i = 0; i < un2; i++) inu2[ilu2++] = up2[i];
        u32 olu2 = 0;
        i32 rcu2 = c2b_translate(inu2, ilu2, outu, sizeof(outu), &olu2, &g_st);
        CHECK(rcu2 == 0 && olu2 > 2 && outu[0] == 13, "g4b: чужой Update проходит как 13");
    }

    /* --- 9b. G-4d: baseline-Update транскодится в S1(13) --- */
    {
        static u8 ub[8192];
        c2b_bw_t uw;
        uw.buf = ub; uw.cap = sizeof(ub); uw.pos = 0; uw.bitval = 0; uw.bitcnt = 0; uw.ovf = 0;
        /* item0: явный индекс 2 (varint 1 -> idx=2), key "1", полный S2-базлайн blp */
        c2b_bw_bit(&uw, 0); c2b_g4b_wvarint(&uw, 1);
        c2b_bw_bit(&uw, 1); c2b_bw_bit(&uw, 0); tst_wstr(&uw, "1");
        c2b_bw_bit(&uw, 1);
        c2b_bw_bits(&uw, blp_n, 17);
        for (u32 i = 0; i < blp_n; i++) c2b_bw_bits(&uw, blp[i], 8);
        /* item1: инкремент -> idx3, неклассовый ключ (skip) */
        c2b_bw_bit(&uw, 1);
        c2b_bw_bit(&uw, 1); c2b_bw_bit(&uw, 0); tst_wstr(&uw, "123:456");
        c2b_bw_bit(&uw, 1);
        c2b_bw_bits(&uw, 1, 17);
        c2b_bw_bits(&uw, 'Z', 8);
        u32 ub_n = c2b_bw_flush(&uw);
        CHECK(uw.ovf == 0, "g4d: S2-блоб апдейта без оверфлоу");

        u8 up3[64]; u32 un3 = 0;
        up3[un3++] = (1u << 3); un3 += c2b_write_varint(up3 + un3, tbl_before);
        up3[un3++] = (2u << 3); un3 += c2b_write_varint(up3 + un3, 2);
        up3[un3++] = (3u << 3) | 2; un3 += c2b_write_varint(up3 + un3, ub_n);
        for (u32 i = 0; i < ub_n; i++) up3[un3++] = ub[i];
        u8 inu3[1024]; u32 ilu3 = 0;
        ilu3 += c2b_write_varint(inu3 + ilu3, 45);
        ilu3 += c2b_write_varint(inu3 + ilu3, un3);
        for (u32 i = 0; i < un3; i++) inu3[ilu3++] = up3[i];

        u32 g4d_before = g_g4d_msgs;
        static u8 outu3[8192]; u32 olu3 = 0;
        i32 rcu3 = c2b_translate(inu3, ilu3, outu3, sizeof(outu3), &olu3, &g_st);
        CHECK(rcu3 == 0 && olu3 > 4 && outu3[0] == 13, "g4d: baseline-Update -> S1 13");
        CHECK(g_g4d_msgs == g4d_before + 1, "g4d: счётчик msgs");

        u32 o3 = 1, l3 = 0;
        o3 += c2b_read_varint(outu3 + o3, olu3 - o3, &l3);
        CHECK(o3 + l3 == olu3, "g4d: длина payload сходится");
        u32 p3 = o3, f1v = 0, f2v = 0;
        const u8 *d3 = 0; u32 d3n = 0;
        while (p3 < o3 + l3) {
            u32 tag, c = c2b_read_varint(outu3 + p3, o3 + l3 - p3, &tag);
            if (!c) break;
            p3 += c;
            u32 fid = tag >> 3, wt = tag & 7;
            if (wt == 0) { u32 v; c = c2b_read_varint(outu3 + p3, o3 + l3 - p3, &v); p3 += c;
                           if (fid == 1) f1v = v; if (fid == 2) f2v = v; }
            else if (wt == 2) { u32 l; c = c2b_read_varint(outu3 + p3, o3 + l3 - p3, &l); p3 += c;
                                if (fid == 3) { d3 = outu3 + p3; d3n = l; } p3 += l; }
            else break;
        }
        CHECK(f1v == tbl_before, "g4d: f1 table_id сохранён");
        CHECK(f2v == 1, "g4d: f2 num_changed = 1 (неклассовый skip)");
        CHECK(d3 && d3n > 0, "g4d: f3 data есть");

        c2b_br_t br3; c2b_br_init(&br3, d3, d3n);
        CHECK(c2b_br_bit(&br3) == 0, "g4d: item0 явный индекс");
        u32 vi = c2b_g4b_bit_varint(&br3);
        CHECK(vi + 1 == 2, "g4d: idx == 2");
        CHECK(c2b_br_bit(&br3) == 1, "g4d: hasKey");
        CHECK(c2b_br_bit(&br3) == 0, "g4d: без истории");
        char k3[40];
        c2b_g4b_bit_str(&br3, k3, sizeof(k3));
        CHECK(k3[0] == '0' && k3[1] == 0, "g4d: key \"0\" (S1 class_id, R32)");
        CHECK(c2b_br_bit(&br3) == 1, "g4d: hasValue");
        u32 sz3 = c2b_br_bits(&br3, 17);
        CHECK(sz3 == pl_n, "g4d: S1-размер базлайна == create-пути");
        static u8 db3[4096];
        for (u32 i = 0; i < sz3 && i < sizeof(db3); i++) db3[i] = (u8)c2b_br_bits(&br3, 8);
        CHECK(sz3 <= sizeof(db3) && memcmp(db3, plb, pl_n) == 0,
              "g4d: S1-базлайн байт-в-байт == create-пути");
        CHECK(br3.ovf == 0, "g4d: ридер без оверфлоу (item больше нет)");
        CHECK(g_g4d_kept == 1 && g_g4d_skip == 1, "g4d: счётчики kept/skip");
    }

    /* --- 10. не-baseline таблица: generic-путь (XF_RENUM 44->12) не сломан --- */
    {
        u8 oth[64]; u32 on = 0;
        const char *tn = "userinfo";
        oth[on++] = (1u << 3) | 2; oth[on++] = 8;
        memcpy(oth + on, tn, 8); on += 8;
        oth[on++] = (2u << 3); on += c2b_write_varint(oth + on, 5);   /* S2 f2 -> S1 f3 */
        u8 ino[96]; u32 ilo = 0;
        ilo += c2b_write_varint(ino + ilo, 44);
        ilo += c2b_write_varint(ino + ilo, on);
        for (u32 i = 0; i < on; i++) ino[ilo++] = oth[i];
        static u8 outo[256]; u32 olo = 0;
        i32 rco = c2b_translate(ino, ilo, outo, sizeof(outo), &olo, &g_st);
        CHECK(rco == 0 && olo > 2 && outo[0] == 12, "g4b: userinfo проходит generic-путь");
        /* generic-ренум: S2 f2 (num_entries) -> S1 f3 */
        u32 saw_f3 = 0;
        u32 po = 1; u32 lo = 0;
        po += c2b_read_varint(outo + po, olo - po, &lo);
        u32 pp = po;
        while (pp < po + lo) {
            u32 tag, c = c2b_read_varint(outo + pp, po + lo - pp, &tag);
            if (!c) break;
            pp += c;
            if ((tag & 7) == 0) { u32 v; c = c2b_read_varint(outo + pp, po + lo - pp, &v); pp += c;
                                  if ((tag >> 3) == 3) saw_f3 = v; }
            else if ((tag & 7) == 2) { u32 l; c = c2b_read_varint(outo + pp, po + lo - pp, &l);
                                       if (!c) break; pp += c; pp += l; }
            else break;
        }
        CHECK(saw_f3 == 5, "g4b: generic-ренум f3 сохранён");
    }

    /* --- 11. W-1 (t35): flags&1 (per-item) != whole-blob snappy: апдейт raw-блоба
     * при flags=1 обязан транскодиться (раньше: snappy-фейл -> -3, ovf++) --- */
    {
        static u8 cb2[4096];                     /* Create: items c per-item битом 0 */
        c2b_bw_t w2;
        w2.buf = cb2; w2.cap = sizeof(cb2); w2.pos = 0; w2.bitval = 0; w2.bitcnt = 0; w2.ovf = 0;
        c2b_bw_bit(&w2, 0); c2b_g4b_wvarint(&w2, 0);            /* idx=1 */
        c2b_bw_bit(&w2, 1); c2b_bw_bit(&w2, 0); tst_wstr(&w2, "1"); /* key "1" -> класс */
        c2b_bw_bit(&w2, 1);
        c2b_bw_bit(&w2, 0);                                      /* per-item compressed=0 */
        c2b_bw_bits(&w2, blp_n, 17);
        for (u32 i = 0; i < blp_n; i++) c2b_bw_bits(&w2, blp[i], 8);
        u32 cb2_n = c2b_bw_flush(&w2);
        CHECK(w2.ovf == 0, "w1: create-блоб (flags=1) без оверфлоу");

        u8 cw[9216]; u32 cwn = 0;                /* S2 CreateStringTable, f6 flags=1 */
        cw[cwn++] = (1u << 3) | 2; cw[cwn++] = 16;
        memcpy(cw + cwn, "instanceBaseline", 16); cwn += 16;
        cw[cwn++] = (2u << 3); cwn += c2b_write_varint(cw + cwn, 1);
        cw[cwn++] = (6u << 3); cwn += c2b_write_varint(cw + cwn, 1);   /* flags=1 */
        cw[cwn++] = (7u << 3) | 2; cwn += c2b_write_varint(cw + cwn, cb2_n);
        for (u32 i = 0; i < cb2_n; i++) cw[cwn++] = cb2[i];
        u8 inc[10240]; u32 ilc = 0;
        ilc += c2b_write_varint(inc + ilc, 44);
        ilc += c2b_write_varint(inc + ilc, cwn);
        for (u32 i = 0; i < cwn; i++) inc[ilc++] = cw[i];
        static u8 outc[512 * 1024]; u32 olc = 0;
        i32 rcc = c2b_translate(inc, ilc, outc, sizeof(outc), &olc, &g_st);
        CHECK(rcc == 0 && olc > 2 && outc[0] == 12, "w1: create flags=1 -> S1 12");

        static u8 ub2[8192];                     /* апдейт: СЫРОЙ блоб (без snappy) */
        c2b_bw_t u2;
        u2.buf = ub2; u2.cap = sizeof(ub2); u2.pos = 0; u2.bitval = 0; u2.bitcnt = 0; u2.ovf = 0;
        c2b_bw_bit(&u2, 0); c2b_g4b_wvarint(&u2, 1);            /* idx=2 */
        c2b_bw_bit(&u2, 1); c2b_bw_bit(&u2, 0); tst_wstr(&u2, "1");
        c2b_bw_bit(&u2, 1);
        c2b_bw_bit(&u2, 0);                                      /* per-item compressed=0 */
        c2b_bw_bits(&u2, blp_n, 17);
        for (u32 i = 0; i < blp_n; i++) c2b_bw_bits(&u2, blp[i], 8);
        u32 ub2_n = c2b_bw_flush(&u2);
        CHECK(u2.ovf == 0, "w1: апдейт-блоб без оверфлоу");

        u8 upw[64]; u32 unw = 0;                 /* table_id уже обновлён Create-ем */
        upw[unw++] = (1u << 3); unw += c2b_write_varint(upw + unw, g_g4b_tbl_id);
        upw[unw++] = (2u << 3); unw += c2b_write_varint(upw + unw, 1);
        upw[unw++] = (3u << 3) | 2; unw += c2b_write_varint(upw + unw, ub2_n);
        for (u32 i = 0; i < ub2_n; i++) upw[unw++] = ub2[i];
        u8 inw[1024]; u32 ilw = 0;
        ilw += c2b_write_varint(inw + ilw, 45);
        ilw += c2b_write_varint(inw + ilw, unw);
        for (u32 i = 0; i < unw; i++) inw[ilw++] = upw[i];
        u32 ovf_w1 = g_g4d_ovf, msgs_w1 = g_g4d_msgs;
        static u8 outw[8192]; u32 olw = 0;
        i32 rcw = c2b_translate(inw, ilw, outw, sizeof(outw), &olw, &g_st);
        CHECK(rcw == 0 && olw > 4 && outw[0] == 13, "w1: апдейт при flags=1 проходит");
        CHECK(g_g4d_ovf == ovf_w1, "w1: snappy-попытки не было (ovf не растёт)");
        CHECK(g_g4d_msgs == msgs_w1 + 1, "w1: апдейт посчитан в msgs");
    }

    printf("  [i] g4b: msgs=%u rows=%u kept=%u skip=%u nocls=%u decerr=%u ovf=%u upd_drop=%u in=%u out=%u cls_ovf=%u\n",
           g_g4b_msgs, g_g4b_rows, g_g4b_kept, g_g4b_skip, g_g4b_nocls,
           g_g4b_decerr, g_g4b_ovf, g_g4b_upd_drop, g_g4b_bin, g_g4b_bout,
           g_g4b_cls_ovf);
}

/* ---------- фаза G-4c: полиморфные указатели (per-entity active serializer) ---------- */
static void test_g4c(void)
{
    printf("[t] polymorphic pointers (G-4c)\n");
    CHECK(g_cls_emitted >= 1, "g4c: класс 1 зарегистрирован (наследие test_g4)");
    u32 poly_before = g_g4_poly;

    /* --- 1. FSV v2: CBodyComponentS2 + CCSPlayer v2 (m_pBody -> poly) --- */
    u8 m[512]; u32 n = 0;
    const char *syms[] = {
        "CCSPlayer",               /* 0 */
        "m_pBody",                 /* 1 */
        "CBodyComponentS1",        /* 2  (ser_name) */
        "CBodyComponentS1*",       /* 3  (type) */
        "CBodyComponentS2",        /* 4  (poly + ser_name) */
        "m_iHealth", "int32",      /* 5,6 */
        "m_flMaxspeed", "float32", /* 7,8 */
        "m_nTickBase", "int32",    /* 9,10 */
    };
    for (u32 i = 0; i < sizeof(syms) / sizeof(syms[0]); i++)
        n += fsv_sym(m + n, syms[i]);

    fsv_fld_spec_t fs2[2] = {          /* CBodyComponentS2 */
        { 8, 7, -1, 0, 0, 0, 0 },      /* m_flMaxspeed float32 -> NOSCALE */
        { 10, 9, -1, 0, 0, 0, 0 },     /* m_nTickBase int32 -> VARINT_S */
    };
    for (u32 i = 0; i < 2; i++) n += fsv_field(m + n, &fs2[i]);
    fsv_fld_spec_t fp2[2] = {          /* CCSPlayer v2 (replace) */
        { 3, 1, -1, 0, 2, 0, 4 },      /* m_pBody CBodyComponentS1* poly=[S2] */
        { 6, 5, -1, 0, 0, 0, 0 },      /* m_iHealth */
    };
    for (u32 i = 0; i < 2; i++) n += fsv_field(m + n, &fp2[i]);

    u32 ivs2[2] = { 0, 1 };            /* CBodyComponentS2: f3-ординалы [maxspeed, tickbase] */
    u32 ivp2[2] = { 2, 3 };            /* CCSPlayer v2: f3-ординалы [m_pBody, m_iHealth] */
    n += fsv_ser(m + n, 4, 0, ivs2, 2);
    n += fsv_ser(m + n, 0, 2, ivp2, 2);
    c2b_fsv_parse(m, n);
    CHECK(g_fsv_err == 1, "g4c: fsv err==1 (garbage-41 из test_translate; FSV-хук теперь и на 41)");

    /* --- 2. разметка полей: ser_id, poly, poly_slot --- */
    i32 serS1 = c2b_fsv_find_ser("CBodyComponentS1");
    i32 serS2 = c2b_fsv_find_ser("CBodyComponentS2");
    i32 serP2 = c2b_fsv_find_ser("CCSPlayer");
    CHECK(serS1 >= 0 && serS2 >= 0 && serP2 >= 0, "g4c: сериализаторы на месте");
    CHECK(g_fsv_ser[serP2].ver == 2 && g_fsv_ser[serP2].n == 2,
          "g4c: CCSPlayer v2 replace (2 поля)");
    {
        u32 ref = g_fsv_ser[serP2].fbase + g_fsv_idx[g_fsv_ser[serP2].idx_off + 0];
        const c2b_fsv_field_t *F = &g_fsv_field[ref];
        CHECK(F->poly_n == 1, "g4c: m_pBody poly_n=1");
        CHECK(F->poly_slot != 0xFFFFu && F->poly_slot < C2B_G4_POLY_SLOTS,
              "g4c: m_pBody poly_slot выдан");
        CHECK(F->ser_id == (u16)serS1, "g4c: m_pBody own = CBodyComponentS1");
        CHECK(F->poly[0] == (u16)serS2, "g4c: m_pBody poly[0] = CBodyComponentS2");
    }

    /* --- 3. ClassInfo re-synth: класс 1 -> CCSPlayer v2 --- */
    {
        static u8 ci_in[64], ci_out[256 * 1024];
        u32 cn = 0;
        cn += c2b_write_varint(ci_in + cn, (1u << 3) | 0);
        cn += c2b_write_varint(ci_in + cn, 1);
        u8 inner[64]; u32 inn = 0;
        inner[inn++] = (1u << 3); inn += c2b_write_varint(inner + inn, 1);
        const char *nm = "CCSPlayer";
        u32 l = 0; while (nm[l]) l++;
        inner[inn++] = (3u << 3) | 2; inn += c2b_write_varint(inner + inn, l);
        for (u32 i = 0; i < l; i++) inner[inn++] = (u8)nm[i];
        cn += c2b_write_varint(ci_in + cn, (2u << 3) | 2);
        cn += c2b_write_varint(ci_in + cn, inn);
        for (u32 i = 0; i < inn; i++) ci_in[cn++] = inner[i];
        u8 in[80]; u32 il = 0;
        il += c2b_write_varint(in + il, 42);
        il += c2b_write_varint(in + il, cn);
        for (u32 i = 0; i < cn; i++) in[il++] = ci_in[i];
        u32 olen = 0;
        i32 rc = c2b_translate(in, il, ci_out, sizeof(ci_out), &olen, &g_st);
        CHECK(rc == 0 && g_class_ser_map[1] == (u16)serP2,
              "g4c: класс 1 перепривязан к CCSPlayer v2");
    }

    /* --- 4. create entity 4: poly sel=1 (S2), maxspeed/tickbase/health --- */
    static u8 e1[1024];
    c2b_bw_t w;
    w.buf = e1; w.cap = sizeof(e1); w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
    g4e_fp_t fp;
    c2b_bw_ubitvar(&w, 4);
    c2b_bw_bits(&w, 2, 2);
    c2b_bw_bits(&w, 1, c2b_g4_class_bits(64));
    c2b_bw_bits(&w, 0x2A, 17);
    g4e_varu(&w, 0);
    g4e_fp_reset(&fp);
    g4e_target0(&w, &fp, 0);                       /* [0] m_pBody */
    g4e_push(&w, &fp, 0, 0);                       /* [0,0] m_flMaxspeed */
    g4e_huff(&w, 0); fp.path[1]++;                 /* [0,1] m_nTickBase */
    g4e_huff(&w, 29); fp.last--; fp.path[0]++;     /* [1] m_iHealth */
    g4e_huff(&w, 39);
    c2b_bw_bit(&w, 1); c2b_bw_ubitvar(&w, 1);      /* [0] active, poly sel=1 -> S2 (readUBitVar) */
    c2b_bw_bits(&w, c2b_f32_to_bits(320.0f), 32);  /* [0,0] */
    g4e_varu(&w, 42u << 1);                        /* [0,1] zigzag */
    g4e_varu(&w, 111u << 1);                       /* [1] zigzag */
    u32 e1n = c2b_bw_flush(&w);
    CHECK(w.ovf == 0, "g4c: S2-энкодер create без оверфлоу");

    static u8 out1[256 * 1024]; u32 olen1 = 0;
    {
        u8 pe[2048]; u32 pn = 0;
        pe[pn++] = (1u << 3); pn += c2b_write_varint(pe + pn, 64);
        pe[pn++] = (2u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (3u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (7u << 3) | 2; pn += c2b_write_varint(pe + pn, e1n);
        for (u32 i = 0; i < e1n; i++) pe[pn++] = e1[i];
        u8 in[4096]; u32 il = 0;
        il += c2b_write_varint(in + il, 55);
        il += c2b_write_varint(in + il, pn);
        for (u32 i = 0; i < pn; i++) in[il++] = pe[i];
        i32 rc = c2b_translate(in, il, out1, sizeof(out1), &olen1, &g_st);
        CHECK(rc == 0, "g4c: translate create rc==0");
    }
    CHECK(g_g4_poly == poly_before + 1, "g4c: poly-активация учтена (sel=1 -> S2)");

    /* --- 5. разбор S1 create: слоты maxspeed/tickbase/health --- */
    u32 slot_max = 0xFFFFFFFFu, slot_tb = 0xFFFFFFFFu, slot_h = 0xFFFFFFFFu;
    {
        const dt_entry *dte = c2b_dt_find(c2b_fnv1a("DT_CSPlayer"));
        u32 off = 0, cnt = 0;
        c2b_s1_slots_of((u32)(dte - g_dt_index), &off, &cnt);
        slot_max = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_flMaxspeed"));
        slot_tb  = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_nTickBase"));
        slot_h   = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_iHealth"));
    }
    CHECK(slot_max != 0xFFFFFFFFu && slot_tb != 0xFFFFFFFFu && slot_h != 0xFFFFFFFFu,
          "g4c: слоты m_flMaxspeed/m_nTickBase/m_iHealth есть в DT_CSPlayer");
    CHECK(olen1 > 2 && out1[0] == 26, "g4c: S1 svc(26)");
    {
        u32 o = 1, slen = 0;
        o += c2b_read_varint(out1 + o, olen1 - o, &slen);
        const u8 *f7 = 0; u32 f7n = 0;
        u32 p = o;
        while (p < o + slen) {
            u32 tag, c = c2b_read_varint(out1 + p, o + slen - p, &tag);
            if (!c) break;
            p += c;
            u32 fid = tag >> 3, wt = tag & 7;
            if (wt == 0) { u32 v; c = c2b_read_varint(out1 + p, o + slen - p, &v); p += c; }
            else if (wt == 2) { u32 l; c = c2b_read_varint(out1 + p, o + slen - p, &l); p += c;
                                if (fid == 7) { f7 = out1 + p; f7n = l; } p += l; }
            else break;
        }
        CHECK(f7 && f7n > 0, "g4c: entity_data есть");
        c2b_br_t r;
        c2b_br_init(&r, f7, f7n);
        CHECK(c2b_br_ubitvar(&r) == 4, "g4c: idx=4");
        CHECK(c2b_br_bit(&r) == 0 && c2b_br_bit(&r) == 1, "g4c: enter");
        c2b_br_bits(&r, c2b_g4_class_bits(g_cls_emitted));
        c2b_br_bits(&r, 10);
        CHECK(c2b_br_bit(&r) == 1, "g4c: newWay");
        i32 prev = -1;
        u32 got[8], gn = 0;
        for (;;) {
            i32 ix;
            if (c2b_br_bit(&r)) ix = prev + 1;
            else if (c2b_br_bit(&r)) ix = prev + 1 + (i32)c2b_br_bits(&r, 3);
            else {
                u32 ret = c2b_br_bits(&r, 7);
                switch (ret & 96u) {
                case 32: ret = (ret & ~96u) | (c2b_br_bits(&r, 2) << 5); break;
                case 64: ret = (ret & ~96u) | (c2b_br_bits(&r, 4) << 5); break;
                case 96: ret = (ret & ~96u) | (c2b_br_bits(&r, 7) << 5); break;
                }
                if (ret == 0xFFF) { ix = -1; break; }
                ix = prev + 1 + (i32)ret;
            }
            if (ix < 0) break;
            prev = ix;
            if (gn < 8) got[gn++] = (u32)ix;
        }
        u32 cand[3], wn = 0;
        cand[wn++] = slot_max; cand[wn++] = slot_tb; cand[wn++] = slot_h;
        for (u32 i = 0; i < wn; i++)
            for (u32 j = i + 1; j < wn; j++)
                if (cand[j] < cand[i]) { u32 t = cand[i]; cand[i] = cand[j]; cand[j] = t; }
        CHECK(gn == wn, "g4c: create: 3 слота");
        int ok = (gn == wn);
        for (u32 i = 0; i < wn && ok; i++) ok = (got[i] == cand[i]);
        CHECK(ok, "g4c: create слоты по возрастанию");
        {
            u32 hv = 0xFFFFFFFFu, tv = 0xFFFFFFFFu;
            float mv = 0;
            for (u32 i = 0; i < gn; i++) {
                if (got[i] == slot_h) hv = c2b_br_bits(&r, 32);
                else if (got[i] == slot_tb) tv = c2b_br_bits(&r, 32);
                else if (got[i] == slot_max) mv = c2b_f32_from_bits(c2b_br_bits(&r, 32));
            }
            CHECK(hv == 111 && tv == 42 && mv == 320.0f,
                  "g4c: create значения 111/42/320.0 (S2-схема!)");
        }
    }

    /* --- 6. update entity 4: poly sel=0 -> СВИЧ на CBodyComponentS1 --- */
    static u8 e2[1024];
    w.buf = e2; w.cap = sizeof(e2); w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
    c2b_bw_ubitvar(&w, 4);
    c2b_bw_bits(&w, 0, 2);                         /* delta */
    g4e_fp_reset(&fp);
    g4e_target0(&w, &fp, 0);                       /* [0] m_pBody */
    g4e_push(&w, &fp, 0, 0);                       /* [0,0] m_cellX (R42: полная шестёрка) */
    g4e_huff(&w, 0); fp.path[1]++;                 /* [0,1] m_cellY */
    g4e_huff(&w, 0); fp.path[1]++;                 /* [0,2] m_cellZ */
    g4e_huff(&w, 0); fp.path[1]++;                 /* [0,3] m_vecX */
    g4e_huff(&w, 0); fp.path[1]++;                 /* [0,4] m_vecY */
    g4e_huff(&w, 0); fp.path[1]++;                 /* [0,5] m_vecZ */
    g4e_huff(&w, 29); fp.last--; fp.path[0]++;     /* [1] m_iHealth */
    g4e_huff(&w, 39);
    c2b_bw_bit(&w, 1); c2b_bw_ubitvar(&w, 0);      /* [0] active, sel=0 -> S1 (readUBitVar) */
    g4e_varu(&w, 0);                               /* [0,0] cellX=0 */
    g4e_varu(&w, 10);                              /* [0,1] cellY=10 */
    g4e_varu(&w, 0);                               /* [0,2] cellZ=0 */
    g4e_coord(&w, 0.0f);                           /* [0,3] vecX=0 */
    g4e_coord(&w, 1.5f);                           /* [0,4] vecY=1.5 */
    g4e_coord(&w, 0.0f);                           /* [0,5] vecZ=0 */
    g4e_varu(&w, 222u << 1);                       /* [1] health */
    u32 e2n = c2b_bw_flush(&w);
    CHECK(w.ovf == 0, "g4c: S2-энкодер update без оверфлоу");

    static u8 out2[256 * 1024]; u32 olen2 = 0;
    {
        u8 pe[2048]; u32 pn = 0;
        pe[pn++] = (1u << 3); pn += c2b_write_varint(pe + pn, 64);
        pe[pn++] = (2u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (3u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (7u << 3) | 2; pn += c2b_write_varint(pe + pn, e2n);
        for (u32 i = 0; i < e2n; i++) pe[pn++] = e2[i];
        u8 in[4096]; u32 il = 0;
        il += c2b_write_varint(in + il, 55);
        il += c2b_write_varint(in + il, pn);
        for (u32 i = 0; i < pn; i++) in[il++] = pe[i];
        i32 rc = c2b_translate(in, il, out2, sizeof(out2), &olen2, &g_st);
        CHECK(rc == 0, "g4c: translate update rc==0");
    }
    CHECK(g_g4_poly == poly_before + 2, "g4c: свич poly sel=0 -> S1 учтён");

    /* --- 7. разбор S1 update: m_vecOrigin[1] = 10*512-16384+1.5, health 222 --- */
    {
        u32 o = 1, slen = 0;
        o += c2b_read_varint(out2 + o, olen2 - o, &slen);
        const u8 *f7 = 0; u32 f7n = 0;
        u32 p = o;
        while (p < o + slen) {
            u32 tag, c = c2b_read_varint(out2 + p, o + slen - p, &tag);
            if (!c) break;
            p += c;
            u32 fid = tag >> 3, wt = tag & 7;
            if (wt == 0) { u32 v; c = c2b_read_varint(out2 + p, o + slen - p, &v); p += c; }
            else if (wt == 2) { u32 l; c = c2b_read_varint(out2 + p, o + slen - p, &l); p += c;
                                if (fid == 7) { f7 = out2 + p; f7n = l; } p += l; }
            else break;
        }
        CHECK(f7 && f7n > 0, "g4c: update entity_data есть");
        c2b_br_t r;
        c2b_br_init(&r, f7, f7n);
        CHECK(c2b_br_ubitvar(&r) == 4, "g4c: upd idx=4");
        CHECK(c2b_br_bit(&r) == 0 && c2b_br_bit(&r) == 0, "g4c: delta-флаги");
        CHECK(c2b_br_bit(&r) == 1, "g4c: newWay");
        i32 prev = -1;
        u32 got[8], gn = 0;
        for (;;) {
            i32 ix;
            if (c2b_br_bit(&r)) ix = prev + 1;
            else if (c2b_br_bit(&r)) ix = prev + 1 + (i32)c2b_br_bits(&r, 3);
            else {
                u32 ret = c2b_br_bits(&r, 7);
                switch (ret & 96u) {
                case 32: ret = (ret & ~96u) | (c2b_br_bits(&r, 2) << 5); break;
                case 64: ret = (ret & ~96u) | (c2b_br_bits(&r, 4) << 5); break;
                case 96: ret = (ret & ~96u) | (c2b_br_bits(&r, 7) << 5); break;
                }
                if (ret == 0xFFF) { ix = -1; break; }
                ix = prev + 1 + (i32)ret;
            }
            if (ix < 0) break;
            prev = ix;
            if (gn < 8) got[gn++] = (u32)ix;
        }
        u32 slot_org = 0xFFFFFFFFu;
        {
            const dt_entry *dte = c2b_dt_find(c2b_fnv1a("DT_CSPlayer"));
            u32 off = 0, cnt = 0;
            c2b_s1_slots_of((u32)(dte - g_dt_index), &off, &cnt);
            slot_org = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_vecOrigin"));
        }
        u32 cand[2], wn = 0;
        cand[wn++] = slot_org; cand[wn++] = slot_h;
        for (u32 i = 0; i < wn; i++)
            for (u32 j = i + 1; j < wn; j++)
                if (cand[j] < cand[i]) { u32 t = cand[i]; cand[i] = cand[j]; cand[j] = t; }
        CHECK(gn == wn, "g4c: update: 2 слота (origin+health)");
        int ok = (gn == wn);
        for (u32 i = 0; i < wn && ok; i++) ok = (got[i] == cand[i]);
        CHECK(ok, "g4c: update слоты по возрастанию");
        {
            u32 hv = 0xFFFFFFFFu;
            float ox = 0, oy = 0, oz = 0;
            for (u32 i = 0; i < gn; i++) {
                if (got[i] == slot_h) hv = c2b_br_bits(&r, 32);
                else if (got[i] == slot_org) {
                    ox = c2b_f32_from_bits(c2b_br_bits(&r, 32));
                    oy = c2b_f32_from_bits(c2b_br_bits(&r, 32));
                    oz = c2b_f32_from_bits(c2b_br_bits(&r, 32));
                }
            }
            CHECK(hv == 222, "g4c: update health=222");
            /* R42: полная шестёрка cell(0/10/0)+vec(0/1.5/0) ->
             * 0*512-16384+0=-16384; 10*512-16384+1.5=-11262.5; 0*512-16384+0=-16384 */
            CHECK(ox == -16384.0f && oy == -11262.5f && oz == -16384.0f,
                  "g4c: m_vecOrigin = cell*512-16384+off, полная шестёрка (R42, без нулей)");
        }
    }
    printf("  [i] g4c: poly=%u (было %u)\n", g_g4_poly, poly_before);
}

/* ---------- t35: cmd=3 (LEAVE+DELETE) + дроп UPDATE по удалённой ---------- */
static void test_g4_cmd3(void)
{
    printf("[t] g4 entity cmd=3 (leave+delete + дроп апдейта)\n");
    CHECK(g_cls_emitted >= 1, "cmd3: класс зарегистрирован (наследие test_g4)");
    u32 newb = g_g4_ent_new, delb = g_g4_ent_del, dsb = g_g4_desync;
    u32 slot_health = 0xFFFFFFFFu;
    {
        const dt_entry *dte = c2b_dt_find(c2b_fnv1a("DT_CSPlayer"));
        u32 off = 0, cnt = 0;
        if (dte && c2b_s1_slots_of((u32)(dte - g_dt_index), &off, &cnt) == 0)
            slot_health = c2b_g4_slot_hash(off, cnt, c2b_fnv1a("m_iHealth"));
    }
    CHECK(slot_health != 0xFFFFFFFFu, "cmd3: слот m_iHealth найден");

    /* --- msgA: CREATE entity 6 (cmd=2), класс 1, serial 0x2C, health=777 --- */
    static u8 ent[512];
    c2b_bw_t w; w.buf = ent; w.cap = sizeof(ent);
    w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
    g4e_fp_t fp;
    c2b_bw_ubitvar(&w, 6);                       /* idx 6 */
    c2b_bw_bits(&w, 2, 2);                       /* cmd=2 CREATE */
    CHECK(g_fsv_max_classes == 64, "cmd3: max_classes не тронут (t36/audit08)");
    c2b_bw_bits(&w, 1, c2b_g4_class_bits(g_fsv_max_classes)); /* cls2=1 (как ридер) */
    c2b_bw_bits(&w, 0x2C, 17);                   /* serial */
    g4e_varu(&w, 0);
    g4e_fp_reset(&fp);
    g4e_huff(&w, 0); fp.path[0] = 0;             /* [0] m_pBody */
    g4e_huff(&w, 0); fp.path[0] = 1;             /* [1] m_iHealth */
    g4e_huff(&w, 39);
    c2b_bw_bit(&w, 1);                           /* [0] pointer bool */
    g4e_varu(&w, 777u << 1);                     /* [1] health (zigzag) */
    u32 an = c2b_bw_flush(&w);
    CHECK(w.ovf == 0, "cmd3: S2-энкодер msgA без ovf");

    u8 inA[1024]; u32 ilA = 0;
    {   u8 pe[1024]; u32 pn = 0;
        pe[pn++] = (1u << 3); pn += c2b_write_varint(pe + pn, 64);
        pe[pn++] = (2u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (3u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (7u << 3) | 2; pn += c2b_write_varint(pe + pn, an);
        for (u32 i = 0; i < an; i++) pe[pn++] = ent[i];
        ilA += c2b_write_varint(inA + ilA, 55);
        ilA += c2b_write_varint(inA + ilA, pn);
        for (u32 i = 0; i < pn; i++) inA[ilA++] = pe[i]; }
    static u8 outA[256 * 1024]; u32 olA = 0;
    CHECK(c2b_translate(inA, ilA, outA, sizeof(outA), &olA, &g_st) == 0,
          "cmd3: msgA translate rc==0");
    CHECK(g_g4_ent_new == newb + 1, "cmd3: ent_new +1");

    CHECK(olA > 2 && outA[0] == 26, "cmd3: S1 svc_PacketEntities(26)");
    u32 oa = 1, la = 0; oa += c2b_read_varint(outA + oa, olA - oa, &la);
    const u8 *f7a = 0; u32 f7an = 0, f2a = 0, p = oa;
    while (p < oa + la) {
        u32 tag, c = c2b_read_varint(outA + p, oa + la - p, &tag); if (!c) break;
        p += c;
        u32 fid = tag >> 3, wt = tag & 7;
        if (wt == 0) { u32 v; c = c2b_read_varint(outA + p, oa + la - p, &v); p += c;
                       if (fid == 2) f2a = v; }
        else if (wt == 2) { u32 l; c = c2b_read_varint(outA + p, oa + la - p, &l); p += c;
                            if (fid == 7) { f7a = outA + p; f7an = l; } p += l; }
        else break;
    }
    CHECK(f2a == 1 && f7a && f7an > 0, "cmd3: msgA f2=1, entity_data есть");

    c2b_br_t r; c2b_br_init(&r, f7a, f7an);
    u32 dA = c2b_br_ubitvar(&r), lvA = c2b_br_bit(&r), enA = c2b_br_bit(&r);
    CHECK(dA == 6 && lvA == 0 && enA == 1, "cmd3: S1 create (idx 6, enter)");
    CHECK(c2b_br_bits(&r, c2b_g4_class_bits(g_cls_emitted)) == 0 &&
          c2b_br_bits(&r, 10) == (0x2C & 0x3FF), "cmd3: class=0, serial 0x2C");
    CHECK(c2b_br_bit(&r) == 1, "cmd3: newWay=1");
    {   /* t36-фикс: S1-лейаут = список fieldidx -> 0xFFF-терминатор -> значения
         * (см. c2b_g4_emit_fieldlist). Единственный слот m_iHealth = 777 (32 бита). */
        i32 pv = -1, ix = -1;
        for (;;) {
            if (c2b_br_bit(&r)) ix = pv + 1;
            else if (c2b_br_bit(&r)) ix = pv + 1 + (i32)c2b_br_bits(&r, 3);
            else {
                u32 ret = c2b_br_bits(&r, 7);
                switch (ret & 96u) {
                case 32: ret = (ret & ~96u) | (c2b_br_bits(&r, 2) << 5); break;
                case 64: ret = (ret & ~96u) | (c2b_br_bits(&r, 4) << 5); break;
                case 96: ret = (ret & ~96u) | (c2b_br_bits(&r, 7) << 5); break;
                }
                if (ret == 0xFFF) { ix = -1; break; }
                ix = pv + 1 + (i32)ret;
            }
            if (ix < 0) break;
            pv = ix;
        }
        CHECK(pv == (i32)slot_health && c2b_br_bits(&r, 32) == 777,
              "cmd3: слот m_iHealth = 777");
    }

    /* --- msgB: cmd=3 (LEAVE+DELETE) entity 6 --- */
    w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
    c2b_bw_ubitvar(&w, 6);
    c2b_bw_bits(&w, 3, 2);                       /* cmd=3: больше ничего не читается */
    u32 bn = c2b_bw_flush(&w);
    u8 inB[128]; u32 ilB = 0;
    {   u8 pe[128]; u32 pn = 0;
        pe[pn++] = (1u << 3); pn += c2b_write_varint(pe + pn, 64);
        pe[pn++] = (2u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (3u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (7u << 3) | 2; pn += c2b_write_varint(pe + pn, bn);
        for (u32 i = 0; i < bn; i++) pe[pn++] = ent[i];
        ilB += c2b_write_varint(inB + ilB, 55);
        ilB += c2b_write_varint(inB + ilB, pn);
        for (u32 i = 0; i < pn; i++) inB[ilB++] = pe[i]; }
    u8 outB[4096]; u32 olB = 0;
    CHECK(c2b_translate(inB, ilB, outB, sizeof(outB), &olB, &g_st) == 0,
          "cmd3: msgB translate rc==0");
    CHECK(g_g4_ent_del == delb + 1, "cmd3: ent_del +1");
    {   u32 ob = 1, lb = 0; ob += c2b_read_varint(outB + ob, olB - ob, &lb);
        const u8 *f7b = 0; u32 f7bn = 0, q = ob;
        while (q < ob + lb) {
            u32 tag, c = c2b_read_varint(outB + q, ob + lb - q, &tag); if (!c) break;
            q += c;
            u32 fid = tag >> 3, wt = tag & 7;
            if (wt == 0) { u32 v; c = c2b_read_varint(outB + q, ob + lb - q, &v); q += c; }
            else if (wt == 2) { u32 l; c = c2b_read_varint(outB + q, ob + lb - q, &l); q += c;
                                if (fid == 7) { f7b = outB + q; f7bn = l; } q += l; }
            else break;
        }
        c2b_br_t r2; c2b_br_init(&r2, f7b, f7bn);
        u32 dB = c2b_br_ubitvar(&r2), lvB = c2b_br_bit(&r2);
        u32 dlB = lvB ? c2b_br_bit(&r2) : 0;
        CHECK(dB == 6 && lvB == 1 && dlB == 1, "cmd3: S1 leave+delete (idx 6)");
        CHECK(r2.ovf == 0, "cmd3: S1-ридер msgB без ovf");
    }

    /* --- msgC: UPDATE удалённой entity 6 -> g_g4_desync -> кадр ДРОП (-3) --- */
    w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
    c2b_bw_ubitvar(&w, 6);
    c2b_bw_bits(&w, 0, 2);                       /* UPDATE */
    u32 cn = c2b_bw_flush(&w);
    u8 inC[128]; u32 ilC = 0;
    {   u8 pe[128]; u32 pn = 0;
        pe[pn++] = (1u << 3); pn += c2b_write_varint(pe + pn, 64);
        pe[pn++] = (2u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (3u << 3); pn += c2b_write_varint(pe + pn, 1);
        pe[pn++] = (7u << 3) | 2; pn += c2b_write_varint(pe + pn, cn);
        for (u32 i = 0; i < cn; i++) pe[pn++] = ent[i];
        ilC += c2b_write_varint(inC + ilC, 55);
        ilC += c2b_write_varint(inC + ilC, pn);
        for (u32 i = 0; i < pn; i++) inC[ilC++] = pe[i]; }
    u8 outC[4096]; u32 olC = 0; u32 drb = g_st.dropped;
    i32 rcC = c2b_translate(inC, ilC, outC, sizeof(outC), &olC, &g_st);
    CHECK(rcC == 0 && olC == 0, "cmd3: UPDATE по удалённой -> out пуст (rc=-3)");
    CHECK(g_st.dropped == drb + 1 && g_g4_desync == dsb + 1,
          "cmd3: dropped+1, desync+1");
}

/* ---------- фаза G-5: selftest аплинка ---------- */
/* битрайтер — существующий c2b_bw_t (LSB-first, см. G-4): buf/cap/pos/bitcnt/ovf/bitval */

/* SDK WriteUsercmd 1:1 (дельта против from) */
static void c2b_bw_s1cmd(c2b_bw_t *w, const c2b_s1cmd_t *from, const c2b_s1cmd_t *to)
{
    if (to->cmd_num != from->cmd_num + 1) { c2b_bw_bit(w, 1); c2b_bw_bits(w, to->cmd_num, 32); }
    else c2b_bw_bit(w, 0);
    if (to->tick != from->tick + 1)       { c2b_bw_bit(w, 1); c2b_bw_bits(w, to->tick, 32); }
    else c2b_bw_bit(w, 0);
    for (int i = 0; i < 3; i++) {
        if (to->va[i] != from->va[i]) { c2b_bw_bit(w, 1); c2b_bw_bits(w, c2b_f32_to_bits(to->va[i]), 32); }
        else c2b_bw_bit(w, 0);
    }
    for (int i = 0; i < 3; i++) {
        if (to->aim[i] != from->aim[i]) { c2b_bw_bit(w, 1); c2b_bw_bits(w, c2b_f32_to_bits(to->aim[i]), 32); }
        else c2b_bw_bit(w, 0);
    }
    if (to->fwd != from->fwd) { c2b_bw_bit(w, 1); c2b_bw_bits(w, c2b_f32_to_bits(to->fwd), 32); } else c2b_bw_bit(w, 0);
    if (to->side != from->side) { c2b_bw_bit(w, 1); c2b_bw_bits(w, c2b_f32_to_bits(to->side), 32); } else c2b_bw_bit(w, 0);
    if (to->up != from->up) { c2b_bw_bit(w, 1); c2b_bw_bits(w, c2b_f32_to_bits(to->up), 32); } else c2b_bw_bit(w, 0);
    if (to->buttons != from->buttons) { c2b_bw_bit(w, 1); c2b_bw_bits(w, to->buttons, 32); }
    else c2b_bw_bit(w, 0);
    if (to->impulse != from->impulse) { c2b_bw_bit(w, 1); c2b_bw_bits(w, to->impulse, 8); }
    else c2b_bw_bit(w, 0);
    if (to->weap_sel != from->weap_sel) {
        c2b_bw_bit(w, 1); c2b_bw_bits(w, to->weap_sel, 11);
        if (to->weap_sub != from->weap_sub) { c2b_bw_bit(w, 1); c2b_bw_bits(w, to->weap_sub, 6); }
        else c2b_bw_bit(w, 0);
    } else c2b_bw_bit(w, 0);
    if (to->mdx != from->mdx) { c2b_bw_bit(w, 1); c2b_bw_bits(w, (u32)(u16)to->mdx, 16); }
    else c2b_bw_bit(w, 0);
    if (to->mdy != from->mdy) { c2b_bw_bit(w, 1); c2b_bw_bits(w, (u32)(u16)to->mdy, 16); }
    else c2b_bw_bit(w, 0);
}

static u32 c2b_t_s1_move(u8 *o, u32 backup, u32 nnew, const u8 *data, u32 dlen)
{
    u32 n = 0;
    o[n++] = 0x08; n += c2b_write_varint(o + n, backup);
    o[n++] = 0x10; n += c2b_write_varint(o + n, nnew);
    o[n++] = 0x1A; n += c2b_write_varint(o + n, dlen);
    for (u32 k = 0; k < dlen; k++) o[n++] = data[k];
    return n;
}

static u32 c2b_t_msg(u8 *o, u32 type, const u8 *pl, u32 pln)
{
    u32 n = c2b_write_varint(o, type);
    n += c2b_write_varint(o + n, pln);
    for (u32 k = 0; k < pln; k++) o[n++] = pl[k];
    return n;
}

/* парсер CBaseUserCmdPB из блока [0x0A][len][base] */
static i32 c2b_t_parse_block(const u8 *p, u32 n, u32 *cmd, u32 *tick, u32 *buttons,
                             u32 *va0b, u32 *fwdb, u32 *sideb, u32 *impulse,
                             u32 *weap, i32 *mdx, i32 *mdy, u32 *mdy_len)
{
    u32 ip = 0;
    if (n < 2 || p[ip] != 0x0A) return -1;
    ip++;
    u32 ln, c = c2b_read_varint(p + ip, n - ip, &ln); if (!c) return -1;
    ip += c;
    if (ln > n - ip) return -1;
    n = ip + ln;                                       /* граница base; ip уже на начале base */
    while (ip < n) {
        u32 tag; c = c2b_read_varint(p + ip, n - ip, &tag); if (!c) return -1;
        u32 f = tag >> 3, wt = tag & 7u;
        ip += c;
        if (wt == 0) {
            u64 v = 0; u32 sh = 0;
            for (;;) {
                if (ip >= n) return -1;
                u8 b = p[ip++];
                v |= (u64)(b & 0x7F) << sh;
                if (!(b & 0x80)) break;
                sh += 7;
            }
            if (f == 1) *cmd = (u32)v;
            else if (f == 2) *tick = (u32)v;
            else if (f == 8) *impulse = (u32)v;
            else if (f == 9) *weap = (u32)v;
            else if (f == 11) *mdx = (i32)(i64)v;
            else if (f == 12) { *mdy = (i32)(i64)v; *mdy_len = sh / 7 + 1; }
        } else if (wt == 2) {
            u32 sl; c = c2b_read_varint(p + ip, n - ip, &sl); if (!c) return -1;
            ip += c;
            if (sl > n - ip) return -1;
            if (f == 3) {                              /* buttons_pb {1 buttonstate1} */
                u32 j = ip;
                if (p[j] != 0x08) return -1;
                j++;
                u64 v = 0; u32 sh = 0;
                for (;;) {
                    if (j >= ip + sl) return -1;
                    u8 b = p[j++];
                    v |= (u64)(b & 0x7F) << sh;
                    if (!(b & 0x80)) break;
                    sh += 7;
                }
                *buttons = (u32)v;
            } else if (f == 4) {                       /* viewangles {1,2,3 fixed32} */
                u32 j = ip;
                for (u32 a = 0; a < 3; a++) {
                    u32 tag2; u32 c2 = c2b_read_varint(p + j, sl, &tag2); if (!c2) return -1;
                    if (tag2 != ((a + 1) << 3 | 5)) return -1;
                    j += c2;
                    if (a == 0) { u32 va32; memcpy(&va32, p + j, 4); *va0b = va32; } /* не выровнен */
                    j += 4;
                }
            }
            ip += sl;
        } else if (wt == 5) {
            if (n - ip < 4) return -1;
            u32 bits; memcpy(&bits, p + ip, 4);         /* p+ip не выровнен */
            if (f == 5) *fwdb = bits;
            else if (f == 6) *sideb = bits;
            ip += 4;
        } else return -1;
    }
    return 0;
}

static void test_uplink(void)
{
    printf("[t] uplink (G-5)\n");
    c2b_uplink_reset();

    /* --- msg1: S1 CLC_Move backup=1 new=2, цепочка c1->c2->c3 --- */
    static const c2b_s1cmd_t Z = { 0 };
    c2b_s1cmd_t c1 = Z, c2, c3, c4 = Z;
    c1.cmd_num = 5;  c1.tick = 600;
    c1.va[0] = 1.5f; c1.va[1] = -89.0f;
    c1.fwd = 250.0f; c1.side = -10.5f;
    c1.buttons = 1;  c1.impulse = 13;
    c1.weap_sel = 7; c1.weap_sub = 2;
    c1.mdx = 5;      c1.mdy = -7;
    c2 = c1; c2.cmd_num = 6; c2.tick = 601; c2.buttons = 0;
    c3 = c2; c3.cmd_num = 9; c3.va[0] = -0.25f; c3.mdy = 3;

    u8 bits1[128], bits2[64];
    c2b_bw_t w = { bits1, sizeof(bits1), 0, 0, 0, 0 };
    c2b_bw_s1cmd(&w, &Z, &c1);
    c2b_bw_s1cmd(&w, &c1, &c2);
    c2b_bw_s1cmd(&w, &c2, &c3);
    u32 nb1 = c2b_bw_flush(&w);
    CHECK(w.ovf == 0, "up: битрайтер msg1 без ovf");

    u8 pl1[256], stream[1024], out[4096];
    u32 sn = 0;
    sn += c2b_t_msg(stream + sn, 9, pl1,
                    c2b_t_s1_move(pl1, 1, 2, bits1, nb1));

    /* --- msg2: backup=0 new=1, цепочка c4 (продолжение baseline c3) --- */
    c4 = c3; c4.cmd_num = 10; c4.tick = 610; c4.fwd = 0.0f; c4.buttons = 8;
    w = (c2b_bw_t){ bits2, sizeof(bits2), 0, 0, 0, 0 };
    c2b_bw_s1cmd(&w, &c3, &c4);
    u32 nb2 = c2b_bw_flush(&w);
    u8 pl2[128];
    sn += c2b_t_msg(stream + sn, 9, pl2, c2b_t_s1_move(pl2, 0, 1, bits2, nb2));

    /* --- сопутствующие сообщения --- */
    u8 ci[64]; u32 cin = 0;
    {   /* ClientInfo S1: f1 fx64, f2=7, f3=1, f4(is_replay)=0 -> дроп, f5=12345,
           f6="player", f7 fx64 -> дроп */
        u8 b8[8] = { 0x44, 0x33, 0x22, 0x11, 0xDD, 0xCC, 0xBB, 0xAA };
        ci[cin++] = 0x09; for (int i = 0; i < 8; i++) ci[cin++] = b8[i];
        ci[cin++] = 0x10; cin += c2b_write_varint(ci + cin, 7);
        ci[cin++] = 0x18; ci[cin++] = 1;
        ci[cin++] = 0x20; ci[cin++] = 0;                 /* is_replay -> дроп */
        ci[cin++] = 0x28; cin += c2b_write_varint(ci + cin, 12345);
        ci[cin++] = 0x32; ci[cin++] = 6;
        for (int i = 0; i < 6; i++) ci[cin++] = "player"[i];
        ci[cin++] = 0x39; for (int i = 0; i < 8; i++) ci[cin++] = 0xEF;
        sn += c2b_t_msg(stream + sn, 8, ci, cin);
    }
    u8 vd[64]; u32 vdn = 0;
    {   /* VoiceData S1: f1="VOIC", f2 xuid=0x1122334455667788, f4=123, f5=4, f6=8 */
        vd[vdn++] = 0x0A; vd[vdn++] = 4;
        vd[vdn++] = 'V'; vd[vdn++] = 'O'; vd[vdn++] = 'I'; vd[vdn++] = 'C';
        vd[vdn++] = 0x11;
        { u64 x = 0x1122334455667788ull; for (int i = 0; i < 8; i++) vd[vdn++] = (u8)(x >> (8 * i)); }
        vd[vdn++] = 0x20; vdn += c2b_write_varint(vd + vdn, 123);
        vd[vdn++] = 0x28; vdn += c2b_write_varint(vd + vdn, 4);
        vd[vdn++] = 0x30; vdn += c2b_write_varint(vd + vdn, 8);
        sn += c2b_t_msg(stream + sn, 10, vd, vdn);
    }
    {   /* BaselineAck 11->{23}, identity payload */
        u8 ba[8]; u32 n = 0;
        ba[n++] = 0x08; n += c2b_write_varint(ba + n, 100);
        ba[n++] = 0x10; n += c2b_write_varint(ba + n, 1);
        sn += c2b_t_msg(stream + sn, 11, ba, n);
    }
    {   /* StringCmd 5 identity */
        u8 sc[16]; u32 n = 0;
        sc[n++] = 0x0A; sc[n++] = 6;
        for (int i = 0; i < 6; i++) sc[n++] = "say hi"[i];
        sn += c2b_t_msg(stream + sn, 5, sc, n);
    }
    sn += c2b_t_msg(stream + sn, 12, (const u8 *)"\x09\x01\x02\x03\x04\x05\x06\x07\x08", 9); /* R41: ListenEvents -> 206 (eventarraybits) */
    sn += c2b_t_msg(stream + sn, 14, (const u8 *)"\x08\x01", 2);   /* FileCRCCheck -> дроп */
    sn += c2b_t_msg(stream + sn, 17, (const u8 *)"\x08\x01", 2);   /* ClientMessage -> дроп */
    sn += c2b_t_msg(stream + sn, 99, (const u8 *)"\x08\x01", 2);   /* unknown -> дроп */

    u32 olen = 0;
    i32 rc = c2b_uplink_translate(stream, sn, out, sizeof(out), &olen);
    CHECK(rc == 0, "up: translate rc=0");
    CHECK(g_up_in == 10, "up: msgs_in=10 (2 Move + CI + Voice + BA + StringCmd + LE + 3 дропа)");
    CHECK(g_up_out == 7, "up: msgs_out=7 (2 Move + CI + Voice + BA + StringCmd + LE206)");
    CHECK(g_up_drop == 3, "up: dropped=3 (14/17/99; 12 теперь транскодится в 206)");
    CHECK(g_up_move == 2, "up: move-сообщений 2");
    CHECK(g_up_ucmds == 4, "up: usercmd'ов 4");

    /* --- разбор выхода --- */
    u32 ip = 0, saw_ci = 0, saw_vd = 0, saw_ba = 0, saw_sc = 0, saw_le = 0;
    u32 m21 = 0;
    while (ip < olen) {
        u32 type, ln, c;
        c = c2b_read_varint(out + ip, olen - ip, &type); if (!c) break;
        ip += c;
        c = c2b_read_varint(out + ip, olen - ip, &ln); if (!c) break;
        ip += c;
        if (type == 21) {
            /* payload: [0x1A][dn][blocks][0x20][last] */
            u32 p = ip;
            if (out[p] != 0x1A) { ip += ln; continue; }
            p++;
            u32 dn; c = c2b_read_varint(out + p, ln, &dn); if (!c) break;
            p += c;
            u32 q = p, nb = 0, cmdlast = 0;
            while (q < p + dn) {
                u32 bl; c = c2b_read_varint(out + q, p + dn - q, &bl); if (!c) break;
                q += c;
                u32 cmd = 0, tick = 0, buttons = 0, va0b = 0, fwdb = 0, sideb = 0;
                u32 impulse = 0, weap = 0, mdy_len = 0;
                i32 mdx = 0, mdy = 0;
                if (c2b_t_parse_block(out + q, bl, &cmd, &tick, &buttons, &va0b, &fwdb,
                                      &sideb, &impulse, &weap, &mdx, &mdy, &mdy_len) != 0) break;
                if (m21 == 0 && nb == 0) {
                    CHECK(cmd == 5, "up: c1 legacy_command_number=5");
                    CHECK(tick == 600, "up: c1 client_tick=600");
                    CHECK(buttons == 1, "up: c1 buttons=1");
                    CHECK(va0b == c2b_f32_to_bits(1.5f), "up: c1 va0 = 1.5 (fixed32)");
                    CHECK(fwdb == c2b_f32_to_bits(250.0f), "up: c1 fwd = 250.0");
                    CHECK(sideb == c2b_f32_to_bits(-10.5f), "up: c1 side = -10.5 -> leftmove");
                    CHECK(impulse == 13, "up: c1 impulse=13");
                    CHECK(weap == 7, "up: c1 weaponselect=7");
                    CHECK(mdx == 5 && mdy == -7, "up: c1 mdx=5 mdy=-7");
                    CHECK(mdy_len == 10, "up: c1 mdy=-7 -> 10-байтовый varint64");
                }
                q += bl;
                nb++;
                cmdlast = cmd;
            }
            {
                u32 last = 0;
                if (q < olen && out[q] == 0x20)
                    c2b_read_varint(out + q + 1, olen - q - 1, &last);
                CHECK(last == cmdlast, "up: last_command_number == последнему блоку");
                if (m21 == 0) CHECK(nb == 3 && last == 9, "up: msg1 -> 3 блока, last=9");
                else CHECK(nb == 1 && last == 10, "up: msg2 -> 1 блок, last=10");
            }
            m21++;
            ip += ln;
        } else if (type == 20) {
            saw_ci = 1;
            /* f1 fx64, f2=7, f3=1, f5=12345, f6="player"; 4/7 дропнуты */
            u32 p = ip;
            CHECK(out[p] == 0x09, "up: CI f1 fixed64 tag");
            p += 1 + 8;
            CHECK(out[p] == 0x10, "up: CI f2 tag");
            p++;
            u32 v; c = c2b_read_varint(out + p, 4, &v);
            CHECK(v == 7, "up: CI server_count=7");
            p += c;
            CHECK(out[p] == 0x18 && out[p + 1] == 1, "up: CI is_hltv=1");
            p += 2;
            CHECK(out[p] == 0x28, "up: CI f5 tag (f4 дропнут)");
            p++;
            c = c2b_read_varint(out + p, 4, &v);
            CHECK(v == 12345, "up: CI friends_id=12345");
            p += c;
            CHECK(out[p] == 0x32, "up: CI f6 tag");
            p += 1;
            c = c2b_read_varint(out + p, 4, &v);
            CHECK(v == 6 && out[p + c + 0] == 'p', "up: CI friends_name=\"player\"");
            CHECK(ln == 24 && out[ip + ln - 1] == 'r',
                  "up: CI payload 24Б, f4/f7 дропнуты (последний байт 'r')");
            ip += ln;
        } else if (type == 22) {
            saw_vd = 1;
            u32 p = ip;
            CHECK(out[p] == 0x0A, "up: Voice f1 audio tag");
            p++;
            u32 al; c = c2b_read_varint(out + p, 8, &al); p += c;
            CHECK(out[p] == 0x12 && out[p + 1] == 4, "up: audio voice_data len=4");
            CHECK(out[p + 2] == 'V' && out[p + 5] == 'C', "up: voice_data=VOIC");
            p += 6;
            CHECK(out[p] == 0x18, "up: audio sequence_bytes tag");
            p++;
            u32 v; c = c2b_read_varint(out + p, 4, &v);
            CHECK(v == 123, "up: sequence_bytes=123");
            p += c;
            CHECK(out[p] == 0x20, "up: audio section_number tag");
            p++;
            c = c2b_read_varint(out + p, 4, &v);
            CHECK(v == 4, "up: section_number=4");
            p += c;
            CHECK(out[p] == 0x30, "up: audio uso tag");
            p++;
            c = c2b_read_varint(out + p, 4, &v);
            CHECK(v == 8, "up: uncompressed_sample_offset=8");
            p += c;
            CHECK(out[p] == 0x11, "up: Voice f2 xuid tag");
            u64 x = 0;
            for (int i = 0; i < 8; i++) x |= (u64)out[p + 1 + i] << (8 * i);
            CHECK(x == 0x1122334455667788ull, "up: xuid fixed64 на месте");
            ip += ln;
        } else if (type == 23) {
            saw_ba = 1;
            CHECK(out[ip] == 0x08 && out[ip + 2] == 0x10, "up: BaselineAck identity payload");
            ip += ln;
        } else if (type == 25) {
            CHECK(0, "up: RespondCvar не посылали");
            ip += ln;
        } else if (type == 5) {
            saw_sc = 1;
            CHECK(ln == 8 && out[ip] == 0x0A, "up: StringCmd identity");
            ip += ln;
        } else if (type == 206) {
            /* R41: ListenEvents перестроен: fixed32 event_mask -> varint eventarraybits */
            saw_le = 1;
            u32 p = ip, v;
            CHECK(out[p] == 0x10, "up: LE206 f2 eventarraybits tag (0x10)");
            p++;
            c = c2b_read_varint(out + p, ip + ln - p, &v);
            CHECK(v == 0x04030201u, "up: LE206 bits[0]=0x04030201");
            p += c;
            CHECK(out[p] == 0x10, "up: LE206 f2 tag[1] (0x10)");
            p++;
            c = c2b_read_varint(out + p, ip + ln - p, &v);
            CHECK(v == 0x08070605u, "up: LE206 bits[1]=0x08070605");
            ip += ln;
        } else {
            CHECK(0, "up: посторонний тип в выходе");
            ip += ln;
        }
    }
    CHECK(saw_ci && saw_vd && saw_ba && saw_sc, "up: все немовые сообщения на месте");
    CHECK(saw_le == 1, "up: 12->206 ListenEvents дошёл до выхода (R41)");
    CHECK(m21 == 2, "up: два CLC_Move(21) в выходе");
    CHECK(g_up_base_valid == 1 && g_up_base.cmd_num == 10, "up: baseline = cmd 10 после msg2");

    /* --- продолжение цепочки БЕЗ reset: baseline(10) -> 11 (без бита cmd) ---
       b10 повторяет состояние c4 (cmd 10, tick 610, buttons 8, fwd 0) —
       энкодер пишет от него, декодер моста ждёт продолжения от своего
       baseline (тоже cmd 10) — значения обязаны совпасть. */
    {
        c2b_s1cmd_t b10 = Z; b10.cmd_num = 10; b10.tick = 610;
        b10.fwd = 0.0f; b10.buttons = 8;
        c2b_s1cmd_t b11 = b10; b11.cmd_num = 11; b11.tick = 611; b11.buttons = 0;
        u8 bt[64], pl[128], st2[256], o2[1024];
        w = (c2b_bw_t){ bt, sizeof(bt), 0, 0, 0, 0 };
        c2b_bw_s1cmd(&w, &b10, &b11);
        u32 sn2 = c2b_t_msg(st2, 9, pl, c2b_t_s1_move(pl, 0, 1, bt, c2b_bw_flush(&w)));
        u32 ol2 = 0;
        rc = c2b_uplink_translate(st2, sn2, o2, sizeof(o2), &ol2);
        CHECK(rc == 0, "up: msg3-translate rc=0");
        u32 cmd = 0, tick = 0, buttons = 0, va0b = 0, fwdb = 0, sideb = 0;
        u32 impulse = 0, weap = 0, mdy_len = 0;
        i32 mdx = 0, mdy = 0;
        /* один блок внутри [21][pn][0x1A dn][ln][block][0x20 last] */
        u32 q = 0;
        while (q < ol2 && o2[q] != 21) {
            u32 t2, l2, cc;
            cc = c2b_read_varint(o2 + q, ol2 - q, &t2); q += cc;
            cc = c2b_read_varint(o2 + q, ol2 - q, &l2); q += cc + l2;
        }
        CHECK(q < ol2, "up: msg3 [21] найден");
        u32 p = q + 1;                                    /* type 21 = 1 байт */
        u32 ln, c2v;
        c2v = c2b_read_varint(o2 + p, 4, &ln); p += c2v;
        u32 pp = p;
        CHECK(o2[pp] == 0x1A, "up: msg3 payload f3 tag");
        pp++;
        u32 dn; c2v = c2b_read_varint(o2 + pp, 4, &dn); pp += c2v;
        u32 bl; c2v = c2b_read_varint(o2 + pp, 4, &bl); pp += c2v;
        c2b_t_parse_block(o2 + pp, bl, &cmd, &tick, &buttons, &va0b, &fwdb, &sideb,
                          &impulse, &weap, &mdx, &mdy, &mdy_len);
        CHECK(cmd == 11, "up: продолжение цепочки cmd=11 (без бита cmd)");
        CHECK(tick == 611 && buttons == 0, "up: продолжение tick/buttons");
    }
}

/* --- стаб orig ProcessMessages для test_downlink --- */
static u8   st_dn_cap[4096];
static u32  st_dn_cap_len;
static u32  st_dn_calls;
static uptr st_dn_last_brd;
static i32  st_dn_fake(uptr chan, uptr brd, u32 flag)
{
    bf_read_t *br = (bf_read_t *)brd;
    st_dn_calls++;
    st_dn_last_brd = brd;
    if (br && br->m_pBuffer && br->m_nDataBytes <= sizeof(st_dn_cap)) {
        memcpy(st_dn_cap, (const void *)br->m_pBuffer, (u32)br->m_nDataBytes);
        st_dn_cap_len = (u32)br->m_nDataBytes;
    } else st_dn_cap_len = 0;
    (void)chan; (void)flag;
    return 42;
}

static void test_downlink(void)
{
    /* downlink v1: хук ProcessMessages -> c2b_translate -> свой bf_read -> orig.
       Вход: CS2-поток [40 ServerInfo][48 Print][4 Tick][47 VoiceData][77 NMP].
       Ожидаемый выход: [8 ServerInfo][16 "hi"][4 Tick] (40->8, 48->16, 4->4;
       47/77 дроп по таблицам фазы F). */
    u8 in[96]; u32 ip = 0;
    u8 si[24]; u32 sp = 0;
    si[sp++]=0x08; sp+=c2b_write_varint(si+sp, 2001);       /* S2 п1 protocol */
    si[sp++]=0x20; si[sp++]=0x00;                            /* S2 п4 is_hltv -> S1 п5 */
    si[sp++]=0x7A; si[sp++]=2; si[sp++]='d'; si[sp++]='2';   /* S2 п15 -> S1 п16 */
    si[sp++]=0x8A; si[sp++]=0x01; si[sp++]=4;                /* S2 п17 -> S1 п19 */
    si[sp++]='h'; si[sp++]='o'; si[sp++]='s'; si[sp++]='t';
    ip += c2b_write_varint(in + ip, 40); ip += c2b_write_varint(in + ip, sp);
    for (u32 k = 0; k < sp; k++) in[ip++] = si[k];
    ip += c2b_write_varint(in + ip, 48); ip += c2b_write_varint(in + ip, 2);
    in[ip++] = 'h'; in[ip++] = 'i';
    ip += c2b_write_varint(in + ip, 4);  ip += c2b_write_varint(in + ip, 4);
    in[ip++]=0x08; in[ip++]=0x64; in[ip++]=0x48; in[ip++]=0x05;   /* S2: п1=100, п9=5 */
    /* 47: полный голос (G-5): client=3 + audio{format=2, voice_data="z"} */
    ip += c2b_write_varint(in + ip, 47); ip += c2b_write_varint(in + ip, 9);
    in[ip++]=0x10; in[ip++]=0x03;                 /* f2 client=3 */
    in[ip++]=0x0A; in[ip++]=5;                   /* f1 audio{ */
    in[ip++]=0x08; in[ip++]=0x02;                 /*   format=OPUS */
    in[ip++]=0x12; in[ip++]=1; in[ip++]='z';      /*   voice_data } */
    ip += c2b_write_varint(in + ip, 77); ip += c2b_write_varint(in + ip, 1); in[ip++] = 0x03;

    /* bf_read так, как его ставит движок: cur=0, avail=32, DataIn=Buffer+1
       (конвенция prefetch; хук сохраняет относительный сдвиг — симметрично) */
    static u32 in_words[32];
    memcpy(in_words, in, ip);
    bf_read_t br; memset(&br, 0, sizeof(br));
    br.m_pBuffer    = in_words;
    br.m_pDataIn    = in_words + 1;
    br.m_pDataEnd   = (u32 *)((u8 *)in_words + ip);
    br.m_nDataBytes = ip;
    br.m_nDataBits  = ip << 3;
    br.m_nBitsAvail = 32;
    br.m_nInBufWord = in_words[0];

    u8 *save_tramp = g_trampoline;
    g_dn_mode = 1;
    g_trampoline = (u8 *)&st_dn_fake;
    st_dn_calls = 0; st_dn_cap_len = 0; st_dn_last_brd = 0;

    printf("[t] downlink v1 (in=%u bytes)\n", ip);
    i32 rv = c2b_hook_process_messages(0x11, (uptr)&br, 7);
    CHECK(rv == 42, "dn: rv от fake orig (42)");
    CHECK(st_dn_calls == 1, "dn: orig зван 1 раз");

    u8 exp[96]; u32 ep = 0;
    /* R37-синтез: у S2-ServerInfo нет f10/f11/f12/f14 -> хвост: protocol=13762,
     * mcl=64 (дефолт), mcs=512 (дефолт), "csgo", слот=-1 (10Б varint) */
    ep += c2b_write_varint(exp + ep, 8); ep += c2b_write_varint(exp + ep, 39);   /* 14 (без f1) + 25 (хвост) */
    /* S2 п1 (08 D1 0F) -> ДРОП: protocol синтезируется в хвосте */
    exp[ep++]=0x28; exp[ep++]=0x00;
    exp[ep++]=0x82; exp[ep++]=0x01; exp[ep++]=2;
    exp[ep++]='d'; exp[ep++]='2';
    exp[ep++]=0x9A; exp[ep++]=0x01; exp[ep++]=4;
    exp[ep++]='h'; exp[ep++]='o'; exp[ep++]='s'; exp[ep++]='t';
    /* хвост: 08 C2 6B | 58 40 | 60 80 04 | 7A 04 csgo | 68 FF x9 01 */
    exp[ep++]=0x08; exp[ep++]=0xC2; exp[ep++]=0x6B;
    exp[ep++]=0x58; exp[ep++]=0x40;
    exp[ep++]=0x60; exp[ep++]=0x80; exp[ep++]=0x04;          /* mcs=512 (дефолт: f11 нет) */
    exp[ep++]=0x7A; exp[ep++]=4; exp[ep++]='c'; exp[ep++]='s'; exp[ep++]='g'; exp[ep++]='o';
    exp[ep++]=0x68; for (int k=0;k<9;k++) exp[ep++]=0xFF; exp[ep++]=0x01;
    ep += c2b_write_varint(exp + ep, 16); ep += c2b_write_varint(exp + ep, 2);
    exp[ep++]='h'; exp[ep++]='i';
    ep += c2b_write_varint(exp + ep, 4); ep += c2b_write_varint(exp + ep, 4);
    exp[ep++]=0x08; exp[ep++]=0x64; exp[ep++]=0x38; exp[ep++]=0x05;
    ep += c2b_write_varint(exp + ep, 15); ep += c2b_write_varint(exp + ep, 7); /* G-5: голос 47->15 */
    exp[ep++]=0x08; exp[ep++]=0x03;               /* client=3 */
    exp[ep++]=0x2A; exp[ep++]=1; exp[ep++]='z';   /* voice_data="z" */
    exp[ep++]=0x38; exp[ep++]=0x02;               /* format=OPUS */
    CHECK(st_dn_cap_len == ep && memcmp(st_dn_cap, exp, ep) == 0,
          "dn: orig получил CS:GO-поток байт-в-байт (вкл. G-5 голос)");

    /* observe-режим: passthrough ИСХОДНОГО bf_read */
    g_dn_mode = 0;
    st_dn_calls = 0; st_dn_cap_len = 0;
    rv = c2b_hook_process_messages(0x11, (uptr)&br, 7);
    CHECK(rv == 42 && st_dn_calls == 1, "dn: observe — orig зван");
    CHECK(st_dn_last_brd == (uptr)&br, "dn: observe — passthrough исходного br");
    CHECK(st_dn_cap_len == ip && memcmp(st_dn_cap, in, ip) == 0,
          "dn: observe — CS2-поток не тронут");

    /* trunc: len за границей буфера -> passthrough исходного потока */
    g_dn_mode = 1;
    {
        u8 bad[8]; u32 bp = 0;
        bp += c2b_write_varint(bad + bp, 8); bp += c2b_write_varint(bad + bp, 100);
        static u32 bad_words[2]; memcpy(bad_words, bad, bp);
        bf_read_t bbr; memset(&bbr, 0, sizeof(bbr));
        bbr.m_pBuffer    = bad_words;
        bbr.m_pDataIn    = bad_words + 1;
        bbr.m_pDataEnd   = (u32 *)((u8 *)bad_words + bp);
        bbr.m_nDataBytes = bp;
        bbr.m_nDataBits  = bp << 3;
        bbr.m_nBitsAvail = 32;
        bbr.m_nInBufWord = bad_words[0];
        st_dn_calls = 0; st_dn_cap_len = 0;
        rv = c2b_hook_process_messages(0x11, (uptr)&bbr, 7);
        CHECK(rv == 42 && st_dn_calls == 1, "dn: trunc — orig зван");
        /* F4 (t35) fail-closed: кривой S2-поток НЕ идёт движку — пустой буфер */
        CHECK(st_dn_cap_len == 0, "dn: fail-closed — движку ушло 0 байт");
        { u32 fc0 = g_fini2.dn2_fc;
          CHECK(fc0 >= 1, "dn: fc инкрементирован (F4)"); (void)fc0; }

        /* cur!=0 -> passthrough исходного bf_read */
        bbr.m_iCurBit = 5;
        st_dn_calls = 0; st_dn_last_brd = 0;
        c2b_hook_process_messages(0x11, (uptr)&bbr, 7);
        CHECK(st_dn_last_brd == (uptr)&bbr, "dn: cur!=0 — passthrough исходного br");

        /* R29: CAS-конфликт (эмуляция 2-го потока) -> passthrough исходного br */
        {
            u32 pass0 = g_dn_stats.pass, rival0 = g_dn_stats.rival;
            g_dn_busy = 1;
            st_dn_calls = 0; st_dn_last_brd = 0;
            bbr.m_iCurBit = 0;
            rv = c2b_hook_process_messages(0x11, (uptr)&bbr, 7);
            CHECK(rv == 42 && st_dn_calls == 1, "dn: rival — orig зван");
            CHECK(st_dn_last_brd == (uptr)&bbr, "dn: rival — passthrough исходного br");
            CHECK(g_dn_stats.rival == rival0 + 1, "dn: rival зафиксирован");
            CHECK(g_dn_stats.pass == pass0 + 1, "dn: rival — учтён как pass");
            CHECK(g_dn_busy == 1, "dn: чужой лок не снят");
            g_dn_busy = 0;
        }
    }
    CHECK(g_dn_busy == 0, "dn: гвард снят во всех ветках");
    /* R31: диагностика запаса до DN-потолка */
    CHECK(g_dn_stats.max_in > 0 && g_dn_stats.max_in <= g_dn_stats.bytes_in,
          "dn: max_in согласован (0 < max <= суммарный in)");
    CHECK(g_dn_stats.max_out > 0 && g_dn_stats.max_out <= g_dn_stats.bytes_out,
          "dn: max_out согласован (0 < max <= суммарный out)");
    CHECK(g_dn_stats.max_out <= C2B_DN_CAP,
          "dn: max_out в потолке 256КБ");
    CHECK(g_dn_stats.max_out >= 36,
          "dn: max_out не меньше голос-эмиссии G-5 (36 Б)");
    g_dn_mode = 0;
    g_trampoline = save_tramp;
    printf("  dn stats: calls=%u ok=%u pass=%u trunc=%u oom=%u mxi=%u mox=%u\n",
           g_dn_stats.calls, g_dn_stats.ok, g_dn_stats.pass,
           g_dn_stats.trunc, g_dn_stats.oom,
           g_dn_stats.max_in, g_dn_stats.max_out);
}

static void test_g5_voice(void)
{
    u32 m0 = 0, d0 = 0;
    u8 in[256]; u32 ip = 0;
    u8 aud[96]; u32 an = 0;

    printf("[t] G-5 VoiceData (CS2 47 -> S1 15)\n");
    {   /* test_downlink уже гонял голос через полный путь — счётчики по ДЕЛЬТАМ */
        m0 = g_g5_msgs; d0 = g_g5_drop;
        printf("  g5: база от downlink-теста: msgs=%u drop=%u\n", m0, d0);
    }

    /* CS2 CMsgVoiceAudio: format=2(OPUS), voice_data="ABCDEF"(6),
       sequence_bytes=64, section_number=2, sample_rate=24000(ДРОП),
       uncompressed_sample_offset=128 */
    aud[an++]=0x08; an+=c2b_write_varint(aud+an, 2);        /* f1 format */
    aud[an++]=0x12; aud[an++]=6;
    aud[an++]='A'; aud[an++]='B'; aud[an++]='C';
    aud[an++]='D'; aud[an++]='E'; aud[an++]='F';            /* f2 voice_data */
    aud[an++]=0x18; an+=c2b_write_varint(aud+an, 64);       /* f3 sequence_bytes */
    aud[an++]=0x20; an+=c2b_write_varint(aud+an, 2);        /* f4 section_number */
    aud[an++]=0x28; an+=c2b_write_varint(aud+an, 24000);    /* f5 sample_rate -> дроп */
    aud[an++]=0x30; an+=c2b_write_varint(aud+an, 128);      /* f6 uso */
    aud[an++]=0x40; aud[an++]=3;                            /* f7 num_packets -> дроп */
    aud[an++]=0x42; aud[an++]=0x02; aud[an++]=0x01; aud[an++]=0x02; /* f8 packed offsets -> дроп */

    /* CS2 CSVCMsg_VoiceData: audio, client=7, proximity=1, xuid fx64,
       audible_mask=15, tick(ДРОП), passthrough(ДРОП), entity(ДРОП), caster=1 */
    in[ip++]=0x0A; ip+=c2b_write_varint(in+ip, an);
    for (u32 k = 0; k < an; k++) in[ip++] = aud[k];
    in[ip++]=0x10; ip+=c2b_write_varint(in+ip, 7);          /* f2 client */
    in[ip++]=0x18; in[ip++]=0x01;                           /* f3 proximity */
    in[ip++]=0x21;                                          /* f4 xuid fixed64 */
    for (int k = 0; k < 8; k++) in[ip++] = (u8)(0x1122334455667788ULL >> (k * 8));
    in[ip++]=0x28; ip+=c2b_write_varint(in+ip, 15);         /* f5 audible_mask */
    in[ip++]=0x30; ip+=c2b_write_varint(in+ip, 99999);      /* f6 tick -> дроп */
    in[ip++]=0x38; ip+=c2b_write_varint(in+ip, 0);          /* f7 passthrough -> дроп */
    in[ip++]=0x40; ip+=c2b_write_varint(in+ip, 0xFFFF);     /* f8 entity -> дроп */
    in[ip++]=0x48; in[ip++]=0x01;                           /* f9 caster */

    u8 out[512]; u32 op = 0, olen = 0;
    i32 rc = c2b_g5_voice(in, ip, out, 0, sizeof(out), &olen);
    CHECK(rc == 0, "g5: rc=0");
    CHECK(out[0] == 15, "g5: тег S1 svc=15");

    /* ожидаемый payload (после [15][len]): клиент=7, prox=1, xuid 8Б,
       amask=15, voice_data="ABCDEF", caster=1, format=2, seq=64, sect=2, uso=128 */
    u8 exp[64]; u32 ep = 0;
    exp[ep++]=0x08; ep+=c2b_write_varint(exp+ep, 7);
    exp[ep++]=0x10; exp[ep++]=0x01;
    exp[ep++]=0x19;
    for (int k = 0; k < 8; k++) exp[ep++] = (u8)(0x1122334455667788ULL >> (k * 8));
    exp[ep++]=0x20; ep+=c2b_write_varint(exp+ep, 15);
    exp[ep++]=0x2A; exp[ep++]=6;
    exp[ep++]='A'; exp[ep++]='B'; exp[ep++]='C'; exp[ep++]='D'; exp[ep++]='E'; exp[ep++]='F';
    exp[ep++]=0x30; exp[ep++]=0x01;
    exp[ep++]=0x38; ep+=c2b_write_varint(exp+ep, 2);
    exp[ep++]=0x40; ep+=c2b_write_varint(exp+ep, 64);
    exp[ep++]=0x48; ep+=c2b_write_varint(exp+ep, 2);
    exp[ep++]=0x50; ep+=c2b_write_varint(exp+ep, 128);

    CHECK(ep == 34, "g5: ожидание payload=34 (проверка фикстуры)");
    CHECK(olen == 1 + 1 + ep, "g5: olen=[15][34]+payload");
    CHECK(out[1] == ep, "g5: len=34");
    CHECK(memcmp(out + 2, exp, ep) == 0, "g5: S1 payload байт-в-байт (аудио раскрыто, дропы выполнены)");
    CHECK(g_g5_msgs == m0 + 1, "g5: счётчик msgs дельта +1");

    /* дроп: голос без client_deprecated (S1 без источника) */
    u8 noc[64]; u32 np = 0;
    noc[np++]=0x0A; noc[np++]=an;
    for (u32 k = 0; k < an; k++) noc[np++] = aud[k];
    u32 nl = 0;
    rc = c2b_g5_voice(noc, np, out, 0, sizeof(out), &nl);
    CHECK(rc == -3 && g_g5_drop == d0 + 1, "g5: без client -> rc=-3 (дроп)");

    /* дроп: голос без audio (только метаданные) */
    u8 noa[16]; u32 na = 0;
    noa[na++]=0x10; noa[na++]=0x07;
    rc = c2b_g5_voice(noa, na, out, 0, sizeof(out), &nl);
    CHECK(rc == -3 && g_g5_drop == d0 + 2, "g5: без audio -> rc=-3 (дроп)");

    printf("  g5 stats: msgs=%u bytes=%u drop=%u\n", g_g5_msgs, g_g5_bytes, g_g5_drop);
}

static void test_detour(void)
{
    uptr stub = (uptr)&c2b_stub;
    printf("[t] detour (stub @0x%lx)\n", (unsigned long)stub);

    /* RWX на странице заглушки: SIG уже там, но mprotect нужен до патча */
    CHECK(c2b_page_protect(stub, 128, 0x07) == 0, "mprotect RWX");

    /* negative: сигнатура обязана совпасть на заглушке */
    i32 r = c2b_install(stub);
    CHECK(r == 0, "install rc==0");
    if (r != 0) { printf("  (install failed: %d)\n", r); return; }

    /* патч реально на месте */
#ifdef __x86_64__
    CHECK(((u8 *)stub)[0] == 0xFF && ((u8 *)stub)[1] == 0x25, "patch jmp-[rip] in place");
#else
    CHECK(((u8 *)stub)[0] == 0x68 && ((u8 *)stub)[5] == 0xC3, "patch push/ret in place");
#endif
    /* трамплин начинается с сохранённых байтов */
    CHECK(memcmp(g_trampoline, C2B_SIG, C2B_STOLEN) == 0, "trampoline keeps stolen bytes");

    c2b_stub_in_a = 1; c2b_stub_in_b = 2; c2b_stub_in_c = 3;
    printf("  tramp bytes:");
    for (int i = 0; i < C2B_STOLEN + C2B_PATCH_LEN; i++)
        printf(" %02X", g_trampoline[i]);
    printf("\n"); fflush(stdout);

    u32 before = g_st.calls;
    c2b_stub(1, 0, 3);   /* brd=0: observer-guard на NULL */
    CHECK(c2b_stub_result == 6, "call routed via hook, body executed (1+2+3=6)");
    CHECK(g_st.calls == before + 1, "hook observed the call");
    CHECK(c2b_stub_result == 6, "result via stub global");

    /* uninstall: восстановление и прямой путь */
    c2b_uninstall();
    CHECK(memcmp((const void *)stub, C2B_SIG, C2B_STOLEN) == 0, "uninstall restores bytes");
    u32 after = g_st.calls;
    c2b_stub_in_a = 10; c2b_stub_in_b = 20; c2b_stub_in_c = 30;
    c2b_stub(10, 0, 30);
    CHECK(c2b_stub_result == 60, "direct call works after uninstall");
    CHECK(g_st.calls == after, "hook NOT called after uninstall");

    /* negative: сломанная сигнатура -> отказ */
    ((u8 *)stub)[3] ^= 0xFF;
    CHECK(c2b_install(stub) == -1, "install refuses tampered prolog");
    ((u8 *)stub)[3] ^= 0xFF;
}

/* --- стабы "движка" для test_up_dispatch --- */
static u8  st_pb[256];          /* protobuf-байты fake-msg */
static u32 st_pb_len;
static u8  st_cap[4096];        /* что forged WriteToBuffer записал в "buf" */
static u32 st_cap_len;
static u32 st_orig_calls;
static uptr st_last_msg;
static uptr st_last_vt;   /* vtable msg, захваченная ВНУТРИ orig (msg может умереть после) */
static u32 st_last_rel, st_last_vo;

static u32 st_bytesize(uptr pb) { (void)pb; return st_pb_len; }
static void *st_serialize(uptr pb, void *dst)
{
    (void)pb;
    memcpy(dst, st_pb, st_pb_len);
    return dst;
}
static i32 st_writebytes(uptr buf, const void *data, u32 len)
{
    (void)buf;
    memcpy(st_cap + st_cap_len, data, len);
    st_cap_len += len;
    return 1;
}
static i32 st_gt_move(void *m)   { (void)m; return 9; }
static i32 st_gt_drop(void *m)   { (void)m; return 14; }   /* R41: 12 теперь транскодится, дропаем на 14 */
static i32 st_gt_string(void *m) { (void)m; return 5; }
static i32 st_gt_unknown(void *m){ (void)m; return 99; }
static i32 st_isrel0(void *m)    { (void)m; return 0; }
static i32 st_isrel1(void *m)    { (void)m; return 1; }
static const char *st_name(void *m) { (void)m; return "STUB"; }

/* fake orig (трамплин): для forged — дергает его WriteToBuffer, rv=42 */
static i32 st_fake_orig(uptr chan, uptr msg, u32 rel, u32 vo)
{
    (void)chan;
    st_orig_calls++;
    st_last_msg = msg;
    st_last_vt = *(uptr *)msg;   /* читаем пока lifetime валиден */
    st_last_rel = rel;
    st_last_vo = vo;
    if (*(uptr *)msg == (uptr)g_fg_vt) {
        i32 (*isrel)(void *) = (i32 (*)(void *)) *(uptr *)((uptr)g_fg_vt + 7 * sizeof(uptr));
        st_last_rel = isrel ? (u32)isrel((void *)msg) : 0;   /* как реальный SendNetMsg */
        i32 (*w2b)(uptr, uptr) = (i32 (*)(uptr, uptr)) *(uptr *)((uptr)g_fg_vt + 6 * sizeof(uptr));
        (void)w2b(msg, (uptr)(void *)st_cap);    /* buf-стаб: st_writebytes игнорирует */
        return 42;
    }
    st_last_rel = rel;
    return 42;
}

static void test_up_dispatch(void)
{
    printf("[t] uplink dispatch (v1: forged + translate)\n");
    c2b_uplink_reset();
    g_up_in = 0; g_up_out = 0; g_up_drop = 0; g_up_unknown = 0;
    g_up_err = 0; g_up_move = 0; g_up_ucmds = 0;   /* reset не трогает счётчики */
    g_up_st.calls = 0;

    st_orig_calls = 0; st_cap_len = 0;

    /* движок-стабы + fake trampoline */
    g2_trampoline = (u8 *)(void *)&st_fake_orig;
    g2e_bytesize_p = (uptr)(void *)&st_bytesize;
    g2e_serialize_p = (uptr)(void *)&st_serialize;
    g2e_writebytes_p = (uptr)(void *)&st_writebytes;
    g_up_mode = 1;

    /* fake msg: vtable + protobuf @ +8 (как у CNetMessagePB) */
    static const uptr fvt[14] = {
        0, 0, 0, 0, 0, 0, 0,
        (uptr)st_isrel0, (uptr)st_gt_move, 0, (uptr)st_name, 0, 0, 0 };
    struct { uptr vt; u8 pb[32]; } fmsg;
    fmsg.vt = (uptr)fvt;

    /* protobuf CLC_Move S1: f1 backup=0, f2 new=1, f3 data = 1 команда (c1).
       total = backup + new = 1 — иначе декодер потребует 2-ю команду из потока. */
    static const c2b_s1cmd_t Z = { 0 };
    c2b_s1cmd_t c1 = Z;
    c1.cmd_num = 5;  c1.tick = 600;
    c1.va[0] = 1.5f; c1.va[1] = -89.0f;
    c1.fwd = 250.0f; c1.side = -10.5f;
    c1.buttons = 1;  c1.impulse = 13;
    c1.weap_sel = 7; c1.weap_sub = 2;
    c1.mdx = 5;      c1.mdy = -7;
    u8 bits[128];
    c2b_bw_t w = { bits, sizeof(bits), 0, 0, 0, 0 };
    c2b_bw_s1cmd(&w, &Z, &c1);
    u32 nb = c2b_bw_flush(&w);
    CHECK(w.ovf == 0, "updisp: битрайтер без ovf");

    st_pb_len = 0;
    st_pb[st_pb_len++] = 0x08; st_pb[st_pb_len++] = 0;        /* f1 backup=0 */
    st_pb[st_pb_len++] = 0x10; st_pb[st_pb_len++] = 1;        /* f2 new=1 */
    st_pb[st_pb_len++] = 0x1A; st_pb[st_pb_len++] = (u8)nb;   /* f3 data */
    memcpy(st_pb + st_pb_len, bits, nb);
    st_pb_len += nb;

    /* --- 1) Move: подмена forged-объектом, rv от orig --- */
    uptr blk[5] = { 0, 0, 0, (uptr)(void *)&fmsg, 0x77 };     /* rcx=0 rdx=0 rsi=msg rdi=chan */
    u64 rv = c2b_up_dispatch(blk);
    CHECK(rv == 42, "updisp: rv=42 от orig через forged");
    CHECK(st_orig_calls == 1, "updisp: orig вызван 1 раз");
    CHECK(st_last_msg != (uptr)(void *)&fmsg, "updisp: orig получил ПОДМЕНЕННЫЙ msg");
    CHECK(st_last_vt == (uptr)g_fg_vt, "updisp: vtable forged-объекта");
    CHECK(st_last_rel == 0, "updisp: rel проброшен (0)");
    CHECK(st_cap_len > 4 && st_cap[0] == 21, "updisp: выход = [varint 21 (CS2 Move)]");
    {   /* структурная сверка: [21][len'][payload=[0x1A][dn][блоки...][0x20][last]]
           блок = [varint cn][CSGOUserCmdPB=[0x0A][bn][base=[0x08 cmd][0x10 tick]...]] */
        u32 p = 0, t2 = 0, ln = 0, c;
        c = c2b_read_varint(st_cap + p, st_cap_len - p, &t2); p += c;
        CHECK(t2 == 21, "updisp: t'=21");
        c = c2b_read_varint(st_cap + p, st_cap_len - p, &ln); p += c;
        CHECK(ln == st_cap_len - p, "updisp: len' согласован с длиной потока");
        CHECK(st_cap[p] == 0x1A, "updisp: payload.f3 tag (data)");
        u32 dn = 0;
        c = c2b_read_varint(st_cap + p + 1, st_cap_len - p - 1, &dn);
        u32 q = p + 1 + c;                       /* blocks: [varint len][0x0A]... */
        u32 bl2 = 0;
        c = c2b_read_varint(st_cap + q, st_cap_len - q, &bl2);   /* len блока */
        CHECK(bl2 > 10, "updisp: len блока CSGOUserCmdPB");
        CHECK(st_cap[q + c] == 0x0A, "updisp: CSGOUserCmdPB.f1 base tag");
        u32 bn = 0;
        u32 c2v = c2b_read_varint(st_cap + q + c + 1, st_cap_len - q - c - 1, &bn);
        u32 r2 = q + c + 1 + c2v;                /* начало CBaseUserCmdPB */
        CHECK(st_cap[r2] == 0x08 && st_cap[r2 + 1] == 0x05, "updisp: cmd=5 в base.f1");
        CHECK(st_cap[r2 + 2] == 0x10 && st_cap[r2 + 3] == 0xD8 && st_cap[r2 + 4] == 0x04,
              "updisp: tick=600 (varint D8 04)");
        (void)dn; (void)bn;
    }
    CHECK(g_up_move == 1 && g_up_out == 1 && g_up_in == 1, "updisp: счётчики move/out/in=1");

    /* --- 2) дроп по карте (12 ListenEvents): rv=1, orig НЕ вызван --- */
    static const uptr fvt12[14] = {
        0, 0, 0, 0, 0, 0, 0,
        (uptr)st_isrel0, (uptr)st_gt_drop, 0, (uptr)st_name, 0, 0, 0 };
    fmsg.vt = (uptr)fvt12;
    st_cap_len = 0;
    rv = c2b_up_dispatch(blk);
    CHECK(rv == 1, "updisp: дроп -> rv=1 (фейк-ОК)");
    CHECK(st_orig_calls == 1, "updisp: orig НЕ вызван при дропе");
    CHECK(st_cap_len == 0, "updisp: на провод ничего не ушло");
    CHECK(g_up_drop == 1, "updisp: счётчик дропов=1");

    /* --- 3) identity-тип (5 StringCmd): forged, payload без изменений --- */
    static const uptr fvt5[14] = {
        0, 0, 0, 0, 0, 0, 0,
        (uptr)st_isrel1, (uptr)st_gt_string, 0, (uptr)st_name, 0, 0, 0 };
    fmsg.vt = (uptr)fvt5;
    st_pb_len = 0;
    st_pb[st_pb_len++] = 0x0A; st_pb[st_pb_len++] = 6;
    memcpy(st_pb + st_pb_len, "say hi", 6);
    st_pb_len += 6;
    st_cap_len = 0;
    rv = c2b_up_dispatch(blk);
    CHECK(rv == 42 && st_orig_calls == 2, "updisp: StringCmd через orig");
    CHECK(st_cap_len == 10 && st_cap[0] == 5 && st_cap[1] == 8,
          "updisp: [varint 5][len'=8] + payload 1:1 (10Б)");
    CHECK(memcmp(st_cap + 2, "\x0A\x06say hi", 8) == 0, "updisp: payload StringCmd не тронут");
    CHECK(st_last_rel == 1, "updisp: rel=1 от IsReliable исходного msg");

    /* --- 4) unknown (99): дроп --- */
    static const uptr fvt99[14] = {
        0, 0, 0, 0, 0, 0, 0,
        (uptr)st_isrel0, (uptr)st_gt_unknown, 0, (uptr)st_name, 0, 0, 0 };
    fmsg.vt = (uptr)fvt99;
    st_cap_len = 0;
    rv = c2b_up_dispatch(blk);
    CHECK(rv == 1 && st_orig_calls == 2, "updisp: unknown 99 -> дроп без orig");

    /* --- 5) observe-режим: passthrough с ИСХОДНЫМ msg --- */
    g_up_mode = 0;
    fmsg.vt = (uptr)fvt;          /* снова Move */
    rv = c2b_up_dispatch(blk);
    CHECK(rv == 42 && st_orig_calls == 3, "updisp: observe -> passthrough");
    CHECK(st_last_msg == (uptr)(void *)&fmsg, "updisp: observe -> orig получил исходный msg");

    /* --- 6) сбой хелперов: passthrough с исходным msg --- */
    g_up_mode = 1;
    g2e_serialize_p = 0;
    rv = c2b_up_dispatch(blk);
    CHECK(rv == 42 && st_orig_calls == 4, "updisp: нет serialize -> passthrough");
    CHECK(st_last_msg == (uptr)(void *)&fmsg, "updisp: passthrough msg оригинал");
    g2e_serialize_p = (uptr)(void *)&st_serialize;

    /* --- 6b) R29: CAS-конфликт (эмуляция 2-го потока) -> passthrough --- */
    fmsg.vt = (uptr)fvt;
    st_cap_len = 0;
    g2_busy = 1;
    rv = c2b_up_dispatch(blk);
    CHECK(rv == 42 && st_orig_calls == 5, "updisp: rival -> passthrough rv=orig");
    CHECK(st_last_msg == (uptr)(void *)&fmsg, "updisp: rival -> исходный msg");
    CHECK(g_up_st.rival == 1, "updisp: rival зафиксирован");
    g2_busy = 0;

    /* --- 7) reentrancy guard --- */
    CHECK(g2_busy == 0, "updisp: g2_busy снят во всех ветках");

    /* очистка за собой (не ломать соседние тесты) */
    g_up_mode = 0;
    g2_trampoline = 0;
    g2e_bytesize_p = 0;
    g2e_serialize_p = 0;
    g2e_writebytes_p = 0;
    c2b_uplink_reset();
    g_up_st.calls = 0;
}

static void test_detour2(void)
{
#if defined(__x86_64__)
    uptr stub = (uptr)&c2b_stub2;
    printf("[t] detour2 uplink (stub @0x%lx)\n", (unsigned long)stub);

    CHECK(c2b_page_protect(stub, 128, 0x07) == 0, "up: mprotect RWX");
    i32 r = c2b_install2(stub);
    CHECK(r == 0, "up: install rc==0");
    if (r != 0) { printf("  (install2 failed: %d)\n", r); return; }

    CHECK(((u8 *)stub)[0] == 0xFF && ((u8 *)stub)[1] == 0x25, "up: patch jmp-[rip] in place");
    CHECK(memcmp(g2_trampoline, UPL_SIG, UPL_STOLEN) == 0, "up: trampoline keeps stolen bytes");

    c2b_stub2_result = 0;
    u32 before = g_up_st.calls;
    i32 rv = c2b_stub2(10, (void *)0, 3, 4);
    CHECK(rv == 17, "up: rv через хук (10+3+4=17)");
    CHECK(c2b_stub2_result == 17, "up: stub body executed via trampoline");
    CHECK(g_up_st.calls == before + 1, "up: hook observed the call");

    c2b_uninstall2();
    CHECK(memcmp((const void *)stub, UPL_SIG, UPL_STOLEN) == 0, "up: uninstall restores bytes");
    g_up_st.calls = before;
    c2b_stub2_result = 0;
    c2b_stub2(10, (void *)0, 3, 4);
    CHECK(c2b_stub2_result == 17, "up: direct call works after uninstall");
    CHECK(g_up_st.calls == before, "up: hook NOT called after uninstall");

    ((u8 *)stub)[3] ^= 0xFF;
    CHECK(c2b_install2(stub) == -1, "up: install refuses tampered prolog");
    ((u8 *)stub)[3] ^= 0xFF;
#else
    printf("[t] detour2 uplink: только x86_64, пропуск\n");
#endif
}

static void test_fmap(void)
{
    printf("[t] fmap (G-3d): slot-space + словарь S2->S1\n");
    CHECK(g_s1_err == 0, "fmap: ошибок сборки слот-пространства нет");
    /* test_translate_classinfo покрыл 5 именованных классов при CCSPlayer v2
     * (replace после test_fsv: n=1, поле m_nHealth) -> 1 путь, 1 miss */
    CHECK(g_fmap_cls == 5, "fmap: покрытие вызвано для 5 именованных классов");
    CHECK(g_fmap_nofsv == 0, "fmap: FSV-стейт был готов (test_fsv раньше)");
    CHECK(g_fmap_paths == 1 && g_fmap_miss == 1 && g_fmap_hit == 0,
          "fmap: v2-стейт (n=1) дал 1 путь/1 miss");
    u32 p0 = g_fmap_paths, h0 = g_fmap_hit, v0 = g_fmap_vec, a0 = g_fmap_amb,
        s0 = g_fmap_miss;

    /* перерегистрируем ПОЛНЫЙ CCSPlayer (v3) + CBodyComponent (v6) — msg3 */
    u8 m3[1024]; u32 n3 = 0;
    const char *syms3[] = {
        "CCSPlayer", "CBodyComponent", "m_angRotation", "QAngle",
        "m_vecVelocity", "Vector", "coord", "m_nHealth", "int32",
        "m_hModel", "CStrongHandle< InfoForResourceTypeCModel >", "fixed64",
        "m_pBodyComponent", "CBodyComponent*", "m_szClan", "char[16]",
        "m_iAmmo", "CNetworkUtlVectorBase< CHandle< CBaseCombatWeapon > >",
        "m_iClip1", "m_flPoseParameter", "float32",
        "CNetworkedQuantizedFloat", "m_flQuant" };
    for (u32 i = 0; i < sizeof(syms3) / sizeof(syms3[0]); i++)
        n3 += fsv_sym(m3 + n3, syms3[i]);
    static const u8 lohi01b[8] = { 0,0,0,0, 0,0,0x80,0x3F };
    fsv_fld_spec_t flds3[10] = {
        { 3,  2,  -1, 0,     0, 0 },         /* 0 m_angRotation QAngle */
        { 5,  4,  -1, 6,     0, 0 },         /* 1 m_vecVelocity Vector/coord */
        { 8,  7,  -1, 0,     0, 0 },         /* 2 m_nHealth int32 */
        { 10, 9,  -1, 11,    0, 0 },         /* 3 m_hModel CStrongHandle/fixed64 */
        { 13, 12, -1, 0,     1, 0 },         /* 4 m_pBodyComponent CBodyComponent* */
        { 15, 14, -1, 0,     0, 0 },         /* 5 m_szClan char[16] */
        { 17, 16, -1, 0,     0, 0 },         /* 6 m_iAmmo CNetworkUtlVectorBase */
        { 8,  18, -1, 0,     0, 0 },         /* 7 m_iClip1 int32 */
        { 20, 19, 11, 0,     0, lohi01b },   /* 8 m_flPoseParameter quant */
        { 21, 22, 8,  0,     0, 0 },         /* 9 m_flQuant */
    };
    for (u32 i = 0; i < 10; i++) n3 += fsv_field(m3 + n3, &flds3[i]);
    u32 iv3[] = { 0 };
    u32 i3[9]; for (u32 i = 0; i < 9; i++) i3[i] = i + 1;
    n3 += fsv_ser(m3 + n3, 1, 6, iv3, 1);      /* CBodyComponent v6 */
    n3 += fsv_ser(m3 + n3, 0, 3, i3, 9);       /* CCSPlayer v3 */
    u32 fn3 = g_fsv_field_n, err3 = g_fsv_err;
    c2b_fsv_parse(m3, n3);
    CHECK(g_fsv_err == err3 && g_fsv_field_n == fn3 + 10, "fmap: msg3 распарсен (10 новых полей)");
    CHECK(g_fsv_ser[1].ver == 3 && g_fsv_ser[1].n == 9, "fmap: CCSPlayer заменён на v3 (9 полей)");

    c2b_fmap_class("CCSPlayer", "DT_CSPlayer", c2b_fsv_find_ser("CCSPlayer"));
    CHECK(g_fmap_paths - p0 == 9, "fmap: +9 листовых путей (8 полей v3 + вложенный m_angRotation)");
    CHECK(g_fmap_hit - h0 == 4, "fmap: +4 hit (m_angRotation, m_vecVelocity, m_iAmmo, m_flPoseParameter)");
    CHECK(g_fmap_vec - v0 == 1, "fmap: +1 vec (S2 Vector m_vecVelocity -> S1 m_vecVelocity[0..2])");
    CHECK(g_fmap_amb - a0 == 1, "fmap: +1 amb (m_iAmmo в двух контекстах)");
    CHECK(g_fmap_miss - s0 == 5, "fmap: +5 miss (m_nHealth, m_hModel, m_szClan, m_iClip1, m_flQuant)");

    /* слот-пространство DT_CSPlayer: число из step_g8_s1_flatten.py */
    const dt_entry *e = c2b_dt_find(c2b_fnv1a("DT_CSPlayer"));
    CHECK(e != 0, "fmap: DT_CSPlayer найден в g_dt_index");
    u32 off = 0, cnt = 0;
    CHECK(c2b_s1_slots_of((u32)(e - g_dt_index), &off, &cnt) == 0 && cnt == 717,
          "fmap: DT_CSPlayer slots == 717 (демо-алгоритм)");

    /* unit-правила матча */
    i32 comp = -1;
    CHECK(c2b_slot_match(off, cnt, "m_iHealth", 0, &comp) == 2,
          "fmap: m_iHealth -> 2 слота (PlayerState+LocalPlayerExclusive)");
    CHECK(c2b_slot_match(off, cnt, "m_NotAPropZzz", 0, &comp) == 0,
          "fmap: неизвестное имя -> miss");
    u32 nv = c2b_sym_store((const u8 *)"m_vecVelocity", 13);
    CHECK(c2b_slot_match(off, cnt, "m_vecX", nv, &comp) > 0 && comp == 0,
          "fmap: правило (b) node+'[x|y|z]': m_vecX @m_vecVelocity -> [0]");
    CHECK(c2b_slot_match(off, cnt, "m_vecVelocity", 0, &comp) > 0 && comp == -2,
          "fmap: правило (c) S2-Vector -> S1-компоненты [0..2]");
    CHECK(c2b_slot_match(off, cnt, "m_hMyWeapons", 0, &comp) == 2,
          "fmap: S2 VariableArray -> S1 DPT_Array (2 контекста)");
    CHECK(g_s1_pri == 0, "fmap: не-64 priority в блобе нет (identity-порядок)");

    printf("    slots_total=%u fmap: cls=%u paths=%u hit=%u vec=%u amb=%u miss=%u\n",
           g_s1_slots_n, g_fmap_cls, g_fmap_paths, g_fmap_hit, g_fmap_vec, g_fmap_amb,
           g_fmap_miss);
}

static void test_vlog(void)
{
    printf("[t] vlog (R30): rate-limit живого лога\n");
    CHECK(c2b_vlog_hit(1, 1, 8, 1024), "vlog: первый вызов попадает");
    CHECK(c2b_vlog_hit(1, 8, 8, 1024), "vlog: граница first=8");
    CHECK(!c2b_vlog_hit(1, 9, 8, 1024), "vlog: 9-й вызов — пропуск");
    CHECK(c2b_vlog_hit(1, 1024, 8, 1024), "vlog: каждый every-й (1024)");
    CHECK(!c2b_vlog_hit(1, 1023, 8, 1024), "vlog: перед every — пропуск");
    CHECK(c2b_vlog_hit(1, 2048, 8, 1024), "vlog: 2048 тоже every");
    CHECK(!c2b_vlog_hit(0, 1, 8, 1024), "vlog: level 0 — никогда");
    CHECK(c2b_vlog_hit(2, 999999, 8, 1024), "vlog: level 2 — всегда");
    CHECK(!c2b_vlog_hit(1, 10, 8, 0), "vlog: every=0 — пропуск вне first");
    CHECK(c2b_vlog_hit(1, 5, 8, 0), "vlog: every=0 — first работает");
    CHECK(c2b_vlog_hit(2, 0, 0, 0), "vlog: level 2 приоритетнее нулей");
}

/* R36: ubitvar писатель 16/256/4096 (движковая схема WriteUBitVar) */
static void test_r36(void)
{
    printf("[t] r36: ubitvar 16/256/4096\n");
    /* (1) roundtrip + точная бит-длина по всем формам */
    static const u32 vv[] = { 0, 1, 15, 16, 17, 31, 63, 64, 100, 255,
                              256, 257, 1000, 1023, 1024, 4095, 4096,
                              16383, 16384, 65535, 0x10000u, 0xFFFFFFFFu };
    for (u32 i = 0; i < (u32)(sizeof(vv) / sizeof(vv[0])); i++) {
        u8 buf[16]; c2b_bw_t w;
        w.buf = buf; w.cap = sizeof(buf); w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
        c2b_bw_ubitvar(&w, vv[i]);
        u32 nbits = 8 * w.pos + w.bitcnt;      /* до flush — точная длина */
        u32 want = (vv[i] < 16) ? 6 : (vv[i] < 256) ? 10 : (vv[i] < 4096) ? 14 : 34;
        c2b_bw_flush(&w);
        c2b_br_t r; c2b_br_init(&r, buf, w.pos);
        u32 back = c2b_br_ubitvar(&r);
        if (!(nbits == want && back == vv[i] && !r.ovf)) {
            printf("  FAIL r36 roundtrip #%u v=%u (nbits=%u want=%u back=%u)\n",
                   i, vv[i], nbits, want, back);
            fails++;
        }
    }
    /* (2) wire-паттерны: границы 64/1024/16384 + баговые диапазоны старого кода */
    static const struct { u32 v; u32 n; u8 b[5]; } wr[] = {
        { 16,           2, { 0x50, 0x00 } },                      /* esc-1 нижняя граница */
        { 17,           2, { 0x51, 0x00 } },
        { 63,           2, { 0xDF, 0x00 } },                      /* баг 16..63: desync */
        { 64,           2, { 0x10, 0x01 } },                      /* «порог 64» */
        { 255,          2, { 0xDF, 0x03 } },
        { 256,          2, { 0x20, 0x04 } },                      /* баг 256..1023: усечение */
        { 1024,         2, { 0x20, 0x10 } },                      /* «порог 1024» */
        { 4095,         2, { 0xEF, 0x3F } },
        { 16384,        5, { 0x30, 0x00, 0x01, 0x00, 0x00 } },    /* «порог 16384», esc-3 */
        { 0xFFFFFFFFu,  5, { 0xFF, 0xFF, 0xFF, 0xFF, 0x03 } },    /* максимум */
    };
    for (u32 i = 0; i < (u32)(sizeof(wr) / sizeof(wr[0])); i++) {
        u8 buf[8]; c2b_bw_t w;
        w.buf = buf; w.cap = sizeof(buf); w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
        c2b_bw_ubitvar(&w, wr[i].v);
        u32 n = c2b_bw_flush(&w);
        if (!(n == wr[i].n && memcmp(buf, wr[i].b, wr[i].n) == 0)) {
            printf("  FAIL r36 wire #%u v=%u\n", i, wr[i].v); fails++;
        }
    }
    /* (3) e2e: escape-дельта 19 сквозь c2b_g4_packetentities (LEAVE-only кадр) */
    {
        static u8 eb[64]; c2b_bw_t w;
        w.buf = eb; w.cap = sizeof(eb); w.pos = 0; w.bitval = 0; w.bitcnt = 0; w.ovf = 0;
        c2b_bw_ubitvar(&w, 0);  c2b_bw_bits(&w, 1, 2);   /* idx 0  LEAVE (d=0)  */
        c2b_bw_ubitvar(&w, 19); c2b_bw_bits(&w, 1, 2);   /* idx 20 LEAVE (d=19>=16) */
        u32 en = c2b_bw_flush(&w);
        u8 pe[96]; u32 pn = 0;
        pe[pn++] = (2u << 3); pn += c2b_write_varint(pe + pn, 2);
        pe[pn++] = (4u << 3); pn += c2b_write_varint(pe + pn, 1);   /* f4 update_baseline=1 */
        pe[pn++] = (7u << 3) | 2; pn += c2b_write_varint(pe + pn, en);
        for (u32 i = 0; i < en; i++) pe[pn++] = eb[i];
        u8 in[128]; u32 il = 0;
        il += c2b_write_varint(in + il, 55);
        il += c2b_write_varint(in + il, pn);
        for (u32 i = 0; i < pn; i++) in[il++] = pe[i];
        static u8 out[512]; u32 olen = 0;
        u32 ub0 = g_g4_ub;
        i32 rc = c2b_translate(in, il, out, sizeof(out), &olen, &g_st);
        CHECK(rc == 0 && olen > 2 && out[0] == 26, "r36: leave-кадр переведён (svc 26)");
        CHECK(g_g4_ub == ub0 + 1, "r36: ub+1 — f4 update_baseline=1 учтён");
        /* парс f7: две LEAVE-записи, вторая дельта обязана пройти escape-формой */
        u32 o = 1, slen = 0; const u8 *f7 = 0; u32 f7n = 0;
        o += c2b_read_varint(out + o, olen - o, &slen);
        for (u32 p = o; p < o + slen;) {
            u32 tag, c = c2b_read_varint(out + p, o + slen - p, &tag);
            if (!c) break; p += c;
            if ((tag & 7) == 0) { u32 v; c = c2b_read_varint(out + p, o + slen - p, &v); p += c; }
            else if ((tag & 7) == 2) { u32 l; c = c2b_read_varint(out + p, o + slen - p, &l); p += c;
                                       if ((tag >> 3) == 7) { f7 = out + p; f7n = l; } p += l; }
            else break;
        }
        CHECK(f7 && f7n > 0, "r36: entity_data есть");
        c2b_br_t r; c2b_br_init(&r, f7, f7n);
        u32 d0 = c2b_br_ubitvar(&r);
        CHECK(d0 == 0 && c2b_br_bit(&r) == 1 && c2b_br_bit(&r) == 0, "r36: idx0 leave (6Б форма)");
        u32 d19 = c2b_br_ubitvar(&r);
        CHECK(d19 == 19 && c2b_br_bit(&r) == 1 && c2b_br_bit(&r) == 0,
              "r36: дельта 19 escape-формой (10Б)");   /* до R36a: desync/мусор */
        CHECK(!r.ovf, "r36: ридер S1-вывода без оверфлоу");
    }
    printf("  OK   r36 ubitvar roundtrip x%d + wire x10 + e2e\n",
           (int)(sizeof(vv) / sizeof(vv[0])));
}

static void test_r33_cache(void)
{
    printf("[t] cls-at cache (R33): cap 4096 + ovf-счётчик\n");
    CHECK(C2B_G4B_CLS_AT == 4096, "r33: cap поднят 1024 -> 4096");
    g_g4b_cls_at[1023] = 7;
    g_g4b_cls_at[1024] = 9;       /* раньше — за границей: кэш молча терялся */
    g_g4b_cls_at[4095] = 11;
    CHECK(g_g4b_cls_at[1023] == 7 && g_g4b_cls_at[1024] == 9 &&
          g_g4b_cls_at[4095] == 11, "r33: запись/чтение вокруг старой границы 1024");
    g_g4b_cls_ovf = 0;
    CHECK(g_g4b_cls_ovf == 0, "r33: счётчик ovf доступен и сброшен");
    for (u32 ci = 0; ci < C2B_G4B_CLS_AT; ci++) g_g4b_cls_at[ci] = C2B_G4B_NOCLS;
    CHECK(g_g4b_cls_at[1024] == C2B_G4B_NOCLS && g_g4b_cls_at[4095] == C2B_G4B_NOCLS,
          "r33: сброс покрывает весь cap (Create-инициализация)");
}

static void test_gc_policy(void)
{
    printf("[t] gc policy (t39/audit_t38): таблицы роя + id-мапа + слот-парсер\n");
    CHECK(C2B_GC_S1_TAB_N == 196, "t39: S1-таблица 196 имён роя");
    CHECK(C2B_GC_S2_TAB_N == 664, "t39: S2-таблица 664 имён роя");
    CHECK(c2b_gc_act_by_name(C2B_GC_S1_TAB, C2B_GC_S1_TAB_N,
                             "CMsgGCCStrike15_v2_AccountPrivacySettings") == C2B_GC_IDENTITY,
          "t39: identity-пара S1≡S2 (AccountPrivacySettings)");
    CHECK(c2b_gc_act_by_name(C2B_GC_S1_TAB, C2B_GC_S1_TAB_N,
                             "CMsgGCHAccountVacStatusChange") == C2B_GC_S1ONLY,
          "t39: S1-only -> кандидат DROP аплинка (GCHVacStatusChange)");
    CHECK(c2b_gc_act_by_name(C2B_GC_S2_TAB, C2B_GC_S2_TAB_N,
                             "CMsgAckPetEvent") == C2B_GC_S2NEW,
          "t39: new-in-S2 -> fail-closed DROP даунлинка (AckPetEvent)");
    CHECK(c2b_gc_act_by_name(C2B_GC_S2_TAB, C2B_GC_S2_TAB_N,
                             "CMsgGCCStrike15_v2_GC2ClientTextMsgEE") == C2B_GC_IDENTITY,
          "t39: EE-твин выжил в обоих (GC2ClientTextMsgEE)");
    const c2b_gc_ent_t *e = c2b_gc_by_id(9158);   /* k_EMsgGCCStrike15_v2_AccountPrivacySettings */
    CHECK(e && e->id == 9158 && e->act == C2B_GC_IDENTITY,
          "t39: id-мапа 9158 -> AccountPrivacySettings/identity");
    CHECK(c2b_gc_by_id(1) == 0, "t39: id вне частичного прото -> 0 (act=? в логе)");
    /* t42v9: даунлинк-фильтр S2NEW (fail-closed по audit_t38) */
    CHECK(c2b_gc_dn_drop(9210) == 1, "t42v9: S2NEW 9210 DeepStats -> dn DROP");
    CHECK(c2b_gc_dn_drop(9158) == 0, "t42v9: identity 9158 -> dn passthrough");
    CHECK(c2b_gc_dn_drop(4004) == 0, "t42v9: core 4004 ClientWelcome -> dn passthrough");
    CHECK(c2b_gc_dn_drop(0) == 0, "t42v9: id=0 (wire-id неизвестен) -> passthrough");
    /* слот-парсер: mov rax,[rdi]; jmp [rax+0x10] => слот 2 (массивы 32Б — окно парсера) */
    static const u8 flat2[32] = { 0x48,0x8B,0x07,0xFF,0x60,0x10 };
    CHECK(c2b_gc_slot_of(flat2) == 2, "t39: flat jmp [rax+0x10] -> слот 2");
    static const u8 flat0[32] = { 0xFF,0x20 };   /* jmp [rax] -> слот 0 */
    CHECK(c2b_gc_slot_of(flat0) == 0, "t39: flat jmp [rax] -> слот 0");
    static const u8 flat3[32] = { 0x48,0x8B,0x07,0xFF,0xA0,0x18,0x00,0x00 }; /* [rax+0x18] */
    CHECK(c2b_gc_slot_of(flat3) == 3, "t39: flat disp32 [rax+0x18] -> слот 3");
    static const u8 badfn[32] = { 0x90 };
    CHECK(c2b_gc_slot_of(badfn) == -1, "t39: без FF /4 -> отказ (fail-closed)");
    printf("  OK   gc policy: 196/664 + idmap 51 + слоты vtable\n");
}

/* t42v10: ClientHello-pump на дублях — автомат верифицируется без GC:
 * A) GC молчит: все попытки исчерпаны -> state=exhausted, дренаж работал;
 * B) GC отвечает 4004 ClientWelcome: state=dn-received, dn/uniq учтены. */
static u32 t_hl_sends, t_hl_retr_n, t_hl_reply_at;
static void *t_hl_last_self;      /* run31-ABI-фикс: self обязан доходить */
static i32 t_hl_fake_send(void *self, u32 mt, const void *d, u32 sz)
{ (void)mt; (void)d; (void)sz; t_hl_sends++; t_hl_last_self = self; return 1; }
static i32 t_hl_retr_empty(void *self, u32 *mt, void *d, u32 dsz, u32 *rsz)
{ (void)mt; (void)d; (void)dsz; (void)rsz; t_hl_retr_n++; t_hl_last_self = self;
  return 2; }
static i32 t_hl_retr_welcome(void *self, u32 *mt, void *d, u32 dsz, u32 *rsz)
{
    t_hl_retr_n++; t_hl_last_self = self;
    if (t_hl_reply_at && t_hl_retr_n >= t_hl_reply_at) {
        static const u8 body[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        *mt = 0x80000000u | 4004u;            /* CMsgClientWelcome */
        u32 n = (u32)sizeof(body);
        if (n > dsz) n = dsz;
        memcpy(d, body, n);
        *rsz = n;
        t_hl_reply_at = 0;                    /* один раз */
        return 1;
    }
    return 2;
}
static void test_gc_hello(void)
{
    printf("[t] gc hello-pump (t42v8/10): автомат ClientHello на дублях\n");
    c2b_gc_send_t sv_send = g_gc_orig_send;
    c2b_gc_retr_t sv_retr = g_gc_orig_retr;
    u32 sv_every = g_hello_every, sv_pre = g_hello_pre, sv_tail = g_hello_tail;
    u32 sv_iters = g_hello_iters, sv_tick = g_hello_tick_us;
    u32 sv_state = g_hello_state, sv_sends = g_hello_sends;
    u8 sv_mode = g_hello_mode, sv_tmode = g_gc_t_mode;
    u32 sv_upn = g_gc_up_n, sv_dnn = g_gc_dn_n, sv_uniqn = g_gc_uniq_n;
    u8 sv_estate = g_state;
    void *sv_obj = g_gc_obj;
    static u8 t_hl_obj_anchor;       /* сентинел-объект для ABI-чека */
    g_hello_mode = 1; g_gc_t_mode = 0; g_hello_tick_us = 1000;
    g_state = 1;                     /* pump гейтится на ARMED движка */
    g_gc_obj = (void *)&t_hl_obj_anchor;
    t_hl_last_self = 0;

    /* A: GC молчит (pre=1, every=2, iters=12 -> 6 попыток укладываются) */
    g_hello_every = 2; g_hello_pre = 1; g_hello_tail = 2; g_hello_iters = 12;
    g_gc_orig_send = t_hl_fake_send; g_gc_orig_retr = t_hl_retr_empty;
    t_hl_sends = 0; t_hl_retr_n = 0; g_hello_state = 0; g_hello_sends = 0;
    __atomic_store_n(&g_gc_state, 1u, __ATOMIC_SEQ_CST);
    c2b_gc_hello_pump();
    CHECK(t_hl_sends == C2B_HELLO_TRIES, "hello: A — все 6 попыток сделаны");
    CHECK(g_hello_state == 3, "hello: A — state=exhausted после тишины");
    CHECK(t_hl_retr_n > t_hl_sends, "hello: A — дренаж очереди работал");
    CHECK(t_hl_last_self == (void *)&t_hl_obj_anchor,
          "hello: ABI — self (this) доходит до оригинала (run31-фикс)");

    /* B: GC отвечает 4004 на 5-м вызове retr — ранний выход по tail */
    g_gc_orig_send = t_hl_fake_send; g_gc_orig_retr = t_hl_retr_welcome;
    t_hl_sends = 0; t_hl_retr_n = 0; t_hl_reply_at = 5; t_hl_last_self = 0;
    g_hello_state = 0; g_hello_sends = 0; g_gc_dn_n = 0; g_gc_uniq_n = 0;
    c2b_gc_hello_pump();
    CHECK(g_hello_state == 2, "hello: B — state=dn-received");
    CHECK(g_gc_dn_n == 1, "hello: B — dn=1 (4004 ClientWelcome учтён)");
    {   /* uniq: hello 4006 (up) попадает раньше ответа — ищем 4004/dn по таблице */
        u32 seen4004 = 0;
        for (u32 k = 0; k < g_gc_uniq_n; k++)
            if (g_gc_uniq[k].id == 4004 && g_gc_uniq[k].dn == 1) seen4004 = 1;
        CHECK(seen4004, "hello: B — uniq-таблица видит 4004 dn");
        CHECK(g_gc_uniq_n >= 2, "hello: B — в uniq и hello(4006), и welcome(4004)");
    }
    CHECK(t_hl_sends >= 1, "hello: B — hello был отправлен до ответа");

    /* restore: мост после selftest остаётся в исходном состоянии */
    g_gc_orig_send = sv_send; g_gc_orig_retr = sv_retr;
    g_hello_every = sv_every; g_hello_pre = sv_pre; g_hello_tail = sv_tail;
    g_hello_iters = sv_iters; g_hello_tick_us = sv_tick;
    g_hello_state = sv_state; g_hello_sends = sv_sends;
    g_hello_mode = sv_mode; g_gc_t_mode = sv_tmode;
    g_gc_up_n = sv_upn; g_gc_dn_n = sv_dnn; g_gc_uniq_n = sv_uniqn;
    g_state = sv_estate; g_gc_obj = sv_obj;
    __atomic_store_n(&g_gc_state, 0u, __ATOMIC_SEQ_CST);
    printf("  OK   gc hello-pump: silence->exhausted, welcome->dn-received\n");
}

/* 41e-a: connectionless-слой v1 — классификация/фильтры/hexline (без сети:
 * чистые функции слоя; хуки sendto/recvfrom в selftest не вызываются) */
static void test_cl(void)
{
    printf("[t] cl: connectionless v1 — классификация/фильтр/hexline\n");
    static const u8 p_gc[] = { 0xFF,0xFF,0xFF,0xFF,'g','e','t','c','h','a','l','l','e','n','g','e',0 };
    static const u8 p_cn[] = { 0xFF,0xFF,0xFF,0xFF,'c','o','n','n','e','c','t',' ','1','2','7',0 };
    static const u8 p_rc[] = { 0xFF,0xFF,0xFF,0xFF,'r','c','o','n',' ','p','w',0 };
    static const u8 p_qc[] = { 0xFF,0xFF,0xFF,0xFF,'q','c','o','n','n','e','c','t','0','x',
                               '1','2','3','4','A','B','C','D',0 };   /* S1 CS:GO (41e-b) */
    static const u8 p_a2[] = { 0xFF,0xFF,0xFF,0xFF,'T','S','o','u','r','c','e',0 };
    static const u8 p_ch[] = { 0xFF,0xFF,0xFF,0xFF,'A',12,0,0,0,0 };
    static const u8 p_9r[] = { 0xFF,0xFF,0xFF,0xFF,'9','b','a','d',0 };
    static const u8 p_br[] = { 0xFF,0xFF,0xFF,0xFF,'B','n','o','p',0 };
    static const u8 p_si[] = { 0xFF,0xFF,0xFF,0xFF,'C',0 };
    static const u8 p_in[] = { 0xFF,0xFF,0xFF,0xFF,'m',0 };
    static const u8 p_q[]  = { 0xDE,0xAD,0xBE,0xEF,1,2,3,4,0 };   /* игровой (не connless) */
    static const u8 p_sh[] = { 0xFF,0xFF,0xFF,0 };                /* короткое «похожее» */
#define CL_N(a) ((u32)sizeof(a) - 1)    /* у всех массивов хвостовой 0 вне датаграммы */
    CHECK(c2b_cl_is_connless(p_gc, CL_N(p_gc)) == 1, "cl: ffff-префикс распознан");
    CHECK(c2b_cl_is_connless(p_q, CL_N(p_q)) == 0, "cl: игровой пакет не connless");
    CHECK(c2b_cl_is_connless(p_sh, CL_N(p_sh)) == 0, "cl: 3 байта ff — не connless");
    CHECK(c2b_cl_class_up(p_gc, CL_N(p_gc)) == C2B_CLQ_CHALLENGE, "cl: up getchallenge");
    CHECK(c2b_cl_class_up(p_cn, CL_N(p_cn)) == C2B_CLQ_CONNECT, "cl: up connect");
    CHECK(c2b_cl_class_up(p_rc, CL_N(p_rc)) == C2B_CLQ_RCON, "cl: up rcon");
    CHECK(c2b_cl_class_up(p_qc, CL_N(p_qc)) == C2B_CLQ_QCONNECT, "cl: up qconnect0x (S1 CS:GO, 41e-b)");
    CHECK(c2b_cl_class_up(p_a2, CL_N(p_a2)) == C2B_CLQ_OTHER, "cl: up прочее (A2S 'T')");
    CHECK(c2b_cl_class_up(p_q, CL_N(p_q)) == C2B_CLQ_NONE, "cl: up не-connless -> NONE");
    CHECK(c2b_cl_class_dn(p_ch, CL_N(p_ch)) == C2B_CLR_CHALLENGE, "cl: dn 'A' challenge");
    CHECK(c2b_cl_class_dn(p_9r, CL_N(p_9r)) == C2B_CLR_REJECT, "cl: dn '9' reject");
    CHECK(c2b_cl_class_dn(p_br, CL_N(p_br)) == C2B_CLR_REJECT, "cl: dn 'B' reject");
    CHECK(c2b_cl_class_dn(p_si, CL_N(p_si)) == C2B_CLR_SINFO, "cl: dn 'C' sinfo");
    CHECK(c2b_cl_class_dn(p_in, CL_N(p_in)) == C2B_CLR_INFO, "cl: dn 'm' info");
    CHECK(c2b_cl_filter_uplink(p_cn, CL_N(p_cn)) == C2B_CL_PASSTHROUGH, "cl: uplink v1 = passthrough");
    CHECK(c2b_cl_filter_downlink(p_ch, CL_N(p_ch)) == C2B_CL_PASSTHROUGH, "cl: downlink v1 = passthrough");
    {
        char ln[C2B_CL_DUMP_MAX * 3 + C2B_CL_DUMP_MAX + 8];
        u32 n = CL_N(p_gc), o = c2b_cl_hexline(p_gc, n, ln, (u32)sizeof(ln));
        CHECK(o == n * 3 + 2 + n && ln[o] == 0, "cl: hexline длина/NUL");
        CHECK(ln[0] == 'f' && ln[48] == '|' && ln[50] == '.' && ln[54] == 'g', "cl: hexline формат (hex 48, '| ', ascii '....getchallenge')");
        static u8 big[C2B_CL_DUMP_MAX + 24];
        for (u32 i = 0; i < sizeof(big); i++) big[i] = 0xFF;
        u32 ob = c2b_cl_hexline(big, (u32)sizeof(big), ln, (u32)sizeof(ln));
        CHECK(ob == C2B_CL_DUMP_MAX * 4 + 2, "cl: hexline кламп 96 байт");
    }
    g_cl_log_n = 0;                      /* трассировка: печать без краха, счётчики классов */
    c2b_cl_trace(1, p_gc, CL_N(p_gc), C2B_CL_PASSTHROUGH);
    c2b_cl_trace(0, p_ch, CL_N(p_ch), C2B_CL_PASSTHROUGH);
    /* 41e-c: CL v2 phase A — S2 GNS challenge-обмен (чистые функции, без сети) */
    {
        u8 req[512];
        /* 41f-a: c2b_ver_pfx — префикс-чек версий интерфейсов (SteamUser022) */
        CHECK(c2b_ver_pfx("SteamUser022", "SteamUser0") == 1, "auth: SteamUser022 матчит префикс");
        CHECK(c2b_ver_pfx("SteamUser023", "SteamUser0") == 1, "auth: SteamUser023 матчит префикс");
        CHECK(c2b_ver_pfx("SteamFriends017", "SteamUser0") == 0, "auth: SteamFriends не матчит");
        CHECK(c2b_ver_pfx("SteamUser", "SteamUser0") == 0, "auth: короткая версия не матчит");
        CHECK(c2b_ver_pfx(0, "SteamUser0") == 0, "auth: NULL версия безопасна");
        u32 rl = c2b_clv2_build_chalreq(req);
        CHECK(rl == 512, "clv2: ChallengeRequest = 512 байт (GNS min padded)");
        CHECK(req[0] == 0x20, "clv2: msgid 0x20");
        u32 pl = (u32)req[1] | ((u32)req[2] << 8);
        CHECK(pl == 16, "clv2: pb-длина = 16 (f1+cid, f3+ts, f4+ver)");
        CHECK(req[3] == 0x0d, "clv2: f1 connection_id fixed32 tag");
        {
            u32 cid = (u32)req[4] | ((u32)req[5] << 8) |
                      ((u32)req[6] << 16) | ((u32)req[7] << 24);
            CHECK(cid != 0, "clv2: connection_id != 0 (сервер роняет cid=0)");
            CHECK(req[3 + pl - 2] == 0x20 && req[3 + pl - 1] == 0x0d,
                  "clv2: f4 protocol_version=13");
            /* канонический ответ сервера (песочница 20261004, challenge живой) */
            static const u8 rp[] = {
                0x21,
                0x0d, 0x01, 0x5e, 0xda, 0xd0,                  /* f1 cid=0xd0da5e01 */
                0x11, 0x17, 0x48, 0x33, 0x59, 0xa5, 0xe7, 0xfe, 0xe5, /* f2 challenge 0xe5fee7a559334817 */
                0x19, 0x21, 0x5b, 0x8b, 0x07, 0xa1, 0x01, 0x00, 0x00, /* f3 your_ts */
                0x20, 0x0d                                     /* f4 varint 13 */
            };
            u64 ch = 0, ts = 0;
            CHECK(c2b_clv2_parse_chalreply(rp, (u32)sizeof(rp), 0xd0da5e01u, &ch, &ts) == 1,
                  "clv2: ChallengeReply парсится");
            CHECK(ch == 0xe5fee7a559334817ull, "clv2: challenge64 извлечён");
            CHECK(ts == 0x000001a1078b5b21ull, "clv2: g31 your_ts эхо извлечено");
            CHECK(c2b_clv2_parse_chalreply(rp, (u32)sizeof(rp), 0xdeadbeefu, &ch, &ts) == 0,
                  "clv2: чужой connection_id отвергнут");
            CHECK(c2b_clv2_parse_chalreply(rp, 8, 0xd0da5e01u, &ch, &ts) == 0,
                  "clv2: усечённый ответ отвергнут");
            {
                static const u8 rb[] = { 0x20, 0x0d, 0x01 };
                CHECK(c2b_clv2_parse_chalreply(rb, (u32)sizeof(rb), 0xd0da5e01u, &ch, &ts) == 0,
                      "clv2: не-0x21 отвергнут");
            }
            /* 41e-d: форматы 'A'-ответа движку (матрица C2B_CLV2_FMT) */
            {
                u8 ar[128]; u32 al;
                al = c2b_clv2_build_chalreply(ar, (u32)sizeof(ar), 0, 0, 0xB0AA4BD7u);
                CHECK(al == 9 && ar[4] == 'A' && ar[5] == 0xd7 && ar[8] == 0xb0,
                      "clv2: fmt0 = 41+le32");
                al = c2b_clv2_build_chalreply(ar, (u32)sizeof(ar), 1, 0, 0xB0AA4BD7u);
                CHECK(al == 16, "clv2: fmt1 = ascii0x длина 16");
                CHECK(ar[4]=='A' && ar[5]=='0' && ar[6]=='x' && ar[15] == 0,
                      "clv2: fmt1 = '0x' + hex + NUL");
                al = c2b_clv2_build_chalreply(ar, (u32)sizeof(ar), 2, 0, 0xB0AA4BD7u);
                CHECK(al == 13 && ar[9] == 17, "clv2: fmt2 = le32+le32(17)");
                al = c2b_clv2_build_chalreply(ar, (u32)sizeof(ar), 3, 7u, 0xB0AA4BD7u);
                CHECK(al == 13 && ar[5] == 7, "clv2: fmt3 = echo(qc)+le32");
                al = c2b_clv2_build_chalreply(ar, (u32)sizeof(ar), 4, 0, 0xB0AA4BD7u);
                CHECK(al == 20 && ar[15] == 0 && ar[16] == 17,
                      "clv2: fmt4 = ascii + le32(17)");
                CHECK(c2b_clv2_build_chalreply(ar, 8, 0, 0, 1) == 0,
                      "clv2: крошечный буфер -> 0");
                /* 41e-g: fmt8 — N-агностик (хвост = (reserve)*9 NUL) */
                {
                    u32 i;
                    al = c2b_clv2_build_chalreply(ar, (u32)sizeof(ar), 8, 0, 0x11223344u);
                    CHECK(al == 79, "clv2: fmt8 = 79 байт");
                    CHECK(ar[9] == 3 && ar[13] == 0 && ar[14] == 0, "clv2: fmt8 заголовок");
                    {
                        static const char w[] = "reserve";
                        u32 ok = 1;
                        for (i = 0; i < 63; i++)
                            if (ar[15 + i] != (u8)w[i % 7]) ok = 0;
                        CHECK(ok, "clv2: fmt8 хвост = (reserve)*9");
                    }
                    CHECK(ar[78] == 0, "clv2: fmt8 NUL");
                }
                /* 41e-i: fmt9 — REAL-legacy 'A', 59 байт на проводе
                 * (payload 55 после ffffffff-префикса; run 80: паддинг
                 * считали с префиксом — 4 байта коротки) */
                {
                    u32 i9;
                    al = c2b_clv2_build_chalreply(ar, (u32)sizeof(ar), 9,
                                                  0x00000000u, 0x11223344u);
                    CHECK(al == 59, "clv2: fmt9 = 59 байт (payload 55)");
                    CHECK(ar[4]=='A' && ar[9]==3 && ar[13]==0 && ar[14]==0,
                          "clv2: fmt9 заголовок (A, proto=3, ks=0)");
                    CHECK(ar[15]==0x07 && ar[16]==0x0a && ar[17]==0xee &&
                          ar[18]==0x00, "clv2: fmt9 value=steamid-low");
                    CHECK(ar[19]==0 && ar[20]==0x00 && ar[21]==0x30 &&
                          ar[22]==0x01 && ar[23]==0x01, "clv2: fmt9 flag+mystry4");
                    {
                        static const char p9[] = "connect0x00000000";
                        u32 ok9 = 1;
                        for (i9 = 0; i9 < 17; i9++)
                            if (ar[24 + i9] != (u8)p9[i9]) ok9 = 0;
                        CHECK(ok9, "clv2: fmt9 эхо connect0x%08X (qc=0)");
                    }
                    CHECK(ar[41]==0 && ar[42]=='9' && ar[43]=='6' && ar[44]==0,
                          "clv2: fmt9 NUL строки + '96'");
                    {
                        u32 okp = 1;
                        for (i9 = 45; i9 < 59; i9++) if (ar[i9] != 0) okp = 0;
                        CHECK(okp, "clv2: fmt9 хвостовой паддинг NUL до 59");
                    }
                    CHECK(c2b_clv2_build_chalreply(ar, 32, 9, 0, 1) == 0,
                          "clv2: fmt9 крошечный буфер -> 0");
                }
                /* 41e-j: A2S 'I' трансформ — реальные байты CYBERSHOKE
                 * (run 83 барьер: EDF + версия 1.41.8.8 -> тихий abort) */
                {
                    static const char *RI_HEX =
                        "ffffffff491143533220355835207c203576352023323837205b42525d20e28094204359"
                        "42455253484f4b452e4e45540064655f6d6972616765006373676f00436f756e7465722d"
                        "537472696b65203200da02004000646c0001312e34312e382e3800b1766d070aee000000"
                        "3001656d7074792c3576352c357673352c3578352c62742c63796265722c6379626572"
                        "73686f6b652c64655f6d69726167652c64726f702c6475656c2c656e2c6700da020000"
                        "00000000";
                    u8 rin[512], rout2[1200];
                    u32 rn2 = 0, rq;
                    for (rq = 0; RI_HEX[2 * rq] && RI_HEX[2 * rq + 1]; rq++) {
                        char c1 = RI_HEX[2 * rq], c2c = RI_HEX[2 * rq + 1];
                        u8 hi = (u8)((c1 > '9') ? (c1 | 32) - 'a' + 10 : c1 - '0');
                        u8 lo = (u8)((c2c > '9') ? (c2c | 32) - 'a' + 10 : c2c - '0');
                        rin[rq] = (u8)((hi << 4) | lo);
                    }
                    rn2 = rq;
                    al = c2b_a2s_transform_i(rin, rn2, rout2,
                                             (u32)sizeof(rout2));
                    CHECK(al > 0, "a2s: CYBERSHOKE 'I' распарсен");
                    CHECK(rout2[4] == 'I', "a2s: 'I' сохранён");
                    {
                        u32 q2 = 6, w2, vs2, ve2, okv = 1;
                        static const char vexp[] = "1.38.0.4";
                        for (w2 = 0; w2 < 4; w2++) {
                            while (q2 < al && rout2[q2] != 0) q2++;
                            q2++;
                        }
                        CHECK(q2 + 2 <= al && rout2[q2] == 0xda &&
                              rout2[q2 + 1] == 0x02, "a2s: appid=730 на месте");
                        vs2 = q2 + 2 + 7;
                        for (ve2 = 0; ve2 < 8; ve2++)
                            if (rout2[vs2 + ve2] != (u8)vexp[ve2]) okv = 0;
                        CHECK(okv && rout2[vs2 + 8] == 0,
                              "a2s: версия=1.38.0.4 (бандл)");
                        CHECK(vs2 + 9 == al, "a2s: EDF срезан (конец после версии)");
                    }
                    CHECK(c2b_a2s_transform_i(rin, rn2, rout2, 16) == 0,
                          "a2s: крошечный cap -> 0");
                    CHECK(c2b_a2s_transform_i(rin, 30, rout2,
                                              (u32)sizeof(rout2)) == 0,
                          "a2s: слишком короткий -> 0");
                }
                /* 41e-m: INFO-PUSH блоб — ферма-формат, движок потребляет
                 * unsolicited 'I' (run 72 CL dn #f4-8) */
                {
                    u8 ib[160];
                    u32 il = c2b_clv2_build_infoblob(ib, (u32)sizeof(ib));
                    CHECK(il > 60 && il < 128, "ipush: блоб собран");
                    CHECK(ib[4] == 'I' && ib[5] == 0x11,
                          "ipush: 'I' + protocol 17");
                    {
                        static const char h9[] = "c2b-bridge\0de_dust2\0"
                                                 "csgo\0";
                        u32 q9, ok9 = 1;
                        for (q9 = 0; q9 < sizeof(h9) - 1; q9++)
                            if (ib[6 + q9] != (u8)h9[q9]) ok9 = 0;
                        CHECK(ok9, "ipush: hostname/map/folder");
                    }
                    {
                        u32 q9 = 6, w9;
                        for (w9 = 0; w9 < 4; w9++) {
                            while (q9 < il && ib[q9] != 0) q9++;
                            q9++;
                        }
                        CHECK(ib[q9] == 0xda && ib[q9 + 1] == 0x02,
                              "ipush: appid=730");
                        CHECK(ib[q9 + 2] == 0 && ib[q9 + 3] == 24 &&
                              ib[q9 + 4] == 0, "ipush: 0/24/0");
                        CHECK(ib[q9 + 5] == 'd' && ib[q9 + 6] == 'l',
                              "ipush: dedicated/linux");
                        CHECK(ib[q9 + 7] == 0 && ib[q9 + 8] == 0,
                              "ipush: public/VAC off");
                        {
                            static const char ve[] = "1.38.0.4";
                            u32 vs9 = q9 + 9, e9, okv9 = 1;
                            for (e9 = 0; e9 < 8; e9++)
                                if (ib[vs9 + e9] != (u8)ve[e9]) okv9 = 0;
                            CHECK(okv9 && ib[vs9 + 8] == 0 && vs9 + 9 == il,
                                  "ipush: версия бандла + конец (без EDF)");
                        }
                    }
                }
                /* 41f-g31: X25519 (RFC 7748 §6.1) + 0x22 ConnectRequest */
                {
                    /* векторы §6.1 (hex в RFC = API-байты, little-endian):
                     * pub_a = X25519(a,9); shared = X25519(a, pub_b) */
                    static const u8 ka[32] = {
                        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a };
                    static const u8 paa[32] = {
                        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
                        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
                        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
                        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a };
                    static const u8 pub_b[32] = {   /* Bob PUBLIC X25519(b,9) */
                        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
                        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
                        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
                        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f };
                    static const u8 shx[32] = {     /* shared K */
                        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
                        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
                        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42 };
                    u8 base9[32], pa[32], ss[32];
                    u32 j, eqa = 1, eqs = 1;
                    for (j = 0; j < 32; j++) base9[j] = 0;
                    base9[0] = 9;
                    c2b_x25519(pa, ka, base9);
                    for (j = 0; j < 32; j++) if (pa[j] != paa[j]) eqa = 0;
                    CHECK(eqa, "g31: x25519(a,9) == pub_a (RFC 7748 6.1)");
                    c2b_x25519(ss, ka, pub_b);
                    for (j = 0; j < 32; j++) if (ss[j] != shx[j]) eqs = 0;
                    CHECK(eqs, "g31: x25519(a,pub_b) == shared (RFC 7748 6.1)");
                }
                {
                    /* note_reply/pick_fresh на РЕАЛЬНОМ байте run168 (pcap a1):
                     * 210d13de469d 11 3cc03e6203ef6335 19 adcedc6f71371796 20 0d
                     * cid=0x9d46de13 ch=0x3563ef03623ec03c ts=0x961737716fdccead */
                    static const u8 r168[] = {
                        0x21, 0x0d, 0x13, 0xde, 0x46, 0x9d, 0x11,
                        0x3c, 0xc0, 0x3e, 0x62, 0x03, 0xef, 0x63, 0x35,
                        0x19, 0xad, 0xce, 0xdc, 0x6f, 0x71, 0x37, 0x17, 0x96,
                        0x20, 0x0d };
                    u32 fc; u64 fch, fts;
                    u32 qi;
                    for (qi = 0; qi < 4; qi++) g_clv2_chrec[qi].valid = 0;
                    g_clv2_chrec_i = 0;
                    c2b_clv2_note_reply(r168, (u32)sizeof(r168));
                    CHECK(c2b_clv2_pick_fresh(&fc, &fch, &fts) == 1,
                          "g31: свежий challenge найден (run168 сэмпл)");
                    CHECK(fc == 0x9d46de13u, "g31: cid эхо = 0x9d46de13");
                    CHECK(fch == 0x3563ef03623ec03cull,
                          "g31: challenge = 0x3563ef03623ec03c (run168 wire)");
                    CHECK(fts == 0x961737716fdcceadull,
                          "g31: ts-эхо = 0x961737716fdccead (LE run168)");
                    CHECK(g_clv2_chrec[0].ms > 0, "g31: ms-метка записи стоит");
                }
                {
                    /* note_sid: самая длинная цифра-строка 'k' -> account id */
                    u8 fakek[64];
                    u32 qi;
                    for (qi = 0; qi < 64; qi++) fakek[qi] = 0;
                    fakek[0] = 0xff; fakek[1] = 0xff; fakek[2] = 0xff; fakek[3] = 0xff;
                    fakek[4] = 'k';
                    fakek[40] = '6'; fakek[41] = '8'; fakek[42] = '7';
                    fakek[43] = '1'; fakek[44] = '6'; fakek[45] = '8';
                    fakek[46] = '2'; fakek[47] = '1'; fakek[48] = '9';
                    g_clv2_sid64 = 0;
                    c2b_clv2_note_sid(fakek, (u32)sizeof(fakek));
                    CHECK(g_clv2_sid64 == (0x0110000100000000ULL | 687168219ull),
                          "g31: note_sid -> steamid64 = public|account");
                }
                {
                    /* build_connreq: фрейминг v1 (bare) и v2 (+crypt) */
                    u8 cr[512];
                    u32 pl2, qi;
                    g_clv2_sid64 = 0x0110000100000000ULL | 687168219ull;
                    pl2 = c2b_clv2_build_connreq(cr, 1, 0x12345678u,
                                                 0x1122334455667788ull,
                                                 0x0102030405060708ull);
                    CHECK(pl2 == 512, "g31: 0x22 = 512 байт (pad)");
                    CHECK(cr[0] == 0x22, "g31: msgid 0x22");
                    pl2 = (u32)cr[1] | ((u32)cr[2] << 8);
                    CHECK(pl2 == 34, "g31: v1 pb-длина = 34 (f1+f3+f4+f5+f8)");
                    CHECK(cr[3] == 0x0d && cr[4] == 0x78 && cr[7] == 0x12,
                          "g31: f1 cid LE = 0x12345678");
                    CHECK(cr[8] == 0x19 && cr[9] == 0x88 && cr[16] == 0x11,
                          "g31: f3 challenge LE");
                    CHECK(cr[17] == 0x21 && cr[18] == 0x08 && cr[25] == 0x01,
                          "g31: f4 my_timestamp LE");
                    CHECK(cr[26] == 0x28 && cr[27] == 0x0d,
                          "g31: f5 protocol_version=13");
                    CHECK(cr[28] == 0x41 && cr[33] == 0x01 && cr[36] == 0x01,
                          "g31: f8 steamid64 LE (0x01100001...: byte4+byte7=01)");
                    CHECK(cr[3 + pl2] == 0 && cr[511] == 0, "g31: паддинг NUL");
                    g_clv2_cr_have = 0;          /* форс keygen в v2 */
                    for (qi = 0; qi < 32; qi++) g_clv2_cr_pub[qi] = 0;
                    pl2 = c2b_clv2_build_connreq(cr, 2, 0x12345678u,
                                                 0x1122334455667788ull,
                                                 0x0102030405060708ull);
                    pl2 = (u32)cr[1] | ((u32)cr[2] << 8);
                    CHECK(pl2 == 74, "g31: v2 pb-длина = 74 (+40 crypt)");
                    CHECK(cr[28] == 0x3a && cr[29] == 38, "g31: f7 crypt tag+len 38");
                    CHECK(cr[30] == 0x0a && cr[31] == 36,
                          "g31: key_info len=36");
                    CHECK(cr[32] == 0x08 && cr[33] == 0x01,
                          "g31: key_type=1 (CURVE25519)");
                    CHECK(cr[34] == 0x12 && cr[35] == 32,
                          "g31: key_data len=32");
                    {
                        u32 nz = 0;
                        for (qi = 36; qi < 68; qi++) if (cr[qi]) nz = 1;
                        CHECK(nz, "g31: x25519 pub сгенерён (не все нули)");
                    }
                    CHECK(cr[68] == 0x41, "g31: f8 после crypt");
                    {
                        u32 okz = 1;
                        for (qi = 68; qi < 512; qi++)
                            if (qi > 76 && cr[qi] != 0) okz = 0;
                        CHECK(okz, "g31: v2 хвост = sid(8) + NUL-паддинг");
                    }
                    g_clv2_sid64 = 0;            /* не протекает в другие тесты */
                }
            }
        }
    }
    CHECK(g_cl_log_n == 2, "cl: trace считает пакеты (первые 32 всегда)");
    CHECK(g_cl_s_gc >= 1 && g_cl_r_ch >= 1, "cl: счётчики классов инкрементируются");
#undef CL_N
}

/* Детур-тесты патчат код заглушек в рантайме — под санитайзерами исполняемая
   инструментированная пролог-часть (stolen bytes) невалидна вне родного фрейма
   (clang+ASan: SIGSEGV). Логика детура покрыта test_up_dispatch без патчей. */
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_UNDEFINED__)
#  define C2B_ST_NO_DETOUR 1
#endif
#if defined(__has_feature)
#  if __has_feature(address_sanitizer) || __has_feature(undefined_behavior_sanitizer)
#    define C2B_ST_NO_DETOUR 1
#  endif
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = c2b_segv; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, 0);
    printf("c2bridge selftest\n=================\n");
    test_varint();
    test_translate();
    test_translate_ge();
    test_translate_sos();   /* t36/P208: фаза G-6 */
    test_translate_um();
    test_fsv();
    test_translate_classinfo();
    test_fmap();
    test_g4();
    test_r36();
    test_g4_cmd3();     /* t36: T35-гап cmd=3 (между test_g4 и test_g4b) */
    test_fph_weight();  /* t36: T35-гап fph-веса 100% */
    test_g4b();
    test_g4c();
    test_uplink();
    test_up_dispatch();
    test_downlink();
    test_g5_voice();
    test_vlog();
    test_r33_cache();
    test_gc_policy();   /* t39: GC-транзит Фаза 2 (рой audit_t38) */
    test_gc_hello();    /* t42v10: автомат ClientHello-pump на дублях */
    test_cl();          /* 41e-a: connectionless v1 (классификация/фильтр) */
    test_fini2();       /* t36/audit05: контракт FINI/FINI2 (ранее был НЕ зарегистрирован) */
#ifndef C2B_ST_NO_DETOUR
    test_detour();
    test_detour2();
#else
    printf("[i] detour/detour2 skipped: self-modifying code under sanitizers\n");
#endif
    printf("\n%s (%d failures)\n", fails ? "FAILED" : "PASSED", fails);
    return fails ? 1 : 0;
}
#endif /* C2B_SELFTEST */
