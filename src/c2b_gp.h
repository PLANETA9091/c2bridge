/* c2b_gp.h — v51: GOT-PATCH — перенаправление send-слотов ПРИВАТНЫХ копий
 * libsteamnetworkingsockets.so / steamclient.so (dlmopen-ns) в хуки моста.
 *
 * КОНТЕКСТ (elimination matrix runs 392-396, 20:39-раунд):
 *  - 0x22-класс движка = НЕ ДОСТИЖИМ ни одним libc-PLT интерпозингом
 *    (sendto любой addr/family, sendmsg любой iovlen, send, write,
 *    syscall-сайты, сырые syscall'ы, AF_PACKET, вторые процессы/бинды —
 *    ВСЁ закрыто, rewrites = 0 при живом crt-cap).
 *  - МЕХАНИЗМ НАЗВАН: dlmopen-ns — движок грузит СТЕАМОВСКИЙ
 *    steamclient.so ('/home/runner/.local/share/Steam/linux64/') в
 *    ОТДЕЛЬНОЕ пространство имён; его зависимости (включая вторую
 *    libsteamnetworkingsockets.so) резолвятся в НОВОЙ ns => LD_PRELOAD
 *    моста там НЕ ВИДЕН => отправитель 0x20/0x22 = невидим.
 *
 * V51-ХОД (ledger-план 20:39, пункт ii): ГОН-патч — /proc/self/maps ->
 * все сопоставления libsteamnetworkingsockets + steamclient.so -> ELF-
 * прогулка В ПАМЯТИ через безопасный pread(/proc/self/mem) (v4.3-урок:
 * модуль может анмапиться — прямые разыменования запрещены house-style):
 * Ehdr -> PT_DYNAMIC -> DT_JMPREL/.rela.plt -> R_X86_64_JUMP_SLOT ->
 * DT_SYMTAB/DT_STRTAB имена -> слоты sendto/sendmsg/send/write ->
 * ПЕРЕЗАПИСЬ на адреса ХУКОВ моста. Слоты приватной копии указывали в
 * приватную libc (не хуки) => перезапись = фактический перехват; слоты
 * главной копии УЖЕ указывают на хуки (LD_PRELOAD) => 'already' = дешё-
 * вый дискриминатор ns-копий. Запись = pwrite(/proc/self/mem) (self-
 * доступ, yama не мешает, прот страницы не важен); фолбэк = mprotect
 * RW + прямая запись (RW-GOT оставить = легально, lazy живёт).
 *
 * ПОСЛЕДСТВИЕ: все исходящие кадры приватной копии (0x20 hello, 0x22
 * ConnectRequest, пробы) ВХОДЯТ в те же хуки, что уже гоняют legacy-
 * лан движка (baseline run392-396 = незломанный) => crt-механизм v50
 * (капчер серта + rewrite [22][4c 00] -> принятая форма) ФИНАЛЬНО
 * получает свои фреймы.
 *
 * ОЖИДАЕМЫЙ ИСХОД run (дерево 20:39 без изменений): (а) 0x23 ConnectOK
 * К :27005 = ВЕХА -> шифростадия = v52 (экспорт ed25519-приватника из
 * кучи steamclient по пабкичу серта); (б) 0x24 named-reject = требование
 * названо; (в) тишина = релей требует crypto-подпись ДО ответа => v52 =
 * подпись в c2b_crt_build; (г) rewrites снова 0 = отправитель ВООБЩЕ не
 * через PLT (raw-syscall в приватной копии — там аудит не проводился)
 * => v52 = /proc/net/udp-аудит + strace-in-artifact.
 *
 * АРХ: x86-64 only (ELF64 оффсеты; i386-сборка = весь хедер пуст).
 * ГЕЙТ: C2B_GOTPATCH=1 (armed-класс: меняет чужие GOT). Триггер = свин-
 * ячки-сайты sendto/recvfrom хуков (rate 2с, кап 256 сканов, busy-гвард
 * __sync). Лог-маркеры: '[c2b] v51: mod ...' (дискавери, once/base),
 * '[c2b] v51 gp: sym=... slot=... old=...' (патч), '[c2b] v51: scan #...'
 * (сводка). */
#ifndef C2B_GP_H
#define C2B_GP_H

#if defined(__x86_64__)

/* ---------- чистые хелперы (selftest-ируемые) ---------- */

/* hex-нибл; 0xff = не-хекс */
static inline unsigned int c2b_gp_nib(unsigned char c)
{
    if (c >= '0' && c <= '9') return (unsigned int)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (unsigned int)(c - 'A' + 10);
    return 0xffu;
}

/* 64-бит hex в лог (C2B_LOGH = 32-битный; адреса = 64) */
static inline void c2b_gp_lh64(unsigned long long v)
{
    char b[20];
    unsigned int i;
    b[0] = '0'; b[1] = 'x';
    for (i = 0; i < 16u; i++)
        b[2 + i] = (char)("0123456789abcdef"[(v >> ((15 - i) * 4)) & 0xf]);
    b[18] = ' '; b[19] = 0;
    C2B_LOGS(b);
}

/* символьный фильтр: 1=sendto 2=sendmsg 3=send 4=write; 0 = чужое
 * (индекс = хук-слот hooks[]; writev/sendmmsg НЕ импортируются ни одной
 * либой = elimination matrix — не перехватываем) */
static inline int c2b_gp_sym_want(const char *s)
{
    if (!s) return 0;
    if (s[0]=='s'&&s[1]=='e'&&s[2]=='n'&&s[3]=='d'&&s[4]=='t'&&s[5]=='o'&&s[6]==0)
        return 1;
    if (s[0]=='s'&&s[1]=='e'&&s[2]=='n'&&s[3]=='d'&&s[4]=='m'&&s[5]=='s'&&
        s[6]=='g'&&s[7]==0)
        return 2;
    if (s[0]=='s'&&s[1]=='e'&&s[2]=='n'&&s[3]=='d'&&s[4]==0)
        return 3;
    if (s[0]=='w'&&s[1]=='r'&&s[2]=='i'&&s[3]=='t'&&s[4]=='e'&&s[5]==0)
        return 4;
    return 0;
}

/* подстрока без libc */
static inline int c2b_gp_has_sub(const char *s, unsigned int n, const char *t)
{
    unsigned int i, j;
    if (!s || !t) return 0;
    for (i = 0; i < n; i++) {
        for (j = 0; t[j]; j++)
            if (i + j >= n || s[i + j] != t[j]) break;
        if (!t[j]) return 1;
    }
    return 0;
}

/* путь: 1 = libsteamnetworkingsockets* (обе ns-копии), 2 = steamclient.so
 * (стимовский dlmopen-груз; GNS может быть статически внутри!), 0 = чужое */
static inline int c2b_gp_path_want(const char *path, unsigned int len)
{
    if (!path || !len) return 0;
    if (c2b_gp_has_sub(path, len, "libsteamnetworkingsockets")) return 1;
    if (c2b_gp_has_sub(path, len, "steamclient.so")) return 2;
    return 0;
}

/* "lo-hi" из maps-строки; возврат = съеденных символов (0 = фейл) */
static inline unsigned int c2b_gp_lohi(const char *p, unsigned long *lo,
                                       unsigned long *hi)
{
    unsigned long v = 0;
    unsigned int k, d, k1;
    if (!p || !lo || !hi) return 0;
    for (k = 0; k < 16u; k++) {
        d = c2b_gp_nib((unsigned char)p[k]);
        if (d == 0xffu) break;
        v = (v << 4) | (unsigned long)d;
    }
    if (!k || p[k] != '-') return 0;
    *lo = v;
    k1 = k;
    p += k + 1;
    v = 0;
    for (k = 0; k < 16u; k++) {
        d = c2b_gp_nib((unsigned char)p[k]);
        if (d == 0xffu) break;
        v = (v << 4) | (unsigned long)d;
    }
    if (!k) return 0;
    *hi = v;
    return k1 + 1u + k;                 /* точный расход строки */
}

/* проты "rwx..." -> биты r=1 w=2 x=4 (до пробела/конца, кап 7) */
static inline unsigned int c2b_gp_prot(const char *p, unsigned int n)
{
    unsigned int i, b = 0;
    if (!p) return 0;
    for (i = 0; i < n && i < 7u; i++) {
        if (p[i] == ' ') break;
        if (p[i] == 'r') b |= 1u;
        else if (p[i] == 'w') b |= 2u;
        else if (p[i] == 'x') b |= 4u;
    }
    return b;
}

/* слот-санити: в (base, end-8), выровнен на 8 */
static inline int c2b_gp_slot_ok(unsigned long slot, unsigned long base,
                                 unsigned long end)
{
    if (end <= base + 64ul) return 0;
    if (slot <= base) return 0;
    if (slot >= end - 8ul) return 0;
    if (slot & 7ul) return 0;
    return 1;
}

/* parse maps-строки: lo/hi/prot/off/path/plen + linelen (с '\n').
 * Формат: lo-hi perms offset dev inode [path]\n. path = от первого '/'
 * (в perms/offset/dev/inode '/' не встречается). 1 = ок. */
static inline int c2b_gp_line(const char *p, unsigned int cap,
                              unsigned long *lo, unsigned long *hi,
                              unsigned int *prot, unsigned long *off,
                              const char **path, unsigned int *plen,
                              unsigned int *linelen)
{
    const char *q, *pend;
    unsigned int k, z;
    if (!p || !lo || !hi || !prot || !off || !path || !plen || !linelen)
        return 0;
    *path = 0; *plen = 0; *prot = 0; *off = 0;
    for (z = 0; z < cap; z++)
        if (p[z] == '\n') break;
    *linelen = (z < cap) ? z + 1u : cap;
    pend = p + z;                       /* до '\n' (или конца буфера) */
    k = c2b_gp_lohi(p, lo, hi);
    if (!k) return 0;
    q = p + k;
    while (q < pend && *q == ' ') q++;
    *prot = c2b_gp_prot(q, (unsigned int)(pend - q));
    while (q < pend && *q != ' ') q++;
    while (q < pend && *q == ' ') q++;
    {   unsigned long v = 0;
        unsigned int d;
        for (z = 0; z < 16u && q < pend; z++) {
            d = c2b_gp_nib((unsigned char)*q);
            if (d == 0xffu) break;
            v = (v << 4) | (unsigned long)d;
            q++;
        }
        *off = v;
    }
    {   const char *r;
        for (r = q; r < pend; r++)
            if (*r == '/') { *path = r; *plen = (unsigned int)(pend - r); break; }
    }
    return 1;
}

/* ---------- ELF64-константы (рукописные оффсеты, house-style) ---------- */
#define C2B_GP_PT_DYNAMIC   2u
#define C2B_GP_DT_NULL      0u
#define C2B_GP_DT_PLTRELSZ  2u
#define C2B_GP_DT_STRTAB    5u
#define C2B_GP_DT_SYMTAB    6u
#define C2B_GP_DT_JMPREL    23u
#define C2B_GP_R_JUMP_SLOT  7u

/* Прогулка одного модуля + патч слотов. ВСЕ чтения = pread(/proc/self/mem)
 * (v4.3: 0-краш на невалидных адресах). Патч = pwrite (self-доступ; прот
 * страницы не важен); фолбэк = mprotect RW + прямая запись (RW-GOT оста-
 * вить = легально: lazy-резолюция других слотов живёт, GOT[0..2] мы не
 * трогаем). r_offset в .rela.plt = vaddr слота ОТНОСИТЕЛЬНО base (x86-64
 * ABI: ld.so применяет l_addr + r_offset) => slot = base + r_offset.
 * d_ptr динамических записей ПОСЛЕ ld.so = АБСОЛЮТНЫЙ (glibc x86-64 кор-
 * ректирует d_ptr += l_addr in-place); страховка: значение < base => это
 * нескорректированный vaddr => + base.
 * hooks[1..4] = адреса хуков (1=sendto 2=sendmsg 3=send 4=write).
 * quiet: 1 = не логировать 'already'-слоты (ресканы; патчи логируются
 * всегда). Возврат: 1 = пройден; 0 = нет PT_DYNAMIC/JMPREL (нечего де-
 * лать); <0 = структурный фейл (-1 pread, -2 magic, -3 phdr, -4 dyn). */
static int c2b_gp_patch_module(int mfd, unsigned long base, unsigned long end,
                               const unsigned long hooks[5],
                               unsigned int quiet,
                               unsigned int *patched, unsigned int *alread,
                               unsigned int *skipn)
{
    /* pread/pwrite/mprotect = файловые декларации: .so — блок extern
     * c2bridge.c (pread/pwrite/mprotect), selftest — unistd.h/sys/mman.h
     * (блок-скоуп extern здесь = конфликт типов с libc-хедерами — probe-
     * урок 22:09-раунда; g24-паттерн живёт только в .so-режиме). */
    unsigned char hdr[0x400];
    unsigned char phb[32u * 56u];
    unsigned char dynb[512u * 16u];
    unsigned char sbuf[64];
    unsigned long phoff, dynva = 0, strtab = 0, symtab = 0, jmprel = 0, relsz = 0;
    unsigned int phentsize, phnum, i;
    long long rn;
    if (!patched || !alread || !skipn) return -1;
    rn = pread(mfd, hdr, sizeof hdr, base);
    if (rn != (long long)sizeof hdr) return -1;
    if (hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F')
        return -2;
    if (hdr[4] != 2 /*ELFCLASS64*/ || hdr[5] != 1 /*ELFDATA2LSB*/) return -2;
    phoff     = *(const unsigned long *)(hdr + 0x20);
    phentsize = *(const unsigned short *)(hdr + 0x36);
    phnum     = *(const unsigned short *)(hdr + 0x38);
    if (phentsize < 56u || !phnum) return -3;
    if ((unsigned long)phnum * phentsize > sizeof phb)
        phnum = (unsigned short)(sizeof phb / phentsize);
    rn = pread(mfd, phb, (unsigned long)phnum * phentsize, base + phoff);
    if (rn != (long long)((unsigned long)phnum * phentsize)) return -3;
    for (i = 0; i < phnum; i++) {
        const unsigned char *ph = phb + (unsigned long)i * phentsize;
        if (*(const u32 *)(ph + 0) == C2B_GP_PT_DYNAMIC) {
            dynva = *(const unsigned long *)(ph + 0x10);
            break;
        }
    }
    if (!dynva) return 0;
    rn = pread(mfd, dynb, sizeof dynb, base + dynva);
    if (rn < 16) return -4;
    for (i = 0; i < (unsigned int)(rn / 16u); i++) {
        unsigned long tag = *(const unsigned long *)(dynb + (unsigned long)i * 16u);
        unsigned long val = *(const unsigned long *)(dynb + (unsigned long)i * 16u + 8u);
        if (tag == C2B_GP_DT_NULL) break;
        if (tag == C2B_GP_DT_STRTAB) strtab = val;
        else if (tag == C2B_GP_DT_SYMTAB) symtab = val;
        else if (tag == C2B_GP_DT_JMPREL) jmprel = val;
        else if (tag == C2B_GP_DT_PLTRELSZ) relsz = val;
    }
    if (!jmprel || !relsz || !symtab || !strtab) return 0;
    strtab = strtab >= base ? strtab : strtab + base;
    symtab = symtab >= base ? symtab : symtab + base;
    jmprel = jmprel >= base ? jmprel : jmprel + base;
    if (relsz > 8192ul) relsz = 8192ul;         /* кап ~340 слотов */
    for (i = 0; i < (unsigned int)(relsz / 24ul); i++) {
        unsigned char rb[24];
        unsigned long r_off, r_info, slot, old;
        unsigned int symidx, sid;
        u32 stname;
        if (pread(mfd, rb, 24, jmprel + 24ul * i) != 24) break;
        r_off  = *(const unsigned long *)(rb + 0);
        r_info = *(const unsigned long *)(rb + 8);
        if ((r_info & 0xfffffffful) != C2B_GP_R_JUMP_SLOT) continue;
        symidx = (unsigned int)(r_info >> 32);
        if (!symidx) continue;
        {   unsigned char sb[24];
            if (pread(mfd, sb, 24, symtab + 24ul * symidx) != 24) continue;
            stname = *(const u32 *)(sb + 0);
        }
        if (pread(mfd, sbuf, sizeof sbuf - 1u, strtab + stname) < 1) continue;
        sbuf[sizeof sbuf - 1u] = 0;
        sid = (unsigned int)c2b_gp_sym_want((const char *)sbuf);
        if (!sid) continue;
        slot = base + r_off;
        if (!c2b_gp_slot_ok(slot, base, end)) { (*skipn)++; continue; }
        if (pread(mfd, &old, 8, slot) != 8) { (*skipn)++; continue; }
        if (old == hooks[sid]) {
            (*alread)++;
            if (!quiet) {
                C2B_LOGS("[c2b] v51 gp: sym="); C2B_LOGS((const char *)sbuf);
                C2B_LOGS("slot="); c2b_gp_lh64(slot);
                C2B_LOGS("already\n");
            }
            continue;
        }
        {   long long wr = pwrite(mfd, &hooks[sid], 8, slot);
            if (wr != 8) {
                unsigned long pg = slot & ~0xffful;
                if (mprotect((void *)pg, 0x1000u, 0x3 /*RW*/) != 0) {
                    (*skipn)++;
                    continue;
                }
                *(volatile unsigned long *)slot = hooks[sid];
                C2B_LOGS("[c2b] v51 gp: sym="); C2B_LOGS((const char *)sbuf);
                C2B_LOGS("slot="); c2b_gp_lh64(slot);
                C2B_LOGS("old="); c2b_gp_lh64(old);
                C2B_LOGS("fb\n");
            } else {
                C2B_LOGS("[c2b] v51 gp: sym="); C2B_LOGS((const char *)sbuf);
                C2B_LOGS("slot="); c2b_gp_lh64(slot);
                C2B_LOGS("old="); c2b_gp_lh64(old);
                C2B_LOGS("\n");
            }
        }
        (*patched)++;
    }
    return 1;
}

#endif /* __x86_64__ */
#endif /* C2B_GP_H */
