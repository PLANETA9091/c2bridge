/* c2b_raw.h — v75: RAW-SYSCALL SEND INTERCEPT — патч raw-syscall стабов
 * sendto/sendmsg в ФАЙЛ-БЭКЕД модулях движка/стима (GNS/steamclient/csgo-
 * lite) с редиректом в хуки моста.
 *
 * КОНТЕКСТ (run468-форензика, 22:39-раунд — ПОСЛЕДНЕЕ ЗВЕНО цепочки):
 *  - tracefs_send.log (52145 записей, 0 переполнений): csgo_linux64 шлёт
 *    RAW sys_sendto len:0x200 x41 + len:0x201 x31 (fd 0x29 = СОКЕТ
 *    ДВИЖКА 0.0.0.0:27005, треды 16536/16504/16552/16800/16803) — это
 *    НАТИВНЫЕ GNS-кадры движка. pcap байт-в-байт: [20][10 00] x40
 *    (hello) + [22][4c 00] x40 (connect, 1:1 интерлив = retry-цикл GNS)
 *    + [24][47 00] x2 + ff×4 513B x62 + 80a5db/81a5db (SNP-сессия
 *    моста) — И ВСЁ это НАПРАВЛЯЕТСЯ НА РЕАЛЬНЫЙ СЕРВЕР
 *    (152.233.19.133:28022)! Ледер-заметка 2209 ':27005' = ИСТОЧНИК-порт
 *    (клиентский порт движка), НЕ адресат.
 *  - => движок ВСЮ ЖИЗНЬ ПРОЕКТА сам стучится в реальный сервер своей
 *    GNS-лалой, МИМО всех хуков (raw-syscall стабы внутри модулей).
 *    v74-crt-rewrite = мёртвый код НЕ потому что 'кадры не проходят
 *    хук' вообще, а потому что raw-стабы МИНУЮТ libc/PLT/GOT: v51
 *    (GOT 8 слотов = все уже указывают на хуки, НО не используются
 *    для 0x22), v52 (libc-прологи), v53 (anon-r-x/exe/eng — файл-бэ-
 *    кед steam/GNS ПОПУТНО ИСКЛЮЧЕНЫ 'v51-аудитом закрыты'), v55/v57
 *    (tracefs-мисаттрибуция run403 исправлена в 55b, но класс стабов
 *    в ФАЙЛ-БЭКЕД модулях так и не сканировался).
 *  - ФИКС v75: скан r-x регионов с путём steam/csgo (libsteamnetwork-
 *    ingsockets.so, steamclient.so, csgo-lite/bin/...) -> стабы
 *      b8 2c 00 00 00 0f 05            mov eax,44(sendto); syscall
 *      b8 2e 00 00 00 0f 05            mov eax,46(sendmsg); syscall
 *      48 c7 c0 <nr> 00 00 00 0f 05    mov rax,nr; syscall (форма B)
 *    + хвост-гвард p[plen]==0xc3 (ret = канонический хвост стаба =
 *    отсекает мид-инструкшн ложняки) -> трамплин 'mov rcx,r10' (ядро
 *    АБИ: 4-й арг флагов в r10; C АБИ = rcx; rcx/r11 = колонные регистры
 *    syscall = коллер их не хранит) + movabs fn + jmp rax -> e9 rel32 +
 *    90 90 на сайте (7/9 байт хватает). sendmsg (3 аргс) = АБИ-идентич-
 *    но, фиксапа r10 не нужно. Возврат = rax как у syscall.
 *  - ЭНТРИ-пойнты c2b_raw_st_entry/c2b_raw_sm_entry = g_raw_tls=1 ->
 *    НАШ хук sendto/sendmsg (crt-класс отработает там сам) -> g_raw_tls=0.
 *    В sendto-хуке: ветка 'if (g_raw_tls)' ПОСЛЕ crt-блока = census +
 *    passthrough МИМО CLV2-классифаера (сырые ff×4-блобы/hello/ A2S
 *    движка = классы, которые классифаер НЕ ТРОГАЕТ; qconnect-транс-
 *    форм/бейты = движение чужих кадров = ЗАПРЕЩЕНО на сырой лане).
 *    sendmsg-хук = НЕ трогаем (tail = ноты + passthrough, crt уже там).
 *  - ОЖИДАЕМЫЕ ИСХОДЫ run (дерево): (а) sites>0 + PATCH + 'v75: raw'
 *    census + crt-fix rewrite на нативной 0x22 -> сервер 0x23 к сокету
 *    движка (тот же egress IP, ответ придёт NAT'ом на fd 0x29) = ВЕХА:
 *    GNS-сессия ДВИЖОК<->СЕРВЕР живая, signon нативный; (б) 0x24
 *    named-reject (g131) = требование названо (cold-chal/cert); (в)
 *    тишина = chal-гейт (движок шлёт [20]-hello x40 БЕЗ ответа 0x21 —
 *    почему сервер молчит на hello = следующий RE); (г) crash/дестаб
 *    = killswitch C2B_GPR=0 через dispatch-инпут gpr.
 *
 * ЧИСТЫЕ функции = selftest-ируемые; живой скан/патч = c2bridge.c
 * (.so-only, гейт C2B_GPR=1 — MODES/dispatch = дефолт '1', откат = '0').
 */
#ifndef C2B_RAW_H
#define C2B_RAW_H

/* pure: fixed-form стаб sendto(44)/sendmsg(46) на p.
 * Форма A (7B): b8 <nr> 00 00 00 0f 05 (mov eax,nr; syscall)
 * Форма B (9B): 48 c7 c0 <nr> 00 00 00 0f 05 (mov rax,nr; syscall)
 * Возврат = длина паттерна (7/9), *nr = 44/46; 0 = мимо. */
static u32 c2b_raw_pat(const u8 *p, u32 n, u32 *nr)
{
    if (!p || !nr) return 0;
    *nr = 0;
    if (n >= 7u && p[0] == 0xb8u && p[2] == 0u && p[3] == 0u &&
        p[4] == 0u && p[5] == 0x0fu && p[6] == 0x05u &&
        (p[1] == 44u || p[1] == 46u)) {
        *nr = (u32)p[1];
        return 7u;
    }
    if (n >= 9u && p[0] == 0x48u && p[1] == 0xc7u && p[2] == 0xc0u &&
        p[4] == 0u && p[5] == 0u && p[7] == 0x0fu && p[8] == 0x05u &&
        (p[3] == 44u || p[3] == 46u)) {
        *nr = (u32)p[3];
        return 9u;
    }
    return 0u;
}

/* pure: патч-пригодность = паттерн + ret-хвост сразу после стаба
 * (b8-формы: стаб = хвост обёртки '...; syscall; ret'). Отсекает
 * мид-инструкшн совпадения (данные/другой поток инструкций). */
static u32 c2b_raw_patchable(const u8 *p, u32 n, u32 *nr)
{
    u32 pl = c2b_raw_pat(p, n, nr);
    if (!pl || n < pl + 1u || p[pl] != 0xc3u) return 0u;
    return pl;
}

/* pure: байты трамплина (16B, пад 0x90). sendto (ядро АБИ: rdi/rsi/rdx/
 * r10/r8/r9 -> C АБИ rdi/rsi/rdx/rcx/r8/r9): 4c 89 d1 = mov rcx,r10;
 * 48 b8 <imm64> = movabs rax,fn; ff e0 = jmp rax. sendmsg (3 аргс =
 * АБИ-идентично): без mov rcx,r10. rax = возврат (как syscall). */
static u32 c2b_raw_tramp(u8 *t, u32 cap, unsigned long long fn, u32 nr)
{
    u32 i = 0, q;
    if (!t || cap < 16u) return 0;
    if (nr == 44u) { t[i++] = 0x4cu; t[i++] = 0x89u; t[i++] = 0xd1u; }
    else if (nr != 46u) return 0;
    t[i++] = 0x48u; t[i++] = 0xb8u;
    for (q = 0; q < 8u; q++) t[i + q] = (u8)((fn >> (q * 8u)) & 0xffu);
    i += 8u;
    t[i++] = 0xffu; t[i++] = 0xe0u;
    while (i < 16u) t[i++] = 0x90u;
    return i;
}

/* pure: rel32 от site до tramp (e9-таргет = site+5). 0 = вне +/-2GB
 * (реальный 0 = tramp==site+5 = невозможно для свежей anon-страницы). */
static i32 c2b_raw_rel32(unsigned long long site, unsigned long long tramp)
{
    long long d;
    if (tramp < site + 5ull) {
        d = -(long long)((site + 5ull) - tramp);
    } else {
        d = (long long)(tramp - (site + 5ull));
    }
    if (d > 2147483647ll || d < -2147483648ll) return 0;
    return (i32)d;
}

/* pure: подстрока в буфере фикс. длины (0 = мимо). */
static i32 c2b_raw_has(const char *s, u32 n, const char *t)
{
    u32 i, j, m = 0u;
    if (!s || !t) return 0;
    while (t[m]) m++;
    if (m == 0u || n < m) return 0;
    for (i = 0u; i + m <= n; i++) {
        for (j = 0u; j < m && s[i + j] == t[j]; j++) { }
        if (j == m) return 1;
    }
    return 0;
}

/* pure: фильтр путей r-x регионов. 1 = СКАНИРОВАТЬ. Классы: steam/csgo
 * (libsteamnetworkingsockets*, steamclient.so, csgo-lite/...), минус
 * система (libc/ld/pthread), минус наш собственный .so (точное совпа-
 * дение пути из dladdr — ПУТЬ РЕПО СОДЕРЖИТ 'c2bridge' (work/
 * c2bridge/c2bridge/), поэтому НЕ подстрокой!), минус псевдо-пути
 * ([vdso]/[vvar] — нет '/'). */
static i32 c2b_raw_path_want(const char *p, u32 n, const char *self,
                             u32 selfn)
{
    if (!p || !n) return 0;
    if (p[0] == '[') return 0;
    if (c2b_raw_has(p, n, "libc.so") || c2b_raw_has(p, n, "libc-") ||
        c2b_raw_has(p, n, "/ld-linux") || c2b_raw_has(p, n, "/ld-2.") ||
        c2b_raw_has(p, n, "libpthread")) return 0;
    if (self && selfn && n == selfn) {
        u32 i;
        for (i = 0u; i < n && p[i] == self[i]; i++) { }
        if (i == n) return 0;               /* наш собственный .so */
    }
    if (c2b_raw_has(p, n, "steam") || c2b_raw_has(p, n, "csgo")) return 1;
    return 0;
}

#endif /* C2B_RAW_H */
