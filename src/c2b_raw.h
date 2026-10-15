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

/* v77 pure: патч-пригодность СИСТЕМНОГО (glibc) стаба. Хвост libc-стаба
 * = НЕ ret, а каноничный errno-чек '48 3d 00 f0 ff ff' (cmp $-4096,%rax)
 * + jae — форма байт-строгая = FP-доказательство. run474-вердикт: 4x
 * nr=0x2c стаба в mod=sys lib'ax, 3 НЕ вооружены (v52 = только
 * dlsym-канонический entry), отправитель нативных кадров = один из них. */
static u32 c2b_raw_patchable_sys(const u8 *p, u32 n, u32 *nr)
{
    u32 pl = c2b_raw_pat(p, n, nr);
    if (!pl || n < pl + 6u) return 0u;
    if (p[pl] != 0x48u || p[pl + 1u] != 0x3du || p[pl + 2u] != 0x00u ||
        p[pl + 3u] != 0xf0u || p[pl + 4u] != 0xffu || p[pl + 5u] != 0xffu)
        return 0u;
    return pl;
}

/* v77 pure: СИСТЕМНЫЙ класс путей — определение НИЖЕ (после c2b_raw_has;
 * вынесено из этого места = ошибка порядка 20261015-0039-раунда). */

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

/* v77c pure: ХВОСТ-дискриминатор СИСТЕМНОГО стаба. run476-РАЗБОР: у libc
 * обёрток send/sendto/sendmsg ДВА стаба каждый — хвостовой (fast-путь:
 * ...; стаб; cmp -4096; ja; RET = хвост функции, [rsp] = адрес возврата
 * коллера -> e9 на C-энтри = корректный tail-call) и СЕРЕДИННЫЙ (full-путь
 * асинк-отмены: call enable_asynccancel; стаб; cmp; ja; mov edi,ebx;...
 * leave; ret — кадр АКТИВЕН, rsp = rbp-0x30, [rsp] = ЛОКАЛ -> e9 на C-энтри
 * = ret pops МУСОР = rip=1 (run475/476 = детерминированный SEGV)).
 * Движок многопоточный (__libc_single_threaded=0) => HOT = ИМЕННО full-путь
 * => хвост-стабы никогда не исполняются, середина = боевые.
 * Хвост = стаб + 48 3d 00 f0 ff ff (cmp) + 77 ?? (ja disp8) + c3 (ret).
 * Возврат = pl (7), 0 = не хвост (=> мид-сайт -> трамплин-санка). */
static u32 c2b_raw_patchable_sys_tail(const u8 *p, u32 n, u32 *nr)
{
    u32 pl = c2b_raw_patchable_sys(p, n, nr);
    if (!pl) return 0u;
    if (n < pl + 9u) return 0u;
    /* p[pl..pl+5] = 48 3d 00 f0 ff ff — уже проверено patchable_sys;
     * здесь строго: 77 <disp8> c3 */
    if (p[pl + 6u] != 0x77u || p[pl + 8u] != 0xc3u) return 0u;
    return pl;
}

/* v82c pure: ТОЛЕРАНТНАЯ форма СИСТЕМНОГО стаба — НЕ-СМЕЖное окно:
 *   b8 <nr> 00 00 00 [gap 0..15B: перезагрузки регистров 48/4c/44/41 8b
 *   ...] 0f 05 48 3d 00 f0 ff ff
 * РЕАЛЬНЫЙ КЛАСС (run487-libc.node.so sendto@@GLIBC+0x55 = 0x12c375):
 *   b8 2c 00 00 00 48 8b 55 d8 48 8b 75 e0 0f 05 48 3d 00 f0 ff ff 77 34
 *   (mov $44,%eax; mov -0x28(%rbp),%rdx; mov -0x20(%rbp),%rsi; syscall;
 *    cmp $-4096,%rax; ja) — ГОРЯЧИЙ путь многопоточного процесса
 *   (__libc_single_threaded=0), v77c-смежный скан = ПРОПУСТИЛ его
 *   (0x12c330 = холодное смежное окно запатчено, горячее = raw syscall
 *   мимо ВСЕХ хуков = ноль rewrite в runs 486/487).
 * КЛАСС САЙТА = СЕРЕДИНА (кадр активен: sub rsp + call до окна, эпилог
 * = leave; ret) => патч = ТОЛЬКО санка (v77c-контракт, back = site+len).
 * Гвард против FP: (а) nr строго 44/46; (б) gap = ТОЛЬКО байты переза-
 * грузок mov r64,[rbp-x]/mov r64,reg (префикс 48/4c/44/41 + 8b/89), БЕЗ
 * 0f (syscall), БЕЗ c3 (ret), БЕЗ e8/e9 (call/jmp); (в) errno-якорь
 * 48 3d 00 f0 ff ff СТРОГО после syscall. Возврат = ПОЛНАЯ длина окна
 * (mov..syscall, 7..22), 0 = мимо. */
static u32 c2b_raw_pat_gap(const u8 *p, u32 n, u32 *nr)
{
    u32 k, gap;
    if (!p || !nr || n < 16u) return 0u;
    *nr = 0;
    if (p[0] != 0xb8u || p[2] != 0u || p[3] != 0u || p[4] != 0u ||
        (p[1] != 44u && p[1] != 46u))
        return 0u;
    *nr = (u32)p[1];
    /* gap: до 15 байт перезагрузок до syscall */
    for (k = 5u; k < 20u && k < n; ) {
        u8 b = p[k];
        if (b == 0x0fu) {                       /* syscall */
            gap = k - 5u;
            if (k + 1u >= n || p[k + 1u] != 0x05u) return 0u;
            k += 2u;
            /* errno-якорь строго после syscall */
            if (n < k + 6u || p[k] != 0x48u || p[k + 1u] != 0x3du ||
                p[k + 2u] != 0x00u || p[k + 3u] != 0xf0u ||
                p[k + 4u] != 0xffu || p[k + 5u] != 0xffu)
                return 0u;
            return 5u + gap + 2u;               /* mov..syscall */
        }
        if (b == 0xc3u || b == 0xe8u || b == 0xe9u || b == 0xebu)
            return 0u;                          /* ret/call/jmp в гэпе = мимо */
        /* перезагрузка: префикс 48/4c/44/41/45/49/4d + 8b/89 (+ modrm/disp) */
        if ((b == 0x48u || b == 0x4cu || b == 0x44u || b == 0x41u ||
             b == 0x45u || b == 0x49u || b == 0x4du) &&
            k + 1u < n && (p[k + 1u] == 0x8bu || p[k + 1u] == 0x89u)) {
            u8 modrm = (k + 2u < n) ? p[k + 2u] : 0u;
            u32 len = 2u;                       /* prefix + opcode */
            u8 mod = (u8)(modrm >> 6);
            len += 1u;                          /* modrm */
            if (mod == 1u) len += 1u;           /* disp8 */
            else if (mod == 2u) len += 4u;      /* disp32 */
            if (mod == 0u && (modrm & 0xc7u) == 0x05u) len += 4u; /* rip-rel */
            k += len;
            continue;
        }
        return 0u;                              /* чужой байт в гэпе = мимо */
    }
    return 0u;
}

/* v77c pure: САНКА мид-сайта (регистро-сохраняющая, БЕЗ кадра).
 * Контракт на входе: rsp кратно 16 (проверено: __send rbp-0x30, sendmsg
 * rbp-0x20 — оба кратно 0 mod 16); живы kernel-арги rdi/rsi/rdx/r10/r8/r9
 * (sendmsg: r8 = cancel-type — НЕ арг!), rbx/rbp/r12-15 = кадр обёртки.
 * Санка: сэйв 6 аргов -> вызов C-хелпера (C АБИ: 5 аргов в регах, rax:rdx
 * = struct из 2 qword) -> перезагрузка fd/buf/flags/addr/addrlen ->
 * mov eax,nr; syscall (в самой санке; rcx/r11 = колонные — пост-код их
 * не читает) -> ВОССТАНОВЛЕНИЕ r8 (cancel-type sendmsg!) -> jmp site+7.
 * Пост-стаб код читает ТОЛЬКО rax/rbx/rbp/rsp/r8 (+память rbp-0x18).
 * rbx/rbp/r12-15 сохраняет САМ хелпер (C АБИ callee-saved).
 * ЛЭЙАУТ (112B, все офсеты фикс. — селфтест байт-строгий):
 *   00: 48 83 ec 40           sub rsp,0x40            (rsp: 0->0 mod 16)
 *   04: 48 89 3c 24           mov [rsp],rdi
 *   08: 48 89 74 24 08        mov [rsp+8],rsi         (disp8! без disp = [rsp])
 *   0d: 48 89 54 24 10        mov [rsp+0x10],rdx      (disp8! УРОК: 48 89 34/14 24
 *                              = БЕЗ disp = ТОТ ЖЕ [rsp] — слот rdi затирается,
 *                              fd в хелпер = len (харнесс v77c, run-класс))
 *   12: 4c 89 54 24 18        mov [rsp+0x18],r10
 *   17: 4c 89 44 24 20        mov [rsp+0x20],r8
 *   1c: 4c 89 4c 24 28        mov [rsp+0x28],r9
 *   21: 48 8b 3c 24           mov rdi,[rsp]           (arg1 fd)
 *   25: 48 8b 74 24 08        mov rsi,[rsp+8]         (arg2 buf/msg)
 *   2a: 48 8b 54 24 10        mov rdx,[rsp+0x10]      (arg3 len/flags46)
 *   2f: 48 8b 4c 24 18        mov rcx,[rsp+0x18]      (arg4 flags44)
 *   34: 4c 8b 44 24 20        mov r8,[rsp+0x20]       (arg5 addr44)
 *   39: 48 b8 <imm64>         movabs rax,helper       (10B)
 *   43: ff d0                 call rax                (rsp кратно 16 -> C_std)
 *   45: 48 89 c6              mov rsi,rax             (new buf/msg)
 *   48: (rdx = new len/flags — возврат хелпера, уже на месте)
 *   48: 48 8b 3c 24           mov rdi,[rsp]
 *   4c: 4c 8b 54 24 18        mov r10,[rsp+0x18]
 *   51: 4c 8b 44 24 20        mov r8,[rsp+0x20]
 *   56: 4c 8b 4c 24 28        mov r9,[rsp+0x28]
 *   5b: b8 <nr>               mov eax,nr              (5B)
 *   60: 0f 05                 syscall
 *   62: 4c 8b 44 24 20        mov r8,[rsp+0x20]       (RESTORE cancel-type!)
 *   67: 48 83 c4 40           add rsp,0x40
 *   6b: e9 <rel32>            jmp back (site+7 = cmp rax,-4096)
 * Возврат = длина (112), 0 = кап/NULL. rel32 = back - (pg+0x70). */
static u32 c2b_raw_thunk(u8 *t, u32 cap, unsigned long long helper, u32 nr,
                         unsigned long long pg, unsigned long long back)
{
    u32 i = 0, q;
    i32 rel;
    if (!t || cap < 112u || (nr != 44u && nr != 46u)) return 0u;
    /* rel32 от конца jmp (pg+0x70) до back */
    {
        long long d = (long long)(back - (pg + 0x70ull));
        if (d > 2147483647ll || d < -2147483648ll) return 0u;
        rel = (i32)d;
    }
    t[i++] = 0x48u; t[i++] = 0x83u; t[i++] = 0xecu; t[i++] = 0x40u;
    t[i++] = 0x48u; t[i++] = 0x89u; t[i++] = 0x3cu; t[i++] = 0x24u;
    t[i++] = 0x48u; t[i++] = 0x89u; t[i++] = 0x74u; t[i++] = 0x24u;
    t[i++] = 0x08u;                     /* [rsp+8] — disp8 ОБЯЗАТЕЛЕН */
    t[i++] = 0x48u; t[i++] = 0x89u; t[i++] = 0x54u; t[i++] = 0x24u;
    t[i++] = 0x10u;                     /* [rsp+0x10] — disp8 ОБЯЗАТЕЛЕН */
    t[i++] = 0x4cu; t[i++] = 0x89u; t[i++] = 0x54u; t[i++] = 0x24u;
    t[i++] = 0x18u;
    t[i++] = 0x4cu; t[i++] = 0x89u; t[i++] = 0x44u; t[i++] = 0x24u;
    t[i++] = 0x20u;
    t[i++] = 0x4cu; t[i++] = 0x89u; t[i++] = 0x4cu; t[i++] = 0x24u;
    t[i++] = 0x28u;
    t[i++] = 0x48u; t[i++] = 0x8bu; t[i++] = 0x3cu; t[i++] = 0x24u;
    t[i++] = 0x48u; t[i++] = 0x8bu; t[i++] = 0x74u; t[i++] = 0x24u;
    t[i++] = 0x08u;
    t[i++] = 0x48u; t[i++] = 0x8bu; t[i++] = 0x54u; t[i++] = 0x24u;
    t[i++] = 0x10u;
    t[i++] = 0x48u; t[i++] = 0x8bu; t[i++] = 0x4cu; t[i++] = 0x24u;
    t[i++] = 0x18u;
    t[i++] = 0x4cu; t[i++] = 0x8bu; t[i++] = 0x44u; t[i++] = 0x24u;
    t[i++] = 0x20u;
    t[i++] = 0x48u; t[i++] = 0xb8u;
    for (q = 0; q < 8u; q++) t[i + q] = (u8)((helper >> (q * 8u)) & 0xffu);
    i += 8u;
    t[i++] = 0xffu; t[i++] = 0xd0u;
    t[i++] = 0x48u; t[i++] = 0x89u; t[i++] = 0xc6u;
    t[i++] = 0x48u; t[i++] = 0x8bu; t[i++] = 0x3cu; t[i++] = 0x24u;
    t[i++] = 0x4cu; t[i++] = 0x8bu; t[i++] = 0x54u; t[i++] = 0x24u;
    t[i++] = 0x18u;
    t[i++] = 0x4cu; t[i++] = 0x8bu; t[i++] = 0x44u; t[i++] = 0x24u;
    t[i++] = 0x20u;
    t[i++] = 0x4cu; t[i++] = 0x8bu; t[i++] = 0x4cu; t[i++] = 0x24u;
    t[i++] = 0x28u;
    t[i++] = 0xb8u; t[i++] = (u8)(nr & 0xffu); t[i++] = 0u; t[i++] = 0u;
    t[i++] = 0u;
    t[i++] = 0x0fu; t[i++] = 0x05u;
    t[i++] = 0x4cu; t[i++] = 0x8bu; t[i++] = 0x44u; t[i++] = 0x24u;
    t[i++] = 0x20u;
    t[i++] = 0x48u; t[i++] = 0x83u; t[i++] = 0xc4u; t[i++] = 0x40u;
    t[i++] = 0xe9u;
    t[i++] = (u8)((u32)rel & 0xffu);
    t[i++] = (u8)(((u32)rel >> 8) & 0xffu);
    t[i++] = (u8)(((u32)rel >> 16) & 0xffu);
    t[i++] = (u8)(((u32)rel >> 24) & 0xffu);
    if (i != 112u) return 0u;
    return i;
}

/* v83 pure: САНКА С АСМ-ГВАРДОМ (nr44 ТОЛЬКО). РЕАЛЬНЫЙ УРОК run488:
 * безусловная санка на ГОРЯЧЕМ sendto-стабе (0x12c375) = крах старта —
 * С:ЛЮЧАЙНЫЕ ранние/чужие sendto-коллеры (сырые clone-треды с fs=0, пре-
 * д-инициализационный хук-слой) умирали на TLS/getenv/лог-касаниях хел-
 * пера (SEGV addr=0xffffffffffffeab8 = fs-относительный доступ при fs=0,
 * rax=1 = dlsym-fail-сентинел). ФИКС = гвард В САМНЕЙ САНКЕ, чистый asm:
 *   cmp byte [rsi], 0x22      ; 80 3e 22 — только connreq-класс (движковые
 *                             ; 0x22 + мостовые 0x22 = GNS/netcode-треды =
 *                             ; pthreads = fs-валидные) входит в C-слой
 *   v84: test rsi,rsi; je .skip; cmp rdx,40; jb .skip (БУФ = МОЖЕТ БЫТЬ
 *   NULL: run490 = sendto(fd18, NULL, 2) = реальный коллер; len<40 = вне
 *   класса) + cmp [rsi],0x22; jne .skip — весь не-connreq трафик = ЧИСТЫЙ
 *   passthrough (ноль C-касаний = ноль краша)
 * Контракт хелпера/санки = ИДЕНТИЧЕН 112B-версии (rax:rdx = (buf,len)),
 * skip-путь = ВСЕ регистры оригинальные (гвард стоит ДО перезагрузок —
 * rdi/rsi/rdx/r10/r8/r9 не тронуты, reload = те же значения).
 * Лэйаут (0x80 = 128B, v84):
 *  00 sub rsp,0x40 | 04..1c сэйвы rdi/rsi/rdx/r10/r8/r9 (disp8!)
 *  21 test rsi,rsi | 24 je ->58 | 26 cmp rdx,40 | 2a jb ->58
 *  2c cmp [rsi],0x22 | 2f jne ->58
 *  31..48 перезагрузки rdi/rsi/rdx/rcx/r8 | 49 movabs rax,helper
 *  53 call rax | 55 mov rsi,rax
 *  58..6f reload rdi/r10/r8/r9 | 6b mov eax,44 | 70 syscall
 *  72 restore r8 | 77 add rsp,0x40 | 7b e9 rel32 (next = pg+0x80)
 * nr46 = ЗАПРЕЩЁН (rsi = msghdr*, первый байт = не пейлоад — гвард неве-
 * рен): старая 112B-санка. back = site + ПОЛНАЯ длина окна (как v82c). */
static u32 c2b_raw_thunk_gate(u8 *t, u32 cap, unsigned long long helper,
                              unsigned long long pg, unsigned long long back)
{
    u32 i = 0, q;
    i32 rel;
    if (!t || cap < 128u) return 0u;
    {
        long long d = (long long)(back - (pg + 0x80ull));
        if (d > 2147483647ll || d < -2147483648ll) return 0u;
        rel = (i32)d;
    }
    t[i++] = 0x48u; t[i++] = 0x83u; t[i++] = 0xecu; t[i++] = 0x40u;
    t[i++] = 0x48u; t[i++] = 0x89u; t[i++] = 0x3cu; t[i++] = 0x24u;
    t[i++] = 0x48u; t[i++] = 0x89u; t[i++] = 0x74u; t[i++] = 0x24u;
    t[i++] = 0x08u;
    t[i++] = 0x48u; t[i++] = 0x89u; t[i++] = 0x54u; t[i++] = 0x24u;
    t[i++] = 0x10u;
    t[i++] = 0x4cu; t[i++] = 0x89u; t[i++] = 0x54u; t[i++] = 0x24u;
    t[i++] = 0x18u;
    t[i++] = 0x4cu; t[i++] = 0x89u; t[i++] = 0x44u; t[i++] = 0x24u;
    t[i++] = 0x20u;
    t[i++] = 0x4cu; t[i++] = 0x89u; t[i++] = 0x4cu; t[i++] = 0x24u;
    t[i++] = 0x28u;
    /* v84: ПОЛНЫЙ гвард — run490-урок: БУФ МОЖЕТ БЫТЬ NULL (sendto(fd18,
     * NULL, 2) = реальный коллер: rsi=0 => cmp [rsi] = SEGV addr=0) и
     * len < 40 = вне crt-класса. test rsi/je + cmp rdx,40/jb + cmp [rsi]/jne
     * = 16B гварда, .skip = перезагрузка rdi @0x58. */
    t[i++] = 0x48u; t[i++] = 0x85u; t[i++] = 0xf6u;    /* test rsi,rsi */
    t[i++] = 0x74u; t[i++] = 0x32u;                    /* je  -> +0x32 (0x58) */
    t[i++] = 0x48u; t[i++] = 0x83u; t[i++] = 0xfau; t[i++] = 0x28u;
                                                        /* cmp rdx,40 */
    t[i++] = 0x72u; t[i++] = 0x2cu;                    /* jb  -> +0x2c (0x58) */
    t[i++] = 0x80u; t[i++] = 0x3eu; t[i++] = 0x22u;    /* cmp [rsi],0x22 */
    t[i++] = 0x75u; t[i++] = 0x27u;                    /* jne -> +0x27 (0x58) */
    t[i++] = 0x48u; t[i++] = 0x8bu; t[i++] = 0x3cu; t[i++] = 0x24u;
    t[i++] = 0x48u; t[i++] = 0x8bu; t[i++] = 0x74u; t[i++] = 0x24u;
    t[i++] = 0x08u;
    t[i++] = 0x48u; t[i++] = 0x8bu; t[i++] = 0x54u; t[i++] = 0x24u;
    t[i++] = 0x10u;
    t[i++] = 0x48u; t[i++] = 0x8bu; t[i++] = 0x4cu; t[i++] = 0x24u;
    t[i++] = 0x18u;
    t[i++] = 0x4cu; t[i++] = 0x8bu; t[i++] = 0x44u; t[i++] = 0x24u;
    t[i++] = 0x20u;
    t[i++] = 0x48u; t[i++] = 0xb8u;
    for (q = 0; q < 8u; q++) t[i + q] = (u8)((helper >> (q * 8u)) & 0xffu);
    i += 8u;
    t[i++] = 0xffu; t[i++] = 0xd0u;
    t[i++] = 0x48u; t[i++] = 0x89u; t[i++] = 0xc6u;
    t[i++] = 0x48u; t[i++] = 0x8bu; t[i++] = 0x3cu; t[i++] = 0x24u;
    t[i++] = 0x4cu; t[i++] = 0x8bu; t[i++] = 0x54u; t[i++] = 0x24u;
    t[i++] = 0x18u;
    t[i++] = 0x4cu; t[i++] = 0x8bu; t[i++] = 0x44u; t[i++] = 0x24u;
    t[i++] = 0x20u;
    t[i++] = 0x4cu; t[i++] = 0x8bu; t[i++] = 0x4cu; t[i++] = 0x24u;
    t[i++] = 0x28u;
    t[i++] = 0xb8u; t[i++] = 0x2cu; t[i++] = 0u; t[i++] = 0u; t[i++] = 0u;
    t[i++] = 0x0fu; t[i++] = 0x05u;
    t[i++] = 0x4cu; t[i++] = 0x8bu; t[i++] = 0x44u; t[i++] = 0x24u;
    t[i++] = 0x20u;
    t[i++] = 0x48u; t[i++] = 0x83u; t[i++] = 0xc4u; t[i++] = 0x40u;
    t[i++] = 0xe9u;
    t[i++] = (u8)((u32)rel & 0xffu);
    t[i++] = (u8)(((u32)rel >> 8) & 0xffu);
    t[i++] = (u8)(((u32)rel >> 16) & 0xffu);
    t[i++] = (u8)(((u32)rel >> 24) & 0xffu);
    if (i != 128u) return 0u;
    return i;
}

/* v77 pure: СИСТЕМНЫЙ класс путей (libc/libpthread и родня). Эти регионы
 * = исключены v75b-фильтром (рекурсия-страховка), НО их raw-стабы = посы-
 * латель нативной ланы (run474). Патчим ТОЛЬКО со строгим glibc-хвостом
 * (c2b_raw_patchable_sys) — наш g_clp-passthrough = ra-гвард v52 + энтри
 * на inline-asm syscall = цикла нет. */
static i32 c2b_raw_path_sys(const char *p, u32 n)
{
    if (!p || !n) return 0;
    if (c2b_raw_has(p, n, "libc.so") || c2b_raw_has(p, n, "libc-") ||
        c2b_raw_has(p, n, "libpthread"))
        return 1;
    return 0;
}

/* pure: фильтр путей r-x/rwx регионов. 1 = СКАНИРОВАТЬ.
 * v75b-ИНВЕРСИЯ (run469-урок: steam|csgo-фильтр = sites=0 — отправитель
 * raw-sendto НЕ в GNS-либе (дамп байт-верифицирован: 0 стабов), не в
 * просканированной половине steamclient (48-кап). want = РАСШИРЕН до
 * всего файл-бэкед, исключения = минимальны:
 *   ХОТИМ: всё файл-бэкед (csgo-модули, steamclient, steam-рантайм,
 *   SDL/crypto/любые third-party — стаб может быть где угодно; RWX-
 *   регионы steamclient = рантайм-генерация кода = тоже скан).
 *   НЕ хотим: СИСТЕМНАЯ libc ("libc.so"/"libc-" — её стабы = путь наших
 *   собственных g_clp-вызовов = РЕКУРСИЯ), ld, libpthread, наш
 *   собственный .so (точное dladdr-совпадение — путь РЕПО содержит
 *   'c2bridge', подстрокой НЕ гвард!), псевдо-пути ([vdso]/[vvar]). */
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
    return 1;
}

#endif /* C2B_RAW_H */
