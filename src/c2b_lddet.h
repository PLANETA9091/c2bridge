/* c2b_lddet.h — v52: LIBC-PROLOGUE DETOUR — патч ПРОЛОГОВ sendto/sendmsg/
 * send в САМОЙ libc.so.6 (точки входа) с переносящим трамплином.
 *
 * КОНТЕКСТ (ledger 22:09, run397): elimination matrix ЗАКРЫТА в обе сторо-
 * ны — (1) ни один PLT/GOT-слот ни одного модуля не минует хуки (v51:
 * все 8 слотов = 'already' = LD_PRELOAD покрывает даже steamclient.so,
 * НИКАКОГО dlmopen-ns НЕТ); (2) сырых syscall'ов send-класса НЕТ ни в
 * одном модуле (v51_syscall_audit.py: 6 копий steamclient + движок +
 * compat = 0 сайтов). Остаётся ЕДИНСТВЕННЫЙ класс механизма: ПРЯМОЙ
 * указатель на libc-send (dlopen-хэндл dlsym / заранее-resolved pointer
 * в анонимном коде) — мимо ВСЕХ GOT/PLT. Единственное место, где такой
 * вызов ЕЩЁ проходит = тело самой libc-функции => патч её ПРОЛОГА.
 *
 * ФОРМЫ ПРОЛОГОВ (реальные дизасмы; фикстуры = тест):
 *  glibc 2.39 (ubuntu 24.04 = раннер):
 *    sendto:  f3 0f 1e fa | 80 3d <d32> 00 | 41 89 ca | 74 10 | b8 2c..0f05
 *             ^endbr64     ^cmpb $0,rip+^   ^mov ecx,r10d ^je slow
 *             RIP-ОТНОСИТЕЛЬНЫЙ cmpb (@__libc_single_threaded) — при пере-
 *             носе в трамп disp32 ПЕРЕСЧИТЫВАЕТСЯ (форма той же длины).
 *    sendmsg: f3 0f 1e fa | 80 3d <d32> 00 | 74 13 | b8 2e..  (je В ОКНЕ)
 *    send:    как sendto, je <disp8> (slow-path = entry+0x30).
 *  glibc 2.35 (ubuntu 22.04):
 *    sendto:  f3 0f 1e fa | 41 89 ca | 64 8b 04 25 18000000 | 85 c0 | 75 15
 *             fs-ПРЕФИКС = АБСОЛЮТНЫЙ disp32 = перенос вербатим (не rip!).
 *  glibc 2.41 (Debian 13):
 *    sendto:  48 83 ec 10 | 48 63 c9 | 48 63 ff | 45 89 c9 | 6a 2c | e8 ..
 *             чистая прямолинейка до call — 15B, call НЕ в окне.
 *
 * ДИЗАЙН: ОБЩИЙ декодер окна (не точные сигнатуры!): идём по инструкциям
 * от входа, пока не наберём >= 14 байт (ff25+abs8) НА ГРАНИЦЕ инструкции
 * (кап 24). Каждая инструкция = копия в трамп; фиксапы:
 *  - rip-относительный modrm (mod=0,rm=5): disp32' = цель - (tramp+конец
 *    инструкции) — форма той же длины;
 *  - короткий jcc (74-7f): ВСЕГДА разворачивается в 0f 8x rel32 (6B) с
 *    абсолютным rel32 = цель - (tramp+конец) — корректно и для цели
 *    внутри окна (смещения трампа != смещения окна из-за разворотов);
 *  - 0f 8x = rel32-пересчёт той же длины; 0f 05/прямолинейные/imm/push =
 *    копия вербатим.
 * ОТКАЗЫ (без патча, с логом вызывающего): нет якоря syscall-nr (b8 nr
 * ..0f 05 ИЛИ 6a nr в первых 64B = идентичность ф-ции), неизвестный
 * опкод, e8/e9/c3/cc/ff-косвенный в окне, окно > 24, короткое чтение.
 *
 * БЕЗОПАСНОСТЬ: чтение байтов цели = ОБЯЗАННОСТЬ вызывающего (pread
 * /proc/self/mem, v4.3-дисциплина — хедер НЕ разыменовывает цель);
 * tramp = mmap RWX вызывающего. Запись сайта = mprotect RW + memcpy +
 * mprotect RX (c2bridge-паттерн c2b_install). Ре-вход: детур-фн зовёт
 * ТОЛЬКО трамплин (не entry) => петли нет. write/логи = не патчатся.
 *
 * АРХ: x86-64 only (i386 = хедер пуст). Гейт = C2B_LIBCDET=1 (armed-
 * класс: меняет текст libc). Лог-маркеры: '[c2b] v52: ARMED <fn>@..',
 * '[c2b] v52: HIT sendto len=.. ra=..' (доказательство прямого-укателя),
 * '[c2b] v52: <fn> build=0 have=<hex>' (дрифт-протокол g124).
 *
 * ОЖИДАЕМЫЙ ИСХОД run398 (дерево 22:09 без изменений): (а) 0x23
 * ConnectOK К :27005 = ВЕХА (accept-путь движка доказан) => шифроста-
 * дия = v53 (экспорт ed25519-приватника из кучи steamclient по пабкичу
 * серта 0f9d1db0...); (б) 0x24 named-reject = требование названо;
 * (в) тишина = релей требует crypto-подпись до ответа => v53 = подпись
 * в c2b_crt_build; (г) HIT'ов ноль, а 0x22 движка на проводе ЕСТЬ =>
 * отправитель = syscall-стаб в анонимной r-x памяти => v53 = скан ано-
 * нимных r-x регионов на '0f 05' с nr=44/46 (pread-прогулка v51 = инст-
 * румент готов). */
#ifndef C2B_LDD_H
#define C2B_LDD_H

#if defined(__x86_64__)

#define C2B_LDD_MINSTOLEN 14u   /* ff 25 00000000 + abs8 */
#define C2B_LDD_MAXSTOLEN 24u   /* кап окна (сиг-размер) */
#define C2B_LDD_MAXTRAMP  96u   /* 24 + развороты + ff25(14) с запасом */
#define C2B_LDD_NREAD     64u   /* байт читать с цели (якорь-скан + окно) */
/* Макс. |tgt - tramp|: все фиксапы = rel32/disp32 = ±2ГБ; запас 0.25ГБ
 * (CI-урок: mmap'ы на раннере = НЕ соседи; дальняя пара = усечённый disp
 * = дикий riprel-рид = SIGSEGV @первом исполнении трампа) */
#define C2B_LDD_MAXDIST   0x70000000ull

/* класс инструкции */
#define C2B_LDD_C_COPY   0u     /* копия вербатим */
#define C2B_LDD_C_RIPREL 1u     /* копия + пересчёт disp32 (mod=0,rm=5) */
#define C2B_LDD_C_JCC8   2u     /* разворот 2B короткого jcc -> 6B 0f 8x */
#define C2B_LDD_C_JMP8   3u     /* 0xeb -> 0xe9 rel32 */
#define C2B_LDD_C_JCC32  4u     /* 0f 8x: rel32-пересчёт той же длины */

/* modrm-дисп: длина disp-поля; *riprel = 1 iff mod=0 && rm=5; *sib = 1
 * iff байт SIB присутствует (rm=4). mod=3 (reg-форма) = 0. */
static inline unsigned int c2b_ldd_mdisp(unsigned char modrm,
                                         unsigned int *riprel,
                                         unsigned int *sib)
{
    unsigned int mod = (unsigned int)(modrm >> 6);
    unsigned int rm  = (unsigned int)(modrm & 7u);
    *riprel = 0u; *sib = 0u;
    if (mod == 3u) return 0u;
    if (rm == 4u) {                                 /* SIB */
        *sib = 1u;
        /* base=5 при mod=0 => disp32 есть, но это АБСОЛЮТ (базы нет),
         * НЕ rip-относительный => фиксапа нет */
        if (mod == 0u) return 4u;
        return (mod == 1u) ? 1u : 4u;
    }
    if (mod == 0u && rm == 5u) { *riprel = 1u; return 4u; }
    if (mod == 1u) return 1u;
    if (mod == 2u) return 4u;
    return 0u;
}

/* Классификация инструкции с оффса o в tgt (валидно n байт).
 * Возврат: C2B_LDD_C_* или 0xff = отказ. Выходы: *ilen (длина в окне),
 * *tlen (длина в трампе), *cc (low-nibble условия для jcc), *doff (оф-
 * фс disp32 внутри инструкции; валиден при RIPREL). */
static inline unsigned char c2b_ldd_class(const unsigned char *tgt,
                                          unsigned int n, unsigned int o,
                                          unsigned int *ilen,
                                          unsigned int *tlen,
                                          unsigned int *cc,
                                          unsigned int *doff)
{
    unsigned int p = o, rex = 0u, npfx = 0u, op, m, disp, rip, sib;
    unsigned char b;
    *ilen = 0u; *tlen = 0u; *cc = 0u; *doff = 0u;
    if (o >= n) return 0xffu;
    /* префиксы: legacy (66/f2/f3/2e/3e/26/36/64/65) + REX 40-4f (последн.) */
    for (;;) {
        if (p >= n || npfx >= 4u) return 0xffu;
        b = tgt[p];
        if (b == 0x66u || b == 0xf2u || b == 0xf3u || b == 0x2eu ||
            b == 0x3eu || b == 0x26u || b == 0x36u || b == 0x64u ||
            b == 0x65u) { p++; npfx++; continue; }
        if (b >= 0x40u && b <= 0x4fu) { rex = 1u; p++; npfx++; continue; }
        break;
    }
    if (p >= n) return 0xffu;
    op = (unsigned int)tgt[p];
    if (op == 0x0fu) {
        if (p + 1 >= n) return 0xffu;
        op = (unsigned int)tgt[p + 1];
        if (op == 0x05u) {                          /* syscall */
            *ilen = (p - o) + 2u; *tlen = *ilen; return C2B_LDD_C_COPY;
        }
        if (op == 0x1eu || op == 0x1fu) {           /* endbr/nop-long */
            if (p + 2 >= n) return 0xffu;
            m = (unsigned int)tgt[p + 2];
            disp = c2b_ldd_mdisp((unsigned char)m, &rip, &sib);
            if (rip) return 0xffu;
            *ilen = (p - o) + 3u + disp; *tlen = *ilen;
            return C2B_LDD_C_COPY;
        }
        if (op >= 0x80u && op <= 0x8fu) {           /* длинный jcc */
            *ilen = (p - o) + 6u; *tlen = *ilen;
            *cc = op & 0xfu; *doff = (p - o) + 2u;
            return C2B_LDD_C_JCC32;
        }
        return 0xffu;                               /* 0f 0b/0f bx/прочее */
    }
    if (op == 0x80u || op == 0x81u || op == 0x83u) { /* grp1 imm */
        if (p + 1 >= n) return 0xffu;
        m = (unsigned int)tgt[p + 1];
        disp = c2b_ldd_mdisp((unsigned char)m, &rip, &sib);
        *ilen = (p - o) + 2u + sib + disp +
                ((op == 0x81u) ? 4u : 1u);
        *tlen = *ilen;
        if (rip) { *doff = (p - o) + 2u + sib; return C2B_LDD_C_RIPREL; }
        return C2B_LDD_C_COPY;
    }
    if (op == 0x88u || op == 0x89u || op == 0x8au || op == 0x8bu ||
        op == 0x85u || op == 0x87u || op == 0x8du || op == 0x63u ||
        (op <= 0x3du && (op & 7u) != 4u)) {         /* alu/mov modrm-класс
                                                     * (аккум-формы x4 искл.) */
        if (p + 1 >= n) return 0xffu;
        m = (unsigned int)tgt[p + 1];
        disp = c2b_ldd_mdisp((unsigned char)m, &rip, &sib);
        *ilen = (p - o) + 2u + sib + disp;
        *tlen = *ilen;
        if (rip) { *doff = (p - o) + 2u + sib; return C2B_LDD_C_RIPREL; }
        return C2B_LDD_C_COPY;
    }
    if (op == 0x69u || op == 0x6bu) {               /* imul imm */
        if (p + 1 >= n) return 0xffu;
        m = (unsigned int)tgt[p + 1];
        disp = c2b_ldd_mdisp((unsigned char)m, &rip, &sib);
        *ilen = (p - o) + 2u + sib + disp + ((op == 0x69u) ? 4u : 1u);
        *tlen = *ilen;
        if (rip) { *doff = (p - o) + 2u + sib; return C2B_LDD_C_RIPREL; }
        return C2B_LDD_C_COPY;
    }
    if (op == 0xf6u || op == 0xf7u) {               /* grp3 (test/not/..) */
        unsigned int rg;
        if (p + 1 >= n) return 0xffu;
        m = (unsigned int)tgt[p + 1];
        rg = (m >> 3) & 7u;
        disp = c2b_ldd_mdisp((unsigned char)m, &rip, &sib);
        *ilen = (p - o) + 2u + sib + disp;
        if (rg <= 1u) *ilen += (op == 0xf7u) ? 4u : 1u;   /* test imm */
        *tlen = *ilen;
        if (rip) { *doff = (p - o) + 2u + sib; return C2B_LDD_C_RIPREL; }
        return C2B_LDD_C_COPY;
    }
    if (op >= 0xb8u && op <= 0xbfu) {               /* mov imm r */
        *ilen = (p - o) + ((rex && (tgt[p - 1u] & 8u)) ? 10u : 5u);
        *tlen = *ilen; return C2B_LDD_C_COPY;
    }
    if (op == 0x68u) { *ilen = (p - o) + 5u; *tlen = *ilen;
        return C2B_LDD_C_COPY; }                    /* push imm32 */
    if (op == 0x6au) { *ilen = (p - o) + 2u; *tlen = *ilen;
        return C2B_LDD_C_COPY; }                    /* push imm8 */
    if (op >= 0x50u && op <= 0x5fu) { *ilen = (p - o) + 1u;
        *tlen = *ilen; return C2B_LDD_C_COPY; }     /* push/pop r64 */
    if (op == 0x90u || op == 0x98u || op == 0x99u) {
        *ilen = (p - o) + 1u; *tlen = *ilen; return C2B_LDD_C_COPY;
    }
    if (op >= 0x70u && op <= 0x7fu) {               /* короткий jcc */
        *ilen = (p - o) + 2u; *tlen = (p - o) + 6u;
        *cc = op & 0xfu; return C2B_LDD_C_JCC8;
    }
    if (op == 0xebu) {                              /* короткий jmp */
        *ilen = (p - o) + 2u; *tlen = (p - o) + 5u;
        return C2B_LDD_C_JMP8;
    }
    /* 3d (cmp eax,imm32) / 04-классы аккум-имм: только 3d встречается */
    if (op == 0x3du) { *ilen = (p - o) + 5u; *tlen = *ilen;
        return C2B_LDD_C_COPY; }
    return 0xffu;   /* e8/e9/c3/cc/ff/c6/c7/неизвестное = отказ */
}

/* ГЛАВНЫЙ: построить трамп. tgt = ПЕРВЫЕ n (>= C2B_LDD_NREAD желательно)
 * байт реальной ф-ции (читатель = pread, безопасно); tgt_addr = её адрес;
 * tramp = буфер >= C2B_LDD_MAXTRAMP; tramp_addr = его адрес; nr = ожидае-
 * мый syscall-nr (44 = sendto/send, 46 = sendmsg). Возврат: украденная
 * длина (olen >= 14, сайт = patch14 + nop до olen) или 0 = ОТКАЗ.
 * *tlen_out = полная длина трампа (с ff25-jmp-back). */
static inline unsigned int c2b_ldd_build(const unsigned char *tgt,
                                         unsigned int n,
                                         unsigned long long tgt_addr,
                                         unsigned char *tramp,
                                         unsigned long long tramp_addr,
                                         unsigned int nr,
                                         unsigned int *olen_out,
                                         unsigned int *tlen_out)
{
    unsigned int o = 0u, t = 0u, i, j;
    if (!tgt || !tramp || !olen_out || !tlen_out || n < 8u) return 0u;
    *olen_out = 0u; *tlen_out = 0u;
    /* ДИСТАНЦИЯ: rel32/disp32-фиксапы = ±2ГБ — дальняя пара = отказ ДО
     * записи трампа (иначе усечённый disp = дикий рид на исполнении) */
    {
        unsigned long long d = (tgt_addr > tramp_addr)
                                   ? (tgt_addr - tramp_addr)
                                   : (tramp_addr - tgt_addr);
        if (d > C2B_LDD_MAXDIST) return 0u;
    }
    /* ЯКОРЬ идентичности: 'b8 <nr> 00 00 00 0f 05' (inline-syscall форма,
     * glibc 2.35/2.39) ИЛИ '6a <nr>' (push-nr обёртка, glibc 2.41) в пер-
     * вых 64 байтах. */
    {
        unsigned int lim = n < 64u ? n : 64u, found = 0u;
        for (i = 0u; i + 7u <= lim; i++) {
            if (tgt[i] == 0xb8u && tgt[i + 1u] == (unsigned char)nr &&
                tgt[i + 2u] == 0u && tgt[i + 3u] == 0u &&
                tgt[i + 4u] == 0u && tgt[i + 5u] == 0x0fu &&
                tgt[i + 6u] == 0x05u) { found = 1u; break; }
        }
        if (!found) {
            for (i = 0u; i + 2u <= lim; i++) {
                if (tgt[i] == 0x6au && tgt[i + 1u] == (unsigned char)nr) {
                    found = 1u; break;
                }
            }
        }
        if (!found) return 0u;
    }
    /* прогулка окна */
    for (;;) {
        unsigned int ilen, tlen, cc, doff, kind;
        unsigned char k = c2b_ldd_class(tgt, n, o, &ilen, &tlen, &cc,
                                        &doff);
        if (k == 0xffu) return 0u;
        kind = (unsigned int)k;
        if (o + ilen > C2B_LDD_MAXSTOLEN) return 0u;
        if (t + tlen + 14u > C2B_LDD_MAXTRAMP) return 0u;
        if (kind == C2B_LDD_C_COPY || kind == C2B_LDD_C_RIPREL) {
            for (j = 0u; j < ilen; j++) tramp[t + j] = tgt[o + j];
            if (kind == C2B_LDD_C_RIPREL) {
                long long orig = 0ll, nu, target;
                unsigned int q;
                for (q = 0u; q < 4u; q++)
                    orig |= ((long long)tgt[o + doff + q]) << (8 * q);
                /* цель = RIP-после-инструкции в ОРИГИНАЛЕ + disp */
                target = (long long)tgt_addr + (long long)(o + ilen) +
                         orig;
                nu = target - ((long long)tramp_addr +
                               (long long)(t + ilen));
                for (q = 0u; q < 4u; q++)
                    tramp[t + doff + q] =
                        (unsigned char)(((unsigned long long)nu >>
                                         (8 * q)) & 0xffu);
            }
        } else if (kind == C2B_LDD_C_JCC8) {
            long long target, rel, d8;
            unsigned int q;
            d8 = (long long)(signed char)tgt[o + ilen - 1u];
            tramp[t] = 0x0fu;
            tramp[t + 1u] = (unsigned char)(0x80u | (cc & 0xfu));
            target = (long long)tgt_addr + (long long)o +
                     (long long)ilen + d8;
            rel = target - ((long long)tramp_addr + (long long)t + 6ll);
            for (q = 0u; q < 4u; q++)
                tramp[t + 2u + q] =
                    (unsigned char)(((unsigned long long)rel >> (8 * q)) &
                                    0xffu);
        } else if (kind == C2B_LDD_C_JMP8) {
            long long target, rel, d8;
            unsigned int q;
            d8 = (long long)(signed char)tgt[o + ilen - 1u];
            tramp[t] = 0xe9u;
            target = (long long)tgt_addr + (long long)o +
                     (long long)ilen + d8;
            rel = target - ((long long)tramp_addr + (long long)t + 5ll);
            for (q = 0u; q < 4u; q++)
                tramp[t + 1u + q] =
                    (unsigned char)(((unsigned long long)rel >> (8 * q)) &
                                    0xffu);
        } else { /* C2B_LDD_C_JCC32 */
            long long orig = 0ll, target, rel;
            unsigned int q;
            for (q = 0u; q < 4u; q++)
                orig |= ((long long)tgt[o + ilen - 4u + q]) << (8 * q);
            for (j = 0u; j < ilen; j++) tramp[t + j] = tgt[o + j];
            target = (long long)tgt_addr + (long long)(o + ilen) + orig;
            rel = target - ((long long)tramp_addr + (long long)t + 6ll);
            for (q = 0u; q < 4u; q++)
                tramp[t + doff + q] =
                    (unsigned char)(((unsigned long long)rel >> (8 * q)) &
                                    0xffu);
        }
        o += ilen; t += tlen;
        if (o >= C2B_LDD_MINSTOLEN) break;           /* граница инструкции */
    }
    /* ff25-jmp-back -> tgt_addr + olen */
    tramp[t] = 0xffu; tramp[t + 1u] = 0x25u;
    tramp[t + 2u] = 0u; tramp[t + 3u] = 0u;
    tramp[t + 4u] = 0u; tramp[t + 5u] = 0u;
    {
        unsigned int q;
        unsigned long long v = tgt_addr + (unsigned long long)o;
        for (q = 0u; q < 8u; q++)
            tramp[t + 6u + q] = (unsigned char)((v >> (8 * q)) & 0xffu);
    }
    *olen_out = o; *tlen_out = t + 14u;
    return o;
}

#endif /* __x86_64__ */
#endif /* C2B_LDD_H */
