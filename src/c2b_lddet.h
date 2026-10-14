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
 * румент готов).
 *
 * v56 (run411, ledger 01:09): elimination-matrix расширилась — v52 = не
 * прологи libc (ARMED 4/4, ZERO HITs), v51 = не GOT/PLT, v55 = не
 * фиксированные стабы (реальный скан = zero в exe/eng/anon), tracefs =
 * отправитель = raw sys_sendto. Оставшийся libc-путь = ОБЁРТКА syscall
 * (__NR_sendto, ...) — переменный nr => якорь b8/6a НЕ примет. Новый
 * якорь C2B_LDD_NR_VAR: '48 89 f8' (mov %rdi,%rax = ЗАГРУЗКА перемен-
 * ного nr) в первых 8 байтах + '0f 05' в первых 64. Форма glibc 2.39
 * (дизасм @0x127510): endbr64 | mov rdi,rax | mov rsi,rdi | mov rdx,rsi
 * | mov rcx,rdx = ОКНО 16B (все copy-класс, riprel НЕТ) | r8->r10 |
 * r9->r8 | mov 0x8(%rsp),r9 | syscall | cmp -4095 | jae | ret | errno-
 * хвост (riprel ТОЛЬКО в хвосте = исполняется jmp-back'ом). Детур = 7
 * long (арг7 = [rsp+8]: ff25 rsp НЕ двигает, трамп читает тот же слот
 * => addrlen проходит ОБА пути). */
#ifndef C2B_LDD_H
#define C2B_LDD_H

#if defined(__x86_64__)

#define C2B_LDD_MINSTOLEN 14u   /* ff 25 00000000 + abs8 */
#define C2B_LDD_MAXSTOLEN 24u   /* кап окна (сиг-размер) */
/* v59: 192 — site-детур = 26(spill) + 30(args) + 5(call) + 13(restore)
 * + 24(окно с разворотами) + 14(ff25) = 112 с запасом */
#define C2B_LDD_MAXTRAMP  192u  /* 24 + развороты + ff25(14) с запасом */
#define C2B_LDD_NREAD     64u   /* байт читать с цели (якорь-скан + окно) */
/* Макс. |tgt - tramp|: все фиксапы = rel32/disp32 = ±2ГБ; запас 0.25ГБ
 * (CI-урок: mmap'ы на раннере = НЕ соседи; дальняя пара = усечённый disp
 * = дикий riprel-рид = SIGSEGV @первом исполнении трампа) */
#define C2B_LDD_MAXDIST   0x70000000ull
/* v56: сентинел nr для VARIABLE-NR цели (обёртка libc syscall()): якорь
 * = '48 89 f8' в первых 8B + '0f 05' в первых 64B (см. шапку) */
#define C2B_LDD_NR_VAR    0xffffu

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
            /* v59-SIB-фикс: rm=4 => байт SIB ПОСЛЕ modrm (0f 1f 84 00 ..
             * = 11B nop libc-текста; без +sib окно резалось посреди
             * инструкции => tramp-поток съезжал на 1 байт) */
            *ilen = (p - o) + 3u + sib + disp; *tlen = *ilen;
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
        (op <= 0x3du && (op & 7u) != 4u && (op & 7u) != 5u)) {
        /* alu/mov modrm-класс (аккум-имм формы x8 искл.: (op&7)==4 =
         * imm8 + (op&7)==5 = imm32 — БЕЗ modrm; v59-урок: 48 3d 00 f0
         * ff ff (cmp rax,-4096) = в КАЖДОМ syscall-окне — без фикса
         * ilen = 3 = окно срезалось посреди инструкции) */
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
    /* семейство accum-imm32 (op&7)==5: 05/0d/15/1d/25/2d/35/3d = +imm32
     * (REX-префикс уже съеден циклом выше => (p-o) учитывает его) */
    if (op <= 0x3du && (op & 7u) == 5u) {
        if (p + 4 >= n) return 0xffu;
        *ilen = (p - o) + 5u; *tlen = *ilen;
        return C2B_LDD_C_COPY;
    }
    /* 3d (cmp eax,imm32) покрыт веткой выше; прочее = отказ */
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
     * вых 64 байтах. v56: nr == C2B_LDD_NR_VAR = VARIABLE-NR цель (обёрт-
     * ка syscall()): '48 89 f8' (mov %rdi,%rax) в первых 8B + '0f 05' в
     * первых 64B. */
    {
        unsigned int lim = n < 64u ? n : 64u, found = 0u;
        if (nr == C2B_LDD_NR_VAR) {
            for (i = 0u; i + 3u <= 8u && i + 3u <= lim; i++) {
                if (tgt[i] == 0x48u && tgt[i + 1u] == 0x89u &&
                    tgt[i + 2u] == 0xf8u) { found = 1u; break; }
            }
            if (found) {
                found = 0u;
                for (i = 0u; i + 2u <= lim; i++) {
                    if (tgt[i] == 0x0fu && tgt[i + 1u] == 0x05u) {
                        found = 1u; break;
                    }
                }
            }
        } else {
            for (i = 0u; i + 7u <= lim; i++) {
                if (tgt[i] == 0xb8u && tgt[i + 1u] == (unsigned char)nr &&
                    tgt[i + 2u] == 0u && tgt[i + 3u] == 0u &&
                    tgt[i + 4u] == 0u && tgt[i + 5u] == 0x0fu &&
                    tgt[i + 6u] == 0x05u) { found = 1u; break; }
            }
            if (!found) {
                for (i = 0u; i + 2u <= lim; i++) {
                    if (tgt[i] == 0x6au &&
                        tgt[i + 1u] == (unsigned char)nr) {
                        found = 1u; break;
                    }
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

/* v59: SITE-ДЕТУР (MID-ФУНКЦИЯ) — патч syscall-САЙТА внутри чужой ф-ции
 * (cancel-arch спины + send-family внутренние syscall'ы). ОТЛИЧИЯ от
 * c2b_ldd_build: (1) БЕЗ якоря-идентичности (вызывающий = pread-верифи-
 * кация ожидаемых байтов — дрифт-протокол); (2) tramp = ПРЕФИКС spill-
 * аргументы-call-logger-restore (rax/rcx/rdx/rsi/rdi/r8-r11 = ВСЁ живое
 * на сайте; xmm = мертвы: glibc cancel-arch = рукописный asm; первый
 * украденный insn = mov/b8 = флаги-независимый => call-клоббер флагов
 * безопасен); (3) syscall = ВНУТРИ украденного окна => passthrough =
 * исполнение украденных байтов. Логгер-сигнатура:
 *   void fn(u64 rax, u64 rdi, u64 rsi, u64 rdx, u64 rcx, u64 sp,
 *           u64 r8, u64 r9, u64 r10)  — r8/r9/r10 = стек-слоты 7-9
 * sp = ИСХОДНЫЙ rsp сайта + 3 СТЕКОВЫХ арга (r10/r9/r8 push ДО call =
 * ABI-слоты 7-9: r8=[rsp+8], r9=[rsp+16], r10=[rsp+24] на входе логгера).
 * ИНТЕРПРЕТАЦИЯ = класс-зависима (логгер = сырье, анализ = офлайн):
 *   b8-сайты (snd/smg/smsg/wr): fd=rdi, buf=rsi, len=rdx (nr = const
 *     сайта — rax на входе окна ЕЩЁ МУСОР: spill ДО b8!)
 *   csp-сайты (cancel-arch): ch=rdi, cx=rsi, nr=rdx, a1=rcx=fd,
 *     a2=r8=buf, a3=r9=len (спин = mov eax,edx => nr ИЗ edx)
 * Байты префикса (порядок push: rax первым => rax=[rsp'+64]=0x40,
 * rdi=[+32]=0x20, rsi=[+40]=0x28, rdx=[+48]=0x30, rcx=[+56]=0x38;
 * rsp' = rsp-72; затем push r10/r9/r8 = стек- args):
 *   50 51 52 56 57 41 50 41 51 41 52 41 53      (9 push, 13B)
 *   48 8b 7c 24 40   mov 0x40(%rsp),%rdi        (nr -> arg1)
 *   48 8b 74 24 20   mov 0x20(%rsp),%rsi        (a1 -> arg2)
 *   48 8b 54 24 28   mov 0x28(%rsp),%rdx        (a2 -> arg3)
 *   48 8b 4c 24 30   mov 0x30(%rsp),%rcx        (a3 -> arg4)
 *   4c 8b 44 24 38   mov 0x38(%rsp),%r8         (arg5 = orig rcx)
 *   4c 8d 4c 24 48   lea 0x48(%rsp),%r9         (orig rsp -> arg6; v68: БЫЛО 49)
 *   50                                           (push rax = ВЫРАВНИВАНИЕ:
 *     13 push = 104B; site-rsp%16==8 (стандартный кадр) => call при
 *     rsp%16==0 = ABI-контракт; run417-урок: 12 push = misaligned
 *     call => gcc-логгер movaps-класс = SIGSEGV = menu=0)
 *   41 52 41 51 41 50                            (push r10 r9 r8 = args 9-7)
 *   e8 <rel32>                                   call logger
 *   41 58 41 59 41 5a                            (pop r8 r9 r10)
 *   58                                           (pop rax = выравнивание)
 *   41 5b 41 5a 41 59 41 58 5f 5e 5a 59 58      (9 pop, реверс)
 * Возврат: olen (>= 14) или 0 = отказ (окно/дистанция/неизвестный опкод). */
#define C2B_LDD_SITE_PRE  75u
static inline unsigned int c2b_ldd_site_prefix(
    unsigned char *tramp, unsigned long long tramp_addr,
    unsigned long long logger_addr)
{
    static const unsigned char pre[70] = {
        0x50u, 0x51u, 0x52u, 0x56u, 0x57u,
        0x41u, 0x50u, 0x41u, 0x51u, 0x41u, 0x52u, 0x41u, 0x53u,
        0x48u, 0x8bu, 0x7cu, 0x24u, 0x40u,
        0x48u, 0x8bu, 0x74u, 0x24u, 0x20u,
        0x48u, 0x8bu, 0x54u, 0x24u, 0x28u,
        0x48u, 0x8bu, 0x4cu, 0x24u, 0x30u,
        0x4cu, 0x8bu, 0x44u, 0x24u, 0x38u,
        0x4cu, 0x8du, 0x4cu, 0x24u, 0x48u,   /* v68-ФИКС БЫЛО 49: REX=49
            = R=0,B=1 = lea rcx,[r12+0x48] (арг6 r9 НИКОГДА не грузился:
            логгер получал ИСХОДНЫЙ r9 = мусор/0 => [0] = SEGV addr=0
            = run433 4/4 смерть + v67 st=FAULT 6/6; arg4 = rcx
            затирался r12+0x48). REX=4c = R=1,B=0 = lea r9,[rsp+0x48]
            = ЗАДУМАННОЕ кодирование (arg6 = sp, arg4 = цел) */
        /* call rel32 = пишется отдельно ниже; далее 27 байтов:
         * push rax (выравнивание) | push r10 r9 r8 | pop r8 r9 r10 |
         * pop rax | pop r11 r10 r9 r8 rdi rsi rdx rcx rax */
        0x50u,
        0x41u, 0x52u, 0x41u, 0x51u, 0x41u, 0x50u,
        0x41u, 0x58u, 0x41u, 0x59u, 0x41u, 0x5au,
        0x58u,
        0x41u, 0x5bu, 0x41u, 0x5au, 0x41u, 0x59u, 0x41u, 0x58u,
        0x5fu, 0x5eu, 0x5au, 0x59u, 0x58u
    };
    unsigned int q, t = 0u;
    for (q = 0u; q < 43u; q++) tramp[t++] = pre[q];   /* push+args */
    /* call rel32 -> logger */
    {
        long long rel = (long long)logger_addr -
                        ((long long)tramp_addr + (long long)t + 5ll);
        tramp[t] = 0xe8u;
        for (q = 0u; q < 4u; q++)
            tramp[t + 1u + q] = (unsigned char)(((unsigned long long)rel >>
                                                (8 * q)) & 0xffu);
    }
    t += 5u;
    for (q = 43u; q < 70u; q++) tramp[t++] = pre[q];  /* стек-args + pop'ы */
    return t;                   /* 75 байта: 43 + 5 call + 27 хвост */
}

static inline unsigned int c2b_ldd_site_build(const unsigned char *tgt,
                                              unsigned int n,
                                              unsigned long long tgt_addr,
                                              unsigned char *tramp,
                                              unsigned long long tramp_addr,
                                              unsigned long long logger_addr,
                                              unsigned int *olen_out,
                                              unsigned int *tlen_out)
{
    unsigned int o = 0u, t, j;
    if (!tgt || !tramp || !olen_out || !tlen_out || n < 16u) return 0u;
    *olen_out = 0u; *tlen_out = 0u;
    {
        unsigned long long d = (tgt_addr > tramp_addr)
                                   ? (tgt_addr - tramp_addr)
                                   : (tramp_addr - tgt_addr);
        if (d > C2B_LDD_MAXDIST) return 0u;
    }
    /* ПРЕФИКС spill/args/call-logger/restore = ПЕРВЫМ (украденное окно
     * = ПОСЛЕ него;_syscall = внутри окна => passthrough = украденные
     * байты); call-rel32 = известен уже здесь (logger = константа) */
    t = c2b_ldd_site_prefix(tramp, tramp_addr, logger_addr);
    /* окно БЕЗ якоря: тот же декодер, та же граница >= 14 */
    for (;;) {
        unsigned int ilen, tlen, cc, doff, kind, pad;
        unsigned char k = c2b_ldd_class(tgt, n, o, &ilen, &tlen, &cc,
                                        &doff);
        if (k == 0xffu) return 0u;
        kind = (unsigned int)k;
        if (o + ilen > C2B_LDD_MAXSTOLEN) return 0u;
        /* v61: ERESTART-PAD — если украденная инсн = syscall (окно
         * кончается '0f 05'), в трампе ПЕРЕД '0f 05' вставляется 2B-nop
         * '66 90'. ПРИЧИНА: ядро на ERESTARTSYS/ERESTART_RESTARTBLOCK
         * перезапускает прерванный syscall РЕВАЙНОМ RIP-2 (rax = orig nr
         * / 219 восстанавливает САМО ядро) — в трампе -2 от '0f 05' =
         * хвост 'b8 <nr> 00 00 00' = '00 00' = add %al,(%rax) = ДИКИЙ
         * рид = SIGSEGV, проглоченный crash-хэндлером движка = ЧИСТЫЙ
         * инстант-выход (run420/421: wr2 = menu=0 x4/5, dmesg = zero
         * segv; wr2 = write()-cancellable-путь = ЕДИНСТВЕННЫЙ ИСПОЛНЯЕМЫЙ
         * сайт с syscall в окне). '66 90' = xchg %ax,%ax = полный 2B-insn:
         * ревайн садится НА НЕГО, фоллсру = '0f 05' с ядерными rax = к о
         * р р е к т н ы й рестарт. Ложноположит. детект (imm64-хвост
         * '0f 05') = безвреден (+2B nop в трампе). v52-энтри = окно БЕЗ
         * syscall (пролог) => пад не нужен, оригинальный syscall не
         * патчен. */
        pad = (ilen >= 2u && tgt[o + ilen - 2u] == 0x0fu &&
               tgt[o + ilen - 1u] == 0x05u) ? 2u : 0u;
        if (t + pad + tlen + 14u > C2B_LDD_MAXTRAMP) return 0u;
        if (pad) {
            tramp[t] = 0x66u; tramp[t + 1u] = 0x90u;
            t += 2u;
        }
        if (kind == C2B_LDD_C_COPY || kind == C2B_LDD_C_RIPREL) {
            for (j = 0u; j < ilen; j++) tramp[t + j] = tgt[o + j];
            if (kind == C2B_LDD_C_RIPREL) {
                long long orig = 0ll, nu, target;
                unsigned int q;
                for (q = 0u; q < 4u; q++)
                    orig |= ((long long)tgt[o + doff + q]) << (8 * q);
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
        if (o >= C2B_LDD_MINSTOLEN) break;
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

/* v60: C2B_DSITES-фильтр сайтов = bisect-рычаг flake-vs-v59 (run417/418
 * FAIL menu=0 при чистом exit = вину v59 НЕ доказана; run419 = сайты-off
 * = точная копия PASS-дерева 404-416 => PASS = v59 виновен => site-
 * bisect; FAIL = runner-флак). Семантика: unset = все 8 (v59b), "" =
 * НОЛЬ сайтов, "wr1,wr2" = подмножество. Plain-substring достаточен:
 * теги csp1/csp2/csp3/snd/smg/smsg/wr1/wr2 = без кросс-подстрок (smg
 * НЕ сабстринг smsg и наоборот — проверено selftest'ом). Pure = в
 * хедере (static inline) = живёт в ОБЕИХ компиляциях (.so + selftest). */
static inline unsigned int c2b_dsite_pass(const char *flt, const char *tag)
{
    unsigned int tl, i, j;
    if (!flt) return 1u;            /* unset = фильтра нет = все */
    if (!flt[0]) return 0u;         /* "" = ноль сайтов */
    tl = 0u;
    while (tag[tl]) tl++;
    for (i = 0u; flt[i]; i++) {
        unsigned int same = 1u;
        for (j = 0u; j < tl; j++)
            if (flt[i + j] != tag[j]) { same = 0u; break; }
        if (same) return 1u;
    }
    return 0u;
}

/* v62: sendmsg-ФОРМА (сайт smsg = nr 46 = b8 2e): у syscall sendmsg
 * rsi = msghdr*, rdx = ФЛАГИ — buf/len = ВНУТРИ msghdr (msg_iov[0]).
 * glibc/x86-64 struct msghdr: msg_name@0, msg_namelen@8 (4B), msg_iov@
 * 16, msg_iovlen@24, msg_control@32, msg_controllen@40, msg_flags@48;
 * struct iovec = {iov_base@0, iov_len@8} = 16B. Прежний фильтр (rsi[0]
 * == 0x22 && rdx in [40,640]) для smsg = СЛЕП: rsi[0] = байт msg_name-
 * указателя, rdx = флаги => 0x22 ЧЕРЕЗ sendmsg = НЕВИДИМ (run425: smsg
 * FIRE fd=33 len=72 = rdx = НЕ len). Pure (byte-wise = без выравн).
 * Возврат 1 = 0x22-форма найдена (base/len = выходы), 0 = мимо. */
static inline unsigned int c2b_ldd_mh0x22(const unsigned char *mh,
                                          unsigned long long *base_out,
                                          unsigned long long *len_out)
{
    unsigned long long iovec, base, ln;
    const unsigned char *iv;
    unsigned int q;
    if (!mh || !base_out || !len_out) return 0u;
    iovec = 0ull;
    for (q = 0u; q < 8u; q++)
        iovec |= ((unsigned long long)mh[16u + q]) << (8u * q);
    if (!iovec) return 0u;
    ln = 0ull;
    for (q = 0u; q < 8u; q++)
        ln |= ((unsigned long long)mh[24u + q]) << (8u * q);
    if (!ln) return 0u;             /* iovlen = 0 = мимо */
    iv = (const unsigned char *)(uptr)iovec;
    base = 0ull;
    for (q = 0u; q < 8u; q++)
        base |= ((unsigned long long)iv[q]) << (8u * q);
    ln = 0ull;
    for (q = 0u; q < 8u; q++)
        ln |= ((unsigned long long)iv[8u + q]) << (8u * q);
    if (!base || ln < 40u || ln > 640u) return 0u;
    if (((const unsigned char *)(uptr)base)[0] != 0x22u) return 0u;
    *base_out = base;
    *len_out = ln;
    return 1u;
}

/* v63: FIRE-профайлер sendmsg-пути = ИСТИННЫЙ iov[0].len (без 0x22-
 * гейта и без [40,640]-окна — профайл = ЛЮБАЯ форма: run425/427 FIRE
 * len=72/213/220 = сырое reg-гадание (rdx = флаги, r9v = мусор), не
 * длины). Дисциплина = ТА ЖЕ что класс-3 (v62b): вызыватель обязан
 * сайт-гейтить tag == C2B_DSITE_SMSG — на sendto-сайтах rsi = буфер =
 * слепой парс msg_iov = дикий deref (урок run426). Дереф = ТОЛЬКО
 * msghdr->msg_iov (указатель, который сам sendmsg разыменует дальше
 * по коду) + iv[8..15]; iov_base НЕ трогаем. 0 = парс не удался. */
static inline unsigned long long c2b_ldd_mh_len(const unsigned char *mh)
{
    unsigned long long iovec, ln;
    const unsigned char *iv;
    unsigned int q;
    if (!mh) return 0ull;
    iovec = 0ull;
    for (q = 0u; q < 8u; q++)
        iovec |= ((unsigned long long)mh[16u + q]) << (8u * q);
    if (!iovec) return 0ull;
    ln = 0ull;
    for (q = 0u; q < 8u; q++)
        ln |= ((unsigned long long)mh[24u + q]) << (8u * q);
    if (!ln) return 0ull;           /* iovlen = 0 = мимо */
    iv = (const unsigned char *)(uptr)iovec;
    ln = 0ull;
    for (q = 0u; q < 8u; q++)
        ln |= ((unsigned long long)iv[8u + q]) << (8u * q);
    return ln;
}

/* v64: FIRE-аргументы = ABI-сплит по КЛАССУ сайта (g_dsite_tab-индекс).
 * КЛАСС b8 (tab[3..7] = snd/smg/smsg/wr1(+wr2), диск = b8 <nr> 00 00 00
 * 0f ..): ловушка = ПЕРЕД окном (ax = pre-site мусор — FIRE ax=0/2 =
 * доказательство), syscall-аргументы УЖЕ разведены: fd=rdi, len=rdx
 * (rdx = НЕ флаги — флаги = r10). => fd/len = rdi/rdx ВСЕГДА, БЕЗ
 * fallback'а: прежний "иначе fd=rcx len=r9v" = сырые pre-syscall
 * остатки libc (run425/427/428 FIRE-1 smg fd=0x8940/0x5940 len=0 =
 * МУСОР, не данные; run427 FIRE smg fd=0x17 len=0x48 = rdx=0x48 =
 * прошла [40,640]-окно случайно). rdx вне [40,640] = ВСЁ РАВНО
 * реальные данные (0 = 0-лен датаграмма-класс; >640 = крупный кадр).
 * КЛАСС csp (tab[0..2] = '?'-спин 89 d0 0f 05): rdx = НОМЕР (mov
 * eax,edx) => syscall-аргументы сдвинуты, конвенция cls=2 (fd=rcx,
 * len=r9) — держится. smsg (tab[5], nr 46 = sendmsg): len = ИСТИННЫЙ
 * iov[0].len = c2b_ldd_mh_len (v63; сайт-гейт = дисциплина v62b,
 * инвариант инсталлера v62b гвардит tab[5] = b8 2e — здесь тот же
 * индекс 5 = константа-дубль, пин selftest'ом).
 * v64b-вердикт (census-лейбл): smg = sendto-КЛАСС (b8 2c = nr 44 на
 * диске + fd=rdi/len=rdx=0x48 в рантайме = ABI sendto; sendmmsg =
 * nr 307 = b8 33 01 00 00 = НЕ эта форма) — 'sendmmsg inner' =
 * МИСНОМЕР run414-census, mmsghdr-план 0839 = СНЯТ.
 * Pure = в хедере = обе компиляции = selftest. */
static inline void c2b_ldd_fire_args(unsigned int tag,
                                     unsigned long long rdi,
                                     unsigned long long rsi,
                                     unsigned long long rdx,
                                     unsigned long long rcx,
                                     unsigned long long r9v,
                                     unsigned long long *fd,
                                     unsigned long long *len)
{
    if (tag == 5u) {                /* smsg = sendmsg (v63, гейт v62b) */
        *fd = rdi;
        *len = rsi ? c2b_ldd_mh_len((const unsigned char *)(uptr)rsi)
                   : 0ull;
    } else if (tag >= 3u) {         /* b8-класс: syscall ABI без fallback */
        *fd = rdi; *len = rdx;
    } else {                        /* csp-спин: конвенция cls=2 */
        *fd = rcx; *len = r9v;
    }
}

#endif /* __x86_64__ */
#endif /* C2B_LDD_H */
