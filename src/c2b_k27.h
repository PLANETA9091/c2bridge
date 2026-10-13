/* c2b_k27.h — v27: IN-CHANNEL CLV2 'A'/'B' SNIFF — общий контракт
 * producer (c2b_client_hook64.so, LD_PRELOAD, g126-dec-tap) =>
 * consumer (c2bridge64.so, g97-тред).
 *
 * КОНТЕКСТ (run361/364-уроки):
 *  - Сервер шлёт IN-CHANNEL 'A' (ff×4+'A'+chal+proto+val+echo) в ЖИВУЮ
 *    SDR-сессию — run361 DEC32#1 len=0x36: chal=0, proto=3, val=
 *    gameserver_relay_session_id. Это = ЗАПРОС АУТЕНТИФИКАЦИИ от
 *    геймсервера на уровне CLV2, туннелированный в SNP-стрим.
 *  - Ответ = 'k' (ff×4+'k'+chal+ticket) IN-CHANNEL (run357 форма), НО
 *    chal должен быть ИМЕННО тот, что в этом 'A' (run357-смерть =
 *    гипотеза: chal от коннлесс-пути при in-channel контексте).
 *  - Оба .so = в ИГРОВОМ процессе; hook = LD_PRELOAD = глобальный скоуп
 *    => мост находит структуру через dlsym(RTLD_DEFAULT, ...).
 *
 * ПОСЛЕДОВАТЕЛЬНОСТЬ: producer пишет поля, ЗАТЕМ bump seq (release-RMW).
 * consumer: load seq (acquire) -> load поля -> load seq; равны = консистентно.
 */
#ifndef C2B_K27_H
#define C2B_K27_H

/* v43: raw-капчер — ПОЛНЫЙ wire-'A' (от ff×4) для релея в движок
 * (a2e = A-to-Engine). Серверский 'A' = 42B (run379/381 DEC32 полный
 * plaintext: ff×4+'A'+chal4+proto+pad5+val4+00 00 30 01 01+echo NUL) —
 * 72 = запас на будущие формы. rawlen=0 = не захвачено. */
#define C2B_K27_RAWMAX 72

typedef struct c2b_k27_A {
    volatile unsigned int       seq;    /* +1 на каждый новый 'A' */
    volatile unsigned int       chal;   /* LE u32 @ 'A'+5 */
    volatile unsigned int       proto;  /* байт @ 'A'+9 */
    volatile unsigned int       val;    /* LE u32 @ 'A'+15 (v41b: РЕАЛЬНЫЙ
                                         * офсет — run379/380 полный 54B-dump:
                                         * [10..14] = 5 нулей, val='07 0a ee
                                         * 00'=0x00ee0a07 @15; старый +10 чи-
                                         * тал 0 = v41 выстрелил qconnect0x0
                                         * и сервер ре-челленджил 2-й 'A') */
    volatile unsigned long long gcm;    /* gcm-контекст расшифровки (пост-фактум
                                         * атрибуция сессии: in=<8B> ↔ pcap) */
    volatile unsigned int       rawlen; /* v43: байт в raw (42 = сервер 'A');
                                         * пишется ДО seq-bump (контракт) */
    volatile unsigned char      raw[C2B_K27_RAWMAX]; /* v43: 'A' от ff×4 */
} c2b_k27_A_t;

/* Чистый сканер одного вхождения ff×4+'A'|'B' с offset off в буфере p[0..n).
 * Возвращает 1 и заполняет cls/chal/proto/val; 0 = нет вхождения.
 * v43: mo (если не NULL) = офсет НАЧАЛА вхождения (ff×4) в p — нужен
 * продюсеру для капчера полных байт 'A' (raw от ff×4).
 * 'A'-форма (run379/380 54B): ff×4+cls+chal4+proto+pad5+val4 = мин. хвост 19B
 * (для 'B' хвост короче, но общий гейт 19 = безопасен: скан по ff×4+'A'/'B'). */
static inline int c2b_k27_scan_clv2(const unsigned char *p, unsigned n,
                                    unsigned off, unsigned char *cls,
                                    unsigned int *chal, unsigned int *proto,
                                    unsigned int *val, unsigned int *mo)
{
    unsigned i;
    if (!p || n < 14 || off + 14 > n) return 0;
    for (i = off; i + 14 <= n; i++) {
        if (p[i] == 0xff && p[i + 1] == 0xff && p[i + 2] == 0xff &&
            p[i + 3] == 0xff && (p[i + 4] == 'A' || p[i + 4] == 'B')) {
            if (mo) *mo = i;
            *cls = p[i + 4];
            *chal = (unsigned int)p[i + 5] |
                    ((unsigned int)p[i + 6] << 8) |
                    ((unsigned int)p[i + 7] << 16) |
                    ((unsigned int)p[i + 8] << 24);
            *proto = p[i + 9];
            if (p[i + 4] == 'B' || i + 19 > n) {
                /* 'B': val = u32 @+10 (старая модель, не используется) либо
                 * 'A' короче 19B: val = то, что осталось (гейт выше) */
                *val = (unsigned int)p[i + 10] |
                       ((unsigned int)p[i + 11] << 8) |
                       ((unsigned int)p[i + 12] << 16) |
                       ((unsigned int)p[i + 13] << 24);
            } else {
                /* 'A' v41b: pad5 @[10..14], val = LE u32 @[15..18] */
                *val = (unsigned int)p[i + 15] |
                       ((unsigned int)p[i + 16] << 8) |
                       ((unsigned int)p[i + 17] << 16) |
                       ((unsigned int)p[i + 18] << 24);
            }
            return 1;
        }
    }
    return 0;
}

/* v46 DEC-X: чистый гейт наблюдателя S>C-верdictов (c2b_g126_decx в хуке,
 * pre-rate-gate). ОБОСНОВАНИЕ (run385-pcap + логи, 17:38-раунд): reliable
 * 0x81-кадры 45/46B = сессионные верdict-протобуфы ({inner{4x0,code}}:
 * run383 code=0x9f01=159 (reject), run385 code=0x72=114 x2 @+22s) — на
 * проводе есть, в DEC32-логах НЕТ (rate-гейт first-64+every-8th пропустил
 * оба события; grep len=00000039/0000002d = только 'A'-кадры). Снифф =
 * pre-gate = точка 100%-захвата.
 * v47-ПОПРАВКА (run386-pcap, 18:09-раунд): 49B-кадр = ТОТ ЖЕ класс, но
 * ПРОТОБУФ ЧИТАЕТСЯ ПРЯМО НА ПРОВОДЕ (0a10 0a0e 080010001801200b 2872
 * 3000 3800 = {inner{c=1,d=11},e=114,f=0,g=0} = ПИНГ-СТАТУС, НЕ reject;
 * e=114/159 = RTT-оценка, 33B-кадры = {c=2} keepalive ~10.2s). Расшиф-
 * рованная длина = wire - (заголовок+tag) ≈ 23B для 49B-wire => пол
 * 24B ПРОПУСКАЛ класс. Окно: 20..72B (49-10-16=23; 46-10-16=20) ИЛИ
 * голова 0x22..0x25. Эмпирика run386 DEC32: 'A' = 54B plaintext, 7B =
 * SNP-keepalive (за полом = правильно, дедап-шум). */
static inline int c2b_decx_want(unsigned int len, unsigned char c0)
{
    if (len == 0u) return 0;
    if (len >= 20u && len <= 72u) return 1;
    if (c0 >= 0x22u && c0 <= 0x25u) return 1;
    return 0;
}

/* v47 K27K: чистый сборщик 'k'-БЕЗ-ff×4 (in-channel uplink, единственная
 * непроверенная форма после 5 смертей 2047 + 1 тишины).
 * РАЦИОНАЛ (run386, 18:09-раунд): (1) 0x24 PARSE_ERROR "2047" = варинт-
 * взрыв: in-channel получатель = NET-фреймер, первый байт 0xff = варинт-
 * размер -> кламп 2047 -> parse-error; ff×4-ASCII ('qconnect') терпим,
 * ff×4-'k'-бинарный = смерть (365/368/369/370/373). (2) СТРИПНУТЫЙ 496B
 * (run366, без ff×4 И без 'k'-заголовка) = тишина: нет опкода 'k' =
 * подключечный обработчик не вызывается. (3) СЕРЕДИНА = НЕ ПРОВЕРЕНА:
 * 'k'+ver+proto+chal+тикет БЕЗ ff×4 = опкод жив, варинт-взрыва нет.
 * ФОРМА: g_kfull (513B: ff×4+'k'+'96\0'+00 03+00 00+chal@13+тикет)
 * -> копия байтов [4..klen) = 509B, chal патчится на @9..12 (LE) в
 * in-channel-'A'-chal. Отправка = unreliable (flags=0, run366-урок:
 * reliable-lane = парсер; unreliable = безопасный класс). */
static inline int c2b_k27k_build(const unsigned char *kfull, unsigned int klen,
                                 unsigned int chal, unsigned char *out,
                                 unsigned int outcap, unsigned int *outlen)
{
    unsigned int i;
    if (!kfull || !out || !outlen) return 0;
    if (klen < 32u || klen > 1100u) return 0;      /* разумный 'k' */
    if (kfull[0] != 0xff || kfull[1] != 0xff ||
        kfull[2] != 0xff || kfull[3] != 0xff) return 0;   /* нет connless */
    if (kfull[4] != 'k') return 0;                 /* не 'k'-опкод */
    if (outcap < klen - 4u) return 0;
    for (i = 4u; i < klen; i++) out[i - 4u] = kfull[i];
    *outlen = klen - 4u;
    /* chal u32 LE @9 (= @13 в исходном минус 4) */
    if (*outlen >= 13u) {
        out[9] = (unsigned char)(chal & 0xff);
        out[10] = (unsigned char)((chal >> 8) & 0xff);
        out[11] = (unsigned char)((chal >> 16) & 0xff);
        out[12] = (unsigned char)((chal >> 24) & 0xff);
    }
    return 1;
}

#endif /* C2B_K27_H */
