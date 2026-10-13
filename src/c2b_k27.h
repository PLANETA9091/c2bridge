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
 * pre-gate = точка 100%-захвата. Класс гейта: расшифрованный 24..72B
 * (wire 45B -> расшифрованный ~28B) ИЛИ голова 0x22..0x25 (relay-управле-
 * ние, in-session форма неизвестна = само наблюдение и есть цель). */
static inline int c2b_decx_want(unsigned int len, unsigned char c0)
{
    if (len == 0u) return 0;
    if (len >= 24u && len <= 72u) return 1;
    if (c0 >= 0x22u && c0 <= 0x25u) return 1;
    return 0;
}

#endif /* C2B_K27_H */
