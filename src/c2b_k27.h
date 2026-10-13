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

typedef struct c2b_k27_A {
    volatile unsigned int       seq;    /* +1 на каждый новый 'A' */
    volatile unsigned int       chal;   /* LE u32 @ 'A'+5 */
    volatile unsigned int       proto;  /* байт @ 'A'+9 */
    volatile unsigned int       val;    /* LE u32 @ 'A'+10 */
    volatile unsigned long long gcm;    /* gcm-контекст расшифровки (пост-фактум
                                         * атрибуция сессии: in=<8B> ↔ pcap) */
} c2b_k27_A_t;

/* Чистый сканер одного вхождения ff×4+'A'|'B' с offset off в буфере p[0..n).
 * Возвращает 1 и заполняет cls/chal/proto/val; 0 = нет вхождения.
 * Мин. длина хвоста = 14B (ff×4 + класс + chal4 + proto + val4). */
static inline int c2b_k27_scan_clv2(const unsigned char *p, unsigned n,
                                    unsigned off, unsigned char *cls,
                                    unsigned int *chal, unsigned int *proto,
                                    unsigned int *val)
{
    unsigned i;
    if (!p || n < 14 || off + 14 > n) return 0;
    for (i = off; i + 14 <= n; i++) {
        if (p[i] == 0xff && p[i + 1] == 0xff && p[i + 2] == 0xff &&
            p[i + 3] == 0xff && (p[i + 4] == 'A' || p[i + 4] == 'B')) {
            *cls = p[i + 4];
            *chal = (unsigned int)p[i + 5] |
                    ((unsigned int)p[i + 6] << 8) |
                    ((unsigned int)p[i + 7] << 16) |
                    ((unsigned int)p[i + 8] << 24);
            *proto = p[i + 9];
            *val = (unsigned int)p[i + 10] |
                   ((unsigned int)p[i + 11] << 8) |
                   ((unsigned int)p[i + 12] << 16) |
                   ((unsigned int)p[i + 13] << 24);
            return 1;
        }
    }
    return 0;
}

#endif /* C2B_K27_H */
