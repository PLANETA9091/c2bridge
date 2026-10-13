/* c2b_crt.h — v50: CRT-FIX — ПЕРЕПИСЫВКА 0x22 ConnectRequest компат-GNS
 * движка в релей-принятую форму (общий контракт: чистые функции =
 * selftest-ируемые; wire-сайты = c2bridge.c sendto/sendmsg-хуки).
 *
 * КОНТЕКСТ (run391-pcap байт-в-байт, 20:39/20:10-раунды):
 *  - ДВИЖОК (libsteamnetworkingsockets.so__cb0ca8, из :27005, x40 ретраев,
 *    релей = МОЛЧАНИЕ) шлёт СЛОМАННЫЙ 0x22 (512B с нулевым падом):
 *      [22][4c 00]                      <- u16-LE len-префикс 0x004c = 76:
 *                                          релей парсит key 0x4c = f9/wt4
 *                                          (end-group) = МГНОВЕННЫЙ фейл
 *                                          (v35-вскрытие, run372-аутопсия)
 *      [0d <cid4>]                      <- f1 fixed32 client_connection_id
 *      [12 <chal8>]                     <- f2 ОБЛОМ: key wt2 (LEN), но НЕТ
 *                                          байта длины — 8 сырых байт; ва-
 *                                          ринт-парс релея читает a9 24 как
 *                                          длину 4649 > хвост = EOF-фейл
 *      [19 <sid8>]                      <- f3 fixed64 legacy_client_steam_id
 *      [29 <ts8>]                       <- f5 fixed64 time_sent
 *      [30 14]                          <- f6 varint ping_est_ms = 20
 *      [40 0d]                          <- f8 varint (у принятой формы НЕТ)
 *      [3a 26 <38B>]                    <- f7 crypto: {f1{f1=1,f2=32B DH-pub}}
 *                                          БЕЗ подписи (compat = нет CM-cert
 *                                          хука: 'Requesting cert' висит,
 *                                          fallback = self-signed temp)
 *      [0000...]                        <- нулевой пад до 512
 *  - МОСТ (steamclient GNSLIB, сессионные порты, x4, релей = 0x23 ConnectOK
 *    = ПРИНЯТО) шлёт ЧИСТЫЙ 0x22 (332B):
 *      [22][0d cid4][11 chal8][19 sid8][22 ae01 <174B cert-signed>]
 *      [29 ts8][30 a001=160][3a 75 <117B crypto с подписью>]
 *    cert-signed f4 = CA 0xb68350cff5aa391b (= 13151444190962006299, тот
 *    самый 'CA key' из Bad-cert-лога движка!), identity = ТОТ ЖЕ steamid
 *    (76561198647433947 = db5af52801001001 в ОБЕИХ формах = shared-identity).
 *
 * V50-ДИЗАЙН (20:10-поправка леdger'a): инжект сертификата в движок БЕСПО-
 * ЛЕЗЕН без фикса сериализатора; САМЫЙ дешёвый ход = байтовая хирургия на
 * send-слое: перехватить исходящий 0x22 движка (сигнатура [22][4c 00]),
 * собрать корректный protobuf = ПОЛЯ ДВИЖКА (cid/chal/sid/ts/ping + f7
 * crypto ДВИЖКА вербатим — DH-консистентность: приватный DH-ключ у движка!)
 * + f4 = ЗАХВАЧЕННЫЙ блоб сертификата МОСТА (капчер с исходящих чистых
 * 0x22 моста: [22][0d...] -> f4). f8 (у принятой формы отсутствует) = дроп.
 *
 * ЧЕГО НЕ ДЕЛАЕМ (сознательно, v51+):
 *  - f7 МОСТА НЕ СПЛАЙСИМ: crypto.key_exchange = ЭФЕМЕРНЫЙ DH-пубк движка;
 *    блоб моста = чужой DH-пубк (приват у моста) => DH-мисматч = смерть на
 *    первом шифрованном пакете. Оставляем f7 движка: если релей не проверя-
 *    ет подпись crypto на accept-стадии — 0x23 ConnectOK К ДВИЖКУ = веха,
 *    и шифрованная стадия = консистентна (DH свой).
 *  - подпись ed25519 под f7 движка = v51 (экспорт приватника моста из кучи
 *    steamclient по пабкич-cert'а 0f9d1db0...).
 *
 * ОЖИДАЕМЫЕ ИСХОДЫ run (решение-дерево): (а) 0x23 ConnectOK к :27005 =
 * ВЕХА (accept-путь доказан; дальше = шифростадия); (б) 0x24 named-reject =
 * требование названо (сигнатура crypto / repeat-challenge) = v51-вход;
 * (в) тишина = релей молча дропает (сиг-проверка до ответа) = v51 = подпись.
 */
#ifndef C2B_CRT_H
#define C2B_CRT_H

/* Макс. капчур f4-блоба сертификата (174 = run391-экземпляр; запас x1.5). */
#define C2B_CRT_CERTMAX 256

/* Сигнатура СЛОМАННОГО 0x22 движка: [22][4c 00][0d][..][12]... Полная
 * форма-гвард: ключи f1/f2/f3/f5/f6/f7 на своих местах (run391: форма
 * x40 идентична). Минимум = 79B (0x22 + 4c00 + 76B proto). */
static inline int c2b_crt_is_eng(const unsigned char *p, unsigned int n)
{
    if (!p || n < 79u) return 0;
    if (p[0] != 0x22 || p[1] != 0x4c || p[2] != 0x00) return 0;
    if (p[3] != 0x0d) return 0;                 /* f1 fixed32 */
    if (p[8] != 0x12) return 0;                 /* f2 (сломанный wt2) */
    if (p[17] != 0x19) return 0;                /* f3 fixed64 */
    if (p[26] != 0x29) return 0;                /* f5 fixed64 */
    if (p[35] != 0x30) return 0;                /* f6 varint */
    if (p[37] != 0x40) return 0;                /* f8 varint (compat-хвост) */
    if (p[39] != 0x3a) return 0;                /* f7 LEN */
    return 1;
}

/* Чистый сборщик: движковый 0x22 + блоб сертификата моста ->
 * корректный 0x22 (поля движка + cert моста + f7 движка вербатим).
 * Возвращает длину out (0 = отказ: форма/кап не те).
 * Смещения (полный кадр, 0x22 включительно):
 *  [0]=22 [1..2]=4c00 [3]=0d [4..7]=cid [8]=12 [9..16]=chal [17]=19
 *  [18..25]=sid [26]=29 [27..34]=ts [35]=30 [36]=ping(1B varint)
 *  [37]=40 [38]=f8val [39]=3a [40]=f7len(1B varint) [41..]=f7 */
static inline unsigned int c2b_crt_build(const unsigned char *eng,
                                         unsigned int elen,
                                         const unsigned char *cert,
                                         unsigned int clen,
                                         unsigned char *out,
                                         unsigned int outcap)
{
    unsigned int oi = 0, f7len, need;
    if (!eng || !cert || !out || !clen) return 0;
    if (clen > C2B_CRT_CERTMAX) return 0;
    if (!c2b_crt_is_eng(eng, elen)) return 0;
    f7len = eng[40];
    if (f7len < 8u || f7len > 127u) return 0;          /* разумный crypto */
    if ((unsigned int)elen < 41u + f7len) return 0;    /* f7 целиком в буфере */
    if (elen > 640u) return 0;                         /* не наш класс */
    need = 1u + 5u + 9u + 9u + 1u + 2u + clen + 9u + 2u + 2u + f7len;
    /*        22   f1    f2    f3   f4key varint cert  f5   f6   f7hdr f7 */
    if (outcap < need) return 0;
    out[oi++] = 0x22;                                   /* packet type */
    out[oi++] = 0x0d;                                   /* f1 fixed32 cid */
    out[oi++] = eng[4]; out[oi++] = eng[5];
    out[oi++] = eng[6]; out[oi++] = eng[7];
    out[oi++] = 0x11;                                   /* f2 fixed64 chal
                                                         * (фикс wt2->wt1:
                                                         * те же 8 байт) */
    {   unsigned int q; for (q = 9u; q < 17u; q++) out[oi++] = eng[q]; }
    out[oi++] = 0x19;                                   /* f3 fixed64 sid */
    {   unsigned int q; for (q = 18u; q < 26u; q++) out[oi++] = eng[q]; }
    out[oi++] = 0x22;                                   /* f4 LEN cert */
    out[oi++] = (unsigned char)((clen & 0x7f) | 0x80);  /* varint: clen<256
                                                         * => max 2 байта */
    out[oi++] = (unsigned char)(clen >> 7);
    {   unsigned int q; for (q = 0; q < clen; q++) out[oi++] = cert[q]; }
    out[oi++] = 0x29;                                   /* f5 fixed64 ts */
    {   unsigned int q; for (q = 27u; q < 35u; q++) out[oi++] = eng[q]; }
    out[oi++] = 0x30;                                   /* f6 varint ping */
    out[oi++] = eng[36];
    /* f8 (compat: [40 <v>] @37..38) = ДРОП: у принятой формы нет; ключ не
     * идентифицирован, повторять неизвестное = риск, дроп = форма моста. */
    out[oi++] = 0x3a;                                   /* f7 LEN crypto */
    out[oi++] = (unsigned char)f7len;
    {   unsigned int q; for (q = 41u; q < 41u + f7len; q++) out[oi++] = eng[q]; }
    return oi;
}

/* Капчер f4-блоба сертификата из ЧИСТОГО 0x22 моста:
 * [22][0d cid4][11 chal8][19 sid8][22 varintlen blob]... Гвард-формы;
 * возвращает 1 и кладёт блоб в cert[*clen] (0 = не наш/облом). */
static inline int c2b_crt_capture(const unsigned char *p, unsigned int n,
                                  unsigned char *cert, unsigned int *clen)
{
    unsigned int o = 25u, ln = 0, sh = 0;   /* 25 = за ключом f4 @24 */
    if (!p || !cert || !clen || n < 30u || n > 640u) return 0;
    if (p[0] != 0x22 || p[1] != 0x0d || p[6] != 0x11 || p[15] != 0x19) return 0;
    if (p[24] != 0x22) return 0;                        /* f4 LEN */
    for (;;) {                                          /* varint-длина */
        unsigned char x;
        if (o >= n || sh > 14) return 0;
        x = p[o++]; ln |= ((unsigned int)(x & 0x7f)) << sh;
        if (!(x & 0x80)) break;
        sh += 7;
    }
    if (ln < 32u || ln > C2B_CRT_CERTMAX || o + ln > n) return 0;
    {   unsigned int q; for (q = 0; q < ln; q++) cert[q] = p[o + q]; }
    *clen = ln;
    return 1;
}

#endif /* C2B_CRT_H */
