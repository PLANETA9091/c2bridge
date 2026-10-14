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
 *
 * V82 (run485-пкп-декод, поле-в-поле): движковый 0x22 СТАЛ ДРУГИМ —
 * [22][fb 00] 254B-контент (legacy u16-LE msglen=251), ВНУТРИ уже есть
 * f4 = ТОТ ЖЕ 174B нативный серт (серт-инжект в движок РАБОТАЕТ), но
 * форма всё ещё смертельна в трёх местах:
 *   (1) [fb 00]-префикс = инвалил-протобуф под современным парсером
 *       (key 0xfb = f31/wt3 start-group = мгновенный фейл — тот же класс,
 *       что run372-аутопсия [4c 00]);
 *   (2) f2 = СЛОМАННЫЙ wt2 (0x12 + 8 сырых байт, БЕЗ LEN) — v50-баг жив;
 *   (3) f7 = 38B БЕЗ подписи (0a24{f1=1,f2=32B DH}) против принятой 117B
 *       (0a75 + подпись). v50-рационал: f7 движка оставляем (DH-консис-
 *       тентность, приват у движка); сиг-проверка = 0x24 named-reject =
 *       v51-вход.
 * Строитель v2 = ход по полям: старая форма (f5@26, серт = капчуренный
 * аргумент) / новая (f4@26, серт = из пакета, аргумент игнорируется).
 * Вывод ОДИНАКОВ для обеих: [22][0d cid][11 chal][19 sid][22 varint cert]
 * [29 ts][30 ping][3a f7] — современная принятая форма (run485 33188).
 * Старая ветка байт-в-байт = v50-поведение (селфтест v50f_want 252B).
 */
#ifndef C2B_CRT_H
#define C2B_CRT_H

/* Макс. капчур f4-блоба сертификата (174 = run391-экземпляр; запас x1.5). */
#define C2B_CRT_CERTMAX 256

/* v82-хелпер: varint-чтение (LE 7-битный, максимум 2 байта — наших длин
 * хватает: cert<=256, ping<16384). Возврат = число байт (0 = облом). */
static inline unsigned int c2b_crt_varlen(const unsigned char *p,
                                          unsigned int o, unsigned int n,
                                          unsigned int *out_v)
{
    unsigned int v = 0, sh = 0, k = 0;
    if (!out_v) return 0;
    while (k < 2u) {
        unsigned char x;
        if (o + k >= n) return 0;
        x = p[o + k]; k++;
        v |= ((unsigned int)(x & 0x7f)) << sh;
        if (!(x & 0x80)) { *out_v = v; return k; }
        sh += 7;
    }
    return 0;
}

/* v82-хелпер: varint-запись (каноническая, 1-2 байта для наших длин).
 * Возврат = число записанных байт. clen=174 -> ae 01 (= v50-фикс-форма). */
static inline unsigned int c2b_crt_varput(unsigned char *out, unsigned int v)
{
    unsigned int k = 0;
    for (;;) {
        unsigned char b = (unsigned char)(v & 0x7f);
        v >>= 7;
        if (v) b |= 0x80;
        out[k++] = b;
        if (!v) break;
    }
    return k;
}

/* Сигнатура СЛОМАННОГО 0x22 движка. v82 = ДВЕ формы с общим головным
 * лэйаутом [22][u16-LE msglen][0d cid4][12 chal-8raw][19 sid8]...
 *   СТАРАЯ (run391, 79B):  ...@26=29(ts) @35=30 @37=40(f8) @39=3a(f7)
 *   НОВАЯ   (run485, 254B): ...@26=22(f4 cert, varint-len, серт внутри)
 * Дискриминатор чистой формы моста [22][0d...]: p[1]=0x0d = ключ f1, НО
 * тогда mlen = 0x0d | cid0<<8 >= 0x0d00 > 640 ИЛИ mlen+3 > n ИЛИ p[3] !=
 * 0x0d — все три красят её в отказ. mlen-консистентность = главный
 * гвард: legacy-форма несёт НАСТОЯЩУЮ длину тела (76/251), чистая — нет.
 * Минимум = 79B (старая форма целиком). */
static inline int c2b_crt_is_eng(const unsigned char *p, unsigned int n)
{
    unsigned int mlen;
    if (!p || n < 79u) return 0;
    if (p[0] != 0x22) return 0;                 /* packet type */
    if (p[3] != 0x0d) return 0;                 /* f1 fixed32 */
    if (p[8] != 0x12) return 0;                 /* f2 (сломанный wt2) */
    if (p[17] != 0x19) return 0;                /* f3 fixed64 */
    mlen = (unsigned int)p[1] | ((unsigned int)p[2] << 8);
    if (mlen < 76u || mlen > 640u) return 0;    /* разумный класс тел */
    if (mlen + 3u > n) return 0;                /* длина = консистентна */
    if (p[26] == 0x29) {                        /* СТАРАЯ форма (без серта) */
        if (p[35] != 0x30) return 0;            /* f6 varint */
        if (p[37] != 0x40) return 0;            /* f8 varint (compat-хвост) */
        if (p[39] != 0x3a) return 0;            /* f7 LEN */
        return 1;
    }
    if (p[26] == 0x22) {                        /* НОВАЯ форма (серт внутри) */
        unsigned int clen, k, o;
        k = c2b_crt_varlen(p, 27, mlen + 3u, &clen);
        if (!k || clen < 32u || clen > C2B_CRT_CERTMAX) return 0;
        o = 27u + k + clen;
        if (o + 9u > mlen + 3u) return 0;       /* ts целиком в теле */
        if (p[o] != 0x29) return 0;             /* f5 сразу за сертом */
        return 1;
    }
    return 0;
}

/* Чистый сборщик v82: движковый 0x22 (любая из двух форм) -> корректный
 * 0x22 современной принятой формы (поля движка + серт + f7 движка верба-
 * тим). Серт: НОВАЯ форма = из пакета (аргумент игнорируется), СТАРАЯ =
 * капчуренный блоб моста (аргумент обязателен — v50-контракт). Возвращает
 * длину out (0 = отказ: форма/кап не те). Смещения головного лэйаута
 * (0x22 включительно, ОБЕ формы): [3]=0d [4..7]=cid [8]=12 [9..16]=chal
 * [17]=19 [18..25]=sid; дальше — ход по полям (varlen). f8 (старая форма,
 * [40 <v>] @37..38) = ДРОП: у принятой формы нет. */
static inline unsigned int c2b_crt_build(const unsigned char *eng,
                                         unsigned int elen,
                                         const unsigned char *cert,
                                         unsigned int clen,
                                         unsigned char *out,
                                         unsigned int outcap)
{
    unsigned int oi = 0, mlen, f7len, need, o;
    unsigned int ts_o, ping_o, ping_n, f7_o, vl;
    const unsigned char *cb;
    unsigned int cl;
    if (!eng || !out) return 0;
    if (!c2b_crt_is_eng(eng, elen)) return 0;
    mlen = (unsigned int)eng[1] | ((unsigned int)eng[2] << 8);
    cb = cert; cl = clen;
    if (eng[26] == 0x29) {                      /* СТАРАЯ форма (v50) */
        if (!cert || !clen) return 0;           /* капчуренный обязателен */
        if (clen > C2B_CRT_CERTMAX) return 0;
        ts_o = 27u; ping_o = 35u; ping_n = 1u; f7_o = 40u;
        /* ping_o = ПОЗИЦИЯ КЛЮЧА 0x30 (@35), значение = @36 = ping_o+1
         * (единый контракт с новой веткой: emit = eng[ping_o+1..]); */
    } else {                                    /* НОВАЯ форма (серт в пакете) */
        unsigned int pv, kk;
        kk = c2b_crt_varlen(eng, 27, mlen + 3u, &cl);
        if (!kk || cl < 32u || cl > C2B_CRT_CERTMAX) return 0;
        cb = eng + 27u + kk;
        o = 27u + kk + cl;
        if (eng[o] != 0x29) return 0;           /* f5 ts */
        ts_o = o + 1u;
        ping_o = o + 9u;
        if (eng[ping_o] != 0x30) return 0;      /* f6 ping */
        kk = c2b_crt_varlen(eng, ping_o + 1u, mlen + 3u, &pv);
        if (!kk) return 0;
        ping_n = kk;
        o = ping_o + 1u + kk;
        if (eng[o] != 0x3a) return 0;           /* f7 LEN */
        f7_o = o + 1u;                          /* f7_o = позиция LEN-байта
                                                 * (контракт старой ветки:
                                                 * @40 = LEN, байты = +1) */
    }
    f7len = eng[f7_o];
    if (f7len < 8u || f7len > 127u) return 0;   /* разумный crypto */
    if (f7_o + 1u + f7len > mlen + 3u) return 0; /* f7 целиком в теле */
    vl = (cl < 128u) ? 1u : 2u;                 /* varint-длина серта */
    need = 1u + 5u + 9u + 9u + 1u + vl + cl + 9u + 1u + ping_n + 2u + f7len;
    /*        22   f1    f2    f3   f4key varint cert  f5   f6    f7hdr f7 */
    if (outcap < need) return 0;
    out[oi++] = 0x22;                                   /* packet type */
    out[oi++] = 0x0d;                                   /* f1 fixed32 cid */
    out[oi++] = eng[4]; out[oi++] = eng[5];
    out[oi++] = eng[6]; out[oi++] = eng[7];
    out[oi++] = 0x11;                                   /* f2 fixed64 chal
                                                         * (фикс wt2->wt1:
                                                         * те же 8 байт) */
    {   unsigned int qq; for (qq = 9u; qq < 17u; qq++) out[oi++] = eng[qq]; }
    out[oi++] = 0x19;                                   /* f3 fixed64 sid */
    {   unsigned int qq; for (qq = 18u; qq < 26u; qq++) out[oi++] = eng[qq]; }
    out[oi++] = 0x22;                                   /* f4 LEN cert */
    oi += c2b_crt_varput(out + oi, cl);
    {   unsigned int qq; for (qq = 0; qq < cl; qq++) out[oi++] = cb[qq]; }
    out[oi++] = 0x29;                                   /* f5 fixed64 ts */
    {   unsigned int qq; for (qq = 0; qq < 8u; qq++) out[oi++] = eng[ts_o + qq]; }
    out[oi++] = 0x30;                                   /* f6 varint ping */
    {   unsigned int qq;
        for (qq = 0; qq < ping_n; qq++) out[oi++] = eng[ping_o + 1u + qq]; }
    /* f8 (старая форма: [40 <v>] @37..38) = ДРОП: у принятой формы нет;
     * ключ не идентифицирован, повторять неизвестное = риск, дроп = форма
     * моста. Новая форма f8 не содержит. */
    out[oi++] = 0x3a;                                   /* f7 LEN crypto */
    out[oi++] = (unsigned char)f7len;
    {   unsigned int qq;
        for (qq = 0; qq < f7len; qq++) out[oi++] = eng[f7_o + 1u + qq]; }
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
