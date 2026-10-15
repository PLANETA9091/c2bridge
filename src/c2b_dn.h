/* c2b_dn.h — v94/v95: DOWNLINK PLAINTEXT RING — общий контракт
 * producer (c2b_client_hook64.so, LD_PRELOAD, g126-dec-tap) =>
 * consumer (c2bridge64.so, g97-тред, c2b_s2dn_maybe).
 *
 * КОНТЕКСТ (S2S1 STEP-3a): расшифрованный серверный SNP-plaintext =
 * ЕДИНСТВЕННЫЙ живой источник S2-даунлинка (PM-never-fires: движок на
 * этапе коннекта не зовёт CNetChan::ProcessMessages — факт 496/500/501).
 * Каждый decrypt (site C = ctr32 fast path + site D = 4-arg) отдаёт
 * out = ГОТОВЫЙ plaintext (v95: до 0x8000Б — signon-блобы REL идут в
 * пересборку) — кладём в ring, мост разбирает SNP-кадры (c2b_snpw_walk),
 * собирает REL-поток (v95) и пишет spec-логи (s2dn/s2t).
 *
 * КОНТРАКТ (тот же стиль, что c2b_k27.h): producer пишет поля записи,
 * ЗАТЕМ bump wi (release-RMW). consumer: load wi (acquire) -> читает
 * rec -> свой ri (локальный, мост). Переполнение = overwrite-oldest:
 * если wi - ri >= CAP, consumer прыгает на wi-(CAP-1) (потерю считает).
 * Телеметрия-grade: рваные чтения = допускаются (дедап/санити len).
 */
#ifndef C2B_DN_H
#define C2B_DN_H

/* v95: 2048 -> 0x8000 — гейт dec_capture (0x800) теперь только на лог-пути;
 * ring обязана видеть ПОЛНЫЙ plaintext (signon-блобы ClassInfo/FSV > 2КБ). */
#define C2B_DNR_CAP 8u
#define C2B_DNR_MAX 0x8000u

typedef struct c2b_dn_rec {
    volatile unsigned int       len;   /* <= C2B_DNR_MAX; пишется ДО wi-bump */
    volatile unsigned long long gcm;   /* gcm-контекст (атрибуция сессии) */
    unsigned char               data[C2B_DNR_MAX];
} c2b_dn_rec_t;

typedef struct c2b_dn {
    volatile unsigned int       wi;    /* producer: всего записей (монотонный) */
    c2b_dn_rec_t                rec[C2B_DNR_CAP];
} c2b_dn_t;

/* Размер структуры = фиксированный ABI (объекта-пару .so не перекосит):
 * 4 + pad4 + 8*(4+pad4+8+32768) = 8 + 8*32784 = 262280Б (v95). */
#endif /* C2B_DN_H */
