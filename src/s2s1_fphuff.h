/* s2s1_fphuff.h — СГЕНЕРИРОВАНО scripts/step_g9_huff_gen.py, не править руками.
 * Хаффман-дерево field path (CS2 PacketEntities, G-4): точная реплика
 * demoinfocs-golang sendtablescs2/{field_path.go,huffman.go} (веса 40 op,
 * слияние min-heap, tie-break Value()>=, bit0=left/bit1=right).
 * Узлов: 79, max длина кода: 17 бит, средняя (по весам): 2.695 бит.
 * C2B_FPOP_* — порядок fieldPathTable; коды op — для C-энкодера selftest.
 */
#ifndef S2S1_FPHUFF_H
#define S2S1_FPHUFF_H

#define C2B_FP_MAXNODES 79
#define C2B_FP_NOPS 40

/* индексы op: PlusOne, PlusTwo, PlusThree, PlusFour, PlusN, PushOneLeftDeltaZeroRightZero, PushOneLeftDeltaZeroRightNonZero, PushOneLeftDeltaOneRightZero, PushOneLeftDeltaOneRightNonZero, PushOneLeftDeltaNRightZero, PushOneLeftDeltaNRightNonZero, PushOneLeftDeltaNRightNonZeroPack6Bits, PushOneLeftDeltaNRightNonZeroPack8Bits, PushTwoLeftDeltaZero, PushTwoPack5LeftDeltaZero, PushThreeLeftDeltaZero, PushThreePack5LeftDeltaZero, PushTwoLeftDeltaOne, PushTwoPack5LeftDeltaOne, PushThreeLeftDeltaOne, PushThreePack5LeftDeltaOne, PushTwoLeftDeltaN, PushTwoPack5LeftDeltaN, PushThreeLeftDeltaN, PushThreePack5LeftDeltaN, PushN, PushNAndNonTopological, PopOnePlusOne, PopOnePlusN, PopAllButOnePlusOne, PopAllButOnePlusN, PopAllButOnePlusNPack3Bits, PopAllButOnePlusNPack6Bits, PopNPlusOne, PopNPlusN, PopNAndNonTopographical, NonTopoComplex, NonTopoPenultimatePlusOne, NonTopoComplexPack4Bits, FieldPathEncodeFinish */

typedef struct { short left, right, op; } c2b_fph_node_t;
static const c2b_fph_node_t g_fph_nodes[C2B_FP_MAXNODES] = {
    { 1, 2, 78 },   /* node v=78 */
    { -32768, -32768, 0 },   /* LEAF op=0 */
    { 3, 4, 77 },   /* node v=77 */
    { -32768, -32768, 39 },   /* LEAF op=39 */
    { 5, 76, 76 },   /* node v=76 */
    { 6, 11, 74 },   /* node v=74 */
    { 7, 8, 72 },   /* node v=72 */
    { -32768, -32768, 8 },   /* LEAF op=8 */
    { 9, 10, 70 },   /* node v=70 */
    { -32768, -32768, 2 },   /* LEAF op=2 */
    { -32768, -32768, 29 },   /* LEAF op=29 */
    { 12, 13, 73 },   /* node v=73 */
    { -32768, -32768, 4 },   /* LEAF op=4 */
    { 14, 67, 71 },   /* node v=71 */
    { 15, 62, 68 },   /* node v=68 */
    { 16, 61, 64 },   /* node v=64 */
    { 17, 18, 61 },   /* node v=61 */
    { -32768, -32768, 30 },   /* LEAF op=30 */
    { 19, 20, 60 },   /* node v=60 */
    { -32768, -32768, 38 },   /* LEAF op=38 */
    { 21, 60, 59 },   /* node v=59 */
    { 22, 59, 58 },   /* node v=58 */
    { 23, 36, 57 },   /* node v=57 */
    { 24, 29, 54 },   /* node v=54 */
    { 25, 28, 52 },   /* node v=52 */
    { 26, 27, 40 },   /* node v=40 */
    { -32768, -32768, 35 },   /* LEAF op=35 */
    { -32768, -32768, 34 },   /* LEAF op=34 */
    { -32768, -32768, 27 },   /* LEAF op=27 */
    { 30, 33, 51 },   /* node v=51 */
    { 31, 32, 42 },   /* node v=42 */
    { -32768, -32768, 25 },   /* LEAF op=25 */
    { -32768, -32768, 24 },   /* LEAF op=24 */
    { 34, 35, 41 },   /* node v=41 */
    { -32768, -32768, 33 },   /* LEAF op=33 */
    { -32768, -32768, 28 },   /* LEAF op=28 */
    { 37, 44, 56 },   /* node v=56 */
    { 38, 43, 53 },   /* node v=53 */
    { 39, 40, 48 },   /* node v=48 */
    { -32768, -32768, 13 },   /* LEAF op=13 */
    { 41, 42, 47 },   /* node v=47 */
    { -32768, -32768, 15 },   /* LEAF op=15 */
    { -32768, -32768, 14 },   /* LEAF op=14 */
    { -32768, -32768, 6 },   /* LEAF op=6 */
    { 45, 52, 55 },   /* node v=55 */
    { 46, 49, 50 },   /* node v=50 */
    { 47, 48, 44 },   /* node v=44 */
    { -32768, -32768, 21 },   /* LEAF op=21 */
    { -32768, -32768, 20 },   /* LEAF op=20 */
    { 50, 51, 43 },   /* node v=43 */
    { -32768, -32768, 23 },   /* LEAF op=23 */
    { -32768, -32768, 22 },   /* LEAF op=22 */
    { 53, 56, 49 },   /* node v=49 */
    { 54, 55, 46 },   /* node v=46 */
    { -32768, -32768, 17 },   /* LEAF op=17 */
    { -32768, -32768, 16 },   /* LEAF op=16 */
    { 57, 58, 45 },   /* node v=45 */
    { -32768, -32768, 19 },   /* LEAF op=19 */
    { -32768, -32768, 18 },   /* LEAF op=18 */
    { -32768, -32768, 5 },   /* LEAF op=5 */
    { -32768, -32768, 36 },   /* LEAF op=36 */
    { -32768, -32768, 10 },   /* LEAF op=10 */
    { 63, 64, 65 },   /* node v=65 */
    { -32768, -32768, 7 },   /* LEAF op=7 */
    { 65, 66, 62 },   /* node v=62 */
    { -32768, -32768, 12 },   /* LEAF op=12 */
    { -32768, -32768, 37 },   /* LEAF op=37 */
    { 68, 73, 69 },   /* node v=69 */
    { 69, 70, 66 },   /* node v=66 */
    { -32768, -32768, 9 },   /* LEAF op=9 */
    { 71, 72, 63 },   /* node v=63 */
    { -32768, -32768, 31 },   /* LEAF op=31 */
    { -32768, -32768, 26 },   /* LEAF op=26 */
    { 74, 75, 67 },   /* node v=67 */
    { -32768, -32768, 32 },   /* LEAF op=32 */
    { -32768, -32768, 3 },   /* LEAF op=3 */
    { 77, 78, 75 },   /* node v=75 */
    { -32768, -32768, 1 },   /* LEAF op=1 */
    { -32768, -32768, 11 }    /* LEAF op=11 */
};

typedef struct { unsigned code; unsigned char len; } c2b_fph_code_t;
static const c2b_fph_code_t g_fph_codes[40] = {
    { 0x0u,  1u }, /* PlusOne                                w=36271 */
    { 0xEu,  4u }, /* PlusTwo                                w=10334 */
    { 0x32u,  6u }, /* PlusThree                              w=1375 */
    { 0xDFu,  8u }, /* PlusFour                               w=646 */
    { 0x1Au,  5u }, /* PlusN                                  w=4128 */
    { 0xD8Du, 12u }, /* PushOneLeftDeltaZeroRightZero          w=35 */
    { 0x6C65u, 15u }, /* PushOneLeftDeltaZeroRightNonZero       w=3 */
    { 0xDAu,  8u }, /* PushOneLeftDeltaOneRightZero           w=521 */
    { 0x18u,  5u }, /* PushOneLeftDeltaOneRightNonZero        w=2942 */
    { 0xDCu,  8u }, /* PushOneLeftDeltaNRightZero             w=560 */
    { 0xD9u,  8u }, /* PushOneLeftDeltaNRightNonZero          w=471 */
    { 0xFu,  4u }, /* PushOneLeftDeltaNRightNonZeroPack6Bits w=10530 */
    { 0x1B6u,  9u }, /* PushOneLeftDeltaNRightNonZeroPack8Bits w=251 */
    { 0xD8C8u, 16u }, /* PushTwoLeftDeltaZero                   w=0 */
    { 0x1B193u, 17u }, /* PushTwoPack5LeftDeltaZero              w=0 */
    { 0x1B192u, 17u }, /* PushThreeLeftDeltaZero                 w=0 */
    { 0x1B19Du, 17u }, /* PushThreePack5LeftDeltaZero            w=0 */
    { 0x1B19Cu, 17u }, /* PushTwoLeftDeltaOne                    w=0 */
    { 0x1B19Fu, 17u }, /* PushTwoPack5LeftDeltaOne               w=0 */
    { 0x1B19Eu, 17u }, /* PushThreeLeftDeltaOne                  w=0 */
    { 0x1B199u, 17u }, /* PushThreePack5LeftDeltaOne             w=0 */
    { 0x1B198u, 17u }, /* PushTwoLeftDeltaN                      w=0 */
    { 0x1B19Bu, 17u }, /* PushTwoPack5LeftDeltaN                 w=0 */
    { 0x1B19Au, 17u }, /* PushThreeLeftDeltaN                    w=0 */
    { 0xD8C5u, 16u }, /* PushThreePack5LeftDeltaN               w=0 */
    { 0xD8C4u, 16u }, /* PushN                                  w=0 */
    { 0x1BBu,  9u }, /* PushNAndNonTopological                 w=310 */
    { 0x6C61u, 15u }, /* PopOnePlusOne                          w=2 */
    { 0xD8C7u, 16u }, /* PopOnePlusN                            w=0 */
    { 0x33u,  6u }, /* PopAllButOnePlusOne                    w=1837 */
    { 0x1B0u,  9u }, /* PopAllButOnePlusN                      w=149 */
    { 0x1BAu,  9u }, /* PopAllButOnePlusNPack3Bits             w=300 */
    { 0xDEu,  8u }, /* PopAllButOnePlusNPack6Bits             w=634 */
    { 0xD8C6u, 16u }, /* PopNPlusOne                            w=0 */
    { 0xD8C1u, 16u }, /* PopNPlusN                              w=0 */
    { 0xD8C0u, 16u }, /* PopNAndNonTopographical                w=1 */
    { 0x6C7u, 11u }, /* NonTopoComplex                         w=76 */
    { 0x1B7u,  9u }, /* NonTopoPenultimatePlusOne              w=271 */
    { 0x362u, 10u }, /* NonTopoComplexPack4Bits                w=99 */
    { 0x2u,  2u }  /* FieldPathEncodeFinish                  w=25474 */
};

#endif /* S2S1_FPHUFF_H */
