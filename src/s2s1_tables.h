/* s2s1_tables.h — СГЕНЕРИРОВАНО scripts/step_e2_gen_tables.py, не править руками
 * (фаза G-1: добавлена GE-зона 205/206/207 + би-диры 16..19, см. step_g1_wire_types.py)
 * Ренумерация SVC S2->S1: 20 сообщений. NET: identity (6).
 * Дроп S2-only SVC: 41, 51, 59, 60, 61, 62, 63, 70, 71, 75, 76, 77
 * Дроп S2-only NET: 8, 9, 11, 12, 13, 15
 * Фаза F: XF_RENUM-сообщения (ренумерация полей): 4(CNETMsg_Tick), 7(CNETMsg_SignonState), 40(CSVCMsg_ServerInfo), 44(CSVCMsg_CreateStringTable)
 * Фаза G-1: GE-зона (EBaseGameEvents как прямые wire-типы, доказано шаблонами CNetMessagePB в cs2_client.so): 205->30, 207->25; дроп 201, 202, 203, 204, 208, 209, 210, 211, 212, 213, 214
 */
#ifndef S2S1_TABLES_H
#define S2S1_TABLES_H

#define XF_DIRECT 0
#define XF_RENUM  1
#define XF_DROP   2

typedef struct { unsigned char s2; unsigned char s1; unsigned char xf; const char *name; } c2b_msg_map_t;

static const c2b_msg_map_t g_svc_map[] = {
  { 40 , 8  , XF_RENUM , "svc_ServerInfo" },
  { 42 , 10 , XF_DIRECT, "svc_ClassInfo" },
  { 43 , 11 , XF_DIRECT, "svc_SetPause" },
  { 44 , 12 , XF_RENUM , "svc_CreateStringTable" },
  { 45 , 13 , XF_DIRECT, "svc_UpdateStringTable" },
  { 46 , 14 , XF_DIRECT, "svc_VoiceInit" },
  { 47 , 15 , XF_DROP  , "svc_VoiceData" },
  { 48 , 16 , XF_DIRECT, "svc_Print" },
  { 49 , 17 , XF_DIRECT, "svc_Sounds" },
  { 50 , 18 , XF_DIRECT, "svc_SetView" },
  { 52 , 34 , XF_DIRECT, "svc_CmdKeyValues" },
  { 53 , 21 , XF_DIRECT, "svc_BSPDecal" },
  { 54 , 22 , XF_DIRECT, "svc_SplitScreen" },
  { 55 , 26 , XF_DIRECT, "svc_PacketEntities" },
  { 56 , 28 , XF_DIRECT, "svc_Prefetch" },
  { 57 , 29 , XF_DIRECT, "svc_Menu" },
  { 58 , 31 , XF_DIRECT, "svc_GetCvarValue" },
  { 72 , 23 , XF_DROP  , "svc_UserMessage" },
  { 74 , 38 , XF_DIRECT, "svc_Broadcast_Command" },
  { 78 , 35 , XF_DIRECT, "svc_EncryptedData" },
  { 205, 30 , XF_DIRECT, "svc_GameEventList<-CMsgSource1LegacyGameEventList" },
  { 206, 0  , XF_DROP  , "CMsgSource1LegacyListenEvents" },
  { 207, 25 , XF_RENUM , "svc_GameEvent<-CMsgSource1LegacyGameEvent" },
};
#define SVC_MAP_COUNT 23

static const unsigned char g_s2_svc_drop[] = { 41, 51, 59, 60, 61, 62, 63, 70, 71, 75, 76, 77, 201, 202, 203, 204, 208, 209, 210, 211, 212, 213, 214 };
#define SVC_DROP_COUNT 23

static const unsigned char g_s2_net_drop[] = { 8, 9, 11, 12, 13, 15, 16, 17, 18, 19 };
#define NET_DROP_COUNT 10

/* identity-пары NET (S2==S1): net_SetConVar, net_SplitScreenUser, net_NOP, net_Tick, net_StringCmd, net_SignonState */
#define NET_IDENTITY_MIN 0
#define NET_IDENTITY_MAX 7

/* ---- Фаза F: карты ренумерации полей (индекс = S2 field, значение = S1 field,
 * 0xFF = дроп поля; wire-типы полей совпадают — значения копируются as-is) ---- */
typedef struct { unsigned char map[32]; const char *name; } c2b_field_renum_t;

static const c2b_field_renum_t g_renum_4 = { /* S2 msg 4: CNETMsg_Tick */
  { 0xFF, 1, 2, 3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 7, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CNETMsg_Tick" };
static const c2b_field_renum_t g_renum_7 = { /* S2 msg 7: CNETMsg_SignonState */
  { 0xFF, 1, 2, 3, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CNETMsg_SignonState" };
static const c2b_field_renum_t g_renum_40 = { /* S2 msg 40: CSVCMsg_ServerInfo */
  { 0xFF, 0xFF, 2, 3, 5, 0xFF, 7, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 13, 14, 15, 16, 18, 19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CSVCMsg_ServerInfo" };
static const c2b_field_renum_t g_renum_44 = { /* S2 msg 44: CSVCMsg_CreateStringTable */
  { 0xFF, 1, 3, 4, 5, 6, 7, 8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CSVCMsg_CreateStringTable" };
static const c2b_field_renum_t g_renum_207 = { /* S2 msg 207: CSVCMsg_GameEvent<-CMsgSource1LegacyGameEvent */
  { 0xFF, 1, 2, 3, 0xFF, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CSVCMsg_GameEvent<-CMsgSource1LegacyGameEvent" };

static const c2b_field_renum_t * const g_renum_lookup[] = {
  0, 0, 0, 0, &g_renum_4, 0, 0, &g_renum_7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_renum_40, 0, 0, 0, &g_renum_44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_renum_207,
};
#define RENUM_LOOKUP_COUNT 208

/* CS2 wire-пространство (плоское, без SVC-обёртки для юзер-сообщений):
 *   NET 0..15, CLC 20..37, SVC 40..78, engine-usermsg 100..170,
 *   bi_* 16..19, GE/EBaseGameEvents 200..214, P2P 256..258, ClientUI 280..282,
 *   CS-usermsg 301..389, TE 400..453. Зоны >=100 при приёме: ДРОП (счётчик unknown),
 *   кроме 205/207 (GameEvent-мост). Источник: analysis/cs2_wire_types.json.
 *
 * Поле-карта: см. analysis/field_map_report.md. NEEDS_TRANSCODE:
 *   CNETMsg_SignonState                    <- CNETMsg_SignonState                    chg:1 s1only:0 s2only:1
 *   CNETMsg_Tick                           <- CNETMsg_Tick                           chg:1 s1only:1 s2only:6
 *   CSVCMsg_CreateStringTable              <- CSVCMsg_CreateStringTable              chg:6 s1only:1 s2only:3
 *   CSVCMsg_ServerInfo                     <- CSVCMsg_ServerInfo                     chg:10 s1only:9 s2only:3
 *   CSVCMsg_VoiceData                      <- CSVCMsg_VoiceData                      chg:4 s1only:6 s2only:5
 *   CCSUsrMsg_MatchEndConditions           <- CCSUsrMsg_MatchEndConditions           chg:1 s1only:0 s2only:0
 *   CSVCMsg_GameEvent                      <- CMsgSource1LegacyGameEvent             chg:2 s1only:0 s2only:1
 *   CSVCMsg_GameEventList                  <- CMsgSource1LegacyGameEventList         chg:1 s1only:0 s2only:0
 */

#endif /* S2S1_TABLES_H */
