/* s2s1_um_tables.h — СГЕНЕРИРОВАНО scripts/step_g4_gen_um_tables.py (фаза G-2)
 * usermsg-мост: CS2-плоский wire [N][payload] -> S1 svc_UserMessage(23){1 msg_type,2 data}.
 * Источники: analysis/usermsg_map.json (48 мостов) + analysis/um_fdp_diff.json
 * (побайтовый дифф по НОМЕРАМ полей, FDP s1_client vs cs2).
 * Дропнутые пары: 368 (PlayerDecalDigitalSignature), 369 (WeaponSound) —
 * S1-payload прото не извлеклись (NO_FDP); добрать в фазе G-3+.
 * Override-логика (repeated-merge, float-конверсии) — в шапке скрипта-генератора.
 */
#ifndef S2S1_UM_TABLES_H
#define S2S1_UM_TABLES_H

#define UM_ASIS    0
#define UM_RENUM   1
#define UM_CONV334 2
#define UM_CONV106 3
#define UM_CONV110 4

typedef struct { u16 wire; u8 s1; u8 xf; const c2b_field_renum_t *renum; } c2b_um_t;

static const c2b_field_renum_t g_um_renum_105 = { { 0xFF, 0x01, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CUserMessageDesiredTimescale" };
static const c2b_field_renum_t g_um_renum_118 = { { 0xFF, 0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CUserMessageSayText2" };
static const c2b_field_renum_t g_um_renum_124 = { { 0xFF, 0x01, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CUserMessageTextMsg" };
static const c2b_field_renum_t g_um_renum_128 = { { 0xFF, 0xFF, 0xFF, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CUserMessageVoiceMask" };
static const c2b_field_renum_t g_um_renum_130 = { { 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CUserMessageSendAudio" };
static const c2b_field_renum_t g_um_renum_134 = { { 0xFF, 0x01, 0x02, 0xFF, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CUserMessageShowMenu" };
static const c2b_field_renum_t g_um_renum_346 = { { 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CCSUsrMsg_VoteStart" };
static const c2b_field_renum_t g_um_renum_350 = { { 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CCSUsrMsg_ServerRankRevealAll" };
static const c2b_field_renum_t g_um_renum_351 = { { 0xFF, 0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, "CCSUsrMsg_SendLastKillerDamageToClient" };

static const c2b_um_t g_um_map[] = {
  { 101, 33, UM_ASIS, 0 },  /* CUserMessageAchievementEvent */
  { 104, 32, UM_ASIS, 0 },  /* CUserMessageCurrentTimescale */
  { 105, 31, UM_RENUM, &g_um_renum_105 },  /* CUserMessageDesiredTimescale */
  { 106, 13, UM_CONV106, 0 },  /* CUserMessageFade */
  { 110, 8, UM_CONV110, 0 },  /* CUserMessageHudMsg */
  { 111, 4, UM_ASIS, 0 },  /* CUserMessageHudText */
  { 114, 20, UM_ASIS, 0 },  /* CUserMessageRequestState */
  { 115, 9, UM_ASIS, 0 },  /* CUserMessageResetHUD */
  { 116, 14, UM_ASIS, 0 },  /* CUserMessageRumble */
  { 117, 5, UM_ASIS, 0 },  /* CUserMessageSayText */
  { 118, 6, UM_RENUM, &g_um_renum_118 },  /* CUserMessageSayText2 */
  { 120, 12, UM_ASIS, 0 },  /* CUserMessageShake */
  { 124, 7, UM_RENUM, &g_um_renum_124 },  /* CUserMessageTextMsg */
  { 128, 19, UM_RENUM, &g_um_renum_128 },  /* CUserMessageVoiceMask */
  { 130, 17, UM_RENUM, &g_um_renum_130 },  /* CUserMessageSendAudio */
  { 131, 53, UM_ASIS, 0 },  /* CUserMessageItemPickup */
  { 132, 56, UM_ASIS, 0 },  /* CUserMessageAmmoDenied */
  { 134, 54, UM_RENUM, &g_um_renum_134 },  /* CUserMessageShowMenu */
  { 301, 1, UM_ASIS, 0 },  /* CCSUsrMsg_VGUIMenu */
  { 317, 17, UM_ASIS, 0 },  /* CCSUsrMsg_SendAudio */
  { 318, 18, UM_ASIS, 0 },  /* CCSUsrMsg_RawAudio */
  { 321, 21, UM_ASIS, 0 },  /* CCSUsrMsg_Damage */
  { 322, 22, UM_ASIS, 0 },  /* CCSUsrMsg_RadioText */
  { 323, 23, UM_ASIS, 0 },  /* CCSUsrMsg_HintText */
  { 324, 24, UM_ASIS, 0 },  /* CCSUsrMsg_KeyHintText */
  { 325, 25, UM_ASIS, 0 },  /* CCSUsrMsg_ProcessSpottedEntityUpdate */
  { 327, 27, UM_ASIS, 0 },  /* CCSUsrMsg_AdjustMoney */
  { 330, 30, UM_ASIS, 0 },  /* CCSUsrMsg_KillCam */
  { 334, 34, UM_CONV334, 0 },  /* CCSUsrMsg_MatchEndConditions */
  { 336, 36, UM_ASIS, 0 },  /* CCSUsrMsg_PlayerStatsUpdate */
  { 345, 45, UM_ASIS, 0 },  /* CCSUsrMsg_CallVoteFailed */
  { 346, 46, UM_RENUM, &g_um_renum_346 },  /* CCSUsrMsg_VoteStart */
  { 347, 47, UM_ASIS, 0 },  /* CCSUsrMsg_VotePass */
  { 348, 48, UM_ASIS, 0 },  /* CCSUsrMsg_VoteFailed */
  { 349, 49, UM_ASIS, 0 },  /* CCSUsrMsg_VoteSetup */
  { 350, 50, UM_RENUM, &g_um_renum_350 },  /* CCSUsrMsg_ServerRankRevealAll */
  { 351, 51, UM_RENUM, &g_um_renum_351 },  /* CCSUsrMsg_SendLastKillerDamageToClient */
  { 352, 52, UM_ASIS, 0 },  /* CCSUsrMsg_ServerRankUpdate */
  { 361, 61, UM_ASIS, 0 },  /* CCSUsrMsg_SendPlayerItemDrops */
  { 362, 62, UM_ASIS, 0 },  /* CCSUsrMsg_RoundBackupFilenames */
  { 363, 63, UM_ASIS, 0 },  /* CCSUsrMsg_SendPlayerItemFound */
  { 364, 64, UM_ASIS, 0 },  /* CCSUsrMsg_ReportHit */
  { 365, 65, UM_ASIS, 0 },  /* CCSUsrMsg_XpUpdate */
  { 366, 66, UM_ASIS, 0 },  /* CCSUsrMsg_QuestProgress */
  { 367, 67, UM_ASIS, 0 },  /* CCSUsrMsg_ScoreLeaderboardData */
  { 374, 35, UM_ASIS, 0 },  /* CCSUsrMsg_DisconnectToLobby */
};
#define UM_MAP_COUNT 46

#endif /* S2S1_UM_TABLES_H */
