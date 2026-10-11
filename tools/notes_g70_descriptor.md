# g70: CMsgSteamSockets_UDP_ConnectRequest — полный RE дескриптора (2026-10-11)

## Источник
`steamclient.so__5b08b7.so` (staged в /tmp/f220/x/bins/), сериализованный
FileDescriptorProto файла `steamnetworkingsockets_messages_udp.proto`
(blob начинается с `0x0A 0x25 "steamnetworkingsockets_messages_udp.proto"`).
Численные номера полей — из FieldDescriptorProto (поле 3), НЕ порядок
объявления. Сверено с открытым SDK (steamnetworkingsockets_messages_udp.proto).

## CMsgSteamSockets_UDP_ConnectRequest  (wire msg 0x22)

| #  | имя                     | тип          | wire |
|----|-------------------------|--------------|------|
| f1 | client_connection_id    | fixed32      | 5    |
| f2 | challenge               | fixed64      | 1    |
| f3 | legacy_client_steam_id  | fixed64      | 1    |
| f4 | cert                    | CMsgSteamDatagramCertificateSigned | 2 |
| f5 | my_timestamp            | fixed64      | 1    |
| f6 | ping_est_ms             | uint32       | 0    |
| f7 | crypt                   | CMsgSteamDatagramSessionCryptInfoSigned | 2 |
| f8 | legacy_protocol_version | uint32       | 0    |
| f9 | legacy_identity_binary  | CMsgSteamNetworkingIdentityLegacyBinary | 2 |
| f10| identity_string         | string       | 2    |

## CMsgSteamSockets_UDP_ChallengeRequest (0x20) / ChallengeReply (0x21)

- 0x20: f1 connection_id fixed32, f3 my_timestamp fixed64, f4 protocol_version varint
- 0x21: f1 connection_id fixed32, f2 challenge fixed64, f3 your_timestamp fixed64,
  f4 protocol_version varint. 26B на проводе = 1 + (1+4) + (1+8) + (1+8) + (1+2)
  хвост по len. Парсер c2b_clv2_parse_chalreply КОРРЕКТЕН.

## CMsgSteamNetworkingIdentityLegacyBinary  (для f9)

- f16 steam_id        fixed64
- f2  generic_bytes   bytes
- f3  generic_string  string
- f4  ipv6_and_port   bytes
(дескриптор в steamnetworkingsockets_messages_certs.proto, blob @0xcffb52)

## КЛЮЧЕВОЙ ВЫВОД (исправление g59-теории)

1. **В ConnectRequest НЕТ auth-ticket поля.** 'steam2_auth_ticket'
   (@0xd4d453 steamclient 5b08b7) = поле **CMsgClientLogon** (Steam-сеть
   logon-сессия, НЕ игровой сервер). Тикет движкового 'k' (byte 17+) нужен
   ВНУТРИ зашифрованной сессии (game-level auth), не в 0x22.
2. **Старый билдер 0x22 был mis-tagged** (f3 chal / f4 ts / f5 ver / f8 sid):
   protobuf-парсер ключуется на (номер, wire-type); challenge попадал в f3
   (= legacy_client_steam_id!), остальные поля — wire-mismatch -> unknown-field
   skip. Сервер не видел challenge -> молча дропал -> НЕТ 0x23. ЭТО и была
   стена, а не "нет тикета".
3. g70-фикс (e99b599): f1 cid / f2 ch / f3 sid / f5 ts / f6 ping=20 /
   f8 ver=13 (+f7 crypt в v2). Selftest: v1 pb=36B, v2 pb=76B.

## Ожидаемые ответы сервера на корректный 0x22

- 0x23 ConnectOK: f1 client_connection_id f32 / f5 server_connection_id f32 /
  f3 your_timestamp f64 / f4 delay_time_usec varint / f7 crypt / f8 cert /
  f11 identity_string / f2 legacy_server_steam_id f64 / f10 legacy_identity_binary
- 0x24 ConnectionClosed: f4 to_connection_id f32 / f5 from_connection_id f32 /
  f2 debug string / f3 reason_code varint  <- ВАЖНЫЙ диагностический исход
- 0x25 NoConnection: f2 from_connection_id / f3 to_connection_id

## Если сервер потребует cert (0x24 reason)

cert = CMsgSteamDatagramCertificateSigned — нужен подписанный серт от Steam
backend (в legacy-пути клиент без серта -> identity по f3/f9/f10). Варианты:
попробовать v1 (bare, без crypt) — если сервер требует crypt/cert, вернёт
0x24 с reason_code, что и есть следующий точный требователь.

## Инструменты

- Парсер дескрипторов: python walk по blob от `0x0A <len> <proto-name>`
  (см. скрипт в этой сессии 20261011; re-usable).
- Бинарники: /tmp/f220/x/bins/ (VOLATILE — перекачать из artifact последнего
  e2e при чистке).
