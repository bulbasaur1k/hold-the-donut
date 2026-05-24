# CRATES — карта воркспейса: как работает каждый крейт

> Учебно-справочный документ. Для каждого крейта: **назначение · как работает ·
> ключевые типы/функции · место в стеке · статус**. Архитектурные принципы и
> направление зависимостей — в [`ANALYSIS.md`](ANALYSIS.md) §5; стек технологий —
> [`TECHNOLOGIES.md`](TECHNOLOGIES.md).

Направление зависимостей (никогда не наоборот):

```
donut-server / donut-client (bins)
        │
        ├── donut-socks ── donut-carrier ── donut-quic
        │                       │               │
        │                  donut-wire ───── donut-veil ── donut-rustls ── donut-tls(=rustls fork)
        │                                        │
        ├── donut-routing ── donut-geo           │
        ├── donut-dns                            │
        └── donut-config ───────── donut-core ───┘   (+ donut-io: буферы/тюнинг сокетов)
```

Статусы: ✅ реализован · 🟡 частично · ⛔ заглушка (M0).

---

## donut-core — доменные типы и порты ✅
- **Назначение:** общий словарь типов и trait-портов; ни одного фреймворка, без async.
- **Как работает:** чистые типы + сериализация (serde). Реализации живут в
  транспортных крейтах, которые зависят от `core`, а не наоборот (Clean/Hex).
- **Ключевое:** `Address` (Ip/Domain), `Endpoint`, `UserId` (UUID), `ShortId`
  (hex, парсится из строки), `Command` (Tcp/Udp/Mux), `FlowKind`
  (None/Extended=`xtls-rprx-vision`), `TransportKind` (RawTcp/Carrier/CarrierQuic),
  `TlsKind` (None/Tls/Veil); порты `Inbound`/`Outbound`/`Dialer`/`Resolver`.
- **Место в стеке:** фундамент, его импортируют почти все.

## donut-wire — кодек VLESS ✅ (M1)
- **Назначение:** байт-точный encode/decode VLESS-заголовка (см. `PROTOCOLS.md §1`).
- **Как работает:** `Request` (version, UUID, addons, command, target) ↔ `Bytes`;
  `Addons` (flow + seed) через ручной/`prost` proto; `Response`-префикс;
  валидатор flow (`""`/`"none"`/`"xtls-rprx-vision"`).
- **Ключевое:** `Request`, `Response`, `Addons`, `WireError`.
- **Vision:** flow распознаётся, но padding/`trafficState` ещё не реализованы (M5.5).
- **Тесты:** unit + fuzz round-trip + criterion bench (encode ~7ns / decode ~20ns).

## donut-tls — форк rustls (пакет `rustls`) ✅ (M2)
- **Назначение:** rustls 0.23 с патчами под REALITY. Физически в `crates/donut-tls`,
  но **пакет назван `rustls`** и подключён через `[patch.crates-io]`, поэтому им
  пользуются и наши крейты, и транзитивные (quinn, tokio-rustls, hyper-rustls).
- **Патч-точки:** `ClientConfig::client_hello_mutator` (клиентский хук мутации
  ClientHello), `ServerConfig::raw_client_hello_hook` + `enum VeilDecision
  {Tunnel, Forward{raw_client_hello}}`, `ServerConnection::take_forwarded()`
  (забрать сырой ClientHello для байт-релея).
- **Как работает Forward:** в state-машине сервера на ClientHello вызывается хук;
  при `Forward` соединение уходит в терминальное состояние `ForwardedVeil`, а сырые
  байты кладутся в `take_forwarded()` — caller сам проксирует транспорт на подложку.
- **Место в стеке:** TLS-слой (см. `TECHNOLOGIES.md §4`). Диффы — `crates/donut-tls/MODIFICATIONS.md`.

## donut-rustls — фасад над форком ✅
- **Назначение:** тонкая стабильная обёртка-реэкспорт, чтобы крейты использовали
  TLS-хуки, не импортируя `rustls` по имени.
- **Реэкспорт:** `ClientHelloMutator`, `RawClientHelloHook`, `VeilDecision`.

## donut-veil — REALITY auth + вердикт ✅ (M3)
- **Назначение:** склейка REALITY-логики поверх хуков форка.
- **Как работает:**
  - **Клиент:** `build_client_hello_mutator(VeilClientConfig)` — переиспользует
    эфемерный X25519 из TLS, выводит `AuthKey = HKDF-SHA256(...).expand(ECDH)`,
    `AES-256-GCM`-запечатывает `(version, ts, shortId)` в `SessionID`.
  - **Сервер:** `decide()` — общее ядро: парс ClientHello, ECDH, HKDF, AEAD-open,
    проверка `shortId`. Поверх него два API:
    - `build_raw_client_hello_hook(VeilServerConfig)` → `RawClientHelloHook` (путь через rustls);
    - `server_verdict(&cfg, client_hello) → Verdict{Tunnel|Forward}` — **без rustls**,
      для socket-level триажа (см. `donut-server`).
  - `VeilX25519`/`VEIL_X25519` — кастомная kx-группа с неразрушающим DH
    (`donut-veil/src/kx.rs`).
- **Ключевое:** `VeilServerConfig`/`VeilClientConfig`, `Verdict`, `server_verdict`,
  `build_*`. Крипто — `auth.rs`, парс — `parse.rs`.
- **Тесты:** полный TLS-handshake через хуки; unknown-shortId → Forward; plain-client → Forward.

## donut-carrier — XHTTP (3 режима, H1/H2) ✅ (M4)
- **Назначение:** транспорт XHTTP поверх HTTP/1.1/2 (см. `PROTOCOLS.md §3`).
- **Как работает:** на `hyper`. Сервер (`server::Server::serve(listener, cfg)`)
  поднимает accept-loop, на каждое соединение — http1, диспетчер по режиму, отдаёт
  `Session{stream, session_id, remote}`. Клиент (`client::dial(addr, cfg)`)
  открывает carrier-стрим. Дуплекс — `CarrierStream`.
- **Режимы:** `stream-one` (один запрос несёт оба направления, дефолт под REALITY),
  `stream-up` (длинный POST + GET), `packet-up` (секвентные POST + GET).
- **Интеграция с REALITY:** пока carrier владеет своим TCP; veiled-TLS-слой перед
  ним — M6 step2/M7 step2 (требует carrier «поверх произвольного стрима»).
- **Ключевое:** `ClientConfig`/`ServerConfig`, `Mode`, `Placement`, `SessionId`, `CarrierStream`.

## donut-quic — QUIC / HTTP-3 🟡 (M5)
- **Назначение:** QUIC-транспорт и H3-carrier (сценарий 3).
- **Как работает:** на `quinn` 0.11. `bidi.rs` — raw QUIC bidi (ALPN `h3` для
  маскировки, без H3-framing внутри); `server.rs`/`client.rs` — H3 stream-one.
- **Готово:** H3 stream-one round-trip ✅, raw-bidi full-duplex ✅.
- **Pending:** H3-framing поверх raw-bidi (xray-compat), REALITY-провайдер в QUIC-TLS,
  опц. Brutal-CC.

## donut-socks — SOCKS5 inbound ✅ (M7.1)
- **Назначение:** локальный listener протокола SOCKS5 (RFC 1928) для `donut-client`.
- **Как работает:** greeting → выбор метода (NO-AUTH) → `CONNECT` с адресом →
  ответ → прозрачный поток. Минимальная поверхность (без UDP ASSOCIATE пока).

## donut-server (bin) — серверный демон 🟡 (M6.1 + selfsteal)
- **Назначение:** боевой сервер (sing-out).
- **Как работает сейчас:**
  - `run_carrier_proxy(bind)` — поднимает carrier `stream-one`, на сессию: парс
    VLESS-заголовка → resolve target → `freedom`-dial → `copy_bidirectional`.
  - `selfsteal::triage(client, &veil, dest)` — читает ClientHello, зовёт
    `server_verdict`; на `Forward` байт-прозрачно релеит соединение
    (ClientHello включительно) на подложку `dest`; на `Tunnel` отдаёт стрим.
  - `VeilServer` (`veil_server.rs`) — терминирует veiled-TLS на Tunnel
    (`PrefixedStream` реплеит ClientHello), отдаёт расшифрованный `TlsStream`.
  - `run_veil_proxy(...)` — боевой путь: triage → Tunnel → TLS → carrier
    `serve_connection` → VLESS+freedom. (`run_carrier_proxy` — plain, без veil.)
- **Pending:** routing/DNS (M6.3), JSON-конфиг + `main.rs` wiring (M6.4),
  встроенный decoy (feature `decoy`).

## donut-client (bin) — клиентский демон 🟡 (M7.1)
- **Назначение:** локальный агент (sing-in).
- **Как работает сейчас:** `run_local_socks_proxy(local, server)` — SOCKS5 listener,
  на `CONNECT` открывает carrier `stream-one` к серверу, шлёт VLESS-заголовок,
  снимает Response-префикс, `copy_bidirectional`.
  - `VeilClient` (`veil_dial.rs`) — TCP-connect + veiled-TLS рукопожатие,
    отдаёт расшифрованный `TlsStream`.
  - `run_veil_socks_proxy(local, veil_client, server, router, resolver)` — боевой
    путь со **split-tunnel**: на каждый CONNECT `Router` решает `direct` (клиент
    дозванивается сам, минуя сервер — RU/домашнее остаётся на локальном IP) /
    `block` / `proxy` (через veiled-туннель). `main.rs` грузит router+resolver из конфига.
- **Pending:** uTLS-фингерпринт (M7), HTTP CONNECT inbound.

## Заглушки (M0, реализация в M6+)
- **donut-config** ⛔ — JSON-загрузчик xray-совместимого подмножества (M6.4).
- **donut-routing** ⛔ — матчинг `domain/ip/port/user → outbound` (M6.3).
- **donut-dns** ⛔ — async-resolver UDP + DoH (`hickory-resolver`) (M6.3).
- **donut-geo** ⛔ — парсер/lookup geoip/geosite (`.dat` v2fly, `geosite-rs`).
- **donut-io** ⛔ — пул буферов, тюнинг сокетов (SO_REUSEPORT, TFO), splice/io_uring.
- **donut-tools** (bin) ⛔ — `keygen`, `check-reality`, `gen-decoy`, `config-gen` (M9).

---

## Где что искать (шпаргалка)
- Новый протокол на проводе → начни с `PROTOCOLS.md`, потом `donut-wire`/`donut-veil`.
- Маскировка/anti-probing → `REALITY-SELFSTEAL.md` + `donut-server/src/selfsteal.rs`.
- Транспорт → `donut-carrier` (H1/H2), `donut-quic` (H3).
- TLS-хуки → `donut-tls` (форк) ← `donut-rustls` (фасад) ← `donut-veil` (логика).
</content>
