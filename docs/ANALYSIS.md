# hold-the-donut — технический анализ

> Проект: минималистичный Rust-рерайт необходимого подмножества [xray-core](https://github.com/xtls/xray-core).
> Дата анализа: 2026-04-17. Эталонная версия xray-core: **v26.4.15**.

---

## 1. Цели

1. **Server (sing-out):** Xray-совместимый прокси-сервер с `VLESS + REALITY + XHTTP` + selfsteal/selfSNI.
2. **Client (sing-in):** свой локальный клиент (SOCKS5/HTTP listener → REALITY+XHTTP outbound), совместимый с тем же сервером.
3. **Cross-target:** клиент собирается под OpenWrt (armv7, aarch64, mipsel — musl).
4. **Без GC:** только Rust/C/C++/Zig; заимствуем только из компилируемых источников.
5. **Совместимость клиентов:** сторонние Xray-клиенты (v2rayN, NekoBox, Hiddify) должны работать с нашим сервером по VLESS+REALITY+XHTTP с базовыми настройками.

## 2. Что оставляем / что выкидываем

### Оставляем

| Компонент | Почему |
|---|---|
| **VLESS** (inbound + outbound) | Минимальный протокол-обёртка, работает с REALITY и с XHTTP |
| **REALITY** (TLS-авторизация через X25519 + selfsteal) | Главная маскировка 2026 |
| **XHTTP** (`packet-up` / `stream-up` / `stream-one`) | Актуальный транспорт, работает поверх H1/H2/H3 |
| **HTTP/3 (QUIC)** как транспорт XHTTP | Часть требования, уже встроено через XHTTP |
| **Vision flow** (`xtls-rprx-vision`) — **только на TCP+REALITY** | В XHTTP не работает (issue [#5576](https://github.com/XTLS/Xray-core/issues/5576)) |
| **geoip/geosite** (v2fly .dat формат) | Требование пользователя |
| **Routing** по domain/ip/port/user | Нужен для split-tunnel на клиенте |
| **SOCKS5 / HTTP inbound** (для локального клиента) | Классический клиентский listener |
| **DNS: DoH + UDP + system** | Минимум, без лишнего |
| **JSON config** Xray-совместимого подмножества | Чтобы переиспользовать существующие конфиги |

### Выкидываем осознанно

| Компонент | Почему |
|---|---|
| VMess (AEAD и legacy) | Устарел, небезопасен (timing), заменён VLESS+REALITY |
| Shadowsocks все варианты | Слабая маскировка vs REALITY; если нужен — как отдельный крейт позже |
| Trojan-go / Trojan legacy | REALITY перекрывает usecase |
| mKCP / QUIC-raw custom | Своя QUIC не нужна — HTTP/3 через XHTTP даёт тот же бенефит с лучшей маскировкой |
| WireGuard inbound | Не прокси-протокол, это отдельный проект |
| Reverse / Blackhole / Freedom-sniff дебри | Не нужны для минимального set |
| DNS-server mode, FakeDNS | Клиенту достаточно resolver |
| mKCP, quic-legacy, gRPC-transport, WS, H2-custom | XHTTP поглощает все usecase transport'ов |
| Metrics / API / Stats сервис в ядре | Вынесем тонкий `/metrics` в Prometheus text format, без xray API |
| Multiplex / Mux.Cool | Xray сам от него отходит; потоки через H2/H3 лучше |
| MLDSA-65 post-quantum (пока) | Новая штука v25.7.26, **опциональный add-on в M7**, не блокирует MVP |
| WebRTC-маскировка | Отложено по договорённости |

### Под вопросом (обсуждаемо)

- **Sniffing** (определение TLS-SNI/HTTP-Host на inbound для роутинга) — полезно для клиента, но 300 LOC. Тянем в M6 если успеваем.
- **uTLS-подобный fingerprinting** (Chrome/Firefox/Safari ClientHello imitation) — важно для outbound-маскировки, в rustls нет из коробки. Добавляем через форк rustls в M2 сразу.

---

## 3. Техническая анатомия (ground-truth из исходников)

### 3.1 REALITY — протокол

Файл-референс: `transport/internet/reality/reality.go` (xray-core main).

**Клиент (на ClientHello, до отправки):**
1. Генерирует ephemeral X25519 → `client_pub`.
2. `shared = X25519(client_priv, server_pub_long_term)`.
3. `AuthKey = HKDF-SHA256(salt = ClientHello.Random[:20], info = "REALITY").expand(shared)` (32 байта).
4. Формирует plaintext SessionID (32 байта):
   - `[0..4]` — версия Xray (x, y, z, reserved)
   - `[4..8]` — Unix timestamp BE u32
   - `[8..16]` — ShortID (8 байт; в конфиге hex-строка 1..16 nibbles, добивается нулями)
   - `[16..32]` — AEAD-sealed auth material (AES-256-GCM под AuthKey)
5. Пишет SessionID в `ClientHello.Raw` по смещению **39** (стандартный TLS layout: type(1) + len(3) + legacy_version(2) + random(32) + session_id_len(1) = 39).

**Сервер (на получении ClientHello):**
1. Читает SessionID[8..16] → ShortID, сверяет со списком конфигурируемых ShortID.
2. Если ShortID неизвестен → **forward to target** (selfsteal), передаёт всё соединение целевому сайту.
3. Если ShortID известен → выводит AuthKey, пытается раскрыть AEAD [16..32] → получает ephemeral pub ключ и HMAC tag.
4. Проверяет `HMAC-SHA512(AuthKey, cert.Signature)` → если совпало, **tunnel mode**, иначе снова forward.
5. В tunnel mode сервер завершает TLS handshake от своего имени (с сертификатом целевого сайта), внутри TLS идёт VLESS+XHTTP.

**Что это значит для Rust-реализации:**
- Нужен доступ к `ClientHello.Raw` и мутация 32 байт до подписи в client; и перехват SessionID + полный контроль над handshake в server.
- `rustls` 0.23 **не даёт таких хуков** (issue [rustls#1932](https://github.com/rustls/rustls/issues/1932)).
- Вариант A: **форкаем rustls** под именем `rustls-reality`, патчим: (a) `ClientHelloPayload` expose raw/mutate SessionID; (b) server-side hook "raw ClientHello bytes pre-crypto" для REALITY-check.
- Вариант B: **boring** (BoringSSL FFI) + callbacks — быстрее, но тащим C и теряем pure-Rust.
- Вариант C: собственный минимальный TLS 1.3 client/server из `tls-parser` + `ring`/`rustcrypto` — 1-2 месяца чистой работы.

**Решение: Вариант A (форк rustls).** Реалистично, rustls хорошо структурирован, патч локальный (5-7 файлов). Форк держим в `crates/rustls-reality` как git submodule на пин-коммите `rustls` 0.23.

### 3.2 XHTTP — транспорт

Файл-референс: `transport/internet/splithttp/` (xray-core main).

**Три режима:**

| Mode | Upload | Download | Когда |
|---|---|---|---|
| `packet-up` | множество коротких `POST /?seq=N` | один длинный `GET` | sync-чувствительные каналы, default |
| `stream-up` | один длинный chunked `POST` | один длинный `GET` | быстрый upload |
| `stream-one` | единый `POST` (или `GET` с body) несёт оба направления | — | **default при REALITY** (auto → stream-one) |

**Session binding:** UUID (обычно 32 hex char) помещается в one of: `Path` / `Query` / `Header(X-Session)` / `Cookie(x_session)` / `Body`. Default = **Path**.

**Seq binding** (только `packet-up`): аналогично, default — `X-Seq` header.

**HTTP versions:** H1.1 / H2 / H3 (QUIC). С v26.3.27 HTTP/3 использует BBR congestion control.

**Сервер-tunables (default):**
- `scMaxEachPostBytes = 1_000_000`
- `scMinPostsIntervalMs = 30`
- `scMaxBufferedPosts = 30`
- `scStreamUpServerSecs = 20..80`
- `xPaddingBytes` — padding через `Referer` query

**Обёртка внутри XHTTP:** VLESS header в самом начале первого upload-chunk; далее raw payload.

**Для Rust:** используем `hyper` 1.x + `h3` + `h3-quinn`. TLS-слой ниже — `rustls-reality`. `quinn` + `rustls-reality`-вариант для QUIC. Никакого MASQUE не нужно (это не cone-tunnel, это HTTP-transport).

### 3.3 VLESS — заголовок

Референс: `proxy/vless/encoding/encoding.go` + `vless.go`.

```
offset  size   field
0       1      version byte = 0x00
1       16     UUID (binary, не hex)
17      1      addon length L (u8)
18      L      addons (protobuf Addons { flow: string, seed: bytes })
18+L    1      command (1=TCP, 2=UDP, 3=Mux)
19+L    2      port (BE u16)                  # нет для Mux/Reserved
21+L    1      address type (1=IPv4, 2=Domain-len-prefixed, 3=IPv6)
22+L    N      address bytes (4 / 1+len / 16)
...            payload
```

**Flow (Addons.flow)** — только два значения в коде v26.4.15: `""/"none"` и `"xtls-rprx-vision"`. Остальные значения отвергаются.

**Правило:** `xtls-rprx-vision` работает только на TCP+REALITY. С XHTTP flow=`""`. Это нужно захардкодить — валидатор конфига отказывает на некорректных комбо (issue [#5576](https://github.com/XTLS/Xray-core/issues/5576)).

### 3.4 Geoip / Geosite

- Формат: protobuf, совместим с v2fly.
- .proto: `common/geodata/geodat.proto`. Сообщения `GeoIPList`, `GeoSiteList` — по списку `{country_code, cidr[]}` и `{country_code, domain[]}`.
- **Не переизобретаем:** используем крейт [`geosite-rs`](https://crates.io/crates/geosite-rs) (парсит оба .dat). Если понадобится кастомизация — форкаем.
- Файлы тянем с `github.com/v2fly/geoip` и `github.com/v2fly/domain-list-community` (готовые релизы).

### 3.5 QUIC / HTTP-3

- `quinn` 0.11+ — pure Rust, mature.
- `h3` + `h3-quinn` — сервер и клиент HTTP/3.
- TLS под QUIC — тот же `rustls-reality` (quinn использует rustls внутри).
- BBR congestion — у quinn есть custom congestion controller API, BBR придётся либо портировать из quiche (C), либо запилить cubic-default и пометить TODO.

---

## 4. Крейты: выбор и форки

### Прямые зависимости (ok)

| Крейт | Назначение | Примечание |
|---|---|---|
| `tokio` 1 | async runtime | workstealing, hot-path |
| `bytes` | zero-copy буферы | |
| `hyper` 1 | HTTP/1.1 + /2 | сервер+клиент |
| `h3`, `h3-quinn` | HTTP/3 | |
| `quinn` 0.11 | QUIC | custom TLS provider |
| `ring` или `aws-lc-rs` | AES-GCM, HKDF, HMAC | используется rustls-reality |
| `x25519-dalek` | X25519 | ephemeral keys для REALITY |
| `serde`, `serde_json` | конфиг | xray-compat JSON |
| `thiserror` | ошибки | по CLAUDE.md |
| `tracing`, `tracing-subscriber` | логи | |
| `clap` 4 | CLI | server+client binaries |
| `socket2` | SO_REUSEPORT, TFO, mark | hot-path tuning |
| `geosite-rs` | .dat парсер | v2fly формат |
| `prost` или `quick-protobuf` | protobuf runtime | для geosite и VLESS addons |

### Форки (необходимые)

| Форк | База | Причина |
|---|---|---|
| **`rustls-reality`** | `rustls` 0.23 pinned | Перехват и мутация ClientHello SessionID; server-side raw-CH hook |
| **`xray-geo-tools`** (optional) | `geosite-rs` | Если понадобятся доп. query-API (range-IP lookup оптимизированный) |

### uTLS-fingerprint

rustls по умолчанию шлёт ClientHello с rustls-specific extension-ordering, это **fingerprintable**. Для outbound-маскировки нам нужен Chrome/Firefox fingerprint. Опции:
- **Go's utls** — референс; портируем в `rustls-reality` как набор presets (CH-extensions order + GREASE + TLS-ext values).
- Начинаем с **Chrome 120+ preset** (один фингерпринт), добавляем остальные в M7.

---

## 5. Архитектура

### Направление

- **Не актёры в hot-path.** Per-connection — обычные `tokio::spawn` задачи.
- Акторы — **нигде.** Избегаем любого message-passing overhead: state (users, routing-table) — `Arc<RwLock<…>>` или `arc-swap` для конфига на read-mostly.
- **Clean/Hex частично:** domain types + ports/traits в `core`, реализации в транспортных крейтах. Без fat DDD.
- **Workspace, много крейтов** — параллельная компиляция, переиспользование клиентом и сервером.

### Структура

```
hold-the-donut/
├── Cargo.toml                          # workspace
├── crates/
│   ├── donut-core/                     # domain types, ports, errors
│   ├── donut-veil/                  # REALITY auth + selfsteal logic
│   ├── donut-rustls/                   # thin wrapper поверх rustls-reality форка
│   ├── donut-wire/                    # VLESS encode/decode
│   ├── donut-carrier/                    # XHTTP: server + client, 3 modes
│   ├── donut-quic/                     # QUIC listener/dialer + rustls-reality
│   ├── donut-geo/                      # geoip/geosite lookup
│   ├── donut-dns/                      # async resolver (UDP + DoH)
│   ├── donut-routing/                  # match engine
│   ├── donut-config/                   # JSON loader (xray-subset)
│   ├── donut-io/                       # buffer pool, copy_bidirectional tuned
│   ├── donut-socks/                    # SOCKS5 + HTTP inbound (для клиента)
│   ├── donut-server/ (bin)             # серверный демон
│   ├── donut-client/ (bin)             # клиентский демон + tray-less
│   └── donut-tools/ (bin)              # keygen, config-gen, check-reality
├── forks/
│   └── rustls-reality/                 # git submodule, pin rustls 0.23.x
├── docs/
│   ├── ANALYSIS.md
│   ├── PLAN.md
│   └── PROTOCOLS.md                    # byte-level спеки (M0 deliverable)
├── scripts/
│   ├── build-openwrt.sh
│   └── build-release.sh
└── tests/
    └── e2e/                            # pair: donut-server ↔ donut-client ↔ xray-client
```

### Направление зависимостей

```
server/client → xhttp/quic/socks → vless → reality → rustls-reality
                 ↓
              routing → geo
                 ↓
               config → core (types)
                 ↓
                dns → io
```

### Hot-path правила

1. Zero-copy где реально: `copy_bidirectional` из tokio, подтюнен для splice/io_uring где доступно.
2. Буферы — `bytes::Bytes` и pool (`crossbeam-queue`).
3. Никаких `Box<dyn Trait>` в per-packet codepath; dispatch через enum + match.
4. `arc-swap` для конфига, чтобы reload без блокировок reader'ов.
5. Metrics — атомарные счётчики, Prometheus text format, без каналов.

---

## 6. OpenWrt — cross-compile

- **Таргеты:** `aarch64-unknown-linux-musl` (tier-2), `armv7-unknown-linux-musleabihf` (tier-2), `mipsel-unknown-linux-musl` (tier-3 nightly + `-Z build-std`).
- Сборка через `cross` (Docker-образы `rust-musl-cross`).
- Отключаем heavy deps под openwrt feature-flag:
  - `tokio` — `rt` + `rt-multi-thread` с `--threads=2`
  - `aws-lc-rs` → свич на `ring` или `rustcrypto` (меньше)
  - H2/H3 опционально; минимальная сборка — только VLESS+REALITY+XHTTP(H1) для 8MB flash роутеров
- UPX-сжатие бинаря, target ≤ 4MB stripped.

---

## 7. Риски

| Риск | Вероятность | Митигация |
|---|---|---|
| Форк rustls требует поддержки при релизах rustls | High | Пин версии, обновление раз в квартал; документируем патч-точки |
| ML-DSA-65 станет default в xray → наши клиенты не подключатся | Med | Добавить в M7, следить за xray release notes |
| XHTTP спека меняется (4-й режим) | Med | Тесты против реального xray-core контейнера в CI |
| Vision+XHTTP исправят в xray — users будут включать | Low | Enable flag, но не реализуем до стабилизации |
| Regression против xray по latency/throughput | High | Benchmark gate: ≥ 0.9× throughput xray в CI |
| MIPS tier-3 перестанет собираться | Med | Отдельный CI job на nightly; fallback на `cross` pinned |

---

## 8. Что меряем (acceptance)

- **Функциональность:** xray клиент (стандартный) подключается к `donut-server` и проходит трафик. Наш `donut-client` подключается к xray-серверу и работает.
- **Производительность:** throughput ≥ 0.9× vs xray на iperf-через-туннель, latency p50 ≤ 1.1× vs xray.
- **Безопасность:** `cargo audit` clean; `cargo geiger` — unsafe только в pool/io.
- **Маскировка:** реальный selfsteal-тест — curl без клиента получает контент целевого домена; client получает tunnel.
- **Бинарь:** Linux x86_64 stripped ≤ 8MB. OpenWrt aarch64 stripped ≤ 5MB.

---

## 9. Источники (pin)

- REALITY: https://github.com/XTLS/Xray-core/blob/main/transport/internet/reality/reality.go
- XHTTP: https://github.com/XTLS/Xray-core/tree/main/transport/internet/splithttp
- VLESS encoding: https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go
- Geo proto: https://github.com/XTLS/Xray-core/blob/main/common/geodata/geodat.proto
- ML-DSA-65 PR: https://github.com/XTLS/Xray-core/pull/4915
- stream-up PR: https://github.com/XTLS/Xray-core/pull/3994
- rustls ClientHello issue: https://github.com/rustls/rustls/issues/1932
- Vision×XHTTP bug: https://github.com/XTLS/Xray-core/issues/5576
- xray-lite (MPL reference): https://github.com/undead-undead/xray-lite
- geosite-rs: https://crates.io/crates/geosite-rs
