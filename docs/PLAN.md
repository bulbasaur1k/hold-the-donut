# hold-the-donut — план работ

> Живой документ. Milestones, deliverables, acceptance, зависимости.
> Отмечаем в `[x]` сделанное по мере прогресса.

## Текущий статус

| ID  | Статус | Коммит | Тестов |
|---|---|---|---|
| M0  | ✅ done | `8b65360` | — |
| Renames | ✅ done | `07fd583` | — |
| M1  | ✅ done | `fd8341c` + `99a4ac2` | 17 unit + 1 doctest + criterion bench (encode 7ns / decode 20ns) |
| M2  | ✅ done | `47e23ac` baseline + `eb5c887` patches | 2 e2e smoke (rustls hooks fire end-to-end) |
| M3  | ✅ done | `4aca33d` | 3 auth unit + 3 veil e2e (handshake / unknown short_id / unauth → forward) |
| M4  | ✅ done | `e608bb6` | 3 session unit + 4 e2e across stream-one / stream-up / packet-up |
| M5 step 1 | ✅ done (request → response) | `e76b7e3` | 1 H3 e2e |
| M5 step 2 | ✅ done — raw QUIC bidi, full bidirectional | `80dd0e7` | 1 bidi e2e (overlapping read+write) |
| M5 step 3 | ⏳ pending — H3 framing wrapped on top of raw bidi (xray-compat) | — | — |
| M6 step 1 | ✅ done — carrier proxy (stream-one + freedom outbound) | `a2c4992` | 1 e2e (real TCP echo through proxy) |
| M6 step 2 | ⏳ pending — veiled-TLS layer in front of carrier | — | — |
| M6 step 3 | ⏳ pending — JSON config loader + routing + DNS resolver | — | — |
| M7 step 1 | ✅ done — SOCKS5 inbound + carrier outbound | _next commit_ | 1 e2e (curl-style SOCKS5 → donut-client → donut-server → echo) |
| M7 step 2 | ⏳ pending — veiled-TLS dial from client side | — | — |
| M8  | ⏳ pending | — | — |
| M9  | ⏳ pending | — | — |
| M10 | ⏳ pending — optional | — | — |

Workspace test count: **44** (`cargo test --workspace` зелёное).
Lint gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings` чисто.

---

## Принципы

- **Каждый milestone — самостоятельно работает и тестируется.** Не делаем "M3 закончим через полгода".
- **Пишем тесты сразу** для протокольных крейтов — байт-точные vectors from xray-core.
- **CI с первого milestone** — GitHub Actions, `cargo fmt + clippy + test` в каждом PR.
- **Golden path first:** сначала happy case proxy через REALITY+XHTTP, потом error paths, потом оптимизации.
- **Interop-тест** против реального `xray-core` в Docker — обязательный gate для M4+.

---

## M0 — Разведка и скелет *(1-2 дня)*

**Цель:** зафиксировать все byte-level спеки и поднять пустой workspace.

**Deliverables:**
- [ ] `Cargo.toml` workspace с 15 crate stubs (по списку из ANALYSIS §5)
- [ ] `docs/PROTOCOLS.md` — byte-level спеки REALITY/VLESS/XHTTP с test-vectors, скопированные вручную из исходников xray-core
- [ ] `rust-toolchain.toml` (pin stable + nightly для MIPS)
- [ ] `.github/workflows/ci.yml` — fmt + clippy + test на Linux+macOS
- [ ] `forks/rustls-reality/` — submodule, fork rustls 0.23 pinned tag
- [ ] `scripts/xray-testbench/` — docker-compose с xray-core server+client для interop-тестов
- [ ] `donut-core` crate: `Address`, `Endpoint`, `UserId`, `FlowKind`, `TransportKind`, `TlsKind`; traits `Inbound`, `Outbound`, `Dialer`, `Resolver`

**Acceptance:** `cargo build --workspace` зелёное, CI проходит на пустых крейтах.

---

## M1 — VLESS codec *(2-3 дня)*

**Цель:** байт-точный encode/decode VLESS header.

**Crate:** `donut-wire`.

**Deliverables:**
- [ ] `Request { version, user_uuid, flow, command, target }` — encode → `Bytes`, decode из `&mut Bytes`
- [ ] `Addons` — protobuf через `prost` (micro-proto: `flow: string`, `seed: bytes`)
- [ ] Flow-валидатор: `""`, `"none"`, `"xtls-rprx-vision"` — остальное ошибка
- [ ] Unit-тесты с vectors, собранными из xray wireshark-capture (записать через testbench)
- [ ] `cargo bench` baseline на encode/decode (цель < 100ns per op)

**Acceptance:** fuzz-test `cargo fuzz run decode` 1M iter без паник; round-trip encode→decode identity на 10k random UUID.

---

## M2 — rustls-reality форк *(1-2 недели)* ⚠️ РИСКОВЫЙ

**Цель:** форк rustls с хуками, нужными для REALITY.

**Deliverable patches (список на forks/rustls-reality):**
- [ ] `ClientConfig::client_hello_mutator: Option<Arc<dyn Fn(&mut ClientHelloPayload)>>` — вызывается ПОСЛЕ сериализации ClientHello, ДО отправки; даёт `&mut [u8]` на raw CH bytes
- [ ] `ServerConfig::raw_client_hello_hook: Option<Arc<dyn Fn(&[u8]) -> RealityDecision>>` — на сервере, до начала криптоопераций
  - `enum RealityDecision { Tunnel, Forward { to: TcpStream } }`
- [ ] Сервер: при `Forward` — return `Connection::Forwarded(raw_bytes_consumed)` чтобы upper-layer проксировал байты без TLS
- [ ] Патч locked minimal — не трогаем public API для non-REALITY users
- [ ] Документируем патч-точки в `forks/rustls-reality/PATCH_POINTS.md`

**Unit-тесты в `donut-rustls`:**
- [ ] Client: ClientHello бьёт SessionID по нашему hook, рабочий handshake с контролируемым сервером
- [ ] Server: hook вызывается, Forward-ветка работает как transparent TCP-relay
- [ ] TLS 1.3 only (REALITY требует TLS 1.3)

**Acceptance:**
- Подключение `donut-rustls` client → echo-сервер через обычный rustls → TLS handshake OK
- `donut-rustls` server получает ClientHello от curl, hook получает raw bytes

**План-Б если rustls-форк заблокируется:** переключаемся на `boring` crate (BoringSSL FFI), срок +1 неделя.

---

## M3 — REALITY протокол *(1 неделя, параллельно с M2 частично)*

**Цель:** auth-логика REALITY поверх rustls-reality хуков.

**Crate:** `donut-veil`.

**Deliverables:**
- [ ] `RealityServerConfig { private_key: X25519, short_ids: HashSet<[u8;8]>, target: SocketAddr, server_names: Vec<String> }`
- [ ] `RealityClientConfig { server_pub_key, short_id, server_name, fingerprint: Fingerprint }`
- [ ] Client-side: `build_client_hello_mutator()` — делает HKDF + AES-GCM + пишет SessionID
- [ ] Server-side: `build_raw_ch_hook()` — читает ShortID, проверяет AEAD, возвращает `Tunnel` / `Forward(target)`
- [ ] HMAC-SHA512(AuthKey, cert.signature) проверка
- [ ] Fingerprint presets: Chrome120 (первый), на уровне TLS extensions ordering

**Тесты:**
- [ ] Known-answer tests: фиксированный private_key + short_id + timestamp → expected SessionID bytes (собираем из xray-сервера через wireshark+private-key-dump)
- [ ] Integration: `donut-rustls` server + `donut-rustls` client проходят REALITY handshake
- [ ] Selfsteal: запрос curl без клиент-ключа прозрачно проксируется к google.com

**Acceptance:** xray-core client (стандартный) подключается к нашему серверу, SessionID валидируется. Взятый curl ловит google.com content.

---

## M4 — XHTTP транспорт *(1-2 недели)*

**Цель:** server + client для XHTTP по H1/H2.

**Crate:** `donut-carrier`.

**Deliverables:**
- [ ] Server mode `stream-one` (MVP, default под REALITY):
  - [ ] hyper service, ловит POST на path `{session_id_template}`
  - [ ] request body = upload stream, response body = download stream
  - [ ] VLESS header в начале request body
- [ ] Server mode `stream-up`:
  - [ ] POST для upload, parallel GET для download, session binding по path UUID
- [ ] Server mode `packet-up`:
  - [ ] POST `?seq=N` для chunks, buffered merge в правильном порядке
  - [ ] `scMaxBufferedPosts = 30`, `scMaxEachPostBytes = 1_000_000`
- [ ] Client: одинаковый 3-mode dialer, возвращает AsyncRead/AsyncWrite
- [ ] Placements: Path (default), Query, Header(`X-Session`/`X-Seq`), Cookie, Body
- [ ] Padding via Referer query
- [ ] `xhttp-config` в JSON-совместимом виде
- [ ] HTTP/1.1 и HTTP/2 — HTTP/3 отложен до M5

**Тесты:**
- [ ] Interop: xray-core client в `stream-one` подключается к нашему серверу, passes trafic (iperf)
- [ ] Interop: наш client → xray-core server, passes
- [ ] Все три режима: interop в обе стороны

**Acceptance:** HTTP-maskirovka проходит `Wireshark`-взгляд "это нормальный POST/GET", traffic дешифруется только с REALITY ключом.

---

## M5 — QUIC / HTTP-3 *(1 неделя)*

**Цель:** XHTTP поверх HTTP/3.

**Crate:** `donut-quic` + расширение `donut-carrier`.

**Deliverables:**
- [ ] `quinn` с custom `rustls-reality` как TLS provider
- [ ] `h3` + `h3-quinn` сервер и клиент
- [ ] Все 3 XHTTP mode работают поверх H3 (маршрутизация XHTTP-слоя абстрагирована от HTTP-версии)
- [ ] Custom congestion: cubic default; TODO: BBR port из quiche — отдельный тикет
- [ ] `allowInsecure=false` по-умолчанию
- [ ] UDP-socket tuning: `SO_RCVBUF=8M`, GSO/GRO где есть

**Acceptance:** xray-core client в `stream-one` over H3 → наш сервер; наш client over H3 → xray сервер.

---

## M6 — Server daemon (sing-out) *(1 неделя)*

**Цель:** боевой серверный бинарь.

**Crates:** `donut-server` (bin), `donut-config`, `donut-dns`, `donut-routing`, `donut-io`.

**Deliverables:**
- [ ] JSON config loader, compatible subset of Xray schema (inbounds, outbounds, routing, log)
- [ ] Inbound: VLESS+REALITY+XHTTP(H1/H2/H3) — единственный поддерживаемый sign-in
- [ ] Outbound: `freedom` (direct), `blackhole` (drop) — минимум
- [ ] DNS resolver: UDP + DoH (`https://1.1.1.1/dns-query`)
- [ ] Routing: domain/ip/port/user match → outbound tag
- [ ] `geoip:cn`, `geosite:category-ads-all` через `donut-geo`
- [ ] Graceful shutdown SIGTERM
- [ ] `RUST_LOG`-compatible tracing
- [ ] systemd unit-file в `/packaging/systemd/`

**Acceptance:** `./donut-server -c config.json` стартует, читает xray-подобный конфиг, держит 1000 concurrent VLESS+REALITY+XHTTP соединений в iperf.

---

## M7 — Client daemon *(1 неделя)*

**Цель:** клиентский бинарь с SOCKS5/HTTP listener.

**Crates:** `donut-client` (bin), `donut-socks`, переиспользует M1-M5.

**Deliverables:**
- [ ] SOCKS5 inbound (CONNECT+UDP ASSOCIATE)
- [ ] HTTP CONNECT inbound
- [ ] Outbound: VLESS+REALITY+XHTTP через все три режима и H1/H2/H3
- [ ] Routing client-side (split-tunnel по geosite)
- [ ] uTLS Chrome fingerprint (минимум один, Chrome 120)
- [ ] Mobile-friendly: single config file, no daemon complexity
- [ ] Xray JSON config — импорт субсета

**Acceptance:** `curl --socks5 127.0.0.1:1080 https://www.google.com` через наш сервер — проходит; в Wireshark — TLS на порт 443 с ClientHello, похожим на Chrome.

---

## M8 — OpenWrt сборка *(3-5 дней)*

**Deliverables:**
- [ ] `scripts/build-openwrt.sh` — cross-compile через Docker `rust-musl-cross`
- [ ] Target `aarch64-unknown-linux-musl` — основной (modern routers)
- [ ] Target `armv7-unknown-linux-musleabihf` — ipq806x и co.
- [ ] Target `mipsel-unknown-linux-musl` — `-Z build-std`, nightly-CI
- [ ] Feature `openwrt-minimal`:
  - отключает H3
  - использует `ring` вместо `aws-lc-rs`
  - логи stderr-only, без `tracing-subscriber` file rotation
  - disable geosite (или lazy-load с /tmp)
- [ ] UPX-сжатие
- [ ] OpenWrt `Makefile` в `packaging/openwrt/` для кастомной прошивки
- [ ] Smoke-test: запустить на эмуляторе QEMU armv7

**Acceptance:** стрипнутый `donut-client` для aarch64-musl ≤ 5 MB; запускается на роутере с 64MB RAM, держит 50 concurrent соединений.

---

## M9 — Observability + прод-подготовка *(3-5 дней)*

**Deliverables:**
- [ ] Prometheus `/metrics` на сервере (отдельный listener)
- [ ] Metrics: bytes_in/out per user, active_conns, handshakes{result=}, forward_events{reason=}
- [ ] `donut-tools keygen` — генерация X25519 keypair + shortID
- [ ] `donut-tools check-reality <host:port>` — проверяет что удалённый REALITY-сервер жив и selfsteal работает
- [ ] `donut-tools config-gen --server|--client` — интерактивный генератор конфига
- [ ] Docker images: `ghcr.io/<user>/donut-server`, `donut-client`
- [ ] Release CI: `cargo-dist` или ручной `scripts/release.sh` → бинари под 5 таргетов

**Acceptance:** можно развернуть сервер из docker-compose за 5 минут, `keygen → config → up`.

---

## M10 (опционально) — Post-quantum / fingerprints / Vision *(отложено)*

- ML-DSA-65 post-quantum (xray v25.7.26+): подписывает certSignature в `ExtraExtensions`, 3309 байт; требует RSA-target или fat cert chain.
- Дополнительные uTLS fingerprints: Firefox, Safari, Safari iOS
- Vision flow (`xtls-rprx-vision`) для TCP+REALITY (не XHTTP) — если будет спрос

---

## Зависимости между milestones

```
M0 ─┬─ M1 ─────────────────┐
    │                      │
    ├─ M2 ── M3 ── M4 ─────┼── M6 (server)
    │              │       │
    │              └─ M5 ──┴── M7 (client) ── M8 (openwrt)
    │                                          │
    └─ *crates dns/routing/geo* ───────────────┴── M9 (obs)
```

**Критический путь:** M0 → M2 → M3 → M4 → M6. Всё остальное ответвляется.

---

## Риск-регистр и контроль

| Milestone | Risk | Triger → mitigation |
|---|---|---|
| M2 | rustls-форк не проходит | +1 неделя, переход на `boring` |
| M3 | REALITY test-vectors несходятся с xray | pair-debug через tcpdump+wireshark-keylog |
| M4 | XHTTP spec поменялся | ежемесячная сверка `git log transport/internet/splithttp` |
| M5 | quinn + custom rustls несовместимы | downgrade на H2-only, H3 → M10 |
| M8 | MIPS tier-3 не собирается | downgrade: поддерживаем только armv7+aarch64 на v1.0 |

---

## Ежемесячная рутина

- **Первый понедельник месяца:** `git pull` xray-core main, diff против нашей зафиксированной версии, апдейт `docs/PROTOCOLS.md` если есть breaking changes
- **Раз в квартал:** update `rustls-reality` fork на свежий rustls tag
- **Перед release:** interop-тест против последних 3 стабильных версий xray-core в Docker
