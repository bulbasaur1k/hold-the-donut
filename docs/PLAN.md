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
| M5.5 step 1 | ✅ done — Vision padding-кодек (`donut-wire`: `VisionPadder`/`VisionUnpadder`, state-machine, сверено с v26.4.15) | _uncommitted_ | 5 unit (round-trip/chunked/UUID/End→direct/empty) |
| M5.5 step 2 | ⏳ pending — trafficState TLS-детект + raw-TCP+REALITY carrier + `flow=vision` wiring | — | — |
| REALITY-hardening | ✅ done — server-auth proof `HMAC(AuthKey)` в туннеле; клиент без `trusted_cert` (NoCertVerification), MITM-защита; снято M3-упрощение | _uncommitted_ | 1 unit (proof) + покрыт veil-tunnel e2e |
| M6 step 1 | ✅ done — carrier proxy (stream-one + freedom outbound) | `a2c4992` | 1 e2e (real TCP echo through proxy) |
| M6 step 2a | ✅ done — selfsteal triage + REALITY-Forward relay (байт-прозрачный) | _uncommitted_ | 1 e2e (real ClientHello → relay to decoy, обе стороны) |
| M6 step 2b | ✅ done — veiled-TLS терминация на Tunnel (`VeilServer` + `PrefixedStream`) | _uncommitted_ | 1 e2e (veil tunnel: рукопожатие + расшифрованное эхо) |
| M6 step 2c | ✅ done — carrier-over-stream (`serve_connection`/`dial_over_stream`) поверх veiled-TLS | _uncommitted_ | 1 e2e (carrier поверх veil-туннеля, payload round-trip) |
| M6/M7 veiled демоны | ✅ done — `run_veil_proxy` (server) + `run_veil_socks_proxy` (client) | _uncommitted_ | **капстоун e2e**: SOCKS5 → veil → carrier → freedom → echo |
| M6 step 4 | ✅ done — JSON config loader (`donut-config`) + `main.rs` wiring обоих бинарей | _uncommitted_ | 3 config unit + примеры `docs/examples/` |
| M6 step 3a | ✅ done — routing match-движок (`donut-routing`: domain/cidr/port → outbound) | _uncommitted_ | 7 unit (suffix/full/keyword, v4/v6 CIDR, ports, порядок) |
| M6 step 3b | ✅ done — routing проведён в сервер (конфиг `routing` → `Router` → `handle_session`, `block`/`blackhole` дропает) | _uncommitted_ | 2 routing-config unit + 1 blackhole e2e |
| M6 step 3c | ✅ done — geo `.dat` парсер (`donut-geo`: GeoIP/GeoSite parse + lookup/contains/matches) | _uncommitted_ | 2 unit (prost round-trip + contains/matches) |
| M6 step 3d | ✅ done — `geoip:`/`geosite:` условия в routing (`donut-routing`×`donut-geo`, конфиг грузит `.dat`) | _uncommitted_ | 1 geo-routing unit |
| M6 step 3e | ✅ done — DNS resolver (`donut-dns`: system + DoH) проведён в сервер (конфиг `dns`) | _uncommitted_ | 1 dns unit (IP short-circuit) |
| donut-tools keygen | ✅ done — X25519 keypair + shortID (base64-url, xray-compat) | _uncommitted_ | unit (pub↔priv) |
| donut-tools config-gen | ✅ done — согласованная пара server+client конфигов (свежий keypair) | _uncommitted_ | 1 unit (консистентность + serde round-trip) |
| M9 metrics | ✅ done — Prometheus `/metrics` (English): connections/active/handshakes{tunnel,forward}/blackhole/bytes{up,down} | _uncommitted_ | 1 unit (render) + 1 e2e (GET /metrics) |
| M7 step 1 | ✅ done — SOCKS5 inbound + carrier outbound | _next commit_ | 1 e2e (curl-style SOCKS5 → donut-client → donut-server → echo) |
| M7 step 2 | ✅ done — veiled-TLS dial (`VeilClient`) | _uncommitted_ | покрыт тем же veil-tunnel e2e |
| M7 split-tunnel | ✅ done — client-side routing: `direct`/`block`/proxy по domain/ip/port/geoip/geosite (RU/домашнее — мимо сервера, с локального IP) | _uncommitted_ | 1 e2e (direct минует недоступный сервер) |
| M8  | ⏳ pending | — | — |
| M9  | ⏳ pending | — | — |
| M10 | ⏳ pending — optional | — | — |

Workspace test count: **76** (`cargo test --workspace` зелёное).
Lint gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings` чисто.

---

## Принципы

- **Каждый milestone — самостоятельно работает и тестируется.** Не делаем "M3 закончим через полгода".
- **Пишем тесты сразу** для протокольных крейтов — байт-точные vectors from xray-core.
- **CI с первого milestone** — GitHub Actions, `cargo fmt + clippy + test` в каждом PR.
- **Golden path first:** сначала happy case proxy через REALITY+XHTTP, потом error paths, потом оптимизации.
- **Interop-тест** против реального `xray-core` в Docker — обязательный gate для M4+.

---

## Целевые сценарии деплоя *(зафиксировано 2026-05-21)*

Проект целится в **3 боевых сценария**. Все три используют общее ядро **VLESS + REALITY** (TLS-маскировка + auth) и различаются только транспортом поверх него:

| # | Сценарий | Транспорт | Назначение | Milestone | Interop |
|---|---|---|---|---|---|
| 1 | **Reality** | VLESS+REALITY + **Vision** (`xtls-rprx-vision`) поверх raw TCP | Самый быстрый: без HTTP-обёртки и без TLS-in-TLS; классический Reality-сетап | **M5.5** | xray Vision-клиент ↔ наш сервер |
| 2 | **XHTTP** | VLESS+REALITY + XHTTP (stream-one/up, packet-up) поверх **H1/H2** | CDN-дружелюбная HTTP-маскировка | **M4 ✅** | xray XHTTP ↔ наш сервер (обе стороны) |
| 3 | **QUIC / HTTP-3** *(«Hysteria-like»)* | VLESS+REALITY + XHTTP поверх **H3 (QUIC/UDP)** | Низкая латентность, lossy/throttled сети | **M5** | xray H3 ↔ наш сервер |

**Решения (2026-05-21):**
- Сценарий 1 «Reality» = **Vision over raw TCP** — поднят из M10-опционального в **core** (новый **M5.5**). Vision несовместим с XHTTP (issue #5576), поэтому это отдельный TCP-путь, а не режим XHTTP.
- Сценарий 3 «QUIC/HTTP3» = **текущий M5** (XHTTP-over-H3, xray-совместимый), а **не** отдельный протокол Hysteria. «Аналог Hysteria» — разговорное: берём от Hysteria только идею **опционального Brutal-CC** (фикс. полоса для lossy-сетей); masquerade неавторизованных уже даёт REALITY-Forward на QUIC-TLS handshake. **Не** делаем собственный H3-auth / Salamander / reverse-proxy — interop с xray важнее.

---

## Self-Steal и подложка — как REALITY прикрывает VPN-сервер *(исследование, 2026-05-21)*

### Зачем это вообще

REALITY защищается от **активного зондирования** (active probing) GFW. Любой
может постучаться TLS-хендшейком на наш `IP:443`. Сервер обязан выглядеть как
**настоящий веб-сайт**, иначе «TLS-сервер, который на всё отвечает странно» —
сам по себе сигнатура. Механизм: на ClientHello без валидного REALITY-auth
(чужой/зонд/браузер) сервер **байт-прозрачно проксирует** соединение к
*реальному* TLS-сайту (`dest`/`target`). Зонд видит валидный сертификат и
настоящий контент этого сайта и не может отличить нас от обычного reverse-proxy
к этому сайту. Для авторизованных же клиентов (SessionID-seal сходится) идёт
проксирование туннеля. Подробности байт-логики — `PROTOCOLS.md §2`.

### Две стратегии `dest`

| | **Borrowed (классика)** | **Self-Steal (selfSteal)** |
|---|---|---|
| `dest` | внешний популярный сайт (`www.microsoft.com:443`) | свой веб-сервер на **той же машине** (`127.0.0.1:8443`), отдающий **твой** домен |
| SNI | чужой домен | твой домен |
| Сертификат, что видит зонд | настоящий cert чужого сайта | настоящий cert твоего домена (Let's Encrypt) |
| Контроль | нет (зависим от чужого поведения/аптайма) | полный |
| Латентность forward | до внешнего сайта | localhost |
| Слабые места | твой ASN/PTR/гео не совпадают с «чужим» доменом; чужой сайт должен держать TLS1.3+X25519+H2 и не быть с тобой в одной CDN; редиректы/гео-различия | домен и контент целиком на тебе → нужна **достоверная подложка**, иначе «пустой nginx» = палево |

**Вывод:** для нашего деплоя целимся в **Self-Steal** (полный контроль,
консистентный ASN/PTR/домен, localhost-латентность). Borrowed оставляем как
поддерживаемый конфиг-вариант, но рекомендуем selfSteal.

### Нужна ли подложка? — Да. Что именно «достоверный сайт»

Пустая дефолтная страница nginx, `444`/обрыв соединения или голый `200 OK` —
это **палево**: зонд и случайный браузер должны увидеть правдоподобный сайт.
Требования к подложке:

- реальный контент (несколько страниц, ассеты, favicon, `robots.txt`);
- консистентные заголовки (`Server:`, HSTS, тип контента), TLS-стек —
  распространённый (nginx/caddy/наш);
- **ALPN совпадает** с тем, что реально умеет подложка (h2/http1.1) — forward
  байт-прозрачный, поэтому ALPN = что договорит `dest`;
- одинаковое поведение для «зонд» и «браузер» (никакой ветки «если не наш —
  отдать другое»);
- желательно правдоподобная причина трафика (страница загрузок/облако/статус —
  объясняет полосу).

### Что можем сделать (варианты подложки)

1. **External nginx/caddy рядом** (рекомендуемый прод-дефолт): инструкция +
   готовый конфиг, `dest=127.0.0.1:8443`, реальный домен + Let's Encrypt.
   Наш бинарь не лезет в HTTP — только REALITY-forward.
2. **Встроенный decoy-сервер** (`--decoy ./site`, feature `decoy`): минимальный
   статик-HTTP+TLS на отдельном порту в `donut-server`, чтобы single-binary
   деплой работал без nginx. Нужен **свой валидный cert** для SNI-домена.
3. **`donut-tools gen-decoy`**: генератор статической подложки из шаблона
   (`blog` / `landing` / `status` / `files`) + рекомендованный nginx/caddy конфиг.
4. **Reverse-proxy-зеркало реального сайта** — не рекомендуем (правовые/
   поведенческие риски), оставляем borrowed-dest как путь для этого кейса.

### Дельта к плану (deliverables)

- **M6** — REALITY-Forward relay: реализовать `VeilDecision::Forward` →
  байт-прозрачный TCP-relay на конфигурируемый `dest` (selfSteal `127.0.0.1:N`
  или внешний). Сейчас решение возвращается, но relay не подключён.
- **M6 (опц., feature `decoy`)** — встроенный статик-HTTPS decoy-listener.
- **M9 / donut-tools** — `gen-decoy` (генератор подложки + конфиг) и расширение
  `check-reality`: проверка, что fallback ведёт себя идентично для зонда и
  браузера, ALPN корректен, cert валиден, нет дефолт-страницы-палева.

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

## M5 — QUIC / HTTP-3 *(1 неделя)* — сценарий 3 «QUIC/HTTP3 (Hysteria-like)»

**Цель:** XHTTP поверх HTTP/3 (xray-совместимый). Это и есть боевой сценарий 3; «Hysteria» — разговорное обозначение QUIC-транспорта, отдельный протокол не делаем.

**Crate:** `donut-quic` + расширение `donut-carrier`.

**Deliverables:**
- [ ] `quinn` с custom `rustls-reality` как TLS provider
- [ ] `h3` + `h3-quinn` сервер и клиент
- [ ] Все 3 XHTTP mode работают поверх H3 (маршрутизация XHTTP-слоя абстрагирована от HTTP-версии)
- [ ] Custom congestion: cubic default; **опц. Brutal-CC** (фикс. целевая полоса, игнор loss-backoff — Hysteria-style для lossy/throttled сетей); TODO: BBR port из quiche — отдельный тикет
- [ ] Masquerade неавторизованных: переиспользуем REALITY-Forward на QUIC-TLS handshake (как в M3); собственный H3-auth / reverse-proxy / Salamander **не** делаем
- [ ] `allowInsecure=false` по-умолчанию
- [ ] UDP-socket tuning: `SO_RCVBUF=8M`, GSO/GRO где есть

**Acceptance:** xray-core client в `stream-one` over H3 → наш сервер; наш client over H3 → xray сервер.

---

## M5.5 — REALITY + Vision over raw TCP *(сценарий 1 «Reality», ~1 неделя)*

**Цель:** самый быстрый сценарий — VLESS+REALITY с flow `xtls-rprx-vision` поверх голого TCP, без HTTP/XHTTP-обёртки и без видимого TLS-in-TLS. Поднят из M10-опционального в core (решение 2026-05-21). Зависит от M3 (REALITY) + M1 (VLESS), параллелен M4/M5.

**Crates:** `donut-wire` (Vision flow + padding), `donut-veil` (переиспользует REALITY auth), TCP-carrier путь.

**Deliverables:**
- [ ] `docs/PROTOCOLS.md` — байт-спека Vision (сверить с `proxy/vless/encoding` xray-core при реализации): addon `flow="xtls-rprx-vision"`, padding-команды (`commandPaddingContinue=0x00` / `End=0x01` / `Direct=0x02`), `trafficState`, детект окончания inner TLS 1.3 handshake
- [ ] `donut-wire`: Vision reader/writer — инъекция padding в первые записи, переключение в direct-copy (splice) после inner handshake
- [ ] Server: VLESS+REALITY поверх raw TCP, ветка `flow=vision`; `flow="none"` поверх TCP по-прежнему работает
- [ ] Client: dial Vision поверх REALITY+TCP
- [ ] Валидатор конфига отвергает Vision вместе с XHTTP (issue #5576)

**Тесты:**
- [ ] Interop: стандартный xray-core client с `flow=xtls-rprx-vision` ↔ наш сервер, проходит трафик (iperf)
- [ ] Interop: наш client ↔ xray-core server с Vision
- [ ] Known-answer: padding-вектора из xray-capture

**Acceptance:** xray Vision-клиент качает через наш сервер; в Wireshark — один TLS 1.3 поток на :443 без видимого double-wrap на установившемся соединении.

---

## M6 — Server daemon (sing-out) *(1 неделя)*

**Цель:** боевой серверный бинарь.

**Crates:** `donut-server` (bin), `donut-config`, `donut-dns`, `donut-routing`, `donut-io`.

**Deliverables:**
- [ ] JSON config loader, compatible subset of Xray schema (inbounds, outbounds, routing, log)
- [ ] Inbound: VLESS+REALITY все 3 сценария — Vision/raw-TCP (M5.5), XHTTP H1/H2 (M4), XHTTP H3 (M5); единственный поддерживаемый sign-in
- [ ] **REALITY-Forward relay (selfsteal)**: на `VeilDecision::Forward` — байт-прозрачный TCP-relay на конфигурируемый `dest` (selfSteal `127.0.0.1:N` или внешний сайт). См. раздел «Self-Steal и подложка»
- [ ] _(опц., feature `decoy`)_ встроенный статик-HTTPS decoy-listener (`--decoy ./site`) со своим cert — для single-binary деплоя без nginx
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
- [ ] Outbound: VLESS+REALITY все 3 сценария — Vision/raw-TCP, XHTTP (3 режима) H1/H2, XHTTP H3
- [x] Routing client-side split-tunnel: `geoip`/`geosite`/domain/ip/port → `direct` (минуя сервер, с локального IP) / `block` / `proxy`; client-side resolver для direct-dial ✅
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
- [x] Prometheus `/metrics` на сервере (отдельный listener), английские имена ✅
- [x] Metrics: connections_total, active_connections, handshakes{tunnel,forward}, blackhole, bytes{up,down} ✅ (per-user — позже)
- [x] `donut-tools keygen` — генерация X25519 keypair + shortID (base64-url xray-compat + hex) ✅
- [ ] `donut-tools check-reality <host:port>` — проверяет что удалённый REALITY-сервер жив и selfsteal работает: fallback идентичен для зонда и браузера, ALPN корректен, cert валиден, нет дефолт-страницы-палева
- [ ] `donut-tools gen-decoy --domain <d> --template <blog|landing|status|files>` — генератор статической подложки + рекомендованный nginx/caddy конфиг
- [x] `donut-tools config-gen` — генератор согласованной пары server+client конфигов (свежий keypair+shortID, флаги для домена/адресов/путей) ✅
- [ ] Docker images: `ghcr.io/<user>/donut-server`, `donut-client`
- [ ] Release CI: `cargo-dist` или ручной `scripts/release.sh` → бинари под 5 таргетов

**Acceptance:** можно развернуть сервер из docker-compose за 5 минут, `keygen → config → up`.

---

## M10 (опционально) — Post-quantum / fingerprints *(отложено)*

- ML-DSA-65 post-quantum (xray v25.7.26+): подписывает certSignature в `ExtraExtensions`, 3309 байт; требует RSA-target или fat cert chain.
- Дополнительные uTLS fingerprints: Firefox, Safari, Safari iOS
- _Vision flow (`xtls-rprx-vision`) перенесён в core → **M5.5** (решение 2026-05-21)._

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

**Критический путь:** M0 → M2 → M3 → M4 → M6. Всё остальное ответвляется. M5 (QUIC/H3) и M5.5 (Vision/TCP) — параллельные транспортные ответвления от M3, не на критическом пути.

---

## Риск-регистр и контроль

| Milestone | Risk | Triger → mitigation |
|---|---|---|
| M2 | rustls-форк не проходит | +1 неделя, переход на `boring` |
| M3 | REALITY test-vectors несходятся с xray | pair-debug через tcpdump+wireshark-keylog |
| M4 | XHTTP spec поменялся | ежемесячная сверка `git log transport/internet/splithttp` |
| M5 | quinn + custom rustls несовместимы | downgrade на H2-only, H3 → M10 |
| M5.5 | Vision padding / trafficState spec drift | сверка `proxy/vless/encoding` при реализации + known-answer vectors из xray-capture |
| M8 | MIPS tier-3 не собирается | downgrade: поддерживаем только armv7+aarch64 на v1.0 |

---

## Ежемесячная рутина

- **Первый понедельник месяца:** `git pull` xray-core main, diff против нашей зафиксированной версии, апдейт `docs/PROTOCOLS.md` если есть breaking changes
- **Раз в квартал:** update `rustls-reality` fork на свежий rustls tag
- **Перед release:** interop-тест против последних 3 стабильных версий xray-core в Docker
