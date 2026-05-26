# HANDOFF — hold-the-donut (для новой сессии)

Дата чекпоинта: 2026-05-26. Отвечай по-русски, research/специфику пиши в `docs/`.

## Что это
Rust-рерайт подмножества Xray: личный anti-censorship прокси на своём VPS,
**cert-based + self-steal**, RU-трафик идёт **direct** (split-tunnel). Перед
работой читай `docs/DEPLOYMENT.md` (полное состояние) и `docs/VISION_PROTOCOL.md`
(спека Vision).

## Боевой сервер (обновлено 2026-05-26 — один флоу: raw+vision:xray)
`ssh cozbystorage` (Rocky 9.4 x86_64, `cozbystorage.duckdns.org` → 144.31.85.233). **Канал
флаки — оборачивай SSH/коннекты в ретраи.**
- **tcp/443** = `donut-server.service` → `/etc/donut/server.toml`: `transport:raw`,
  **`vision:xray`** (faithful Xray Vision + raw splice), cert-TLS (Let's Encrypt),
  self-steal `dest=127.0.0.1:8080` (filebrowser). Конфиг в **TOML**. Один user-UUID.
  Метрики `127.0.0.1:9090`, JSON-логи, port-25 → block.
- **Совместимо с готовыми App Store VLESS-клиентами** (HAPP/Streisand/v2box) — vless://-ссылка
  из `donut-tools config-gen --transport raw`. Проверено боевым Xray-клиентом end-to-end
  (api.ipify → 144.31.85.233, cloudflare-trace loc=DE tls=1.3, self-steal → filebrowser 200).
- **Отключены/остановлены тестовые**: `donut-server-tls` (был tcp/443 XHTTP), QUIC-инстанс
  (был udp/443) — старый бинарь и `.json`-конфиги в бэкапе (`/etc/donut/backup/`,
  `/usr/local/bin/donut-server.bak.*`). udp/443 сейчас свободен.
- `certbot-renew.timer` + `donut-cert-deploy.sh` (хук теперь рестартит только `donut-server`,
  серт до 2026-08-24). `donut-log-vacuum.timer`.
- **Деплой-артефакты**: `Dockerfile` (amd64 кросс-сборка) → `/tmp/donut-deploy/`. Конвенция
  в `docs/DEPLOYMENT.md` §4. Бинарь на bookworm-glibc 2.36 запускается на Rocky glibc 2.34 (ок).
- Клиент локально `~/.donut/`: `donut-client` + конфиги, базы geoip/geosite. Репро Xray-клиента: `/tmp/donut-interop/prod-client.json`.

## Реализованные транспорты/флоу (всё закоммичено в main, НЕ запушено)
- Транспорты: `veil`(REALITY), `tls`(cert XHTTP: mode stream-one/stream-up/packet-up), `quic`/`h3`, `carrier`(за reverse-proxy, mode → CDN, #9 закрыт), **`raw`**(VLESS прямо по TLS + self-steal triage).
- Flow: `none`, `xtls-rprx-vision` (две реализации — см. ниже).
- **UUID-аутентификация** во всех транспортах (`inbound.users`/`outbound.uuid`, fail-closed).
- Метрики Prometheus, JSON-логи, vacuum-таймер.

## Interop с настоящими VLESS-клиентами (Xray и т.п.)
- **`raw` + flow=""** — РАБОТАЕТ (проверено реальным Xray 26.5.9). `donut-wire` байт-совместим с Xray VLESS.
- **`raw` + `xtls-rprx-vision`** — dual-стратегия:
  - `vision: "donut"` (дефолт) — наш простой Vision (`donut-io::vision`), для нашего клиента.
  - `vision: "xray"` (opt-in) — **faithful Xray Vision** — РАБОТАЕТ с настоящим Xray-клиентом обе стороны (см. ниже).
- `tls`/`xhttp`/`h3` (carrier) — НЕ Xray-совместимы (своё framing); решено **НЕ портировать** Xray-XHTTP/h3 (большой объём, низкий ROI, QUIC в RU душится).

## faithful Xray Vision на `raw` — ГОТОВО ✅ (2026-05-26)
Цель: чтобы готовые VLESS-клиенты из App Store (HAPP и т.п.) работали через наш
`raw`+`vision:xray` без своего iOS-клиента. Достигнуто.

**Root cause (была неверная гипотеза прошлой сессии «потерянный байт»):** XTLS
Vision-splice **обходит внешний TLS**. После `CommandPaddingDirect` настоящий
Xray-клиент читает/пишет сырой TCP (inner-TLS как есть, без двойного шифрования —
`UnwrapRawConn` в `proxy/proxy.go:690`). Наш сервер терминировал внешний TLS через
rustls и продолжал писать через него → клиент видел rustls-шифртекст вместо сырого
inner-TLS → rc=56.

**Фикс (реализован, без модификации форка rustls):**
- `crates/donut-server/src/vision_xray_splice.rs`:
  - `RecordTlsServer` — ручной драйв `rustls::ServerConnection` **по одной
    outer-TLS-записи за раз** (парс 5-байтного plaintext-заголовка → скармливаем
    ровно одну запись), чтобы rustls не «переедал» за Direct-запись.
  - `vision_server_splice` — один `select!`-таск: uplink `Unpadder`, downlink
    `xtls_padding`/`FilterState`; на `CommandPaddingDirect` каждая сторона
    переходит на сырой TCP мимо rustls; после splice обеих → `copy_bidirectional`
    на сыром сокете (полный дуплекс + XTLS «без двойного шифрования»).
  - Провязка: `run_raw_proxy` → `handle_xray_vision_session` (ручной handshake →
    triage → VLESS-request → splice). `vision:donut`/`flow:none` — на tokio-rustls.
- Удалён мёртвый `donut-io::vision_xray::vision_server_copy` (старый небайт-точный
  путь через rustls). Кодек-примитивы (`xtls_padding`/`Unpadder`/`FilterState`/
  `is_complete_record`) остались в `donut-io`.

**Проверено (Xray 26.5.9 Docker → donut-server `vision:xray` → локальный инспектируемый
TLS-апстрим `/tmp/donut-interop/upstream.py`):** HTTPS GET (200, байт-точно), 5 MB
download (SHA совпал), **3 MB POST** (апстрим получил точные байты/SHA — это то, что
no-splice провалил бы), plaintext-HTTP (Continue-padding без splice). `cargo test
--workspace` зелёный, `clippy -D warnings` чист.

## Открытое / отложенное
- **REALITY (`veil`) + Vision** — сейчас `veil` ходит только через `vision:donut`;
  faithful-splice пока только на `raw`+cert-TLS. Если захотим REALITY+Vision для
  клиентов — перенести splice-логику на veil-путь (та же `RecordTlsServer`-идея,
  но conn от REALITY-handshake).
- Производительность: в mixed-фазе (одна сторона сплайснута, другая нет) tunnel
  read/write сериализованы в одном select-таске; bulk-фаза уже full-duplex через
  `copy_bidirectional`. Узким местом не выглядит, но можно мерить.
- **X1-X3**: faithful Xray XHTTP-over-h3 — решено НЕ делать.
- Метрики байт для xray-vision-пути не считаются (`add_bytes`) — мелочь, при желании добавить.

## Команды
```bash
cargo build --release -p donut-server -p donut-client   # native
cargo test --workspace                                   # 43+ групп ok
cargo clippy --workspace --all-targets -- -D warnings    # чист
# amd64 для сервера: docker build --platform linux/amd64 -t donut . ; docker cp ...
```

## Правила
- **НЕ коммитить без явной просьбы; без Co-Authored-By/Claude-трейлеров.** Работать прямо в `main`, без worktree/веток.
- Секреты (root-пароль, filebrowser, реальный SECRET_PATH `/assets/8ff0ff9209379251/upload`) — в менеджере паролей; в репо плейсхолдеры.
