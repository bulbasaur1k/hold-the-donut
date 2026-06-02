# xHTTP transport — design doc

Цель: реализовать **Xray-совместимый xHTTP-транспорт** на стороне `donut-server`
так, чтобы готовые off-the-shelf VLESS-клиенты (HAPP, xray в PassWall) могли
подключаться по xHTTP без перекомпиляции.

Контекст: ТСПУ-2026 распознаёт сигнатуру `raw + xtls-rprx-vision` (см.
[TSPU_NOTES.md](TSPU_NOTES.md)). xHTTP — workaround по дизайну RPRX:
прокси-трафик «как обычный веб», блокировка должна ломать настоящие сайты.

**Статус**: **milestone 1 реализован** (2026-06-02). Все wire-параметры ниже
сверены с [`splithttp/dialer.go`](https://github.com/XTLS/Xray-core/blob/main/transport/internet/splithttp/dialer.go),
[`hub.go`](https://github.com/XTLS/Xray-core/blob/main/transport/internet/splithttp/hub.go),
[`config.go`](https://github.com/XTLS/Xray-core/blob/main/transport/internet/splithttp/config.go)
и [Discussion #4113](https://github.com/XTLS/Xray-core/discussions/4113) на
2026-06-02. Перед расширением (M2+) — пересверить с актуальной веткой
xray-core, спецификация эволюционирует.

### Что реально сделано в M1 (и чем отличается от черновика выше)

Ключевое архитектурное решение: **не заводили отдельный крейт `donut-xhttp`**
(как предлагал §3.2). У нас уже есть `donut-carrier` — hyper+h2 сервер с
`stream-one`/`stream-up`/`packet-up`, спариванием сессий, decoy self-steal и
4 placement'ами. Он закрывал ~90% работы, поэтому вместо дублирования сделали
его **byte-faithful к Xray** и добавили тонкий arm `transport = "xhttp"` в
`donut-server`. Соответствует глобальному правилу «один крейт, split только при
реальной нужде».

Конкретные правки (всё аддитивно — `transport = "tls"` и donut-клиент не
сломаны, что подтверждают зелёные `tls_carrier_*_e2e`):

1. **Session-id**: `donut_carrier::SessionId::from_str` теперь принимает и
   donut-форму (32 hex), и **Xray-форму — UUID с дефисами (36 символов,
   `8-4-4-4-12`)**. Обе декодируются в те же 16 байт, так что uplink-POST и
   downlink-GET спариваются независимо от клиента. Это была главная wire-несовместимость
   (`crates/donut-carrier/src/session.rs`).
2. **X-Padding** (рандом 100–1000 на КАЖДЫЙ response) + **SSE/anti-buffer
   заголовки** (`Content-Type: text/event-stream`, `X-Accel-Buffering: no`,
   `Cache-Control: no-store`, CORS) — на всех downlink-ответах всех трёх mode
   (`server/mod.rs::downlink_response`, `x_padding`).
3. **Host-pin**: `ServerConfig.host: Option<String>` — запрос с правильным
   path но чужим `Host`/`:authority` уходит в decoy/404, как hub.go у Xray
   (`server/session_extract.rs::host_matches`).
4. **Config**: `ServerInbound.host` + значение `transport = "xhttp"`; arm в
   `main.rs` дефолтит mode в `stream-up` (Xray `auto` для TLS+H2).
5. **Uplink keepalive (stream-up) — ОКАЗАЛОСЬ ОБЯЗАТЕЛЬНЫМ для корректности,
   не просто anti-idle.** В Xray тело *ответа* на uplink-POST переиспользуется
   как keepalive-канал (downlink-данные идут по отдельному GET): сервер держит
   этот response открытым и периодически пишет в него `X`-padding
   (`scStreamUpServerSecs`, рандом). Критично: если завершить response на
   uplink-POST (пустой 200), H2 шлёт END_STREAM и **закрывает uplink-стрим** —
   клиент больше не может дослать данные (TLS Finished и т.п.), хендшейк
   виснет. Реализовано в `server/mod.rs::uplink_keepalive_response`, включается
   когда клиент прислал `Referer` (Xray шлёт; donut-клиент — нет и закрывает
   uplink сам, поэтому ему keepalive не нужен и не отправляется, иначе он
   буферизовал бы бесконечный padding).
6. **Тесты**: `stream_up_accepts_xray_uuid_session` (сырой hyper-клиент шлёт
   dashed-UUID в path + `Referer`, проверяет echo, Xray-заголовки и keepalive-
   заголовки на uplink-POST) и `wrong_host_is_rejected` в
   `donut-carrier/src/tests.rs`; unit-тесты UUID-парсинга в `session.rs`.

### ✅ Wire-тест против реального Xray CLI (2026-06-02) — ПРОЙДЕН

Прогон с **xray-core 26.5.9** (docker `teddysun/xray`) как клиентом против
нашего `donut-server transport="xhttp"` (testbench: `scripts/xray-testbench/`,
конфиги `donut-xhttp-server.json` + `xray-client-xhttp.json`):

- xray дайлит `network=xhttp, mode=stream-up, HTTP version 2, host tunnel.example`;
- TLS pin (`pinnedPeerCertSha256`, т.к. `allowInsecure` удалён в 26.5.9), host-pin,
  спаривание сессии по dashed-UUID, decode VLESS-запроса — всё ОК;
- полный multi-roundtrip: HTTPS-хендшейк + GET через туннель к локальному target,
  `up=204 down=24237` байт, `curl exit 0`, HTTP 200.

Замечание по окружению: внешние хосты (example.com, ifconfig.me) резетятся —
это фильтрация egress самой машины + DoH-резолвер отдаёт гео-блокнутые IP
(тот же relay-путь отдаёт 24 КБ на локальный target без ошибок). К xHTTP-коду
отношения не имеет.

**Ещё НЕ сделано** (вынесено в M2+): packet-up seq в path (Xray-форма
`path/sid/seq` — наш сервер пока читает seq из заголовка), HTTP/3, wire-тест
HAPP через прод-VPS (нужен деплой + телефон).

---

## 1. Зачем xHTTP, а не остальное

| Альтернатива | Почему не делаем |
|---|---|
| Hysteria 2 sidecar | Сторонний бинарь, нарушает принцип «один Rust-крейт». См. [TSPU_NOTES §4](TSPU_NOTES.md#что-работает-на-2026-06-01) |
| REALITY (через `veil`) | Уже есть наполовину (veil_server) но REALITY+Vision splice не реализован. Меняет ситуацию средне (тоже TLS-сигнатура) |
| Свой carrier-протокол (текущий `transport = "tls"`) | НЕ xray-совместим — HAPP не подключится. Сами решили в `HANDOFF.md` |
| Альтернативные TCP-порты | По данным 2026-05-31 ТСПУ режет IP+pattern, не порт. Не помогает |
| Смена VPS IP | Резервный план, но это `ops` а не код |

xHTTP — **минимальный код-чейндж который восстанавливает работу через ТСПУ**
для существующих пользователей с существующими клиентами.

---

## 2. Wire-протокол

### 2.1 Три mode

Источники: [Discussion #4113](https://github.com/XTLS/Xray-core/discussions/4113),
[PR #3994](https://github.com/XTLS/Xray-core/pull/3994), [dialer.go](
https://github.com/XTLS/Xray-core/blob/main/transport/internet/splithttp/dialer.go).

| Mode | Wire-форма | Запросов на сессию | Когда взаимодействует |
|---|---|---|---|
| **packet-up** | `POST /<path>/<UUID>/<seq>` для каждого uplink-чанка (seq инкрементальный), `GET /<path>/<UUID>` для downlink-стрима | N+1 | За CDN/Nginx, max совместимость |
| **stream-up** | `POST /<path>/<UUID>` потоковый uplink, `GET /<path>/<UUID>` потоковый downlink | 2 | Direct (без CDN), H2+REALITY |
| **stream-one** | Один `POST /<path>/<UUID>` с **bidirectional stream** в одном запросе | 1 | Только Nginx с `grpc_pass` или CF gRPC |

**Wire-pattern на стороне DPI** (это и есть наш main DPI-evasion):
- packet-up = много мелких HTTP-запросов с инкрементирующимся URL
- stream-up = два долгоживущих потоковых запроса
- stream-one = один полностью двусторонний поток

Для **минимально жизнеспособного donut-сервера**: рекомендую начать с
**stream-up over H2+TLS** — это canonical путь для direct connection без CDN,
и реализация проще чем stream-one (две независимые streams вместо одной
bidirectional).

### 2.2 HTTP-версия

`decideHTTPVersion()` в `dialer.go`:

```
if reality_config != nil:  return "h2"
if tls_config == nil:      return "h1.1"   # not for our case
if "h3" in alpn:           return "h3"     # переключает dest на UDP
else:                      return "h2"     # default
```

Для нашего сетапа (cert-TLS, серверный TLS-handshake мы и так делаем сами через
rustls в `RecordTlsServer`) канон — **HTTP/2 over TLS 1.3**.

**HTTP/3 (over QUIC)** — нет в первой milestone. Это отдельный транспортный
стек (`quinn`-style), цена high. HAPP клиенты могут запросить `h3` только если
явно сконфигурированы — defaultly идут h2.

### 2.3 URL-схема

```
https://<host>/<path>[?<query>][#<fragment>]
                |
                +---> <session-id>/<seq-str>   (packet-up)
                +---> <session-id>             (stream-up, stream-one)
```

`session-id` и `seq-str` могут быть в одном из четырёх мест (placement enum):

| placement | Пример |
|---|---|
| `PlacementPath` | `/<path>/<sessionId>/<seqStr>` (default) |
| `PlacementQuery` | `/<path>?sid=<sessionId>&seq=<seqStr>` |
| `PlacementHeader` | `X-Session-Id: ..., X-Seq: ...` |
| `PlacementCookie` | `Cookie: sid=...; seq=...` |

Для **минимальной имплементации** поддержать **PlacementPath** (default) +
**PlacementQuery**. Header/Cookie добавлять только если конкретный HAPP-конфиг
их требует.

### 2.4 Заголовки и обязательный padding

Каждый клиентский request:
```http
POST /<path>/<sessionId>/<seq> HTTP/2
Host: <transportConfig.Host or tls.ServerName>
Referer: https://<host>/<path>?x_padding=XXXXXX... (100–1000 байт случайно)
User-Agent: <стандартный браузерный, рандомизировать или клиентский config>
```

Каждый серверный response:
```http
HTTP/2 200 OK
Content-Type: application/grpc (или text/event-stream для SSE-fallback)
X-Padding: XXXXXX... (100–1000 байт случайно, на каждый response разное)
```

**X-Padding в response — ОБЯЗАТЕЛЕН для DPI-evasion.** Без него DPI поймает
сервер по фиксированной длине header-block'а. Также: padding должен быть
**случайным на каждый response**, не статическим.

Источник конкретных параметров: [PR #4298](https://github.com/XTLS/Xray-core/pull/4298)
— `x_padding` специально вынесен в Referer (а не в кастомный header), чтобы
не раздувать reverse-proxy логи и не триггерить CORS preflight в Browser Dialer.

### 2.5 Payload framing

После того как HTTP-headers распарсены и сессия идентифицирована (sessionId +
seq), **тело request/response — это сырой VLESS inner-frame** (для первого
запроса в сессии: `[VERSION:1][UUID:16][ADDONS_LEN:1][ADDONS:N][CMD:1][TARGET:M]`),
далее уже application bytes.

Никакого дополнительного xHTTP-framing внутри тела нет. xHTTP отвечает только
за HTTP-обёртку и framing-по-запросам, не за inner-данные. Это удобно — нам
уже не нужно делать ничего нового на уровне VLESS-пакетов, только присоединить
upstream-handler к HTTP-stream'у.

---

## 3. Server-side: что нужно реализовать

### 3.1 Новый transport mode в config

`donut-config::ServerInbound::transport = "xhttp"` (новое значение).

Дополнительные поля в `ServerInbound` (Optional, default'ы из xray):

```toml
[inbound]
listen = "0.0.0.0:443"
transport = "xhttp"
mode = "stream-up"                   # one of: stream-one, stream-up, packet-up
path = "/secret-prefix"              # secret URL prefix (must match client)
cert = "/etc/donut/fullchain.pem"
key = "/etc/donut/privkey.pem"
users = ["<UUID>"]

[inbound.xhttp]
host = "cozbystorage.duckdns.org"    # accepted Host: header value
x_padding_bytes_min = 100            # min X-Padding/Referer x_padding bytes
x_padding_bytes_max = 1000           # max
sc_max_each_post_bytes_min = 100000  # packet-up: min chunk size
sc_max_each_post_bytes_max = 1000000 # packet-up: max chunk size
sc_min_posts_interval_ms_min = 30    # packet-up: min jitter between POSTs
sc_min_posts_interval_ms_max = 80    # packet-up: max jitter
session_placement = "path"           # path | query
```

### 3.2 HTTP/2 server

Нужен полноценный HTTP/2 listener. Текущий код в `donut-server` HTTP не делает.
Варианты:

- **`hyper` + `h2`** — стандарт de-facto, поддерживается; интегрируется с rustls
  через `tokio-rustls`. Размер крейта приемлемый.
- **`axum` поверх hyper** — даёт удобный routing, но тащит много dependencies;
  для нашего «единственный endpoint на любом path» это overkill.
- **Self-rolled h2** — слишком дорого.

**Решение**: `hyper 1.x` + `h2`, без axum. Один Service<Request, Response>
который ловит все методы, парсит path/query, диспатчит.

### 3.3 Request handler skeleton

```rust
async fn xhttp_handle(
    req: Request<Incoming>,
    cfg: Arc<XHttpConfig>,
    state: Arc<SessionTable>,    // map<sessionId, SessionEntry>
) -> Result<Response<BoxBody>, hyper::Error> {
    // 1. Validate Host header
    let host = req.headers().get(HOST).map(|v| v.as_str().ok()).flatten();
    if host != Some(&cfg.host) { return Ok(decoy_response()); }

    // 2. Parse path → (path_prefix, session_id, seq_str_or_none)
    let uri = req.uri();
    let parsed = match cfg.placement {
        Placement::Path => parse_path(uri.path(), &cfg.path_prefix),
        Placement::Query => parse_query(uri),
        _ => unimplemented!(),
    };
    let Some((session_id, seq)) = parsed else {
        return Ok(decoy_response());  // non-tunnel request, forward to decoy
    };

    // 3. Dispatch by method × mode
    match (req.method(), cfg.mode) {
        (&Method::POST, Mode::StreamOne) => handle_stream_one(req, ...).await,
        (&Method::POST, Mode::StreamUp) => handle_upload(req, session_id).await,
        (&Method::GET,  Mode::StreamUp) => handle_download(req, session_id).await,
        (&Method::POST, Mode::PacketUp) => handle_packet(req, session_id, seq).await,
        (&Method::GET,  Mode::PacketUp) => handle_download(req, session_id).await,
        _ => Ok(decoy_response()),
    }
}
```

### 3.4 SessionTable

`HashMap<SessionId, SessionEntry>` за `tokio::sync::Mutex`. SessionEntry содержит:
- Authenticated UUID (после первого POST с inner-frame VLESS request)
- Upstream `TcpStream` (или buffered pipe пока not dialed)
- Mux upload/download channels (для stream-up: два независимых mpsc)
- TTL (idle-timeout, например 180с — переиспользуем `tuning.mux_idle`)

При получении первого POST по новому sessionId:
1. Прочитать VLESS inner-frame request из body
2. Auth UUID против `inbound.users`
3. Resolve `target` (DNS если домен)
4. Dial upstream
5. Зарегистрировать SessionEntry, запустить relay-task

Последующие POST'ы по тому же sessionId — просто пайпят bytes в upstream.

### 3.5 X-Padding generation

```rust
fn x_padding(cfg: &XHttpConfig) -> String {
    let len = rand::thread_rng().gen_range(cfg.x_padding_bytes_min..=cfg.x_padding_bytes_max);
    Alphanumeric.sample_string(&mut rand::thread_rng(), len)
}
```

Применяется в КАЖДОМ response.

### 3.6 Anti-active-probing

ОТКРЫТЫЙ ВОПРОС (см. §6): нужен ли HMAC-check session-id / seq до того
как сервер начнёт что-то отдавать? Это защита от **active probing** — DPI
мог бы посылать тестовые HTTP-запросы на `/<path>/random-uuid` и смотреть
отличается ли response от случайного 404.

**Минимум для milestone 1**: на любой запрос с невалидным sessionId или
неизвестным path — отдавать ровно тот же response что отдал бы decoy
(`fileserver` на 127.0.0.1:8080), либо `404 Not Found` если decoy не настроен.
Без дифференциации по тому "был ли это попытка туннеля". Это базовая защита.

Более продвинутая защита — HMAC-check на основе shared secret (xHTTP это
поддерживает через `auth` поля, нужно сверить со свежей xray-веткой). На
milestone 2.

---

## 4. Milestone breakdown

### Milestone 1 — Bare bones stream-up over H2+TLS

**Цель**: подключиться к нашему donut-server из xray-cli с минимальным конфигом,
получить рабочий VLESS-туннель через xHTTP stream-up.

- [x] Добавить `transport = "xhttp"` в `donut-config::ServerInbound` (+ `host`)
- [x] ~~Добавить `donut-xhttp` крейт~~ → **переиспользовали `donut-carrier`**
      (см. «Что реально сделано в M1» выше)
- [x] hyper+h2 server на rustls listener (`run_tls_carrier_proxy`, общий с `tls`)
- [x] Path-placement parser для `stream-up` (`/<prefix>/<sid>`) + Xray UUID-форма sid
- [x] POST handler → VLESS request decode → upstream dial → relay (`handle_session`)
- [x] GET handler → relay из upstream обратно
- [x] X-Padding (random 100–1000) + SSE/anti-buffer заголовки в каждом response
- [x] Host-pin (как hub.go)
- [x] Uplink-POST keepalive (stream-up) — обязателен, держит H2 uplink-стрим открытым
- [x] e2e/wire тесты: `stream_up_accepts_xray_uuid_session`, `wrong_host_is_rejected`
      (сырой hyper, Xray-байты) + unit-тесты UUID-парсинга
- [x] **Wire test против реального `xray` CLI (26.5.9, локально) — ПРОЙДЕН**
      (`up=204 down=24237`, curl exit 0; см. секцию выше)
- [ ] Wire test против HAPP на телефоне (через VPS) — после деплоя

**Не делали в milestone 1** (как и планировали): HTTP/3, REALITY-integration,
HMAC anti-probing. `stream-one`/`packet-up` — серверная сторона уже
byte-faithful (получили «бесплатно» от carrier), но клиентская wire-проверка
против Xray для них — M2.

### Milestone 2 — Packet-up + CDN-compat

- [ ] Packet-up handler (POST `/<sid>/<seq>`)
- [ ] `scMaxEachPostBytes` + `scMinPostsIntervalMs` (если actively нужно)
- [ ] Query/Header/Cookie placement parsers
- [ ] Cloudflare gRPC-style тест (если есть тест-CDN)

### Milestone 3 — Stream-one + REALITY integration

- [ ] Stream-one bidirectional handler
- [ ] REALITY hooks (вместе с veil-сервером)
- [ ] HTTP/3 listener (QUIC) — отдельная большая работа

### Milestone 4 — Active-probing resistance

- [ ] HMAC-check session-id / path
- [ ] Stealth-decoy logic (отдавать настоящий response от reverse-proxy)

---

## 5. Тестирование

### 5.1 Локальные e2e

Создать `crates/donut-server/tests/xhttp_e2e.rs`:

```rust
#[tokio::test]
async fn xhttp_stream_up_e2e() {
    // 1. spawn donut-server with transport="xhttp" mode="stream-up"
    // 2. spawn target echo-server
    // 3. send VLESS request via hyper client (mimic xray client)
    // 4. assert echo flows through
}
```

### 5.2 Wire-compat с xray

Запустить настоящий `xray client` (можно в docker, см. `.session/CONTEXT.md`
testbench) с конфигом:
```json
{
  "outbounds": [{
    "protocol": "vless",
    "settings": { "vnext": [{
      "address": "127.0.0.1", "port": 443,
      "users": [{ "id": "<UUID>", "encryption": "none" }]
    }]},
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": { "serverName": "test.example.com" },
      "xhttpSettings": {
        "path": "/our-secret-path",
        "mode": "stream-up",
        "host": "test.example.com"
      }
    }
  }]
}
```

Если xray client успешно пробрасывает SOCKS5 через наш donut-server — wire-compat
confirmed.

### 5.3 HAPP test

Сгенерировать `vless://`-ссылку с `type=xhttp&mode=stream-up&path=...&host=...`,
вставить в HAPP, открыть сайт через VPN. Если работает — production-compat.

---

## 6. Открытые вопросы — РЕЗОЛВНУТЫ 2026-06-01 (раунд 2)

Бóльшая часть вопросов прояснилась через прямой WebFetch на
[Discussion #4113](https://github.com/XTLS/Xray-core/discussions/4113):

### ✅ Вопрос 1: `auto` mode selector (RESOLVED)

Все валидные `mode`: `packet-up`, `stream-up`, `stream-one`, `auto`.

**Client-side `auto` логика:**
- TLS+H2 → `stream-up`
- REALITY → `stream-one` (если есть `downloadSettings` → `stream-up`)
- Иначе → `packet-up`

**Server-side**: по умолчанию принимает **все 3 mode**; если задан явно —
только указанный. **Исключение: при `mode = "stream-up"` сервер также
принимает запросы в `stream-one` форме.**

→ Для нашей milestone 1 implementing `stream-up` mode = автоматически
получаем поддержку `stream-one` тоже.

### ✅ Вопрос 2: stream-up GET-стрим wire (RESOLVED)

**Response headers** (сервер обязан):
- `X-Accel-Buffering: no` (отключить буферизацию reverse-proxy)
- `Cache-Control: no-store` (отключить кэширование)
- `Content-Type: text/event-stream` (SSE-маскировка; можно отключить через
  `noSSEHeader: true`)
- `Transfer-Encoding: chunked` (только HTTP/1.1; H2/H3 — нативный фрейминг)
- `X-Padding: XXX...` (100–1000 байт, рандом на каждый response)
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST`

**Body**: HTTP/1.1 chunked, H2/H3 native frames. **Не gRPC-len-prefix, не
SSE-event-lines** — несмотря на `Content-Type: text/event-stream`, это просто
маскировка, body — raw bytes.

**End-of-stream**: просто закрытие TCP connection. Никаких terminator-фреймов.

**Idle keepalive**: каждые `scStreamUpServerSecs` (default `"20-80"`s рандом)
сервер шлёт padding-чанк чтобы H2-stream не закрылся middlebox'ом по idle.

### ✅ Вопрос 3+5: Anti-active-probing (RESOLVED — слабая защита)

**HMAC / signature нет.** Единственная защита — UUID в path с **30-секундным
association window** между POST upload и GET download. Сторонние HTTP-пробы
получают что-то отличимое только потому что они приходят без правильного
sessionId.

Это означает: ТСПУ-active-probing на xHTTP-endpoint **в принципе работает** —
надо самим добавить anti-probing logic если хочется, через secret-path длиной
≥16 байт + 404 на любой невалидный path.

### ✅ Вопрос 4 — НЕ блокирует xHTTP (отложен)

zapret/nfqws стратегии — это client-side, к серверной имплементации не
относятся. Не блокирует.

### 🆕 НОВОЕ важное знание (бонус из research):

- **`mux.cool` под xHTTP = pure-XUDP, и это РЕАЛИЗОВАНО (2026-06-02).**
  Уточнение к раннему черновику: Xray *не* хард-реджектит `Command::Mux` под
  xHTTP — `vless/inbound` принимает его. Правильная конфигурация клиента —
  **pure XUDP**: `mux.concurrency = -1` (TCP идёт напрямую, его и так мультиплексит
  XMUX на уровне H2) + `mux.xudpConcurrency > 0` (UDP/QUIC мультиплексируется
  через один `Command::Mux`-коннект, target `v1.mux.cool:9527`).

  **Эмпирически подтверждено** (xray 26.5.9, testbench): с `mux.enabled` клиент
  шлёт `Command::Mux`. Реализация на нашей стороне:
  - `mux_relay` генерализован через трейт `MuxIo` (`crates/donut-server/src/mux.rs`):
    работает и над TLS-record-туннелем (raw/vision, `RecordTlsServer`), и над
    **байт-стримом carrier'а** (`CarrierMuxIo` — xHTTP). XUDP-only (TCP под
    mux не нужен — XMUX уже мультиплексит TCP).
  - `handle_session` (carrier/xHTTP путь) теперь роутит `Command::Mux` → `mux_relay`.
  - Тест `carrier_mux_relay_echoes_xudp_datagram`: XUDP-датаграмма эхо-ится
    через `CarrierMuxIo` end-to-end.
  - Клиентский генератор: `donut-tools config-gen --transport xhttp` отдаёт
    готовый xray client.json с `fingerprint: firefox` (uTLS) и pure-XUDP mux,
    плюс `vless://…&fp=firefox…` ссылку.

- **XMUX параметры** (connection-multiplexing уровня, отличные от sc*-параметров
  на upload-уровне):
  - `maxConcurrency` = `16-32` рандом — макс параллельных proxy-requests на
    одно H2-соединение
  - `hMaxRequestTimes` = `600-900` — макс кумулятивных HTTP-requests до закрытия
    connection
  - `hMaxReusableSecs` = `1800-3000` — макс время жизни H2-connection

  **Реализовано в генераторе (2026-06-02):** `donut-tools config-gen --transport
  xhttp` кладёт `xhttpSettings.xmux` в client.json с RPRX-рекомендованными
  диапазонами (`maxConcurrency "16-32"`, `hMaxRequestTimes "600-900"`,
  `hMaxReusableSecs "1800-3000"`). XMUX — чисто клиентская настройка (как клиент
  переиспользует один H2-коннект под много proxy-запросов); сервер ничего
  особого не требует и уже корректно обслуживает XMUX-клиента (подтверждено
  wire-тестом xray 26.5.9 → HTTP 200). Это и есть «mux в xhttp» в обычном смысле,
  в отличие от mux.cool/XUDP выше.

---

## 7. Зависимости

Минимальный набор новых crate'ов:

- `hyper` `^1.0` — HTTP server (уже есть в transitive через `donut-carrier`?
  Проверить, либо добавить)
- `h2` `^0.4` — раздельный HTTP/2 multiplex (некоторые версии hyper включают)
- `http-body-util` — utilities для body streaming
- `bytes` — уже есть
- `rand` — уже есть

REALITY-integration (milestone 3) добавит зависимость от наших `donut-veil` и
`donut-tls`.

---

## 8. Размер работы (estimate)

- Milestone 1 (bare bones stream-up): **~2-3 рабочих дня** для одного
  разработчика. Включая интеграционные тесты и wire-compat verification.
- Milestone 2 (packet-up + CDN): **+1 день**
- Milestone 3 (stream-one + REALITY): **+3-5 дней**
- Milestone 4 (anti-probing): **+1-2 дня**

Reality check: это всё SDE estimates без учёта тестирования с реальным HAPP
через прод-VPS. Plan padding ×1.5.

---

## 9. Источники (что читать прежде чем кодить)

- [Xray-core dialer.go](https://github.com/XTLS/Xray-core/blob/main/transport/internet/splithttp/dialer.go)
  — client-side wire-протокол, образец что мы должны принимать
- [Xray-core server side в том же пакете](https://github.com/XTLS/Xray-core/tree/main/transport/internet/splithttp)
  — серверная имплементация для reference
- [Discussion #4113](https://github.com/XTLS/Xray-core/discussions/4113) —
  RPRX-design rationale (на китайском, нужен перевод)
- [PR #3994](https://github.com/XTLS/Xray-core/pull/3994) — введение stream-up
- [PR #4298](https://github.com/XTLS/Xray-core/pull/4298) — перенос x_padding
  в Referer
- [DeepWiki XTLS chapter 4.3](https://deepwiki.com/XTLS/Xray-core/4.3-splithttp-transport)
  — обзорное summary spec
- [Habr 990208](https://habr.com/en/articles/990208/) — RU-language разбор
- [Discussion #5969](https://github.com/XTLS/Xray-core/discussions/5969) — про
  reassembly DPI и почему xHTTP нужен (мотивация)

---

## 10. Подписка (subscription endpoint) — реализовано 2026-06-02

Клиент по одной ссылке получает **готовый рабочий конфиг** под xHTTP (с geoip
split-tunnel и XMUX), не собирая его руками.

### Где
Встроено в `donut-server` как опциональный listener (рядом с `[metrics]`).
Генерация конфигов вынесена в чистый модуль `donut-config::subgen`
(`XhttpParams`, `vless_xhttp_link`, `xray_client_json`, `clash_yaml`,
`RoutingProfile`) — им же пользуется `donut-tools config-gen`, так что CLI и
подписка байт-в-байт совпадают.

### Конфиг
```json
"subscription": {
  "listen": "127.0.0.1:8088",            // за TLS reverse-proxy (Caddy)
  "public_address": "edge.example:443",  // обязателен: что дайлит клиент
  "server_name": "edge.example",         // обязателен: TLS SNI
  "host": "edge.example",                // опц.: дефолт = inbound.host
  "path": "/secret",                     // опц.: дефолт = inbound.path
  "mode": "stream-up",                   // опц.: дефолт = inbound.mode
  "fp": "firefox",                       // опц.
  "socks": "127.0.0.1:1080"              // опц.
}
```

### API
```
GET /sub/<uuid>?format=xray|clash|links&profile=ru|all
```
- `format=xray` (дефолт) — полный xray `client.json`: xHTTP+TLS(H2) + firefox-fp
  + XMUX + pure-XUDP mux + routing.
- `format=clash` — Clash-Meta (mihomo) YAML (xHTTP — экспериментально в mihomo).
- `format=links` — base64 списка `vless://` (классическая подписка v2rayN/NG).
- `profile=ru` (дефолт) — RU split-tunnel (`geoip:ru`/`geoip:private`/RU-geosite
  → direct, ads → block, остальное → proxy); `profile=all` — proxy-all.

`<uuid>` обязан быть в `inbound.users`, иначе **404** (тот же ответ, что на любой
неизвестный путь — не подтверждаем UUID пробующему). geoip/geosite-теги
резолвятся `.dat`-базами на стороне клиента (HAPP их носит с собой).

### Проверено
- Все три формата отдаются с правильными Content-Type; неизвестный UUID → 404;
  `profile=all` убирает RU-правило.
- **xray 26.5.9** импортирует конфиг, отданный подпиской, и туннелирует →
  HTTP 200 (при routing, форснутом в proxy; с дефолтным RU-профилем loopback-
  цель корректно уходит в `direct` — split-tunnel работает как задумано).
