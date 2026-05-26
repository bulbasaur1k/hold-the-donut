# Развёртывание и текущее состояние

Снимок того, что реализовано, что работает, что задеплоено, и пошаговая
инструкция по развёртке. Секреты (пароли, реальный secret-path) здесь —
плейсхолдеры; держи их в менеджере паролей.

---

## 1. Транспорты (что реализовано)

Прокси несёт VLESS-фрейм внутри «carrier»-обёртки. Маскировка — настоящий
HTTPS/H3-сайт с **self-steal**: секретный путь = туннель, всё остальное
отдаётся подложке (filebrowser). REALITY оставлен для TCP-veil, но для
cert-based деплоя не используется.

### Серверные режимы (`inbound.transport` в server.json)

| transport | Порт | TLS | Self-steal | Статус |
|---|---|---|---|---|
| `tls`     | tcp/443 | donut-server сам (реальный серт) | path-gating → `dest` (filebrowser); h1+h2; carrier mode `stream-one`/`stream-up`/`packet-up` | **рекоменд. TCP**, все 3 mode проверены E2E на боевом |
| `quic`    | udp/443 | donut-server сам (реальный серт) | path-gating → `dest` (filebrowser) | **рабочий**, задеплоен и проверен |
| `raw`     | свой TCP-порт | donut-server сам (реальный серт) | 1-й дешифр. байт `0x00`=VLESS → туннель, иначе → relay на `dest` | **реализован+протестирован E2E** (на боевом — на 8443, юнит `donut-server-raw` сейчас disabled); несёт flow `xtls-rprx-vision` |
| `carrier` | localhost | нет (TLS терминирует фронт) | фронт (Caddy) | бэкенд за reverse-proxy; honor-ит `mode` → `stream-up`/`packet-up` для CDN (#9 закрыт) |
| `veil`    | tcp/443 | REALITY veiled-TLS | forward на `dest` | исходный путь, тесты проходят; для cert-деплоя не нужен |

### Клиентские режимы (`outbound.transport` в client.json)

| transport | Как ходит | Статус |
|---|---|---|
| `h3`    | QUIC/HTTP-3 carrier к серверу (full-duplex) | **рабочий**, проверен боевым деплоем |
| `xhttp` | carrier поверх обычного TLS; `mode` = `stream-one`/`stream-up`/`packet-up` | работает с серверным `tls` (все 3 mode на боевом) и с `carrier`-бэкендом за Caddy/CDN через `stream-up`/`packet-up` (#9 закрыт) |
| `raw`   | VLESS напрямую по TLS (без carrier); `flow` = `none`/`xtls-rprx-vision` | **реализован+протестирован E2E на боевом** (Xray RAW/TCP-аналог) |
| `veil`  | REALITY veiled-TLS + carrier | исходный, тесты проходят |

## 2. Возможности

- **Full-duplex H3** (клиент и сервер) — через `h3::RequestStream::split()`.
- **Full-duplex carrier-клиент** (неблокирующий, как QUIC).
- **h2c carrier-сервер** (auto h1/h2) — для работы за reverse-proxy.
- **Self-steal**: на `quic`, `tls` (все 3 carrier-mode) и `raw` — не-туннельные
  запросы reverse-proxy/relay на decoy (filebrowser); зонд видит файл-сайт.
- **XHTTP carrier-modes**: `stream-one` (один full-duplex обмен), `stream-up`
  (раздельные POST-up/GET-down), `packet-up` (много POST + один GET) — поверх
  cert-based `tls`; сервер пэйрит по session-id через общий dispatcher.
- **RAW-транспорт** (`transport: "raw"`): VLESS напрямую по TLS 1.3 без HTTP-
  обёртки (аналог Xray RAW/TCP); 1-й дешифрованный байт триажит VLESS-vs-зонд,
  зонд relay-ится на decoy. Несёт flow `xtls-rprx-vision`.
- **XTLS-Vision** (`flow: "xtls-rprx-vision"`, наш эквивалент): padding первых
  пакетов в обе стороны (маскирует длины inner-TLS-хэндшейка против TLS-in-TLS
  детекции) → затем raw passthrough. Кодек в `donut-io::vision`. **Только на
  `raw`** (поверх XHTTP/QUIC Vision не работает — он расщепляет сырые TLS-записи).
- **Split-tunnel роутинг** на клиенте: `geoip`/`geosite` RU + private →
  `direct` (мимо сервера, локальный IP — прокси не светится для RU).
- **uTLS-style `randomized` fingerprint** на ClientHello (перестановка
  cipher-suites/extensions), TLS-resumption отключён.
- **Ретраи коннекта** на клиенте (12×5с) — против нестабильного канала.
- **Кросс-сборка** под x86_64-linux через Docker (`Dockerfile`).
- Конфиг — server IP напрямую (без startup-DNS), `server_name` для серта/SNI.

## 3. Что задеплоено (cozbystorage.duckdns.org → 144.31.85.233, Rocky 9.4)

**Развёрнута рекомендованная TCP+UDP-схема (раздел 4.4): donut-server владеет
обоими портами 443.** Caddy убран из пути. Проверено E2E (xhttp и h3):
foreign-запрос выходит с IP сервера, RU-домены (yandex.ru, vk.com) идут direct.

Сервисы (systemd):
- `donut-server-tls` — TLS-carrier на **tcp/443**, `/etc/donut/tls.json`
  (`transport:tls`, path=`<SECRET_PATH>`, dest=`127.0.0.1:8080`, cert/key).
  Self-steal на filebrowser работает по h1 и h2 (см. фикс decoy-Host ниже).
- `donut-server` — QUIC на **udp/443**, `/etc/donut/server.json`
  (`transport:quic`, path=`<SECRET_PATH>`, dest=`127.0.0.1:8080`, cert/key).
- `filebrowser` — `127.0.0.1:8080`, корень `/srv/files`.
- `certbot-renew.timer` (`enabled`/`active`) + deploy-hook
  `/usr/local/bin/donut-cert-deploy.sh` (прописан как `renew_hook` в
  `/etc/letsencrypt/renewal/<domain>.conf`) — продлевает LE-серт через
  standalone (:80), копирует в `/etc/donut/{fullchain,privkey}.pem` и
  рестартит оба donut-сервиса. Серт валиден до 2026-08-24.
- `caddy`, `donut-cert-sync.timer`, `donut-server-carrier` (Caddy-эпохи
  h2c-бэкенд на :8444), `donut-server-raw` (тест RAW на :8443) — **остановлены
  и `disabled`** (убраны из пути; конфиги/Caddyfile сохранены для отката).
- `donut-log-vacuum.timer` — ежедневно `journalctl --vacuum-time=14d
  --vacuum-size=200M` (очистка старых логов).

### Observability
- **Prometheus-метрики** (`metrics.listen`, только localhost): QUIC →
  `127.0.0.1:9090/metrics`, TLS → `127.0.0.1:9091/metrics`. Серии:
  `donut_connections_total`, `donut_active_connections`,
  `donut_handshakes_total{result}`, `donut_blackhole_total`,
  `donut_bytes_total{direction}`. Скрейп локально или через SSH-туннель
  (наружу порты не открыты).
- **Логи** — `tracing` → journald; `log.format: "json"` на боевом
  (структурно, для анализа: `journalctl -u donut-server-tls -o cat | jq`).
  `"text"` — человекочитаемо. Уровень — `log.level`.

Файлы на сервере: бинарь `/usr/local/bin/donut-server` (общий для всех
юнитов); конфиги `/etc/donut/{tls,server,raw}.json`; серт
`/etc/donut/{fullchain,privkey}.pem`. Откат TCP-схемы: `systemctl stop
donut-server-tls; systemctl enable --now caddy`.

> ⚠️ Порт метрик не должен конфликтовать между юнитами на одной машине:
> 9090 (QUIC) / 9091 (TLS) различны. Старый `donut-server-carrier` тоже
> занимал 9090 — поэтому он отключён.

Локально (твой Mac, `~/.donut/`): бинарь `donut-client`, конфиги
`client-h3.json` / `client-xhttp.json`, базы `geoip.dat` / `geosite.dat`.
Запуск: `~/.donut/donut-client --config ~/.donut/client-h3.json` (h3/udp)
или `client-xhttp.json` (xhttp/tcp) → SOCKS5 на `127.0.0.1:1080`.

Репозиторий: `github.com/bulbasaur1k/hold-the-donut`. Ключевые коммиты:
randomized fingerprint+MCP, cert-based транспорты+full-duplex H3, QUIC
self-steal, carrier h2c+неблокирующий клиент, TLS carrier transport.

**Свежие фиксы (на момент TCP-деплоя, проверь статус коммита):**
- **decoy self-steal по HTTP/2** — `proxy_to_decoy` (donut-carrier) строил
  upstream-запрос к filebrowser без `Host` для h2-вызовов (authority в
  `:authority`, не в заголовке `host`) → `400 missing required Host header`.
  Теперь Host выводится из `:authority`/`host`/`localhost`. Добавлен h2
  регресс-тест в `tls_carrier_e2e.rs`. Без фикса современные браузеры по h2
  видят 400 вместо filebrowser → маскировка ломается.
- **DoH-резолвер клиента** — `hickory-resolver` подключался без фичи
  `webpki-roots`/`native-certs` → пустой корневой стор → любой DoH-TLS падал
  с `UnknownIssuer`. Это ломало **RU-direct** (direct-дозвон резолвит имя
  локально через DoH). Добавлена фича `webpki-roots`. Клиент нужно
  пересобрать; иначе split-tunnel RU-direct не работает.
- **XHTTP carrier modes (`stream-up`/`packet-up`)** — заведены на
  выбираемый транспорт `tls`/`xhttp` через поле `inbound.mode`/`outbound.mode`
  (`"stream-one"` дефолт / `"stream-up"` / `"packet-up"`). Сервер использует
  **общий dispatcher** на listener (`ConnectionAcceptor`), чтобы POST-up и
  GET-down с разных TLS-соединений пэйрились по session-id; клиент дозванивается
  через TLS-фабрику соединений (uTLS на каждом). Проверено E2E на боевом для
  всех трёх режимов (foreign→server, RU→direct).
- **Self-steal во всех carrier-режимах** — раньше decoy-проксирование делал
  только `stream-one`; `stream-up`/`packet-up` на не-туннельный запрос отдавали
  `404` (маскировка ломалась). Теперь все три режима reverse-проксируют
  не-туннельные запросы на `dest` (filebrowser). Регресс-тесты в
  `tls_carrier_modes_e2e.rs`.

---

## 4. Инструкция по развёртке (с нуля)

Рекомендуемая боевая схема: **donut-server владеет обоими портами 443**
(tcp = `tls`, udp = `quic`), оба с self-steal на filebrowser. Reverse-proxy
в пути туннеля нет → нет проблем с full-duplex.

### 4.0. Переменные

```sh
DOMAIN=cozbystorage.duckdns.org
SECRET_PATH="/assets/$(openssl rand -hex 8)/upload"   # сгенерируй и сохрани
```

### 4.1. SSH-доступ (one-time)

```sh
ssh-keygen -t ed25519 -f ~/.ssh/<host> -N ''
ssh-copy-id -i ~/.ssh/<host> root@$DOMAIN        # либо вручную в authorized_keys
# ~/.ssh/config: Host <alias> / HostName $DOMAIN / User root /
#   IdentityFile ~/.ssh/<host> / ConnectionAttempts 6 / ControlMaster auto
passwd                                            # сменить root-пароль, в менеджер
```

### 4.2. Сборка бинаря под сервер (amd64 Linux)

С Apple Silicon — через Docker (`Dockerfile` в корне):

```sh
docker build --platform linux/amd64 -t donut .
id=$(docker create --platform linux/amd64 donut)
docker cp "$id:/usr/local/bin/donut-server" ./donut-server
docker rm "$id"
scp ./donut-server <alias>:/usr/local/bin/donut-server
ssh <alias> chmod +x /usr/local/bin/donut-server
```

Клиент (`donut-client`) собирается локально под свою ОС:
`cargo build --release -p donut-client`.

### 4.3. Подложка (self-steal) + сертификат

filebrowser как локальный файл-сайт + certbot для серта:

```sh
# filebrowser → 127.0.0.1:8080, systemd-сервис, корень /srv/files
# (один Go-бинарь; на сервере без Rust — берём релиз с проверкой sha256)

# сертификат Let's Encrypt (порт 80 свободен — его держит только ACME):
dnf install -y certbot
certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos -m <email>
# деплой-хук: cp /etc/letsencrypt/live/$DOMAIN/{fullchain,privkey}.pem
#   /etc/donut/ ; chmod 600 privkey.pem ; systemctl restart donut-server donut-server-tls
# certbot.timer перевыпускает автоматически и дёргает хук.
```

Firewall:
```sh
firewall-cmd --permanent --add-port=80/tcp --add-port=443/tcp --add-port=443/udp
firewall-cmd --reload
```

### 4.4. donut-server: два инстанса (tcp + udp)

`/etc/donut/tls.json` (TCP):
```json
{ "log": { "level": "info" },
  "inbound": { "listen": "0.0.0.0:443", "transport": "tls",
    "users": ["<UUID>"],
    "path": "<SECRET_PATH>", "dest": "127.0.0.1:8080",
    "cert": "/etc/donut/fullchain.pem", "key": "/etc/donut/privkey.pem" },
  "routing": { "default": "freedom", "rules": [ { "port": ["25"], "outbound": "block" } ] } }
```

`/etc/donut/server.json` (QUIC) — то же, но `"transport": "quic"`.

> **Аутентификация.** `inbound.users` — список разрешённых VLESS-UUID; это
> и есть реальный credential прокси. Сессия с UUID не из списка **дропается**
> до проксирования (на всех транспортах — единая точка в `handle_session`).
> Список **обязателен и непустой**, иначе сервер не стартует (fail-closed).
> UUID и `users`/`uuid` пару проще всего получить из `donut-tools config-gen`
> (он чеканит общий UUID), либо `uuidgen`. Сравнение UUID — constant-time
> (без timing-оракула на секрет).

systemd-юниты `donut-server.service` (→ server.json) и
`donut-server-tls.service` (→ tls.json), у обоих:
`ExecStart=/usr/local/bin/donut-server --config <...>`,
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, `Restart=on-failure`. Затем:
```sh
systemctl daemon-reload
systemctl enable --now donut-server donut-server-tls
```
TCP/443 и UDP/443 не конфликтуют (разные протоколы).

### 4.5. Клиент

`client.json` (или `client-h3.json` для H3):
```json
{ "log": { "level": "info" },
  "inbound": { "socks": "127.0.0.1:1080" },
  "outbound": { "server": "144.31.85.233:443", "transport": "xhttp",
    "uuid": "<UUID>",
    "server_name": "cozbystorage.duckdns.org", "path": "<SECRET_PATH>" },
  "routing": { "default": "proxy", "rules": [
    { "geoip": ["ru", "private"], "outbound": "direct" },
    { "geosite": ["category-ru", "yandex", "vk"], "outbound": "direct" } ] },
  "geo": { "geoip": "~/.donut/geoip.dat", "geosite": "~/.donut/geosite.dat" },
  "dns": { "doh": ["77.88.8.8"], "doh_tls_name": "common.dot.dns.yandex.net" } }
```
- `server` — **IP**, чтобы не зависеть от startup-DNS на флаки-канале.
- `uuid` — VLESS-credential; должен совпадать с одним из `inbound.users` сервера.
- `server_name` — имя из серта (для TLS/SNI).
- `transport: "xhttp"` → tcp/443 (`tls`-сервер); `"h3"` → udp/443 (`quic`).
- geo-базы: `geoip.dat` (v2fly/geoip), `geosite.dat` (v2fly dlc.dat).

Запуск: `donut-client --config client.json` → SOCKS5 `127.0.0.1:1080`.

### 4.6. Проверка

```sh
# foreign → должен показать IP сервера:
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
# RU → должен идти direct (в логах клиента "direct dial (bypassing server)")
curl --socks5-hostname 127.0.0.1:1080 https://yandex.ru -o /dev/null -w '%{http_code}\n'
# self-steal → браузером открыть https://$DOMAIN — увидеть filebrowser
```

---

## 5. Известные ограничения / TODO

- **#9 xhttp через reverse-proxy (Caddy/CDN) — ЗАКРЫТО.** `stream-one`
  дедлочил через Go-reverse-proxy (нет full-duplex по одному запросу).
  Решение: режимы `stream-up`/`packet-up` (раздельные POST-up/GET-down на
  отдельных соединениях). `run_carrier_backend` теперь honor-ит
  `inbound.mode`, а `Server::serve` держит **общий dispatcher** на listener
  → пары POST/GET с разных CDN-форварднутых соединений матчатся по
  session-id. Регресс-тест: `carrier_backend_stream_up_pairs_separate_connections`.
  (Для прямого VPS по-прежнему достаточно `tls` stream-one / h3.)
- **Cert renewal** — при схеме 4.4 серт обновляет certbot (Caddy уходит из
  пути 443). Если оставлен Caddy на 443 — работает `donut-cert-sync.timer`.
- **Флаки-канал** — у клиента ретраи коннекта; долгоживущий туннель при
  разрыве пересоздаётся приложением (новый SOCKS-коннект → новый туннель).
