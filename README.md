# hold-the-donut

Минимальная реализация на Rust подмножества протоколов xray-core: VLESS поверх
REALITY, транспорт XHTTP (HTTP/1.1, HTTP/2) и QUIC/HTTP-3. Цель — компактные
сервер и клиент, совместимые на проводе с xray-core, без Go-рантайма.

Проект на ранней стадии разработки (статус — в конце файла).

## Что это

Две программы:

- **`donut-server`** — серверный демон. Принимает VLESS+REALITY-соединения; при
  чужом или невалидном ClientHello прозрачно проксирует трафик на подложку
  (self-steal), иначе терминирует туннель и роутит исходящий трафик.
- **`donut-client`** — локальный клиент. Поднимает SOCKS5 на `127.0.0.1` и
  заворачивает трафик в VLESS+REALITY+XHTTP-туннель до сервера. Умеет
  split-tunnel: часть трафика по geoip/geosite/домену идёт напрямую, мимо сервера.

Эталон протоколов — xray-core v26.4.15. Байт-точные спецификации лежат в
[docs/PROTOCOLS.md](docs/PROTOCOLS.md).

## Сборка

Нужен Rust 1.88 (см. `rust-toolchain.toml`).

```sh
cargo build --release
```

Бинарники окажутся в `target/release/donut-server` и `target/release/donut-client`.

Тесты и линтеры:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Конфиг: JSON или TOML

Оба демона читают конфиг (по умолчанию `/etc/donut/server.json` /
`client.json`, путь — флагом `--config`). Формат выбирается по расширению:
**`*.toml` → TOML, иначе JSON** — одни и те же поля, TOML просто читабельнее
для ручной правки. Примеры — в [docs/examples/](docs/examples/).

```sh
donut-server --config /etc/donut/server.toml
donut-client --config ~/.donut/client.toml      # SOCKS5 на inbound.socks
```

## Развёртывание сервера (production)

Рекомендуемый боевой флоу: **`raw` + `xtls-rprx-vision` + cert-TLS** с
self-steal. Это байт-совместимо с **готовыми VLESS-клиентами из App Store**
(HAPP, Streisand, v2box, Shadowrocket) — своё приложение под iOS не нужно,
клиент подключается по `vless://`-ссылке.

### Docker или напрямую?

**Запускать сервер нативным бинарём под systemd, не в Docker.** Docker-bridge
добавляет на каждый пакет NAT + conntrack + `docker-proxy`, режет throughput и
**теряет/реордерит UDP-пакеты** (критично для QUIC). `--network=host`
смягчает, но полностью убрать оверхед нельзя. Docker используем **только для
кросс-сборки** amd64-бинаря с Apple Silicon (см. ниже) — не для запуска.

### 1. Сгенерировать конфиг + ссылку

```sh
cargo run -p donut-tools -- config-gen --transport raw \
  --server-addr <DOMAIN>:443 --server-name <DOMAIN> \
  --cert /etc/donut/fullchain.pem --key /etc/donut/privkey.pem \
  --dest 127.0.0.1:8080            # self-steal → filebrowser
```
Печатает `server.json` (со свежим UUID, `vision:"xray"`) **и** готовую
`vless://`-ссылку. Сохрани ссылку и UUID в менеджер паролей. Конфиг можно
переписать в TOML (читабельнее) — поля те же.

### 2. Сертификат (Let's Encrypt)

`donut-server` сам терминирует TLS — Caddy/reverse-proxy не нужен.

```sh
dnf install -y certbot                                    # или apt
certbot certonly --standalone -d <DOMAIN> -m <EMAIL> --agree-tos -n
install -m644 /etc/letsencrypt/live/<DOMAIN>/fullchain.pem /etc/donut/fullchain.pem
install -m600 /etc/letsencrypt/live/<DOMAIN>/privkey.pem   /etc/donut/privkey.pem
# deploy-hook (перевыпуск): cp ... + systemctl restart donut-server
```

### 3. Подложка (self-steal)

Любой локальный HTTP-сайт на `dest` (например filebrowser на
`127.0.0.1:8080`): не-VLESS запросы и активные зонды отдаются туда — порт
выглядит как обычный HTTPS-файлообменник.

### 4. Собрать amd64-бинарь (с Apple Silicon — через Docker)

```sh
docker build --platform linux/amd64 -t donut .
id=$(docker create --platform linux/amd64 donut)
docker cp "$id:/usr/local/bin/donut-server" ./donut-server && docker rm "$id"
scp ./donut-server <vps>:/usr/local/bin/donut-server
```

### 5. systemd-юнит

`/etc/systemd/system/donut-server.service`:
```ini
[Unit]
Description=donut-server (raw + Xray Vision, tcp/443)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/donut-server --config /etc/donut/server.toml
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
```
```sh
firewall-cmd --permanent --add-port=80/tcp --add-port=443/tcp && firewall-cmd --reload
systemctl daemon-reload && systemctl enable --now donut-server
```

### Проверка

```sh
curl -k https://<DOMAIN>          # зонд → должен показать filebrowser (self-steal)
journalctl -u donut-server -f     # JSON-логи
```

### Смена VPS

Переносимо: бинарь (`/usr/local/bin/donut-server`), `/etc/donut/server.toml`,
systemd-юнит, certbot. На новой машине: установить certbot+filebrowser,
выпустить серт на новый домен, обновить `server-name`/`server-addr` в конфиге и
в `vless://`-ссылке (или перегенерировать `config-gen`), скопировать бинарь+юнит.
Клиентам раздать новую ссылку.

## Подключение клиентов

**Готовый клиент (iOS/Android/desktop):** вставить `vless://`-ссылку из шага 1
в HAPP / Streisand / v2box — работает сразу (полный Vision).

**Свой `donut-client`** (роутер и т.п.) — импорт ссылки + split-tunnel «РФ →
direct» (российский трафик идёт мимо VPS, напрямую):

```sh
donut-client import "vless://...."        # → ~/.donut/client.toml (РФ-direct включён)
donut-client geo-update                   # скачать geoip.dat + geosite.dat
donut-client --config ~/.donut/client.toml   # SOCKS5 127.0.0.1:1080
```
`import` кладёт правила `geoip:ru/private` и `geosite:category-ru/yandex/vk →
direct`, пути к geo-базам и Yandex-DoH. Флаг `--no-ru-direct` — проксировать
всё. (Примечание: `donut-client` ходит plain-VLESS `flow=none`; полный
`xtls-rprx-vision` — у готовых клиентов по ссылке.)

## Структура

Cargo-воркспейс, крейты в `crates/`:

| Крейт | Назначение |
|---|---|
| `donut-core` | доменные типы и trait-порты |
| `donut-wire` | кодек заголовка VLESS |
| `donut-tls` | форк rustls с хуками под REALITY |
| `donut-rustls` | фасад-реэкспорт над форком |
| `donut-veil` | REALITY-аутентификация и вердикт tunnel/forward |
| `donut-carrier` | транспорт XHTTP поверх HTTP/1.1 и HTTP/2 |
| `donut-quic` | QUIC и HTTP/3 |
| `donut-socks` | SOCKS5 inbound |
| `donut-routing`, `donut-geo`, `donut-dns` | роутинг, geoip/geosite, DNS-резолвер |
| `donut-config` | загрузчик конфига (JSON/TOML) |
| `donut-server`, `donut-client` | бинарники |

Карта зависимостей и подробности по каждому крейту — [docs/CRATES.md](docs/CRATES.md).

## Документация

Подробные материалы лежат в [docs/](docs/): разбор сетевого стека,
спецификации протоколов, механика REALITY и self-steal, план по этапам.

## Статус

Версия 0.0.1. Готово: кодек VLESS, форк rustls с REALITY-хуками, транспорты
`veil`(REALITY)/`tls`(XHTTP H1/H2)/`quic`(H3)/`raw`, SOCKS5 inbound, роутинг +
DNS + geo (split-tunnel), UUID-аутентификация, метрики + JSON-логи, конфиг
JSON/TOML. **Faithful Xray Vision** (`xtls-rprx-vision` + raw-splice мимо
внешнего TLS) на `raw` — байт-совместим с готовыми VLESS-клиентами (HAPP и др.),
проверен боевым деплоем. `donut-tools config-gen --transport raw` чеканит
конфиг + `vless://`-ссылку; `donut-client import` принимает ссылку с РФ→direct.
В работе: REALITY+Vision на veil-пути, client-side faithful Vision,
кросс-компиляция под роутеры. Детали — [docs/PLAN.md](docs/PLAN.md).

## Лицензия

MPL-2.0.
