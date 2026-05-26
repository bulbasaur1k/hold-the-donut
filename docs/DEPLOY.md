# Развёртывание (подробный гайд)

Пошаговая инструкция с пояснениями. Краткий copy-paste — в корневом
[README](../README.md#быстрый-старт). Боевой флоу: **`raw` +
`xtls-rprx-vision` + cert-TLS** с self-steal — байт-совместим с готовыми
VLESS-клиентами из App Store (HAPP, Streisand, v2box, Shadowrocket), своё
iOS-приложение не нужно.

## Что где выполняется

Три роли — не путать, где какие команды:

- **Машина сборки** (твой ПК/Mac, Rust + Docker): клонируешь репо, тут
  запускаешь `cargo …` и `docker build`. Установка: `git clone <repo> && cd
  hold-the-donut`, Rust c [rustup.rs](https://rustup.rs) (1.88, см.
  `rust-toolchain.toml`).
- **VPS**: Rust и репо **не нужны** — копируешь туда только готовый бинарь
  `donut-server` + конфиг + systemd-юнит.
- **Клиент**: приложение из App Store (ничего не ставить) **или** бинарь
  `donut-client`.

## Про UUID (это и логин, и пароль)

`donut-tools` ничего не «регистрирует» по сети — регистрации как процесса нет.
UUID — единственный credential VLESS (как bearer-token, не пара логин/пароль).
`config-gen` генерирует случайный UUID и вписывает его сразу в серверный конфиг
(`inbound.users`) **и** в `vless://`-ссылку. Сервер «узнаёт» пользователя,
прочитав `inbound.users` из своего конфига при старте — это общий секрет,
зашитый по обе стороны ещё до запуска.

- **Добавить юзера:** дописать UUID в `inbound.users` + `systemctl restart
  donut-server` (hot-reload нет).
- **Отозвать:** убрать UUID + рестарт.
- Ссылку держать приватно — кто знает UUID, тот подключается. В Xray так же
  (`clients[].id` в конфиге).

## Конфиг: JSON или TOML

Формат выбирается по расширению: `*.toml` → TOML, иначе JSON (поля те же, TOML
читабельнее). Минимальный серверный `server.toml`:

```toml
[inbound]
listen = "0.0.0.0:443"
transport = "raw"
vision = "xray"
users = ["<UUID>"]
cert = "/etc/donut/fullchain.pem"
key = "/etc/donut/privkey.pem"
dest = "127.0.0.1:8080"     # self-steal → filebrowser

[metrics]
listen = "127.0.0.1:9090"

[routing]
default = "freedom"
[[routing.rules]]
port = ["25"]               # блок исходящего SMTP (анти-абуз)
outbound = "block"
```

## Docker или напрямую?

**Сервер запускать нативным бинарём под systemd, не в Docker.** Docker-bridge
добавляет на каждый пакет NAT + conntrack + `docker-proxy`, режет throughput и
**теряет/реордерит UDP-пакеты** (критично для QUIC). `--network=host`
смягчает, но полностью оверхед не убирает. Docker используем **только для
кросс-сборки** amd64-бинаря с Apple Silicon — не для запуска. Подробности и
бенчмарки — в [PRODUCTION.md](PRODUCTION.md).

## Шаги

### 1. Конфиг + ссылка (на машине сборки)

```sh
cargo run -p donut-tools -- config-gen --transport raw \
  --server-addr <DOMAIN>:443 --server-name <DOMAIN> \
  --cert /etc/donut/fullchain.pem --key /etc/donut/privkey.pem \
  --dest 127.0.0.1:8080
```
Печатает `server.json` (свежий UUID, `vision:"xray"`) **и** `vless://`-ссылку.
Либо собери конфиг руками (см. выше) с `UUID=$(uuidgen)` и получи ссылку через
`donut-tools link --uuid "$UUID" --server-addr <DOMAIN>:443 --sni <DOMAIN>`.

### 2. Сертификат на VPS (Let's Encrypt)

`donut-server` сам терминирует TLS — Caddy/reverse-proxy не нужен.

```sh
dnf install -y certbot                                    # или apt
certbot certonly --standalone -d <DOMAIN> -m <EMAIL> --agree-tos -n
mkdir -p /etc/donut
install -m644 /etc/letsencrypt/live/<DOMAIN>/fullchain.pem /etc/donut/fullchain.pem
install -m600 /etc/letsencrypt/live/<DOMAIN>/privkey.pem   /etc/donut/privkey.pem
# deploy-hook на перевыпуск: те же cp + `systemctl restart donut-server`
```

### 3. Подложка (self-steal)

Любой локальный HTTP-сайт на `dest` (например filebrowser на
`127.0.0.1:8080`): не-VLESS запросы и активные зонды отдаются туда — порт
выглядит как обычный HTTPS-сайт/файлообменник.

### 4. Собрать amd64-бинарь (с Apple Silicon — через Docker)

```sh
docker build --platform linux/amd64 -t donut .
id=$(docker create --platform linux/amd64 donut)
docker cp "$id:/usr/local/bin/donut-server" ./donut-server && docker rm "$id"
scp ./donut-server <vps>:/usr/local/bin/donut-server
scp server.toml    <vps>:/etc/donut/server.toml
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

## Смена VPS

Переносимо: бинарь (`/usr/local/bin/donut-server`), `/etc/donut/server.toml`,
systemd-юнит, certbot. На новой машине: установить certbot+filebrowser,
выпустить серт на новый домен, обновить `server-name`/`server-addr` в конфиге и
в ссылке (или перегенерировать `config-gen`), скопировать бинарь+юнит. Клиентам
раздать новую ссылку.

## Подключение клиентов

**Готовый клиент (iOS/Android/desktop):** вставить `vless://`-ссылку в HAPP /
Streisand / v2box — работает сразу (полный Vision).

**Свой `donut-client`** (роутер и т.п.) — импорт ссылки + split-tunnel «РФ →
direct» (российский трафик идёт мимо VPS, напрямую):

```sh
donut-client import "vless://...."        # → ~/.donut/client.toml (РФ-direct включён)
donut-client geo-update                   # скачать geoip.dat + geosite.dat
donut-client --config ~/.donut/client.toml   # SOCKS5 127.0.0.1:1080
```
`import` кладёт правила `geoip:ru/private` и `geosite:category-ru/yandex/vk →
direct`, пути к geo-базам и Yandex-DoH. Флаг `--no-ru-direct` — проксировать
всё. Примечание: `donut-client` ходит plain-VLESS (`flow=none`); полный
`xtls-rprx-vision` — у готовых клиентов по ссылке.

Проверка:
```sh
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org              # → IP сервера
curl --socks5-hostname 127.0.0.1:1080 https://yandex.ru -o /dev/null -w '%{http_code}\n'  # → direct
```
