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

## Быстрый старт

С нуля: только что создан VPS (Linux x86_64), есть домен `<DOMAIN>` → его IP.
Подставь `<DOMAIN>` / `<EMAIL>` / `<vps>`. Пояснения и варианты —
[docs/DEPLOY.md](docs/DEPLOY.md).

### A. На машине сборки (Rust + Docker)

```sh
git clone <repo> && cd hold-the-donut

# UUID = единственный credential (и логин, и пароль) + серверный конфиг:
UUID=$(uuidgen)
cat > server.toml <<EOF
[inbound]
listen = "0.0.0.0:443"
transport = "raw"
vision = "xray"
users = ["$UUID"]
cert = "/etc/donut/fullchain.pem"
key = "/etc/donut/privkey.pem"
dest = "127.0.0.1:8080"

# Prometheus /metrics — только на localhost, наружу порт НЕ открывать.
[metrics]
listen = "127.0.0.1:9090"
EOF

# ссылка для клиента — СОХРАНИ её (приватно):
cargo run -p donut-tools -- link --uuid "$UUID" --server-addr <DOMAIN>:443 --sni <DOMAIN>

# серверный бинарь под Linux amd64 (Docker только собирает, не запускает):
docker build --platform linux/amd64 -t donut .
id=$(docker create --platform linux/amd64 donut)
docker cp "$id:/usr/local/bin/donut-server" ./donut-server && docker rm "$id"

# залить на VPS:
ssh <vps> mkdir -p /etc/donut
scp ./donut-server <vps>:/usr/local/bin/donut-server
scp ./server.toml  <vps>:/etc/donut/server.toml
```

### B. На VPS (свежий, ничего нет)

```sh
# 1. сертификат Let's Encrypt (порт 80 должен быть свободен)
dnf install -y certbot                       # Debian/Ubuntu: apt install -y certbot
certbot certonly --standalone -d <DOMAIN> -m <EMAIL> --agree-tos -n
install -m644 /etc/letsencrypt/live/<DOMAIN>/fullchain.pem /etc/donut/fullchain.pem
install -m600 /etc/letsencrypt/live/<DOMAIN>/privkey.pem   /etc/donut/privkey.pem

# 2. подложка self-steal: любой http-сайт на 127.0.0.1:8080 (например filebrowser)

# 3. systemd-юнит
cat > /etc/systemd/system/donut-server.service <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/donut-server --config /etc/donut/server.toml
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF

firewall-cmd --permanent --add-port=80/tcp --add-port=443/tcp && firewall-cmd --reload
systemctl daemon-reload && systemctl enable --now donut-server

curl -k https://<DOMAIN>                     # проверка: должен открыться сайт-подложка
curl -s http://127.0.0.1:9090/metrics | head # проверка: счётчики donut_* отдаются
```

### C. Клиент

Готовый клиент (телефон): вставить `vless://`-ссылку в HAPP / Streisand / v2box — всё.

Свой `donut-client` (роутер/ПК, РФ-трафик идёт мимо VPS):

```sh
cargo build --release -p donut-client
./target/release/donut-client import "vless://...."   # → ~/.donut/client.toml (РФ→direct)
./target/release/donut-client geo-update              # geoip.dat + geosite.dat
./target/release/donut-client --config ~/.donut/client.toml   # SOCKS5 127.0.0.1:1080
```

### Добавить ещё пользователя

UUID = отдельный credential на устройство (можно отзывать независимо). На VPS
добавь новый UUID в массив `users` в `/etc/donut/server.toml` и перезапусти:

```sh
NEW=$(uuidgen)
sed -i "s#^users = \[\(.*\)\]#users = [\1, \"$NEW\"]#" /etc/donut/server.toml
systemctl restart donut-server
# ссылка для нового юзера (на машине сборки):
cargo run -p donut-tools -- link --uuid "$NEW" --server-addr <DOMAIN>:443 --sni <DOMAIN>
```
Отозвать = убрать UUID из `users` + `systemctl restart donut-server`.

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

- [docs/DEPLOY.md](docs/DEPLOY.md) — подробный гайд по развёртыванию и клиенту.
- [docs/PRODUCTION.md](docs/PRODUCTION.md) — прод-готовность: аудит багов, перф.
- [docs/](docs/) — сетевой стек, спеки протоколов, REALITY/self-steal, план.

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
