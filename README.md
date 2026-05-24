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

## Запуск

Оба демона читают JSON-конфиг (по умолчанию `/etc/donut/server.json` и
`/etc/donut/client.json`, путь переопределяется флагом `--config`). Примеры
конфигов — в [docs/examples/](docs/examples/).

```sh
donut-server --config server.json
donut-client --config client.json
```

После старта клиент слушает SOCKS5 по адресу из `inbound.socks` (в примере —
`127.0.0.1:1080`).

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
| `donut-config` | загрузчик JSON-конфига |
| `donut-server`, `donut-client` | бинарники |

Карта зависимостей и подробности по каждому крейту — [docs/CRATES.md](docs/CRATES.md).

## Документация

Подробные материалы лежат в [docs/](docs/): разбор сетевого стека,
спецификации протоколов, механика REALITY и self-steal, план по этапам.

## Статус

Версия 0.0.1, ранняя разработка. Готово: кодек VLESS, форк rustls с
REALITY-хуками, XHTTP-carrier (H1/H2), SOCKS5 inbound, базовый veil-путь на
сервере и клиенте. В работе: роутинг, DNS и geo, QUIC/HTTP-3 carrier,
Vision-padding, кросс-компиляция под роутеры (musl-таргеты заданы в
`rust-toolchain.toml`). Детали и этапы — [docs/PLAN.md](docs/PLAN.md).

## Лицензия

MPL-2.0.
