# TLS-фингерпринт ClientHello (uTLS-style)

Учебно-справочный разбор: что такое fingerprinting на уровне ClientHello,
что значит режим `randomized`, как это устроено в xray-core/uTLS и что из
этого реализовано в hold-the-donut.

Код: `donut-veil/src/fingerprint.rs`. Конфиг: `outbound.reality.fingerprint`.

## 1. Зачем вообще нужен fingerprint

TLS 1.3 шифрует почти всё, но **ClientHello идёт открытым текстом** — это
первый пакет, который видит любой пассивный DPI. Его форма (а не содержимое)
выдаёт, какой клиент его отправил:

- набор и **порядок** cipher suites;
- набор и **порядок** extensions;
- значения внутри extensions (supported_groups, signature_algorithms,
  supported_versions, ALPN…);
- наличие/позиция GREASE-значений (RFC 8701).

Хэш от этих полей — это **JA3** (и его наследник JA4). Каждая TLS-библиотека
имеет узнаваемый «почерк»: Chrome, Firefox, Go-stdlib, **rustls** — все
различимы по JA3 даже без расшифровки трафика.

Проблема для нас: rustls шлёт ClientHello со **стабильным, rustls-специфичным**
порядком расширений. Даже при идеальном REALITY-маскировании (правдоподобный
SNI, валидная подложка) JA3 = «rustls» — это аномалия для трафика, который
притворяется браузером, идущим на `www.microsoft.com`. DPI может занести такой
JA3 в чёрный список независимо от SNI.

## 2. uTLS и режим `randomized`

[uTLS](https://github.com/refraction-networking/utls) — форк Go-шного `crypto/tls`
с низкоуровневым доступом к ClientHello ради **мимикрии**. Два класса пресетов:

- **Parrot** (`HelloChrome_120`, `HelloFirefox_*`, `HelloSafari_*`, `HelloIOS_*`…) —
  байт-в-байт копируют ClientHello конкретного браузера, включая GREASE и
  точный порядок. Минус — «parrot-is-dead»: если копия отстала от реального
  релиза браузера, рассогласование версий само становится сигнатурой.

- **Randomized** (`HelloRandomized`, `HelloRandomizedALPN`,
  `HelloRandomizedNoALPN`) — генерируют **случайный, но полностью валидный**
  ClientHello: случайные cipher suites и extensions в случайном порядке, причём
  все выбранные значения поддержаны uTLS. Это «движущаяся мишень»: нет
  фиксированного JA3, который можно занести в blacklist, и нет риска
  parrot-is-dead (клиент всегда консистентен сам с собой).
  - `RandomizedALPN` / `RandomizedNoALPN` дополнительно **гарантируют наличие
    или отсутствие** расширения ALPN (остальное рандомизируется).

> Цитата из README uTLS: рандомизированные отпечатки хороши против чёрных
> списков, т.к. ciphersuites/extensions случайны и в случайном порядке, при
> этом все поддержаны uTLS — solid moving target без риска parrot-is-dead.

### Как это задаётся в xray-core

В xray-core поле `fingerprint` (TLS/REALITY-настройки) — строка, которую
`transport/internet/tls` нормализует (lowercase) и мапит на пресет uTLS:
`"chrome"`, `"firefox"`, `"safari"`, `"ios"`, `"android"`, `"edge"`, `"360"`,
`"qq"`, `"random"`/`"randomized"`, `"randomizedalpn"`, `"randomizednoalpn"`,
`""`/`"unspecified"` → без uTLS.

## 3. Что реализовано в hold-the-donut

Хук, через который мы правим ClientHello, — это
`ClientHelloMutator` форка `donut-rustls`. Контракт хука (см.
`donut-tls/src/client/client_conn.rs`):

- на вход даётся `&mut [u8]` поверх **уже сериализованного** тела handshake
  (заголовок на offset 0, 32-байтный legacy SessionID на offset 39);
- **длину менять нельзя** (`callback must not change the slice length`).

В рамках этого контракта верный поднабор `randomized` — это
**перестановка порядка** списка cipher suites и списка extensions
(длина сохраняется, оба списка лежат после SessionID):

| uTLS-строка                          | `Fingerprint`              | Поведение сейчас                |
|--------------------------------------|----------------------------|---------------------------------|
| `""`, `unspecified`, `none`, `native`| `Native` (по умолчанию)    | ClientHello rustls без изменений|
| `random`, `randomized`               | `Randomized`               | shuffle cipher suites + extensions |
| `randomizedalpn`                     | `RandomizedAlpn`           | как `Randomized` (см. ограничения) |
| `randomizednoalpn`                   | `RandomizedNoAlpn`         | как `Randomized` (см. ограничения) |
| `chrome`/`firefox`/… (parrot)        | —                          | **ошибка парсинга** (пока не реализовано) |

Перестановка делается на каждое соединение (`rand::thread_rng`), что и даёт
«движущуюся мишень» на уровне порядка (JA3 перестаёт быть стабильным).

### Почему это не ломает REALITY-печать

REALITY-метка вшивается в SessionID и запечатывается AES-256-GCM, где **AAD =
весь ClientHello с обнулённым SessionID**. Сервер реконструирует AAD из байтов,
которые реально приехали по проводу. Перестановку мы делаем **до** запечатывания
(см. `donut-veil/src/client.rs`), она трогает только байты *после* SessionID, а
сами Random[..32] и SessionID не двигаются — поэтому AAD на клиенте и сервере
совпадает, и seal остаётся валидным. Доказано тестом
`randomized_fingerprint_handshake_still_authenticates` (16 реальных
TLS 1.3-хендшейков подряд).

### PSK / resumption — почему выключен

`pre_shared_key` (TLS 1.3 resumption) несёт **binder'ы** — HMAC по усечённому
транскрипту ClientHello, посчитанные rustls **до** мутатора. Любая перестановка
ломает binder → сервер падает с `IncorrectBinder`. Поэтому:

1. Мутатор **не переставляет** ClientHello, если в нём есть `pre_shared_key`
   (инвариант: никогда не делать handshake невалидным).
2. Клиент-дайлер (`donut-client/src/veil_dial.rs`) **отключает resumption**
   (`Resumption::disabled()`): REALITY-соединения свежие, а PSK-тикет — это и
   сам по себе отдельный отпечаток.

## 4. Ограничения и дальнейшая работа

Из-за length-preserving контракта мутатора мы **не можем**:

- менять **набор** cipher suites/extensions (только порядок существующих);
- вставлять **GREASE** (RFC 8701) — это +N байт;
- форсить наличие/отсутствие ALPN (`RandomizedALPN`/`NoALPN`) — это
  добавление/удаление расширения, т.е. изменение длины. Поэтому ALPN-варианты
  пока ведут себя как обычный `Randomized`;
- реализовать **parrot-пресеты** (Chrome/Firefox): им нужен точный набор
  расширений с GREASE и конкретными значениями.

**Правильный путь дальше** — расширить хук форка так, чтобы он мог вернуть
владеющий буфер изменённой длины (`Fn(Vec<u8>, kx) -> Vec<u8>` или builder поверх
структурированного ClientHello). Тогда станут возможны GREASE, полноценный
`HelloRandomized` (с варьированием набора) и parrot-пресеты. Это отдельная
веха (см. `PLAN.md`, M7/M10).

## 5. Использование

```jsonc
// client.json → outbound.reality
{
  "public_key": "…",
  "short_id": "deadbeef",
  "server_name": "www.microsoft.com",
  "version": [26, 4, 15],
  "fingerprint": "randomized"   // "" | native | randomized | randomizedalpn | randomizednoalpn
}
```

Программно:

```rust
let cfg = VeilClientConfig::new(server_pub, short_id, [26, 4, 15])
    .with_fingerprint(donut_veil::Fingerprint::Randomized);
```

## Ссылки

- uTLS: <https://github.com/refraction-networking/utls>
- xray-core TLS-транспорт: `transport/internet/tls/tls.go` (XTLS/Xray-core)
- JA3: <https://github.com/salesforce/ja3>
- GREASE: RFC 8701 · PSK binders: RFC 8446 §4.2.11
