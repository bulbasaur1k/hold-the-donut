# Каскад + скрытая админка + подписки вне общего пула

Стратегический разворот после блокировки текущего одиночного NL-сервера
(см. [TSPU_RECOVERY.md](TSPU_RECOVERY.md), история инцидентов 2026-05-29…06-01).
Документ фиксирует: (1) готовность REALITY к бою, (2) новую ops-модель
«дешёвые серверы без мониторинг-стека», (3) ресёрч по CDN-обходу и zapret,
(4) каскад РФ→заграница по белым спискам, (5) как раздавать подписки, не светя
узлы из общего пула.

Дата: 2026-06-24. Эталон протоколов: xray-core v26.4.15.

---

## 1. Готовность REALITY (аудит кода на 2026-06-24)

Вывод: **ядро REALITY функционально готово к бою.** Реализация живёт в
`crates/donut-veil` (крипто+handshake) + `crates/donut-server/src/selfsteal.rs`
(triage/forward) + `veil_server.rs` (терминация) + `crates/donut-client/src/veil_dial.rs`.

| Компонент | Файл | Статус |
|---|---|---|
| X25519 ECDH → HKDF-SHA256 auth-key | `donut-veil/src/auth.rs` | ✅ |
| SessionID seal/open (AES-256-GCM, AAD=весь ClientHello) | `donut-veil/src/auth.rs` | ✅ |
| ClientHello parse (key_share, random, sessionid@39) | `donut-veil/src/parse.rs` | ✅ |
| Серверный вердикт + fallback на Forward | `donut-veil/src/server.rs` | ✅ |
| Клиентский ClientHello-mutator | `donut-veil/src/client.rs` | ✅ |
| Server-auth proof (HMAC-SHA256, анти-MITM внутри туннеля) | `donut-veil/src/proof.rs` | ✅ |
| Selfsteal triage + байт-прозрачный relay на `dest` | `donut-server/src/selfsteal.rs` | ✅ |
| uTLS fingerprint randomization (анти-JA3) | `donut-veil/src/fingerprint.rs` | ✅ |
| Конфиг (private/public key, short_ids, dest, server_name, version, fp) | `donut-config/src/lib.rs` | ✅ |
| E2E: handshake / forward-to-decoy / tunnel-echo / carrier / full SOCKS→freedom | `donut-veil/src/tests.rs`, `donut-server/tests/selfsteal_e2e.rs`, `donut-client/tests/veil_*_e2e.rs` | ✅ |

**Частично / отсутствует (не блокирует запуск, но хардит против ТСПУ):**

- ⚠️ **Anti-replay**: `unix_ts` пишется клиентом в plaintext SessionID, но сервер
  его НЕ проверяет (нет окна clock-skew, нет reject старых меток). Захваченный
  ClientHello можно переиграть. Фикс ~10 строк в `donut-veil/src/server.rs`
  (после распаковки plaintext: `|now - ts| > allowed_drift → Verdict::Forward`).
- ⏳ **Vision flow-control / TLS-in-TLS splice**: codec `donut-wire/src/vision.rs`
  готов (5 unit-тестов round-trip), но wiring `flow=vision` поверх raw-TCP+REALITY
  carrier ещё не подключён (M5.5 step 2). Без него HTTPS-в-туннеле даёт двойную
  TLS-сигнатуру. Для каскада это критичнее, чем раньше (см. §5).
- 📋 **Post-quantum (ML-KEM hybrid)**: X25519-only, отложено в M10. `donut-tls`
  backend (aws-lc-rs) умеет, REALITY-auth — нет. Не приоритет.

**Что нужно сделать перед боевым каскадом (по REALITY):**
1. Закрыть anti-replay window (дёшево, повышает стойкость).
2. Подключить Vision-транспорт (M5.5 step 2) — особенно для inter-node hop.
3. Подложка (`dest`) — реальный сайт с валидным TLS 1.3 + правильным ALPN
   (вне scope кода, ops-задача).

---

## 2. Новая ops-модель: дешёвые серверы, ноль мониторинг-стека

**Решение (2026-06-24):** больше не разворачиваем Prometheus/Grafana/отдельные
мониторинг-VPS. Серверы — самые дешёвые (1 vCPU / 512–1024 MB). Хелсчеки,
метрики и логи остаются, но **прячутся под админскую микро-аутентификацию**,
чтобы не открывать лишних портов и не светить сервис сканерам.

### Текущее состояние (что уже есть)

- `metrics::serve` (`donut-server/src/metrics.rs`) — отдаёт Prometheus-текст на
  **отдельном** listener'е. Сейчас биндится на `127.0.0.1:9090` (loopback,
  доступ только через SSH-туннель). Аутентификации нет — любой, кто на loopback,
  читает.
- `subscription::serve` (`donut-server/src/subscription.rs`) — опциональный
  публичный HTTP-эндпоинт `/sub/<uuid>`. Сейчас это **открытый порт** (за TLS
  reverse-proxy в проде). Это и есть «общий пул», который мы хотим убрать (§6).
- Логи — через `tracing` → journald на сервере, читаются по SSH.

### Целевая модель: «admin-over-tunnel», ноль лишних портов

Главный принцип: **не открывать ни одного нового публичного порта под админку.**
Любой отдельный порт (9090, /metrics, /admin) — это то, что Шодан/ТСПУ-сканер
найдёт и по чему классифицирует сервер. Вместо этого админ ходит **через тот же
REALITY-туннель**, что и обычный VPN-клиент, но с привилегированным UUID,
который роутится на внутренний loopback-сервис.

```
admin-клиент --REALITY/VLESS--> :443 --(triage: admin-UUID)--> 127.0.0.1:9090 /metrics
                                                          \--> 127.0.0.1:9091 /healthz
                                                          \--> journald tail (admin command)
обычный юзер --REALITY/VLESS--> :443 --(triage: user-UUID)--> freedom/каскад-хоп
сканер/зонд  --plain TLS------> :443 --(triage: no-auth)----> relay на decoy dest
```

Преимущества:
- Поверхность атаки = ровно один порт :443, неотличимый от подложки.
- `/metrics`, `/healthz`, `tail логов` слушают только loopback — снаружи их нет.
- «Микро-auth» = факт владения admin-UUID + short_id (тот же REALITY-крипто,
  ничего нового изобретать не нужно). Можно усилить отдельным bearer-токеном в
  HTTP-заголовке поверх туннеля.

**Реализация (план):**
1. В конфиге сервера — секция `[admin]`: `admin_uuid`, опц. `bearer_token`,
   `metrics_addr=127.0.0.1:9090`, `health_addr`, `allow_log_tail=true`.
2. В triage (`selfsteal.rs` / `proxy.rs`): если аутентифицированный VLESS-таргет
   == зарезервированный internal-адрес (напр. `donut.internal:9090`) И UUID ==
   `admin_uuid` → роутить на loopback metrics/health вместо обычного proxy.
   Иначе — как обычный пользователь.
3. `metrics::serve` оставить на loopback (он уже там). Добавить рядом
   `healthz` (200 + версия + аптайм + active_sessions).
4. Опциональный `bearer_token`: проверять `Authorization: Bearer …` в
   metrics/health-респондере — второй фактор поверх REALITY.
5. Грейс: НИКОГДА не биндить metrics/health на `0.0.0.0`. CI-линт/тест на это.

### Реализовано (2026-06-24): Basic Auth + /healthz на admin-эндпоинте

Вместо «всё через туннель» выбран более простой и совместимый с Prometheus
путь (по запросу пользователя — логин+пароль + scrape Прометеусом):

- **HTTP Basic Auth** на эндпоинте метрик (`donut-server/src/metrics.rs`,
  `AdminAuth`): username + **Argon2** PHC-хеш пароля. Верификация
  constant-time. Prometheus умеет `basic_auth` нативно → scrape работает.
- **`/healthz`** на том же листенере (JSON `{"status":"ok","version":…}`) —
  для uptime-чеков/балансировщиков.
- Конфиг `[metrics] username` + `password_hash` (оба или ни одного; если нет —
  лог-warning, что эндпоинт без auth). Генерация креды:
  `donut-tools admin-passwd [--user U] [--password P]` — печатает пароль один
  раз + Argon2-хеш + готовый `[metrics]` сниппет.
- **Стелс**: `listen` биндить на loopback / приватную mgmt-сеть (WireGuard),
  НИКОГДА на `0.0.0.0`. Тогда снаружи порта нет, central-узел scrape'ит по WG;
  Basic Auth — второй фактор поверх сетевой изоляции.

**Модель сбора с центрального узла:** один admin/мониторинг-узел (можно
держать Prometheus+Grafana ТОЛЬКО на нём) ходит к дешёвым нодам по приватной
сети (WireGuard mgmt) и scrape'ит `/metrics` с Basic Auth. Дешёвые ноды сами
ничего не разворачивают.

### Логи в этой модели (как получать)

Prometheus метрики *pull*-ит, но логи он не собирает. Варианты (от простого):

1. **journald локально + SSH** (ноль нового кода/демонов): ноды логируют через
   `tracing`→journald (systemd), central-узел тянет `ssh node journalctl -u
   donut-server --since …`. Так уже делает [TSPU_RECOVERY.md](TSPU_RECOVERY.md).
2. **`/logs` ring-buffer эндпоинт** (donut-native, рекомендую): in-process
   кольцевой буфер последних N структурированных строк (tracing-layer) +
   `GET /logs?tail=N` на том же admin-листенере за тем же Basic Auth. Central-узел
   просто `curl`-ит. Без отдельного агента на дешёвой ноде. ⏭️ не реализовано.
3. **Loki + promtail/Alloy** («Прометеус для логов»): полноценная агрегация, но
   это агент-шиппер на каждой ноде + Loki — противоречит «без мониторинг-стека
   на дешёвых». Если хочется красивых дашбордов — держать Loki+Grafana ТОЛЬКО на
   central-узле, а на ноды НЕ ставить (тянуть journald по варианту 1/2).

**Хелсчек для дешёвого хостинга без мониторинга:** `/healthz` на loopback +
маленький `donut-tools` healthcheck-режим, который сам сервер дёргает по cron и
шлёт пуш (telegram/webhook) только при FAIL. Пуш-модель вместо pull-мониторинга:
тихо, пока всё ок; пинг, когда лежит. (Метрики из `metrics.rs` уже содержат всё
для алертов: `donut_open_fds/max_fds`, `donut_session_errors_total{kind=tls_handshake}`,
`donut_sessions_total`, `donut_resident_memory_bytes` — см. §8 TSPU_RECOVERY.)

---

## 3. ТСПУ-контекст: почему одиночный загран-IP больше не живёт

Из [TSPU_RECOVERY.md](TSPU_RECOVERY.md) + свежий ресёрч (habr 990206, 2026):

- ТСПУ перешла от RST-обрыва к **«заморозке»**: после ~15–20 KB в одной TCP-сессии
  пакеты просто перестают доходить (zero-window freeze). Прямое соединение
  «юзер → иностранный хостинг» режется объёмной фильтрацией.
- Фильтрация идёт **по IP+pattern, не по порту** — добавлять порты бессмысленно
  (мы это уже проверили, §9 TSPU_RECOVERY).
- **Белые списки**: трафик «российский сервер → российский сервер» фильтруется
  гораздо мягче. IP одобренного российского хостинга (Yandex.Cloud, EDGE и т.п.)
  фактически в whitelist. Проверка «белизны»: подними web на :443, открой с
  мобильного (МТС/Мегафон) без VPN — открылось → IP whitelisted.

Вывод: будущее — **каскад с входом на белом российском IP** (§5).

---

## 4. Ресёрч: CDN-обход и zapret

### 4.1 zapret (bol-van) — что это и где предел

[zapret](https://github.com/bol-van/zapret) — кроссплатформенный DPI-bypass,
**локальная** манипуляция пакетами (не туннель). Демоны `nfqws` (через NFQUEUE)
и `tpws` (transparent proxy).

Механика — **десинхронизация DPI**: заставить DPI увидеть НЕ то, что увидит сервер.
- Фрагментация TLS ClientHello (split на границе SNI).
- **Fake-пакеты** (поддельный сегмент с TTL/bad-checksum, который доходит до DPI,
  но не до сервера) — DPI «травится» фейком, реальный запрос проходит.
- Фазы: на TCP-handshake / decoy-сегменты / модификация реального запроса.
- Hostlist-режим: десинк только для нужных доменов. Умеет работать прозрачно на
  роутере для всей сети. Есть QUIC/UDP-десинк.

**Предел (важно для нас):** современные ТСПУ всё чаще делают **полную TCP-reassembly**
— тогда чисто пакетные трюки (split/fake) теряют силу. zapret — это про доступ к
заблокированным **сайтам напрямую**, он НЕ заменяет туннель и НЕ обходит whitelist
объёмную фильтрацию. Для нас zapret — это:
- (а) запасной канал доступа к сайтам без VPN на клиенте;
- (б) **идея десинка применима к нашему REALITY-хопу** — фрагментировать наш
  собственный ClientHello, чтобы 1424-байтовая сигнатура (§3 TSPU_NOTES) не
  складывалась в один сегмент. Это дешёвый client-side хардинг.

### Нативный десинк в нашем софте (вместо сайдкара) — рекомендуется

xray-core реализует DPI-десинк **прямо в коде** через `freedom { fragment }`
(см. docs xtls /config/outbounds/freedom): фрагментация TLS ClientHello на уровне
приложения — `packets:"tlshello"`, `length` (размер фрагмента), `interval` (мс).
Плюс `noises` для UDP/QUIC. Это **не требует NFQUEUE/root**, работает для трафика,
который мы сами инициируем.

**Вывод для нас:** в каскаде РФ-узел САМ дозванивается до YouTube через freedom
(geoip:ru→freedom). Значит мы фрагментируем его ClientHello **нативно в нашем
freedom-outbound** — надёжнее хрупкого nfqws-сайдкара и без отдельного сервиса.

✅ **РЕАЛИЗОВАНО 2026-06-24:** `donut-server/src/fragment.rs` — детект TLS
ClientHello (0x16…0x01) + переэмит payload как несколько меньших TLS-записей
(`length`-байт чанки) с задержкой `interval`. Конфиг `[fragment] {packets,
length, interval}` (donut-config), применяется в freedom-ветке `handle_session`
(только direct egress, не chain). `Outbounds` несёт `FragmentParams`. Tests:
`fragment::tests` (2 unit) + `fragment_e2e.rs` (e2e: client→server→target
получает фрагментированный ClientHello). Сайдкар zapret — только fallback, если
фрагментации мало (fake-пакеты с TTL, чего на app-уровне не сделать).

**Выбор цели прикрытия (`dest`/`serverNames`):** `donut-tools tls-ping <host>` —
аналог `xray tls ping`: проверяет TLS 1.3 + X25519 + ALPN h2 и печатает SAN'ы
сертификата (готовые `serverNames`). Best-practice: красть серт у соседа по ASN
(тот же датацентр, что VPS), НЕ за чужим CDN, иностранный/популярный/стабильный.

Сравнения: zapret vs GoodbyeDPI vs ByeDPI — zapret самый гибкий и
router-friendly ([bypasscore](https://bypasscore.com/blog/zapret-vs-goodbyedpi-vs-byedpi-comparison)).

### 4.2 CDN для обхода — что реально работает в 2026

- **Domain fronting (классический)** — SNI=невинный домен CDN, зашифрованный
  `Host:` = реальный бэкенд. **Практически мёртв**: Cloudflare/Google/Amazon
  отключили fronting (CF — давно, Google/AWS — 2018). Не закладываемся.
- **Что живёт — CDN-passthrough / «CDN как фронт»**: VLESS/xHTTP/WebSocket
  через Cloudflare-проксируемый домен. DPI видит TLS к **IP Cloudflare**,
  расшаренному миллионами сайтов — блокировать = положить пол-интернета. SNI и
  Host совпадают (твой домен на CF), но сам IP «слишком ценный, чтобы блокировать».
  Минусы: CF terminates TLS (REALITY поверх CF не работает — REALITY требует
  сквозной TLS до нашего сервера); по CF идёт WS/xHTTP в открытом (для CF) виде;
  CF баним по abuse; латентность/скорость хуже.
- **Вывод по CDN для нас:** CDN — это **альтернативный транспорт-фронт**, а не
  замена REALITY. Два непересекающихся профиля стойкости:
  - REALITY (selfsteal) — лучшая маскировка, но прямой IP (его и режут → каскад).
  - xHTTP-over-CDN — IP не палится (прячется за CF), но без REALITY-маскировки
    и с деградацией. Хороший **резервный** профиль на случай блокировки входного
    IP каскада. У нас xHTTP-транспорт уже есть (`XHTTP_DESIGN.md`).

---

## 5. Каскад: РФ-вход → загран-выход по белым спискам

### 5.1 Топология

```
[Клиент в РФ]
   │  REALITY/VLESS (selfsteal :443), маскировка под белый сайт
   ▼
[ВХОД — дешёвый VPS на БЕЛОМ российском IP]   (Yandex.Cloud / EDGE / ru-hoster)
   │  inter-node hop: VLESS+Vision поверх xHTTP packet-up (RU→RU = не мёрзнет)
   ▼
[ВЫХОД — дешёвый загран-VPS]                   (NL/DE/любой)
   │  freedom outbound в открытый интернет
   ▼
[Заблокированный сайт]
```

Почему так:
- Хоп «клиент → ВХОД» — это `юзер → российский IP`, мягкая фильтрация, объёмной
  заморозки нет (белый список).
- Хоп «ВХОД → ВЫХОД» — это `сервер → сервер`, ТСПУ видит обычный межсерверный
  обмен, фильтрует слабо. Внутри — наш REALITY/Vision, наружу — TLS к загран-IP.
- ВЫХОД делает реальный выход в интернет; его IP в РФ напрямую не светится.

### 5.2 Протоколы между узлами (рекомендация)

- **Клиент → ВХОД:** наш REALITY selfsteal на :443 (как сейчас). Это то, что
  юзер импортирует. Маскировка максимальная.
- **ВХОД → ВЫХОД:** VLESS + **Vision** поверх **xHTTP packet-up** (так же
  советует habr 990206 ради низкого RAM на дешёвом VPS). Vision критичен здесь —
  убирает TLS-in-TLS сигнатуру на загран-плече (поэтому §1 M5.5 step 2 нужен).
  ВХОД выступает как наш `donut-client` в роли релея (dialerProxy-аналог).

### 5.3 Маршрутизация по белым спискам (split на ВХОДЕ)

ВХОД роутит:
- `geosite:category-ru` + `geoip:ru` → **direct** (прямо из РФ, не гоним за
  границу — быстро и не палим загран-канал на российском трафике).
- остальное → **хоп на ВЫХОД** → freedom.

У нас уже есть RU-split (`donut-routing`, geoip/geosite, профиль `ru` в подписках).
Тот же движок переносится на ВХОД, только outbound для «не-РФ» = не freedom, а
chain-hop на ВЫХОД. См. `donut-routing/src/lib.rs` + `subgen.rs` (профиль RU
уже зашит в JSON-подписку).

### 5.4 Что нужно дописать в коде под каскад

1. **Relay/chain outbound на сервере**: сейчас `donut-server` умеет freedom +
   selfsteal-forward. Нужен исходящий VLESS-клиент-аутбаунд (переиспользовать
   `donut-client/src/veil_dial.rs` как библиотеку) — чтобы ВХОД дозванивался до
   ВЫХОДА по REALITY/Vision.
2. **Маршрут «не-РФ → chain»** в `donut-routing` (новый тип outbound = chain).
3. **Vision wiring** (M5.5 step 2) на inter-node плече.
4. **Anti-replay** (§1) — на обоих узлах.

---

## 6. Подписки вне общего пула

### 6.1 Проблема

Публичный `/sub/<uuid>` (`subscription.rs`) = «общий пул»: один known хост раздаёт
конфиги всем. Если этот хост/домен спалится — палятся и адреса узлов внутри
выдаваемых конфигов, и сам факт сервиса. Плюс это лишний публичный порт на дешёвом
сервере (§2). Решение: **убрать публичную раздачу, перейти на каскадную модель.**

### 6.2 Ключевой принцип для каскада

В подписке клиента должен фигурировать **только адрес ВХОДА** (белый РФ-IP).
Адрес ВЫХОДА (загран) **никогда не попадает в клиентский конфиг** — он известен
только ВХОДУ. Так загран-узел не палится из клиентских подписок вообще:
скомпрометированная подписка раскрывает лишь «белый» вход, который и так не жалко
(легко заменить, объёмно не режется).

### 6.3 Рекомендуемая схема раздачи (от простого к стойкому)

**Вариант A — рекомендую для старта: статичные подписки вне сервиса.**
- Генерируем конфиг/`vless://`-ссылку оффлайн утилитой `donut-tools`
  (переиспользует `donut-config/src/subgen.rs`, который уже умеет json/xray/
  clash/links/happ).
- Раздаём файл вручную/через приватный канал (Telegram-бот, gist с токеном,
  зашифрованный pastebin). Сервер НЕ держит публичный sub-порт вообще.
- `subscription::serve` отключаем в проде (не задаём `[subscription] listen`) —
  код остаётся для локальной генерации.

**Вариант B — подписка через сам туннель (admin-over-tunnel, §2).**
- `/sub/<uuid>` слушает **только loopback** на ВХОДЕ и доступен лишь через
  аутентифицированный REALITY-туннель (как метрики). Юзер с валидным UUID,
  подключившись, тянет обновление конфига изнутри туннеля. Снаружи порта нет.
- Плюс: ротация коротких ID/ключей без переотправки ссылок.

**Вариант C — резерв: подписка за CDN (§4.2).**
- `/sub` за Cloudflare-доменом с длинным секретным путём и bearer-токеном. IP
  сервера скрыт за CF. Только как fallback, если приватный канал недоступен.

**Per-user изоляция (против «общего пула»):**
- Свой `short_id` + свой UUID на каждого пользователя (у нас allowed-user set
  уже есть — `UserAuth`). Утечка одного юзера → ревок одного short_id, остальные
  живы, узел не меняется.
- Ротация `short_ids` по расписанию.

### 6.4 Что делаем с текущим `subscription.rs`

- Прод: **не поднимать** публичный listener (убрать `[subscription] listen` из
  `/etc/donut/server.toml`).
- Логику генерации вынести в `donut-tools` CLI (оффлайн) — вариант A.
- Опционально позже: перевесить listener на loopback + admin-gate — вариант B.

---

## 7. Решения зафиксированы (2026-06-24)

По ответам пользователя:
- **Каскад**: клиент → РФ-вход (REALITY+xHTTP) → РФ-узел роутит: `geoip:ru`
  **+ YouTube** остаются на РФ-выходе **через zapret** (РФ душит YouTube даже
  напрямую — zapret-десинк снимает троттлинг); остальное не-РФ → хоп на загран-выход.
- **Inter-node**: VLESS+**Vision** over **xHTTP packet-up** (низкий RAM, убирает
  TLS-in-TLS). Требует Vision wiring (M5.5 step 2).
- **Админка**: один центральный узел может собирать метрики/состояние тачек, но
  всё закрыто admin-аутом (admin-over-tunnel, §2). Публичных metrics/health-портов нет.
- **Подписки**: оставляем `/sub`, но за **CDN** (Cloudflare) с секретным путём +
  bearer-токеном (вариант C, §6.3). IP сервера скрыт за CF. Адрес ВЫХОДА в конфиг
  не попадает.
- **Деплой пока нет**: готовим и тестируем локально; пользователь купит 2 тачки
  и протестируем.

### zapret на РФ-узле (новое требование)

РФ душит YouTube/Google-видео даже для прямого РФ-egress. На РФ-узле для
direct-ветки ставим **zapret** (`nfqws` через NFQUEUE) как системный сервис рядом
с нашим бинарём — десинк (split ClientHello + fake-пакеты) снимает троттлинг
QUIC/TLS к `googlevideo`. Это ops-интеграция (не в нашем Rust-коде): hostlist на
домены YouTube/Google. Альтернатива/дополнение: client-side фрагментация нашего
ClientHello, чтобы 1424-байтовая сигнатура не складывалась в один сегмент.

## 8. Дорожная карта (статус)

1. ✅ **Anti-replay** в `donut-veil/src/server.rs` — DONE 2026-06-24. Окно
   clock-skew (дефолт 120с, конфиг `reality.anti_replay_skew_secs`, `0`=off).
   Tests: `fresh_timestamp_authenticates`, `stale_timestamp_is_forwarded`,
   `disabled_skew_accepts_any_timestamp` (+ e2e selfsteal/veil зелёные).
2. 🟡 **Admin endpoint auth** — ЧАСТИЧНО DONE 2026-06-24: Basic Auth (Argon2) +
   `/healthz` на metrics-листенере; `donut-tools admin-passwd`; конфиг
   `[metrics] username/password_hash`. Tests: `metrics_e2e` (401/200/healthz).
   ⏭️ Осталось: `/logs` ring-buffer эндпоинт (вариант 2 в §2); push-healthcheck.
3. ⏭️ **Vision wiring** (M5.5 step 2) — для inter-node плеча.
4. ✅ **Chain outbound** — DONE 2026-06-24. `donut-server/src/outbound.rs`:
   `Outbounds`/`ChainOutbound` (veil/REALITY dial → carrier stream-one → VLESS
   request с оригинальным таргетом → relay). Wired в `handle_session` (egress =
   `Box<dyn Duplex>`: chain | freedom), прокинут через `run_veil_proxy`. Конфиг
   `[[outbounds]]` (tag/transport/server/uuid/reality). Test:
   `donut-client/tests/cascade_e2e.rs` (client→вход[chain]→выход[freedom]→echo).
   ⏭️ Follow-up: xhttp-вход (`run_tls_carrier_proxy`) тоже умеет chain — нужно
   прокинуть туда `outbounds` (сейчас передаётся пустой). REALITY-вход готов.
5. ⏭️ **Routing chain**: «не-РФ → chain», «YouTube → direct+zapret» в `donut-routing`
   (движок готов — нужны geoip/geosite-правила в конфиге ВХОДА, см. §9).
6. ⏭️ **CDN-подписка**: bearer/секретный-путь gate в `subscription.rs` (вариант C).
7. ⏭️ zapret hostlist на РФ-узле (ops, при деплое).
8. Развернуть: ВХОД на белом РФ-IP (Yandex.Cloud/EDGE), ВЫХОД на дешёвом загран-VPS.

---

## 9. Конфиги для развёртывания каскада (REALITY)

Генерация ключей: `donut-tools keygen` (на каждый узел свой keypair + short_id),
UUID — `uuidgen`. Адрес ВЫХОДА фигурирует ТОЛЬКО в конфиге ВХОДА (`[[outbounds]]`).

### ВЫХОД (загран-VPS) — `server.json`

Обычный REALITY-сервер с freedom-egress (как сейчас на NL), плюс свой user:

```json
{
  "inbound": {
    "listen": "0.0.0.0:443", "transport": "veil",
    "users": ["<EXIT_UUID>"],
    "reality": {
      "private_key": "<EXIT_PRIV>", "short_ids": ["<EXIT_SID>"],
      "dest": "127.0.0.1:8443", "cert": "/etc/donut/fullchain.pem", "key": "/etc/donut/privkey.pem"
    }
  },
  "metrics": { "listen": "127.0.0.1:9090", "username": "ops", "password_hash": "<argon2>" }
}
```

### ВХОД (белый РФ-IP) — `server.json`

REALITY-вход для клиентов + chain-outbound на ВЫХОД + RU-split routing:

```json
{
  "inbound": {
    "listen": "0.0.0.0:443", "transport": "veil",
    "users": ["<CLIENT_UUID>"],
    "reality": {
      "private_key": "<ENTRY_PRIV>", "short_ids": ["<ENTRY_SID>"],
      "dest": "127.0.0.1:8443", "cert": "/etc/donut/fullchain.pem", "key": "/etc/donut/privkey.pem"
    }
  },
  "outbounds": [
    {
      "tag": "exit", "transport": "veil",
      "server": "<EXIT_IP>:443", "uuid": "<EXIT_UUID>",
      "reality": {
        "public_key": "<EXIT_PUB>", "short_id": "<EXIT_SID>",
        "server_name": "<EXIT_SNI>", "version": [26,4,15], "fingerprint": "randomized"
      }
    }
  ],
  "routing": {
    "default": "exit",
    "rules": [
      { "geoip": ["ru"], "outbound": "freedom" },
      { "geosite": ["youtube","google"], "outbound": "freedom" }
    ]
  },
  "metrics": { "listen": "127.0.0.1:9090", "username": "ops", "password_hash": "<argon2>" }
}
```

Семантика routing ВХОДА: `geoip:ru` + YouTube/Google → `freedom` (прямой egress
из РФ; YouTube — через zapret на хосте, §7); всё остальное → `exit` (chain на
загран-выход). Клиент получает только адрес ВХОДА.

> **NB:** при `transport="veil"` chain работает. Для `transport="xhttp"` входа
> нужен 1-строчный follow-up (прокинуть `outbounds` в `run_tls_carrier_proxy`).

## Источники (ресёрч 2026-06-24)

- zapret: <https://github.com/bol-van/zapret>, DPI techniques —
  <https://deepwiki.com/bol-van/zapret/4-dpi-circumvention-techniques>
- DPI bypass сравнение — <https://bypasscore.com/blog/zapret-vs-goodbyedpi-vs-byedpi-comparison>
- Белые списки + цепочки (РФ, 2026) — <https://habr.com/en/articles/990206/>
- Reality/CDN/Warp универсальный обход — <https://habr.com/en/articles/990542/>
- Domain fronting (история/статус) — <https://en.wikipedia.org/wiki/Domain_fronting>
- Xray routing (chain/dialerProxy) — <https://xtls.github.io/en/config/routing.html>
