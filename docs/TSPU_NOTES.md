# Что делает ТСПУ (как мы её понимаем на 2026-06-01)

Технические заметки про устройство и поведение ТСПУ (Технические Средства
Противодействия Угрозам, РКН-управляемая распределённая DPI-сеть у российских
операторов) — сведено из live-наблюдений на нашем боевом сервере + deep-research
по open-source-источникам (xray-core PRs, zapret/byedpi docs, IMC 2022, hub-посты
комьюнити). Источники процитированы по месту.

Цель документа: фиксация знаний для следующих итераций (xHTTP, anti-fingerprint).
Не runbook — для оперативного реагирования см. [TSPU_RECOVERY.md](TSPU_RECOVERY.md).

---

## 1. Архитектура и базовые классы фильтров

ТСПУ — это **распределённая DPI-сеть** у всех российских операторов, установленная
после "Закона о суверенном интернете" 2019 г. Через общий control-plane получает
свежие сигнатуры от РКН. Академическое описание методологии — [Xue et al., ACM IMC
2022](https://ensa.fi/papers/tspu-imc22.pdf).

Известные классы фильтрации на 2024-2026:

1. **SNI / ClientHello парсинг** — самый старый и до сих пор основной механизм.
   Hostname извлекается из (а) `Host:` заголовка в plain HTTP и (б) SNI extension
   в TLS ClientHello. Источники: [zapret docs](https://github.com/bol-van/zapret),
   [tspu-docs](https://github.com/DanielLavrushin/tspu-docs).

2. **JA3/JA4 fingerprint matching** — анализ структуры ClientHello: набор
   cipher suites, extensions, supported groups, ALPN, signature algorithms.
   Конкретный пример эскалации: **MTProxy Fake-TLS блокирован с 1 апреля 2026**
   по сигнатуре `TELEGRAM_TLS` (extension `0xfe02` + 20-байтный random — оба
   нестандартные). Подтверждение: [tdesktop PR #30513](
   https://github.com/telegramdesktop/tdesktop/pull/30513).

3. **Stateful traffic policing** — `freeze` после ~25 пакетов / ~16 КБ
   переданных байт на иностранную AS (Hetzner, DigitalOcean, OVH). Сессия
   «обнуляется» (zero-window), а не закрывается RST. [net4people #490](
   https://github.com/net4people/bbs/issues/490).

4. **CIDR-блок-листы на datacenter-ASN** — особенно агрессивно на мобильных сетях.
   [net4people #516](https://github.com/net4people/bbs/issues/516).

5. **TCP-реассемблия multi-packet ClientHello** — с дефолтом TLS-kyber
   (`X25519MLKEM768`) в Chromium 124+ ClientHello стал часто >MTU. ТСПУ-2026
   собирает сегменты обратно перед фингерпринт-анализом. Это **обесценивает
   простую TCP-фрагментацию** как обходной приём. Подтверждение:
   [BypassCore (2026)](https://bypasscore.com/blog/zapret-vs-goodbyedpi-vs-byedpi-comparison),
   [XTLS Discussion #5969](https://github.com/XTLS/Xray-core/discussions/5969).

6. **Port-specific policies** — :443/TCP имеет отдельную политику; альтернативные
   порты часто проходят легче. Репорты на [habr 990236](https://habr.com/en/articles/990236/)
   показывают ~80% success rate на портах >47000. _Не подтверждено для нашего IP_
   — у нас на :443 и :8443 success rate был одинаковым (~50%), значит фильтрация
   была не строго port-specific, а IP+pattern-specific.

7. **ML-классификация** — РКН с 2025 г. объявил публично об интеграции ML-моделей.
   [HRW Report 2025](https://www.hrw.org/report/2025/07/30/disrupted-throttled-and-blocked/state-censorship-control-and-increasing-isolation),
   [ACF 2026 Report](https://fbk.info/files/acf-internet-report-EN.pdf).

8. **Селективная блокировка ECH** — `cloudflare-ech.com` + ECH-extension в одном
   CH режется молча с ноября 2024. [net4people #417](
   https://github.com/net4people/bbs/issues/417).

---

## 2. Наша наблюдаемая сигнатура (live data, 2026-05-29 — 2026-06-01)

На cozbystorage (raw + vision:xray + cert-TLS, NL DC, IP `144.31.85.233`):

- **Первый TCP-сегмент 1424 байта от клиента проходит, последующие дропаются.**
  ClientHello не достигает сервера полностью → `rustls::handshake().await` блокируется
  → срабатывает наш 10-секундный таймаут.

- **`bytes_read = 1424` на КАЖДОМ TimedOut failure** — это
  `MTU 1500 − IP/TCP headers ≈ 1424` = ровно один TCP-сегмент payload.
  Видим это в логе как `error_kind:"TimedOut"`, `bytes_read:1424`.

- **Failure rate ~50%** — half-half. То есть ТСПУ работает **стохастически**,
  не «всё или ничего». Пропускает примерно половину попыток, режет другую.
  Поэтому xray-клиент в PassWall массово ретраит и в итоге получает рабочий
  туннель, но «лагает» на старте новых сессий.

- **Сигнатура одинакова на `:443` и `:8443`** — обе порта дают тот же ~50% fail
  rate с тем же `bytes_read=1424`. Значит для нашего IP ТСПУ-policing **по IP +
  TLS-pattern**, а не строго по порту. Дополнительные TCP-порты (например 2053,
  2096) скорее всего не помогут (мы их специально не подняли).

- **`donut_dial_failed = 149 за 10ч`** = 0.16% от 93k туннелей. То есть upstream
  reachability с сервера нормальная, проблема ровно на ingress-handshake. Это
  снимает гипотезу "Telegram не работает потому что сервер не достучаться".

**Класс атаки**: это **не split-detection** и **не fingerprint-by-CH-size**.
Это **stateful policing**: ТСПУ пускает первый TCP-сегмент чтобы TCP handshake
завершился, потом анализирует контент первого record и применяет policy.
По совокупности сигналов (JA3? ALPN? timing?) она "решает" дропать
последующие сегменты или нет. Согласуется с описанием в [habr 1009560](
https://habr.com/ru/articles/1009560/): _«первые пять пакетов соединения
проходят без активного вмешательства, ТСПУ собирает данные»_.

---

## 3. Почему обходные приёмы 2023-2024 больше не работают

### Простая TCP-фрагментация SNI (`fragment: tlshello`, `--split`)

**Был**: разрезать ClientHello на 2 куска так чтобы SNI был на границе сегментов
— DPI с однопроходным парсером не находит SNI.

**Стало**: ТСПУ-2026 делает TCP-реассемблию (особенно для CH с TLS-kyber, который
теперь дефолт в Chromium 124+ и часто >MTU). Сегменты склеиваются перед анализом,
SNI снова видим. Подтверждено: [XTLS #5969](https://github.com/XTLS/Xray-core/discussions/5969),
[zapret #1756](https://github.com/bol-van/zapret/issues/1756).

**Что ещё работает на стороне zapret/byedpi** (но требует более продвинутых
техник, не просто freedom-fragment):

- `nfqws` маркеры позиций — `host`, `midsld` (середина SLD), `sniext` (начало
  SNI extension) — режут CH так чтобы SNI оказался на стыке сегментов.
  [zapret readme](https://github.com/bol-van/zapret/blob/master/docs/readme.en.md).

- `--disorder` через `TTL=1` — фрагмент умирает по пути до DPI, SACK заставляет
  пересылать в порядке N..end, 1..N. Реверс порядка ломает DPI state-машину.
  [ByeDPI](https://github.com/hufrea/byedpi).

- Fake-пакеты с подобранным TTL — пакет с подменённым content доходит до DPI
  но не до сервера, сбивает DPI accounting. Требует тонкой настройки под
  каждый ASN.

### Vision padding (`xtls-rprx-vision`)

**Был**: рандомизировать длины TLS-records чтобы flatten timing/size фингерпринт.

**Стало**: само наличие `xtls-rprx-vision` flow и характерный pattern padding
теперь — distinctive feature. ТСПУ научилась распознавать Vision-traffic с
конкретного IP. Наш `~50% fail rate` — конкретное проявление этого: ТСПУ
видит наш паттерн с `144.31.85.233:443/TCP` и применяет стохастический drop.

### Чистый VLESS-TCP без vision

Та же проблема: предсказуемый pattern (постоянная TLS-сессия с большим объёмом
данных, ровный ритм) распознаётся ML-классификатором.

---

## 4. Что РАБОТАЕТ на 2026-06-01

### REALITY (XTLS)

Не передаёт собственный ClientHello — клиент **реплицирует CH с реального сайта**
(target `dest`), сервер знает что нужно перехватить. SNI и TLS-fingerprint валидны
для популярного домена.

**Состояние**: жив, в Иране переживает 100 ГБ трафика → graylist через ~48ч
([XTLS Discussion #3269](https://github.com/XTLS/Xray-core/discussions/3269)).
В РФ работает, но появляются репорты [net4people #546](
https://github.com/net4people/bbs/issues/546) что на некоторых ISP (МТС/МГТС,
JustLan, RTK Ижевск) **VLESS+REALITY+Vision на 443/TCP режется** — тот же класс
проблем что у нас на cert-TLS+Vision.

**Свежие апдейты** (релизы Xray-core):

- v25.7.26 — ML-DSA-65 post-quantum-сигнатуры в сертификате REALITY ([PR #4915](
  https://github.com/XTLS/Xray-core/pull/4915))
- v25.9.5 — ML-KEM-768 PFS в самом VLESS
- v25.12.8 — Vision padding улучшен (paddingMin/paddingMax настраиваются)
- v26.3.27 — предупреждения о небезопасных конфигах, default ECH "full"

### xHTTP transport (Xray)

Wire-протокол: вместо одного длинного TLS-туннеля — **множество коротких
HTTP-запросов** через H1/H2/H3 с **рандомизированным padding** в заголовках
(`Referer: ...?x_padding=XXX`, `X-Padding: XXX`, 100-1000 байт случайно).

Дизайн-цель RPRX (цитата из [#4113](https://github.com/XTLS/Xray-core/discussions/4113)):
_«增加审查者执行封锁时的「附带伤害」»_ — увеличить collateral damage блокировки,
сделав прокси-трафик похожим на множество естественных HTTP-взаимодействий.
Блокировка таких паттернов била бы по обычному вебу. **См. [XHTTP_DESIGN.md](
XHTTP_DESIGN.md)** для нашего плана внедрения.

### Hysteria 2 (UDP + QUIC + Salamander + port-hopping)

Принципиально другой класс трафика (UDP/QUIC). TCP-only filters ТСПУ к нему не
применимы. Минусы: HTTP/3 в РФ нестабилен (троттлинг QUIC), Salamander сам стал
fingerprint'ом, Gecko (новая обфускация в v2.9.2) ещё экспериментальная и не
поддерживается ядром sing-box у HAPP.

**Решение по hold-the-donut (2026-06-01)**: Hysteria НЕ интегрируем (нет
sterного бинаря в нашем коде, не хотим стороннего бинаря). xHTTP — приоритет.

---

## 5. Ключевые источники

### Live-наблюдения
- Наш собственный лог: `journalctl -u donut-server` на cozbystorage за
  2026-05-29 — 2026-06-01. Метрики `donut_session_errors_total{kind="tls_handshake"}`,
  `donut_probes_total`, `donut_bytes_read` в логах handshake-fails.

### Академическая
- Xue, Diwen et al., "TSPU: Russia's Decentralized Censorship System",
  ACM IMC 2022 ([PDF](https://ensa.fi/papers/tspu-imc22.pdf))
- HRW, "Disrupted, Throttled, and Blocked" (2025-07)
- ACF, "Access Denied" report (2026-03)

### Community
- [net4people/bbs #490](https://github.com/net4people/bbs/issues/490) — freeze на иностранной AS
- [net4people/bbs #546](https://github.com/net4people/bbs/issues/546) — TLS connection-policing на home ISPs
- [Xray-core #5332](https://github.com/XTLS/Xray-core/issues/5332) — «failed to read client hello»
- [Xray-core Discussion #5969](https://github.com/XTLS/Xray-core/discussions/5969) — DPI reassembles segments
- [Xeovo Hub post #132](https://hub.xeovo.com/posts/132-russia-widespread-vless-outages-due-to-tls-handshake-blockingdegradation-request-tlstransport-hardening-and-anti-probing) — operator summary 2026-01
- [Habr 990236](https://habr.com/en/articles/990236/), [1014038](https://habr.com/ru/articles/1014038/), [1009560](https://habr.com/ru/articles/1009560/) — RU-language разборы первых волн

### Bypass инструменты
- [zapret](https://github.com/bol-van/zapret) — nfqws стратегии
- [ByeDPI](https://github.com/hufrea/byedpi) — userspace SOCKS bypass
- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) — Windows-only WinDivert

### XTLS / Xray protocols
- xHTTP: [#4113](https://github.com/XTLS/Xray-core/discussions/4113),
  [PR #3994](https://github.com/XTLS/Xray-core/pull/3994),
  [dialer.go](https://github.com/XTLS/Xray-core/blob/main/transport/internet/splithttp/dialer.go)
- REALITY: [Discussion #3269](https://github.com/XTLS/Xray-core/discussions/3269)
- Freedom fragment: [docs](https://xtls.github.io/en/config/outbounds/freedom.html),
  [PR #2021](https://github.com/XTLS/Xray-core/pull/2021)

### MTProto
- [Telegram MTProto transports](https://core.telegram.org/mtproto/mtproto-transports)
- [tdesktop PR #30513](https://github.com/telegramdesktop/tdesktop/pull/30513) —
  фикс TELEGRAM_TLS classifier (`0xfe02` → `0xfe0d`, random 20→32 байт)

---

## 6. Помеченные неопределённости

Чтобы не вводить читателя в заблуждение — где наши знания «уверенно», где
«вероятно», где «требует подтверждения»:

- **«TELEGRAM_TLS» как название внутренней сигнатуры ТСПУ** — уверенно (прямая
  цитата из tdesktop PR), но это community-RE название, не подтверждение от РКН.
- **«freeze после 25 пакетов / 16 КБ»** — вероятно (net4people #490 + наблюдения),
  но конкретные числа варьируются по ISP.
- **«ML-классификация в ТСПУ»** — уверенно по политическим источникам (HRW, ACF),
  но конкретная архитектура ML-моделей не раскрыта.
- **«stochastic 50% fail rate как стандартное поведение»** — наблюдение только
  на нашем IP за 3 дня; для других IP может быть строже/мягче, и темп
  изменения политики может быть быстрее. Регулярно перепроверять.
- **«port-specific не работает у нас»** — подтверждено для :443 vs :8443
  одинаковый rate, но более экзотические порты (47000+) не тестировали.
