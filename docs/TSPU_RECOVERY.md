# TSPU recovery runbook

Оперативный гид: «VPN сейчас работает плохо или не работает — что делать
по шагам». Прот-уровневое описание ТСПУ — в [TSPU_NOTES.md](TSPU_NOTES.md).
Не дублируем сюда теорию, фокусируемся на triage и действиях.

---

## 0. Что у нас сейчас развёрнуто (2026-06-01)

**Сервер (`ssh cozbystorage`, 144.31.85.233, NL):**
- Primary `donut-server.service` — `raw + vision:xray` на `:443/TCP`, метрики `127.0.0.1:9090`
- Alt `donut-server-alt.service` — то же на `:8443/TCP`, метрики `127.0.0.1:9092`
- Оба под `LimitNOFILE=65536` (drop-in `/etc/systemd/system/donut-server*.service.d/limits.conf`)
- Конфиги `/etc/donut/server.toml` и `/etc/donut/server-alt.toml`, в обоих
  `[tuning] tls_handshake_timeout_secs = 10` и `accept_backoff_ms = 100`

**Роутер (`ssh donut-router`, 192.168.1.1, OpenWrt 24.10.5):**
- PassWall 2 v26.4.10 (новее `26.5.19` только manual ipk)
- xray-core `26.5.9`, sing-box `1.13.12`
- `v2ray-geoip 202605120112-r1`, `v2ray-geosite 20260518025449-r1` (опкг v2fly, **без Loyalsoldier extensions**)
- Узлы PassWall: `donutcozby` (:443), `donutcozby_8443` (:8443), `uGO3645b`
  (NL xHTTP), `WAktKcXZ`/`FUaWODNj` (другие альт-VPN)
- Шанты: `donutshunt_min` / `donutshunt_min_8443` (только `Russia → _direct`,
  работают), `donutshunt`/`donutshunt_8443` (с `OnlyTV1`/`Russia_Block` —
  СЛОМАНЫ после geo-апгрейда, не активировать)

---

## 1. Симптомы → класс события

| Симптом | Класс | Куда смотреть |
|---|---|---|
| HAPP/PassWall показывают «нет интернета», другие сайты тоже не работают | **A. Сервис лёг** | §2 |
| HAPP подключается, но открывает только часть сайтов (часто Telegram падает первым) | **B. ТСПУ стохастически режет** | §3 |
| HAPP не может вообще подключиться, но сам сервер `active` | **C. Полный handshake-block** | §4 |
| Скорость VPN внезапно упала до плинтуса (несколько КБ/с) | **D. Stateful freeze** | §5 |
| После переключения PassWall шанта 2 минуты молчит, потом «не работает» | **E. PassWall settling — норма** | §6 |

---

## 2. Класс A — Сервис лёг

### Диагностика

```sh
ssh cozbystorage '
  systemctl is-active donut-server donut-server-alt
  pid=$(systemctl show donut-server -p MainPID --value)
  ps -o %cpu=,rss=,etimes= -p "$pid"
  ls /proc/$pid/fd | wc -l       # FDs in use
  curl -s -m4 http://127.0.0.1:9090/metrics | head -3
'
```

**Сигналы:**
- `is-active` ≠ `active` → процесс упал
- CPU `>50%` стабильно → возможно busy-loop (fix CPU-spin был 2026-05-29,
  должен держаться; если CPU снова растёт — повторение бага)
- FDs близко к `donut_max_fds=65536` → утечка FD или slowloris атака
- `/metrics` не отдаёт → или сервис лежит, или EMFILE на metrics-listener

### Действия

```sh
ssh cozbystorage 'systemctl restart donut-server donut-server-alt'
# Verify
ssh cozbystorage '
  systemctl is-active donut-server donut-server-alt
  curl -s -m4 http://127.0.0.1:9090/metrics | grep -E "active_sessions|open_fds"
'
```

Рестарт сбрасывает все висячие соединения. Если FDs росли — после рестарта
очень быстро возвращаются к ~10 и потом снова растут до старого значения по мере
прихода реальных клиентов и атак. Watch `donut_open_fds` в Grafana.

---

## 3. Класс B — ТСПУ стохастически режет (типичный случай 2026)

### Диагностика

```sh
ssh cozbystorage '
  # дельта успешных vs failed handshake за 30с
  a_ok=$(curl -s http://127.0.0.1:9090/metrics | grep "outcome=\"ok\"" | awk "{print \$2}")
  a_err=$(curl -s http://127.0.0.1:9090/metrics | grep "kind=\"tls_handshake\"" | awk "{print \$2}")
  sleep 30
  b_ok=$(curl -s http://127.0.0.1:9090/metrics | grep "outcome=\"ok\"" | awk "{print \$2}")
  b_err=$(curl -s http://127.0.0.1:9090/metrics | grep "kind=\"tls_handshake\"" | awk "{print \$2}")
  echo "ok+=$((b_ok - a_ok))  tls_err+=$((b_err - a_err))"
'
```

**Сигналы класса B:**
- Соотношение `tls_err / (ok + tls_err)` ≈ 0.3–0.7 (часть проходит, часть нет)
- В логе handshake-fails: `error_kind:"TimedOut"`, `bytes_read:1424` —
  именно наша «1424-byte signature» из [TSPU_NOTES.md](TSPU_NOTES.md#наша-наблюдаемая-сигнатура)
- Активные сессии живы, bytes-rate ненулевой (что-то проходит)

### Что это значит

VPN **работает**, но с retry-storm на клиенте. Latency старта сессий повышенная.
Старые установленные туннели текут нормально. **Это не «сервер сломался»** — это
ТСПУ-апдейт, который ужесточил policing для нашего IP+TLS-pattern.

### Действия

**Быстро (5 минут):**
1. Подожди 30 минут — часто ТСПУ-волна спадает сама (см. поведение 2026-05-29:
   утром ~50% fail, к вечеру вернулось к ~10%)
2. В PassWall переключись на `donut RU-split MIN :8443` — иногда успехом
   распределяется неравномерно по портам. **ВАЖНО:** PassWall перегенерирует
   nftables ~**118 секунд** (см. §6), не дёргайся раньше двух минут.

**Среднесрочно (этот вечер):**
3. Если ситуация не спадает >2 часов — это новая стабильная ТСПУ-политика.
   Двигаемся в xHTTP роадмап (см. [XHTTP_DESIGN.md](XHTTP_DESIGN.md)).

**Долгосрочно:**
4. Сменить публичный IP сервера (новый VPS) — самый радикальный, но самый
   надёжный сброс ТСПУ-классификации. Цена: 30-60 мин ops + перевыпуск
   vless:// ссылок, новый Let's Encrypt сертификат.

---

## 4. Класс C — Полный handshake-block

### Диагностика

```sh
ssh cozbystorage '
  journalctl -u donut-server -u donut-server-alt --since "5 minutes ago" -o cat \
    | grep "217.15.57.228" | wc -l
'
```

**Сигнал**: НОЛЬ событий с твоего IP за 5+ минут (ни fails, ни sessions).
Раньше что-то приходило — теперь полная тишина. Это **TCP-уровень**: SYN твоего
роутера до сервера не доходит, либо SYN-ACK не возвращается.

### Действия

1. **Проверить с другого пути** — мобильный интернет, не WiFi. Если оттуда
   работает — твой ISP в новой блок-волне.
2. **Проверить что сервер сам жив** для других клиентов — `donut_connections_total`
   делта на :443 за минуту должна быть >0 (где-то ещё кто-то стучится).
   Если 0 от ВСЕХ — наш IP в широком CIDR-блок-листе.
3. **Смена IP/домена** — единственный реальный фикс полного IP-блока.

---

## 5. Класс D — Stateful freeze

### Диагностика

Скорость через VPN внезапно «обнулилась», но соединение живо (HAPP не выкидывает).
Tcp connection state на сервере `ESTABLISHED`, но `bytes_total` не растёт.

```sh
ssh cozbystorage '
  ss -tn state established "( sport = :443 )" \
    | awk "{print \$4}" | sed -E "s/:[0-9]+\$//" | sort | uniq -c | sort -rn | head
  # Watch:
  for i in 1 2 3 4 5; do
    curl -s http://127.0.0.1:9090/metrics | awk "/^donut_bytes_total/{s+=\$2} END{print s+0}"
    sleep 5
  done
'
```

**Сигнал**: bytes_total плоский, но множество ESTABLISHED с твоего IP.
ТСПУ применила `freeze` (zero-window) после ~16 КБ.

### Действия

- Рестарт текущей сессии в HAPP/PassWall — новый touch создаст новые туннели,
  они тоже скоро отфризятся.
- Реальный фикс — другой транспорт (xHTTP) или другой IP.

---

## 6. Класс E — PassWall settling (НЕ ошибка)

### Признак

Переключился в PassWall UI на `donut RU-split MIN :443` или `:8443`. Сразу же
тестируешь — **«не работает»**. Переключаешь обратно на `uGO3645b`.

### Что на самом деле

PassWall на переключение шанта **тратит ~118 секунд** для:
1. Очистить старые nftables-правила
2. Перезапустить xray-core с новым config'ом
3. Загрузить `geoip:ru` (это особенно долго — ~70 секунд на parse + add to NFTSET)
4. Поднять новые nftables-правила
5. Запустить redirect/tproxy

Источник: `/tmp/etc/passwall2/acl/default/passwall2.log` на роутере, цитата
из теста 2026-06-01:
```
12:43:54: Delete nftables rules
12:45:21: parse traffic splitting [Russia]-[geoip:ru] add to NFTSET complete
12:45:37: Use TCP node [donut RU-split MIN :443]
12:45:50: Running complete!     ← ноды активны ТОЛЬКО здесь, +118с от начала
```

### Действия

**ПОДОЖДИ 2 МИНУТЫ** после переключения шанта **перед** тем как делать вывод
«не работает». Если после 2 минут не работает — это уже класс B/C/D.

Тестировать в PassWall можно по логу:
```sh
ssh donut-router 'tail -f /tmp/etc/passwall2/acl/default/passwall2.log' | grep "Running complete"
```

---

## 7. Полезные одноразовые команды

### Быстрая дельта-метрика на сервере (за 30 секунд)

```sh
ssh cozbystorage '
  for port in 9090 9092; do
    a=$(curl -s http://127.0.0.1:$port/metrics)
    sleep 30
    b=$(curl -s http://127.0.0.1:$port/metrics)
    echo "--- port $port ---"
    diff <(echo "$a") <(echo "$b") | grep -E "^[<>] donut" | head
  done
'
```

### Источники TLS-handshake fails — это твой IP или сканеры?

```sh
ssh cozbystorage '
  journalctl -u donut-server --since "5 minutes ago" -o cat \
    | grep "raw tls handshake failed" \
    | grep -oE "peer\":\"[0-9.]+:" \
    | sed -E "s/.*\"([0-9.]+):/\\1/" \
    | sort | uniq -c | sort -rn | head
'
```

### Bytes_read distribution на fails (1424 = ТСПУ, 0 = scanner, >1424 = real client)

```sh
ssh cozbystorage '
  journalctl -u donut-server --since "10 minutes ago" -o cat \
    | grep "raw tls handshake failed" \
    | grep -oE "bytes_read:[0-9]+" \
    | sort | uniq -c | sort -rn
'
```

### Снимок текущей PassWall конфигурации (read-only)

```sh
ssh donut-router '
  echo "active node: $(uci get passwall2.@global[0].node)"
  uci show passwall2 | grep "=nodes\|=shunt_rules" | head
  tail -5 /tmp/etc/passwall2/acl/default/global.log
'
```

### Тестовый switch с auto-rollback (2 минуты)

См. скрипт-шаблон в [TSPU_NOTES.md §3.2] (если ещё не написан — был в нашем
session log 2026-06-01, сохранить отдельно).

---

## 8. Алерты в Grafana (рекомендуемые правила)

```promql
# A. Сервис лёг — нет успешных сессий >3 мин при наличии connection attempts
( rate(donut_connections_total[3m]) > 0.1 ) and ( rate(donut_sessions_total{outcome="ok"}[3m]) == 0 )

# B. TSPU stochastic spike
rate(donut_session_errors_total{kind="tls_handshake"}[5m]) > 5

# C. Полный IP-block — connections с твоего IP исчезли (нужен отдельный label,
#    или watch через external probe)

# D. FD leak
donut_open_fds / donut_max_fds > 0.7

# E. Memory leak
rate(donut_resident_memory_bytes[1h]) > 1048576    # > 1MB/h growth
```

---

## 9. Что мы НЕ делаем (по итогам 2026-06-01)

- **Не ставим сторонние бинари** (`hysteria`, upstream `xray`) — наш проект
  custom Rust, остаёмся в своём коде.
- **Не запускаем массово реактивные тесты** — теперь знаем что PassWall switching
  занимает 2 минуты, не дёргаемся раньше.
- **Не добавляем ещё TCP-портов** (`:2053`, `:2096`) — по нашим данным ТСПУ режет
  не строго по порту, а IP+pattern. Это не помогло бы.
- **Не выдумываем свой fake-TLS обёртку** — как показал MTProxy TELEGRAM_TLS
  classifier (1 апреля 2026), любой нестандартный fingerprint распознается за
  месяцы. Только REALITY-подход (репликация чужого CH) живёт долго.

---

## 10. История инцидентов

### 2026-05-29: CPU spin + FD exhaustion

CPU дошёл до 148%, VPN перестал работать. Корень: mux_relay busy-loop при
тоннель-EOF (см. commits `44be947` fix мукс-спина + `29c8cd8` accept-backpressure).
Заодно подняли LimitNOFILE 1024→65536.

### 2026-05-31: TSPU intensified

Failure rate ~50% на :443 и :8443 одновременно. Доказали что ТСПУ режет
не по порту а по IP+pattern. Ввели `tls_handshake_timeout_secs = 10` (commit
`89a91e8`) — handshakes больше не висят 2 часа, отваливаются за 10с.

### 2026-06-01: PassWall settling period обнаружен

Тест переключения PassWall на наш donut-сервер показал что нужно ждать **118с**
после смены шанта. Раньше думали что наш VPN "не работает", оказалось — просто
не подождали. Документация и runbook (этот файл) написаны.
