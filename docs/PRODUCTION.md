# Производственная готовность

Свод по проду: унаследованные баги xray-core (и наш статус), Docker-vs-native,
чеклист производительности. Источник — аудит 2026-05-26 (ресёрч по xray-core
issues + бенчмарки сети).

## 1. Унаследованные баги xray-core (зона Vision-splice)

Мы реализовали faithful Vision splice (обход внешнего TLS на сырой TCP после
`CommandPaddingDirect`, см. [VISION_PROTOCOL.md](VISION_PROTOCOL.md)). Три бага
xray-core лежат ровно в этой зоне — проверено, что наш дизайн от них защищён:

| Issue | Баг | Наш статус |
|---|---|---|
| [#5961](https://github.com/XTLS/Xray-core/issues/5961) | `panic: slice bounds out of range` в XtlsPadding, когда заголовок обещает длину > остатка буфера | **Иммунны**: `Unpadder` консумит `min(declared, available)` за `push`, не слайсит за границу. Регресс-тест `unpadder_never_panics_on_oversized_declared_lengths` в `donut-io`. |
| [#5737](https://github.com/XTLS/Xray-core/pull/5737) | Гонка: splice стартует до флаша последнего direct-write буфера → SSL error | **Иммунны**: downlink выставляет `downlink_spliced` **после** `write_plaintext` (флашит rustls). Покрыто боевым 3 MB POST. |
| [#5520](https://github.com/XTLS/Xray-core/pull/5520) | В raw-поток мерджится зашифрованный хвост недочитанной TLS-записи из `rawInput` | **Иммунны**: `RecordTlsServer` кормит rustls **по одной outer-TLS-записи**, остаток `inbuf` на splice — чистый сырой inner-TLS. Покрыто боевыми тестами. |
| [#6087](https://github.com/XTLS/Xray-core/pull/6087) | Утечка fd: `defer conn.Close()` на nil-conn при ошибке handshake | **Иммунны**: Rust RAII закрывает сокеты на всех error-путях. |
| [#5725](https://github.com/XTLS/Xray-core/pull/5725) | uTLS-фингерпринт ClientHello (вкл. размер post-quantum CH ~1.2–1.6 КБ, 2 TLS-записи) | Клиентская тема. Для `vision:xray`-сервера неактуально (сервер не шлёт ClientHello). Релевантно `veil`/donut-client — см. [FINGERPRINT.md](FINGERPRINT.md). |

## 2. Docker vs native

**Вывод: сервер запускать нативным бинарём под systemd, не в Docker.**

- Docker-bridge = iptables/NAT на каждый пакет + veth + `docker-proxy`:
  −5…10% throughput, +30 µs латентности на мелких RPC, ломает GSO/GRO-офлоады.
- `conntrack` трекает каждое соединение (дефолт `nf_conntrack_max=65536`) —
  на прокси с многими коннектами → `table full, dropping packet`.
- UDP/QUIC (чувствителен к потерям/реордерингу) — худший случай для bridge.
- Если Docker неизбежен: `--network=host` + `"userland-proxy": false`. Bridge
  для прокси не использовать.
- Docker у нас — **только для кросс-сборки** amd64-бинаря (`Dockerfile`), не для запуска.

## 3. Чеклист производительности (аудит tokio-кода)

- [x] **TCP_NODELAY** — сервер: raw-accept + оба upstream-коннекта; клиент:
  raw/xhttp-dial. (Vision несёт мелкие интерактивные TLS-записи — Nagle вредит.)
- [x] **Graceful half-close + закрытие fd** — RAII + `shutdown` по EOF направления.
- [x] **Splice handoff на границе записи** — переключение в raw после флаша,
  по одной TLS-записи (см. §1 #5737/#5520).
- [x] **Валидация длин** перед slice (§1 #5961).
- [x] **Full-duplex bulk-фаза** — после splice обеих сторон `copy_bidirectional`
  на сыром сокете (независимые направления, без HOL).
- [ ] **Zero-copy `splice(2)`/io_uring** для raw-фазы — отложено (низкий ROI для
  личного прокси; сейчас userspace `copy_bidirectional`, скорость уже хорошая:
  5 MB download ~0.1 c, 3 MB upload ~1 c на боевом).
- [ ] **Buffer-pool** (переиспользование `Vec` на чтение в `vision_server_splice`)
  — микро-опт, отложено.
- [ ] **Лимит max-connections** — пока нет; для личного прокси не критично.
- [ ] **VPS-тюнинг**: при росте нагрузки поднять `nf_conntrack_max`, включить
  UDP GSO/GRO (для QUIC-флоу, если вернём).

Узкие места под нагрузкой мерить через метрики Prometheus (`127.0.0.1:9090`).
