# Документация hold-the-donut

Справочные материалы по проекту: минимальный Rust-рерайт подмножества xray-core
(VLESS + REALITY + XHTTP + QUIC/HTTP-3). Здесь собраны разборы технологий,
спецификации протоколов и схемы.

## С чего начать

1. [TECHNOLOGIES.md](TECHNOLOGIES.md) — сетевой стек снизу вверх (TCP/UDP →
   крипто → TLS 1.3 → QUIC → HTTP/1.1/2/3 → SOCKS5/DNS/geo →
   VLESS/REALITY/XHTTP/Vision): как работает каждая технология и зачем она нужна.
2. [SCENARIOS.md](SCENARIOS.md) — три рабочих сценария (Reality / XHTTP / QUIC-H3)
   и как каждый маскируется: что видит пассивный DPI и активный зонд.
3. [REALITY-SELFSTEAL.md](REALITY-SELFSTEAL.md) — разбор REALITY и Self-Steal:
   механика метки, развилка tunnel/forward, подложка, чек-лист устойчивости к
   зондированию.
4. [CRATES.md](CRATES.md) — карта воркспейса: как устроен каждый крейт, что в нём
   искать, статус.

## Референс

- [PROTOCOLS.md](PROTOCOLS.md) — байт-точные спеки (VLESS §1, REALITY §2,
  XHTTP §3, Vision §4). Сверяется с xray-core при ежемесячном diff.
- [FINGERPRINT.md](FINGERPRINT.md) — TLS-фингерпринт ClientHello (uTLS-style):
  что такое JA3 и режим `randomized`, что реализовано и какие ограничения.
- [ANALYSIS.md](ANALYSIS.md) — технический анализ: что оставляем и что выкидываем,
  выбор крейтов, форки, архитектура, риски.
- [PLAN.md](PLAN.md) — этапы M0..M10, целевые сценарии, стратегия Self-Steal,
  риск-реестр, статус.

## Карта «технология → где читать»

| Тема | Учебно | Байт-спека | Код |
|---|---|---|---|
| TCP/UDP/IP, TLS 1.3, QUIC, HTTP/x, крипто | TECHNOLOGIES.md | — | — |
| VLESS | TECHNOLOGIES.md §8 | PROTOCOLS.md §1 | `donut-wire` |
| REALITY / Self-Steal | REALITY-SELFSTEAL.md | PROTOCOLS.md §2 | `donut-veil`, `donut-server/selfsteal.rs` |
| TLS-фингерпринт (uTLS) | FINGERPRINT.md | — | `donut-veil/fingerprint.rs` |
| XHTTP | TECHNOLOGIES.md §6,§8 | PROTOCOLS.md §3 | `donut-carrier`, `donut-quic` |
| Vision | TECHNOLOGIES.md §8 | PROTOCOLS.md §4 | `donut-wire` (M5.5) |
| Сценарии/маскировка | SCENARIOS.md | — | — |
| Крейты/архитектура | CRATES.md | — | ANALYSIS.md §5 |

Изучили технологию — оставьте здесь краткий артефакт с понятным описанием и
ссылками на исходники (xray-core / RFC).
