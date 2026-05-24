# Документация hold-the-donut

Справочник + учебные материалы по проекту (минимальный Rust-рерайт подмножества
xray-core: VLESS + REALITY + XHTTP + QUIC/HTTP-3). Пишем сюда всё, что изучаем —
технологии, спеки, схемы — чтобы расти как сетевые инженеры.

## С чего начать (порядок чтения для новичка)

1. [**TECHNOLOGIES.md**](TECHNOLOGIES.md) — весь сетевой стек снизу вверх (TCP/UDP
   → крипто → TLS 1.3 → QUIC → HTTP/1.1/2/3 → SOCKS5/DNS/geo → VLESS/REALITY/XHTTP/Vision).
   Как работает каждая технология и зачем она нам.
2. [**SCENARIOS.md**](SCENARIOS.md) — три боевых сценария (Reality / XHTTP / QUIC-H3)
   и **как каждый маскируется**: что видит пассивный DPI и активный зонд.
3. [**REALITY-SELFSTEAL.md**](REALITY-SELFSTEAL.md) — глубокий разбор REALITY и
   Self-Steal: механика метки, развилка tunnel/forward, подложка, чек-лист
   устойчивости к зондированию.
4. [**CRATES.md**](CRATES.md) — карта воркспейса: как работает каждый крейт, что
   в нём искать, статус.

## Референс

- [**PROTOCOLS.md**](PROTOCOLS.md) — байт-точные спеки (VLESS §1, REALITY §2,
  XHTTP §3, Vision §4). Ground-truth, сверяется с xray-core при ежемесячном diff.
- [**ANALYSIS.md**](ANALYSIS.md) — технический анализ: что оставляем/выкидываем,
  выбор крейтов, форки, архитектура, риски.
- [**PLAN.md**](PLAN.md) — milestones M0..M10, целевые сценарии, Self-Steal-стратегия,
  риск-реестр, статус.

## Карта «технология → где читать»

| Тема | Учебно | Байт-спека | Код |
|---|---|---|---|
| TCP/UDP/IP, TLS 1.3, QUIC, HTTP/x, крипто | TECHNOLOGIES.md | — | — |
| VLESS | TECHNOLOGIES.md §8 | PROTOCOLS.md §1 | `donut-wire` |
| REALITY / Self-Steal | REALITY-SELFSTEAL.md | PROTOCOLS.md §2 | `donut-veil`, `donut-server/selfsteal.rs` |
| XHTTP | TECHNOLOGIES.md §6,§8 | PROTOCOLS.md §3 | `donut-carrier`, `donut-quic` |
| Vision | TECHNOLOGIES.md §8 | PROTOCOLS.md §4 | `donut-wire` (M5.5) |
| Сценарии/маскировка | SCENARIOS.md | — | — |
| Крейты/архитектура | CRATES.md | — | ANALYSIS.md §5 |

> Правило проекта: изучил технологию — оставь артефакт здесь, понятно и со
> ссылками на исходники (xray-core / RFC). Документ важнее, чем ответ в чате.
</content>
