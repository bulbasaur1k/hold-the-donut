# Faithful xray REALITY server — wire spec & implementation plan

Цель: серверный транспорт, к которому подключаются **штатные xray-клиенты**
(HAPP, Shadowrocket, v2rayN) по `vless://…security=reality…flow=xtls-rprx-vision`,
с настоящим REALITY-камуфляжем (прикрытие популярным сайтом, стойкость к
active-probing). Источник истины: `github.com/XTLS/REALITY`
(`handshake_server_tls13.go`, `auth.go`) + `Xray-core/.../reality/reality.go`.

> **Почему наш `veil` НЕ подходит:** наш `veil` аутентифицирует сервер через
> in-tunnel HMAC-proof (`donut/reality/server-auth`) + donut-carrier. Настоящий
> REALITY аутентифицирует сервер **подписью временного сертификата** и гонит
> внутри **raw VLESS + Vision**. Это разные протоколы на проводе.

## 1. ClientHello → authKey (УЖЕ реализовано в donut-veil/auth.rs ✓)

Идентично нашему `veil`:
```
shared = X25519(server_realityPriv, clientHello.keyShare.X25519)
authKey = HKDF-SHA256(IKM=shared, salt=clientHello.Random[:20], info="REALITY") → 32 байта
```
SessionID несёт `AES-256-GCM(authKey)` от `version(3)|reserved(1)|ts(4)|shortId(8)`,
nonce = `Random[20:32]`, AAD = весь ClientHello с занулённым SessionID. ✓ совпадает.

Сервер (`handshake_server_tls13.go:106-129`) отдельно считает **session sharedKey**
= ECDH(server_ephemeral, client_keyShare) для ключей TLS-сессии (не authKey).
Поддержка X25519MLKEM768 (PQ) — опционально.

## 2. Server-auth: подпись временного сертификата (ЯДРО, Фаза 1)

`handshake_server_tls13.go:80-164`:

**Глобально (один раз на процесс, `init()`):**
- Генерится ed25519-кейпара `ed25519Priv` (64 байта: [0:32]=seed, [32:64]=pub).
- Строится минимальный self-signed X.509 cert (`x509.Certificate{SerialNumber:0}`),
  подписанный ed25519Priv → `signedCert` (DER). Последние 64 байта DER = ed25519-подпись.

**Per-connection (после вычисления authKey):**
```go
cert = clone(signedCert)
h := hmac.New(sha512.New, authKey)   // HMAC-SHA512, ключ = authKey
h.Write(ed25519Priv[32:])            // над 32-байтным ed25519 ПУБЛИЧНЫМ ключом
h.Sum(cert[:len(cert)-64])           // 64-байтный HMAC → ПЕРЕЗАПИСЫВАЕТ последние 64 байта DER
hs.cert = { Certificate: [cert], PrivateKey: ed25519Priv }; hs.sigAlg = Ed25519
```
То есть `cert.Signature` (последние 64 байта DER) = **HMAC-SHA512(authKey, ed25519_pub)**.

**Клиент проверяет** (`Xray-core reality.go`):
```go
h := hmac.New(sha512.New, AuthKey); h.Write(pub)   // pub = ed25519 pubkey из certs[0]
bytes.Equal(h.Sum(nil), certs[0].Signature)        // == последние 64 байта
```
Плюс обычная проверка CertificateVerify (ed25519-подпись над транскриптом ключом,
чей pub в серте) — доказывает владение ed25519Priv. Двойная проверка:
- CertVerify ⇒ сервер владеет ed25519Priv (соответствует pub в серте).
- HMAC ⇒ сервер владеет REALITY-приватником (из него выводится authKey).

ML-DSA-65 (PQ-подпись серта) — опционально, пока пропускаем.

## 3. Fallback (неуспех аутентификации)

REALITY перехватывает соединение ДО TLS: если SessionID не расшифровался /
shortId неизвестен / время вне окна → **байт-прозрачно проксирует на реальный
target** (`dest`), клиент видит честный TLS целевого сайта. У нас это есть —
`selfsteal.rs` (Verdict::Forward → relay). Для true-REALITY `dest` должен вести
на РЕАЛЬНЫЙ сайт `serverName` (не локальный decoy), чтобы прикрытие было настоящим.

## 4. Data plane

После REALITY-handshake — **raw VLESS + xtls-rprx-vision** (НЕ carrier). У нас уже
есть faithful Vision splice (`vision_xray_splice.rs`, `handle_xray_vision_session`).
Переиспользуем.

## 5. Поэтапный план реализации

| Фаза | Что | Объём/риск | Тест |
|---|---|---|---|
| **1. Cert-примитив** ✅ | `reality_cert.rs`: fixed ed25519 cert + `build_reality_certificate(authKey)` (HMAC-SHA512 в последние 64 байта) | мал / низкий | unit: подпись == HMAC, разные authKey → разные подписи |
| **2. donut-tls интеграция** | ✅ **DONE 2026-06-25** — `VeilDecision::Reality{certified_key}` + `cx.data.reality` (форк), hs.rs хендлинг, tls13.rs подмена `server_key` + skip compression; `build_reality_client_hello_hook` (donut-veil). Тест `reality_handshake_emits_reality_certificate`: handshake завершается, сервер отдаёт REALITY-серт + ed25519 CertVerify. 150 тестов workspace зелёные. | done |
| **3. Триаж + forward на реальный target** | ✅ DONE — `run_reality_proxy` использует selfsteal `triage()` ДО TLS (byte-transparent forward на `dest`), захват ClientHello в `prefix`. `RecordTlsServer::new_with_prefix` засевает его в handshake. | done |
| **4a. REALITY server path + Vision** | ✅ **DONE 2026-06-25** — `run_reality_proxy` (proxy.rs): triage → `RecordTlsServer` (reality-конфиг) → handshake → `handle_xray_vision_session` (raw VLESS + Vision). `build_reality_server_config` (donut-veil, ring-провайдер, dummy cert, ALPN h2). Транспорт `"reality"` в main.rs (cert/key НЕ нужны). E2e `reality_e2e.rs`: REALITY-клиент → handshake → VLESS → echo. 151 тест зелёный. | done |
| **4b. Chain в Vision-путь** | ✅ **DONE 2026-06-25** — `vision_server_splice`/`tls_plain_relay` дженерики по upstream (`G: AsyncRead+AsyncWrite+Unpin+Send`); `handle_xray_vision_session` диспетчит chain/freedom (Box<dyn Duplex>); `run_reality_proxy` несёт `outbounds`. E2e `reality_cascade_e2e.rs`: REALITY-вход → chain → veil-выход → echo. ✅ **fragment в Vision-freedom DONE** — `FragmentWriter` (AsyncWrite-адаптер, фрагментирует первый ClientHello в TLS-записи) оборачивает freedom-upstream в `handle_xray_vision_session` (бьёт по обоим flow=none/Extended). Tests: 2 unit + `reality_fragment_e2e.rs`. 155 тестов. | done |
| **5. Интероп с реальным xray** | ✅ **DONE 2026-06-25** — **реальный xray-core v26.3.27 (REALITY + flow=xtls-rprx-vision) успешно проксировал через наш `run_reality_proxy`** (curl→xray SOCKS→REALITY→freedom→таргет, payload прошёл). Баг найден реальным тестом и пофикшен: REALITY должен ФОРСИТЬ `sigAlg=ED25519` (uTLS chrome не предлагает ED25519 → `NoSignatureSchemesInCommon`); фикс в tls13.rs (override `sigschemes_ext` в reality-режиме). ⏭️ Осталось user-facing: `vless://…security=reality…` ссылка для импорта в HAPP. | done |

**Рабочий xray-клиент-конфиг (validated)** = `vless://<uuid>@<host>:443?security=reality&encryption=none&pbk=<X25519-pub>&sid=<short>&fp=chrome&sni=<serverName>&flow=xtls-rprx-vision&type=tcp` — этот формат HAPP импортирует.

### Фаза 2 — точный дизайн интеграции в форк (locked 2026-06-25)

Ключ: authKey считается в donut-veil (там REALITY-приватник), значит **хук строит
готовый `CertifiedKey` (REALITY-cert + ed25519 signing key) и проносит его в форк**
через `VeilDecision`. Форк cert-ген НЕ содержит → нет цикла зависимостей.

**Строительные блоки (✅ готовы + тесты, donut-veil/reality_cert.rs):**
- `build_reality_certificate(authKey)` — ed25519-cert с подписью HMAC-SHA512.
- `reality_signing_key()` — `Arc<dyn SigningKey>` ed25519 (для CertVerify; через
  `rustls::crypto::ring::sign::any_eddsa_type`).
- `reality_certified_key(authKey)` — `Arc<CertifiedKey>` (cert+key), что форк эмитит.

**Диф форка (donut-tls) — минимальный, локальный:**
1. `server/server_conn.rs`: `VeilDecision` → добавить вариант
   `Reality { certified_key: Arc<CertifiedKey> }` (Clone+Debug сохраняются — Arc+CertifiedKey их имеют).
   `ServerConnectionData` → поле `reality: Option<Arc<CertifiedKey>>`.
2. `server/hs.rs:680` (обработка hook): на `VeilDecision::Reality{ck}` →
   `cx.data.reality = Some(ck)`, дальше handshake идёт нормально (Tunnel-семантика).
3. `server/tls13.rs:380` (перед emit): если `cx.data.reality` Some →
   `server_key = ActiveCertifiedKey::from_certified_key(&ck)` (подмена cert+key) И
   **форсировать НЕ-сжатый путь** (skip `emit_compressed_certificate`, т.к. клиент
   проверяет точные байты подписи). emit_certificate/emit_certificate_verify уже
   используют `server_key.get_cert()/get_key()` — править их НЕ нужно.
4. donut-veil: `build_reality_client_hello_hook(config)` — как `build_raw_client_hello_hook`,
   но на auth-успех возвращает `VeilDecision::Reality { reality_certified_key(authKey) }`.

ServerHello/key-schedule форк делает штатно (session sharedKey ≠ authKey); xray-клиент
(uTLS) принимает любой валидный TLS 1.3 ServerHello. Править надо ТОЛЬКО cert+CertVerify.

**Риск:** деликатная правка крипто-handshake форка; ломается тихо → нужна валидация
полным handshake (Фаза 4) против faithful-mimic клиента или реального HAPP (Фаза 5).

## Источники
- REALITY server: github.com/XTLS/REALITY `handshake_server_tls13.go:80-164`, `auth.go`
- Xray client verify: github.com/XTLS/Xray-core `transport/internet/reality/reality.go`
