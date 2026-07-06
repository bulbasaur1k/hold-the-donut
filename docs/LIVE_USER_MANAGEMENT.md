# Live user management (durable, no-restart provisioning)

Devices (VLESS users) are provisioned **live** — added or removed without a
process restart or a redeploy — through the server's authenticated admin API.
The user set is durable: it survives crashes, restarts, and redeploys.

## Model

- **Source of truth:** `/etc/donut/users.json` (beside the server config), a JSON
  array of `{uuid, name, added}` records. The proxy's credential check reads a
  lock-free hot snapshot of it (`donut_core::AuthHandle`, an `ArcSwap`).
- **Durability:** every add/remove is written to disk **atomically and fsync'd
  (file + directory) _before_** the in-memory snapshot is swapped. A crash can
  only ever lose a write that never became visible to a client. On boot the file
  is reloaded verbatim.
- **Seed:** on first boot, when `users.json` is absent, it is seeded from the
  config's `inbound.users` and written out. Thereafter the **file wins** — the
  config seed (`DEVICE_UUIDS` in the deploy) is ignored, so live edits are
  authoritative across redeploys.
- **Empty is allowed:** the daemon starts with zero users (a loud warning) so a
  fresh node can be populated entirely over the API.

Implementation: `crates/donut-server/src/users.rs` (`UserStore`),
`crates/donut-core/src/id.rs` (`AuthHandle`).

## Admin API

Served on the same loopback admin listener as `/metrics` + `/healthz`
(`[metrics] listen`, default `127.0.0.1:9090`), behind the **same HTTP Basic
Auth** (`metrics.username` / `metrics.password_hash`, Argon2). Bind it to
loopback and reach it over an SSH tunnel — never expose it.

User management **requires** the auth to be configured: on an unauthenticated
endpoint the `/admin/users` routes return `403` (creating a user must take
credentials).

| Method & path | Body | Result |
|---|---|---|
| `GET /admin/users` | — | `200 {"count":N,"users":[{uuid,name,added}]}` |
| `POST /admin/users` | `{"name":"pixel-8"}` or `{"name":..,"uuid":..}` | `201 {uuid,name,added}` · `409` duplicate · `400` bad json/uuid |
| `DELETE /admin/users/<uuid>` | — | `200 {"removed":..}` · `404` unknown · `400` bad uuid |

`POST` mints a fresh v4 UUID when `uuid` is omitted. The new credential
authorises the **next** session immediately — no restart.

### curl (on the node / over the tunnel)

```sh
curl -s -u ops:<PASS> -X POST http://127.0.0.1:9090/admin/users -d '{"name":"pixel-8"}'
curl -s -u ops:<PASS>          http://127.0.0.1:9090/admin/users
curl -s -u ops:<PASS> -X DELETE http://127.0.0.1:9090/admin/users/<uuid>
```

## `donut-tools remote-user`

A thin CLI over the API. Reach the loopback endpoint with
`ssh -L 9090:127.0.0.1:9090 <server>`; pass the password via
`DONUT_ADMIN_PASSWORD` (kept out of shell history / the process list).

```sh
export DONUT_ADMIN_PASSWORD=<ops-password>

# add + print a ready HAPP import link in one step (REALITY params from cascade.yaml):
donut-tools remote-user add --name pixel-8 --link \
  --server 212.111.87.26:443 --pbk <REALITY_PUB> --sid <SHORT_ID> --sni s84.fishservices.ru

donut-tools remote-user list
donut-tools remote-user remove --uuid <UUID>
```

Flags: `--admin http://127.0.0.1:9090` (default), `--user ops` (default),
`--password` (or `DONUT_ADMIN_PASSWORD`). `add` mints the UUID server-side
unless `--uuid` is given; `--link` additionally prints the
`vless://…security=reality…flow=xtls-rprx-vision` share URI.

## Relation to the deploy

The declarative deploy (donut-deploy) still renders `inbound.users` from the
`DEVICE_UUIDS` secret, but that is now only the **first-boot seed**. Because the
server prefers `users.json`, a redeploy (which rewrites `server.json` and
restarts) does **not** wipe live-added users. To reset a node back to the
declarative baseline, delete `/etc/donut/users.json` and restart.
