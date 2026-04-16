# rustls-reality — forked `rustls` for veiled-TLS hooks

## What this is

A vendored copy of upstream [rustls](https://github.com/rustls/rustls)
at tag `v/0.23.38` (commit `6b116bc`), trimmed to the main library
crate only (no `tests/`, `benches/`, `examples/`, `ci-bench/`, etc.).

The outer workspace at the repo root rewires every `rustls = "0.23"`
dependency through this fork via:

```toml
[patch.crates-io]
rustls = { path = "forks/rustls-reality/rustls" }
```

## Status

* **Baseline committed**: yes — compiles unmodified against the pinned
  workspace.
* **Patches applied**: none yet. `PATCH_POINTS.md` lists the planned
  modifications.

## Why vendor instead of git submodule

A submodule would require an external host repo. Vendoring keeps the
fork self-contained in this repo, and the diff against the clean
tag is reviewable as a normal PR. When upstream rustls publishes a
new 0.23.x patch release, the maintenance process is:

1. `cd ../references/rustls && git fetch --tags origin && git checkout v/0.23.<new>`
2. Copy `rustls/` over (preserving our added files).
3. Re-apply the documented patches.
4. Bump the version pin here.

## Maintenance

See `PATCH_POINTS.md` for the list of patches, their motivation, and
their exact locations.

## License

Upstream rustls is tri-licensed `Apache-2.0 OR ISC OR MIT`. The fork
keeps the original license files unchanged.
