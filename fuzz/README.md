# Fuzz targets

Not part of the workspace (requires `cargo-fuzz` + nightly + libfuzzer).

## Setup

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
```

## Running

From the repo root:

```sh
cargo +nightly fuzz run decode_request -- -max_total_time=60
cargo +nightly fuzz run decode_response -- -max_total_time=60
cargo +nightly fuzz run encode_roundtrip -- -max_total_time=60
```

M1 acceptance: each target runs 1,000,000 iterations with no panic.
In CI we use `-runs=1000000` instead of time-bounded runs:

```sh
cargo +nightly fuzz run decode_request -- -runs=1000000
```

## Corpus

Seed corpora live under `corpus/<target>/`. After fuzz runs, new
coverage-extending inputs are added automatically; curate interesting
cases into `corpus-min/` with `cargo fuzz cmin` before committing.
