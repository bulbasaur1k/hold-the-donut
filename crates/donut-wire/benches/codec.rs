//! Baseline benchmarks for the inner-frame codec.
//!
//! Acceptance target per `docs/PLAN.md` M1: encode + decode of a
//! plain TCP+IPv4 request each under 100ns on a modern x86_64 CPU.

use bytes::BytesMut;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use donut_core::{Address, Command, Endpoint, FlowKind, UserId};
use donut_wire::Request;

fn tcp_ipv4() -> Request {
    Request {
        user: UserId::from_bytes([0x11; 16]),
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(Endpoint::new(
            Address::ipv4("1.2.3.4".parse().unwrap()),
            443,
        )),
        seed: vec![],
    }
}

fn tcp_domain_extended() -> Request {
    Request {
        user: UserId::from_bytes([0x22; 16]),
        flow: FlowKind::Extended,
        command: Command::Tcp,
        target: Some(Endpoint::new(Address::domain("example.com").unwrap(), 443)),
        seed: vec![0xaa; 8],
    }
}

fn bench_encode(c: &mut Criterion) {
    let req = tcp_ipv4();
    c.bench_function("encode_tcp_ipv4", |b| {
        let mut buf = BytesMut::with_capacity(64);
        b.iter(|| {
            buf.clear();
            black_box(&req).encode(&mut buf);
        });
    });

    let req = tcp_domain_extended();
    c.bench_function("encode_tcp_domain_extended", |b| {
        let mut buf = BytesMut::with_capacity(128);
        b.iter(|| {
            buf.clear();
            black_box(&req).encode(&mut buf);
        });
    });
}

fn bench_decode(c: &mut Criterion) {
    let frozen = {
        let mut b = BytesMut::new();
        tcp_ipv4().encode(&mut b);
        b.freeze()
    };
    c.bench_function("decode_tcp_ipv4", |b| {
        b.iter(|| {
            let mut cursor = frozen.clone();
            let _ = black_box(Request::decode(&mut cursor).unwrap());
        });
    });

    let frozen_ext = {
        let mut b = BytesMut::new();
        tcp_domain_extended().encode(&mut b);
        b.freeze()
    };
    c.bench_function("decode_tcp_domain_extended", |b| {
        b.iter(|| {
            let mut cursor = frozen_ext.clone();
            let _ = black_box(Request::decode(&mut cursor).unwrap());
        });
    });
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
