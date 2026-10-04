//! dnsbox vs hickory-proto vs domain: parse + full iteration and building,
//! for a typical query, a large response and a pathological
//! compression-heavy response. See `BENCH.md` at the repository root for
//! results and how to run.

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use dnsbox_bench::{dnsbox_impl, domain_impl, fixtures, hickory_impl};

fn parse(c: &mut Criterion) {
    for f in fixtures() {
        // Every library parses the same bytes: the message as dnsbox
        // builds it (byte-identical to what a compressing server sends).
        let mut buf = vec![0u8; 65535];
        let n = dnsbox_impl::build(&dnsbox_impl::prepare(&f), &mut buf);
        let wire = buf[..n].to_vec();
        let mut g = c.benchmark_group(format!("parse/{}", f.id));
        g.throughput(Throughput::Bytes(wire.len() as u64));
        g.bench_function("dnsbox", |b| {
            b.iter(|| dnsbox_impl::parse(black_box(&wire)))
        });
        g.bench_function("dnsbox-validate", |b| {
            b.iter(|| dnsbox_impl::validate(black_box(&wire)))
        });
        g.bench_function("hickory-proto", |b| {
            b.iter(|| hickory_impl::parse(black_box(&wire)))
        });
        g.bench_function("domain", |b| {
            b.iter(|| domain_impl::parse(black_box(&wire)))
        });
        g.finish();
    }
}

fn build(c: &mut Criterion) {
    for f in fixtures() {
        let ours = dnsbox_impl::prepare(&f);
        let hickory = hickory_impl::prepare(&f);
        let domain = domain_impl::prepare(&f);
        let mut g = c.benchmark_group(format!("build/{}", f.id));
        let mut buf = vec![0u8; 65535];
        g.bench_function("dnsbox", |b| {
            b.iter(|| dnsbox_impl::build(black_box(&ours), &mut buf))
        });
        g.bench_function("dnsbox-vec", |b| {
            b.iter(|| dnsbox_impl::build_vec(black_box(&ours)))
        });
        g.bench_function("hickory-proto", |b| {
            b.iter(|| hickory_impl::build(black_box(&hickory)))
        });
        g.bench_function("domain", |b| {
            b.iter(|| domain_impl::build(black_box(&domain)))
        });
        g.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = parse, build
}
criterion_main!(benches);
