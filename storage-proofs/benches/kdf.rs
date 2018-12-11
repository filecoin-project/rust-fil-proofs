#[macro_use]
extern crate criterion;
extern crate blake2;
extern crate blake2b_simd;
extern crate rand;
extern crate storage_proofs;

use std::hash::Hasher as StdHasher;

use blake2::digest::{Input, VariableOutput};
use blake2::{Digest, VarBlake2b};
use blake2b_simd::{blake2b, Params, State};
use criterion::{black_box, Criterion, ParameterizedBenchmark, Throughput};
use rand::{thread_rng, Rng};
use storage_proofs::hasher::*;
use storage_proofs::util::data_at_node_offset;
use storage_proofs::vde;

fn kdf(c: &mut Criterion) {
    let params: Vec<_> = vec![5];

    c.bench(
        "create_key",
        ParameterizedBenchmark::new(
            "actual",
            |b, m| {
                let mut rng = thread_rng();
                let id: <PedersenHasher as Hasher>::Domain = rng.gen();
                let node = 2;
                let parents: Vec<usize> = (0..*m).map(|_| rng.gen_range(0, *m)).collect();
                let data: Vec<u8> = (0..m * 32).map(|_| rng.gen()).collect();
                let node_size = 32;

                let mut to_hash = vec![0u8; 32 * (m + 1)];
                id.write_bytes(&mut to_hash[..32]).unwrap();

                b.iter(|| {
                    black_box(vde::create_key::<PedersenHasher>(
                        &mut to_hash,
                        node,
                        &parents,
                        &data,
                        node_size,
                        *m,
                    ));
                })
            },
            params,
        )
        .with_function("blake2b-64", |b, m| {
            let mut rng = thread_rng();
            let id: <Blake2bHasher as Hasher>::Domain = rng.gen();
            let node = 2;
            let parents: Vec<usize> = (0..*m).map(|_| rng.gen_range(0, *m)).collect();
            let data: Vec<u8> = (0..m * 32).map(|_| rng.gen()).collect();
            let node_size = 32;

            let mut to_hash = vec![0u8; 32 * (m + 1)];
            id.write_bytes(&mut to_hash[..32]).unwrap();

            b.iter(|| {
                black_box(vde::create_key::<Blake2bHasher>(
                    &mut to_hash,
                    node,
                    &parents,
                    &data,
                    node_size,
                    *m,
                ));
            })
        })
        .with_function("blake2b-simd-64", move |b, m| {
            let mut rng = thread_rng();
            let id: <Blake2bHasher as Hasher>::Domain = rng.gen();
            let node = 2;
            let parents: Vec<usize> = (0..*m).map(|_| rng.gen_range(0, *m)).collect();
            let data: Vec<u8> = (0..m * 32).map(|_| rng.gen()).collect();
            let node_size = 32;

            b.iter(|| {
                let mut hasher = State::new();
                hasher.update(id.as_ref());

                for parent in &parents {
                    let offset = data_at_node_offset(*parent, node_size);
                    hasher.update(&data[offset..offset + node_size]);
                }

                black_box(hasher.finalize())
            })
        })
        .with_function("blake2b-simd-32", move |b, m| {
            let mut rng = thread_rng();
            let id: <Blake2bHasher as Hasher>::Domain = rng.gen();
            let node = 2;
            let parents: Vec<usize> = (0..*m).map(|_| rng.gen_range(0, *m)).collect();
            let data: Vec<u8> = (0..m * 32).map(|_| rng.gen()).collect();
            let node_size = 32;

            b.iter(|| {
                let mut hasher = Params::new().hash_length(32).to_state();
                hasher.update(id.as_ref());

                for parent in &parents {
                    let offset = data_at_node_offset(*parent, node_size);
                    hasher.update(&data[offset..offset + node_size]);
                }

                black_box(hasher.finalize())
            })
        })
        .with_function("blake2b-simd-32-together", move |b, m| {
            let mut rng = thread_rng();
            let id: <Blake2bHasher as Hasher>::Domain = rng.gen();
            let node = 2;
            let parents: Vec<usize> = (0..*m).map(|_| rng.gen_range(0, *m)).collect();
            let data: Vec<u8> = (0..m * 32).map(|_| rng.gen()).collect();
            let node_size = 32;

            b.iter(|| {
                let mut hasher = Params::new().hash_length(32).to_state();

                let mut to_hash = vec![0u8; 32 * (m + 1)];
                to_hash[..32].copy_from_slice(id.as_ref());
                for (i, parent) in parents.iter().enumerate() {
                    let offset = data_at_node_offset(*parent, node_size);
                    let start = (i + 1) * 32;
                    let end = (i + 2) * 32;
                    to_hash[start..end].copy_from_slice(&data[offset..offset + node_size]);
                }

                black_box(hasher.update(&to_hash).finalize())
            })
        })
        .with_function("blake2b-simd-32-outside", move |b, m| {
            let mut rng = thread_rng();
            let id: <Blake2bHasher as Hasher>::Domain = rng.gen();
            let node = 2;
            let parents: Vec<usize> = (0..*m).map(|_| rng.gen_range(0, *m)).collect();
            let data: Vec<u8> = (0..m * 32).map(|_| rng.gen()).collect();
            let node_size = 32;

            let mut to_hash = vec![0u8; 32 * (m + 1)];
            to_hash[..32].copy_from_slice(id.as_ref());

            let p = Params::new()
                .hash_length(32)
                .inner_hash_length(32)
                .to_state();

            b.iter(|| {
                for (i, parent) in parents.iter().enumerate() {
                    let offset = data_at_node_offset(*parent, node_size);
                    let start = (i + 1) * 32;
                    let end = start + 32;
                    to_hash[start..end].copy_from_slice(&data[offset..offset + node_size]);
                }

                black_box(p.clone().update(&to_hash).finalize())
            })
        })
        .with_function("blake2b-32", move |b, m| {
            let mut rng = thread_rng();
            let id: <Blake2bHasher as Hasher>::Domain = rng.gen();
            let node = 2;
            let parents: Vec<usize> = (0..*m).map(|_| rng.gen_range(0, *m)).collect();
            let data: Vec<u8> = (0..m * 32).map(|_| rng.gen()).collect();
            let node_size = 32;

            b.iter(|| {
                let mut hasher = VarBlake2b::new_keyed(b"", 32);
                hasher.input(id.as_ref());

                for parent in &parents {
                    let offset = data_at_node_offset(*parent, node_size);
                    hasher.input(&data[offset..offset + node_size]);
                }

                black_box(hasher.vec_result())
            })
        })
        .throughput(|m| Throughput::Bytes(32 * (m + 1) as u32)),
    );
}

criterion_group!(benches, kdf);
criterion_main!(benches);
