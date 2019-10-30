#![feature(test)]

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

extern crate test;

#[bench]
fn blake2s_16_benchmark(b: &mut ::test::Bencher) {
    let mut rng: SmallRng = SeedableRng::seed_from_u64(1);

    let rep: [u8; 32] = rng.gen();
    let node: [u8; 32] = rng.gen();
    let p0: [u8; 32] = rng.gen();
    let p1: [u8; 32] = rng.gen();
    let p2: [u8; 32] = rng.gen();
    let p3: [u8; 32] = rng.gen();
    let p4: [u8; 32] = rng.gen();
    let p5: [u8; 32] = rng.gen();
    let p6: [u8; 32] = rng.gen();
    let p7: [u8; 32] = rng.gen();
    let p8: [u8; 32] = rng.gen();
    let p9: [u8; 32] = rng.gen();
    let p10: [u8; 32] = rng.gen();
    let p11: [u8; 32] = rng.gen();
    let p12: [u8; 32] = rng.gen();
    let p13: [u8; 32] = rng.gen();

    let parents: [&[u8]; 16] = [
        &rep, &node, &p0, &p1, &p2, &p3, &p4, &p5, &p6, &p7, &p8, &p9, &p10, &p11, &p12, &p13,
    ];

    b.bytes = 16 * 32;
    b.iter(|| fil_blake2s::hash_nodes_16(&parents));
}

#[bench]
fn blake2s_8_benchmark(b: &mut ::test::Bencher) {
    let mut rng: SmallRng = SeedableRng::seed_from_u64(1);

    let rep: [u8; 32] = rng.gen();
    let node: [u8; 32] = rng.gen();
    let p0: [u8; 32] = rng.gen();
    let p1: [u8; 32] = rng.gen();
    let p2: [u8; 32] = rng.gen();
    let p3: [u8; 32] = rng.gen();
    let p4: [u8; 32] = rng.gen();
    let p5: [u8; 32] = rng.gen();

    let parents: [&[u8]; 8] = [&rep, &node, &p0, &p1, &p2, &p3, &p4, &p5];

    b.bytes = 8 * 32;
    b.iter(|| fil_blake2s::hash_nodes_8(&parents));
}
