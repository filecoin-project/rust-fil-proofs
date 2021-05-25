use std::collections::HashSet;
use std::convert::TryInto;
use std::mem::size_of;

use blake2b_simd::blake2b;

pub const FEISTEL_ROUNDS: usize = 3;
// 3 rounds is an acceptable value for a pseudo-random permutation,
// see https://github.com/filecoin-project/rust-proofs/issues/425
// (and also https://en.wikipedia.org/wiki/Feistel_cipher#Theoretical_work).

pub type Index = u64;

pub type FeistelPrecomputed = (Index, Index, Index);

// Find the minimum number of even bits to represent `num_elements`
// within a `u32` maximum. Returns the left and right masks evenly
// distributed that together add up to that minimum number of bits.
pub fn precompute(num_elements: Index) -> FeistelPrecomputed {
    let mut next_pow4: Index = 4;
    let mut log4 = 1;
    while next_pow4 < num_elements {
        next_pow4 *= 4;
        log4 += 1;
    }

    let left_mask = ((1 << log4) - 1) << log4;
    let right_mask = (1 << log4) - 1;
    let half_bits = log4;

    (left_mask, right_mask, half_bits)
}

// Pseudo-randomly shuffle an input from a starting position to another
// one within the `[0, num_elements)` range using a `key` that will allow
// the reverse operation to take place.
pub fn permute(
    num_elements: Index,
    index: Index,
    keys: &[Index],
    precomputed: FeistelPrecomputed,
) -> Index {
    let mut u = encode(index, keys, precomputed);

    while u >= num_elements {
        u = encode(u, keys, precomputed)
    }
    // Since we are representing `num_elements` using an even number of bits,
    // that can encode many values above it, so keep repeating the operation
    // until we land in the permitted range.

    u
}

/// Permutes 8 elements at once.
pub fn permute8(
    num_elements: Index,
    indicies: [Index; 8],
    keys: &[Index],
    precomputed: FeistelPrecomputed,
) -> [Index; 8] {
    let mut out = [0; 8];
    let indicies0: [Index; 4] = indicies[..4].try_into().unwrap();
    let indicies1: [Index; 4] = indicies[4..].try_into().unwrap();

    let us0 = encode4(indicies0, keys, precomputed);
    let us1 = encode4(indicies1, keys, precomputed);

    out[..4].copy_from_slice(&us0);
    out[4..].copy_from_slice(&us1);

    let mut missing = HashSet::<usize>::with_capacity(8);
    for (i, el) in out.iter().enumerate() {
        if *el >= num_elements {
            missing.insert(i);
        }
    }

    while !missing.is_empty() {
        let missing_v: Vec<_> = missing.iter().copied().collect();
        for chunk4 in missing_v.chunks(4) {
            if chunk4.len() == 4 {
                let tmp = encode4(
                    [
                        out[chunk4[0]],
                        out[chunk4[1]],
                        out[chunk4[2]],
                        out[chunk4[3]],
                    ],
                    keys,
                    precomputed,
                );

                out[chunk4[0]] = tmp[0];
                out[chunk4[1]] = tmp[1];
                out[chunk4[2]] = tmp[2];
                out[chunk4[3]] = tmp[3];

                for i in chunk4 {
                    if out[*i] < num_elements {
                        missing.remove(i);
                    }
                }
            } else {
                let chunk4 = chunk4.to_vec();
                for chunk2 in chunk4.chunks(2) {
                    if chunk2.len() == 2 {
                        let tmp = encode2([out[chunk2[0]], out[chunk2[1]]], keys, precomputed);

                        out[chunk2[0]] = tmp[0];
                        out[chunk2[1]] = tmp[1];

                        for i in chunk2 {
                            if out[*i] < num_elements {
                                missing.remove(i);
                            }
                        }
                    } else {
                        let i = chunk2[0];
                        out[i] = encode(out[i], keys, precomputed);
                        if out[i] < num_elements {
                            missing.remove(&i);
                        }
                    }
                }
            }
        }
    }

    out
}

// Inverts the `permute` result to its starting value for the same `key`.
pub fn invert_permute(
    num_elements: Index,
    index: Index,
    keys: &[Index],
    precomputed: FeistelPrecomputed,
) -> Index {
    let mut u = decode(index, keys, precomputed);

    while u >= num_elements {
        u = decode(u, keys, precomputed);
    }
    u
}

/// common_setup performs common calculations on inputs shared by encode and decode.
/// Decompress the `precomputed` part of the algorithm into the initial `left` and
/// `right` pieces `(L_0, R_0)` with the `right_mask` and `half_bits` to manipulate
/// them.
fn common_setup(index: Index, precomputed: FeistelPrecomputed) -> (Index, Index, Index, Index) {
    let (left_mask, right_mask, half_bits) = precomputed;

    let left = (index & left_mask) >> half_bits;
    let right = index & right_mask;

    (left, right, right_mask, half_bits)
}

fn encode(index: Index, keys: &[Index], precomputed: FeistelPrecomputed) -> Index {
    let (mut left, mut right, right_mask, half_bits) = common_setup(index, precomputed);

    for key in keys.iter().take(FEISTEL_ROUNDS) {
        let (l, r) = (right, left ^ feistel(right, *key, right_mask));
        left = l;
        right = r;
    }

    (left << half_bits) | right
}

fn encode2(indicies: [Index; 2], keys: &[Index], precomputed: FeistelPrecomputed) -> [Index; 2] {
    let (left_mask, right_mask, half_bits) = precomputed;

    // common setup
    let mut left0 = (indicies[0] & left_mask) >> half_bits;
    let mut right0 = indicies[0] & right_mask;

    let mut left1 = (indicies[1] & left_mask) >> half_bits;
    let mut right1 = indicies[1] & right_mask;

    for key in keys.iter().take(FEISTEL_ROUNDS) {
        let rs = feistel2([right0, right1], *key, right_mask);

        {
            let (l, r) = (right0, left0 ^ rs[0]);
            left0 = l;
            right0 = r;
        }

        {
            let (l, r) = (right1, left1 ^ rs[1]);
            left1 = l;
            right1 = r;
        }
    }

    [(left0 << half_bits) | right0, (left1 << half_bits) | right1]
}

fn encode4(indicies: [Index; 4], keys: &[Index], precomputed: FeistelPrecomputed) -> [Index; 4] {
    let (left_mask, right_mask, half_bits) = precomputed;

    // common setup
    let mut left0 = (indicies[0] & left_mask) >> half_bits;
    let mut right0 = indicies[0] & right_mask;

    let mut left1 = (indicies[1] & left_mask) >> half_bits;
    let mut right1 = indicies[1] & right_mask;

    let mut left2 = (indicies[2] & left_mask) >> half_bits;
    let mut right2 = indicies[2] & right_mask;

    let mut left3 = (indicies[3] & left_mask) >> half_bits;
    let mut right3 = indicies[3] & right_mask;

    for key in keys.iter().take(FEISTEL_ROUNDS) {
        let rs = feistel4([right0, right1, right2, right3], *key, right_mask);

        {
            let (l, r) = (right0, left0 ^ rs[0]);
            left0 = l;
            right0 = r;
        }

        {
            let (l, r) = (right1, left1 ^ rs[1]);
            left1 = l;
            right1 = r;
        }

        {
            let (l, r) = (right2, left2 ^ rs[2]);
            left2 = l;
            right2 = r;
        }

        {
            let (l, r) = (right3, left3 ^ rs[3]);
            left3 = l;
            right3 = r;
        }
    }

    [
        (left0 << half_bits) | right0,
        (left1 << half_bits) | right1,
        (left2 << half_bits) | right2,
        (left3 << half_bits) | right3,
    ]
}

fn decode(index: Index, keys: &[Index], precomputed: FeistelPrecomputed) -> Index {
    let (mut left, mut right, right_mask, half_bits) = common_setup(index, precomputed);

    for i in (0..FEISTEL_ROUNDS).rev() {
        let (l, r) = ((right ^ feistel(left, keys[i], right_mask)), left);
        left = l;
        right = r;
    }

    (left << half_bits) | right
}

const HALF_FEISTEL_BYTES: usize = size_of::<Index>();
const FEISTEL_BYTES: usize = 2 * HALF_FEISTEL_BYTES;

// Round function of the Feistel network: `F(Ri, Ki)`. Joins the `right`
// piece and the `key`, hashes it and returns the lower `u32` part of
// the hash filtered trough the `right_mask`.
fn feistel(right: Index, key: Index, right_mask: Index) -> Index {
    let mut data: [u8; FEISTEL_BYTES] = [0; FEISTEL_BYTES];

    // So ugly, but the price of (relative) speed.
    let r = if FEISTEL_BYTES <= 8 {
        data[0] = (right >> 24) as u8;
        data[1] = (right >> 16) as u8;
        data[2] = (right >> 8) as u8;
        data[3] = right as u8;

        data[4] = (key >> 24) as u8;
        data[5] = (key >> 16) as u8;
        data[6] = (key >> 8) as u8;
        data[7] = key as u8;

        let raw = blake2b(&data);
        let hash = raw.as_bytes();

        Index::from(hash[0]) << 24
            | Index::from(hash[1]) << 16
            | Index::from(hash[2]) << 8
            | Index::from(hash[3])
    } else {
        data[0] = (right >> 56) as u8;
        data[1] = (right >> 48) as u8;
        data[2] = (right >> 40) as u8;
        data[3] = (right >> 32) as u8;
        data[4] = (right >> 24) as u8;
        data[5] = (right >> 16) as u8;
        data[6] = (right >> 8) as u8;
        data[7] = right as u8;

        data[8] = (key >> 56) as u8;
        data[9] = (key >> 48) as u8;
        data[10] = (key >> 40) as u8;
        data[11] = (key >> 32) as u8;
        data[12] = (key >> 24) as u8;
        data[13] = (key >> 16) as u8;
        data[14] = (key >> 8) as u8;
        data[15] = key as u8;

        let raw = blake2b(&data);
        let hash = raw.as_bytes();

        Index::from(hash[0]) << 56
            | Index::from(hash[1]) << 48
            | Index::from(hash[2]) << 40
            | Index::from(hash[3]) << 32
            | Index::from(hash[4]) << 24
            | Index::from(hash[5]) << 16
            | Index::from(hash[6]) << 8
            | Index::from(hash[7])
    };

    r & right_mask
}

#[inline(always)]
fn prepare_data(data: &mut [u8; FEISTEL_BYTES], right: Index, key: Index) {
    if FEISTEL_BYTES <= 8 {
        data[0] = (right >> 24) as u8;
        data[1] = (right >> 16) as u8;
        data[2] = (right >> 8) as u8;
        data[3] = right as u8;

        data[4] = (key >> 24) as u8;
        data[5] = (key >> 16) as u8;
        data[6] = (key >> 8) as u8;
        data[7] = key as u8;
    } else {
        data[0] = (right >> 56) as u8;
        data[1] = (right >> 48) as u8;
        data[2] = (right >> 40) as u8;
        data[3] = (right >> 32) as u8;
        data[4] = (right >> 24) as u8;
        data[5] = (right >> 16) as u8;
        data[6] = (right >> 8) as u8;
        data[7] = right as u8;

        data[8] = (key >> 56) as u8;
        data[9] = (key >> 48) as u8;
        data[10] = (key >> 40) as u8;
        data[11] = (key >> 32) as u8;
        data[12] = (key >> 24) as u8;
        data[13] = (key >> 16) as u8;
        data[14] = (key >> 8) as u8;
        data[15] = key as u8;
    }
}

#[inline(always)]
fn convert_index(hash: &[u8]) -> Index {
    if FEISTEL_BYTES <= 8 {
        Index::from(hash[0]) << 24
            | Index::from(hash[1]) << 16
            | Index::from(hash[2]) << 8
            | Index::from(hash[3])
    } else {
        Index::from(hash[0]) << 56
            | Index::from(hash[1]) << 48
            | Index::from(hash[2]) << 40
            | Index::from(hash[3]) << 32
            | Index::from(hash[4]) << 24
            | Index::from(hash[5]) << 16
            | Index::from(hash[6]) << 8
            | Index::from(hash[7])
    }
}

/// Does the same as feistel but on 2 values at once
fn feistel2(rights: [Index; 2], key: Index, right_mask: Index) -> [Index; 2] {
    use blake2b_simd::{
        many::{hash_many, HashManyJob},
        Params,
    };

    let mut data0 = [0; FEISTEL_BYTES];
    let mut data1 = [0; FEISTEL_BYTES];

    prepare_data(&mut data0, rights[0], key);
    prepare_data(&mut data1, rights[1], key);

    let params = Params::default();
    let mut jobs = [
        HashManyJob::new(&params, &data0),
        HashManyJob::new(&params, &data1),
    ];
    hash_many(jobs.iter_mut());

    [
        convert_index(jobs[0].to_hash().as_bytes()) & right_mask,
        convert_index(jobs[1].to_hash().as_bytes()) & right_mask,
    ]
}

/// Does the same as feistel but on 4 values at once
fn feistel4(rights: [Index; 4], key: Index, right_mask: Index) -> [Index; 4] {
    use blake2b_simd::{
        many::{hash_many, HashManyJob},
        Params,
    };

    let mut data0 = [0; FEISTEL_BYTES];
    let mut data1 = [0; FEISTEL_BYTES];
    let mut data2 = [0; FEISTEL_BYTES];
    let mut data3 = [0; FEISTEL_BYTES];

    prepare_data(&mut data0, rights[0], key);
    prepare_data(&mut data1, rights[1], key);
    prepare_data(&mut data2, rights[2], key);
    prepare_data(&mut data3, rights[3], key);

    let params = Params::default();
    let mut jobs = [
        HashManyJob::new(&params, &data0),
        HashManyJob::new(&params, &data1),
        HashManyJob::new(&params, &data2),
        HashManyJob::new(&params, &data3),
    ];
    hash_many(jobs.iter_mut());

    [
        convert_index(jobs[0].to_hash().as_bytes()) & right_mask,
        convert_index(jobs[1].to_hash().as_bytes()) & right_mask,
        convert_index(jobs[2].to_hash().as_bytes()) & right_mask,
        convert_index(jobs[3].to_hash().as_bytes()) & right_mask,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    use rayon::prelude::{IntoParallelIterator, ParallelIterator};

    // Some sample n-values which are not powers of four and also don't coincidentally happen to
    // encode/decode correctly.
    const BAD_NS: &[Index] = &[5, 6, 8, 12, 17]; //
                                                 //
    fn encode_decode(n: Index, expect_success: bool) {
        let mut failed = false;
        let precomputed = precompute(n);
        for i in 0..n {
            let p = encode(i, &[1, 2, 3, 4], precomputed);
            let v = decode(p, &[1, 2, 3, 4], precomputed);
            let equal = i == v;
            let in_range = p < n;
            if expect_success {
                assert!(equal, "failed to permute (n = {})", n);
                assert!(in_range, "output number is too big (n = {})", n);
            } else if !equal || !in_range {
                failed = true;
            }
        }
        if !expect_success {
            assert!(failed, "expected failure (n = {})", n);
        }
    }

    #[test]
    fn test_feistel_power_of_4() {
        // Our implementation is guaranteed to produce a permutation when input size (number of elements)
        // is a power of our.
        let mut n = 1;

        // Powers of 4 always succeed.
        for _ in 0..4 {
            n *= 4;
            encode_decode(n, true);
        }

        // Some non-power-of 4 also succeed, but here is a selection of examples values showing
        // that this is not guaranteed.
        for i in BAD_NS.iter() {
            encode_decode(*i, false);
        }
    }

    #[test]
    fn test_feistel_on_arbitrary_set() {
        for n in BAD_NS.iter() {
            let precomputed = precompute(*n as Index);
            for i in 0..*n {
                let p = permute(*n, i, &[1, 2, 3, 4], precomputed);
                let v = invert_permute(*n, p, &[1, 2, 3, 4], precomputed);
                // Since every element in the set is reversibly mapped to another element also in the set,
                // this is indeed a permutation.
                assert_eq!(i, v, "failed to permute");
                assert!(p < *n, "output number is too big");
            }
        }
    }

    #[test]
    #[ignore]
    fn test_feistel_valid_permutation() {
        let n = (1u64 << 30) as Index;
        let mut flags = vec![false; n as usize];
        let precomputed = precompute(n);
        let perm: Vec<Index> = (0..n)
            .into_par_iter()
            .map(|i| permute(n, i, &[1, 2, 3, 4], precomputed))
            .collect();
        for i in perm {
            assert!(i < n, "output number is too big");
            flags[i as usize] = true;
        }
        assert!(flags.iter().all(|f| *f), "output isn't a permutation");
    }
}
