use blake2::{Blake2s, Digest};

pub const FEISTEL_ROUNDS: usize = 3;
pub type FeistelPrecomputed = (u32, u32, u32);

pub fn precompute(num_elements: u32) -> FeistelPrecomputed {
    let mut next_pow4 = 4;
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

pub fn permute(
    num_elements: u32,
    index: u32,
    keys: &[u32],
    precomputed: FeistelPrecomputed,
) -> u32 {
    let mut u = encode(index, keys, precomputed);

    while u >= num_elements {
        u = encode(u, keys, precomputed)
    }
    u
}

pub fn invert_permute(
    num_elements: u32,
    index: u32,
    keys: &[u32],
    precomputed: FeistelPrecomputed,
) -> u32 {
    let mut u = decode(index, keys, precomputed);

    while u >= num_elements {
        u = decode(u, keys, precomputed);
    }
    u
}

/// common_setup performs common calculations on inputs shared by encode and decode.
fn common_setup(index: u32, precomputed: FeistelPrecomputed) -> (u32, u32, u32, u32) {
    let (left_mask, right_mask, half_bits) = precomputed;

    let left = (index & left_mask) >> half_bits;
    let right = index & right_mask;

    (left, right, right_mask, half_bits)
}

fn encode(index: u32, keys: &[u32], precomputed: FeistelPrecomputed) -> u32 {
    let (mut left, mut right, right_mask, half_bits) = common_setup(index, precomputed);

    for key in keys.iter().take(FEISTEL_ROUNDS) {
        let (l, r) = (right, left ^ feistel(right, *key, right_mask));
        left = l;
        right = r;
    }

    (left << half_bits) | right
}

fn decode(index: u32, keys: &[u32], precomputed: FeistelPrecomputed) -> u32 {
    let (mut left, mut right, right_mask, half_bits) = common_setup(index, precomputed);

    for i in (0..FEISTEL_ROUNDS).rev() {
        let (l, r) = ((right ^ feistel(left, keys[i], right_mask)), left);
        left = l;
        right = r;
    }

    (left << half_bits) | right
}

fn feistel(right: u32, key: u32, right_mask: u32) -> u32 {
    let mut data: [u8; 8] = [0; 8];
    data[0] = (right >> 24) as u8;
    data[1] = (right >> 16) as u8;
    data[2] = (right >> 8) as u8;
    data[3] = right as u8;

    data[4] = (key >> 24) as u8;
    data[5] = (key >> 16) as u8;
    data[6] = (key >> 8) as u8;
    data[7] = key as u8;

    let hash = Blake2s::digest(&data);

    let r = u32::from(hash[0]) << 24
        | u32::from(hash[1]) << 16
        | u32::from(hash[2]) << 8
        | u32::from(hash[3]);

    r & right_mask
}

#[cfg(test)]
mod tests {
    use super::*;

    // Some sample n-values which are not powers of four and also don't coincidentally happen to
    // encode/decode correctly.
    const BAD_NS: &[u32] = &[5, 6, 8, 12, 17];

    fn encode_decode(n: u32, expect_success: bool) {
        let mut failed = false;
        let precomputed = precompute(n);
        for i in 0..n {
            let p = encode(i, &[1, 2, 3, 4], precomputed);
            let v = decode(p, &[1, 2, 3, 4], precomputed);
            let equal = i == v;
            let in_range = p <= n;
            if expect_success {
                assert!(equal, "failed to permute (n = {})", n);
                assert!(in_range, "output number is too big (n = {})", n);
            } else {
                if !equal || !in_range {
                    failed = true;
                }
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
            let precomputed = precompute(*n as u32);
            for i in 0..*n {
                let p = permute(*n, i, &[1, 2, 3, 4], precomputed);
                let v = invert_permute(*n, p, &[1, 2, 3, 4], precomputed);
                // Since every element in the set is reversibly mapped to another element also in the set,
                // this is indeed a permutation.
                assert_eq!(i, v, "failed to permute");
                assert!(p <= *n, "output number is too big");
            }
        }
    }
}
