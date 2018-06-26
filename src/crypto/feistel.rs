use ring::digest::{Context, SHA256};

pub fn permute(num_elements: u32, index: u32, keys: &[u32]) -> u32 {
    let mut u = encode(num_elements, index, keys);

    while u >= num_elements {
        u = encode(num_elements, u, keys)
    }
    u
}

pub fn invert_permute(num_elements: u32, index: u32, keys: &[u32]) -> u32 {
    let mut u = decode(num_elements, index, keys);

    while u >= num_elements {
        u = decode(num_elements, u, keys);
    }
    u
}

fn common_setup(num_elements: u32, index: u32) -> (u32, u32, u32, u32) {
    let mut next_pow4 = 4;
    let mut log4 = 1;

    while next_pow4 < num_elements {
        next_pow4 *= 4;
        log4 += 1;
    }

    let left_mask = ((1 << log4) - 1) << log4;
    let right_mask = (1 << log4) - 1;
    let half_bits = log4;

    let left = (index & left_mask) >> half_bits;
    let right = index & right_mask;

    (left, right, right_mask, half_bits)
}

fn encode(num_elements: u32, index: u32, keys: &[u32]) -> u32 {
    let (mut left, mut right, right_mask, half_bits) = common_setup(num_elements, index);

    for key in keys.iter().take(4) {
        let (l, r) = (right, left ^ feistel(right, *key, right_mask));
        left = l;
        right = r;
    }

    (left << half_bits) | right
}

fn decode(num_elements: u32, index: u32, keys: &[u32]) -> u32 {
    let (mut left, mut right, right_mask, half_bits) = common_setup(num_elements, index);

    for i in (0..4).rev() {
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

    let hash = sha256_digest(&data);

    let r = u32::from(hash[0]) << 24
        | u32::from(hash[1]) << 16
        | u32::from(hash[2]) << 8
        | u32::from(hash[3]);

    r & right_mask
}

fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut context = Context::new(&SHA256);
    context.update(data);
    context.finish().as_ref().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Some sample n-values which are not powers of four and also don't coincidentally happen to
    // encode/decode correctly.
    const BAD_NS: &[u32] = &[5, 6, 8, 12, 17];

    fn encode_decode(n: u32, expect_success: bool) {
        let mut failed = false;
        for i in 0..n {
            let p = encode(n, i, &[1, 2, 3, 4]);
            let v = decode(n, p, &[1, 2, 3, 4]);
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
            for i in 0..*n {
                let p = permute(*n, i, &[1, 2, 3, 4]);
                let v = invert_permute(*n, p, &[1, 2, 3, 4]);
                // Since every element in the set is reversibly mapped to another element also in the set,
                // this is indeed a permutation.
                assert_eq!(i, v, "failed to permute");
                assert!(p <= *n, "output number is too big");
            }
        }
    }
}
