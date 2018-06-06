use ring::digest::{Context, SHA256};
use std::mem;

fn permute(num_elements: u32, index: u32, keys: &[u32]) -> u32 {
    let mut u = encode(num_elements, index, keys);

    while u >= num_elements {
        u = encode(num_elements, u, keys)
    }
    u
}

fn invert_permute(num_elements: u32, index: u32, keys: &[u32]) -> u32 {
    let mut u = decode(num_elements, index, keys);

    while u >= num_elements {
        u = decode(num_elements, u, keys);
    }
    u
}

fn encode(num_elements: u32, index: u32, keys: &[u32]) -> u32 {
    let mut next_pow4 = 4;
    let mut log4 = 1;

    while next_pow4 < num_elements {
        next_pow4 *= 4;
        log4 += 1;
    }

    let left_mask = ((1 << log4) - 1) << log4;
    let right_mask = (1 << log4) - 1;
    let half_bits = log4;

    let mut left = (index & left_mask) >> half_bits;
    let mut right = index & right_mask;

    for i in 0..4 {
        let (l, r) = (right, left ^ feistel(right, keys[i], right_mask));
        left = l;
        right = r;
    }

    (left << half_bits) | right
}

fn decode(num_elements: u32, index: u32, keys: &[u32]) -> u32 {
    let mut next_pow4 = 4;
    let mut log4 = 1;
    while next_pow4 < num_elements {
        next_pow4 *= 4;
        log4 += 1;
    }
    let left_mask = ((1 << log4) - 1) << log4;
    let right_mask = (1 << log4) - 1;
    let half_bits = log4;

    let mut left = (index & left_mask) >> half_bits;
    let mut right = index & right_mask;

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

    let r =
        (hash[0] as u32) << 24 | (hash[1] as u32) << 16 | (hash[2] as u32) << 8 | (hash[3] as u32);

    r & right_mask
}

fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut context = Context::new(&SHA256);
    context.update(data);
    context.finish().as_ref().into()
}

#[test]
fn test_feistel_multiple_of_4() {
    let n = 16;
    for i in 0..n {
        let p = encode(n, i, &[1, 2, 3, 4]);
        let v = decode(n, p, &[1, 2, 3, 4]);
        assert_eq!(i, v, "failed to permute");
        assert!(p <= n, "output number is too big");
    }
}

#[test]
fn test_feistel_on_arbitrary_set() {
    let n = 12;
    for i in 0..n {
        let p = permute(n, i, &[1, 2, 3, 4]);
        let v = invert_permute(n, p, &[1, 2, 3, 4]);
        assert_eq!(i, v, "failed to permute");
        assert!(p <= n, "output number is too big");
    }
}
