pub const MASK_EVEN_32: u32 = 0x55555555;

/// Negates the even bits in a spread bit-array.
pub fn negate_spread<const LEN: usize>(arr: [bool; LEN]) -> [bool; LEN] {
    assert_eq!(LEN % 2, 0);

    let mut neg = arr;
    for even_idx in (0..LEN).step_by(2) {
        let odd_idx = even_idx + 1;
        assert!(!arr[odd_idx]);

        neg[even_idx] = !arr[even_idx];
    }

    neg
}

/// Returns even bits in a bit-array
pub fn even_bits<const LEN: usize, const HALF: usize>(bits: [bool; LEN]) -> [bool; HALF] {
    assert_eq!(LEN % 2, 0);
    let mut even_bits = [false; HALF];
    for idx in 0..HALF {
        even_bits[idx] = bits[idx * 2]
    }
    even_bits
}

/// Returns odd bits in a bit-array
pub fn odd_bits<const LEN: usize, const HALF: usize>(bits: [bool; LEN]) -> [bool; HALF] {
    assert_eq!(LEN % 2, 0);
    let mut odd_bits = [false; HALF];
    for idx in 0..HALF {
        odd_bits[idx] = bits[idx * 2 + 1]
    }
    odd_bits
}

/// Helper function to transpose an Option<Vec<F>> to a Vec<Option<F>>.
/// The length of the vector must be `len`.
pub fn transpose_option_vec<T: Clone>(vec: Option<Vec<T>>, len: usize) -> Vec<Option<T>> {
    if let Some(vec) = vec {
        vec.into_iter().map(Some).collect()
    } else {
        vec![None; len]
    }
}

/// Given a vector of words as vec![(lo: u16, hi: u16)], returns their sum: u32, along
/// with a carry bit.
pub fn sum_with_carry(words: Vec<(Option<u16>, Option<u16>)>) -> (Option<u32>, Option<u64>) {
    let words_lo: Option<Vec<u64>> = words.iter().map(|(lo, _)| lo.map(|lo| lo as u64)).collect();
    let words_hi: Option<Vec<u64>> = words.iter().map(|(_, hi)| hi.map(|hi| hi as u64)).collect();

    let sum: Option<u64> = {
        let sum_lo: Option<u64> = words_lo.map(|vec| vec.iter().sum());
        let sum_hi: Option<u64> = words_hi.map(|vec| vec.iter().sum());
        sum_lo.zip(sum_hi).map(|(lo, hi)| lo + (1 << 16) * hi)
    };

    let carry = sum.map(|sum| (sum >> 32) as u64);
    let sum = sum.map(|sum| sum as u32);

    (sum, carry)
}
