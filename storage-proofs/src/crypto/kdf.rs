use blake2s_simd::Params as Blake2s;

use algebra::fields::bls12_377::Fr;
use algebra::PrimeField;

use crate::fr32::bytes_into_fr_repr_safe;

/// Key derivation function, based on Pedersen hashing.
pub fn kdf(data: &[u8], m: usize) -> Fr {
    assert_eq!(
        data.len(),
        32 * (1 + m),
        "invalid input length: data.len(): {} m: {}",
        data.len(),
        m
    );

    let hash = Blake2s::new()
        .hash_length(32)
        .to_state()
        .update(data)
        .finalize();

    Fr::from_repr(bytes_into_fr_repr_safe(hash.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_valid_block_len() {
        let m = 1;
        let size = 32 * (1 + m);

        let data = vec![1u8; size];
        let expected = Fr::from_repr(bytes_into_fr_repr_safe(
            &mut vec![
                220, 60, 76, 126, 119, 247, 67, 162, 98, 94, 119, 28, 247, 18, 71, 208, 167, 72,
                33, 85, 59, 56, 96, 13, 9, 67, 49, 109, 95, 246, 152, 63,
            ]
            .as_slice(),
        ));

        let res = kdf(&data, m);
        assert_eq!(res, expected);
    }

    #[test]
    #[should_panic]
    fn kdf_invalid_block_len() {
        let data = vec![2u8; 1234];

        kdf(&data, 44);
    }
}
