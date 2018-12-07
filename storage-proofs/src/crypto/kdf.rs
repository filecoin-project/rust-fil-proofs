use pairing::bls12_381::Fr;
use pairing::Engine;
use crypto::blake2s;
use fr32::bytes_into_fr;
use pairing::bls12_381::Bls12;

/// Key derivation function, based on pedersen hashing.
pub fn kdf<E: Engine>(data: &[u8], m: usize) -> Fr {
    assert_eq!(
        data.len(),
        32 * (1 + m),
        "invalid input length: data.len(): {} m: {}",
        data.len(),
        m
    );

    let mut hash = blake2s::blake2s(&data);
    hash[31] = 0;
    bytes_into_fr::<Bls12>(&hash).unwrap()
}

#[cfg(test)]
mod tests {
    use super::kdf;
    use fr32::bytes_into_fr;
    use pairing::bls12_381::Bls12;

    #[test]
    fn kdf_valid_block_len() {
        let m = 1;
        let size = 32 * (1 + m);

        let data = vec![1u8; size];
        let expected = bytes_into_fr::<Bls12>(
            &mut vec![
                122, 242, 246, 175, 171, 132, 8, 235, 194, 175, 245, 82, 88, 212, 189, 229, 223,
                31, 184, 94, 171, 13, 127, 7, 246, 17, 141, 159, 131, 46, 6, 94,
            ]
            .as_slice(),
        )
        .unwrap();

        let res = kdf::<Bls12>(&data, m);
        assert_eq!(res, expected);
    }

    #[test]
    #[should_panic]
    fn kdf_invalid_block_len() {
        let data = vec![2u8; 1234];

        kdf::<Bls12>(&data, 44);
    }
}
