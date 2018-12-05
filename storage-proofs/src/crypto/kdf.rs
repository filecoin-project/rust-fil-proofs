use crypto::pedersen::pedersen_compression_simple;
use pairing::bls12_381::Fr;
use pairing::Engine;

/// Key derivation function, based on pedersen hashing.
pub fn kdf<E: Engine>(data: &[u8], m: usize) -> Fr {
    assert_eq!(
        data.len(),
        32 * (1 + m),
        "invalid input length: data.len(): {} m: {}",
        data.len(),
        m
    );

    pedersen_compression_simple(data)
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
                254, 137, 34, 17, 163, 239, 240, 72, 109, 88, 46, 29, 35, 197, 15, 118, 73, 156,
                153, 235, 25, 3, 221, 211, 182, 205, 113, 12, 175, 17, 65, 9,
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
