use crypto::pedersen::pedersen_md_no_padding;

/// Key derivation function, based on pedersen hashing.
pub fn kdf(data: &[u8], m: usize) -> Vec<u8> {
    assert_eq!(
        data.len(),
        32 * (1 + m),
        "invalid input length: data.len(): {} m: {}",
        data.len(),
        m
    );

    pedersen_md_no_padding(data)
}

#[cfg(test)]
mod tests {
    use super::kdf;

    #[test]
    fn kdf_valid_block_len() {
        let m = 1;
        let size = 32 * (1 + m);

        let data = vec![1u8; size];
        let expected = vec![
            122, 242, 246, 175, 171, 132, 8, 235, 194, 175, 245, 82, 88, 212, 189, 229, 223, 31,
            184, 94, 171, 13, 127, 7, 246, 17, 141, 159, 131, 46, 6, 94,
        ];

        let res = kdf(&data, m);
        assert_eq!(res.len(), 32);
        assert_eq!(res, expected);
    }

    #[test]
    #[should_panic]
    fn kdf_invalid_block_len() {
        let data = vec![2u8; 1234];

        kdf(&data, 44);
    }
}
