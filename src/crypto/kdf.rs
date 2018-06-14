use crypto::blake2s::blake2s;

/// Key derivation function, based on blake2s.
pub fn kdf(data: &[u8]) -> Vec<u8> {
    blake2s(data)
}

#[cfg(test)]
mod tests {
    use super::kdf;

    #[test]
    fn test_kdf() {
        // Test vector from BLAKE2 testvectors
        let data = hex!("00010203");
        let expected = hex!("0cc70e00348b86ba2944d0c32038b25c55584f90df2304f55fa332af5fb01e20");

        assert_eq!(kdf(&data), expected);
    }
}
