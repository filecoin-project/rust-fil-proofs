use ff::PrimeField;
use paired::bls12_381::Fr;
use sha2::{Digest, Sha256};

use crate::fr32::bytes_into_fr_repr_safe;

/// Key derivation function, based on pedersen hashing.
pub fn kdf(data: &[u8], m: usize) -> Fr {
    assert_eq!(
        data.len(),
        32 * (1 + m),
        "invalid input length: data.len(): {} m: {}",
        data.len(),
        m
    );

    let hash = Sha256::digest(data);
    Fr::from_repr(bytes_into_fr_repr_safe(hash.as_ref())).unwrap()
}

#[cfg(test)]
mod tests {
    use super::kdf;
    use ff::PrimeField;
    use paired::bls12_381::{Fr, FrRepr};

    #[test]
    fn kdf_valid_block_len() {
        let m = 1;
        let size = 32 * (1 + m);

        let data = vec![1u8; size];
        let repr = [
            9465452503567272316,
            12809138445310947895,
            11189866696922576512,
            3822187081354751937,
        ];
        let expected = Fr::from_repr(FrRepr(repr)).unwrap();

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
