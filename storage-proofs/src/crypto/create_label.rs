use anyhow::Result;
use ff::PrimeField;
use paired::bls12_381::Fr;
use sha2::{Digest, Sha256};

use crate::fr32::bytes_into_fr_repr_safe;

/// Key derivation function, based on pedersen hashing.
pub fn create_label(data: &[u8], _m: usize) -> Result<Fr> {
    let hash = Sha256::digest(data);
    Ok(Fr::from_repr(bytes_into_fr_repr_safe(hash.as_ref()))?)
}

#[cfg(test)]
mod tests {
    use super::create_label;
    use ff::PrimeField;
    use paired::bls12_381::{Fr, FrRepr};

    #[test]
    fn create_label_valid_block_len() {
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

        let res = create_label(&data, m).unwrap();
        assert_eq!(res, expected);
    }
}
