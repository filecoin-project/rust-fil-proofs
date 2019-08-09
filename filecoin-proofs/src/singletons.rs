use std::str::FromStr;

use algebra::fields::bls12_381::Fr;
use algebra::fields::PrimeField;
use storage_proofs::hasher::pedersen::PedersenDomain;

lazy_static! {
    pub static ref POST_VDF_KEY: PedersenDomain =
        PedersenDomain(Fr::from_str("12345").unwrap().into_repr());
}
