use ff::PrimeField;
use lazy_static::lazy_static;
use paired::bls12_381::Fr;

use storage_proofs::hasher::pedersen::PedersenDomain;

lazy_static! {
    pub static ref POST_VDF_KEY: PedersenDomain =
        PedersenDomain(Fr::from_str("12345").unwrap().into_repr());
}
