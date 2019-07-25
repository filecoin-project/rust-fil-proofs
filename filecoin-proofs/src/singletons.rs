use ff::PrimeField;
use fil_sapling_crypto::jubjub::JubjubBls12;
use paired::bls12_381::Fr;

use storage_proofs::hasher::pedersen::PedersenDomain;

lazy_static! {
    pub static ref ENGINE_PARAMS: JubjubBls12 = JubjubBls12::new();
    pub static ref POST_VDF_KEY: PedersenDomain =
        PedersenDomain(Fr::from_str("12345").unwrap().into_repr());
}
