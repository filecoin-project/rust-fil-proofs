use ff::PrimeField;
use fil_sapling_crypto::jubjub::JubjubBls12;
use paired::bls12_381::Fr;

use storage_proofs::hasher::pedersen::PedersenDomain;
use storage_proofs::settings;

lazy_static! {
    pub static ref ENGINE_PARAMS: JubjubBls12 = JubjubBls12::new_with_window_size(
        settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size
    );
    pub static ref POST_VDF_KEY: PedersenDomain =
        PedersenDomain(Fr::from_str("12345").unwrap().into_repr());
}
