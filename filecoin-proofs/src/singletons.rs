use ff::PrimeField;
use fil_sapling_crypto::jubjub::JubjubBls12;
use paired::bls12_381::Fr;
use slog::Logger;

use logging_toolkit::make_logger;
use storage_proofs::hasher::pedersen::PedersenDomain;

lazy_static! {
    pub static ref ENGINE_PARAMS: JubjubBls12 = JubjubBls12::new();
}

lazy_static! {
    pub static ref POST_VDF_KEY: PedersenDomain =
        PedersenDomain(Fr::from_str("12345").unwrap().into_repr());
}

lazy_static! {
    pub static ref FCP_LOG: Logger = make_logger("filecoin-proofs");
}
