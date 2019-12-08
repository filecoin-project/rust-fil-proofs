use anyhow::{Context, Result};
use paired::bls12_381::Bls12;
use paired::Engine;
use storage_proofs::fr32::{bytes_into_fr, fr_into_bytes};
use storage_proofs::hasher::Domain;

use crate::types::Commitment;

pub(crate) fn as_safe_commitment<H: Domain, T: AsRef<str>>(
    comm: &Commitment,
    commitment_name: T,
) -> Result<H> {
    bytes_into_fr::<Bls12>(comm)
        .map(Into::into)
        .with_context(|| format!("Invalid commitment ({})", commitment_name.as_ref(),))
}

pub(crate) fn commitment_from_fr<E: Engine>(fr: E::Fr) -> Commitment {
    let mut commitment = [0; 32];
    for (i, b) in fr_into_bytes::<E>(&fr).iter().enumerate() {
        commitment[i] = *b;
    }
    commitment
}
