use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use algebra::curves::bls12_377::Bls12_377 as Bls12;
use snark::groth16;

use storage_proofs::circuit::vdf_post::VDFPoStCircuit;
use storage_proofs::circuit::vdf_post::VDFPostCompound;
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::hasher::PedersenHasher;
use storage_proofs::vdf_post::VDFPoSt;
use storage_proofs::vdf_sloth::Sloth;

use crate::error;
use crate::parameters::{post_public_params, public_params};
use crate::types::*;

type Bls12GrothParams = groth16::Parameters<Bls12>;
pub type Bls12VerifyingKey = groth16::VerifyingKey<Bls12>;

type Cache<G> = HashMap<String, Arc<G>>;
type GrothMemCache = Cache<Bls12GrothParams>;
type VerifyingKeyMemCache = Cache<Bls12VerifyingKey>;

lazy_static! {
    static ref GROTH_PARAM_MEMORY_CACHE: Mutex<GrothMemCache> = Default::default();
    static ref VERIFYING_KEY_MEMORY_CACHE: Mutex<VerifyingKeyMemCache> = Default::default();
}

pub fn cache_lookup<F, G>(
    cache_ref: &Mutex<Cache<G>>,
    identifier: String,
    generator: F,
) -> error::Result<Arc<G>>
where
    F: FnOnce() -> error::Result<G>,
    G: Send + Sync,
{
    info!("trying parameters memory cache for: {}", &identifier);
    {
        let cache = (*cache_ref).lock().unwrap();

        if let Some(entry) = cache.get(&identifier) {
            info!("found params in memory cache for {}", &identifier);
            return Ok(entry.clone());
        }
    }

    info!("no params in memory cache for {}", &identifier);

    let new_entry = Arc::new(generator()?);
    let res = new_entry.clone();
    {
        let cache = &mut (*cache_ref).lock().unwrap();
        cache.insert(identifier, new_entry);
    }

    Ok(res)
}

#[inline]
pub fn lookup_groth_params<F>(
    identifier: String,
    generator: F,
) -> error::Result<Arc<Bls12GrothParams>>
where
    F: FnOnce() -> error::Result<Bls12GrothParams>,
{
    cache_lookup(&*GROTH_PARAM_MEMORY_CACHE, identifier, generator)
}

#[inline]
pub fn lookup_verifying_key<F>(
    identifier: String,
    generator: F,
) -> error::Result<Arc<Bls12VerifyingKey>>
where
    F: FnOnce() -> error::Result<Bls12VerifyingKey>,
{
    let vk_identifier = format!("{}-verifying-key", &identifier);
    cache_lookup(&*VERIFYING_KEY_MEMORY_CACHE, vk_identifier, generator)
}

pub fn get_zigzag_params(
    porep_config: PoRepConfig,
) -> error::Result<Arc<groth16::Parameters<Bls12>>> {
    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
    );

    let parameters_generator = || ZigZagCompound::groth_params(&public_params).map_err(Into::into);

    Ok(lookup_groth_params(
        format!(
            "ZIGZAG[{}]",
            usize::from(PaddedBytesAmount::from(porep_config))
        ),
        parameters_generator,
    )?)
}

pub fn get_post_params(post_config: PoStConfig) -> error::Result<Arc<groth16::Parameters<Bls12>>> {
    let post_public_params = post_public_params(post_config);

    let parameters_generator = || {
        <VDFPostCompound as CompoundProof<
            VDFPoSt<PedersenHasher, Sloth>,
            VDFPoStCircuit,
        >>::groth_params(&post_public_params)
        .map_err(Into::into)
    };

    Ok(lookup_groth_params(
        format!(
            "POST[{}]",
            usize::from(PaddedBytesAmount::from(post_config))
        ),
        parameters_generator,
    )?)
}

pub fn get_zigzag_verifying_key(
    porep_config: PoRepConfig,
) -> error::Result<Arc<Bls12VerifyingKey>> {
    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
    );

    let vk_generator = || ZigZagCompound::verifying_key(&public_params).map_err(Into::into);

    Ok(lookup_verifying_key(
        format!(
            "ZIGZAG[{}]",
            usize::from(PaddedBytesAmount::from(porep_config))
        ),
        vk_generator,
    )?)
}

pub fn get_post_verifying_key(post_config: PoStConfig) -> error::Result<Arc<Bls12VerifyingKey>> {
    let post_public_params = post_public_params(post_config);

    let vk_generator = || {
        <VDFPostCompound as CompoundProof<
            VDFPoSt<PedersenHasher, Sloth>,
            VDFPoStCircuit,
        >>::verifying_key(&post_public_params)
        .map_err(Into::into)
    };

    Ok(lookup_verifying_key(
        format!(
            "POST[{}]",
            usize::from(PaddedBytesAmount::from(post_config))
        ),
        vk_generator,
    )?)
}
