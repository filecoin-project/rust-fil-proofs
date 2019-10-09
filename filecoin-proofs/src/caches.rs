use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use bellperson::groth16;
use paired::bls12_381::Bls12;

use storage_proofs::circuit::rational_post::RationalPoStCircuit;
use storage_proofs::circuit::rational_post::RationalPoStCompound;
use storage_proofs::circuit::stacked::StackedCompound;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::hasher::PedersenHasher;
use storage_proofs::rational_post::RationalPoSt;

use crate::error;
use crate::parameters::{post_public_params, public_params};
use crate::singletons::ENGINE_PARAMS;
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

pub fn get_stacked_params(
    porep_config: PoRepConfig,
) -> error::Result<Arc<groth16::Parameters<Bls12>>> {
    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
    );

    let parameters_generator =
        || StackedCompound::groth_params(&public_params, &ENGINE_PARAMS).map_err(Into::into);

    Ok(lookup_groth_params(
        format!(
            "STACKED[{}]",
            usize::from(PaddedBytesAmount::from(porep_config))
        ),
        parameters_generator,
    )?)
}

pub fn get_post_params(post_config: PoStConfig) -> error::Result<Arc<groth16::Parameters<Bls12>>> {
    let post_public_params = post_public_params(post_config);

    let parameters_generator = || {
        <RationalPoStCompound<PedersenHasher> as CompoundProof<
            Bls12,
            RationalPoSt<PedersenHasher>,
            RationalPoStCircuit<Bls12, PedersenHasher>,
        >>::groth_params(&post_public_params, &ENGINE_PARAMS)
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

pub fn get_stacked_verifying_key(
    porep_config: PoRepConfig,
) -> error::Result<Arc<Bls12VerifyingKey>> {
    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
    );

    let vk_generator =
        || StackedCompound::verifying_key(&public_params, &ENGINE_PARAMS).map_err(Into::into);

    Ok(lookup_verifying_key(
        format!(
            "STACKED[{}]",
            usize::from(PaddedBytesAmount::from(porep_config))
        ),
        vk_generator,
    )?)
}

pub fn get_post_verifying_key(post_config: PoStConfig) -> error::Result<Arc<Bls12VerifyingKey>> {
    let post_public_params = post_public_params(post_config);

    let vk_generator = || {
        <RationalPoStCompound<PedersenHasher> as CompoundProof<
            Bls12,
            RationalPoSt<PedersenHasher>,
            RationalPoStCircuit<Bls12, PedersenHasher>,
        >>::verifying_key(&post_public_params, &ENGINE_PARAMS)
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
