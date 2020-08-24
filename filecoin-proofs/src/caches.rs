use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::Result;
use bellperson::groth16;
use lazy_static::lazy_static;
use log::info;
use paired::bls12_381::Bls12;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::porep::stacked::{StackedCompound, StackedDrg};
use storage_proofs::post::fallback;

use crate::constants::DefaultPieceHasher;
use crate::parameters::{public_params, window_post_public_params, winning_post_public_params};
use crate::types::*;

type Bls12GrothParams = groth16::MappedParameters<Bls12>;
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
) -> Result<Arc<G>>
where
    F: FnOnce() -> Result<G>,
    G: Send + Sync,
{
    info!("trying parameters memory cache for: {}", &identifier);
    {
        let cache = (*cache_ref).lock().expect("poisoned cache");

        if let Some(entry) = cache.get(&identifier) {
            info!("found params in memory cache for {}", &identifier);
            return Ok(entry.clone());
        }
    }

    info!("no params in memory cache for {}", &identifier);

    let new_entry = Arc::new(generator()?);
    let res = new_entry.clone();
    {
        let cache = &mut (*cache_ref).lock().expect("poisoned cache");
        cache.insert(identifier, new_entry);
    }

    Ok(res)
}

#[inline]
pub fn lookup_groth_params<F>(identifier: String, generator: F) -> Result<Arc<Bls12GrothParams>>
where
    F: FnOnce() -> Result<Bls12GrothParams>,
{
    cache_lookup(&*GROTH_PARAM_MEMORY_CACHE, identifier, generator)
}

#[inline]
pub fn lookup_verifying_key<F>(identifier: String, generator: F) -> Result<Arc<Bls12VerifyingKey>>
where
    F: FnOnce() -> Result<Bls12VerifyingKey>,
{
    let vk_identifier = format!("{}-verifying-key", &identifier);
    cache_lookup(&*VERIFYING_KEY_MEMORY_CACHE, vk_identifier, generator)
}

pub fn get_stacked_params<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
) -> Result<Arc<Bls12GrothParams>> {
    let public_params = public_params::<Tree>(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
    )?;

    let parameters_generator = || {
        <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<Tree, DefaultPieceHasher>,
            _,
        >>::groth_params::<rand::rngs::OsRng>(None, &public_params)
        .map_err(Into::into)
    };

    Ok(lookup_groth_params(
        format!(
            "STACKED[{}]",
            usize::from(PaddedBytesAmount::from(porep_config))
        ),
        parameters_generator,
    )?)
}

pub fn get_post_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<Arc<Bls12GrothParams>> {
    match post_config.typ {
        PoStType::Winning => {
            let post_public_params = winning_post_public_params::<Tree>(post_config)?;

            let parameters_generator = || {
                <fallback::FallbackPoStCompound<Tree> as CompoundProof<
                    fallback::FallbackPoSt<Tree>,
                    fallback::FallbackPoStCircuit<Tree>,
                >>::groth_params::<rand::rngs::OsRng>(None, &post_public_params)
                .map_err(Into::into)
            };

            Ok(lookup_groth_params(
                format!(
                    "WINNING_POST[{}]",
                    usize::from(post_config.padded_sector_size())
                ),
                parameters_generator,
            )?)
        }
        PoStType::Window => {
            let post_public_params = window_post_public_params::<Tree>(post_config)?;

            let parameters_generator = || {
                <fallback::FallbackPoStCompound<Tree> as CompoundProof<
                    fallback::FallbackPoSt<Tree>,
                    fallback::FallbackPoStCircuit<Tree>,
                >>::groth_params::<rand::rngs::OsRng>(None, &post_public_params)
                .map_err(Into::into)
            };

            Ok(lookup_groth_params(
                format!(
                    "Window_POST[{}]",
                    usize::from(post_config.padded_sector_size())
                ),
                parameters_generator,
            )?)
        }
    }
}

pub fn get_stacked_verifying_key<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
) -> Result<Arc<Bls12VerifyingKey>> {
    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
    )?;

    let vk_generator = || {
        <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<Tree, DefaultPieceHasher>,
            _,
        >>::verifying_key::<rand::rngs::OsRng>(None, &public_params)
        .map_err(Into::into)
    };

    Ok(lookup_verifying_key(
        format!(
            "STACKED[{}]",
            usize::from(PaddedBytesAmount::from(porep_config))
        ),
        vk_generator,
    )?)
}

pub fn get_post_verifying_key<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<Arc<Bls12VerifyingKey>> {
    match post_config.typ {
        PoStType::Winning => {
            let post_public_params = winning_post_public_params::<Tree>(post_config)?;

            let vk_generator = || {
                <fallback::FallbackPoStCompound<Tree> as CompoundProof<
                    fallback::FallbackPoSt<Tree>,
                    fallback::FallbackPoStCircuit<Tree>,
                >>::verifying_key::<rand::rngs::OsRng>(None, &post_public_params)
                .map_err(Into::into)
            };

            Ok(lookup_verifying_key(
                format!(
                    "WINNING_POST[{}]",
                    usize::from(post_config.padded_sector_size())
                ),
                vk_generator,
            )?)
        }
        PoStType::Window => {
            let post_public_params = window_post_public_params::<Tree>(post_config)?;

            let vk_generator = || {
                <fallback::FallbackPoStCompound<Tree> as CompoundProof<
                    fallback::FallbackPoSt<Tree>,
                    fallback::FallbackPoStCircuit<Tree>,
                >>::verifying_key::<rand::rngs::OsRng>(None, &post_public_params)
                .map_err(Into::into)
            };

            Ok(lookup_verifying_key(
                format!(
                    "WINDOW_POST[{}]",
                    usize::from(post_config.padded_sector_size())
                ),
                vk_generator,
            )?)
        }
    }
}
