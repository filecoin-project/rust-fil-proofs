use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{ensure, Result};
use bellperson::groth16;
use lazy_static::lazy_static;
use log::info;
use paired::bls12_381::Bls12;
use storage_proofs_core::compound_proof::CompoundProof;
use storage_proofs_core::proof::ProofScheme;
use storage_proofs_porep::stacked::{self, LayerChallenges, StackedCompound, StackedDrg};
use storage_proofs_post::fallback;

use crate::{
    constants::{DRG_DEGREE, EXP_DEGREE, LAYERS, POREP_MINIMUM_CHALLENGES},
    types::{
        DefaultPieceHasher, MerkleTreeTrait, PaddedBytesAmount, PoRepConfig, PoRepProofPartitions,
        PoStConfig, PoStType,
    },
};

type Bls12GrothParams = groth16::MappedParameters<Bls12>;
pub type Bls12VerifyingKey = groth16::VerifyingKey<Bls12>;

type Cache<G> = HashMap<String, Arc<G>>;
type GrothMemCache = Cache<Bls12GrothParams>;
type VerifyingKeyMemCache = Cache<Bls12VerifyingKey>;

type WinningPostSetupParams = fallback::SetupParams;
pub type WinningPostPublicParams = fallback::PublicParams;

type WindowPostSetupParams = fallback::SetupParams;
pub type WindowPostPublicParams = fallback::PublicParams;

lazy_static! {
    static ref GROTH_PARAM_MEMORY_CACHE: Mutex<GrothMemCache> = Default::default();
    static ref VERIFYING_KEY_MEMORY_CACHE: Mutex<VerifyingKeyMemCache> = Default::default();
}

pub fn public_params<Tree: 'static + MerkleTreeTrait>(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
    porep_id: [u8; 32],
) -> Result<stacked::PublicParams<Tree>> {
    StackedDrg::<Tree, DefaultPieceHasher>::setup(&setup_params(
        sector_bytes,
        partitions,
        porep_id,
    )?)
}

pub fn winning_post_public_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<WinningPostPublicParams> {
    fallback::FallbackPoSt::<Tree>::setup(&winning_post_setup_params(&post_config)?)
}

pub fn winning_post_setup_params(post_config: &PoStConfig) -> Result<WinningPostSetupParams> {
    ensure!(
        post_config.challenge_count % post_config.sector_count == 0,
        "sector count must divide challenge count"
    );

    let param_sector_count = post_config.challenge_count / post_config.sector_count;
    let param_challenge_count = post_config.challenge_count / param_sector_count;

    ensure!(
        param_sector_count * param_challenge_count == post_config.challenge_count,
        "invald parameters calculated {} * {} != {}",
        param_sector_count,
        param_challenge_count,
        post_config.challenge_count
    );

    Ok(fallback::SetupParams {
        sector_size: post_config.padded_sector_size().into(),
        challenge_count: param_challenge_count,
        sector_count: param_sector_count,
    })
}

pub fn window_post_public_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<WindowPostPublicParams> {
    fallback::FallbackPoSt::<Tree>::setup(&window_post_setup_params(&post_config))
}

pub fn window_post_setup_params(post_config: &PoStConfig) -> WindowPostSetupParams {
    fallback::SetupParams {
        sector_size: post_config.padded_sector_size().into(),
        challenge_count: post_config.challenge_count,
        sector_count: post_config.sector_count,
    }
}

pub fn setup_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
    porep_id: [u8; 32],
) -> Result<stacked::SetupParams> {
    let layer_challenges = select_challenges(
        partitions,
        *POREP_MINIMUM_CHALLENGES
            .read()
            .expect("POREP_MINIMUM_CHALLENGES poisoned")
            .get(&u64::from(sector_bytes))
            .expect("unknown sector size") as usize,
        *LAYERS
            .read()
            .expect("LAYERS poisoned")
            .get(&u64::from(sector_bytes))
            .expect("unknown sector size"),
    )?;
    let sector_bytes = u64::from(sector_bytes);

    ensure!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );

    let nodes = (sector_bytes / 32) as usize;
    let degree = DRG_DEGREE;
    let expansion_degree = EXP_DEGREE;

    Ok(stacked::SetupParams {
        nodes,
        degree,
        expansion_degree,
        porep_id,
        layer_challenges,
    })
}

fn select_challenges(
    partitions: usize,
    minimum_total_challenges: usize,
    layers: usize,
) -> Result<LayerChallenges> {
    let mut count = 1;
    let mut guess = LayerChallenges::new(layers, count);
    while partitions * guess.challenges_count_all() < minimum_total_challenges {
        count += 1;
        guess = LayerChallenges::new(layers, count);
    }
    Ok(guess)
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::{DefaultOctLCTree, PoRepProofPartitions, PoStType, SectorSize};

    #[test]
    fn partition_layer_challenges_test() {
        let f = |partitions| {
            select_challenges(partitions, 12, 11)
                .expect("never fails")
                .challenges_count_all()
        };
        // Update to ensure all supported PoRepProofPartitions options are represented here.
        assert_eq!(6, f(usize::from(PoRepProofPartitions(2))));

        assert_eq!(12, f(1));
        assert_eq!(6, f(2));
        assert_eq!(3, f(4));
    }

    #[test]
    fn test_winning_post_params() {
        let config = PoStConfig {
            typ: PoStType::Winning,
            priority: false,
            challenge_count: 66,
            sector_count: 1,
            sector_size: SectorSize::KiB2,
        };

        let params =
            winning_post_public_params::<DefaultOctLCTree>(&config).expect("failed to get params");
        assert_eq!(params.sector_count, 66);
        assert_eq!(params.challenge_count, 1);
        assert_eq!(params.sector_size, 2048);
    }
}
