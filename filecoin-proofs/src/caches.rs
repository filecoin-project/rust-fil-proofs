use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use bellperson::groth16::{self, prepare_verifying_key};
use blstrs::Bls12;
use lazy_static::lazy_static;
use log::{info, trace};
use once_cell::sync::OnceCell;
use rand::rngs::OsRng;
use storage_proofs_core::{compound_proof::CompoundProof, merkle::MerkleTreeTrait};
use storage_proofs_porep::stacked::{StackedCompound, StackedDrg};
use storage_proofs_post::fallback::{FallbackPoSt, FallbackPoStCircuit, FallbackPoStCompound};

use crate::{
    constants::{DefaultPieceHasher, PUBLISHED_SECTOR_SIZES},
    parameters::{public_params, window_post_public_params, winning_post_public_params},
    types::{PaddedBytesAmount, PoRepConfig, PoRepProofPartitions, PoStConfig, PoStType},
};

type Bls12GrothParams = groth16::MappedParameters<Bls12>;
pub type Bls12PreparedVerifyingKey = groth16::PreparedVerifyingKey<Bls12>;
type Bls12ProverSRSKey = groth16::aggregate::ProverSRS<Bls12>;
type Bls12VerifierSRSKey = groth16::aggregate::VerifierSRS<Bls12>;

type Cache<G> = HashMap<String, Arc<G>>;
type GrothMemCache = Cache<Bls12GrothParams>;
type VerifyingKeyMemCache = Cache<Bls12PreparedVerifyingKey>;

const FIP0013_MIN_SNARKS: usize = 64;
const FIP0013_MAX_SNARKS: usize = 8192;

// Note that proofs testing will use values under and over the FIP13
// min and max, respectively.
const PROOFS_TESTS_MIN_SNARKS: usize = FIP0013_MIN_SNARKS >> 5;
const PROOFS_TESTS_MAX_SNARKS: usize = FIP0013_MAX_SNARKS << 1;

const SRS_IDENTIFIER: &str = "srs-key";
const SRS_VERIFIER_IDENTIFIER: &str = "srs-verifying-key";

lazy_static! {
    static ref GROTH_PARAM_MEMORY_CACHE: Mutex<GrothMemCache> = Default::default();
    static ref VERIFYING_KEY_MEMORY_CACHE: Mutex<VerifyingKeyMemCache> = Default::default();
    static ref SRS_KEY_MEMORY_CACHE: SRSCache<Bls12ProverSRSKey> =
        SRSCache::with_defaults(SRS_IDENTIFIER);
    static ref SRS_VERIFIER_KEY_MEMORY_CACHE: SRSCache<Bls12VerifierSRSKey> =
        SRSCache::with_defaults(SRS_VERIFIER_IDENTIFIER);
}

/// We have a separate SRSCache type for srs keys since they are
/// cached differently (as a hashmap per type, keyed by identifier
/// consisting of sector size and pow2 num proofs to aggregate).
#[derive(Debug, Default)]
pub struct SRSCache<G> {
    data: HashMap<String, OnceCell<Arc<G>>>,
}

impl<G> SRSCache<G> {
    /// Initializes the cache by pre-populating the internal map with
    /// all supported keys that could be looked up at a later time.
    pub fn with_defaults(identifier: &str) -> Self {
        let mut data = HashMap::new();
        let mut num_proofs_to_aggregate = PROOFS_TESTS_MIN_SNARKS;

        loop {
            for sector_size in &PUBLISHED_SECTOR_SIZES {
                let key = format!(
                    "STACKED[{}-{}]-{}",
                    sector_size, num_proofs_to_aggregate, identifier,
                );
                trace!("inserting placeholder srs key with hash key {}", key);
                data.insert(key, OnceCell::new());
            }

            num_proofs_to_aggregate <<= 1;
            if num_proofs_to_aggregate > PROOFS_TESTS_MAX_SNARKS {
                break;
            }
        }

        Self { data }
    }

    /// Returns `None` for non existent entries, `Some(v)` for existing ones, where `v` is either
    /// the result of running `generator` or already existing one.
    pub fn get_or_init<F>(&self, key: &str, generator: F) -> Result<Option<&Arc<G>>>
    where
        F: FnOnce() -> Result<G>,
    {
        if let Some(cell) = self.data.get(key) {
            trace!("generating or waiting on specialize for {}", key);
            let result =
                cell.get_or_try_init(|| -> Result<Arc<G>> { Ok(Arc::new(generator()?)) })?;
            return Ok(Some(result));
        }

        Ok(None)
    }
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

pub fn srs_cache_lookup<F, G>(
    cache_ref: &SRSCache<G>,
    identifier: String,
    generator: F,
) -> Result<Arc<G>>
where
    F: FnOnce() -> Result<G>,
    G: Send + Sync,
{
    trace!("srs_cache_lookup looking up {}", identifier);
    if let Some(entry) = cache_ref.get_or_init(&identifier, generator)? {
        return Ok(entry.clone());
    }

    panic!("unknown identifier {}", identifier);
}

#[inline]
pub fn lookup_groth_params<F>(identifier: String, generator: F) -> Result<Arc<Bls12GrothParams>>
where
    F: FnOnce() -> Result<Bls12GrothParams>,
{
    cache_lookup(&*GROTH_PARAM_MEMORY_CACHE, identifier, generator)
}

#[inline]
pub fn lookup_verifying_key<F>(
    identifier: String,
    generator: F,
) -> Result<Arc<Bls12PreparedVerifyingKey>>
where
    F: FnOnce() -> Result<Bls12PreparedVerifyingKey>,
{
    let vk_identifier = format!("{}-verifying-key", &identifier);
    cache_lookup(&*VERIFYING_KEY_MEMORY_CACHE, vk_identifier, generator)
}

#[inline]
pub fn lookup_srs_key<F>(identifier: String, generator: F) -> Result<Arc<Bls12ProverSRSKey>>
where
    F: FnOnce() -> Result<Bls12ProverSRSKey>,
{
    let srs_identifier = format!("{}-{}", &identifier, SRS_IDENTIFIER);
    srs_cache_lookup::<_, Bls12ProverSRSKey>(&*SRS_KEY_MEMORY_CACHE, srs_identifier, generator)
}

#[inline]
pub fn lookup_srs_verifier_key<F>(
    identifier: String,
    generator: F,
) -> Result<Arc<Bls12VerifierSRSKey>>
where
    F: FnOnce() -> Result<Bls12VerifierSRSKey>,
{
    let srs_identifier = format!("{}-{}", &identifier, SRS_VERIFIER_IDENTIFIER);
    srs_cache_lookup::<_, Bls12VerifierSRSKey>(
        &*SRS_VERIFIER_KEY_MEMORY_CACHE,
        srs_identifier,
        generator,
    )
}

pub fn get_stacked_params<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
) -> Result<Arc<Bls12GrothParams>> {
    let public_params = public_params::<Tree>(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let parameters_generator = || {
        <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<'_, Tree, DefaultPieceHasher>,
            _,
        >>::groth_params::<OsRng>(None, &public_params)
        .map_err(Into::into)
    };

    lookup_groth_params(
        format!(
            "STACKED[{}]",
            usize::from(PaddedBytesAmount::from(porep_config))
        ),
        parameters_generator,
    )
}

pub fn get_post_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<Arc<Bls12GrothParams>> {
    match post_config.typ {
        PoStType::Winning => {
            let post_public_params = winning_post_public_params::<Tree>(post_config)?;

            let parameters_generator = || {
                <FallbackPoStCompound<Tree> as CompoundProof<
                    FallbackPoSt<'_, Tree>,
                    FallbackPoStCircuit<Tree>,
                >>::groth_params::<OsRng>(None, &post_public_params)
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
                <FallbackPoStCompound<Tree> as CompoundProof<
                    FallbackPoSt<'_, Tree>,
                    FallbackPoStCircuit<Tree>,
                >>::groth_params::<OsRng>(None, &post_public_params)
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
) -> Result<Arc<Bls12PreparedVerifyingKey>> {
    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let vk_generator = || {
        let vk = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<'_, Tree, DefaultPieceHasher>,
            _,
        >>::verifying_key::<OsRng>(None, &public_params)?;
        Ok(prepare_verifying_key(&vk))
    };

    lookup_verifying_key(
        format!(
            "STACKED[{}]",
            usize::from(PaddedBytesAmount::from(porep_config))
        ),
        vk_generator,
    )
}

pub fn get_post_verifying_key<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<Arc<Bls12PreparedVerifyingKey>> {
    match post_config.typ {
        PoStType::Winning => {
            let post_public_params = winning_post_public_params::<Tree>(post_config)?;

            let vk_generator = || {
                let vk = <FallbackPoStCompound<Tree> as CompoundProof<
                    FallbackPoSt<'_, Tree>,
                    FallbackPoStCircuit<Tree>,
                >>::verifying_key::<OsRng>(None, &post_public_params)?;
                Ok(prepare_verifying_key(&vk))
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
                let vk = <FallbackPoStCompound<Tree> as CompoundProof<
                    FallbackPoSt<'_, Tree>,
                    FallbackPoStCircuit<Tree>,
                >>::verifying_key::<OsRng>(None, &post_public_params)?;
                Ok(prepare_verifying_key(&vk))
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

pub fn get_stacked_srs_key<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    num_proofs_to_aggregate: usize,
) -> Result<Arc<Bls12ProverSRSKey>> {
    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let srs_generator = || {
        trace!(
            "get_stacked_srs_key specializing STACKED[{}-{}]",
            usize::from(PaddedBytesAmount::from(porep_config)),
            num_proofs_to_aggregate,
        );
        <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<'_, Tree, DefaultPieceHasher>,
            _,
        >>::srs_key::<rand::rngs::OsRng>(None, &public_params, num_proofs_to_aggregate)
    };

    lookup_srs_key(
        format!(
            "STACKED[{}-{}]",
            usize::from(PaddedBytesAmount::from(porep_config)),
            num_proofs_to_aggregate,
        ),
        srs_generator,
    )
}

pub fn get_stacked_srs_verifier_key<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    num_proofs_to_aggregate: usize,
) -> Result<Arc<Bls12VerifierSRSKey>> {
    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let srs_verifier_generator = || {
        trace!(
            "get_stacked_srs_verifier_key specializing STACKED[{}-{}]",
            usize::from(PaddedBytesAmount::from(porep_config)),
            num_proofs_to_aggregate,
        );
        <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<'_, Tree, DefaultPieceHasher>,
            _,
        >>::srs_verifier_key::<rand::rngs::OsRng>(
            None, &public_params, num_proofs_to_aggregate
        )
    };

    lookup_srs_verifier_key(
        format!(
            "STACKED[{}-{}]",
            usize::from(PaddedBytesAmount::from(porep_config)),
            num_proofs_to_aggregate,
        ),
        srs_verifier_generator,
    )
}
