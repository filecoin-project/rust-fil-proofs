use std::collections::BTreeMap;
use std::hash::{Hash, Hasher as StdHasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, ensure, Context, Result};
use bincode::deserialize;
use generic_array::typenum::Unsigned;
use log::{info, trace};
use merkletree::store::StoreConfig;
use storage_proofs::cache_key::CacheKey;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::merkle::{
    create_tree, get_base_tree_count, split_config_and_replica, MerkleTreeTrait, MerkleTreeWrapper,
};
use storage_proofs::multi_proof::MultiProof;
use storage_proofs::post::fallback;
use storage_proofs::post::fallback::SectorProof;
use storage_proofs::proof::ProofScheme;
use storage_proofs::sector::*;
use storage_proofs::util::default_rows_to_discard;

use crate::api::util::{as_safe_commitment, get_base_tree_leafs, get_base_tree_size};
use crate::caches::{get_post_params, get_post_verifying_key};
use crate::constants::*;
use crate::parameters::{window_post_setup_params, winning_post_setup_params};
use crate::types::{
    ChallengeSeed, Commitment, FallbackPoStSectorProof, PersistentAux, PoStConfig, ProverId,
    SectorSize, SnarkProof, TemporaryAux, VanillaProof,
};
use crate::PoStType;

/// The minimal information required about a replica, in order to be able to generate
/// a PoSt over it.
#[derive(Debug)]
pub struct PrivateReplicaInfo<Tree: MerkleTreeTrait> {
    /// Path to the replica.
    replica: PathBuf,
    /// The replica commitment.
    comm_r: Commitment,
    /// Persistent Aux.
    aux: PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    /// Contains sector-specific (e.g. merkle trees) assets
    cache_dir: PathBuf,

    _t: PhantomData<Tree>,
}

impl<Tree: MerkleTreeTrait> Clone for PrivateReplicaInfo<Tree> {
    fn clone(&self) -> Self {
        Self {
            replica: self.replica.clone(),
            comm_r: self.comm_r,
            aux: self.aux.clone(),
            cache_dir: self.cache_dir.clone(),
            _t: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait> std::cmp::PartialEq for PrivateReplicaInfo<Tree> {
    fn eq(&self, other: &Self) -> bool {
        self.replica == other.replica
            && self.comm_r == other.comm_r
            && self.aux == other.aux
            && self.cache_dir == other.cache_dir
    }
}

impl<Tree: MerkleTreeTrait> Hash for PrivateReplicaInfo<Tree> {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.replica.hash(state);
        self.comm_r.hash(state);
        self.aux.hash(state);
        self.cache_dir.hash(state);
    }
}

impl<Tree: MerkleTreeTrait> std::cmp::Eq for PrivateReplicaInfo<Tree> {}

impl<Tree: MerkleTreeTrait> std::cmp::Ord for PrivateReplicaInfo<Tree> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.comm_r.as_ref().cmp(other.comm_r.as_ref())
    }
}

impl<Tree: MerkleTreeTrait> std::cmp::PartialOrd for PrivateReplicaInfo<Tree> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.comm_r.as_ref().partial_cmp(other.comm_r.as_ref())
    }
}

impl<Tree: 'static + MerkleTreeTrait> PrivateReplicaInfo<Tree> {
    pub fn new(replica: PathBuf, comm_r: Commitment, cache_dir: PathBuf) -> Result<Self> {
        ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

        let aux = {
            let f_aux_path = cache_dir.join(CacheKey::PAux.to_string());
            let aux_bytes = std::fs::read(&f_aux_path)
                .with_context(|| format!("could not read from path={:?}", f_aux_path))?;

            deserialize(&aux_bytes)
        }?;

        ensure!(replica.exists(), "Sealed replica does not exist");

        Ok(PrivateReplicaInfo {
            replica,
            comm_r,
            aux,
            cache_dir,
            _t: Default::default(),
        })
    }

    pub fn cache_dir_path(&self) -> &Path {
        self.cache_dir.as_path()
    }

    pub fn replica_path(&self) -> &Path {
        self.replica.as_path()
    }

    pub fn safe_comm_r(&self) -> Result<<Tree::Hasher as Hasher>::Domain> {
        as_safe_commitment(&self.comm_r, "comm_r")
    }

    pub fn safe_comm_c(&self) -> <Tree::Hasher as Hasher>::Domain {
        self.aux.comm_c
    }

    pub fn safe_comm_r_last(&self) -> <Tree::Hasher as Hasher>::Domain {
        self.aux.comm_r_last
    }

    /// Generate the merkle tree of this particular replica.
    pub fn merkle_tree(
        &self,
        sector_size: SectorSize,
    ) -> Result<
        MerkleTreeWrapper<
            Tree::Hasher,
            Tree::Store,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    > {
        let base_tree_size = get_base_tree_size::<Tree>(sector_size)?;
        let base_tree_leafs = get_base_tree_leafs::<Tree>(base_tree_size)?;
        trace!(
            "post: base tree size {}, base tree leafs {}, rows_to_discard {}, arities [{}, {}, {}]",
            base_tree_size,
            base_tree_leafs,
            default_rows_to_discard(base_tree_leafs, Tree::Arity::to_usize()),
            Tree::Arity::to_usize(),
            Tree::SubTreeArity::to_usize(),
            Tree::TopTreeArity::to_usize(),
        );

        let mut config = StoreConfig::new(
            self.cache_dir_path(),
            CacheKey::CommRLastTree.to_string(),
            default_rows_to_discard(base_tree_leafs, Tree::Arity::to_usize()),
        );
        config.size = Some(base_tree_size);

        let tree_count = get_base_tree_count::<Tree>();
        let (configs, replica_config) = split_config_and_replica(
            config,
            self.replica_path().to_path_buf(),
            base_tree_leafs,
            tree_count,
        )?;

        create_tree::<Tree>(base_tree_size, &configs, Some(&replica_config))
    }
}

/// The minimal information required about a replica, in order to be able to verify
/// a PoSt over it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicReplicaInfo {
    /// The replica commitment.
    comm_r: Commitment,
}

impl std::cmp::Ord for PublicReplicaInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.comm_r.as_ref().cmp(other.comm_r.as_ref())
    }
}

impl std::cmp::PartialOrd for PublicReplicaInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PublicReplicaInfo {
    pub fn new(comm_r: Commitment) -> Result<Self> {
        ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
        Ok(PublicReplicaInfo { comm_r })
    }

    pub fn safe_comm_r<T: Domain>(&self) -> Result<T> {
        as_safe_commitment(&self.comm_r, "comm_r")
    }
}

// Ensure that any associated cached data persisted is discarded.
pub fn clear_cache<Tree: MerkleTreeTrait>(cache_dir: &Path) -> Result<()> {
    info!("clear_cache:start");

    let t_aux = {
        let f_aux_path = cache_dir.to_path_buf().join(CacheKey::TAux.to_string());
        let aux_bytes = std::fs::read(&f_aux_path)
            .with_context(|| format!("could not read from path={:?}", f_aux_path))?;

        deserialize(&aux_bytes)
    }?;

    let result = TemporaryAux::<Tree, DefaultPieceHasher>::clear_temp(t_aux);

    info!("clear_cache:finish");

    result
}

// Ensure that any associated cached data persisted is discarded.
pub fn clear_caches<Tree: MerkleTreeTrait>(
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo<Tree>>,
) -> Result<()> {
    info!("clear_caches:start");

    for replica in replicas.values() {
        clear_cache::<Tree>(&replica.cache_dir.as_path())?;
    }

    info!("clear_caches:finish");

    Ok(())
}

/// Generates a Winning proof-of-spacetime with provided vanilla proofs.
pub fn generate_winning_post_with_vanilla<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
) -> Result<SnarkProof> {
    info!("generate_winning_post_with_vanilla:start");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    ensure!(
        vanilla_proofs.len() == post_config.sector_count,
        "invalid amount of vanilla proofs"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(&post_config)?;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: post_config.priority,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let mut pub_sectors = Vec::with_capacity(vanilla_proofs.len());
    for vanilla_proof in &vanilla_proofs {
        pub_sectors.push(fallback::PublicSector {
            id: vanilla_proof.sector_id,
            comm_r: vanilla_proof.comm_r,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let partitions = match pub_params.partitions {
        Some(x) => x,
        None => 1,
    };
    let partitioned_proofs = partition_vanilla_proofs(
        &post_config,
        &pub_params.vanilla_params,
        &pub_inputs,
        partitions,
        &vanilla_proofs,
    )?;

    let proof = fallback::FallbackPoStCompound::prove_with_vanilla(
        &pub_params,
        &pub_inputs,
        partitioned_proofs,
        &groth_params,
    )?;
    let proof = proof.to_vec()?;

    info!("generate_winning_post_with_vanilla:finish");

    Ok(proof)
}

/// Generates a Winning proof-of-spacetime.
pub fn generate_winning_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PrivateReplicaInfo<Tree>)],
    prover_id: ProverId,
) -> Result<SnarkProof> {
    info!("generate_winning_post:start");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    ensure!(
        replicas.len() == post_config.sector_count,
        "invalid amount of replicas"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(&post_config)?;
    let param_sector_count = vanilla_params.sector_count;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: post_config.priority,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let trees = replicas
        .iter()
        .map(|(sector_id, replica)| {
            replica
                .merkle_tree(post_config.sector_size)
                .with_context(|| {
                    format!("generate_winning_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    let mut priv_sectors = Vec::with_capacity(param_sector_count);

    for _ in 0..param_sector_count {
        for ((sector_id, replica), tree) in replicas.iter().zip(trees.iter()) {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("generate_winning_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            let comm_c = replica.safe_comm_c();
            let comm_r_last = replica.safe_comm_r_last();

            pub_sectors.push(fallback::PublicSector::<<Tree::Hasher as Hasher>::Domain> {
                id: *sector_id,
                comm_r,
            });
            priv_sectors.push(fallback::PrivateSector {
                tree,
                comm_c,
                comm_r_last,
            });
        }
    }

    let pub_inputs = fallback::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let proof = fallback::FallbackPoStCompound::<Tree>::prove(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        &groth_params,
    )?;
    let proof = proof.to_vec()?;

    info!("generate_winning_post:finish");

    Ok(proof)
}

/// Given some randomness and the length of available sectors, generates the challenged sector.
///
/// The returned values are indices in the range of `0..sector_set_size`, requiring the caller
/// to match the index to the correct sector.
pub fn generate_winning_post_sector_challenge<Tree: MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    sector_set_size: u64,
    prover_id: Commitment,
) -> Result<Vec<u64>> {
    info!("generate_winning_post_sector_challenge:start");
    ensure!(sector_set_size != 0, "empty sector set is invalid");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let result = fallback::generate_sector_challenges(
        randomness_safe,
        post_config.sector_count,
        sector_set_size,
        prover_id_safe,
    );

    info!("generate_winning_post_sector_challenge:finish");

    result
}

/// Generates the challenges per SectorId required for either a Window
/// proof-of-spacetime or a Winning proof-of-spacetime.
pub fn generate_fallback_sector_challenges<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    pub_sectors: &[SectorId],
    _prover_id: ProverId,
) -> Result<BTreeMap<SectorId, Vec<u64>>> {
    info!("generate_sector_challenges:start");
    ensure!(
        post_config.typ == PoStType::Window || post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;

    let public_params = fallback::PublicParams {
        sector_size: u64::from(post_config.sector_size),
        challenge_count: post_config.challenge_count,
        sector_count: post_config.sector_count,
    };

    let mut sector_challenges: BTreeMap<SectorId, Vec<u64>> = BTreeMap::new();

    let num_sectors_per_chunk = post_config.sector_count;
    let partitions = match post_config.typ {
        PoStType::Window => match get_partitions_for_window_post(pub_sectors.len(), &post_config) {
            Some(x) => x,
            None => 1,
        },
        PoStType::Winning => 1,
    };

    for partition_index in 0..partitions {
        let sectors = pub_sectors
            .chunks(num_sectors_per_chunk)
            .nth(partition_index)
            .ok_or_else(|| anyhow!("invalid number of sectors/partition index"))?;

        for (i, sector) in sectors.iter().enumerate() {
            let mut challenges = Vec::new();

            for n in 0..post_config.challenge_count {
                let challenge_index = ((partition_index * post_config.sector_count + i)
                    * post_config.challenge_count
                    + n) as u64;
                let challenged_leaf = fallback::generate_leaf_challenge(
                    &public_params,
                    randomness_safe,
                    u64::from(*sector),
                    challenge_index,
                );
                challenges.push(challenged_leaf);
            }

            sector_challenges.insert(*sector, challenges);
        }
    }

    info!("generate_sector_challenges:finish");

    Ok(sector_challenges)
}

/// Generates a single vanilla proof required for either Window proof-of-spacetime
/// or Winning proof-of-spacetime.
pub fn generate_single_vanilla_proof<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    sector_id: SectorId,
    replica: &PrivateReplicaInfo<Tree>,
    challenges: &[u64],
) -> Result<FallbackPoStSectorProof<Tree>> {
    info!("generate_single_vanilla_proof:start: {:?}", sector_id);

    let tree = &replica
        .merkle_tree(post_config.sector_size)
        .with_context(|| {
            format!(
                "generate_single_vanilla_proof: merkle_tree failed: {:?}",
                sector_id
            )
        })?;
    let comm_r = replica.safe_comm_r().with_context(|| {
        format!(
            "generate_single_vanilla_poof: safe_comm_r failed: {:?}",
            sector_id
        )
    })?;
    let comm_c = replica.safe_comm_c();
    let comm_r_last = replica.safe_comm_r_last();

    let mut priv_sectors = Vec::with_capacity(1);
    priv_sectors.push(fallback::PrivateSector {
        tree,
        comm_c,
        comm_r_last,
    });

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let vanilla_proof =
        fallback::vanilla_proof(sector_id, &priv_inputs, challenges).with_context(|| {
            format!(
                "generate_single_vanilla_proof: vanilla_proof failed: {:?}",
                sector_id
            )
        })?;

    info!("generate_single_vanilla_proof:finish: {:?}", sector_id);

    Ok(FallbackPoStSectorProof {
        sector_id,
        comm_r,
        vanilla_proof,
    })
}

/// Verifies a winning proof-of-spacetime.
///
/// The provided `replicas` must be the same ones as passed to `generate_winning_post`, and be based on
/// the indices generated by `generate_winning_post_sector_challenge`. It is the responsibility of the
/// caller to ensure this.
pub fn verify_winning_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PublicReplicaInfo)],
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool> {
    info!("verify_winning_post:start");

    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );
    ensure!(
        post_config.sector_count == replicas.len(),
        "invalid amount of replicas provided"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(&post_config)?;
    let param_sector_count = vanilla_params.sector_count;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: false,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    for _ in 0..param_sector_count {
        for (sector_id, replica) in replicas.iter() {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("verify_winning_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            pub_sectors.push(fallback::PublicSector {
                id: *sector_id,
                comm_r,
            });
        }
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let is_valid = {
        let verifying_key = get_post_verifying_key::<Tree>(&post_config)?;

        let single_proof = MultiProof::new_from_reader(None, &proof[..], &verifying_key)?;
        if single_proof.len() != 1 {
            return Ok(false);
        }

        fallback::FallbackPoStCompound::verify(
            &pub_params,
            &pub_inputs,
            &single_proof,
            &fallback::ChallengeRequirements {
                minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
            },
        )?
    };

    if !is_valid {
        return Ok(false);
    }

    info!("verify_winning_post:finish");

    Ok(true)
}

// Partition a flat vector of vanilla sector proofs.  The post_config
// (PoSt) type is required in order to determine the proper shape of
// the returned partitioned proofs.
pub fn partition_vanilla_proofs<Tree: MerkleTreeTrait>(
    post_config: &PoStConfig,
    pub_params: &fallback::PublicParams,
    pub_inputs: &fallback::PublicInputs<<Tree::Hasher as Hasher>::Domain>,
    partition_count: usize,
    vanilla_proofs: &[FallbackPoStSectorProof<Tree>],
) -> Result<Vec<VanillaProof<Tree>>> {
    info!("partition_vanilla_proofs:start");
    ensure!(
        post_config.typ == PoStType::Window || post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let num_sectors_per_chunk = pub_params.sector_count;
    let num_sectors = pub_inputs.sectors.len();

    ensure!(
        num_sectors <= partition_count * num_sectors_per_chunk,
        "cannot prove the provided number of sectors: {} > {} * {}",
        num_sectors,
        partition_count,
        num_sectors_per_chunk,
    );

    let mut partition_proofs = Vec::new();

    // Note that the partition proofs returned are shaped differently
    // based on which type of PoSt is being considered.
    match post_config.typ {
        PoStType::Window => {
            for (j, sectors_chunk) in pub_inputs.sectors.chunks(num_sectors_per_chunk).enumerate() {
                trace!("processing partition {}", j);

                let mut sector_proofs = Vec::with_capacity(num_sectors_per_chunk);

                for pub_sector in sectors_chunk.iter() {
                    let cur_proof = vanilla_proofs
                        .iter()
                        .find(|&proof| proof.sector_id == pub_sector.id)
                        .expect("failed to locate sector proof");

                    // Note: Window post requires all inclusion proofs (based on the challenge
                    // count per sector) per sector proof.
                    sector_proofs.extend(cur_proof.vanilla_proof.sectors.clone());
                }

                // If there were less than the required number of sectors provided, we duplicate the last one
                // to pad the proof out, such that it works in the circuit part.
                while sector_proofs.len() < num_sectors_per_chunk {
                    sector_proofs.push(sector_proofs[sector_proofs.len() - 1].clone());
                }

                partition_proofs.push(fallback::Proof::<<Tree as MerkleTreeTrait>::Proof> {
                    sectors: sector_proofs,
                });
            }
        }
        PoStType::Winning => {
            for (j, sectors_chunk) in vanilla_proofs.chunks(num_sectors_per_chunk).enumerate() {
                trace!("processing partition {}", j);

                // Sanity check incoming structure
                ensure!(
                    sectors_chunk.len() == 1,
                    "Invalid sector chunk for Winning PoSt"
                );
                ensure!(
                    sectors_chunk[0].vanilla_proof.sectors.len() == 1,
                    "Invalid sector count for Winning PoSt chunk"
                );

                // Winning post sector_count is winning post challenges per sector
                ensure!(
                    post_config.sector_count == sectors_chunk[j].vanilla_proof.sectors.len(),
                    "invalid number of sector proofs for Winning PoSt"
                );

                let mut sector_proofs = Vec::with_capacity(post_config.challenge_count);
                let cur_sector_proof = &sectors_chunk[0].vanilla_proof.sectors[0];

                // Unroll inclusions proofs from the single provided sector_proof (per partition)
                // into individual sector proofs, required for winning post.
                for cur_inclusion_proof in cur_sector_proof.inclusion_proofs() {
                    sector_proofs.push(SectorProof {
                        inclusion_proofs: vec![cur_inclusion_proof.clone()],
                        comm_c: cur_sector_proof.comm_c,
                        comm_r_last: cur_sector_proof.comm_r_last,
                    });
                }

                // If there were less than the required number of sectors provided, we duplicate the last one
                // to pad the proof out, such that it works in the circuit part.
                while sector_proofs.len() < num_sectors_per_chunk {
                    sector_proofs.push(sector_proofs[sector_proofs.len() - 1].clone());
                }

                // Winning post Challenge count is the total winning post challenges
                ensure!(
                    sector_proofs.len() == post_config.challenge_count,
                    "invalid number of partition proofs based on Winning PoSt challenges"
                );

                partition_proofs.push(fallback::Proof::<<Tree as MerkleTreeTrait>::Proof> {
                    sectors: sector_proofs,
                });
            }
        }
    }

    info!("partition_vanilla_proofs:finish");

    ensure!(
        fallback::FallbackPoSt::<Tree>::verify_all_partitions(
            pub_params,
            pub_inputs,
            &partition_proofs
        )?,
        "partitioned vanilla proofs failed to verify"
    );

    Ok(partition_proofs)
}

/// Generates a Window proof-of-spacetime with provided vanilla proofs.
pub fn generate_window_post_with_vanilla<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
) -> Result<SnarkProof> {
    info!("generate_window_post_with_vanilla:start");
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let partitions = get_partitions_for_window_post(vanilla_proofs.len(), &post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let partitions = match partitions {
        Some(x) => x,
        None => 1,
    };

    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let mut pub_sectors = Vec::with_capacity(vanilla_proofs.len());
    for vanilla_proof in &vanilla_proofs {
        pub_sectors.push(fallback::PublicSector {
            id: vanilla_proof.sector_id,
            comm_r: vanilla_proof.comm_r,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let partitioned_proofs = partition_vanilla_proofs(
        &post_config,
        &pub_params.vanilla_params,
        &pub_inputs,
        partitions,
        &vanilla_proofs,
    )?;

    let proof = fallback::FallbackPoStCompound::prove_with_vanilla(
        &pub_params,
        &pub_inputs,
        partitioned_proofs,
        &groth_params,
    )?;

    info!("generate_window_post_with_vanilla:finish");

    Ok(proof.to_vec()?)
}

/// Generates a Window proof-of-spacetime.
pub fn generate_window_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo<Tree>>,
    prover_id: ProverId,
) -> Result<SnarkProof> {
    info!("generate_window_post:start");
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let partitions = get_partitions_for_window_post(replicas.len(), &post_config);

    let sector_count = vanilla_params.sector_count;
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let trees: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            replica
                .merkle_tree(post_config.sector_size)
                .with_context(|| {
                    format!("generate_window_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<_>>()?;

    let mut pub_sectors = Vec::with_capacity(sector_count);
    let mut priv_sectors = Vec::with_capacity(sector_count);

    for ((sector_id, replica), tree) in replicas.iter().zip(trees.iter()) {
        let comm_r = replica.safe_comm_r().with_context(|| {
            format!("generate_window_post: safe_comm_r failed: {:?}", sector_id)
        })?;
        let comm_c = replica.safe_comm_c();
        let comm_r_last = replica.safe_comm_r_last();

        pub_sectors.push(fallback::PublicSector {
            id: *sector_id,
            comm_r,
        });
        priv_sectors.push(fallback::PrivateSector {
            tree,
            comm_c,
            comm_r_last,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let proof = fallback::FallbackPoStCompound::prove(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        &groth_params,
    )?;

    info!("generate_window_post:finish");

    Ok(proof.to_vec()?)
}

/// Verifies a window proof-of-spacetime.
pub fn verify_window_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool> {
    info!("verify_window_post:start");

    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let partitions = get_partitions_for_window_post(replicas.len(), &post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: false,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;

    let pub_sectors: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("verify_window_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            Ok(fallback::PublicSector {
                id: *sector_id,
                comm_r,
            })
        })
        .collect::<Result<_>>()?;

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let is_valid = {
        let verifying_key = get_post_verifying_key::<Tree>(&post_config)?;
        let multi_proof = MultiProof::new_from_reader(partitions, &proof[..], &verifying_key)?;

        fallback::FallbackPoStCompound::verify(
            &pub_params,
            &pub_inputs,
            &multi_proof,
            &fallback::ChallengeRequirements {
                minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
            },
        )?
    };
    if !is_valid {
        return Ok(false);
    }

    info!("verify_window_post:finish");

    Ok(true)
}

fn get_partitions_for_window_post(
    total_sector_count: usize,
    post_config: &PoStConfig,
) -> Option<usize> {
    let partitions = (total_sector_count as f32 / post_config.sector_count as f32).ceil() as usize;

    if partitions > 1 {
        Some(partitions)
    } else {
        None
    }
}
