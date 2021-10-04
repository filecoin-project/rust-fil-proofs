use std::fs::{metadata, OpenOptions};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Error};
use blstrs::Scalar as Fr;
use ff::Field;
use filecoin_hashers::{HashFunction, Hasher};
use fr32::{bytes_into_fr, fr_into_bytes};
use generic_array::typenum::{Unsigned, U0};
use log::{info, trace};
use memmap::{Mmap, MmapMut, MmapOptions};
use merkletree::{
    merkle::{get_merkle_tree_leafs, get_merkle_tree_len},
    store::{DiskStore, Store, StoreConfig},
};
use rayon::{iter::IntoParallelIterator, prelude::*};
use serde::{Deserialize, Serialize};
use storage_proofs_core::{
    cache_key::CacheKey,
    data::Data,
    error::Result,
    merkle::{
        create_lc_tree, get_base_tree_count, split_config_and_replica, BinaryMerkleTree, LCTree,
        MerkleProof, MerkleProofTrait, MerkleTreeTrait,
    },
    parameter_cache::ParameterSetMetadata,
    proof::ProofScheme,
};
use storage_proofs_porep::stacked::{StackedDrg, TemporaryAuxCache};

use crate::{
    constants::{
        apex_leaf_count, challenge_count, partition_count, TreeDArity, TreeDDomain, TreeDHasher,
        TreeRDomain, TreeRHasher, ALLOWED_SECTOR_SIZES,
    },
    Challenges,
};

const CHUNK_SIZE_MIN: usize = 4096;
const FR_SIZE: usize = std::mem::size_of::<Fr>() as usize;

#[derive(Clone)]
pub struct SetupParams {
    pub sector_bytes: u64,
}

#[derive(Clone)]
pub struct PublicParams {
    // The sector-size measured in nodes.
    pub sector_nodes: usize,
    // The number of challenges per partition proof.
    pub challenge_count: usize,
    // The number of bits per challenge, i.e. `challenge_bit_len = log2(sector_nodes)`.
    pub challenge_bit_len: usize,
    // The number of partition proofs for this sector-size.
    pub partition_count: usize,
    // The bit length of an integer in `0..partition_count`.
    pub partition_bit_len: usize,
    // The number of leafs in the apex-tree.
    pub apex_leaf_count: usize,
    // The bit length of an integer in `0..apex_leaf_count`.
    pub apex_select_bit_len: usize,
}

impl ParameterSetMetadata for PublicParams {
    fn identifier(&self) -> String {
        format!(
            "empty_sector_update::PublicParams{{ sector_nodes: {} }}",
            self.sector_nodes
        )
    }

    fn sector_size(&self) -> u64 {
        (self.sector_nodes as u64) << 5
    }
}

impl PublicParams {
    pub fn from_sector_size(sector_bytes: u64) -> Self {
        // The sector-size measured in 32-byte nodes.
        let sector_nodes = ALLOWED_SECTOR_SIZES
            .iter()
            .copied()
            .find(|allowed_nodes| (allowed_nodes << 5) as u64 == sector_bytes)
            .expect("provided sector-size is not allowed");

        // `sector_nodes` is guaranteed to be a power of two.
        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
        let challenge_count = challenge_count(sector_nodes);

        let partition_count = partition_count(sector_nodes);
        // `partition_count` is guaranteed to be a power of two.
        let partition_bit_len = partition_count.trailing_zeros() as usize;

        let apex_leaf_count = apex_leaf_count(sector_nodes);
        // `apex_leaf_count` is guaranteed to be a power of two.
        let apex_select_bit_len = apex_leaf_count.trailing_zeros() as usize;

        PublicParams {
            sector_nodes,
            challenge_count,
            challenge_bit_len,
            partition_count,
            partition_bit_len,
            apex_leaf_count,
            apex_select_bit_len,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    pub k: usize,
    pub comm_c: TreeRDomain,
    pub comm_r_old: TreeRDomain,
    pub comm_d_new: TreeDDomain,
    pub comm_r_new: TreeRDomain,
    // The number of high bits to take from each challenge's random bits. Used to verify replica
    // encoding in vanilla proofs. `h_select` is a circuit-only public-input derived from `h`.
    pub h: usize,
}

pub struct PrivateInputs<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    // Contains `tree_r_last_old`.
    pub t_aux_old: TemporaryAuxCache<TreeR, TreeDHasher>,
    pub tree_d_new_config: StoreConfig,
    pub tree_r_new_config: StoreConfig,
    // Path to new replica.
    pub replica_path: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    #[serde(bound(
        serialize = "MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>: Deserialize<'de>"
    ))]
    pub proof_r_old:
        MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
    #[serde(bound(
        serialize = "MerkleProof<TreeDHasher, TreeDArity>: Serialize",
        deserialize = "MerkleProof<TreeDHasher, TreeDArity>: Deserialize<'de>"
    ))]
    pub proof_d_new: MerkleProof<TreeDHasher, TreeDArity>,
    #[serde(bound(
        serialize = "MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>: Deserialize<'de>"
    ))]
    pub proof_r_new:
        MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
}

// Implement `Clone` by hand because `MerkleTreeTrait` does not implement `Clone`.
impl<TreeR> Clone for ChallengeProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    fn clone(&self) -> Self {
        ChallengeProof {
            proof_r_old: self.proof_r_old.clone(),
            proof_d_new: self.proof_d_new.clone(),
            proof_r_new: self.proof_r_new.clone(),
        }
    }
}

impl<TreeR> ChallengeProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    pub fn verify_merkle_proofs(
        &self,
        c: usize,
        comm_r_last_old: &TreeRDomain,
        comm_d_new: &TreeDDomain,
        comm_r_last_new: &TreeRDomain,
    ) -> bool {
        self.proof_r_old.path_index() == c
            && self.proof_d_new.path_index() == c
            && self.proof_r_new.path_index() == c
            && self.proof_r_old.root() == *comm_r_last_old
            && self.proof_d_new.root() == *comm_d_new
            && self.proof_r_new.root() == *comm_r_last_new
            && self.proof_r_old.verify()
            && self.proof_d_new.verify()
            && self.proof_r_new.verify()
    }
}

#[derive(Serialize, Deserialize)]
pub struct PartitionProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    pub apex_leafs: Vec<TreeDDomain>,
    #[serde(bound(
        serialize = "ChallengeProof<TreeR>: Serialize",
        deserialize = "ChallengeProof<TreeR>: Deserialize<'de>"
    ))]
    pub challenge_proofs: Vec<ChallengeProof<TreeR>>,
}

// Implement `Clone` by hand because `MerkleTreeTrait` does not implement `Clone`.
impl<TreeR> Clone for PartitionProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    fn clone(&self) -> Self {
        PartitionProof {
            apex_leafs: self.apex_leafs.clone(),
            challenge_proofs: self.challenge_proofs.clone(),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub struct EmptySectorUpdate<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    _tree_r: PhantomData<TreeR>,
}

impl<'a, TreeR> ProofScheme<'a> for EmptySectorUpdate<TreeR>
where
    TreeR: 'static + MerkleTreeTrait<Hasher = TreeRHasher>,
{
    type SetupParams = SetupParams;
    type PublicParams = PublicParams;
    type PublicInputs = PublicInputs;
    type PrivateInputs = PrivateInputs<TreeR>;
    type Proof = PartitionProof<TreeR>;
    type Requirements = ();

    fn setup(setup_params: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams::from_sector_size(setup_params.sector_bytes))
    }

    fn prove(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let PublicParams {
            sector_nodes,
            partition_count,
            apex_leaf_count,
            ..
        } = pub_params;

        let PublicInputs { k, comm_r_new, .. } = pub_inputs;

        let PrivateInputs {
            t_aux_old,
            tree_d_new_config,
            tree_r_new_config,
            replica_path,
            ..
        } = priv_inputs;

        info!(
            "Proving EmptySectorUpdate vanilla partition (sector_nodes={}, k={})",
            sector_nodes, k,
        );

        let tree_d_arity = TreeDArity::to_usize();
        let tree_r_base_arity = TreeR::Arity::to_usize();
        let tree_r_sub_arity = TreeR::SubTreeArity::to_usize();
        let tree_r_top_arity = TreeR::TopTreeArity::to_usize();

        let tree_r_old = &t_aux_old.tree_r_last;

        // Instantiate TreeD new from the replica cache path. Note that this is similar to what
        // we do when going from t_aux to t_aux cache.
        let tree_d_size = tree_d_new_config.size.expect("config size failure");
        let tree_d_leafs = get_merkle_tree_leafs(tree_d_size, tree_d_arity)?;
        trace!(
            "Instantiating TreeDNew: leafs={}, store_size={})",
            tree_d_leafs,
            tree_d_size
        );
        let tree_d_store =
            DiskStore::<TreeDDomain>::new_from_disk(tree_d_size, tree_d_arity, &tree_d_new_config)
                .context("tree_d_store")?;
        let tree_d_new =
            BinaryMerkleTree::<TreeDHasher>::from_data_store(tree_d_store, tree_d_leafs)
                .context("tree_d")?;

        // Instantiate TreeR new from the replica_cache_path. Note that this is similar to what we
        // do when going from t_aux to t_aux cache.
        let tree_r_size = tree_r_new_config.size.expect("tree_r config size failure");
        let tree_r_leafs = get_merkle_tree_leafs(tree_r_size, tree_r_base_arity)?;
        let tree_r_base_tree_count = get_base_tree_count::<TreeR>();
        let (tree_r_new_configs, replica_config) = split_config_and_replica(
            tree_r_new_config.clone(),
            replica_path.to_path_buf(),
            tree_r_leafs,
            tree_r_base_tree_count,
        )?;
        let tree_r_rows_to_discard = Some(tree_r_new_config.rows_to_discard);

        trace!(
            "Instantiating TreeRNew: arity={}-{}-{}, base_tree_count={}, store_size={}",
            tree_r_base_arity,
            tree_r_sub_arity,
            tree_r_top_arity,
            tree_r_base_tree_count,
            tree_r_size,
        );
        let tree_r_new = create_lc_tree::<
            LCTree<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
        >(tree_r_size, &tree_r_new_configs, &replica_config)?;

        // tree_d borrowed the store, so re-instantiate it here for reading apex leafs.
        let tree_d_store =
            DiskStore::<TreeDDomain>::new_from_disk(tree_d_size, tree_d_arity, &tree_d_new_config)
                .context("tree_d_store")?;
        // TODO: can we use `tree_d_size` instead of `Store::len()` here?
        // let tree_d_total_size = Store::len(&tree_d_store);

        // Total number of nodes in TreeD.
        let total_apex_leafs = partition_count * apex_leaf_count;
        // The number of nodes in TreeD from the apex-leafs row to the root.
        let tree_d_size_apex_leafs_to_root = get_merkle_tree_len(total_apex_leafs, tree_d_arity)?;
        // The number of nodes in TreeD below the apex-leafs row.
        let tree_d_size_below_apex_leafs = tree_d_size - tree_d_size_apex_leafs_to_root;
        trace!(
            "Apex-leafs info: total_apex_leafs={}, apex_leafs_per_partition={}",
            total_apex_leafs,
            apex_leaf_count,
        );

        // Get this partition's apex-leafs.
        let apex_leafs_start = tree_d_size_below_apex_leafs + k * apex_leaf_count;
        let apex_leafs_stop = apex_leafs_start + apex_leaf_count;
        trace!(
            "apex_leafs_start={} for partition k={}",
            apex_leafs_start,
            k
        );
        let apex_leafs: Vec<TreeDDomain> =
            tree_d_store.read_range(apex_leafs_start..apex_leafs_stop)?;
        info!(
            "Finished reading apex-leafs from TreeD for partition k={}",
            k
        );

        let challenges: Vec<usize> = Challenges::new(*sector_nodes, *comm_r_new, *k).collect();

        // Generate this partition's challenge proofs.
        let challenge_proofs = challenges
            .into_par_iter()
            .map(|c| {
                let proof_d_new = tree_d_new.gen_proof(c)?;
                let proof_r_new = tree_r_new.gen_cached_proof(c, tree_r_rows_to_discard)?;
                let proof_r_old = tree_r_old.gen_cached_proof(c, tree_r_rows_to_discard)?;
                ensure!(
                    proof_d_new.verify(),
                    "invalid TreeDNew Merkle proof for c={}",
                    c
                );
                ensure!(
                    proof_r_new.verify(),
                    "invalid TreeRNew Merkle proof for c={}",
                    c
                );
                ensure!(
                    proof_r_old.verify(),
                    "invalid TreeROld Merkle proof for c={}",
                    c
                );
                Ok(ChallengeProof {
                    proof_r_old,
                    proof_d_new,
                    proof_r_new,
                })
            })
            .collect::<Result<Vec<ChallengeProof<TreeR>>>>()?;

        info!("finished generating challege-proofs");

        Ok(PartitionProof {
            apex_leafs,
            challenge_proofs,
        })
    }

    fn prove_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
        _partition_count: usize,
    ) -> Result<Vec<Self::Proof>> {
        let PublicParams {
            sector_nodes,
            partition_count,
            apex_leaf_count,
            ..
        } = pub_params;

        let PublicInputs { comm_r_new, .. } = pub_inputs;

        let PrivateInputs {
            t_aux_old,
            tree_d_new_config,
            tree_r_new_config,
            replica_path,
            ..
        } = priv_inputs;

        info!(
            "Proving all EmptySectorUpdate vanilla partitions (sector_nodes={})",
            sector_nodes,
        );

        let tree_d_arity = TreeDArity::to_usize();
        let tree_r_base_arity = TreeR::Arity::to_usize();
        let tree_r_sub_arity = TreeR::SubTreeArity::to_usize();
        let tree_r_top_arity = TreeR::TopTreeArity::to_usize();

        let tree_r_old = &t_aux_old.tree_r_last;

        // Instantiate TreeD new from the replica cache path. Note that this is similar to what
        // we do when going from t_aux to t_aux cache.
        let tree_d_size = tree_d_new_config.size.expect("config size failure");
        let tree_d_leafs = get_merkle_tree_leafs(tree_d_size, tree_d_arity)?;
        trace!(
            "Instantiating TreeDNew: leafs={}, store_size={})",
            tree_d_leafs,
            tree_d_size
        );
        let tree_d_store =
            DiskStore::<TreeDDomain>::new_from_disk(tree_d_size, tree_d_arity, &tree_d_new_config)
                .context("tree_d_store")?;
        let tree_d_new =
            BinaryMerkleTree::<TreeDHasher>::from_data_store(tree_d_store, tree_d_leafs)
                .context("tree_d")?;

        // Instantiate TreeR new from the replica_cache_path. Note that this is similar to what we
        // do when going from t_aux to t_aux cache.
        let tree_r_size = tree_r_new_config.size.expect("tree_r config size failure");
        let tree_r_leafs = get_merkle_tree_leafs(tree_r_size, tree_r_base_arity)?;
        let tree_r_base_tree_count = get_base_tree_count::<TreeR>();
        let (tree_r_new_configs, replica_config) = split_config_and_replica(
            tree_r_new_config.clone(),
            replica_path.to_path_buf(),
            tree_r_leafs,
            tree_r_base_tree_count,
        )?;
        let tree_r_rows_to_discard = Some(tree_r_new_config.rows_to_discard);

        trace!(
            "Instantiating TreeRNew: arity={}-{}-{}, base_tree_count={}, store_size={}",
            tree_r_base_arity,
            tree_r_sub_arity,
            tree_r_top_arity,
            tree_r_base_tree_count,
            tree_r_size,
        );
        let tree_r_new = create_lc_tree::<
            LCTree<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
        >(tree_r_size, &tree_r_new_configs, &replica_config)?;

        // tree_d borrowed the store, so re-instantiate it here for reading apex leafs.
        let tree_d_store =
            DiskStore::<TreeDDomain>::new_from_disk(tree_d_size, tree_d_arity, &tree_d_new_config)
                .context("tree_d_store")?;
        // TODO: can we use `tree_d_size` instead of `Store::len()` here?
        // let tree_d_total_size = Store::len(&tree_d_store);

        // Total number of nodes in TreeD.
        let total_apex_leafs = partition_count * apex_leaf_count;
        // The number of nodes in TreeD from the apex-leafs row to the root.
        let tree_d_size_apex_leafs_to_root = get_merkle_tree_len(total_apex_leafs, tree_d_arity)?;
        // The number of nodes in TreeD below the apex-leafs row.
        let tree_d_size_below_apex_leafs = tree_d_size - tree_d_size_apex_leafs_to_root;
        trace!(
            "Apex-leafs info: total_apex_leafs={}, apex_leafs_per_partition={}",
            total_apex_leafs,
            apex_leaf_count,
        );

        let vanilla_proofs = (0..*partition_count)
            .into_par_iter()
            .map(|k| {
                // Get this partition's apex-leafs.
                let apex_leafs_start = tree_d_size_below_apex_leafs + k * apex_leaf_count;
                let apex_leafs_stop = apex_leafs_start + apex_leaf_count;
                trace!(
                    "apex_leafs_start={} for partition k={}",
                    apex_leafs_start,
                    k
                );
                let apex_leafs: Vec<TreeDDomain> =
                    tree_d_store.read_range(apex_leafs_start..apex_leafs_stop)?;
                info!(
                    "Finished reading apex-leafs from TreeD for partition k={}",
                    k
                );

                let challenges: Vec<usize> =
                    Challenges::new(*sector_nodes, *comm_r_new, k).collect();

                // Generate this partition's challenge proofs.
                let challenge_proofs = challenges
                    .into_par_iter()
                    .map(|c| {
                        let proof_d_new = tree_d_new.gen_proof(c)?;
                        let proof_r_new = tree_r_new.gen_cached_proof(c, tree_r_rows_to_discard)?;
                        let proof_r_old = tree_r_old.gen_cached_proof(c, tree_r_rows_to_discard)?;
                        ensure!(
                            proof_d_new.verify(),
                            "invalid TreeDNew Merkle proof for c={}",
                            c
                        );
                        ensure!(
                            proof_r_new.verify(),
                            "invalid TreeRNew Merkle proof for c={}",
                            c
                        );
                        ensure!(
                            proof_r_old.verify(),
                            "invalid TreeROld Merkle proof for c={}",
                            c
                        );
                        Ok(ChallengeProof {
                            proof_r_old,
                            proof_d_new,
                            proof_r_new,
                        })
                    })
                    .collect::<Result<Vec<ChallengeProof<TreeR>>>>()?;

                info!("Finished generating Merkle proofs for partition k={}", k);

                Ok(PartitionProof {
                    apex_leafs,
                    challenge_proofs,
                })
            })
            .collect::<Result<Vec<PartitionProof<TreeR>>>>()?;

        info!("Finished generating all partition proofs");

        Ok(vanilla_proofs)
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let PublicParams {
            sector_nodes,
            challenge_count,
            challenge_bit_len,
            partition_bit_len,
            apex_leaf_count,
            apex_select_bit_len,
            ..
        } = pub_params;

        let PublicInputs {
            k,
            comm_c,
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h,
        } = pub_inputs;

        let PartitionProof {
            apex_leafs,
            challenge_proofs,
        } = proof;

        if apex_leafs.len() != *apex_leaf_count || challenge_proofs.len() != *challenge_count {
            return Ok(false);
        }

        // Compute apex-tree.
        let mut apex_tree: Vec<Vec<TreeDDomain>> = vec![apex_leafs.clone()];
        for _ in 0..*apex_select_bit_len {
            let tree_row: Vec<TreeDDomain> = apex_tree
                .last()
                .unwrap()
                .chunks(2)
                .map(|siblings| {
                    <TreeDHasher as Hasher>::Function::hash2(&siblings[0], &siblings[1])
                })
                .collect();
            apex_tree.push(tree_row);
        }

        // All TreeDNew Merkle proofs should have an apex-leaf at height `apex_leafs_height` in the
        // proof path.
        let apex_leafs_height = challenge_bit_len - partition_bit_len - apex_select_bit_len;

        let comm_r_last_old = challenge_proofs[0].proof_r_old.root();
        let comm_r_last_new = challenge_proofs[0].proof_r_new.root();

        // Verify that the TreeROld and TreeRNew Merkle proofs roots agree with the public CommC,
        // CommROld, and CommRNew.
        let comm_r_old_calc = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &comm_r_last_old);
        let comm_r_new_calc = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &comm_r_last_new);
        if comm_r_old_calc != *comm_r_old || comm_r_new_calc != *comm_r_new {
            return Ok(false);
        }

        let phi = phi(&comm_d_new, &comm_r_old);

        // AND-mask to strip partition bits from each `c`.
        let remove_k_from_c_mask = (1 << (challenge_bit_len - partition_bit_len)) - 1;

        let challenges = Challenges::new(*sector_nodes, *comm_r_new, *k);

        for (c, challenge_proof) in challenges.zip(challenge_proofs.iter()) {
            // Verify TreeROld Merkle proof.
            if !challenge_proof.verify_merkle_proofs(
                c,
                &comm_r_last_old,
                &comm_d_new,
                &comm_r_last_new,
            ) {
                return Ok(false);
            }

            // Verify replica encoding.
            let label_r_old: Fr = challenge_proof.proof_r_old.leaf().into();
            let label_d_new: Fr = challenge_proof.proof_d_new.leaf().into();
            let label_r_new = challenge_proof.proof_r_new.leaf();
            let c_high = {
                let c_without_k = c & remove_k_from_c_mask;
                let c_high = c_without_k >> (challenge_bit_len - partition_bit_len - h);
                Fr::from(c_high as u64)
            };
            let rho: Fr = <TreeRHasher as Hasher>::Function::hash2(&phi, &c_high.into()).into();
            let label_r_new_calc: TreeRDomain = (label_r_old + label_d_new * rho).into();
            if label_r_new_calc != label_r_new {
                return Ok(false);
            }

            // Verify that TreeDNew Merkle proof and apex-tree agree.
            if !challenge_proof.proof_d_new.path()
                [apex_leafs_height..apex_leafs_height + apex_select_bit_len]
                .iter()
                .zip(apex_tree.iter())
                .all(|(path_elem, apex_tree_row)| apex_tree_row.contains(&path_elem.0[0]))
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        if partition_proofs.len() != pub_params.partition_count {
            return Ok(false);
        }
        for (k, partition_proof) in partition_proofs.iter().enumerate() {
            let mut partition_pub_inputs = pub_inputs.clone();
            partition_pub_inputs.k = k;
            if !Self::verify(pub_params, &partition_pub_inputs, partition_proof)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn with_partition(mut pub_inputs: Self::PublicInputs, k: Option<usize>) -> Self::PublicInputs {
        pub_inputs.k = k.unwrap();
        pub_inputs
    }
}

// `phi = H(comm_d_new, comm_r_old)`
pub fn phi(comm_d_new: &TreeDDomain, comm_r_old: &TreeRDomain) -> TreeRDomain {
    let comm_d_new: TreeRDomain = {
        let comm_d_new: Fr = (*comm_d_new).into();
        comm_d_new.into()
    };
    <TreeRHasher as Hasher>::Function::hash2(&comm_d_new, &comm_r_old)
}

fn mmap_read(path: &Path) -> Result<Mmap, Error> {
    let f_data = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("could not open path={:?}", path))?;
    unsafe {
        MmapOptions::new()
            .map(&f_data)
            .with_context(|| format!("could not mmap path={:?}", path))
    }
}

fn mmap_write(path: &Path) -> Result<MmapMut, Error> {
    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("could not open path={:?}", &path))?;
    unsafe {
        MmapOptions::new()
            .map_mut(&f_data)
            .with_context(|| format!("could not mmap path={:?}", path))
    }
}

// Note: p_aux has comm_c and comm_r_last
// Note: t_aux has labels and tree_d, tree_c, tree_r_last trees
#[allow(clippy::too_many_arguments)]
#[allow(clippy::from_iter_instead_of_collect)]
impl<TreeR> EmptySectorUpdate<TreeR>
where
    TreeR: 'static + MerkleTreeTrait<Hasher = TreeRHasher>,
{
    /// Returns tuple of (comm_r_new, comm_r_last_new, comm_d_new)
    pub fn encode_into(
        nodes_count: usize,
        t_aux: &TemporaryAuxCache<TreeR, TreeDHasher>,
        comm_c: TreeRDomain,
        comm_r_last_old: TreeRDomain,
        new_replica_path: &Path,
        new_cache_path: &Path,
        sector_key_path: &Path,
        sector_key_cache_path: &Path,
        staged_data_path: &Path,
        h: usize,
    ) -> Result<(TreeRDomain, TreeRDomain, TreeDDomain)> {
        // Sanity check all input path types.
        ensure!(
            metadata(new_cache_path)?.is_dir(),
            "new_cache_path must be a directory"
        );
        ensure!(
            metadata(sector_key_cache_path)?.is_dir(),
            "sector_key_cache_path must be a directory"
        );

        let tree_count = get_base_tree_count::<TreeR>();
        let nodes_count = nodes_count / tree_count;

        let new_replica_path_metadata = metadata(new_replica_path)?;
        let sector_key_path_metadata = metadata(sector_key_path)?;
        let staged_data_path_metadata = metadata(staged_data_path)?;

        ensure!(
            new_replica_path_metadata.is_file(),
            "new_replica_path must be a file"
        );
        ensure!(
            sector_key_path_metadata.is_file(),
            "sector_key_path must be a file"
        );
        ensure!(
            staged_data_path_metadata.is_file(),
            "staged_data_path must be a file"
        );
        ensure!(
            new_replica_path_metadata.len() == sector_key_path_metadata.len(),
            "New replica and sector key file size mis-match (must be equal)"
        );
        ensure!(
            staged_data_path_metadata.len() == sector_key_path_metadata.len(),
            "Staged data and sector key file size mis-match (must be equal)"
        );

        info!(
            "new replica path {:?}, len {}",
            new_replica_path,
            new_replica_path_metadata.len()
        );
        info!(
            "sector key path {:?}, len {}",
            sector_key_path,
            sector_key_path_metadata.len()
        );
        info!(
            "staged data path {:?}, len {}",
            staged_data_path,
            staged_data_path_metadata.len()
        );

        // Setup read-only mmaps for sector_key_path and staged_data_path inputs.
        let sector_key_data = mmap_read(sector_key_path)?;
        let staged_data = mmap_read(staged_data_path)?;

        // Setup writable mmap for new_replica_path output.
        let mut new_replica_data = mmap_write(new_replica_path)?;

        // Re-instantiate a t_aux with the new cache path, then use
        // the tree_d and tree_r_last configs from it.
        let mut t_aux_new = t_aux.t_aux.clone();
        t_aux_new.set_cache_path(new_cache_path);

        // With the new cache path set, get the new tree_d and tree_r_last configs.
        let tree_d_config = StoreConfig::from_config(
            &t_aux_new.tree_d_config,
            CacheKey::CommDTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, TreeDArity::to_usize())?),
        );

        let tree_r_last_config = StoreConfig::from_config(
            &t_aux_new.tree_r_last_config,
            CacheKey::CommRLastTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, TreeR::Arity::to_usize())?),
        );
        t_aux_new.tree_d_config = tree_d_config.clone();
        t_aux_new.tree_r_last_config = tree_r_last_config.clone();

        // Re-open staged_data as Data (type)
        let mut new_data = Data::from_path(staged_data_path.to_path_buf());
        new_data.ensure_data()?;

        // Generate tree_d over the staged_data.
        let tree_d = StackedDrg::<TreeR, TreeDHasher>::build_binary_tree::<TreeDHasher>(
            new_data.as_ref(),
            tree_d_config,
        )?;

        let comm_d_new = tree_d.root();

        let comm_r_old = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &comm_r_last_old);
        let phi = phi(&comm_d_new, &comm_r_old);

        let end = staged_data_path_metadata.len() as u64;

        // chunk_size is the number of Fr elements to process in parallel chunks.
        let chunk_size: usize = std::cmp::min(nodes_count, CHUNK_SIZE_MIN);

        // data_block_size is the segment length that we're processing
        // in Fr elements (i.e. chunk_size * sizeof(Fr)).
        let data_block_size: usize = chunk_size * FR_SIZE;

        // AND-mask which strips the partition-index `k` from a node-index.
        let node_index_bit_len = nodes_count.trailing_zeros() as usize;
        let partition_count = partition_count(nodes_count);
        let partition_bit_len = partition_count.trailing_zeros() as usize;
        let remove_k_from_node_index_mask = (1 << (node_index_bit_len - partition_bit_len)) - 1;

        Vec::from_iter((0..end).step_by(data_block_size))
            .into_par_iter()
            .zip(new_replica_data.par_chunks_mut(data_block_size))
            .try_for_each(|(chunk_index, replica_data)| -> Result<()> {
                for i in (0..data_block_size as u64).step_by(FR_SIZE) {
                    let input_index = (chunk_index as usize) + i as usize;
                    let output_index = i as usize;

                    // Get the `h` high bits from the node-index (sans partition-index).
                    let input_index_without_k = input_index & remove_k_from_node_index_mask;
                    let high =
                        input_index_without_k >> (node_index_bit_len - partition_bit_len - h);
                    let rho: Fr = <TreeRHasher as Hasher>::Function::hash2(
                        &phi,
                        &Fr::from(high as u64).into(),
                    )
                    .into();

                    let sector_key_fr =
                        bytes_into_fr(&sector_key_data[input_index..input_index + FR_SIZE])?;
                    let staged_data_fr =
                        bytes_into_fr(&staged_data[input_index..input_index + FR_SIZE])?;

                    let new_replica_fr = sector_key_fr + (staged_data_fr * rho);
                    let new_replica_bytes = fr_into_bytes(&new_replica_fr);

                    replica_data[output_index..output_index + FR_SIZE]
                        .copy_from_slice(&new_replica_bytes);
                }

                Ok(())
            })?;
        new_replica_data.flush()?;

        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            new_replica_path.to_path_buf(),
            nodes_count,
            tree_count,
        )?;

        // Open the new written replica data as a DiskStore.
        let new_replica_store: DiskStore<TreeRDomain> =
            DiskStore::new_from_slice(nodes_count * tree_count, &new_replica_data[0..])?;

        let mut start = 0;
        let mut end = nodes_count;

        for (i, config) in configs.iter().enumerate() {
            let current_data: Vec<TreeRDomain> = new_replica_store.read_range(start..end)?;

            start += nodes_count;
            end += nodes_count;

            info!(
                "building base tree_r_last with CPU {}/{}",
                i + 1,
                tree_count
            );
            LCTree::<TreeRHasher, TreeR::Arity, U0, U0>::from_par_iter_with_config(
                current_data,
                config.clone(),
            )?;
        }

        let tree_r_last = create_lc_tree::<
            LCTree<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
        >(
            tree_r_last_config.size.expect("config size failure"),
            &configs,
            &replica_config,
        )?;

        let comm_r_last_new = tree_r_last.root();
        let comm_r_new = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &comm_r_last_new);

        Ok((comm_r_new, comm_r_last_new, comm_d_new))
    }

    /// Writes the decoded data into out_data_path
    pub fn decode_from(
        nodes_count: usize,
        out_data_path: &Path,
        replica_path: &Path,
        sector_key_path: &Path,
        sector_key_cache_path: &Path,
        comm_c: TreeRDomain,
        comm_d_new: TreeDDomain,
        comm_sector_key: TreeRDomain,
        h: usize,
    ) -> Result<()> {
        // Sanity check all input path types.
        ensure!(
            metadata(sector_key_cache_path)?.is_dir(),
            "sector_key_cache_path must be a directory"
        );

        let tree_count = get_base_tree_count::<TreeR>();
        let nodes_count = nodes_count / tree_count;

        let out_data_path_metadata = metadata(out_data_path)?;
        let replica_path_metadata = metadata(replica_path)?;
        let sector_key_path_metadata = metadata(sector_key_path)?;

        ensure!(
            out_data_path_metadata.is_file(),
            "out_data_path must be a file"
        );
        ensure!(
            replica_path_metadata.is_file(),
            "replica_path must be a file"
        );
        ensure!(
            sector_key_path_metadata.is_file(),
            "sector_key_path must be a file"
        );

        ensure!(
            replica_path_metadata.len() == sector_key_path_metadata.len(),
            "Replica and sector key file size mis-match (must be equal)"
        );

        info!(
            "out data path {:?}, len {}",
            out_data_path,
            out_data_path_metadata.len()
        );
        info!(
            "replica path {:?}, len {}",
            replica_path,
            replica_path_metadata.len()
        );
        info!(
            "sector key path {:?}, len {}",
            sector_key_path,
            sector_key_path_metadata.len()
        );

        // Setup writable mmap for new_replica_path output.
        let mut out_data = mmap_write(out_data_path)?;

        // Setup read-only mmaps for sector_key_path and staged_data_path inputs.
        let replica_data = mmap_read(replica_path)?;
        let sector_key_data = mmap_read(sector_key_path)?;

        let comm_r_old = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &comm_sector_key);
        let phi = phi(&comm_d_new, &comm_r_old);

        let end = replica_path_metadata.len() as u64;

        // chunk_size is the number of Fr elements to process in parallel chunks.
        let chunk_size: usize = std::cmp::min(nodes_count, CHUNK_SIZE_MIN);

        // data_block_size is the segment length that we're processing
        // in Fr elements (i.e. chunk_size * sizeof(Fr)).
        let data_block_size: usize = chunk_size * FR_SIZE;

        // AND-mask which strips the partition-index `k` from a node-index.
        let node_index_bit_len = nodes_count.trailing_zeros() as usize;
        let partition_count = partition_count(nodes_count);
        let partition_bit_len = partition_count.trailing_zeros() as usize;
        let remove_k_from_node_index_mask = (1 << (node_index_bit_len - partition_bit_len)) - 1;

        Vec::from_iter((0..end).step_by(data_block_size))
            .into_par_iter()
            .zip(out_data.par_chunks_mut(data_block_size))
            .try_for_each(|(chunk_index, output_data)| -> Result<()> {
                for i in (0..data_block_size as u64).step_by(FR_SIZE) {
                    let input_index = (chunk_index as usize) + i as usize;
                    let output_index = i as usize;

                    // Get the `h` high bits from the node-index (sans partition-index).
                    let input_index_without_k = input_index & remove_k_from_node_index_mask;
                    let high =
                        input_index_without_k >> (node_index_bit_len - partition_bit_len - h);
                    let rho: Fr = <TreeRHasher as Hasher>::Function::hash2(
                        &phi,
                        &Fr::from(high as u64).into(),
                    )
                    .into();

                    let sector_key_fr =
                        bytes_into_fr(&sector_key_data[input_index..input_index + FR_SIZE])?;
                    let replica_data_fr =
                        bytes_into_fr(&replica_data[input_index..input_index + FR_SIZE])?;

                    let out_data_fr = (replica_data_fr - sector_key_fr) * rho.invert().unwrap();
                    let out_data_bytes = fr_into_bytes(&out_data_fr);

                    output_data[output_index..output_index + FR_SIZE]
                        .copy_from_slice(&out_data_bytes);
                }

                Ok(())
            })?;
        out_data.flush()?;

        Ok(())
    }

    /// Removes encoded data and outputs the sector_key.
    pub fn remove_encoded_data(
        nodes_count: usize,
        sector_key_path: &Path,
        sector_key_cache_path: &Path,
        replica_path: &Path,
        replica_cache_path: &Path,
        data_path: &Path,
        comm_c: TreeRDomain,
        comm_d_new: TreeDDomain,
        comm_sector_key: TreeRDomain,
        h: usize,
    ) -> Result<()> {
        // Sanity check all input path types.
        ensure!(
            metadata(sector_key_cache_path)?.is_dir(),
            "sector_key_cache_path must be a directory"
        );
        ensure!(
            metadata(replica_cache_path)?.is_dir(),
            "replica_cache_path must be a directory"
        );

        let tree_count = get_base_tree_count::<TreeR>();
        let nodes_count = nodes_count / tree_count;

        let data_path_metadata = metadata(data_path)?;
        let replica_path_metadata = metadata(replica_path)?;
        let sector_key_path_metadata = metadata(sector_key_path)?;

        ensure!(data_path_metadata.is_file(), "data_path must be a file");
        ensure!(
            replica_path_metadata.is_file(),
            "replica_path must be a file"
        );
        ensure!(
            sector_key_path_metadata.is_file(),
            "sector_key_path must be a file"
        );

        ensure!(
            replica_path_metadata.len() == sector_key_path_metadata.len(),
            "Replica and sector key file size mis-match (must be equal)"
        );
        ensure!(
            replica_path_metadata.len() == data_path_metadata.len(),
            "Replica and data file size mis-match (must be equal)"
        );

        info!(
            "data path {:?}, len {}",
            data_path,
            data_path_metadata.len()
        );
        info!(
            "replica path {:?}, len {}",
            replica_path,
            replica_path_metadata.len()
        );
        info!(
            "sector key path {:?}, len {}",
            sector_key_path,
            sector_key_path_metadata.len()
        );

        // Setup writable mmap for new_replica_path output.
        let mut sector_key_data = mmap_write(sector_key_path)?;

        // Setup read-only mmaps for sector_key_path and staged_data_path inputs.
        let replica_data = mmap_read(replica_path)?;
        let data = mmap_read(data_path)?;

        let comm_r_old = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &comm_sector_key);
        let phi = phi(&comm_d_new, &comm_r_old);

        let end = replica_path_metadata.len() as u64;

        // chunk_size is the number of Fr elements to process in parallel chunks.
        let chunk_size: usize = std::cmp::min(nodes_count, CHUNK_SIZE_MIN);

        // data_block_size is the segment length that we're processing
        // in Fr elements (i.e. chunk_size * sizeof(Fr)).
        let data_block_size: usize = chunk_size * FR_SIZE;

        // AND-mask which strips the partition-index `k` from a node-index.
        let node_index_bit_len = nodes_count.trailing_zeros() as usize;
        let partition_count = partition_count(nodes_count);
        let partition_bit_len = partition_count.trailing_zeros() as usize;
        let remove_k_from_node_index_mask = (1 << (node_index_bit_len - partition_bit_len)) - 1;

        Vec::from_iter((0..end).step_by(data_block_size))
            .into_par_iter()
            .zip(sector_key_data.par_chunks_mut(data_block_size))
            .try_for_each(|(chunk_index, skey_data)| -> Result<()> {
                for i in (0..data_block_size as u64).step_by(FR_SIZE) {
                    let input_index = (chunk_index as usize) + i as usize;
                    let output_index = i as usize;

                    // Get the `h` high bits from the node-index (sans partition-index).
                    let input_index_without_k = input_index & remove_k_from_node_index_mask;
                    let high =
                        input_index_without_k >> (node_index_bit_len - partition_bit_len - h);
                    let rho: Fr = <TreeRHasher as Hasher>::Function::hash2(
                        &phi,
                        &Fr::from(high as u64).into(),
                    )
                    .into();

                    let data_fr = bytes_into_fr(&data[input_index..input_index + FR_SIZE])?;
                    let replica_data_fr =
                        bytes_into_fr(&replica_data[input_index..input_index + FR_SIZE])?;

                    // sector_key[i] = replica[i] - data[i] * rho
                    let sector_key_fr = replica_data_fr - (data_fr * rho);

                    let sector_key_bytes = fr_into_bytes(&sector_key_fr);
                    skey_data[output_index..output_index + FR_SIZE]
                        .copy_from_slice(&sector_key_bytes);
                }

                Ok(())
            })?;
        sector_key_data.flush()?;

        Ok(())
    }
}
