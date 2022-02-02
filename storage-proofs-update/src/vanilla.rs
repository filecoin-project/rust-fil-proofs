use std::fs::{metadata, OpenOptions};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Error};
use blstrs::Scalar as Fr;
use ff::Field;
use filecoin_hashers::{Domain, HashFunction, Hasher};
use fr32::{bytes_into_fr, fr_into_bytes_slice};
use generic_array::typenum::Unsigned;
use log::{info, trace};
use memmap::{Mmap, MmapMut, MmapOptions};
use merkletree::{
    merkle::{get_merkle_tree_leafs, get_merkle_tree_len},
    store::{DiskStore, Store, StoreConfig},
};
use neptune::Poseidon;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use serde::{Deserialize, Serialize};
use storage_proofs_core::{
    data::Data,
    error::Result,
    merkle::{
        create_base_merkle_tree, create_lc_tree, get_base_tree_count, split_config_and_replica,
        BinaryMerkleTree, LCTree, MerkleProof, MerkleProofTrait, MerkleTreeTrait,
    },
    parameter_cache::ParameterSetMetadata,
    proof::ProofScheme,
};
use storage_proofs_porep::stacked::{StackedDrg, TreeRElementData};

use crate::{
    constants::{
        apex_leaf_count, challenge_count, challenge_count_poseidon, hs, partition_count, TreeD,
        TreeDArity, TreeDDomain, TreeDHasher, TreeDStore, TreeRDomain, TreeRHasher,
        ALLOWED_SECTOR_SIZES, POSEIDON_CONSTANTS_GEN_RANDOMNESS,
    },
    Challenges,
};

const CHUNK_SIZE_MIN: usize = 4096;
const FR_SIZE: usize = std::mem::size_of::<Fr>() as usize;

#[derive(Clone)]
pub struct SetupParams {
    pub sector_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicParams {
    // The sector-size measured in nodes.
    pub sector_nodes: usize,
    // The number of challenges per partition proof.
    pub challenge_count: usize,
    // The number of bits per challenge, i.e. `challenge_bit_len = log2(sector_nodes)`, which is
    // also the height of TreeD.
    pub challenge_bit_len: usize,
    // The number of partition proofs for this sector-size.
    pub partition_count: usize,
    // The bit length of an integer in `0..partition_count` which is also the height of the
    // partitions-tree within TreeD, i.e. the top of TreeD starting from the tree row containing
    // each partition's apex-root and ending at TreeD's root.
    pub partition_bit_len: usize,
    // The number of leafs in the apex-tree.
    pub apex_leaf_count: usize,
    // The bit length of an integer in `0..apex_leaf_count` which is also the height of each
    // partition's apex-tree.
    pub apex_leaf_bit_len: usize,
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
        let apex_leaf_bit_len = apex_leaf_count.trailing_zeros() as usize;

        PublicParams {
            sector_nodes,
            challenge_count,
            challenge_bit_len,
            partition_count,
            partition_bit_len,
            apex_leaf_count,
            apex_leaf_bit_len,
        }
    }

    pub fn from_sector_size_poseidon(sector_bytes: u64) -> Self {
        let sector_nodes = ALLOWED_SECTOR_SIZES
            .iter()
            .copied()
            .find(|allowed_nodes| (allowed_nodes << 5) as u64 == sector_bytes)
            .expect("provided sector-size is not allowed");

        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
        let challenge_count = challenge_count_poseidon(sector_nodes);

        PublicParams {
            sector_nodes,
            challenge_count,
            challenge_bit_len,
            partition_count: 1,
            partition_bit_len: 0,
            apex_leaf_count: 0,
            apex_leaf_bit_len: 0,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    pub k: usize,
    pub comm_r_old: TreeRDomain,
    pub comm_d_new: TreeDDomain,
    pub comm_r_new: TreeRDomain,
    // The number of high bits to take from each challenge's bits. Used to verify replica encoding
    // in the vanilla proof. `h` is only a public-input for the vanilla proof; the circuit takes
    // `h_select` as a public-input rather than `h`.
    pub h: usize,
}

pub struct PrivateInputs {
    pub comm_c: TreeRDomain,
    pub tree_r_old_config: StoreConfig,
    // Path to old replica.
    pub old_replica_path: PathBuf,
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
        c: u32,
        root_r_old: &TreeRDomain,
        comm_d_new: &TreeDDomain,
        root_r_new: &TreeRDomain,
    ) -> bool {
        let c = c as usize;
        self.proof_r_old.path_index() == c
            && self.proof_d_new.path_index() == c
            && self.proof_r_new.path_index() == c
            && self.proof_r_old.root() == *root_r_old
            && self.proof_d_new.root() == *comm_d_new
            && self.proof_r_new.root() == *root_r_new
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
    pub comm_c: TreeRDomain,
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
            comm_c: self.comm_c,
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
    type PrivateInputs = PrivateInputs;
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
        let PublicParams { sector_nodes, .. } = *pub_params;

        let PrivateInputs {
            tree_r_old_config,
            old_replica_path,
            tree_d_new_config,
            tree_r_new_config,
            replica_path,
            ..
        } = priv_inputs;

        let tree_d_new = Self::instantiate_tree_d(sector_nodes, tree_d_new_config)?;
        let tree_r_old = Self::instantiate_tree_r(tree_r_old_config, old_replica_path, "TreeROld")?;
        let tree_r_new = Self::instantiate_tree_r(tree_r_new_config, replica_path, "TreeRNew")?;

        Self::prove_inner(
            pub_params,
            pub_inputs,
            priv_inputs,
            &tree_r_old,
            &tree_d_new,
            &tree_r_new,
        )
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
            ..
        } = *pub_params;

        let PrivateInputs {
            tree_r_old_config,
            old_replica_path,
            tree_d_new_config,
            tree_r_new_config,
            replica_path,
            ..
        } = priv_inputs;

        let tree_d_new = Self::instantiate_tree_d(sector_nodes, tree_d_new_config)?;
        let tree_r_old = Self::instantiate_tree_r(tree_r_old_config, old_replica_path, "TreeROld")?;
        let tree_r_new = Self::instantiate_tree_r(tree_r_new_config, replica_path, "TreeRNew")?;

        let vanilla_proofs = (0..partition_count)
            .into_par_iter()
            .map(|k| {
                let pub_inputs = Self::with_partition(pub_inputs.clone(), Some(k));
                Self::prove_inner(
                    pub_params,
                    &pub_inputs,
                    priv_inputs,
                    &tree_r_old,
                    &tree_d_new,
                    &tree_r_new,
                )
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
            partition_count,
            partition_bit_len,
            apex_leaf_count,
            apex_leaf_bit_len,
        } = *pub_params;

        let PublicInputs {
            k,
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h,
        } = *pub_inputs;

        // Ensure that public-inputs are valid.
        ensure!(
            k < partition_count,
            "partition-index `k` exceeds partition-count for sector-size"
        );
        ensure!(hs(sector_nodes).contains(&h), "invalid `h` for sector-size");

        let PartitionProof {
            comm_c,
            apex_leafs,
            challenge_proofs,
        } = proof;

        // Check for malformed proof.
        ensure!(
            apex_leafs.len() == apex_leaf_count,
            "invalid number of apex-leafs"
        );
        ensure!(
            challenge_proofs.len() == challenge_count,
            "invalid number of challenge proofs"
        );

        // Compute apex-tree.
        let mut apex_tree: Vec<Vec<TreeDDomain>> = vec![apex_leafs.clone()];
        for _ in 0..apex_leaf_bit_len {
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
        // proof path, i.e. TreeDNew has height `challenge_bit_len`, partition-tree has height
        // `partition_bit_len`, and apex-tree has height `apex_leaf_bit_len`.
        let apex_leafs_height = challenge_bit_len - partition_bit_len - apex_leaf_bit_len;

        let root_r_old = challenge_proofs[0].proof_r_old.root();
        let root_r_new = challenge_proofs[0].proof_r_new.root();

        // Verify that the TreeROld and TreeRNew Merkle proofs roots agree with the public CommC,
        // CommROld, and CommRNew.
        let comm_r_old_calc = <TreeRHasher as Hasher>::Function::hash2(comm_c, &root_r_old);
        let comm_r_new_calc = <TreeRHasher as Hasher>::Function::hash2(comm_c, &root_r_new);
        if comm_r_old_calc != comm_r_old || comm_r_new_calc != comm_r_new {
            return Ok(false);
        }

        let phi = phi(&comm_d_new, &comm_r_old);

        let challenges: Vec<u32> = Challenges::new(sector_nodes, comm_r_new, k).collect();
        let get_high_bits_shr = challenge_bit_len - h;

        let challenge_proofs_are_valid = challenges
            .into_par_iter()
            .zip(challenge_proofs.into_par_iter())
            .all(|(c, challenge_proof)| {
                // Verify TreeROld, TreeDNew, and TreeRNew Merkle proofs.
                if !challenge_proof.verify_merkle_proofs(c, &root_r_old, &comm_d_new, &root_r_new) {
                    return false;
                }

                // Verify replica encoding.
                let label_r_old: Fr = challenge_proof.proof_r_old.leaf().into();
                let label_d_new: Fr = challenge_proof.proof_d_new.leaf().into();
                let label_r_new = challenge_proof.proof_r_new.leaf();
                let c_high = c >> get_high_bits_shr;
                let rho = rho(&phi, c_high);
                let label_r_new_calc: TreeRDomain = (label_r_old + label_d_new * rho).into();
                if label_r_new_calc != label_r_new {
                    return false;
                }

                // Check that apex-path is consistent with apex-tree.
                let apex_path = &challenge_proof.proof_d_new.path()
                    [apex_leafs_height..apex_leafs_height + apex_leaf_bit_len];

                apex_path
                    .iter()
                    .zip(apex_tree.iter())
                    .all(|(path_elem, apex_tree_row)| {
                        let sibling = &path_elem.0[0];
                        apex_tree_row.contains(sibling)
                    })
            });

        Ok(challenge_proofs_are_valid)
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        ensure!(
            partition_proofs.len() == pub_params.partition_count,
            "invalid number of partition proofs",
        );
        for (k, partition_proof) in partition_proofs.iter().enumerate() {
            let partition_pub_inputs = Self::with_partition(pub_inputs.clone(), Some(k));
            if !Self::verify(pub_params, &partition_pub_inputs, partition_proof)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn with_partition(mut pub_inputs: Self::PublicInputs, k: Option<usize>) -> Self::PublicInputs {
        pub_inputs.k = k.expect("must provide `k` to generate partition's public-inputs");
        pub_inputs
    }
}

// `phi = H(comm_d_new, comm_r_old)` where Poseidon uses the custom "gen randomness" domain
// separation tag.
#[inline]
pub fn phi<TreeDDomain: Domain>(comm_d_new: &TreeDDomain, comm_r_old: &TreeRDomain) -> TreeRDomain {
    let comm_d_new: Fr = (*comm_d_new).into();
    let comm_r_old: Fr = (*comm_r_old).into();
    Poseidon::new_with_preimage(
        &[comm_d_new, comm_r_old],
        &POSEIDON_CONSTANTS_GEN_RANDOMNESS,
    )
    .hash()
    .into()
}

// `rho = H(phi, high)` where `high` is the `h` high bits of a node-index and Poseidon uses the
// custom "gen randomness" domain separation tag.
#[inline]
pub fn rho(phi: &TreeRDomain, high: u32) -> Fr {
    let phi: Fr = (*phi).into();
    let high = Fr::from(high as u64);
    Poseidon::new_with_preimage(&[phi, high], &POSEIDON_CONSTANTS_GEN_RANDOMNESS).hash()
}

// Computes all `2^h` rho values for the given `phi`. Each rho corresponds to one of the `2^h`
// possible `high` values where `high` is the `h` high bits of a node-index.
#[inline]
pub fn rhos(h: usize, phi: &TreeRDomain) -> Vec<Fr> {
    (0..1 << h).map(|high| rho(phi, high)).collect()
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

#[allow(clippy::too_many_arguments)]
#[allow(clippy::from_iter_instead_of_collect)]
impl<TreeR> EmptySectorUpdate<TreeR>
where
    TreeR: 'static + MerkleTreeTrait<Hasher = TreeRHasher>,
{
    pub fn instantiate_tree_d(
        tree_d_leafs: usize,
        tree_d_new_config: &StoreConfig,
    ) -> Result<TreeD> {
        // Instantiate TreeD new from the replica cache path. Note that this is similar to what
        // we do when going from t_aux to t_aux cache.
        let tree_d_arity = TreeDArity::to_usize();
        let tree_d_nodes = tree_d_new_config.size.expect("config size failure");
        trace!(
            "Instantiating TreeDNew: leafs={}, base_store_size={}",
            tree_d_leafs,
            tree_d_nodes
        );
        let tree_d_store = TreeDStore::new_from_disk(tree_d_nodes, tree_d_arity, tree_d_new_config)
            .context("tree_d_store")?;
        TreeD::from_data_store(tree_d_store, tree_d_leafs).context("tree_d")
    }

    pub fn instantiate_tree_r(
        tree_r_config: &StoreConfig,
        replica_path: &Path,
        name: &str,
    ) -> Result<LCTree<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>> {
        let tree_r_base_arity = TreeR::Arity::to_usize();
        let tree_r_sub_arity = TreeR::SubTreeArity::to_usize();
        let tree_r_top_arity = TreeR::TopTreeArity::to_usize();
        // Instantiate TreeR new from the replica_cache_path. Note that this is similar to what we
        // do when going from t_aux to t_aux cache.
        let tree_r_base_tree_nodes = tree_r_config.size.expect("tree_r config size failure");
        let tree_r_base_tree_leafs =
            get_merkle_tree_leafs(tree_r_base_tree_nodes, tree_r_base_arity)?;
        let tree_r_base_tree_count = get_base_tree_count::<TreeR>();
        let (tree_r_configs, replica_config) = split_config_and_replica(
            tree_r_config.clone(),
            replica_path.to_path_buf(),
            tree_r_base_tree_leafs,
            tree_r_base_tree_count,
        )?;

        trace!(
            "Instantiating {}: arity={}-{}-{}, base_tree_count={}, base_store_size={}",
            name,
            tree_r_base_arity,
            tree_r_sub_arity,
            tree_r_top_arity,
            tree_r_base_tree_count,
            tree_r_base_tree_nodes,
        );

        trace!("ReplicaConfig Path: {:?}", replica_config.path);
        for config in &tree_r_configs {
            trace!(
                "StoreConfig: {:?}",
                StoreConfig::data_path(&config.path, &config.id)
            );
        }
        create_lc_tree::<LCTree<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>>(
            tree_r_base_tree_nodes,
            &tree_r_configs,
            &replica_config,
        )
    }

    // Generates a partition proof given instantiated trees TreeROld, TreeDNew, and TreeRNew.
    pub fn prove_inner(
        pub_params: &PublicParams,
        pub_inputs: &PublicInputs,
        priv_inputs: &PrivateInputs,
        tree_r_old: &LCTree<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
        tree_d_new: &TreeD,
        tree_r_new: &LCTree<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
    ) -> Result<PartitionProof<TreeR>> {
        let PublicParams {
            sector_nodes,
            partition_count,
            apex_leaf_count,
            ..
        } = *pub_params;

        let PublicInputs { k, comm_r_new, .. } = *pub_inputs;

        let PrivateInputs {
            comm_c,
            tree_r_old_config,
            old_replica_path,
            tree_d_new_config,
            replica_path,
            ..
        } = priv_inputs;

        ensure!(
            k < partition_count,
            "partition-index `k` exceeds partition-count for sector-size"
        );

        ensure!(
            metadata(old_replica_path)?.is_file(),
            "old_replica_path must be a file"
        );
        ensure!(
            metadata(replica_path)?.is_file(),
            "replica_path must be a file"
        );

        info!(
            "Proving EmptySectorUpdate vanilla partition (sector_nodes={}, k={})",
            sector_nodes, k,
        );

        let tree_d_arity = TreeDArity::to_usize();

        // Re-instantiate TreeD's store for reading apex leafs.
        let tree_d_nodes = tree_d_new_config.size.expect("config size failure");
        let tree_d_store = TreeDStore::new_from_disk(tree_d_nodes, tree_d_arity, tree_d_new_config)
            .context("tree_d_store")?;
        ensure!(
            tree_d_nodes == Store::len(&tree_d_store),
            "TreeD store size mismatch"
        );

        // Total number of apex-leafs in TreeD.
        let total_apex_leafs = partition_count * apex_leaf_count;
        // The number of nodes in TreeD from the apex-leafs row to the root.
        let tree_d_nodes_apex_leafs_to_root = get_merkle_tree_len(total_apex_leafs, tree_d_arity)?;
        // The number of nodes in TreeD below the apex-leafs row.
        let tree_d_nodes_below_apex_leafs = tree_d_nodes - tree_d_nodes_apex_leafs_to_root;
        trace!(
            "Apex-leafs info: total_apex_leafs={}, apex_leafs_per_partition={}",
            total_apex_leafs,
            apex_leaf_count,
        );

        // Get this partition's apex-leafs.
        let apex_leafs_start = tree_d_nodes_below_apex_leafs + k * apex_leaf_count;
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

        let challenges: Vec<usize> = Challenges::new(sector_nodes, comm_r_new, k)
            .map(|c| c as usize)
            .collect();

        let tree_r_rows_to_discard = Some(tree_r_old_config.rows_to_discard);

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

        info!("finished generating challenge-proofs for partition k={}", k);

        Ok(PartitionProof {
            comm_c: *comm_c,
            apex_leafs,
            challenge_proofs,
        })
    }

    #[cfg(any(feature = "cuda", feature = "opencl"))]
    #[allow(clippy::unnecessary_wraps)]
    fn prepare_tree_r_data(
        source: &DiskStore<TreeRDomain>,
        _data: Option<&mut Data<'_>>,
        start: usize,
        end: usize,
    ) -> Result<TreeRElementData<TreeR>> {
        let tree_data: Vec<TreeRDomain> = source
            .read_range(start..end)
            .expect("failed to read from source");

        if StackedDrg::<TreeR, TreeDHasher>::use_gpu_tree_builder() {
            Ok(TreeRElementData::FrList(
                tree_data.into_par_iter().map(|x| x.into()).collect(),
            ))
        } else {
            Ok(TreeRElementData::ElementList(tree_data))
        }
    }

    #[cfg(not(any(feature = "cuda", feature = "opencl")))]
    #[allow(clippy::unnecessary_wraps)]
    fn prepare_tree_r_data(
        source: &DiskStore<TreeRDomain>,
        _data: Option<&mut Data<'_>>,
        start: usize,
        end: usize,
    ) -> Result<TreeRElementData<TreeR>> {
        let tree_data: Vec<TreeRDomain> = source
            .read_range(start..end)
            .expect("failed to read from source");

        Ok(TreeRElementData::ElementList(tree_data))
    }

    /// Returns tuple of (comm_r_new, comm_r_last_new, comm_d_new)
    pub fn encode_into(
        nodes_count: usize,
        tree_d_new_config: StoreConfig,
        tree_r_last_new_config: StoreConfig,
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
        let base_tree_nodes_count = nodes_count / tree_count;

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
            staged_data_path_metadata.len() >= sector_key_path_metadata.len(),
            "Staged data and sector key file size mis-match (must be equal or greater than)"
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

        // Re-open staged_data as Data (type)
        let mut new_data = Data::from_path(staged_data_path.to_path_buf());
        new_data.ensure_data_of_len(sector_key_path_metadata.len() as usize)?;

        // Generate tree_d over the staged_data.
        let tree_d = create_base_merkle_tree::<BinaryMerkleTree<TreeDHasher>>(
            Some(tree_d_new_config),
            tree_count * base_tree_nodes_count,
            new_data.as_ref(),
        )?;

        let comm_d_new = tree_d.root();

        let comm_r_old = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &comm_r_last_old);
        let phi = phi(&comm_d_new, &comm_r_old);

        let end = staged_data_path_metadata.len() as u64;

        // chunk_size is the number of Fr elements to process in parallel chunks.
        let chunk_size: usize = std::cmp::min(base_tree_nodes_count, CHUNK_SIZE_MIN);

        // data_block_size is the segment length that we're processing
        // in Fr elements (i.e. chunk_size * sizeof(Fr)).
        let data_block_size: usize = chunk_size * FR_SIZE;

        // Right-shift each node-index by `get_high_bits_shr` to get its `h` high bits.
        let node_index_bit_len = nodes_count.trailing_zeros() as usize;
        let get_high_bits_shr = node_index_bit_len - h;

        // Precompute all rho values.
        let rhos = rhos(h, &phi);

        Vec::from_iter((0..end).step_by(data_block_size))
            .into_par_iter()
            .zip(new_replica_data.par_chunks_mut(data_block_size))
            .try_for_each(|(chunk_index, replica_data)| -> Result<()> {
                for i in (0..data_block_size as u64).step_by(FR_SIZE) {
                    let input_index = (chunk_index as usize) + i as usize;
                    let output_index = i as usize;

                    // Get the `h` high bits from the node-index.
                    let node_index = input_index / FR_SIZE;
                    let high = node_index >> get_high_bits_shr;
                    let rho = rhos[high];

                    let sector_key_fr =
                        bytes_into_fr(&sector_key_data[input_index..input_index + FR_SIZE])?;
                    let staged_data_fr =
                        bytes_into_fr(&staged_data[input_index..input_index + FR_SIZE])?;

                    let new_replica_fr = sector_key_fr + (staged_data_fr * rho);
                    fr_into_bytes_slice(
                        &new_replica_fr,
                        &mut replica_data[output_index..output_index + FR_SIZE],
                    );
                }

                Ok(())
            })?;
        new_replica_data.flush()?;

        // Open the new written replica data as a DiskStore.
        let new_replica_store: DiskStore<TreeRDomain> =
            DiskStore::new_from_slice(nodes_count, &new_replica_data[0..])?;

        // This argument is currently unused by this invocation, but required for the API.
        let mut unused_data = Data::empty();

        let tree_r_last = StackedDrg::<TreeR, TreeDHasher>::generate_tree_r_last::<TreeR::Arity>(
            &mut unused_data,
            base_tree_nodes_count,
            tree_count,
            tree_r_last_new_config,
            new_replica_path.to_path_buf(),
            &new_replica_store,
            Some(Self::prepare_tree_r_data),
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
        let base_tree_nodes_count = nodes_count / tree_count;

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
        let chunk_size: usize = std::cmp::min(base_tree_nodes_count, CHUNK_SIZE_MIN);

        // data_block_size is the segment length that we're processing
        // in Fr elements (i.e. chunk_size * sizeof(Fr)).
        let data_block_size: usize = chunk_size * FR_SIZE;

        // Right-shift each node-index by `get_high_bits_shr` to get its `h` high bits.
        let node_index_bit_len = nodes_count.trailing_zeros() as usize;
        let get_high_bits_shr = node_index_bit_len - h;

        // Precompute all rho^-1 values.
        let rho_invs: Vec<Fr> = rhos(h, &phi)
            .into_iter()
            .map(|rho| rho.invert().unwrap())
            .collect();

        Vec::from_iter((0..end).step_by(data_block_size))
            .into_par_iter()
            .zip(out_data.par_chunks_mut(data_block_size))
            .try_for_each(|(chunk_index, output_data)| -> Result<()> {
                for i in (0..data_block_size as u64).step_by(FR_SIZE) {
                    let input_index = (chunk_index as usize) + i as usize;
                    let output_index = i as usize;

                    // Get the `h` high bits from the node-index.
                    let node_index = input_index / FR_SIZE;
                    let high = node_index >> get_high_bits_shr;
                    let rho_inv = rho_invs[high];

                    let sector_key_fr =
                        bytes_into_fr(&sector_key_data[input_index..input_index + FR_SIZE])?;
                    let replica_data_fr =
                        bytes_into_fr(&replica_data[input_index..input_index + FR_SIZE])?;

                    let out_data_fr = (replica_data_fr - sector_key_fr) * rho_inv;
                    fr_into_bytes_slice(
                        &out_data_fr,
                        &mut output_data[output_index..output_index + FR_SIZE],
                    );
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
        tree_r_last_new_config: StoreConfig,
        comm_c: TreeRDomain,
        comm_d_new: TreeDDomain,
        comm_sector_key: TreeRDomain,
        h: usize,
    ) -> Result<TreeRDomain> {
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
        let base_tree_nodes_count = nodes_count / tree_count;

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
            replica_path_metadata.len() <= data_path_metadata.len(),
            "Replica and data file size mis-match (must be equal or less than)"
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
        let chunk_size: usize = std::cmp::min(base_tree_nodes_count, CHUNK_SIZE_MIN);

        // data_block_size is the segment length that we're processing
        // in Fr elements (i.e. chunk_size * sizeof(Fr)).
        let data_block_size: usize = chunk_size * FR_SIZE;

        // Right-shift each node-index by `get_high_bits_shr` to get its `h` high bits.
        let node_index_bit_len = nodes_count.trailing_zeros() as usize;
        let get_high_bits_shr = node_index_bit_len - h;

        // Precompute all rho values.
        let rhos = rhos(h, &phi);

        Vec::from_iter((0..end).step_by(data_block_size))
            .into_par_iter()
            .zip(sector_key_data.par_chunks_mut(data_block_size))
            .try_for_each(|(chunk_index, skey_data)| -> Result<()> {
                for i in (0..data_block_size as u64).step_by(FR_SIZE) {
                    let input_index = (chunk_index as usize) + i as usize;
                    let output_index = i as usize;

                    // Get the `h` high bits from the node-index.
                    let node_index = input_index / FR_SIZE;
                    let high = node_index >> get_high_bits_shr;
                    let rho = rhos[high];

                    let data_fr = bytes_into_fr(&data[input_index..input_index + FR_SIZE])?;
                    let replica_data_fr =
                        bytes_into_fr(&replica_data[input_index..input_index + FR_SIZE])?;

                    let sector_key_fr = replica_data_fr - (data_fr * rho);
                    fr_into_bytes_slice(
                        &sector_key_fr,
                        &mut skey_data[output_index..output_index + FR_SIZE],
                    );
                }

                Ok(())
            })?;
        sector_key_data.flush()?;

        // Open the new written sector_key data as a DiskStore.
        let sector_key_store: DiskStore<TreeRDomain> =
            DiskStore::new_from_slice(nodes_count, &sector_key_data[0..])?;

        // This argument is currently unused by this invocation, but required for the API.
        let mut unused_data = Data::empty();

        let tree_r_last = StackedDrg::<TreeR, TreeDHasher>::generate_tree_r_last::<TreeR::Arity>(
            &mut unused_data,
            base_tree_nodes_count,
            tree_count,
            tree_r_last_new_config,
            sector_key_cache_path.to_path_buf(),
            &sector_key_store,
            Some(Self::prepare_tree_r_data),
        )?;

        Ok(tree_r_last.root())
    }
}
