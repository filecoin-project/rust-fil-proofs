use std::fs::{metadata, File, OpenOptions};
use std::io::Write;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::Path;

use anyhow::{ensure, Context, Error};
use bincode::serialize;
use blstrs::{Bls12, Scalar as Fr};
use ff::{Field, PrimeField};

use filecoin_hashers::poseidon::{PoseidonDomain, PoseidonHasher};
use filecoin_hashers::{sha256::Sha256Hasher, Domain, HashFunction, Hasher};
use fr32::{bytes_into_fr, fr_into_bytes};
use generic_array::typenum::{Unsigned, U0};
use log::{info, trace};
use memmap::{Mmap, MmapMut, MmapOptions};
use merkletree::{
    merkle::{get_merkle_tree_leafs, get_merkle_tree_len},
    store::{DiskStore, ExternalReader, Store, StoreConfig},
};
use rayon::iter::IntoParallelIterator;
use rayon::prelude::*;
use storage_proofs_core::{
    cache_key::CacheKey,
    data::Data,
    error::Result,
    merkle::{
        create_lc_tree, get_base_tree_count, split_config_and_replica, BinaryMerkleTree, LCTree,
        MerkleTreeTrait,
    },
    util::default_rows_to_discard,
};

use storage_proofs_porep::stacked::{StackedDrg, TemporaryAuxCache};

use crate::constants::{apex_leaf_count, challenge_count, partition_count, BINARY_ARITY};
use crate::{
    ChallengeProof, Challenges, EmptySectorUpdateCircuit, MerkleProof, PublicInputs, PublicParams,
};

const CHUNK_SIZE_MIN: usize = 4096;
const FR_SIZE: usize = std::mem::size_of::<Fr>() as usize;

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub struct CCUpdateVanilla<'a, Tree: MerkleTreeTrait, G: Hasher> {
    _a: PhantomData<&'a Tree>,
    _b: PhantomData<&'a G>,
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
impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> CCUpdateVanilla<'a, Tree, G> {
    /// Returns tuple of (new_comm_r, new_comm_r_last, new_comm_d)
    pub fn encode_into(
        nodes_count: usize,
        t_aux: &TemporaryAuxCache<Tree, G>,
        old_comm_c: <Tree::Hasher as Hasher>::Domain,
        old_comm_r_last: <Tree::Hasher as Hasher>::Domain,
        new_replica_path: &Path,
        new_cache_path: &Path,
        sector_key_path: &Path,
        sector_key_cache_path: &Path,
        staged_data_path: &Path,
    ) -> Result<(
        <Tree::Hasher as Hasher>::Domain,
        <Tree::Hasher as Hasher>::Domain,
        G::Domain,
    )> {
        // Sanity check all input path types.
        ensure!(
            metadata(new_cache_path)?.is_dir(),
            "new_cache_path must be a directory"
        );
        ensure!(
            metadata(sector_key_cache_path)?.is_dir(),
            "sector_key_cache_path must be a directory"
        );

        let tree_count = get_base_tree_count::<Tree>();
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
            Some(get_merkle_tree_len(nodes_count, BINARY_ARITY)?),
        );

        let tree_r_last_config = StoreConfig::from_config(
            &t_aux_new.tree_r_last_config,
            CacheKey::CommRLastTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, Tree::Arity::to_usize())?),
        );
        t_aux_new.tree_d_config = tree_d_config.clone();
        t_aux_new.tree_r_last_config = tree_r_last_config.clone();

        // FIXME: Do we need a t_aux written at the new_cache_path for
        // later reference?
        //
        // It can't be instantiated because of the labels, so instead
        // generate_proofs set the new path and pulls just the tree_d
        // and tree_r_last configs from it for proof generation.
        /*
        // Persist new t_aux here in the new_cache_path for later reference.
        let t_aux_path = new_cache_path.join(CacheKey::TAux.to_string());
        let mut f_t_aux = File::create(&t_aux_path)
            .with_context(|| format!("could not create file t_aux={:?}", t_aux_path))?;
        let t_aux_bytes = serialize(&t_aux_new)?;
        f_t_aux
            .write_all(&t_aux_bytes)
            .with_context(|| format!("could not write to file t_aux={:?}", t_aux_path))?;
        println!("WROTE T_AUX NEW AT {:?}", t_aux_path);
         */

        // Re-open staged_data as Data (type)
        let mut new_data: Data<'a> = Data::from_path(staged_data_path.to_path_buf());
        new_data.ensure_data()?;

        // Generate tree_d over the staged_data.
        let tree_d =
            StackedDrg::<Tree, G>::build_binary_tree::<G>(new_data.as_ref(), tree_d_config)?;

        let new_comm_d = tree_d.root();

        // phi = H(comm_d_new || comm_r_old)
        let poseidon_comm_d: PoseidonDomain =
            <PoseidonDomain as Domain>::try_from_bytes(&new_comm_d.into_bytes())?;
        let poseidon_old_comm_r_last: PoseidonDomain =
            <PoseidonDomain as Domain>::try_from_bytes(&old_comm_r_last.into_bytes())?;
        let phi = <PoseidonHasher as Hasher>::Function::hash2(
            &poseidon_comm_d,
            &poseidon_old_comm_r_last,
        );

        let challenge_bits = (nodes_count as f64).log2() as usize;
        let end = staged_data_path_metadata.len() as u64;

        // chunk_size is the number of Fr elements to process in parallel chunks.
        let chunk_size: usize = std::cmp::min(nodes_count, CHUNK_SIZE_MIN);

        // data_block_size is the segment length that we're processing
        // in Fr elements (i.e. chunk_size * sizeof(Fr)).
        let data_block_size: usize = chunk_size * FR_SIZE;

        Vec::from_iter((0..end).step_by(data_block_size))
            .into_par_iter()
            .zip(new_replica_data.par_chunks_mut(data_block_size))
            .try_for_each(|(chunk_index, replica_data)| -> Result<()> {
                for i in (0..data_block_size as u64).step_by(FR_SIZE) {
                    let input_index = (chunk_index as usize) + i as usize;
                    let output_index = i as usize;

                    let shifted = input_index >> (challenge_bits - 1);
                    let rand = <PoseidonHasher as Hasher>::Function::hash2(
                        &phi,
                        &Fr::from(shifted as u64).into(),
                    );
                    let rho = Fr::from(rand);

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

        // Re-open the new replica data as Data type.
        let new_replica_len = metadata(new_replica_path)?.len() as usize;

        let mut start = 0;
        let mut end = nodes_count;

        // Open the new written replica data as a DiskStore.
        let new_replica_store: DiskStore<<Tree::Hasher as Hasher>::Domain> =
            DiskStore::new_from_slice(nodes_count * tree_count, &new_replica_data[0..])?;

        for (i, config) in configs.iter().enumerate() {
            let current_data: Vec<<Tree::Hasher as Hasher>::Domain> =
                new_replica_store.read_range(start..end)?;

            start += nodes_count;
            end += nodes_count;

            info!(
                "building base tree_r_last with CPU {}/{}",
                i + 1,
                tree_count
            );
            LCTree::<Tree::Hasher, Tree::Arity, U0, U0>::from_par_iter_with_config(
                current_data,
                config.clone(),
            )?;
        }

        let tree_r_last = create_lc_tree::<
            LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
        >(
            tree_r_last_config.size.expect("config size failure"),
            &configs,
            &replica_config,
        )?;

        let new_comm_r_last = tree_r_last.root();
        let new_comm_r = <PoseidonHasher as Hasher>::Function::hash2(
            &<PoseidonDomain as Domain>::try_from_bytes(&old_comm_c.into_bytes())?,
            &<PoseidonDomain as Domain>::try_from_bytes(&new_comm_r_last.into_bytes())?,
        );

        Ok((
            <Tree::Hasher as Hasher>::Domain::try_from_bytes(&new_comm_r.into_bytes())?,
            new_comm_r_last,
            new_comm_d,
        ))
    }

    /// Writes the decoded data into out_data_path
    pub fn decode_from(
        nodes_count: usize,
        out_data_path: &Path,
        replica_path: &Path,
        sector_key_path: &Path,
        sector_key_cache_path: &Path,
        comm_d: G::Domain,
        comm_r: <Tree::Hasher as Hasher>::Domain,
        comm_sector_key: <Tree::Hasher as Hasher>::Domain,
    ) -> Result<()> {
        // Sanity check all input path types.
        ensure!(
            metadata(sector_key_cache_path)?.is_dir(),
            "sector_key_cache_path must be a directory"
        );

        let tree_count = get_base_tree_count::<Tree>();
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

        let poseidon_comm_d: PoseidonDomain =
            <PoseidonDomain as Domain>::try_from_bytes(&comm_d.into_bytes())?;
        let poseidon_old_comm_r_last: PoseidonDomain =
            <PoseidonDomain as Domain>::try_from_bytes(&comm_sector_key.into_bytes())?;
        let phi = <PoseidonHasher as Hasher>::Function::hash2(
            &poseidon_comm_d,
            &poseidon_old_comm_r_last,
        );

        let challenge_bits = (nodes_count as f64).log2() as usize;
        let end = replica_path_metadata.len() as u64;

        // chunk_size is the number of Fr elements to process in parallel chunks.
        let chunk_size: usize = std::cmp::min(nodes_count, CHUNK_SIZE_MIN);

        // data_block_size is the segment length that we're processing
        // in Fr elements (i.e. chunk_size * sizeof(Fr)).
        let data_block_size: usize = chunk_size * FR_SIZE;

        Vec::from_iter((0..end).step_by(data_block_size))
            .into_par_iter()
            .zip(out_data.par_chunks_mut(data_block_size))
            .try_for_each(|(chunk_index, output_data)| -> Result<()> {
                for i in (0..data_block_size as u64).step_by(FR_SIZE) {
                    let input_index = (chunk_index as usize) + i as usize;
                    let output_index = i as usize;

                    let shifted = input_index >> (challenge_bits - 1);
                    let rand = <PoseidonHasher as Hasher>::Function::hash2(
                        &phi,
                        &Fr::from(shifted as u64).into(),
                    );
                    let rho = Fr::from(rand);

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
        comm_d: G::Domain,
        comm_r: <Tree::Hasher as Hasher>::Domain,
        comm_sector_key: <Tree::Hasher as Hasher>::Domain,
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

        let tree_count = get_base_tree_count::<Tree>();
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

        let poseidon_comm_d: PoseidonDomain =
            <PoseidonDomain as Domain>::try_from_bytes(&comm_d.into_bytes())?;
        let poseidon_old_comm_r_last: PoseidonDomain =
            <PoseidonDomain as Domain>::try_from_bytes(&comm_sector_key.into_bytes())?;
        let phi = <PoseidonHasher as Hasher>::Function::hash2(
            &poseidon_comm_d,
            &poseidon_old_comm_r_last,
        );

        let challenge_bits = (nodes_count as f64).log2() as usize;
        let end = replica_path_metadata.len() as u64;

        // chunk_size is the number of Fr elements to process in parallel chunks.
        let chunk_size: usize = std::cmp::min(nodes_count, CHUNK_SIZE_MIN);

        // data_block_size is the segment length that we're processing
        // in Fr elements (i.e. chunk_size * sizeof(Fr)).
        let data_block_size: usize = chunk_size * FR_SIZE;

        Vec::from_iter((0..end).step_by(data_block_size))
            .into_par_iter()
            .zip(sector_key_data.par_chunks_mut(data_block_size))
            .try_for_each(|(chunk_index, skey_data)| -> Result<()> {
                for i in (0..data_block_size as u64).step_by(FR_SIZE) {
                    let input_index = (chunk_index as usize) + i as usize;
                    let output_index = i as usize;

                    let shifted = input_index >> (challenge_bits - 1);
                    let rand = <PoseidonHasher as Hasher>::Function::hash2(
                        &phi,
                        &Fr::from(shifted as u64).into(),
                    );
                    let rho = Fr::from(rand);

                    let data_fr = bytes_into_fr(&data[input_index..input_index + FR_SIZE])?;
                    let replica_data_fr =
                        bytes_into_fr(&replica_data[input_index..input_index + FR_SIZE])?;

                    // sector_key[i] = replica[i] - data[i] * rand[i]
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

    /// Returns the update proof challenges required for the specified partition.
    pub fn get_update_proof_challenges(
        nodes_count: usize,
        partition: usize,
        partition_challenges: usize,
        comm_r_new: <Tree::Hasher as Hasher>::Domain,
    ) -> Result<Vec<usize>> {
        let challenges: Vec<usize> = Challenges::<PoseidonHasher>::new(
            nodes_count,
            <PoseidonDomain as Domain>::try_from_bytes(&comm_r_new.into_bytes())?,
            partition,
        )
        .collect();

        assert_eq!(challenges.len(), partition_challenges);

        Ok(challenges)
    }

    pub fn generate_update_proofs(
        nodes_count: usize,
        pub_params: PublicParams,
        pub_inputs: PublicInputs<Tree>,
        t_aux_old: &TemporaryAuxCache<Tree, Sha256Hasher>,
        tree_d_config: StoreConfig,
        tree_r_last_config: StoreConfig,
        comm_c_old: <Tree::Hasher as Hasher>::Domain,
        comm_r_old: <Tree::Hasher as Hasher>::Domain,
        comm_r_last_old: <Tree::Hasher as Hasher>::Domain,
        comm_r_last_new: <Tree::Hasher as Hasher>::Domain,
        replica_path: &Path,
        replica_cache_path: &Path,
    ) -> Result<()> {
        let new_comm_r = <PoseidonHasher as Hasher>::Function::hash2(
            &<PoseidonDomain as Domain>::try_from_bytes(&comm_c_old.into_bytes())?,
            &<PoseidonDomain as Domain>::try_from_bytes(&comm_r_last_new.into_bytes())?,
        );

        let tree_count = get_base_tree_count::<Tree>();

        // Instantiate Tree-D new from the replica cache path.  Note
        // that this is similar to what we do when going from t_aux to
        // t_aux cache.
        let tree_d_size = tree_d_config.size.expect("config size failure");
        let tree_d_leafs = get_merkle_tree_leafs(tree_d_size, BINARY_ARITY)?;
        trace!(
            "Instantiating tree d with size {} and leafs {}",
            tree_d_size,
            tree_d_leafs,
        );
        let tree_d_store: DiskStore</*G*/ <Sha256Hasher as Hasher>::Domain> =
            DiskStore::new_from_disk(tree_d_size, BINARY_ARITY, &tree_d_config)
                .context("tree_d_store")?;
        let tree_d =
            BinaryMerkleTree::</*G*/ Sha256Hasher>::from_data_store(tree_d_store, tree_d_leafs)
                .context("tree_d")?;

        // Instantiate Tree-R new from the replica_cache_path.  Note
        // that this is similar to what we do when going from t_aux to
        // t_aux cache.
        // tree_r_last_size stored in the config is the base tree size
        let tree_r_last_size = tree_r_last_config.size.expect("config size failure");
        let tree_r_last_config_rows_to_discard = tree_r_last_config.rows_to_discard;
        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            replica_path.to_path_buf(),
            get_merkle_tree_leafs(tree_r_last_size, Tree::Arity::to_usize())?,
            tree_count,
        )?;

        trace!(
            "Instantiating tree r last [count {}] with size {} and arity {}, {}, {}",
            tree_count,
            tree_r_last_size,
            Tree::Arity::to_usize(),
            Tree::SubTreeArity::to_usize(),
            Tree::TopTreeArity::to_usize(),
        );
        let tree_r_last = create_lc_tree::<
            LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
        >(tree_r_last_size, &configs, &replica_config)?;

        // FIXME: tree_d merkle tree borrowed the store, so
        // re-instantiate it here for reading apex leaves.
        let tree_d_store: DiskStore</*G*/ <Sha256Hasher as Hasher>::Domain> =
            DiskStore::new_from_disk(tree_d_size, BINARY_ARITY, &tree_d_config)
                .context("tree_d_store")?;
        let tree_d_total_size = Store::len(&tree_d_store);

        let partitions = partition_count(nodes_count);
        let partition_nodes = nodes_count / partitions;
        let partition_challenges = challenge_count(nodes_count);
        let rows_to_discard = Some(default_rows_to_discard(
            nodes_count,
            Tree::Arity::to_usize(),
        ));

        let apex_leaves_per_partition = apex_leaf_count(nodes_count);
        let total_apex_leaves = apex_leaves_per_partition * partitions;
        let total_apex_tree_len = get_merkle_tree_len(total_apex_leaves, BINARY_ARITY)?;
        info!(
            "{} apex_leaves_per_partition for {} nodes",
            apex_leaves_per_partition, nodes_count
        );
        info!(
            "total apex leaves = {}, total nodes in tree_d = {}",
            total_apex_leaves, tree_d_total_size
        );

        for k in 0..partitions {
            let challenges = Self::get_update_proof_challenges(
                nodes_count,
                k,
                partition_challenges,
                <Tree::Hasher as Hasher>::Domain::try_from_bytes(&new_comm_r.into_bytes())?,
            )?;
            assert_eq!(challenges.len(), partition_challenges);

            // Gather all apex leaves per partition
            let apex_leaf_offset_from_end =
                (tree_d_total_size - total_apex_tree_len) + (k * apex_leaves_per_partition);
            info!(
                "apex_leaves_offset_from_end for partition {} is {}",
                k, apex_leaf_offset_from_end
            );
            let start = apex_leaf_offset_from_end;
            let end = apex_leaf_offset_from_end + apex_leaves_per_partition;
            let apex_leaves: Vec</*G*/ <Sha256Hasher as Hasher>::Domain> =
                tree_d_store.read_range(start..end)?;
            info!(
                "read {} apex leafs for partition {} from store nodes {}-{}",
                apex_leaves.len(),
                k,
                start,
                end
            );

            // Generate all merkle proofs (FIXME: par iter)
            let vanilla_proofs: Vec<Result<ChallengeProof<Tree>>> = challenges
                .iter()
                .map(|challenge| {
                    let proof_d_new: MerkleProof<BinaryMerkleTree</*G*/ Sha256Hasher>> =
                        tree_d.gen_proof(*challenge)?;
                    let proof_r_new: MerkleProof<Tree> =
                        tree_r_last.gen_cached_proof(*challenge, rows_to_discard)?;
                    let proof_r_old: MerkleProof<Tree> = t_aux_old
                        .tree_r_last
                        .gen_cached_proof(*challenge, rows_to_discard)?;

                    Ok(ChallengeProof::from_merkle_proofs(
                        proof_r_old,
                        proof_d_new,
                        proof_r_new,
                    ))
                })
                .collect();

            info!(
                "got {} challenge proofs for partition {}",
                vanilla_proofs.len(),
                k
            );

            /*
                let circuit = EmptySectorUpdateCircuit {
                pub_params,
                k: Some(pub_inputs.k),
                comm_r_old: Some(pub_inputs.comm_r_old),
                comm_d_new: Some(pub_inputs.comm_d_new),
                comm_r_new: Some(pub_inputs.comm_r_new),
                h_select: Some(pub_inputs.h_select),
                comm_c: Some(comm_c_old),
                comm_r_last_old,
                comm_r_last_new,
                apex_leaves,
                partition_path,
                challenge_proofs,
            };
                circuit.synthesize()?;
                 */
        }

        // FIXME: return proof(s)
        Ok(())
    }
}
