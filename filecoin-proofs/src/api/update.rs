use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{self, File};
use std::io::{Read, Seek, Write};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use bincode::{deserialize, serialize};
use blstrs::Scalar as Fr;
use ff::{Field, PrimeField};
use filecoin_hashers::{Domain, Hasher};
use generic_array::typenum::Unsigned;
use log::{info, trace};
use merkletree::merkle::get_merkle_tree_len;
use merkletree::store::StoreConfig;
use storage_proofs_core::{
    cache_key::CacheKey,
    compound_proof::{self, CompoundProof},
    merkle::{get_base_tree_count, MerkleTreeTrait},
    multi_proof::MultiProof,
    proof::ProofScheme,
    util::NODE_SIZE,
};
use storage_proofs_porep::stacked::{PersistentAux, TemporaryAux};
use storage_proofs_update::{
    constants::TreeDArity, constants::TreeRHasher, phi, rho, EmptySectorUpdate,
    EmptySectorUpdateCompound, PartitionProof, PrivateInputs, PublicInputs, PublicParams,
    SetupParams,
};

use crate::{
    caches::{get_empty_sector_update_params, get_empty_sector_update_verifying_key},
    constants::{DefaultPieceDomain, DefaultPieceHasher},
    pieces::verify_pieces,
    types::{
        Commitment, EmptySectorUpdateEncoded, EmptySectorUpdateProof, PieceInfo, PoRepConfig,
        SectorUpdateConfig,
    },
};

// Instantiates p_aux from the specified cache_dir for access to comm_c and comm_r_last
fn get_p_aux<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    cache_path: &Path,
) -> Result<PersistentAux<<Tree::Hasher as Hasher>::Domain>> {
    let p_aux_path = cache_path.join(CacheKey::PAux.to_string());
    let p_aux_bytes = fs::read(&p_aux_path)
        .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

    let p_aux = deserialize(&p_aux_bytes)?;

    Ok(p_aux)
}

fn persist_p_aux<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    p_aux: &PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    cache_path: &Path,
) -> Result<()> {
    let p_aux_path = cache_path.join(CacheKey::PAux.to_string());
    let mut f_p_aux = File::create(&p_aux_path)
        .with_context(|| format!("could not create file p_aux={:?}", p_aux_path))?;
    let p_aux_bytes = serialize(&p_aux)?;
    f_p_aux
        .write_all(&p_aux_bytes)
        .with_context(|| format!("could not write to file p_aux={:?}", p_aux_path))?;

    Ok(())
}

// Instantiates t_aux from the specified cache_dir for access to
// labels and tree_d, tree_c, tree_r_last store configs
fn get_t_aux<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    cache_path: &Path,
) -> Result<TemporaryAux<Tree, DefaultPieceHasher>> {
    let t_aux_path = cache_path.join(CacheKey::TAux.to_string());
    trace!("Instantiating TemporaryAux from {:?}", cache_path);
    let t_aux_bytes = fs::read(&t_aux_path)
        .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

    let mut res: TemporaryAux<Tree, DefaultPieceHasher> = deserialize(&t_aux_bytes)?;
    res.set_cache_path(cache_path);
    trace!("Set TemporaryAux cache_path to {:?}", cache_path);

    Ok(res)
}

fn persist_t_aux<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    t_aux: &TemporaryAux<Tree, DefaultPieceHasher>,
    cache_path: &Path,
) -> Result<()> {
    let t_aux_path = cache_path.join(CacheKey::TAux.to_string());
    let mut f_t_aux = File::create(&t_aux_path)
        .with_context(|| format!("could not create file t_aux={:?}", t_aux_path))?;
    let t_aux_bytes = serialize(&t_aux)?;
    f_t_aux
        .write_all(&t_aux_bytes)
        .with_context(|| format!("could not write to file t_aux={:?}", t_aux_path))?;

    Ok(())
}

// Re-instantiate a t_aux with the new cache path, then use the tree_d
// and tree_r_last configs from it.  This is done to preserve the
// original tree configuration info (in particular, the
// 'rows_to_discard' value) rather than re-setting it to the default
// in case it was not created with the default.
//
// If we are sure that this doesn't matter, it would be much simpler
// to just create new configs, e.g. StoreConfig::new(new_cache_path,
// ...)
//
// Returns a pair of the new tree_d_config and tree_r_last configs
fn get_new_configs_from_t_aux_old<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    t_aux_old: &TemporaryAux<Tree, DefaultPieceHasher>,
    new_cache_path: &Path,
    nodes_count: usize,
) -> Result<(StoreConfig, StoreConfig)> {
    let mut t_aux_new = t_aux_old.clone();
    t_aux_new.set_cache_path(new_cache_path);

    let tree_count = get_base_tree_count::<Tree>();
    let base_tree_nodes_count = nodes_count / tree_count;

    // With the new cache path set, formulate the new tree_d and
    // tree_r_last configs.
    let tree_d_new_config = StoreConfig::from_config(
        &t_aux_new.tree_d_config,
        CacheKey::CommDTree.to_string(),
        Some(get_merkle_tree_len(nodes_count, TreeDArity::to_usize())?),
    );

    let tree_r_last_new_config = StoreConfig::from_config(
        &t_aux_new.tree_r_last_config,
        CacheKey::CommRLastTree.to_string(),
        Some(get_merkle_tree_len(
            base_tree_nodes_count,
            Tree::Arity::to_usize(),
        )?),
    );

    Ok((tree_d_new_config, tree_r_last_new_config))
}

/// Encodes data into an existing replica.  The original replica is
/// not modified and the resulting output data is written as
/// new_replica_path (with required artifacts located in
/// new_cache_path).
#[allow(clippy::too_many_arguments)]
pub fn encode_into<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    porep_config: &PoRepConfig,
    new_replica_path: &Path,
    new_cache_path: &Path,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    staged_data_path: &Path,
    piece_infos: &[PieceInfo],
) -> Result<EmptySectorUpdateEncoded> {
    info!("encode_into:start");
    let config = SectorUpdateConfig::from_porep_config(porep_config);

    let p_aux = get_p_aux::<Tree>(sector_key_cache_path)?;
    let t_aux = get_t_aux::<Tree>(sector_key_cache_path)?;

    let (tree_d_new_config, tree_r_last_new_config) =
        get_new_configs_from_t_aux_old::<Tree>(&t_aux, new_cache_path, config.nodes_count)?;

    let (comm_r_domain, comm_r_last_domain, comm_d_domain) =
        EmptySectorUpdate::<Tree>::encode_into(
            config.nodes_count,
            tree_d_new_config,
            tree_r_last_new_config,
            <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_c.into_bytes())?,
            <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_r_last.into_bytes())?,
            new_replica_path,
            new_cache_path,
            sector_key_path,
            sector_key_cache_path,
            staged_data_path,
            usize::from(config.h_select),
        )?;

    let mut comm_d = [0; 32];
    let mut comm_r = [0; 32];
    let mut comm_r_last = [0; 32];

    comm_d_domain.write_bytes(&mut comm_d)?;
    comm_r_domain.write_bytes(&mut comm_r)?;
    comm_r_last_domain.write_bytes(&mut comm_r_last)?;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
    ensure!(
        comm_r_last != [0; 32],
        "Invalid all zero commitment (comm_r)"
    );
    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.sector_size)?,
        "pieces and comm_d do not match"
    );

    // Persist p_aux and t_aux into the new_cache_path here
    let mut p_aux = p_aux;
    p_aux.comm_r_last = comm_r_last_domain;
    persist_p_aux::<Tree>(&p_aux, new_cache_path)?;
    persist_t_aux::<Tree>(&t_aux, new_cache_path)?;

    info!("encode_into:finish");

    Ok(EmptySectorUpdateEncoded {
        comm_r_new: comm_r,
        comm_r_last_new: comm_r_last,
        comm_d_new: comm_d,
    })
}

/// Reverses the encoding process and outputs the data into out_data_path.
#[allow(clippy::too_many_arguments)]
pub fn decode_from<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    config: SectorUpdateConfig,
    out_data_path: &Path,
    replica_path: &Path,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    comm_d_new: Commitment,
) -> Result<()> {
    info!("decode_from:start");

    let p_aux = get_p_aux::<Tree>(sector_key_cache_path)?;

    let nodes_count = config.nodes_count;
    EmptySectorUpdate::<Tree>::decode_from(
        nodes_count,
        out_data_path,
        replica_path,
        sector_key_path,
        sector_key_cache_path,
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_c.into_bytes())?,
        comm_d_new.into(),
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_r_last.into_bytes())?,
        usize::from(config.h_select),
    )?;

    info!("decode_from:finish");
    Ok(())
}

/// Removes encoded data and outputs the sector key.
#[allow(clippy::too_many_arguments)]
pub fn remove_encoded_data<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    config: SectorUpdateConfig,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
    data_path: &Path,
    comm_d_new: Commitment,
) -> Result<()> {
    info!("remove_data:start");

    let p_aux = get_p_aux::<Tree>(replica_cache_path)?;
    let t_aux = get_t_aux::<Tree>(replica_cache_path)?;

    let (_, tree_r_last_new_config) =
        get_new_configs_from_t_aux_old::<Tree>(&t_aux, sector_key_cache_path, config.nodes_count)?;

    let nodes_count = config.nodes_count;
    let tree_r_last_new = EmptySectorUpdate::<Tree>::remove_encoded_data(
        nodes_count,
        sector_key_path,
        sector_key_cache_path,
        replica_path,
        replica_cache_path,
        data_path,
        tree_r_last_new_config,
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_c.into_bytes())?,
        comm_d_new.into(),
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_r_last.into_bytes())?,
        usize::from(config.h_select),
    )?;

    // Persist p_aux and t_aux into the sector_key_cache_path here
    let mut p_aux = p_aux;
    p_aux.comm_r_last = tree_r_last_new;
    persist_p_aux::<Tree>(&p_aux, sector_key_cache_path)?;
    persist_t_aux::<Tree>(&t_aux, sector_key_cache_path)?;

    info!("remove_data:finish");
    Ok(())
}

/// Computes and returns the empty-sector-update encoding of the next `num_nodes` of the provided
/// updated data file (sometimes called "data-new").
///
/// This function assumes that both the data file and sector update key file (i.e. the sealing
/// replica file, sometimes called "replica-old", of the original empty sector) have been seeked
/// (by this function's caller) to the desired offset.
pub fn encode_updated_data_range(
    data_new_file: &mut File,
    replica_old_file: &mut File,
    num_nodes: usize,
    config: &SectorUpdateConfig,
    comm_d_new: [u8; 32],
    comm_r_old: [u8; 32],
) -> Result<Vec<u8>> {
    let num_bytes = num_nodes * NODE_SIZE;

    let start_node = {
        let file_offset = data_new_file
            .stream_position()
            .with_context(|| "failed to get data-new file offset")?;
        file_offset as usize / NODE_SIZE
    };
    let stop_node = start_node + num_nodes;

    let phi = {
        let comm_d_new = DefaultPieceDomain::try_from_bytes(&comm_d_new)
            .with_context(|| "failed to convert CommDNew bytes into TreeD domain")?;
        let comm_r_old = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)
            .with_context(|| "failed to convert CommROld bytes into TreeR domain")?;
        phi(&comm_d_new, &comm_r_old)
    };

    let high_shr = {
        let sector_nodes = u64::from(config.sector_size) as usize / NODE_SIZE;
        let node_index_bit_len = sector_nodes.trailing_zeros() as usize;
        let h = usize::from(config.h_select);
        node_index_bit_len - h
    };

    let rhos: HashMap<usize, Fr> = {
        let first_high = start_node >> high_shr;
        let last_high = (stop_node - 1) >> high_shr;
        (first_high..=last_high)
            .map(|high| (high, rho(&phi, high as u32)))
            .collect()
    };

    let data_bytes = {
        let mut buf = vec![0u8; num_bytes];
        data_new_file
            .read_exact(&mut buf)
            .with_context(|| format!("failed to read {} bytes from data-new file", num_bytes))?;
        buf
    };

    // Key bytes will also be used to store the encoded data.
    let mut key_bytes = {
        let mut buf = vec![0u8; num_bytes];
        replica_old_file
            .read_exact(&mut buf)
            .with_context(|| format!("failed to read {} bytes from replica-old file", num_bytes))?;
        buf
    };

    for ((node_index, data_bytes), key_bytes) in (start_node..stop_node)
        .zip(data_bytes.chunks(NODE_SIZE))
        .zip(key_bytes.chunks_mut(NODE_SIZE))
    {
        let data_fr = Fr::from_repr_vartime(
            data_bytes
                .try_into()
                .expect("32-byte slice to array conversion should not fail"),
        )
        .with_context(|| "32-byte chunk of data-new file is invalid field repr")?;

        let key_fr = Fr::from_repr_vartime(
            key_bytes
                .try_into()
                .expect("32-byte slice to array conversion should not fail"),
        )
        .with_context(|| "32-byte chunk of replica-old file is invalid field repr")?;

        let high = node_index >> high_shr;
        let rho = rhos[&high];
        let replica_fr = key_fr + (data_fr * rho);
        key_bytes.copy_from_slice(&replica_fr.to_repr());
    }

    let replica_bytes = key_bytes;
    Ok(replica_bytes)
}

/// Computes and returns the empty-sector-update decoding of the next `num_nodes` of the provided
/// updated replica file (sometimes called "replica-new").
///
/// This function assumes that both the replica file and sector update key file (i.e. the sealing
/// replica file, sometimes called "replica-old", of the original empty sector) have been seeked (by
/// this function's caller) to the desired offset.
pub fn decode_updated_replica_range(
    replica_new_file: &mut File,
    replica_old_file: &mut File,
    num_nodes: usize,
    config: &SectorUpdateConfig,
    comm_d_new: [u8; 32],
    comm_r_old: [u8; 32],
) -> Result<Vec<u8>> {
    let num_bytes = num_nodes * NODE_SIZE;

    let start_node = {
        let file_offset = replica_new_file
            .stream_position()
            .with_context(|| "failed to get replica-new file offset")?;
        file_offset as usize / NODE_SIZE
    };
    let stop_node = start_node + num_nodes;

    let phi = {
        let comm_d_new = DefaultPieceDomain::try_from_bytes(&comm_d_new)
            .with_context(|| "failed to convert CommDNew bytes into TreeD domain")?;
        let comm_r_old = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)
            .with_context(|| "failed to convert CommROld bytes into TreeR domain")?;
        phi(&comm_d_new, &comm_r_old)
    };

    let high_shr = {
        let sector_nodes = u64::from(config.sector_size) as usize / NODE_SIZE;
        let node_index_bit_len = sector_nodes.trailing_zeros() as usize;
        let h = usize::from(config.h_select);
        node_index_bit_len - h
    };

    let rho_invs: HashMap<usize, Fr> = {
        let first_high = start_node >> high_shr;
        let last_high = (stop_node - 1) >> high_shr;
        (first_high..=last_high)
            .map(|high| {
                (
                    high,
                    rho(&phi, high as u32)
                        .invert()
                        .expect("rho inversion should not fail"),
                )
            })
            .collect()
    };

    let replica_bytes = {
        let mut buf = vec![0u8; num_bytes];
        replica_new_file
            .read_exact(&mut buf)
            .with_context(|| format!("failed to read {} bytes from replica-new file", num_bytes))?;
        buf
    };

    // Key bytes will also be used to store the decoded data.
    let mut key_bytes = {
        let mut buf = vec![0u8; num_bytes];
        replica_old_file
            .read_exact(&mut buf)
            .with_context(|| format!("failed to read {} bytes from replica-old file", num_bytes))?;
        buf
    };

    for ((node_index, replica_bytes), key_bytes) in (start_node..stop_node)
        .zip(replica_bytes.chunks(NODE_SIZE))
        .zip(key_bytes.chunks_mut(NODE_SIZE))
    {
        let replica_fr = Fr::from_repr_vartime(
            replica_bytes
                .try_into()
                .expect("32-byte slice to array conversion should not fail"),
        )
        .with_context(|| "32-byte chunk of replica-new file is invalid field repr")?;

        let key_fr = Fr::from_repr_vartime(
            key_bytes
                .try_into()
                .expect("32-byte slice to array conversion should not fail"),
        )
        .with_context(|| "32-byte chunk of replica-old file is invalid field repr")?;

        let high = node_index >> high_shr;
        let rho_inv = rho_invs[&high];
        let data_fr = (replica_fr - key_fr) * rho_inv;
        key_bytes.copy_from_slice(&data_fr.to_repr());
    }

    let data_bytes = key_bytes;
    Ok(data_bytes)
}

/// Generate a single vanilla partition proof for a specified partition.
#[allow(clippy::too_many_arguments)]
pub fn generate_single_partition_proof<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    config: SectorUpdateConfig,
    partition_index: usize,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
) -> Result<PartitionProof<Tree>> {
    info!("generate_single_partition_proof:start");

    let comm_r_old_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let public_params: storage_proofs_update::PublicParams =
        PublicParams::from_sector_size(u64::from(config.sector_size));

    let p_aux_old = get_p_aux::<Tree>(sector_key_cache_path)?;

    let partitions = usize::from(config.update_partitions);
    ensure!(partition_index < partitions, "invalid partition index");

    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: partition_index,
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: usize::from(config.h_select),
    };

    let t_aux_old = get_t_aux::<Tree>(sector_key_cache_path)?;

    let (tree_d_new_config, tree_r_last_new_config) =
        get_new_configs_from_t_aux_old::<Tree>(&t_aux_old, replica_cache_path, config.nodes_count)?;

    let private_inputs: PrivateInputs = PrivateInputs {
        comm_c: p_aux_old.comm_c,
        tree_r_old_config: t_aux_old.tree_r_last_config,
        old_replica_path: sector_key_path.to_path_buf(),
        tree_d_new_config,
        tree_r_new_config: tree_r_last_new_config,
        replica_path: replica_path.to_path_buf(),
    };

    let partition_proof =
        EmptySectorUpdate::<Tree>::prove(&public_params, &public_inputs, &private_inputs)?;

    info!("generate_single_partition_proof:finish");

    Ok(partition_proof)
}

/// Verify a single vanilla partition proof for a specified partition.
#[allow(clippy::too_many_arguments)]
pub fn verify_single_partition_proof<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    config: SectorUpdateConfig,
    partition_index: usize,
    proof: PartitionProof<Tree>,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
) -> Result<bool> {
    info!("verify_single_partition_proof:start");

    let comm_r_old_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let public_params: storage_proofs_update::PublicParams =
        PublicParams::from_sector_size(u64::from(config.sector_size));

    let partitions = usize::from(config.update_partitions);
    ensure!(partition_index < partitions, "invalid partition index");

    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: partition_index,
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: usize::from(config.h_select),
    };

    let valid = EmptySectorUpdate::<Tree>::verify(&public_params, &public_inputs, &proof)?;

    info!("verify_single_partition_proof:finish");

    Ok(valid)
}

/// Generate all vanilla partition proofs across all partitions.
#[allow(clippy::too_many_arguments)]
pub fn generate_partition_proofs<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    config: SectorUpdateConfig,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
) -> Result<Vec<PartitionProof<Tree>>> {
    info!("generate_partition_proofs:start");

    let comm_r_old_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let public_params: storage_proofs_update::PublicParams =
        PublicParams::from_sector_size(u64::from(config.sector_size));

    let p_aux_old = get_p_aux::<Tree>(sector_key_cache_path)?;

    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: usize::from(config.update_partitions),
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: usize::from(config.h_select),
    };

    let t_aux_old = get_t_aux::<Tree>(sector_key_cache_path)?;

    let (tree_d_new_config, tree_r_last_new_config) =
        get_new_configs_from_t_aux_old::<Tree>(&t_aux_old, replica_cache_path, config.nodes_count)?;

    let private_inputs: PrivateInputs = PrivateInputs {
        comm_c: p_aux_old.comm_c,
        tree_r_old_config: t_aux_old.tree_r_last_config,
        old_replica_path: sector_key_path.to_path_buf(),
        tree_d_new_config,
        tree_r_new_config: tree_r_last_new_config,
        replica_path: replica_path.to_path_buf(),
    };

    let partition_proofs = EmptySectorUpdate::<Tree>::prove_all_partitions(
        &public_params,
        &public_inputs,
        &private_inputs,
        usize::from(config.update_partitions),
    )?;

    info!("generate_partition_proofs:finish");

    Ok(partition_proofs)
}

/// Verify all vanilla partition proofs across all partitions.
pub fn verify_partition_proofs<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    config: SectorUpdateConfig,
    proofs: &[PartitionProof<Tree>],
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
) -> Result<bool> {
    info!("verify_partition_proofs:start");

    let comm_r_old_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let public_params: storage_proofs_update::PublicParams =
        PublicParams::from_sector_size(u64::from(config.sector_size));

    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: usize::from(config.update_partitions),
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: usize::from(config.h_select),
    };

    let valid =
        EmptySectorUpdate::<Tree>::verify_all_partitions(&public_params, &public_inputs, proofs)?;

    info!("verify_partition_proofs:finish");

    Ok(valid)
}

#[allow(clippy::too_many_arguments)]
pub fn generate_empty_sector_update_proof_with_vanilla<
    Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>,
>(
    porep_config: &PoRepConfig,
    vanilla_proofs: Vec<PartitionProof<Tree>>,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
) -> Result<EmptySectorUpdateProof> {
    info!("generate_empty_sector_update_proof_with_vanilla:start");

    let comm_r_old_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let config = SectorUpdateConfig::from_porep_config(porep_config);

    let partitions = usize::from(config.update_partitions);
    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: partitions,
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: usize::from(config.h_select),
    };

    let setup_params_compound = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            sector_bytes: u64::from(config.sector_size),
        },
        partitions: Some(partitions),
        priority: false,
    };
    let pub_params_compound = EmptySectorUpdateCompound::<Tree>::setup(&setup_params_compound)?;

    let groth_params = get_empty_sector_update_params::<Tree>(porep_config)?;
    let multi_proof = EmptySectorUpdateCompound::prove_with_vanilla(
        &pub_params_compound,
        &public_inputs,
        vanilla_proofs,
        &groth_params,
    )?;

    info!("generate_empty_sector_update_proof_with_vanilla:finish");

    Ok(EmptySectorUpdateProof(multi_proof.to_vec()?))
}

#[allow(clippy::too_many_arguments)]
pub fn generate_empty_sector_update_proof<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    porep_config: &PoRepConfig,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
) -> Result<EmptySectorUpdateProof> {
    info!("generate_empty_sector_update_proof:start");

    let comm_r_old_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let config = SectorUpdateConfig::from_porep_config(porep_config);

    let p_aux_old = get_p_aux::<Tree>(sector_key_cache_path)?;

    let partitions = usize::from(config.update_partitions);
    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: partitions,
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: usize::from(config.h_select),
    };

    let t_aux_old = get_t_aux::<Tree>(sector_key_cache_path)?;

    let (tree_d_new_config, tree_r_last_new_config) =
        get_new_configs_from_t_aux_old::<Tree>(&t_aux_old, replica_cache_path, config.nodes_count)?;

    let private_inputs: PrivateInputs = PrivateInputs {
        comm_c: p_aux_old.comm_c,
        tree_r_old_config: t_aux_old.tree_r_last_config,
        old_replica_path: sector_key_path.to_path_buf(),
        tree_d_new_config,
        tree_r_new_config: tree_r_last_new_config,
        replica_path: replica_path.to_path_buf(),
    };

    let setup_params_compound = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            sector_bytes: u64::from(config.sector_size),
        },
        partitions: Some(partitions),
        priority: false,
    };
    let pub_params_compound = EmptySectorUpdateCompound::<Tree>::setup(&setup_params_compound)?;

    let groth_params = get_empty_sector_update_params::<Tree>(porep_config)?;
    let multi_proof = EmptySectorUpdateCompound::prove(
        &pub_params_compound,
        &public_inputs,
        &private_inputs,
        &groth_params,
    )?;

    info!("generate_empty_sector_update_proof:finish");

    Ok(EmptySectorUpdateProof(multi_proof.to_vec()?))
}

pub fn verify_empty_sector_update_proof<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    porep_config: &PoRepConfig,
    proof_bytes: &[u8],
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
) -> Result<bool> {
    info!("verify_empty_sector_update_proof:start");

    let comm_r_old_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let config = SectorUpdateConfig::from_porep_config(porep_config);
    let partitions = usize::from(config.update_partitions);
    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: partitions,
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: usize::from(config.h_select),
    };
    let setup_params_compound = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            sector_bytes: u64::from(config.sector_size),
        },
        partitions: Some(partitions),
        priority: true,
    };
    let pub_params_compound = EmptySectorUpdateCompound::<Tree>::setup(&setup_params_compound)?;

    let verifying_key = get_empty_sector_update_verifying_key::<Tree>(porep_config)?;
    let multi_proof = MultiProof::new_from_bytes(Some(partitions), proof_bytes, &verifying_key)?;
    let valid =
        EmptySectorUpdateCompound::verify(&pub_params_compound, &public_inputs, &multi_proof, &())?;

    info!("verify_empty_sector_update_proof:finish");

    Ok(valid)
}
