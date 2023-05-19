use std::cmp;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use bincode::{deserialize, serialize};
use ff::PrimeField;
use filecoin_hashers::{Domain, Hasher};
use fr32::bytes_into_fr;
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
    constants::{h_default, TreeDArity, TreeDDomain, TreeRDomain, TreeRHasher},
    phi,
    vanilla::Rhos,
    EmptySectorUpdate, EmptySectorUpdateCompound, PartitionProof, PrivateInputs, PublicInputs,
    PublicParams, SetupParams,
};

use crate::{
    caches::{get_empty_sector_update_params, get_empty_sector_update_verifying_key},
    chunk_iter::ChunkIterator,
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
    t_aux: &TemporaryAux<Tree, DefaultPieceHasher>,
    new_cache_path: &Path,
    nodes_count: usize,
) -> Result<(StoreConfig, StoreConfig)> {
    let tree_count = get_base_tree_count::<Tree>();
    let base_tree_nodes_count = nodes_count / tree_count;

    let tree_d_new_config = StoreConfig {
        path: new_cache_path.into(),
        id: t_aux.tree_d_config.id.clone(),
        size: Some(get_merkle_tree_len(nodes_count, TreeDArity::to_usize())?),
        rows_to_discard: t_aux.tree_d_config.rows_to_discard,
    };

    let tree_r_last_new_config = StoreConfig {
        path: new_cache_path.into(),
        id: t_aux.tree_r_last_config.id.clone(),
        size: Some(get_merkle_tree_len(
            base_tree_nodes_count,
            Tree::Arity::to_usize(),
        )?),
        rows_to_discard: t_aux.tree_r_last_config.rows_to_discard,
    };

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
            h_default(config.nodes_count),
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

/// Decodes a range of data with the given sector key.
///
/// This function is similar to [`decode_from`], the difference is that it operates directly on the
/// given file descriptions. The current position of the file descriptors is where the decoding
/// starts, i.e. you need to seek to the intended offset before you call this function. The
/// `nodes_offset` is the node offset relative to the beginning of the file. This information is
/// needed in order to do the decoding correctly. The `nodes_count` is the total number of nodes
/// within the file. The `num_nodes` defines how many nodes will be decoded, starting from the
/// current position.
#[allow(clippy::too_many_arguments)]
pub fn decode_from_range<R: Read, S: Read, W: Write>(
    nodes_count: usize,
    comm_d: Commitment,
    comm_r: Commitment,
    input_data: R,
    sector_key_data: S,
    output_data: &mut W,
    nodes_offset: usize,
    num_nodes: usize,
) -> Result<()> {
    let comm_d_domain = TreeDDomain::try_from_bytes(&comm_d[..])?;
    let comm_r_domain = TreeRDomain::try_from_bytes(&comm_r[..])?;
    let phi = phi(&comm_d_domain, &comm_r_domain);
    let h = h_default(nodes_count);
    let rho_invs = Rhos::new_inv_range(&phi, h, nodes_count, nodes_offset, num_nodes);

    let bytes_length = num_nodes * NODE_SIZE;

    let input_iter = ChunkIterator::new(input_data);
    let sector_key_iter = ChunkIterator::new(sector_key_data);
    let chunk_size = input_iter.chunk_size();

    for (chunk_index, (input_chunk_result, sector_key_chunk_result)) in
        input_iter.zip(sector_key_iter).enumerate()
    {
        let chunk_offset = chunk_index * chunk_size;

        // The end of the intended decoding range was reached.
        if chunk_offset > bytes_length {
            break;
        }

        let input_chunk = input_chunk_result.context("cannot read input data")?;
        let sector_key_chunk = sector_key_chunk_result.context("connot read sector key data")?;

        // If the bytes that still need to be read is smaller then the chunk size, then use that
        // size.
        let current_chunk_size = cmp::min(bytes_length - chunk_offset, chunk_size);
        ensure!(
            current_chunk_size <= input_chunk.len(),
            "not enough bytes in input",
        );
        ensure!(
            current_chunk_size <= sector_key_chunk.len(),
            "not enough bytes in sector key",
        );

        let output_reprs = (0..current_chunk_size)
            .step_by(NODE_SIZE)
            .map(|index| {
                // The absolute byte offset within the current sector
                let offset = (nodes_offset * NODE_SIZE) + chunk_offset + index;
                let rho_inv = rho_invs.get(offset / NODE_SIZE);

                let sector_key_fr = bytes_into_fr(&sector_key_chunk[index..index + NODE_SIZE])?;
                let input_fr = bytes_into_fr(&input_chunk[index..index + NODE_SIZE])?;

                // This is the actual encoding step. Those operations happen on field elements.
                let output_fr = (input_fr - sector_key_fr) * rho_inv;
                Ok(output_fr.to_repr())
            })
            .collect::<Result<Vec<_>>>()?;

        output_data.write_all(&output_reprs.concat())?;
    }

    Ok(())
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

    EmptySectorUpdate::<Tree>::decode_from(
        config.nodes_count,
        out_data_path,
        replica_path,
        sector_key_path,
        sector_key_cache_path,
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_c.into_bytes())?,
        comm_d_new.into(),
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_r_last.into_bytes())?,
        h_default(config.nodes_count),
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

    let tree_r_last_new = EmptySectorUpdate::<Tree>::remove_encoded_data(
        config.nodes_count,
        sector_key_path,
        sector_key_cache_path,
        replica_path,
        replica_cache_path,
        data_path,
        tree_r_last_new_config,
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_c.into_bytes())?,
        comm_d_new.into(),
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_r_last.into_bytes())?,
        h_default(config.nodes_count),
    )?;

    // Persist p_aux and t_aux into the sector_key_cache_path here
    let mut p_aux = p_aux;
    p_aux.comm_r_last = tree_r_last_new;
    persist_p_aux::<Tree>(&p_aux, sector_key_cache_path)?;
    persist_t_aux::<Tree>(&t_aux, sector_key_cache_path)?;

    info!("remove_data:finish");
    Ok(())
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
        h: config.h,
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
        h: config.h,
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
        h: config.h,
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
        h: config.h,
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
        h: config.h,
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
        h: config.h,
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
        h: config.h,
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
