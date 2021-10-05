use std::fs::{self, metadata, OpenOptions};
use std::path::Path;

use anyhow::{ensure, Context, Error, Result};
use bincode::deserialize;
use blstrs::Scalar as Fr;
use filecoin_hashers::{Domain, Hasher};
use fr32::bytes_into_fr;
use generic_array::typenum::Unsigned;
use log::info;
use memmap::MmapOptions;
use merkletree::merkle::get_merkle_tree_len;
use merkletree::store::StoreConfig;
use storage_proofs_core::{
    cache_key::CacheKey,
    compound_proof::CompoundProof,
    merkle::{get_base_tree_count, MerkleTreeTrait},
    multi_proof::MultiProof,
    proof::ProofScheme,
    util::NODE_SIZE,
};
use storage_proofs_porep::stacked::{PersistentAux, TemporaryAux, BINARY_ARITY};
use storage_proofs_update::{
    constants::TreeRHasher, EmptySectorUpdate, EmptySectorUpdateCompound, PartitionProof,
    PrivateInputs, PublicInputs, PublicParams,
};

use crate::{
    caches::get_stacked_params,
    constants::{DefaultPieceDomain, DefaultPieceHasher},
    pieces::verify_pieces,
    types::{Commitment, HSelect, PieceInfo, PoRepConfig, UpdateProofPartitions},
};

pub fn compare_elements(path1: &Path, path2: &Path) -> Result<(), Error> {
    info!("Comparing elements between {:?} and {:?}", path1, path2);
    let f_data1 = OpenOptions::new()
        .read(true)
        .open(path1)
        .with_context(|| format!("could not open path={:?}", path1))?;
    let data1 = unsafe {
        MmapOptions::new()
            .map(&f_data1)
            .with_context(|| format!("could not mmap path={:?}", path1))
    }?;
    let f_data2 = OpenOptions::new()
        .read(true)
        .open(path2)
        .with_context(|| format!("could not open path={:?}", path2))?;
    let data2 = unsafe {
        MmapOptions::new()
            .map(&f_data2)
            .with_context(|| format!("could not mmap path={:?}", path2))
    }?;
    let fr_size = std::mem::size_of::<Fr>() as usize;
    let end = metadata(path1)?.len() as u64;
    ensure!(
        metadata(path2)?.len() as u64 == end,
        "File sizes must match"
    );

    for i in (0..end).step_by(fr_size) {
        let index = i as usize;
        let fr1 = bytes_into_fr(&data1[index..index + fr_size])?;
        let fr2 = bytes_into_fr(&data2[index..index + fr_size])?;
        ensure!(fr1 == fr2, "Data mismatch when comparing elements");
    }
    info!("Match found for {:?} and {:?}", path1, path2);

    Ok(())
}

/// Encodes data into an existing replica.
#[allow(clippy::too_many_arguments)]
pub fn encode_into<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    porep_config: PoRepConfig,
    new_replica_path: &Path,
    new_cache_path: &Path,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    staged_data_path: &Path,
    piece_infos: &[PieceInfo],
) -> Result<(Commitment, Commitment, Commitment)> {
    info!("encode_into:start");
    let mut comm_d = [0; 32];
    let mut comm_r = [0; 32];
    let mut comm_r_last = [0; 32];

    let nodes_count = u64::from(porep_config.sector_size) as usize / NODE_SIZE;
    let tree_count = get_base_tree_count::<Tree>();
    let base_tree_nodes_count = nodes_count / tree_count;

    // NOTE: p_aux has comm_c and comm_r_last
    let p_aux: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
        let p_aux_path = sector_key_cache_path.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    // Note: t_aux has labels and tree_d, tree_c, tree_r_last store configs
    let t_aux = {
        let t_aux_path = sector_key_cache_path.join(CacheKey::TAux.to_string());
        let t_aux_bytes = fs::read(&t_aux_path)
            .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

        let mut res: TemporaryAux<Tree, DefaultPieceHasher> = deserialize(&t_aux_bytes)?;
        // Switch t_aux to the passed in cache_path
        res.set_cache_path(sector_key_cache_path);
        res
    };

    // Re-instantiate a t_aux with the new cache path, then use
    // the tree_d and tree_r_last configs from it.
    let mut t_aux_new = t_aux;
    t_aux_new.set_cache_path(new_cache_path);

    // With the new cache path set, formulate the new tree_d and tree_r_last configs.
    let tree_d_new_config = StoreConfig::from_config(
        &t_aux_new.tree_d_config,
        CacheKey::CommDTree.to_string(),
        Some(get_merkle_tree_len(base_tree_nodes_count, BINARY_ARITY)?),
    );

    let tree_r_last_new_config = StoreConfig::from_config(
        &t_aux_new.tree_r_last_config,
        CacheKey::CommRLastTree.to_string(),
        Some(get_merkle_tree_len(
            base_tree_nodes_count,
            Tree::Arity::to_usize(),
        )?),
    );

    let (comm_r_domain, comm_r_last_domain, comm_d_domain) =
        EmptySectorUpdate::<Tree>::encode_into(
            nodes_count,
            tree_d_new_config,
            tree_r_last_new_config,
            <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_c.into_bytes())?,
            <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_r_last.into_bytes())?,
            &new_replica_path,
            &new_cache_path,
            &sector_key_path,
            &sector_key_cache_path,
            &staged_data_path,
            u64::from(HSelect::from(porep_config)) as usize,
        )?;

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
        verify_pieces(&comm_d, piece_infos, porep_config.into())?,
        "pieces and comm_d do not match"
    );

    info!("encode_into:finish");
    Ok((comm_r, comm_r_last, comm_d))
}

/// Reverses the encoding process and outputs the data into out_data_path.
#[allow(clippy::too_many_arguments)]
pub fn decode_from<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    porep_config: PoRepConfig,
    out_data_path: &Path,
    replica_path: &Path,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    comm_d_new: Commitment,
) -> Result<()> {
    info!("decode_from:start");

    // NOTE: p_aux has comm_c and comm_r_last
    let p_aux: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
        let p_aux_path = sector_key_cache_path.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    let nodes_count = u64::from(porep_config.sector_size) as usize / NODE_SIZE;
    EmptySectorUpdate::<Tree>::decode_from(
        nodes_count,
        out_data_path,
        replica_path,
        sector_key_path,
        sector_key_cache_path,
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_c.into_bytes())?,
        comm_d_new.into(),
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_r_last.into_bytes())?,
        u64::from(HSelect::from(porep_config)) as usize,
    )?;

    info!("decode_from:finish");
    Ok(())
}

/// Removes encoded data and outputs the sector key.
#[allow(clippy::too_many_arguments)]
pub fn remove_encoded_data<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    porep_config: PoRepConfig,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
    data_path: &Path,
    comm_d_new: Commitment,
) -> Result<()> {
    info!("remove_data:start");

    // NOTE: p_aux has comm_c and comm_r_last
    let p_aux: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
        let p_aux_path = replica_cache_path.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    let nodes_count = u64::from(porep_config.sector_size) as usize / NODE_SIZE;
    EmptySectorUpdate::<Tree>::remove_encoded_data(
        nodes_count,
        sector_key_path,
        sector_key_cache_path,
        replica_path,
        replica_cache_path,
        data_path,
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_c.into_bytes())?,
        comm_d_new.into(),
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_r_last.into_bytes())?,
        u64::from(HSelect::from(porep_config)) as usize,
    )?;

    info!("remove_data:finish");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn generate_single_partition_proof<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    porep_config: PoRepConfig,
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
        PublicParams::from_sector_size(u64::from(porep_config.sector_size));

    // NOTE: p_aux has comm_c and comm_r_last
    let p_aux_old: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
        let p_aux_path = sector_key_cache_path.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: 0,
        comm_c: p_aux_old.comm_c,
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: u64::from(HSelect::from(porep_config)) as usize,
    };

    // Note: t_aux has labels and tree_d, tree_c, tree_r_last store configs
    let t_aux_old = {
        let t_aux_path = sector_key_cache_path.join(CacheKey::TAux.to_string());
        let t_aux_bytes = fs::read(&t_aux_path)
            .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

        let res: TemporaryAux<Tree, DefaultPieceHasher> = deserialize(&t_aux_bytes)?;
        res
    };

    // Re-instantiate a t_aux with the new replica cache path, then
    // use new tree_d_config and tree_r_last_config from it.
    let mut t_aux_new = t_aux_old.clone();
    t_aux_new.set_cache_path(replica_cache_path);

    let private_inputs: PrivateInputs = PrivateInputs {
        tree_r_old_config: t_aux_old.tree_r_last_config,
        old_replica_path: sector_key_path.to_path_buf(),
        tree_d_new_config: t_aux_new.tree_d_config,
        tree_r_new_config: t_aux_new.tree_r_last_config,
        replica_path: replica_path.to_path_buf(),
    };

    let partition_proof =
        EmptySectorUpdate::<Tree>::prove(&public_params, &public_inputs, &private_inputs)?;

    info!("generate_single_partition_proof:finish");

    Ok(partition_proof)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_single_partition_proof<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    porep_config: PoRepConfig,
    proof: PartitionProof<Tree>,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
    sector_key_cache_path: &Path,
) -> Result<bool> {
    info!("verify_single_partition_proof:start");

    let comm_r_old_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let public_params: storage_proofs_update::PublicParams =
        PublicParams::from_sector_size(u64::from(porep_config.sector_size));

    // NOTE: p_aux has comm_c and comm_r_last
    let p_aux_old: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
        let p_aux_path = sector_key_cache_path.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: 0,
        comm_c: p_aux_old.comm_c,
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: u64::from(HSelect::from(porep_config)) as usize,
    };

    let valid = EmptySectorUpdate::<Tree>::verify(&public_params, &public_inputs, &proof)?;
    ensure!(valid, "vanilla proof is invalid");

    info!("verify_single_partition_proof:finish");

    Ok(valid)
}

pub fn generate_partition_proofs<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
>>>>>>> 79aefd57 (feat: expose some required data through filecoin-proofs)
    porep_config: PoRepConfig,
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
        PublicParams::from_sector_size(u64::from(porep_config.sector_size));

    // NOTE: p_aux has comm_c and comm_r_last
    let p_aux_old: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
        let p_aux_path = sector_key_cache_path.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: usize::from(UpdateProofPartitions::from(porep_config)),
        comm_c: p_aux_old.comm_c,
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: u64::from(HSelect::from(porep_config)) as usize,
    };

    // Note: t_aux has labels and tree_d, tree_c, tree_r_last store configs
    let t_aux_old = {
        let t_aux_path = sector_key_cache_path.join(CacheKey::TAux.to_string());
        let t_aux_bytes = fs::read(&t_aux_path)
            .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

        let res: TemporaryAux<Tree, DefaultPieceHasher> = deserialize(&t_aux_bytes)?;
        res
    };

    // Re-instantiate a t_aux with the new replica cache path, then
    // use new tree_d_config and tree_r_last_config from it.
    let mut t_aux_new = t_aux_old.clone();
    t_aux_new.set_cache_path(replica_cache_path);

    let private_inputs: PrivateInputs = PrivateInputs {
        tree_r_old_config: t_aux_old.tree_r_last_config,
        old_replica_path: sector_key_path.to_path_buf(),
        tree_d_new_config: t_aux_new.tree_d_config,
        tree_r_new_config: t_aux_new.tree_r_last_config,
        replica_path: replica_path.to_path_buf(),
    };

    let partition_proofs = EmptySectorUpdate::<Tree>::prove_all_partitions(
        &public_params,
        &public_inputs,
        &private_inputs,
        usize::from(UpdateProofPartitions::from(porep_config)),
    )?;

    info!("generate_partition_proofs:finish");

    Ok(partition_proofs)
}

pub fn verify_partition_proofs<Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    porep_config: PoRepConfig,
    proofs: Vec<PartitionProof<Tree>>,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
    sector_key_cache_path: &Path,
) -> Result<bool> {
    info!("verify_partition_proofs:start");

    let comm_r_old_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let public_params: storage_proofs_update::PublicParams =
        PublicParams::from_sector_size(u64::from(porep_config.sector_size));

    // NOTE: p_aux has comm_c and comm_r_last
    let p_aux_old: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
        let p_aux_path = sector_key_cache_path.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: usize::from(UpdateProofPartitions::from(porep_config)),
        comm_c: p_aux_old.comm_c,
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: u64::from(HSelect::from(porep_config)) as usize,
    };

    let valid =
        EmptySectorUpdate::<Tree>::verify_all_partitions(&public_params, &public_inputs, &proofs)?;
    ensure!(valid, "vanilla proofs are invalid");

    info!("verify_partition_proofs:finish");

    Ok(valid)
}

/*
pub fn generate_update_proof<'a, Tree: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    porep_config: PoRepConfig,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_d_new: Commitment,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
) -> Result<MultiProof<'a>> {
    info!("generate_update_proof:start");

    let comm_r_old_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <TreeRHasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let public_params: storage_proofs_update::PublicParams =
        PublicParams::from_sector_size(u64::from(porep_config.sector_size));

    // NOTE: p_aux has comm_c and comm_r_last
    let p_aux_old: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
        let p_aux_path = sector_key_cache_path.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    let public_inputs: storage_proofs_update::PublicInputs = PublicInputs {
        k: usize::from(UpdateProofPartitions::from(porep_config)),
        comm_c: p_aux_old.comm_c,
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h: u64::from(HSelect::from(porep_config)) as usize,
    };

    // Note: t_aux has labels and tree_d, tree_c, tree_r_last store configs
    let t_aux_old = {
        let t_aux_path = sector_key_cache_path.join(CacheKey::TAux.to_string());
        let t_aux_bytes = fs::read(&t_aux_path)
            .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

        let res: TemporaryAux<Tree, DefaultPieceHasher> = deserialize(&t_aux_bytes)?;
        res
    };

    // Re-instantiate a t_aux with the new replica cache path, then
    // use new tree_d_config and tree_r_last_config from it.
    let mut t_aux_new = t_aux_old.clone();
    t_aux_new.set_cache_path(replica_cache_path);

    let private_inputs: PrivateInputs = PrivateInputs {
        tree_r_old_config: t_aux_old.tree_r_last_config,
        old_replica_path: sector_key_path.to_path_buf(),
        tree_d_new_config: t_aux_new.tree_d_config,
        tree_r_new_config: t_aux_new.tree_r_last_config,
        replica_path: replica_path.to_path_buf(),
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(UpdateProofPartitions::from(porep_config)),
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(usize::from(UpdateProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params = <EmptySectorUpdateCompound<Tree, DefaultPieceHasher> as CompoundProof<
            EmptySectorUpdateCompound<'_, Tree, DefaultPieceHasher>,
        _,
        >>::setup(&compound_setup_params)?;

    let groth_params = get_stacked_params::<Tree>(porep_config)?;
    let proof = EmptySectorUpdateCompound::prove(&pub_params, &public_inputs, &private_inputs, &groth_params)?;

    info!("generate_update_proof:finish");

    Ok(proof)
}
 */
