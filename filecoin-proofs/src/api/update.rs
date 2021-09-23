use std::fs::{self, metadata, OpenOptions};
use std::marker::PhantomData;
use std::path::Path;

use anyhow::{ensure, Context, Error, Result};
use bincode::deserialize;
use blstrs::{Bls12, Scalar as Fr};
use filecoin_hashers::sha256::Sha256Hasher;
use filecoin_hashers::{Domain, Hasher};
use fr32::bytes_into_fr;
use log::info;
use memmap::MmapOptions;
use storage_proofs_core::{cache_key::CacheKey, merkle::MerkleTreeTrait, util::NODE_SIZE};
use storage_proofs_porep::stacked::{PersistentAux, TemporaryAux, TemporaryAuxCache};
use storage_proofs_update::{CCUpdateVanilla, PublicInputs, PublicParams};

use crate::{
    constants::{DefaultPieceDomain, DefaultPieceHasher},
    pieces::verify_pieces,
    types::{Commitment, HSelect, PieceInfo, PoRepConfig, UpdateProofPartitions},
};

// FIXME: This is a debug only method
pub fn dump_elements(path: &Path) -> Result<(), Error> {
    info!("Dumping elements from {:?}", path);
    let f_data = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("could not open path={:?}", path))?;
    let data = unsafe {
        MmapOptions::new()
            .map(&f_data)
            .with_context(|| format!("could not mmap path={:?}", path))
    }?;
    let fr_size = std::mem::size_of::<Fr>() as usize;
    let end = metadata(path)?.len() as u64;
    for i in (0..end).step_by(fr_size) {
        let index = i as usize;
        let fr = bytes_into_fr(&data[index..index + fr_size])?;
        info!("[{}/{}] {:?} ", index, index + fr_size, fr);
    }

    Ok(())
}

// FIXME: This is a test only method (add to test module)
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
pub fn encode_into<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    new_replica_path: &Path,
    new_cache_path: &Path,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    staged_data_path: &Path,
    piece_infos: &[PieceInfo],
    comm_sector_key: Commitment,
) -> Result<(Commitment, Commitment, Commitment)> {
    info!("encode_into:start");
    let mut comm_d = [0; 32];
    let mut comm_r = [0; 32];
    let mut comm_r_last = [0; 32];

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

        let mut res: TemporaryAux<_, _> = deserialize(&t_aux_bytes)?;
        // Switch t_aux to the passed in cache_path
        res.set_cache_path(sector_key_cache_path);
        res
    };

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux_cache: TemporaryAuxCache<Tree, DefaultPieceHasher> =
        TemporaryAuxCache::new(&t_aux, sector_key_path.to_path_buf())
            .context("failed to restore contents of t_aux")?;

    let nodes_count = u64::from(porep_config.sector_size) as usize / NODE_SIZE;
    let (comm_r_domain, comm_r_last_domain, comm_d_domain) =
        CCUpdateVanilla::<Tree, DefaultPieceHasher>::encode_into(
            nodes_count,
            &t_aux_cache,
            <Tree::Hasher as Hasher>::Domain::try_from_bytes(&p_aux.comm_c.into_bytes())?,
            <Tree::Hasher as Hasher>::Domain::try_from_bytes(&comm_sector_key)?,
            &new_replica_path,
            &new_cache_path,
            &sector_key_path,
            &sector_key_cache_path,
            &staged_data_path,
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
pub fn decode_from<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    out_data_path: &Path,
    replica_path: &Path,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    comm_d: Commitment,
    comm_r: Commitment,
    comm_sector_key: Commitment,
) -> Result<()> {
    info!("decode_from:start");

    let nodes_count = u64::from(porep_config.sector_size) as usize / NODE_SIZE;
    CCUpdateVanilla::<Tree, DefaultPieceHasher>::decode_from(
        nodes_count,
        out_data_path,
        replica_path,
        sector_key_path,
        sector_key_cache_path,
        comm_d.into(),
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&comm_r)?,
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&comm_sector_key)?,
    )?;

    info!("decode_from:finish");
    Ok(())
}

/// Removes encoded data and outputs the sector key.
#[allow(clippy::too_many_arguments)]
pub fn remove_encoded_data<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
    data_path: &Path,
    comm_d: Commitment,
    comm_r: Commitment,
    comm_sector_key: Commitment,
) -> Result<()> {
    info!("remove_data:start");

    let nodes_count = u64::from(porep_config.sector_size) as usize / NODE_SIZE;
    CCUpdateVanilla::<Tree, DefaultPieceHasher>::remove_encoded_data(
        nodes_count,
        sector_key_path,
        sector_key_cache_path,
        replica_path,
        replica_cache_path,
        data_path,
        comm_d.into(),
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&comm_r)?,
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(&comm_sector_key)?,
    )?;

    info!("remove_data:finish");
    Ok(())
}

pub fn generate_update_proof<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    comm_r_old: Commitment,
    comm_r_new: Commitment,
    comm_r_last_new: Commitment,
    comm_d_new: Commitment,
    sector_key_path: &Path,
    sector_key_cache_path: &Path,
    replica_path: &Path,
    replica_cache_path: &Path,
) -> Result<()> {
    // FIXME: Return UpdateProof type
    info!("generate_update_proof:start");

    let nodes_count = u64::from(porep_config.sector_size) as usize / NODE_SIZE;

    let comm_r_old_safe = <Tree::Hasher as Hasher>::Domain::try_from_bytes(&comm_r_old)?;
    let comm_r_new_safe = <Tree::Hasher as Hasher>::Domain::try_from_bytes(&comm_r_new)?;
    let comm_r_last_new_safe = <Tree::Hasher as Hasher>::Domain::try_from_bytes(&comm_r_last_new)?;

    let comm_d_new_safe = DefaultPieceDomain::try_from_bytes(&comm_d_new)?;

    let public_params: storage_proofs_update::PublicParams =
        PublicParams::from_sector_size(u64::from(porep_config.sector_size));

    let public_inputs: storage_proofs_update::PublicInputs<Tree> = PublicInputs {
        k: usize::from(UpdateProofPartitions::from(porep_config)),
        comm_r_old: comm_r_old_safe,
        comm_d_new: comm_d_new_safe,
        comm_r_new: comm_r_new_safe,
        h_select: u64::from(HSelect::from(porep_config)),
        _tree_r: PhantomData::default(),
    };

    // NOTE: p_aux has comm_c and comm_r_last
    let p_aux_old: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
        let p_aux_path = sector_key_cache_path.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    // Note: t_aux has labels and tree_d, tree_c, tree_r_last store configs
    let t_aux_old = {
        let t_aux_path = sector_key_cache_path.join(CacheKey::TAux.to_string());
        let t_aux_bytes = fs::read(&t_aux_path)
            .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

        let res: TemporaryAux<_, _> = deserialize(&t_aux_bytes)?;
        res
    };

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux_cache_old: TemporaryAuxCache<Tree, DefaultPieceHasher> =
        TemporaryAuxCache::new(&t_aux_old, sector_key_cache_path.to_path_buf())
            .context("failed to restore contents of t_aux_old")?;

    // Re-instantiate a t_aux with the new replica cache path, then
    // use new tree_d_config and tree_r_last_config from it.
    let mut t_aux_cache_new = t_aux_cache_old.t_aux.clone();
    t_aux_cache_new.set_cache_path(replica_cache_path);

    /*let update_proof = */
    CCUpdateVanilla::<Tree, /*DefaultTreeHasher*/ Sha256Hasher>::generate_update_proofs(
        nodes_count,
        public_params,
        public_inputs,
        &t_aux_cache_old,
        t_aux_cache_new.tree_d_config,
        t_aux_cache_new.tree_r_last_config,
        p_aux_old.comm_c,
        comm_r_old_safe,
        comm_r_last_new_safe,
        replica_path,
        replica_cache_path,
    )?;

    info!("generate_update_proof:finish");

    Ok(/*update_proof*/ ())
}
