use std::{fs, mem::size_of, path::Path};

use anyhow::{Context, Result};
use bellperson::groth16::Proof;
use blstrs::{Bls12, Scalar as Fr};
use filecoin_hashers::{Domain, Hasher};
use fr32::{bytes_into_fr, fr_into_bytes};
use log::trace;
use merkletree::merkle::{get_merkle_tree_leafs, get_merkle_tree_len};
use storage_proofs_core::{
    cache_key::CacheKey,
    merkle::{get_base_tree_count, MerkleTreeTrait},
};
use storage_proofs_porep::stacked::{PersistentAux, TemporaryAux};
use typenum::Unsigned;

use crate::{
    constants::DefaultPieceHasher,
    types::{Commitment, SectorSize},
};

pub fn as_safe_commitment<H: Domain, T: AsRef<str>>(
    comm: &[u8; 32],
    commitment_name: T,
) -> Result<H> {
    bytes_into_fr(comm)
        .map(Into::into)
        .with_context(|| format!("Invalid commitment ({})", commitment_name.as_ref(),))
}

pub fn commitment_from_fr(fr: Fr) -> Commitment {
    let mut commitment = [0; 32];
    for (i, b) in fr_into_bytes(&fr).iter().enumerate() {
        commitment[i] = *b;
    }
    commitment
}

pub fn get_base_tree_size<Tree: MerkleTreeTrait>(sector_size: SectorSize) -> Result<usize> {
    let base_tree_leaves = u64::from(sector_size) as usize
        / size_of::<<Tree::Hasher as Hasher>::Domain>()
        / get_base_tree_count::<Tree>();

    get_merkle_tree_len(base_tree_leaves, Tree::Arity::to_usize())
}

pub fn get_base_tree_leafs<Tree: MerkleTreeTrait>(base_tree_size: usize) -> Result<usize> {
    get_merkle_tree_leafs(base_tree_size, Tree::Arity::to_usize())
}

pub(crate) fn proofs_to_bytes(proofs: &[Proof<Bls12>]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(Proof::<Bls12>::size());
    for proof in proofs {
        proof.write(&mut out).context("known allocation target")?;
    }
    Ok(out)
}

/// Persist p_aux.
pub(crate) fn persist_p_aux<Tree: MerkleTreeTrait>(
    p_aux: &PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    cache_path: &Path,
) -> Result<()> {
    let p_aux_path = cache_path.join(CacheKey::PAux.to_string());
    let p_aux_bytes = bincode::serialize(&p_aux)?;

    fs::write(&p_aux_path, p_aux_bytes)
        .with_context(|| format!("could not write to file p_aux={:?}", p_aux_path))?;

    Ok(())
}

/// Instantiates p_aux from the specified cache_dir for access to comm_c and comm_r_last.
pub(crate) fn get_p_aux<Tree: MerkleTreeTrait>(
    cache_path: &Path,
) -> Result<PersistentAux<<Tree::Hasher as Hasher>::Domain>> {
    let p_aux_path = cache_path.join(CacheKey::PAux.to_string());
    let p_aux_bytes = fs::read(&p_aux_path)
        .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

    let p_aux = bincode::deserialize(&p_aux_bytes)?;

    Ok(p_aux)
}

/// Instantiates t_aux from the specified cache_dir for access to  labels and tree_d, tree_c,
/// tree_r_last store configs.
pub(crate) fn get_t_aux<Tree: MerkleTreeTrait>(
    cache_path: &Path,
) -> Result<TemporaryAux<Tree, DefaultPieceHasher>> {
    let t_aux_path = cache_path.join(CacheKey::TAux.to_string());
    trace!("Instantiating TemporaryAux from {:?}", cache_path);
    let t_aux_bytes = fs::read(&t_aux_path)
        .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

    let mut res: TemporaryAux<Tree, DefaultPieceHasher> = bincode::deserialize(&t_aux_bytes)?;
    res.set_cache_path(cache_path);
    trace!("Set TemporaryAux cache_path to {:?}", cache_path);

    Ok(res)
}

/// Persist t_aux.
pub(crate) fn persist_t_aux<Tree: MerkleTreeTrait>(
    t_aux: &TemporaryAux<Tree, DefaultPieceHasher>,
    cache_path: &Path,
) -> Result<()> {
    let t_aux_path = cache_path.join(CacheKey::TAux.to_string());
    let t_aux_bytes = bincode::serialize(&t_aux)?;

    fs::write(&t_aux_path, t_aux_bytes)
        .with_context(|| format!("could not write to file t_aux={:?}", t_aux_path))?;

    Ok(())
}
