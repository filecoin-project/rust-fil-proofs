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

fn read_t_aux_file<Tree: MerkleTreeTrait>(
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

/// Instantiates t_aux from default values for access to labels and tree_d, tree_c, tree_r_last
/// store configs
#[cfg(feature = "fixed-rows-to-discard")]
// Silence Clippy warning in order to have the same return value as without this feature.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn get_t_aux<Tree: MerkleTreeTrait>(
    cache_path: &Path,
    sector_bytes: u64,
) -> Result<TemporaryAux<Tree, DefaultPieceHasher>> {
    trace!(
        "Instantiating TemporaryAux from default values with cache_path at {:?}",
        cache_path
    );
    let t_aux_path = cache_path.join(CacheKey::TAux.to_string());
    if Path::new(&t_aux_path).exists() {
        log::warn!(
            "`t_aux` file exists, use that file instead of the default values. t_aux={:?}",
            &t_aux_path
        );
        read_t_aux_file(cache_path)
    } else {
        let sector_nodes = sector_bytes as usize / storage_proofs_core::util::NODE_SIZE;
        let layers = *crate::constants::LAYERS
            .read()
            .expect("LAYERS poisoned")
            .get(&sector_bytes)
            .expect("unknown sector size");

        Ok(TemporaryAux::new(
            sector_nodes,
            layers,
            cache_path.to_path_buf(),
        ))
    }
}

/// Instantiates t_aux from the specified cache_dir for access to labels and tree_d, tree_c,
/// tree_r_last store configs.
#[cfg(not(feature = "fixed-rows-to-discard"))]
pub(crate) fn get_t_aux<Tree: MerkleTreeTrait>(
    cache_path: &Path,
    // `sector_bytes` is ignored, it's only there to have the same API as if the
    // `fixed-rows-to-discard` feature was enabled.
    _sector_bytes: u64,
) -> Result<TemporaryAux<Tree, DefaultPieceHasher>> {
    read_t_aux_file(cache_path)
}

/// Persist t_aux.
#[cfg(any(test, not(feature = "fixed-rows-to-discard")))]
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

#[cfg(all(test, feature = "fixed-rows-to-discard"))]
mod tests {
    use super::*;

    use storage_proofs_core::util::{self, NODE_SIZE};

    use crate::{SectorShape32GiB, SECTOR_SIZE_32_GIB};

    /// Testing whether the default values are set if there's no `t_aux` file.
    #[test]
    fn test_get_t_aux_defaults() {
        let dir_does_not_exist = Path::new("/path/does/not/exist");
        let t_aux = get_t_aux::<SectorShape32GiB>(dir_does_not_exist, SECTOR_SIZE_32_GIB)
            .expect("t_aux should have been read");
        let expected_rows_to_discard = util::default_rows_to_discard(
            SECTOR_SIZE_32_GIB as usize / NODE_SIZE,
            <SectorShape32GiB as MerkleTreeTrait>::Arity::to_usize(),
        );
        assert_eq!(
            t_aux.tree_r_last_config.rows_to_discard,
            expected_rows_to_discard
        );
    }

    /// Testing whether the values from the `t_aux` file are used in case there is any.
    #[test]
    fn test_get_t_aux_file_exists() {
        let cache_dir = tempfile::tempdir()
            .expect("tempdir should have been created")
            .into_path();

        // Check if getting t_aux if no such file exists returns the default values.
        let default_t_aux = TemporaryAux::<SectorShape32GiB, DefaultPieceHasher>::new(
            SECTOR_SIZE_32_GIB as usize / NODE_SIZE,
            11,
            cache_dir.clone(),
        );
        let t_aux = get_t_aux::<SectorShape32GiB>(&cache_dir, SECTOR_SIZE_32_GIB)
            .expect("t_aux should have been read");
        assert_eq!(
            t_aux.tree_r_last_config.rows_to_discard,
            default_t_aux.tree_r_last_config.rows_to_discard
        );

        // Check if a custom t_aux is used if such a file exists.
        let mut custom_t_aux = default_t_aux.clone();
        custom_t_aux.tree_r_last_config.rows_to_discard = 5;
        persist_t_aux::<SectorShape32GiB>(&custom_t_aux, &cache_dir)
            .expect("t_aux should have been persisted");
        let read_t_aux = get_t_aux::<SectorShape32GiB>(&cache_dir, SECTOR_SIZE_32_GIB)
            .expect("t_aux should have been read");
        assert_ne!(
            read_t_aux.tree_r_last_config.rows_to_discard,
            default_t_aux.tree_r_last_config.rows_to_discard
        );
        assert_eq!(
            read_t_aux.tree_r_last_config.rows_to_discard,
            custom_t_aux.tree_r_last_config.rows_to_discard
        );
    }
}
