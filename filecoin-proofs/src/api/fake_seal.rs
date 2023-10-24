use std::fs::File;
use std::path::Path;

use anyhow::Result;
use filecoin_hashers::{Domain, Hasher};
use rand::{thread_rng, Rng};
use storage_proofs_core::merkle::MerkleTreeTrait;
use storage_proofs_porep::stacked::StackedDrg;

use crate::{
    api::util,
    constants::DefaultPieceHasher,
    types::{Commitment, PoRepConfig},
};

pub fn fauxrep<R: AsRef<Path>, S: AsRef<Path>, Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
    cache_path: R,
    out_path: S,
) -> Result<Commitment> {
    let mut rng = thread_rng();
    fauxrep_aux::<_, R, S, Tree>(&mut rng, porep_config, cache_path, out_path)
}

pub fn fauxrep_aux<R: Rng, S: AsRef<Path>, T: AsRef<Path>, Tree: 'static + MerkleTreeTrait>(
    mut rng: &mut R,
    porep_config: &PoRepConfig,
    cache_path: S,
    out_path: T,
) -> Result<Commitment> {
    let sector_bytes = porep_config.padded_bytes_amount().0;

    {
        // Create a sector full of null bytes at `out_path`.
        let file = File::create(&out_path)?;
        file.set_len(sector_bytes)?;
    }

    let fake_comm_c = <Tree::Hasher as Hasher>::Domain::random(&mut rng);
    let (comm_r, p_aux) = StackedDrg::<Tree, DefaultPieceHasher>::fake_replicate_phase2(
        fake_comm_c,
        out_path,
        &cache_path,
        sector_bytes as usize,
    )?;

    util::persist_p_aux::<Tree>(&p_aux, cache_path.as_ref())?;

    let mut commitment = [0u8; 32];
    commitment[..].copy_from_slice(&comm_r.into_bytes()[..]);
    Ok(commitment)
}

pub fn fauxrep2<R: AsRef<Path>, S: AsRef<Path>, Tree: 'static + MerkleTreeTrait>(
    cache_path: R,
    existing_p_aux_path: S,
) -> Result<Commitment> {
    let mut rng = thread_rng();

    let fake_comm_c = <Tree::Hasher as Hasher>::Domain::random(&mut rng);

    let (comm_r, p_aux) =
        StackedDrg::<Tree, DefaultPieceHasher>::fake_comm_r(fake_comm_c, existing_p_aux_path)?;

    util::persist_p_aux::<Tree>(&p_aux, cache_path.as_ref())?;

    let mut commitment = [0u8; 32];
    commitment[..].copy_from_slice(&comm_r.into_bytes()[..]);
    Ok(commitment)
}
