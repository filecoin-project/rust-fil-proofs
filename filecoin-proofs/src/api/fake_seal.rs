use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use anyhow::{Context, Result};
use bincode::serialize;
use filecoin_hashers::{Domain, Hasher};
use storage_proofs::cache_key::CacheKey;
use storage_proofs::merkle::MerkleTreeTrait;
use storage_proofs::porep::stacked::StackedDrg;

use crate::constants::DefaultPieceHasher;
pub use crate::pieces;
pub use crate::pieces::verify_pieces;
use crate::types::{Commitment, PaddedBytesAmount, PoRepConfig};

pub fn fauxrep<R: AsRef<Path>, S: AsRef<Path>, Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    cache_path: R,
    out_path: S,
) -> Result<Commitment> {
    let mut rng = rand::thread_rng();
    fauxrep_aux::<_, R, S, Tree>(&mut rng, porep_config, cache_path, out_path)
}

pub fn fauxrep_aux<
    Rng: rand::Rng,
    R: AsRef<Path>,
    S: AsRef<Path>,
    Tree: 'static + MerkleTreeTrait,
>(
    mut rng: &mut Rng,
    porep_config: PoRepConfig,
    cache_path: R,
    out_path: S,
) -> Result<Commitment> {
    let sector_bytes = PaddedBytesAmount::from(porep_config).0;

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

    let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
    let mut f_p_aux = File::create(&p_aux_path)
        .with_context(|| format!("could not create file p_aux={:?}", p_aux_path))?;
    let p_aux_bytes = serialize(&p_aux)?;
    f_p_aux
        .write_all(&p_aux_bytes)
        .with_context(|| format!("could not write to file p_aux={:?}", p_aux_path))?;

    let mut commitment = [0u8; 32];
    commitment[..].copy_from_slice(&comm_r.into_bytes()[..]);
    Ok(commitment)
}

pub fn fauxrep2<R: AsRef<Path>, S: AsRef<Path>, Tree: 'static + MerkleTreeTrait>(
    cache_path: R,
    existing_p_aux_path: S,
) -> Result<Commitment> {
    let mut rng = rand::thread_rng();

    let fake_comm_c = <Tree::Hasher as Hasher>::Domain::random(&mut rng);

    let (comm_r, p_aux) =
        StackedDrg::<Tree, DefaultPieceHasher>::fake_comm_r(fake_comm_c, existing_p_aux_path)?;

    let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
    let mut f_p_aux = File::create(&p_aux_path)
        .with_context(|| format!("could not create file p_aux={:?}", p_aux_path))?;
    let p_aux_bytes = serialize(&p_aux)?;
    f_p_aux
        .write_all(&p_aux_bytes)
        .with_context(|| format!("could not write to file p_aux={:?}", p_aux_path))?;

    let mut commitment = [0u8; 32];
    commitment[..].copy_from_slice(&comm_r.into_bytes()[..]);
    Ok(commitment)
}
