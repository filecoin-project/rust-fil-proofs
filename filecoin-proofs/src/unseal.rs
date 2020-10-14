use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use fr32::write_unpadded;
use log::*;
use merkletree::store::StoreConfig;
use storage_proofs_core::{
    cache_key::CacheKey, hasher::Hasher, merkle::MerkleTreeTrait, sector::SectorId,
    util::default_rows_to_discard,
};
use storage_proofs_porep::{
    stacked::{generate_replica_id, StackedDrg},
    PoRep,
};
use typenum::Unsigned;

use crate::{
    parameters::public_params,
    types::{
        Commitment, DefaultBinaryTree, DefaultPieceHasher, PaddedBytesAmount, PoRepConfig,
        PoRepProofPartitions, ProverId, Ticket, UnpaddedByteIndex, UnpaddedBytesAmount,
    },
    util::{as_safe_commitment, get_base_tree_leafs, get_base_tree_size},
};

/// Unseals the sector at `sealed_path` and returns the bytes for a piece
/// whose first (unpadded) byte begins at `offset` and ends at `offset` plus
/// `num_bytes`, inclusive. Note that the entire sector is unsealed each time
/// this function is called.
///
/// # Arguments
///
/// * `porep_config` - porep configuration containing the sector size.
/// * `cache_path` - path to the directory in which the sector data's Merkle Tree is written.
/// * `sealed_path` - path to the sealed sector file that we will unseal and read a byte range.
/// * `output_path` - path to a file that we will write the requested byte range to.
/// * `prover_id` - the prover-id that sealed the sector.
/// * `sector_id` - the sector-id of the sealed sector.
/// * `comm_d` - the commitment to the sector's data.
/// * `ticket` - the ticket that was used to generate the sector's replica-id.
/// * `offset` - the byte index in the unsealed sector of the first byte that we want to read.
/// * `num_bytes` - the number of bytes that we want to read.
#[allow(clippy::too_many_arguments)]
pub fn get_unsealed_range<T: Into<PathBuf> + AsRef<Path>, Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    cache_path: T,
    sealed_path: T,
    output_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    comm_d: Commitment,
    ticket: Ticket,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> Result<UnpaddedBytesAmount> {
    info!("get_unsealed_range:start");

    let f_in = File::open(&sealed_path)
        .with_context(|| format!("could not open sealed_path={:?}", sealed_path.as_ref()))?;

    let f_out = File::create(&output_path)
        .with_context(|| format!("could not create output_path={:?}", output_path.as_ref()))?;

    let buf_f_out = BufWriter::new(f_out);

    let result = unseal_range::<_, _, _, Tree>(
        porep_config,
        cache_path,
        f_in,
        buf_f_out,
        prover_id,
        sector_id,
        comm_d,
        ticket,
        offset,
        num_bytes,
    );

    info!("get_unsealed_range:finish");
    result
}

/// Unseals the sector read from `sealed_sector` and returns the bytes for a
/// piece whose first (unpadded) byte begins at `offset` and ends at `offset`
/// plus `num_bytes`, inclusive. Note that the entire sector is unsealed each
/// time this function is called.
///
/// # Arguments
///
/// * `porep_config` - porep configuration containing the sector size.
/// * `cache_path` - path to the directory in which the sector data's Merkle Tree is written.
/// * `sealed_sector` - a byte source from which we read sealed sector data.
/// * `unsealed_output` - a byte sink to which we write unsealed, un-bit-padded sector bytes.
/// * `prover_id` - the prover-id that sealed the sector.
/// * `sector_id` - the sector-id of the sealed sector.
/// * `comm_d` - the commitment to the sector's data.
/// * `ticket` - the ticket that was used to generate the sector's replica-id.
/// * `offset` - the byte index in the unsealed sector of the first byte that we want to read.
/// * `num_bytes` - the number of bytes that we want to read.
#[allow(clippy::too_many_arguments)]
pub fn unseal_range<P, R, W, Tree>(
    porep_config: PoRepConfig,
    cache_path: P,
    mut sealed_sector: R,
    mut unsealed_output: W,
    prover_id: ProverId,
    sector_id: SectorId,
    comm_d: Commitment,
    ticket: Ticket,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> Result<UnpaddedBytesAmount>
where
    P: Into<PathBuf> + AsRef<Path>,
    R: Read,
    W: Write,
    Tree: 'static + MerkleTreeTrait,
{
    info!("unseal_range:start");
    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");

    let comm_d =
        as_safe_commitment::<<DefaultPieceHasher as Hasher>::Domain, _>(&comm_d, "comm_d")?;

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let mut data = Vec::new();
    sealed_sector.read_to_end(&mut data)?;

    let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(porep_config.sector_size)?;
    let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size)?;
    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let config = StoreConfig::new(
        cache_path.as_ref(),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(
            base_tree_leafs,
            <DefaultBinaryTree as MerkleTreeTrait>::Arity::to_usize(),
        ),
    );
    let pp = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
    )?;

    let offset_padded: PaddedBytesAmount = UnpaddedBytesAmount::from(offset).into();
    let num_bytes_padded: PaddedBytesAmount = num_bytes.into();

    let unsealed_all =
        StackedDrg::<Tree, DefaultPieceHasher>::extract_all(&pp, &replica_id, &data, Some(config))?;
    let start: usize = offset_padded.into();
    let end = start + usize::from(num_bytes_padded);
    let unsealed = &unsealed_all[start..end];

    // If the call to `extract_range` was successful, the `unsealed` vector must
    // have a length which equals `num_bytes_padded`. The byte at its 0-index
    // byte will be the the byte at index `offset_padded` in the sealed sector.
    let written = write_unpadded(unsealed, &mut unsealed_output, 0, num_bytes.into())
        .context("write_unpadded failed")?;

    let amount = UnpaddedBytesAmount(written as u64);

    info!("unseal_range:finish");
    Ok(amount)
}
