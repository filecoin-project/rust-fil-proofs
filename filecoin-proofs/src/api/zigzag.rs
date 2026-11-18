//! filecoin-proofs level API for ZigZag layered PoRep.
//!
//! This is the ZigZag analogue of the Stacked DRG seal API in [`crate::api::seal`]. ZigZag has a
//! much simpler replication model than Stacked (a single in-memory layered encoding, with no
//! on-disk labels / `p_aux` / `t_aux` yet), so the flow here is correspondingly smaller:
//!
//! * [`zigzag_pre_commit`] replicates fr32-padded sector data in place, verifies piece infos
//!   against the standard Sha256 CommD, and returns commitments plus in-memory prover state.
//! * [`zigzag_prove`] turns that prover state into a Groth16 proof (optionally bound to a chain
//!   challenge seed).
//! * [`zigzag_verify_seal`] verifies such a proof.
//! * [`zigzag_unseal`] / [`zigzag_unseal_range`] recover original (optionally unpadded) user data.
//!
//! ZigZag uses its own Groth16 parameters (distinct cache id, see
//! [`storage_proofs_porep::zigzag::circuit::ZigZagCompound`]) and a binary Poseidon Merkle tree for
//! replica layers, with a Sha256 binary tree for `comm_d` (Filecoin CommD compatibility).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use filecoin_hashers::Hasher;
use fr32::write_unpadded;
use serde::{Deserialize, Serialize};
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    merkle::{create_base_merkle_tree, BinaryMerkleTree, MerkleTreeTrait},
    multi_proof::MultiProof,
    sector::SectorId,
    util::NODE_SIZE,
};
use storage_proofs_porep::{
    stacked::generate_replica_id,
    zigzag::{
        circuit::ZigZagCompound, ChallengeRequirements, LayerTau, PrivateInputs, PublicInputs, Tau,
        ZigZagDrgPoRep,
    },
};

use crate::{
    api::{as_safe_commitment, commitment_from_fr},
    caches::{get_zigzag_params, get_zigzag_verifying_key},
    constants::{DefaultPieceDomain, DefaultPieceHasher},
    parameters::{zigzag_public_params, zigzag_setup_params},
    pieces::verify_pieces,
    types::{
        Commitment, PaddedBytesAmount, PieceInfo, PoRepConfig, ProverId, SealCommitOutput, Ticket,
        UnpaddedByteIndex, UnpaddedBytesAmount,
    },
};

type TreeDomain<Tree> = <<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain;

/// The public commitments produced by ZigZag replication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZigZagPreCommitOutput {
    /// Commitment to the original (unsealed) data: Sha256 CommD (piece-aggregated).
    pub comm_d: Commitment,
    /// Commitment to the sealed replica: the Poseidon root of the final layer.
    pub comm_r: Commitment,
    /// Aggregate commitment folding `replica_id` and every per-layer replica root.
    pub comm_r_star: Commitment,
}

/// On-chain commitment binding: `H(comm_r || comm_r_star)` as a single 32-byte value the chain
/// can store in place of Stacked's `comm_r`.
pub fn zigzag_comm_r_bound(comm_r: &Commitment, comm_r_star: &Commitment) -> Commitment {
    use sha2::{Digest, Sha256};
    let hash = Sha256::new()
        .chain_update(comm_r)
        .chain_update(comm_r_star)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// In-memory prover state carried from [`zigzag_pre_commit`] / [`zigzag_pre_commit_phase2`] to
/// [`zigzag_prove`]. Trees may be disk-backed when a cache path was supplied.
pub struct ZigZagProverState<Tree: MerkleTreeTrait> {
    replica_id: TreeDomain<Tree>,
    tau: Tau<TreeDomain<Tree>, DefaultPieceDomain>,
    tree_d: BinaryMerkleTree<DefaultPieceHasher>,
    trees: Vec<Tree>,
}

/// Persisted manifest written to the cache directory during phase 1 so sealing can resume.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZigZagAux {
    pub comm_d: Commitment,
    pub comm_r: Commitment,
    pub comm_r_star: Commitment,
    pub replica_id: Commitment,
    pub layers: usize,
}

const ZIGZAG_AUX_FILE: &str = "zigzag-aux.json";

/// Replicate fr32-padded `data` in place using ZigZag layered encoding.
///
/// `data` must be exactly the padded sector size. `piece_infos` must describe the pieces that
/// were written into `data` (via [`crate::add_piece`]); they are verified against the resulting
/// Sha256 CommD. When `cache_path` is `Some`, Merkle trees are persisted under that directory
/// (disk-backed stores) and a [`ZigZagAux`] manifest is written for resumability.
pub fn zigzag_pre_commit<Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    data: &mut [u8],
    piece_infos: &[PieceInfo],
    cache_path: Option<&Path>,
) -> Result<(ZigZagPreCommitOutput, ZigZagProverState<Tree>)> {
    let sector_bytes = usize::from(porep_config.padded_bytes_amount());
    ensure!(
        data.len() == sector_bytes,
        "data length ({}) must equal the padded sector size ({})",
        data.len(),
        sector_bytes,
    );
    ensure!(
        data.len() % NODE_SIZE == 0,
        "data length ({}) must be a multiple of the node size ({})",
        data.len(),
        NODE_SIZE,
    );
    ensure!(!piece_infos.is_empty(), "piece_infos must not be empty");

    let pub_params = zigzag_public_params::<Tree>(porep_config)?;
    let leaves = data.len() / NODE_SIZE;

    // Sha256 CommD over the fr32-padded sector data (matches Filecoin piece aggregation).
    let tree_d_preview =
        create_base_merkle_tree::<BinaryMerkleTree<DefaultPieceHasher>>(None, leaves, data)?;
    let comm_d = commitment_from_fr(tree_d_preview.root().into());
    drop(tree_d_preview);

    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.sector_size)?,
        "pieces and comm_d do not match"
    );

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    if let Some(path) = cache_path {
        fs::create_dir_all(path).context("failed to create zigzag cache directory")?;
    }

    let (tau, tree_d, trees) =
        ZigZagDrgPoRep::<Tree, DefaultPieceHasher>::transform_and_replicate_layers(
            &pub_params.graph,
            &pub_params.layer_challenges,
            &replica_id,
            data,
            cache_path,
        )?;

    let simplified = tau.simplify();
    let out = ZigZagPreCommitOutput {
        comm_d: commitment_from_fr(simplified.comm_d.into()),
        comm_r: commitment_from_fr(simplified.comm_r.into()),
        comm_r_star: commitment_from_fr(tau.comm_r_star.into()),
    };
    ensure!(out.comm_d == comm_d, "comm_d mismatch after replication");

    if let Some(path) = cache_path {
        let aux = ZigZagAux {
            comm_d: out.comm_d,
            comm_r: out.comm_r,
            comm_r_star: out.comm_r_star,
            replica_id: commitment_from_fr(replica_id.into()),
            layers: pub_params.layer_challenges.layers(),
        };
        let aux_path = path.join(ZIGZAG_AUX_FILE);
        let aux_bytes = serde_json::to_vec_pretty(&aux).context("serialize zigzag aux")?;
        fs::write(&aux_path, aux_bytes).context("write zigzag aux")?;
    }

    let state = ZigZagProverState {
        replica_id,
        tau,
        tree_d,
        trees,
    };

    Ok((out, state))
}

/// Phase 1 of ZigZag pre-commit: replicate into `data`, persist disk-backed trees and a
/// [`ZigZagAux`] manifest under `cache_path`.
///
/// The returned [`ZigZagPreCommitOutput`] is enough for on-chain pre-commit; the prover state is
/// also returned for an in-process phase-2/prove path. Callers that must resume later can drop the
/// state and recover commitments from the manifest via [`zigzag_load_aux`].
#[allow(clippy::too_many_arguments)]
pub fn zigzag_pre_commit_phase1<Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
    cache_path: impl AsRef<Path>,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    data: &mut [u8],
    piece_infos: &[PieceInfo],
) -> Result<(ZigZagPreCommitOutput, ZigZagProverState<Tree>)> {
    zigzag_pre_commit(
        porep_config,
        prover_id,
        sector_id,
        ticket,
        data,
        piece_infos,
        Some(cache_path.as_ref()),
    )
}

/// Phase 2 of ZigZag pre-commit: validate the phase-1 manifest and return the public commitments.
///
/// Trees remain on disk under `cache_path` from phase 1. The in-process prover state from phase 1
/// should be passed to [`zigzag_prove`] directly; this phase exists so the seal lifecycle matches
/// Stacked's phase1/phase2 shape for FFI callers.
pub fn zigzag_pre_commit_phase2(
    cache_path: impl AsRef<Path>,
    phase1_output: &ZigZagPreCommitOutput,
) -> Result<ZigZagPreCommitOutput> {
    let aux = zigzag_load_aux(cache_path.as_ref())?;
    ensure!(
        aux.comm_d == phase1_output.comm_d
            && aux.comm_r == phase1_output.comm_r
            && aux.comm_r_star == phase1_output.comm_r_star,
        "phase1 output does not match persisted zigzag aux manifest"
    );
    Ok(*phase1_output)
}

/// Load the [`ZigZagAux`] manifest written by [`zigzag_pre_commit_phase1`].
pub fn zigzag_load_aux(cache_path: impl AsRef<Path>) -> Result<ZigZagAux> {
    let aux_path: PathBuf = cache_path.as_ref().join(ZIGZAG_AUX_FILE);
    let bytes = fs::read(&aux_path)
        .with_context(|| format!("failed to read zigzag aux at {:?}", aux_path))?;
    let aux: ZigZagAux = serde_json::from_slice(&bytes).context("deserialize zigzag aux")?;
    Ok(aux)
}

/// Produce a Groth16 proof for a previously replicated sector.
///
/// When `seed` is `Some`, challenges are derived from the chain-provided ticket (interactive
/// binding). When `None`, challenges derive from `comm_r_star` (non-interactive).
pub fn zigzag_prove<Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
    state: ZigZagProverState<Tree>,
    seed: Option<Ticket>,
) -> Result<SealCommitOutput> {
    let ZigZagProverState {
        replica_id,
        tau,
        tree_d,
        trees,
    } = state;

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: zigzag_setup_params(porep_config)?,
        partitions: Some(usize::from(porep_config.partitions)),
        priority: false,
    };
    let compound_public_params =
        ZigZagCompound::<Tree, DefaultPieceHasher>::setup(&compound_setup_params)?;

    let seed_domain = seed
        .map(|s| as_safe_commitment::<TreeDomain<Tree>, _>(&s, "seed"))
        .transpose()?;

    let public_inputs = PublicInputs {
        replica_id,
        seed: seed_domain,
        tau: Some(tau.simplify()),
        comm_r_star: tau.comm_r_star,
        k: None,
    };
    let private_inputs = PrivateInputs::<Tree, DefaultPieceHasher> {
        tree_d,
        aux: trees,
        layer_comm_rs: tau.layer_comm_rs.clone(),
        comm_d: tau.comm_d,
    };

    let groth_params = get_zigzag_params::<Tree>(porep_config)?;
    let proofs = ZigZagCompound::<Tree, DefaultPieceHasher>::prove(
        &compound_public_params,
        &public_inputs,
        &private_inputs,
        &groth_params,
    )?;

    let verifying_key = get_zigzag_verifying_key::<Tree>(porep_config)?;
    let proof = MultiProof::new(proofs, &verifying_key);

    let mut buf = Vec::new();
    proof.write(&mut buf)?;

    Ok(SealCommitOutput { proof: buf })
}

/// Verify a ZigZag seal proof against the given commitments.
#[allow(clippy::too_many_arguments)]
pub fn zigzag_verify_seal<Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    comm_r_star_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Option<Ticket>,
    proof_vec: &[u8],
) -> Result<bool> {
    ensure!(comm_d_in != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r_in != [0; 32], "Invalid all zero commitment (comm_r)");
    ensure!(
        comm_r_star_in != [0; 32],
        "Invalid all zero commitment (comm_r_star)"
    );
    ensure!(!proof_vec.is_empty(), "Invalid proof bytes (empty vector)");

    let comm_r: TreeDomain<Tree> = as_safe_commitment(&comm_r_in, "comm_r")?;
    let comm_d: DefaultPieceDomain = as_safe_commitment(&comm_d_in, "comm_d")?;
    let comm_r_star: TreeDomain<Tree> = as_safe_commitment(&comm_r_star_in, "comm_r_star")?;

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d_in,
        &porep_config.porep_id,
    );

    let seed_domain = seed
        .map(|s| as_safe_commitment::<TreeDomain<Tree>, _>(&s, "seed"))
        .transpose()?;

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: zigzag_setup_params(porep_config)?,
        partitions: Some(usize::from(porep_config.partitions)),
        priority: false,
    };
    let compound_public_params =
        ZigZagCompound::<Tree, DefaultPieceHasher>::setup(&compound_setup_params)?;

    let public_inputs = PublicInputs {
        replica_id,
        seed: seed_domain,
        tau: Some(LayerTau { comm_d, comm_r }),
        comm_r_star,
        k: None,
    };

    let verifying_key = get_zigzag_verifying_key::<Tree>(porep_config)?;
    let proof = MultiProof::new_from_reader(
        Some(usize::from(porep_config.partitions)),
        proof_vec,
        &verifying_key,
    )?;

    ZigZagCompound::<Tree, DefaultPieceHasher>::verify(
        &compound_public_params,
        &public_inputs,
        &proof,
        &ChallengeRequirements {
            minimum_challenges: porep_config.minimum_challenges(),
        },
    )
}

/// Recover the original fr32-padded data from a sealed replica, in place.
pub fn zigzag_unseal<Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    comm_d_in: Commitment,
    data: &mut [u8],
) -> Result<()> {
    ensure!(
        data.len() % NODE_SIZE == 0,
        "data length ({}) must be a multiple of the node size ({})",
        data.len(),
        NODE_SIZE,
    );

    let pub_params = zigzag_public_params::<Tree>(porep_config)?;

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d_in,
        &porep_config.porep_id,
    );

    ZigZagDrgPoRep::<Tree, DefaultPieceHasher>::extract_and_invert_transform_layers(
        &pub_params.graph,
        &pub_params.layer_challenges,
        &replica_id,
        data,
    )
}

/// Unseal a byte range and write the **unpadded** user bytes to `unsealed_output`.
///
/// `data` must contain the full sealed sector and is decoded in place. `offset` / `num_bytes` are
/// measured in unpadded user bytes (same convention as Stacked's `unseal_range`).
#[allow(clippy::too_many_arguments)]
pub fn zigzag_unseal_range<Tree: 'static + MerkleTreeTrait, W: Write>(
    porep_config: &PoRepConfig,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    comm_d_in: Commitment,
    data: &mut [u8],
    mut unsealed_output: W,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> Result<UnpaddedBytesAmount> {
    zigzag_unseal::<Tree>(
        porep_config,
        prover_id,
        sector_id,
        ticket,
        comm_d_in,
        data,
    )?;

    let offset_padded: PaddedBytesAmount = UnpaddedBytesAmount::from(offset).into();
    let num_bytes_padded: PaddedBytesAmount = num_bytes.into();
    let start: usize = offset_padded.into();
    let end = start + usize::from(num_bytes_padded);
    ensure!(end <= data.len(), "unseal range exceeds sector size");

    let written = write_unpadded(&data[start..end], &mut unsealed_output, 0, num_bytes.into())
        .context("write_unpadded failed")?;

    Ok(UnpaddedBytesAmount(written as u64))
}
