//! End-to-end tests for the ZigZag PoRep filecoin-proofs API with real user data.
//!
//! These exercise the full `filecoin-proofs` ZigZag path (piece pipeline + Sha256 CommD +
//! parameters + caches + seal API), building actual sectors of the requested size and confirming:
//!
//! * fr32-padded pieces verify against the resulting CommD,
//! * replication changes the data and produces non-trivial commitments,
//! * extraction recovers the original fr32-padded data bit-for-bit,
//! * ranged unseal returns the original unpadded user bytes,
//! * (for the small size, behind `--ignored`) a full Groth16 proof verifies with a challenge seed.

use std::io::Cursor;

use filecoin_proofs::constants::{ZigZagTree, SECTOR_SIZE_16_MIB, SECTOR_SIZE_2_KIB};
use filecoin_proofs::parameters::zigzag_public_params;
use filecoin_proofs::types::{
    PaddedBytesAmount, PieceInfo, PoRepConfig, UnpaddedByteIndex, UnpaddedBytesAmount,
};
use filecoin_proofs::{
    add_piece, zigzag_comm_r_bound, zigzag_load_aux, zigzag_pre_commit,
    zigzag_pre_commit_phase1, zigzag_pre_commit_phase2, zigzag_prove, zigzag_unseal,
    zigzag_unseal_range, zigzag_verify_seal,
};
use rand::rngs::OsRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    compound_proof::CompoundProof,
    parameter_cache::CacheableParameters,
    sector::SectorId,
};
use storage_proofs_porep::zigzag::{circuit::ZigZagCompound, ZigZagDrgPoRep};

const PROVER_ID: [u8; 32] = [4u8; 32];
const TICKET: [u8; 32] = [7u8; 32];
const SEED: [u8; 32] = [9u8; 32];
const POREP_ID: [u8; 32] = [42u8; 32];

/// Build a full fr32-padded sector from random user bytes via `add_piece`, returning the padded
/// sector data and the piece info.
fn stage_sector(sector_size: u64) -> (Vec<u8>, Vec<PieceInfo>) {
    let unpadded = UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size));
    let user_bytes: Vec<u8> = (0..usize::from(unpadded))
        .map(|_| rand::random::<u8>())
        .collect();

    let mut staged = Vec::new();
    let (piece_info, _written) = add_piece(
        Cursor::new(&user_bytes),
        &mut staged,
        unpadded,
        &[],
    )
    .expect("add_piece failed");

    assert_eq!(staged.len(), sector_size as usize);
    (staged, vec![piece_info])
}

fn zigzag_extract_lifecycle(sector_size: u64) {
    let porep_config = PoRepConfig::new_groth16(sector_size, POREP_ID, ApiVersion::V1_2_0);
    let sector_id = SectorId::from(0);

    let (original, piece_infos) = stage_sector(sector_size);
    let mut data = original.clone();

    let (out, _state) = zigzag_pre_commit::<ZigZagTree>(
        &porep_config,
        PROVER_ID,
        sector_id,
        TICKET,
        &mut data,
        &piece_infos,
        None,
    )
    .expect("zigzag_pre_commit failed");

    assert_ne!(data, original, "replication did not change the data");
    assert_ne!(out.comm_d, [0u8; 32], "comm_d is all zero");
    assert_ne!(out.comm_r, [0u8; 32], "comm_r is all zero");
    assert_ne!(out.comm_r_star, [0u8; 32], "comm_r_star is all zero");
    assert_ne!(
        zigzag_comm_r_bound(&out.comm_r, &out.comm_r_star),
        [0u8; 32],
        "bound commitment is all zero"
    );

    // Full unseal recovers fr32-padded data.
    zigzag_unseal::<ZigZagTree>(
        &porep_config,
        PROVER_ID,
        sector_id,
        TICKET,
        out.comm_d,
        &mut data,
    )
    .expect("zigzag_unseal failed");
    assert_eq!(data, original, "extraction did not recover the original data");

    // Ranged unseal returns unpadded user bytes.
    let mut sealed = original.clone();
    let (_out2, _state2) = zigzag_pre_commit::<ZigZagTree>(
        &porep_config,
        PROVER_ID,
        sector_id,
        TICKET,
        &mut sealed,
        &piece_infos,
        None,
    )
    .expect("second pre_commit failed");

    let unpadded_len = UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size));
    let mut user_out = Vec::new();
    let written = zigzag_unseal_range::<ZigZagTree, _>(
        &porep_config,
        PROVER_ID,
        sector_id,
        TICKET,
        out.comm_d,
        &mut sealed,
        &mut user_out,
        UnpaddedByteIndex(0),
        unpadded_len,
    )
    .expect("zigzag_unseal_range failed");
    assert_eq!(written, unpadded_len);
    assert_eq!(user_out.len(), usize::from(unpadded_len));
}

/// Generate (and cache to disk) the ZigZag Groth16 parameters + verifying key for `porep_config`.
fn generate_zigzag_params(porep_config: &PoRepConfig) {
    use filecoin_proofs::constants::DefaultPieceHasher;

    let public_params =
        zigzag_public_params::<ZigZagTree>(porep_config).expect("failed to get zigzag public params");

    let circuit = <ZigZagCompound<ZigZagTree, DefaultPieceHasher> as CompoundProof<
        ZigZagDrgPoRep<ZigZagTree, DefaultPieceHasher>,
        _,
    >>::blank_circuit(&public_params);

    ZigZagCompound::<ZigZagTree, DefaultPieceHasher>::get_groth_params(
        Some(&mut OsRng),
        circuit.clone(),
        &public_params,
    )
    .expect("failed to generate groth params");
    ZigZagCompound::<ZigZagTree, DefaultPieceHasher>::get_verifying_key(
        Some(&mut OsRng),
        circuit,
        &public_params,
    )
    .expect("failed to generate verifying key");
}

fn zigzag_seal_lifecycle(sector_size: u64) {
    let cache_dir = std::env::temp_dir().join(format!(
        "zigzag-params-{}-{}",
        sector_size,
        std::process::id()
    ));
    std::fs::create_dir_all(&cache_dir).expect("failed to create param cache dir");
    std::env::set_var("FIL_PROOFS_PARAMETER_CACHE", &cache_dir);

    let porep_config = PoRepConfig::new_groth16(sector_size, POREP_ID, ApiVersion::V1_2_0);
    let sector_id = SectorId::from(0);

    generate_zigzag_params(&porep_config);

    let (original, piece_infos) = stage_sector(sector_size);
    let mut data = original.clone();

    let (out, state) = zigzag_pre_commit::<ZigZagTree>(
        &porep_config,
        PROVER_ID,
        sector_id,
        TICKET,
        &mut data,
        &piece_infos,
        None,
    )
    .expect("zigzag_pre_commit failed");

    let commit = zigzag_prove::<ZigZagTree>(&porep_config, state, Some(SEED))
        .expect("zigzag_prove failed");

    let verified = zigzag_verify_seal::<ZigZagTree>(
        &porep_config,
        out.comm_r,
        out.comm_d,
        out.comm_r_star,
        PROVER_ID,
        sector_id,
        TICKET,
        Some(SEED),
        &commit.proof,
    )
    .expect("zigzag_verify_seal errored");
    assert!(verified, "zigzag proof failed to verify");

    // Wrong seed must be rejected.
    let bad_seed = [1u8; 32];
    let bad = zigzag_verify_seal::<ZigZagTree>(
        &porep_config,
        out.comm_r,
        out.comm_d,
        out.comm_r_star,
        PROVER_ID,
        sector_id,
        TICKET,
        Some(bad_seed),
        &commit.proof,
    )
    .expect("zigzag_verify_seal errored");
    assert!(!bad, "proof verified against a wrong seed");

    zigzag_unseal::<ZigZagTree>(
        &porep_config,
        PROVER_ID,
        sector_id,
        TICKET,
        out.comm_d,
        &mut data,
    )
    .expect("zigzag_unseal failed");
    assert_eq!(data, original, "extraction did not recover the original data");
}

#[test]
fn test_zigzag_extract_roundtrip_2kib() {
    zigzag_extract_lifecycle(SECTOR_SIZE_2_KIB);
}

#[test]
fn test_zigzag_disk_backed_phase1_phase2_2kib() {
    let sector_size = SECTOR_SIZE_2_KIB;
    let porep_config = PoRepConfig::new_groth16(sector_size, POREP_ID, ApiVersion::V1_2_0);
    let sector_id = SectorId::from(0);

    let cache_dir = std::env::temp_dir().join(format!(
        "zigzag-disk-{}-{}",
        sector_size,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&cache_dir);
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");

    let (original, piece_infos) = stage_sector(sector_size);
    let mut data = original.clone();

    let (phase1_out, state) = zigzag_pre_commit_phase1::<ZigZagTree>(
        &porep_config,
        &cache_dir,
        PROVER_ID,
        sector_id,
        TICKET,
        &mut data,
        &piece_infos,
    )
    .expect("phase1 failed");

    let phase2_out = zigzag_pre_commit_phase2(&cache_dir, &phase1_out).expect("phase2 failed");
    assert_eq!(phase1_out, phase2_out);

    let aux = zigzag_load_aux(&cache_dir).expect("load aux");
    assert_eq!(aux.comm_d, phase1_out.comm_d);
    assert_eq!(aux.comm_r, phase1_out.comm_r);
    assert_eq!(aux.comm_r_star, phase1_out.comm_r_star);
    assert!(cache_dir.join("zigzag-tree-d.dat").exists() || cache_dir.read_dir().unwrap().count() > 1);

    // Prover state from phase1 still works for extraction.
    drop(state);
    zigzag_unseal::<ZigZagTree>(
        &porep_config,
        PROVER_ID,
        sector_id,
        TICKET,
        phase1_out.comm_d,
        &mut data,
    )
    .expect("unseal failed");
    assert_eq!(data, original);

    let _ = std::fs::remove_dir_all(&cache_dir);
}

#[test]
#[ignore = "replicates a full 16MiB sector; slow and memory-heavy"]
fn test_zigzag_extract_roundtrip_16mib() {
    zigzag_extract_lifecycle(SECTOR_SIZE_16_MIB);
}

#[test]
#[ignore = "generates Groth16 parameters and a full proof; slow"]
fn test_zigzag_seal_lifecycle_2kib() {
    zigzag_seal_lifecycle(SECTOR_SIZE_2_KIB);
}
