use std::collections::BTreeMap;
use std::fs::{read_dir, remove_file};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Once;

use anyhow::{ensure, Result};
use bellperson::bls::{Bls12, Fr};
use bellperson::groth16;
use bincode::serialize;
use ff::Field;
use filecoin_hashers::Hasher;
use filecoin_proofs::{
    add_piece, aggregate_seal_commit_proofs, clear_cache, compute_comm_d, fauxrep_aux,
    generate_fallback_sector_challenges, generate_piece_commitment, generate_single_vanilla_proof,
    generate_window_post, generate_window_post_with_vanilla, generate_winning_post,
    generate_winning_post_sector_challenge, generate_winning_post_with_vanilla, get_seal_inputs,
    seal_commit_phase1, seal_commit_phase2, seal_pre_commit_phase1, seal_pre_commit_phase2,
    unseal_range, validate_cache_for_commit, validate_cache_for_precommit_phase2,
    verify_aggregate_seal_commit_proofs, verify_seal, verify_window_post, verify_winning_post,
    Commitment, DefaultTreeDomain, MerkleTreeTrait, PaddedBytesAmount, PieceInfo, PoRepConfig,
    PoRepProofPartitions, PoStConfig, PoStType, PrivateReplicaInfo, ProverId, PublicReplicaInfo,
    SealCommitOutput, SealPreCommitOutput, SealPreCommitPhase1Output, SectorShape16KiB,
    SectorShape2KiB, SectorShape32KiB, SectorShape4KiB, SectorSize, UnpaddedByteIndex,
    UnpaddedBytesAmount, POREP_PARTITIONS, SECTOR_SIZE_16_KIB, SECTOR_SIZE_2_KIB,
    SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB, WINDOW_POST_CHALLENGE_COUNT, WINDOW_POST_SECTOR_COUNT,
    WINNING_POST_CHALLENGE_COUNT, WINNING_POST_SECTOR_COUNT,
};
use rand::{random, Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{api_version::ApiVersion, is_legacy_porep_id, sector::SectorId};
use tempfile::{tempdir, NamedTempFile, TempDir};

// Use a fixed PoRep ID, so that the parents cache can be re-used between some tests.
// Note however, that parents caches cannot be shared when testing the differences
// between API v1 and v2 behaviour (since the parent caches will be different for the
// same porep_ids).
const ARBITRARY_POREP_ID_V1_0_0: [u8; 32] = [127; 32];
const ARBITRARY_POREP_ID_V1_1_0: [u8; 32] = [128; 32];

static INIT_LOGGER: Once = Once::new();
fn init_logger() {
    INIT_LOGGER.call_once(|| {
        fil_logger::init();
    });
}

const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];

#[test]
#[ignore]
fn test_seal_lifecycle_2kib_porep_id_v1_base_8() -> Result<()> {
    let porep_id_v1: u64 = 0; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
    assert!(is_legacy_porep_id(porep_id));
    seal_lifecycle::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, &porep_id, ApiVersion::V1_0_0)
}

#[test]
#[ignore]
fn test_seal_lifecycle_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    seal_lifecycle::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, &porep_id, ApiVersion::V1_1_0)
}

#[test]
#[ignore]
fn test_seal_lifecycle_4kib_sub_8_2() -> Result<()> {
    seal_lifecycle::<SectorShape4KiB>(
        SECTOR_SIZE_4_KIB,
        &ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_0_0,
    )?;
    seal_lifecycle::<SectorShape4KiB>(
        SECTOR_SIZE_4_KIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_seal_lifecycle_16kib_sub_8_2() -> Result<()> {
    seal_lifecycle::<SectorShape16KiB>(
        SECTOR_SIZE_16_KIB,
        &ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_0_0,
    )?;
    seal_lifecycle::<SectorShape16KiB>(
        SECTOR_SIZE_16_KIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_seal_lifecycle_32kib_top_8_8_2() -> Result<()> {
    seal_lifecycle::<SectorShape32KiB>(
        SECTOR_SIZE_32_KIB,
        &ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_0_0,
    )?;
    seal_lifecycle::<SectorShape32KiB>(
        SECTOR_SIZE_32_KIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

// These tests are good to run, but take a long time.

//#[test]
//#[ignore]
//fn test_seal_lifecycle_512mib_porep_id_v1_top_8_0_0_api_v1() -> Result<()> {
//    let porep_id_v1: u64 = 2; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
//    assert!(is_legacy_porep_id(porep_id));
//    seal_lifecycle::<SectorShape512MiB>(SECTOR_SIZE_512_MIB, &porep_id, ApiVersion::V1_0_0)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_512mib_porep_id_v1_top_8_0_0_api_v1_1() -> Result<()> {
//    let porep_id_v1_1: u64 = 7; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
//    assert!(!is_legacy_porep_id(porep_id));
//    seal_lifecycle::<SectorShape512MiB>(SECTOR_SIZE_512_MIB, &porep_id, ApiVersion::V1_1_0)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_32gib_porep_id_v1_top_8_8_0_api_v1() -> Result<()> {
//    let porep_id_v1: u64 = 3; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
//    assert!(is_legacy_porep_id(porep_id));
//    seal_lifecycle::<SectorShape32GiB>(SECTOR_SIZE_32_GIB, &porep_id, ApiVersion::V1_0_0)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_32gib_porep_id_v1_1_top_8_8_0_api_v1_1() -> Result<()> {
//    let porep_id_v1_1: u64 = 8; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
//    assert!(!is_legacy_porep_id(porep_id));
//    seal_lifecycle::<SectorShape32GiB>(SECTOR_SIZE_32_GIB, &porep_id, ApiVersion::V1_1_0)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_64gib_porep_id_v1_top_8_8_2_api_v1() -> Result<()> {
//    let porep_id_v1: u64 = 4; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
//    assert!(is_legacy_porep_id(porep_id));
//    seal_lifecycle::<SectorShape64GiB>(SECTOR_SIZE_64_GIB, &porep_id, ApiVersion::V1_0_0)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_64gib_porep_id_v1_1_top_8_8_2_api_v1_1() -> Result<()> {
//    let porep_id_v1_1: u64 = 9; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
//    assert!(!is_legacy_porep_id(porep_id));
//    seal_lifecycle::<SectorShape64GiB>(SECTOR_SIZE_64_GIB, &porep_id, ApiVersion::V1_1_0)
//}

fn seal_lifecycle<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
) -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    create_seal::<_, Tree>(rng, sector_size, prover_id, false, porep_id, api_version)?;
    Ok(())
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_1_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 1; // Requires auto-padding

    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    let verified = aggregate_proofs::<SectorShape2KiB>(
        SECTOR_SIZE_2_KIB,
        &porep_id,
        ApiVersion::V1_1_0,
        proofs_to_aggregate,
    )?;
    assert!(verified);

    Ok(())
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_3_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 3; // Requires auto-padding
    inner_test_seal_proof_aggregation_2kib_porep_id_v1_1_base_8(proofs_to_aggregate)
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_5_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 5; // Requires auto-padding
    inner_test_seal_proof_aggregation_2kib_porep_id_v1_1_base_8(proofs_to_aggregate)
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_257_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 257; // Requires auto-padding
    inner_test_seal_proof_aggregation_2kib_porep_id_v1_1_base_8(proofs_to_aggregate)
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_2_4kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 2;

    let porep_id = ARBITRARY_POREP_ID_V1_1_0;
    assert!(!is_legacy_porep_id(porep_id));
    let verified = aggregate_proofs::<SectorShape4KiB>(
        SECTOR_SIZE_4_KIB,
        &porep_id,
        ApiVersion::V1_1_0,
        proofs_to_aggregate,
    )?;
    assert!(verified);

    Ok(())
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_1_32kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 1; // Requires auto-padding

    let porep_id = ARBITRARY_POREP_ID_V1_1_0;
    assert!(!is_legacy_porep_id(porep_id));
    let verified = aggregate_proofs::<SectorShape32KiB>(
        SECTOR_SIZE_32_KIB,
        &porep_id,
        ApiVersion::V1_1_0,
        proofs_to_aggregate,
    )?;
    assert!(verified);

    Ok(())
}

//#[test]
//#[ignore]
//fn test_seal_proof_aggregation_1024_2kib_porep_id_v1_1_base_8() -> Result<()> {
//    let proofs_to_aggregate = 1024;
//    inner_test_seal_proof_aggregation_2kib_porep_id_v1_1_base_8(proofs_to_aggregate)
//}
//
//#[test]
//#[ignore]
//fn test_seal_proof_aggregation_65536_2kib_porep_id_v1_1_base_8() -> Result<()> {
//    let proofs_to_aggregate = 65536;
//    inner_test_seal_proof_aggregation_2kib_porep_id_v1_1_base_8(proofs_to_aggregate)
//}

fn inner_test_seal_proof_aggregation_2kib_porep_id_v1_1_base_8(
    proofs_to_aggregate: usize,
) -> Result<()> {
    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));

    let rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let mut commit_outputs = Vec::with_capacity(proofs_to_aggregate);
    let mut commit_inputs = Vec::with_capacity(proofs_to_aggregate);
    let mut seeds = Vec::with_capacity(proofs_to_aggregate);
    let mut comm_rs = Vec::with_capacity(proofs_to_aggregate);

    let (commit_output, commit_input, seed, comm_r) =
        create_seal_for_aggregation::<_, SectorShape2KiB>(
            rng,
            SECTOR_SIZE_2_KIB,
            prover_id,
            &porep_id,
            ApiVersion::V1_1_0,
        )?;

    // duplicate a single proof to desired target for aggregation
    for _ in 0..proofs_to_aggregate {
        commit_outputs.push(commit_output.clone());
        commit_inputs.extend(commit_input.clone());
        seeds.push(seed);
        comm_rs.push(comm_r);
    }

    let config = porep_config(SECTOR_SIZE_2_KIB, porep_id, ApiVersion::V1_1_0);
    let aggregate_proof = aggregate_seal_commit_proofs::<SectorShape2KiB>(
        config,
        &comm_rs,
        &seeds,
        commit_outputs.as_slice(),
    )?;
    let verified = verify_aggregate_seal_commit_proofs::<SectorShape2KiB>(
        config,
        aggregate_proof,
        &comm_rs,
        &seeds,
        commit_inputs,
    )?;
    assert!(verified);

    Ok(())
}

fn aggregate_proofs<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
    num_proofs_to_aggregate: usize,
) -> Result<bool> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let mut commit_outputs = Vec::with_capacity(num_proofs_to_aggregate);
    let mut commit_inputs = Vec::with_capacity(num_proofs_to_aggregate);
    let mut seeds = Vec::with_capacity(num_proofs_to_aggregate);
    let mut comm_rs = Vec::with_capacity(num_proofs_to_aggregate);

    for _ in 0..num_proofs_to_aggregate {
        let (commit_output, commit_input, seed, comm_r) = create_seal_for_aggregation::<_, Tree>(
            rng,
            sector_size,
            prover_id,
            porep_id,
            api_version,
        )?;
        commit_outputs.push(commit_output);
        commit_inputs.extend(commit_input);
        seeds.push(seed);
        comm_rs.push(comm_r);
    }

    let config = porep_config(sector_size, *porep_id, api_version);
    let aggregate_proof =
        aggregate_seal_commit_proofs::<Tree>(config, &comm_rs, &seeds, commit_outputs.as_slice())?;
    verify_aggregate_seal_commit_proofs::<Tree>(
        config,
        aggregate_proof,
        &comm_rs,
        &seeds,
        commit_inputs,
    )
}

fn get_layer_file_paths(cache_dir: &tempfile::TempDir) -> Vec<PathBuf> {
    let mut list: Vec<_> = read_dir(&cache_dir)
        .unwrap_or_else(|_| panic!("failed to read directory {:?}", cache_dir))
        .filter_map(|entry| {
            let cur = entry.expect("reading directory failed");
            let entry_path = cur.path();
            let entry_str = entry_path.to_str().expect("failed to get string from path");
            if entry_str.contains("data-layer") {
                Some(entry_path.clone())
            } else {
                None
            }
        })
        .collect();
    list.sort();
    list
}

fn clear_cache_dir_keep_data_layer(cache_dir: &TempDir) {
    for entry in read_dir(&cache_dir).expect("faailed to read directory") {
        let entry_path = entry.expect("failed get directory entry").path();
        if entry_path.is_file() {
            // delete everything except the data-layers
            if !entry_path
                .to_str()
                .expect("failed to get string from path")
                .contains("data-layer")
            {
                remove_file(entry_path).expect("failed to remove file")
            }
        }
    }
}

#[test]
fn test_resumable_seal_skip_proofs_v1() {
    let porep_id_v1: u64 = 0; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
    assert!(is_legacy_porep_id(porep_id));
    run_resumable_seal::<SectorShape2KiB>(true, 0, &porep_id, ApiVersion::V1_0_0);
    run_resumable_seal::<SectorShape2KiB>(true, 1, &porep_id, ApiVersion::V1_0_0);
}

#[test]
fn test_resumable_seal_skip_proofs_v1_1() {
    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    run_resumable_seal::<SectorShape2KiB>(true, 0, &porep_id, ApiVersion::V1_1_0);
    run_resumable_seal::<SectorShape2KiB>(true, 1, &porep_id, ApiVersion::V1_1_0);
}

#[test]
#[ignore]
fn test_resumable_seal_v1() {
    let porep_id_v1: u64 = 0; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
    assert!(is_legacy_porep_id(porep_id));
    run_resumable_seal::<SectorShape2KiB>(false, 0, &porep_id, ApiVersion::V1_0_0);
    run_resumable_seal::<SectorShape2KiB>(false, 1, &porep_id, ApiVersion::V1_0_0);
}

#[test]
#[ignore]
fn test_resumable_seal_v1_1() {
    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    run_resumable_seal::<SectorShape2KiB>(false, 0, &porep_id, ApiVersion::V1_1_0);
    run_resumable_seal::<SectorShape2KiB>(false, 1, &porep_id, ApiVersion::V1_1_0);
}

/// Create a seal, delete a layer and resume
///
/// The current code works on two layers only. The `layer_to_delete` specifies (zero-based) which
/// layer should be deleted.
fn run_resumable_seal<Tree: 'static + MerkleTreeTrait>(
    skip_proofs: bool,
    layer_to_delete: usize,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
) {
    init_logger();

    let sector_size = SECTOR_SIZE_2_KIB;
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let (mut piece_file, piece_bytes) =
        generate_piece_file(sector_size).expect("failed to generate piece file");
    let sealed_sector_file = NamedTempFile::new().expect("failed to created sealed sector file");
    let cache_dir = tempdir().expect("failed to create temp dir");

    let config = porep_config(sector_size, *porep_id, api_version);
    let ticket = rng.gen();
    let sector_id = rng.gen::<u64>().into();

    // First create seals as expected
    run_seal_pre_commit_phase1::<Tree>(
        config,
        prover_id,
        sector_id,
        ticket,
        &cache_dir,
        &mut piece_file,
        &sealed_sector_file,
    )
    .expect("failed to run seal pre commit phase1");
    let layers = get_layer_file_paths(&cache_dir);
    assert_eq!(layers.len(), 2, "not all expected layers were created");

    // Delete one layer, keep the other
    clear_cache_dir_keep_data_layer(&cache_dir);
    remove_file(&layers[layer_to_delete]).expect("failed to remove layer");
    let layers_remaining = get_layer_file_paths(&cache_dir);
    assert_eq!(layers_remaining.len(), 1, "expected one layer only");
    if layer_to_delete == 0 {
        assert_eq!(layers_remaining[0], layers[1], "wrong layer was removed");
    } else {
        assert_eq!(layers_remaining[0], layers[0], "wrong layer was removed");
    }

    // Resume the seal
    piece_file
        .seek(SeekFrom::Start(0))
        .expect("failed to seek piece file to start");
    let (piece_infos, phase1_output) = run_seal_pre_commit_phase1::<Tree>(
        config,
        prover_id,
        sector_id,
        ticket,
        &cache_dir,
        &mut piece_file,
        &sealed_sector_file,
    )
    .expect("failed to run seal pre commit phase1");

    // Running proofs clears the cache, hence we can only check for existence of files if we don't
    // run them
    if skip_proofs {
        let layers_recreated = get_layer_file_paths(&cache_dir);
        assert_eq!(
            layers_recreated.len(),
            2,
            "not all expected layers were recreated"
        );
        assert_eq!(
            layers_recreated, layers,
            "recreated layers don't match original ones"
        );
    } else {
        let pre_commit_output = seal_pre_commit_phase2(
            config,
            phase1_output,
            cache_dir.path(),
            sealed_sector_file.path(),
        )
        .expect("failed to run seal pre commit phase2");

        validate_cache_for_commit::<_, _, Tree>(cache_dir.path(), sealed_sector_file.path())
            .expect("failed to validate cache for commit");

        let seed = rng.gen();
        proof_and_unseal::<Tree>(
            config,
            cache_dir.path(),
            &sealed_sector_file,
            prover_id,
            sector_id,
            ticket,
            seed,
            pre_commit_output,
            &piece_infos,
            &piece_bytes,
        )
        .expect("failed to proof");
    }
}

#[test]
#[ignore]
fn test_winning_post_2kib_base_8() -> Result<()> {
    winning_post::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, false, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, true, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, false, ApiVersion::V1_1_0)?;
    winning_post::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, true, ApiVersion::V1_1_0)
}

#[test]
#[ignore]
fn test_winning_post_4kib_sub_8_2() -> Result<()> {
    winning_post::<SectorShape4KiB>(SECTOR_SIZE_4_KIB, false, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape4KiB>(SECTOR_SIZE_4_KIB, true, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape4KiB>(SECTOR_SIZE_4_KIB, false, ApiVersion::V1_1_0)?;
    winning_post::<SectorShape4KiB>(SECTOR_SIZE_4_KIB, true, ApiVersion::V1_1_0)
}

#[test]
#[ignore]
fn test_winning_post_16kib_sub_8_8() -> Result<()> {
    winning_post::<SectorShape16KiB>(SECTOR_SIZE_16_KIB, false, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape16KiB>(SECTOR_SIZE_16_KIB, true, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape16KiB>(SECTOR_SIZE_16_KIB, false, ApiVersion::V1_1_0)?;
    winning_post::<SectorShape16KiB>(SECTOR_SIZE_16_KIB, true, ApiVersion::V1_1_0)
}

#[test]
#[ignore]
fn test_winning_post_32kib_top_8_8_2() -> Result<()> {
    winning_post::<SectorShape32KiB>(SECTOR_SIZE_32_KIB, false, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape32KiB>(SECTOR_SIZE_32_KIB, true, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape32KiB>(SECTOR_SIZE_32_KIB, false, ApiVersion::V1_1_0)?;
    winning_post::<SectorShape32KiB>(SECTOR_SIZE_32_KIB, true, ApiVersion::V1_1_0)
}

#[test]
fn test_winning_post_empty_sector_challenge() -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let sector_count = 0;
    let sector_size = SECTOR_SIZE_2_KIB;
    let api_version = ApiVersion::V1_1_0;

    let (_, _, _, _) = create_seal::<_, SectorShape2KiB>(
        rng,
        sector_size,
        prover_id,
        true,
        &ARBITRARY_POREP_ID_V1_1_0,
        api_version,
    )?;

    let random_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        typ: PoStType::Winning,
        priority: false,
        api_version: ApiVersion::V1_0_0,
    };

    assert!(generate_winning_post_sector_challenge::<SectorShape2KiB>(
        &config,
        &randomness,
        sector_count as u64,
        prover_id
    )
    .is_err());

    Ok(())
}

fn winning_post<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    fake: bool,
    api_version: ApiVersion,
) -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let porep_id = match api_version {
        ApiVersion::V1_0_0 => ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_1_0 => ARBITRARY_POREP_ID_V1_1_0,
    };

    let (sector_id, replica, comm_r, cache_dir) = if fake {
        create_fake_seal::<_, Tree>(rng, sector_size, &porep_id, api_version)?
    } else {
        create_seal::<_, Tree>(rng, sector_size, prover_id, true, &porep_id, api_version)?
    };
    let sector_count = WINNING_POST_SECTOR_COUNT;

    let random_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        typ: PoStType::Winning,
        priority: false,
        api_version,
    };

    let challenged_sectors = generate_winning_post_sector_challenge::<Tree>(
        &config,
        &randomness,
        sector_count as u64,
        prover_id,
    )?;
    assert_eq!(challenged_sectors.len(), sector_count);
    assert_eq!(challenged_sectors[0], 0); // with a sector_count of 1, the only valid index is 0

    let pub_replicas = vec![(sector_id, PublicReplicaInfo::new(comm_r)?)];
    let private_replica_info =
        PrivateReplicaInfo::new(replica.path().into(), comm_r, cache_dir.path().into())?;

    /////////////////////////////////////////////
    // The following methods of proof generation are functionally equivalent:
    // 1)
    //
    let priv_replicas = vec![(sector_id, private_replica_info.clone())];
    let proof = generate_winning_post::<Tree>(&config, &randomness, &priv_replicas[..], prover_id)?;

    let valid =
        verify_winning_post::<Tree>(&config, &randomness, &pub_replicas[..], prover_id, &proof)?;
    assert!(valid, "proof did not verify");

    //
    // 2)
    let mut vanilla_proofs = Vec::with_capacity(sector_count);
    let challenges =
        generate_fallback_sector_challenges::<Tree>(&config, &randomness, &[sector_id], prover_id)?;

    let single_proof = generate_single_vanilla_proof::<Tree>(
        &config,
        sector_id,
        &private_replica_info,
        &challenges[&sector_id],
    )?;

    vanilla_proofs.push(single_proof);

    let proof = generate_winning_post_with_vanilla::<Tree>(
        &config,
        &randomness,
        prover_id,
        vanilla_proofs,
    )?;
    /////////////////////////////////////////////

    let valid =
        verify_winning_post::<Tree>(&config, &randomness, &pub_replicas[..], prover_id, &proof)?;
    assert!(valid, "proof did not verify");

    Ok(())
}

#[test]
#[ignore]
fn test_window_post_single_partition_smaller_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    window_post::<SectorShape2KiB>(
        sector_size,
        sector_count / 2,
        sector_count,
        false,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        sector_count / 2,
        sector_count,
        true,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        sector_count / 2,
        sector_count,
        false,
        ApiVersion::V1_1_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        sector_count / 2,
        sector_count,
        true,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_window_post_two_partitions_matching_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    window_post::<SectorShape2KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        false,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        true,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        false,
        ApiVersion::V1_1_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        true,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_window_post_two_partitions_matching_4kib_sub_8_2() -> Result<()> {
    let sector_size = SECTOR_SIZE_4_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    window_post::<SectorShape4KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        false,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape4KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        true,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape4KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        false,
        ApiVersion::V1_1_0,
    )?;
    window_post::<SectorShape4KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        true,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_window_post_two_partitions_matching_16kib_sub_8_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_16_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    window_post::<SectorShape16KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        false,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape16KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        true,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape16KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        false,
        ApiVersion::V1_1_0,
    )?;
    window_post::<SectorShape16KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        true,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_window_post_two_partitions_matching_32kib_top_8_8_2() -> Result<()> {
    let sector_size = SECTOR_SIZE_32_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    window_post::<SectorShape32KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        false,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape32KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        true,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape32KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        false,
        ApiVersion::V1_1_0,
    )?;
    window_post::<SectorShape32KiB>(
        sector_size,
        2 * sector_count,
        sector_count,
        true,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_window_post_two_partitions_smaller_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    window_post::<SectorShape2KiB>(
        sector_size,
        2 * sector_count - 1,
        sector_count,
        false,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        2 * sector_count - 1,
        sector_count,
        true,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        2 * sector_count - 1,
        sector_count,
        false,
        ApiVersion::V1_1_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        2 * sector_count - 1,
        sector_count,
        true,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_window_post_single_partition_matching_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    window_post::<SectorShape2KiB>(
        sector_size,
        sector_count,
        sector_count,
        false,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        sector_count,
        sector_count,
        true,
        ApiVersion::V1_0_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        sector_count,
        sector_count,
        false,
        ApiVersion::V1_1_0,
    )?;
    window_post::<SectorShape2KiB>(
        sector_size,
        sector_count,
        sector_count,
        true,
        ApiVersion::V1_1_0,
    )
}

fn window_post<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    total_sector_count: usize,
    sector_count: usize,
    fake: bool,
    api_version: ApiVersion,
) -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let mut sectors = Vec::with_capacity(total_sector_count);
    let mut pub_replicas = BTreeMap::new();
    let mut priv_replicas = BTreeMap::new();

    let prover_fr: <Tree::Hasher as Hasher>::Domain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let porep_id = match api_version {
        ApiVersion::V1_0_0 => ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_1_0 => ARBITRARY_POREP_ID_V1_1_0,
    };

    for _ in 0..total_sector_count {
        let (sector_id, replica, comm_r, cache_dir) = if fake {
            create_fake_seal::<_, Tree>(rng, sector_size, &porep_id, api_version)?
        } else {
            create_seal::<_, Tree>(rng, sector_size, prover_id, true, &porep_id, api_version)?
        };
        priv_replicas.insert(
            sector_id,
            PrivateReplicaInfo::new(replica.path().into(), comm_r, cache_dir.path().into())?,
        );
        pub_replicas.insert(sector_id, PublicReplicaInfo::new(comm_r)?);
        sectors.push((sector_id, replica, comm_r, cache_dir, prover_id));
    }
    assert_eq!(priv_replicas.len(), total_sector_count);
    assert_eq!(pub_replicas.len(), total_sector_count);
    assert_eq!(sectors.len(), total_sector_count);

    let random_fr: <Tree::Hasher as Hasher>::Domain = Fr::random(rng).into();
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINDOW_POST_CHALLENGE_COUNT,
        typ: PoStType::Window,
        priority: false,
        api_version,
    };

    /////////////////////////////////////////////
    // The following methods of proof generation are functionally equivalent:
    // 1)
    let proof = generate_window_post::<Tree>(&config, &randomness, &priv_replicas, prover_id)?;

    let valid = verify_window_post::<Tree>(&config, &randomness, &pub_replicas, prover_id, &proof)?;
    assert!(valid, "proof did not verify");

    // 2)
    let replica_sectors = priv_replicas
        .iter()
        .map(|(sector, _replica)| *sector)
        .collect::<Vec<SectorId>>();

    let challenges = generate_fallback_sector_challenges::<Tree>(
        &config,
        &randomness,
        &replica_sectors,
        prover_id,
    )?;

    let mut vanilla_proofs = Vec::with_capacity(replica_sectors.len());

    for (sector_id, replica) in priv_replicas.iter() {
        let sector_challenges = &challenges[sector_id];
        let single_proof =
            generate_single_vanilla_proof::<Tree>(&config, *sector_id, replica, sector_challenges)?;

        vanilla_proofs.push(single_proof);
    }

    let proof =
        generate_window_post_with_vanilla::<Tree>(&config, &randomness, prover_id, vanilla_proofs)?;
    /////////////////////////////////////////////

    let valid = verify_window_post::<Tree>(&config, &randomness, &pub_replicas, prover_id, &proof)?;
    assert!(valid, "proof did not verify");

    Ok(())
}

fn generate_piece_file(sector_size: u64) -> Result<(NamedTempFile, Vec<u8>)> {
    let number_of_bytes_in_piece = UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size));

    let piece_bytes: Vec<u8> = (0..number_of_bytes_in_piece.0)
        .map(|_| random::<u8>())
        .collect();

    let mut piece_file = NamedTempFile::new()?;
    piece_file.write_all(&piece_bytes)?;
    piece_file.as_file_mut().sync_all()?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    Ok((piece_file, piece_bytes))
}

fn porep_config(sector_size: u64, porep_id: [u8; 32], api_version: ApiVersion) -> PoRepConfig {
    PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS
                .read()
                .expect("POREP_PARTITIONS poisoned")
                .get(&sector_size)
                .expect("unknown sector size"),
        ),
        porep_id,
        api_version,
    }
}

fn run_seal_pre_commit_phase1<Tree: 'static + MerkleTreeTrait>(
    config: PoRepConfig,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: [u8; 32],
    cache_dir: &TempDir,
    mut piece_file: &mut NamedTempFile,
    sealed_sector_file: &NamedTempFile,
) -> Result<(Vec<PieceInfo>, SealPreCommitPhase1Output<Tree>)> {
    let number_of_bytes_in_piece =
        UnpaddedBytesAmount::from(PaddedBytesAmount(config.sector_size.into()));

    let piece_info = generate_piece_commitment(piece_file.as_file_mut(), number_of_bytes_in_piece)?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    let mut staged_sector_file = NamedTempFile::new()?;
    add_piece(
        &mut piece_file,
        &mut staged_sector_file,
        number_of_bytes_in_piece,
        &[],
    )?;

    let piece_infos = vec![piece_info];

    let phase1_output = seal_pre_commit_phase1::<_, _, _, Tree>(
        config,
        cache_dir.path(),
        staged_sector_file.path(),
        sealed_sector_file.path(),
        prover_id,
        sector_id,
        ticket,
        &piece_infos,
    )?;

    validate_cache_for_precommit_phase2(
        cache_dir.path(),
        staged_sector_file.path(),
        &phase1_output,
    )?;

    Ok((piece_infos, phase1_output))
}

#[allow(clippy::too_many_arguments)]
fn generate_proof<Tree: 'static + MerkleTreeTrait>(
    config: PoRepConfig,
    cache_dir_path: &Path,
    sealed_sector_file: &NamedTempFile,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: [u8; 32],
    seed: [u8; 32],
    pre_commit_output: &SealPreCommitOutput,
    piece_infos: &[PieceInfo],
) -> Result<(SealCommitOutput, Vec<Vec<Fr>>, [u8; 32], [u8; 32])> {
    let phase1_output = seal_commit_phase1::<_, Tree>(
        config,
        cache_dir_path,
        sealed_sector_file.path(),
        prover_id,
        sector_id,
        ticket,
        seed,
        pre_commit_output.clone(),
        &piece_infos,
    )?;

    clear_cache::<Tree>(cache_dir_path)?;

    ensure!(
        seed == phase1_output.seed,
        "seed and phase1 output seed do not match"
    );
    ensure!(
        ticket == phase1_output.ticket,
        "seed and phase1 output ticket do not match"
    );

    let comm_r = phase1_output.comm_r;
    let inputs = get_seal_inputs::<Tree>(
        config,
        phase1_output.comm_r,
        phase1_output.comm_d,
        prover_id,
        sector_id,
        phase1_output.ticket,
        phase1_output.seed,
    )?;
    let result = seal_commit_phase2(config, phase1_output, prover_id, sector_id)?;

    Ok((result, inputs, seed, comm_r))
}

#[allow(clippy::too_many_arguments)]
fn unseal<Tree: 'static + MerkleTreeTrait>(
    config: PoRepConfig,
    cache_dir_path: &Path,
    sealed_sector_file: &NamedTempFile,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: [u8; 32],
    seed: [u8; 32],
    pre_commit_output: &SealPreCommitOutput,
    piece_infos: &[PieceInfo],
    piece_bytes: &[u8],
    commit_output: &SealCommitOutput,
) -> Result<()> {
    let comm_d = pre_commit_output.comm_d;
    let comm_r = pre_commit_output.comm_r;

    let mut unseal_file = NamedTempFile::new()?;
    let _ = unseal_range::<_, _, _, Tree>(
        config,
        cache_dir_path,
        sealed_sector_file,
        &unseal_file,
        prover_id,
        sector_id,
        comm_d,
        ticket,
        UnpaddedByteIndex(508),
        UnpaddedBytesAmount(508),
    )?;

    unseal_file.seek(SeekFrom::Start(0))?;

    let mut contents = vec![];
    assert!(
        unseal_file.read_to_end(&mut contents).is_ok(),
        "failed to populate buffer with unsealed bytes"
    );
    assert_eq!(contents.len(), 508);
    assert_eq!(&piece_bytes[508..508 + 508], &contents[..]);

    let computed_comm_d = compute_comm_d(config.sector_size, &piece_infos)?;

    assert_eq!(
        comm_d, computed_comm_d,
        "Computed and expected comm_d don't match."
    );

    let verified = verify_seal::<Tree>(
        config,
        comm_r,
        comm_d,
        prover_id,
        sector_id,
        ticket,
        seed,
        &commit_output.proof,
    )?;
    assert!(verified, "failed to verify valid seal");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn proof_and_unseal<Tree: 'static + MerkleTreeTrait>(
    config: PoRepConfig,
    cache_dir_path: &Path,
    sealed_sector_file: &NamedTempFile,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: [u8; 32],
    seed: [u8; 32],
    pre_commit_output: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
    piece_bytes: &[u8],
) -> Result<()> {
    let (commit_output, _commit_inputs, _seed, _comm_r) = generate_proof::<Tree>(
        config,
        cache_dir_path,
        sealed_sector_file,
        prover_id,
        sector_id,
        ticket,
        seed,
        &pre_commit_output,
        piece_infos,
    )?;

    unseal::<Tree>(
        config,
        cache_dir_path,
        sealed_sector_file,
        prover_id,
        sector_id,
        ticket,
        seed,
        &pre_commit_output,
        piece_infos,
        piece_bytes,
        &commit_output,
    )
}

fn create_seal<R: Rng, Tree: 'static + MerkleTreeTrait>(
    rng: &mut R,
    sector_size: u64,
    prover_id: ProverId,
    skip_proof: bool,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
) -> Result<(SectorId, NamedTempFile, Commitment, TempDir)> {
    init_logger();

    let (mut piece_file, piece_bytes) = generate_piece_file(sector_size)?;
    let sealed_sector_file = NamedTempFile::new()?;
    let cache_dir = tempdir().expect("failed to create temp dir");

    let config = porep_config(sector_size, *porep_id, api_version);
    let ticket = rng.gen();
    let seed = rng.gen();
    let sector_id = rng.gen::<u64>().into();

    let (piece_infos, phase1_output) = run_seal_pre_commit_phase1::<Tree>(
        config,
        prover_id,
        sector_id,
        ticket,
        &cache_dir,
        &mut piece_file,
        &sealed_sector_file,
    )?;

    let pre_commit_output = seal_pre_commit_phase2(
        config,
        phase1_output,
        cache_dir.path(),
        sealed_sector_file.path(),
    )?;

    let comm_r = pre_commit_output.comm_r;

    validate_cache_for_commit::<_, _, Tree>(cache_dir.path(), sealed_sector_file.path())?;

    if skip_proof {
        clear_cache::<Tree>(cache_dir.path())?;
    } else {
        proof_and_unseal::<Tree>(
            config,
            cache_dir.path(),
            &sealed_sector_file,
            prover_id,
            sector_id,
            ticket,
            seed,
            pre_commit_output,
            &piece_infos,
            &piece_bytes,
        )
        .expect("failed to proof_and_unseal");
    }

    Ok((sector_id, sealed_sector_file, comm_r, cache_dir))
}

fn create_seal_for_aggregation<R: Rng, Tree: 'static + MerkleTreeTrait>(
    rng: &mut R,
    sector_size: u64,
    prover_id: ProverId,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
) -> Result<(SealCommitOutput, Vec<Vec<Fr>>, [u8; 32], [u8; 32])> {
    init_logger();

    let (mut piece_file, _piece_bytes) = generate_piece_file(sector_size)?;
    let sealed_sector_file = NamedTempFile::new()?;
    let cache_dir = tempfile::tempdir().expect("failed to create temp dir");

    let config = porep_config(sector_size, *porep_id, api_version);
    let ticket = rng.gen();
    let seed = rng.gen();
    let sector_id = rng.gen::<u64>().into();

    let (piece_infos, phase1_output) = run_seal_pre_commit_phase1::<Tree>(
        config,
        prover_id,
        sector_id,
        ticket,
        &cache_dir,
        &mut piece_file,
        &sealed_sector_file,
    )?;

    let pre_commit_output = seal_pre_commit_phase2(
        config,
        phase1_output,
        cache_dir.path(),
        sealed_sector_file.path(),
    )?;

    validate_cache_for_commit::<_, _, Tree>(cache_dir.path(), sealed_sector_file.path())?;

    generate_proof::<Tree>(
        config,
        cache_dir.path(),
        &sealed_sector_file,
        prover_id,
        sector_id,
        ticket,
        seed,
        &pre_commit_output,
        &piece_infos,
    )
}

fn create_fake_seal<R: rand::Rng, Tree: 'static + MerkleTreeTrait>(
    mut rng: &mut R,
    sector_size: u64,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
) -> Result<(SectorId, NamedTempFile, Commitment, TempDir)> {
    init_logger();

    let sealed_sector_file = NamedTempFile::new()?;

    let config = porep_config(sector_size, *porep_id, api_version);

    let cache_dir = tempdir().unwrap();

    let sector_id = rng.gen::<u64>().into();

    let comm_r = fauxrep_aux::<_, _, _, Tree>(
        &mut rng,
        config,
        cache_dir.path(),
        sealed_sector_file.path(),
    )?;

    Ok((sector_id, sealed_sector_file, comm_r, cache_dir))
}

#[test]
fn test_aggregate_proof_encode_decode() -> Result<()> {
    // This byte vector is a natively serialized aggregate proof.
    let aggregate_proof_bytes = vec![
        162, 98, 94, 37, 246, 182, 211, 253, 189, 59, 213, 171, 94, 57, 44, 12, 253, 240, 61, 15,
        106, 115, 245, 156, 66, 202, 220, 217, 250, 43, 59, 66, 253, 83, 100, 142, 139, 91, 10,
        228, 80, 240, 6, 88, 129, 54, 173, 7, 51, 58, 152, 222, 161, 131, 31, 14, 78, 49, 46, 5,
        89, 129, 238, 25, 89, 116, 234, 69, 31, 76, 64, 142, 11, 221, 3, 190, 159, 10, 106, 108,
        24, 232, 70, 78, 68, 238, 46, 134, 31, 99, 199, 105, 12, 88, 40, 18, 176, 214, 238, 142,
        99, 55, 70, 252, 181, 191, 127, 14, 133, 160, 59, 221, 82, 237, 96, 250, 206, 208, 128,
        179, 139, 113, 1, 81, 60, 174, 117, 158, 18, 155, 206, 227, 248, 102, 13, 47, 77, 11, 87,
        167, 97, 42, 99, 8, 182, 244, 213, 161, 189, 173, 114, 183, 191, 229, 48, 84, 168, 15, 233,
        112, 218, 104, 153, 93, 16, 114, 152, 53, 248, 50, 244, 103, 60, 120, 103, 227, 167, 104,
        171, 147, 89, 193, 235, 18, 166, 78, 11, 190, 91, 238, 202, 0, 234, 232, 0, 245, 169, 141,
        209, 154, 89, 205, 64, 147, 102, 119, 190, 132, 60, 128, 93, 206, 2, 135, 4, 38, 71, 99,
        114, 93, 152, 149, 236, 190, 121, 44, 169, 183, 27, 193, 40, 17, 25, 143, 67, 115, 46, 234,
        200, 25, 215, 243, 226, 99, 123, 172, 93, 192, 31, 239, 69, 233, 50, 184, 10, 57, 51, 92,
        159, 41, 145, 225, 51, 4, 39, 87, 66, 110, 194, 242, 41, 128, 104, 206, 10, 91, 74, 73,
        139, 8, 7, 163, 38, 70, 252, 252, 199, 4, 130, 176, 229, 202, 184, 20, 35, 222, 95, 210,
        238, 183, 195, 73, 65, 198, 90, 68, 234, 113, 184, 101, 95, 104, 103, 233, 254, 98, 168,
        181, 53, 132, 147, 83, 229, 12, 10, 62, 79, 31, 6, 66, 245, 175, 200, 136, 221, 22, 91, 60,
        103, 124, 192, 77, 19, 35, 191, 118, 106, 126, 14, 188, 182, 119, 162, 180, 31, 122, 202,
        176, 47, 203, 1, 185, 190, 76, 235, 65, 133, 152, 184, 101, 239, 152, 138, 152, 20, 183,
        119, 114, 220, 86, 103, 69, 251, 0, 123, 245, 195, 183, 116, 21, 53, 130, 178, 78, 233,
        186, 199, 40, 32, 140, 24, 37, 21, 99, 50, 113, 166, 168, 211, 227, 143, 201, 143, 126, 11,
        15, 100, 162, 64, 227, 87, 8, 104, 62, 254, 181, 127, 132, 154, 178, 58, 10, 130, 132, 21,
        128, 41, 91, 28, 237, 123, 186, 72, 161, 9, 160, 3, 190, 91, 92, 83, 96, 149, 187, 75, 12,
        121, 202, 182, 230, 239, 17, 141, 175, 81, 149, 98, 150, 215, 38, 58, 132, 128, 123, 173,
        252, 153, 86, 140, 22, 229, 70, 91, 202, 146, 9, 27, 173, 227, 24, 190, 133, 191, 209, 108,
        124, 19, 35, 236, 70, 247, 152, 214, 41, 255, 10, 136, 64, 131, 175, 100, 11, 221, 120, 94,
        23, 167, 203, 44, 116, 113, 68, 141, 2, 131, 196, 109, 22, 172, 60, 89, 156, 21, 152, 31,
        192, 12, 184, 252, 235, 173, 240, 178, 102, 93, 191, 39, 15, 106, 75, 137, 253, 192, 135,
        86, 151, 136, 51, 207, 225, 223, 187, 216, 4, 59, 193, 90, 236, 229, 138, 221, 178, 182,
        138, 116, 6, 160, 9, 211, 236, 129, 174, 91, 251, 160, 70, 193, 115, 84, 221, 165, 139, 60,
        224, 177, 105, 15, 85, 251, 8, 245, 106, 123, 177, 168, 189, 250, 245, 27, 2, 95, 138, 61,
        131, 70, 55, 173, 100, 171, 121, 160, 194, 42, 15, 186, 48, 231, 5, 246, 78, 79, 114, 113,
        50, 254, 72, 74, 98, 97, 200, 222, 95, 200, 28, 190, 77, 50, 249, 159, 7, 190, 190, 242,
        112, 219, 195, 0, 205, 221, 239, 93, 200, 144, 241, 118, 219, 2, 144, 99, 250, 49, 1, 8,
        28, 185, 32, 50, 239, 245, 142, 156, 117, 29, 174, 104, 199, 134, 2, 119, 53, 242, 96, 240,
        246, 132, 30, 39, 223, 81, 99, 13, 133, 89, 191, 151, 8, 122, 37, 209, 142, 34, 224, 131,
        21, 234, 190, 119, 30, 205, 4, 4, 203, 169, 54, 176, 211, 205, 15, 72, 148, 122, 53, 31,
        167, 103, 211, 0, 23, 134, 196, 162, 116, 47, 19, 56, 197, 142, 149, 188, 61, 197, 130, 33,
        86, 206, 196, 175, 93, 134, 17, 56, 76, 89, 248, 207, 54, 169, 14, 160, 170, 154, 51, 56,
        71, 77, 45, 79, 33, 92, 5, 5, 187, 246, 210, 220, 125, 207, 188, 101, 246, 106, 46, 132,
        141, 128, 86, 156, 28, 32, 212, 73, 155, 107, 124, 255, 7, 120, 0, 215, 1, 228, 228, 207,
        132, 59, 4, 14, 68, 41, 34, 165, 248, 57, 55, 95, 103, 135, 147, 171, 193, 77, 226, 14,
        124, 154, 235, 230, 25, 168, 253, 245, 227, 222, 166, 80, 154, 89, 72, 50, 17, 114, 170,
        55, 52, 228, 177, 187, 227, 234, 225, 222, 54, 238, 23, 19, 92, 63, 7, 209, 32, 225, 49,
        89, 160, 29, 55, 216, 56, 148, 54, 201, 140, 56, 235, 120, 135, 20, 41, 3, 90, 251, 36,
        107, 24, 86, 109, 246, 151, 150, 168, 80, 239, 86, 168, 119, 119, 223, 58, 29, 94, 189, 25,
        21, 170, 117, 92, 148, 240, 227, 222, 200, 172, 129, 171, 73, 220, 175, 60, 23, 10, 196,
        136, 92, 40, 19, 38, 252, 251, 245, 168, 207, 113, 67, 158, 48, 12, 172, 239, 236, 30, 228,
        111, 228, 232, 45, 125, 217, 41, 87, 21, 44, 181, 83, 32, 181, 90, 52, 144, 48, 213, 124,
        25, 30, 57, 18, 188, 77, 85, 183, 15, 60, 46, 137, 228, 238, 27, 14, 238, 124, 53, 66, 111,
        72, 109, 109, 29, 205, 101, 200, 3, 0, 109, 217, 61, 165, 76, 196, 4, 131, 96, 4, 11, 229,
        2, 26, 85, 230, 168, 74, 200, 232, 35, 55, 255, 229, 92, 34, 51, 215, 181, 84, 168, 74,
        170, 91, 34, 10, 231, 56, 239, 248, 108, 183, 74, 52, 194, 171, 126, 133, 64, 81, 41, 169,
        26, 83, 21, 177, 214, 205, 215, 193, 240, 16, 22, 78, 135, 139, 47, 57, 199, 232, 33, 162,
        23, 163, 210, 61, 65, 130, 114, 150, 100, 165, 38, 78, 173, 222, 104, 166, 181, 111, 88,
        191, 152, 4, 141, 23, 130, 108, 198, 223, 238, 91, 15, 134, 72, 246, 189, 242, 230, 158,
        10, 115, 174, 20, 57, 75, 226, 173, 137, 117, 71, 154, 49, 99, 62, 79, 108, 48, 90, 25, 4,
        221, 134, 109, 190, 81, 147, 59, 13, 60, 190, 176, 228, 12, 127, 153, 76, 90, 188, 13, 1,
        115, 140, 87, 9, 74, 187, 7, 98, 63, 97, 206, 42, 164, 225, 126, 195, 110, 32, 138, 185,
        68, 6, 74, 71, 79, 173, 41, 134, 128, 121, 122, 162, 119, 97, 11, 96, 143, 155, 74, 254,
        102, 76, 189, 127, 112, 170, 94, 9, 240, 122, 57, 207, 172, 166, 134, 137, 233, 67, 45, 83,
        20, 161, 168, 82, 63, 232, 119, 34, 92, 108, 126, 140, 201, 22, 244, 29, 200, 138, 44, 174,
        7, 198, 188, 136, 9, 35, 225, 48, 167, 213, 191, 157, 168, 147, 206, 0, 78, 53, 125, 62,
        24, 122, 181, 128, 81, 145, 1, 196, 19, 251, 133, 25, 51, 222, 203, 39, 83, 208, 38, 74,
        116, 57, 6, 142, 118, 41, 102, 243, 182, 137, 105, 142, 59, 203, 127, 129, 220, 16, 161,
        121, 190, 78, 0, 8, 100, 201, 146, 228, 77, 187, 41, 189, 1, 100, 200, 117, 10, 189, 242,
        97, 94, 121, 58, 29, 9, 117, 164, 245, 224, 152, 217, 153, 89, 151, 233, 135, 214, 140, 8,
        142, 119, 66, 230, 170, 145, 81, 152, 228, 89, 99, 85, 1, 26, 121, 151, 149, 228, 76, 91,
        39, 124, 245, 65, 235, 191, 53, 108, 7, 239, 217, 125, 128, 112, 117, 170, 199, 10, 247,
        110, 90, 56, 104, 180, 176, 63, 129, 224, 206, 140, 182, 156, 230, 228, 38, 28, 7, 131,
        185, 109, 17, 77, 158, 104, 182, 106, 103, 129, 75, 27, 14, 146, 152, 158, 147, 32, 67, 79,
        203, 97, 241, 144, 162, 149, 119, 207, 203, 252, 193, 78, 23, 56, 36, 116, 146, 175, 226,
        214, 151, 74, 83, 50, 228, 114, 174, 20, 189, 251, 17, 133, 3, 75, 115, 136, 63, 154, 198,
        113, 195, 86, 69, 90, 16, 222, 86, 105, 35, 173, 128, 202, 165, 155, 87, 3, 132, 137, 67,
        183, 102, 122, 180, 55, 236, 71, 15, 34, 134, 104, 103, 237, 155, 50, 241, 76, 15, 239, 17,
        0, 2, 0, 0, 87, 63, 103, 23, 10, 209, 154, 178, 213, 127, 5, 144, 2, 242, 221, 34, 217, 11,
        194, 4, 65, 54, 25, 95, 141, 173, 87, 141, 173, 96, 160, 31, 131, 67, 123, 173, 60, 184,
        181, 139, 123, 54, 229, 86, 228, 1, 13, 5, 19, 58, 165, 127, 172, 66, 65, 5, 156, 219, 216,
        177, 143, 232, 177, 155, 126, 213, 244, 228, 148, 176, 238, 142, 35, 213, 160, 51, 131, 24,
        127, 171, 182, 26, 26, 241, 132, 151, 128, 36, 6, 90, 112, 92, 64, 5, 90, 24, 177, 217, 4,
        185, 56, 77, 64, 144, 81, 182, 134, 144, 219, 221, 155, 0, 71, 117, 42, 33, 121, 50, 116,
        253, 159, 172, 253, 23, 29, 218, 215, 17, 135, 179, 158, 173, 186, 212, 235, 148, 19, 47,
        202, 201, 228, 128, 108, 14, 8, 143, 22, 147, 241, 244, 31, 87, 172, 216, 240, 146, 16,
        215, 104, 5, 49, 160, 156, 195, 60, 58, 74, 103, 138, 189, 122, 205, 231, 143, 216, 32, 88,
        45, 20, 234, 118, 180, 70, 91, 136, 239, 155, 59, 21, 58, 253, 13, 83, 59, 253, 186, 40,
        148, 88, 230, 159, 54, 178, 135, 137, 60, 145, 160, 21, 223, 55, 99, 17, 11, 78, 31, 169,
        112, 15, 107, 82, 112, 98, 113, 108, 164, 166, 16, 27, 199, 107, 9, 191, 19, 126, 119, 18,
        159, 79, 13, 16, 157, 217, 233, 113, 130, 28, 213, 105, 218, 55, 236, 181, 35, 94, 85, 214,
        101, 24, 22, 8, 21, 88, 36, 9, 115, 122, 16, 28, 155, 89, 8, 131, 49, 136, 65, 142, 39, 75,
        198, 10, 58, 196, 230, 228, 194, 187, 20, 17, 162, 253, 163, 253, 24, 224, 197, 202, 189,
        124, 23, 240, 50, 112, 166, 188, 230, 22, 174, 6, 154, 53, 211, 79, 118, 116, 250, 223,
        189, 247, 98, 178, 169, 127, 200, 187, 229, 82, 84, 251, 201, 87, 71, 199, 130, 223, 7,
        134, 62, 236, 229, 210, 145, 246, 186, 219, 64, 191, 112, 35, 84, 140, 58, 7, 87, 239, 212,
        162, 94, 213, 13, 211, 42, 230, 167, 178, 238, 9, 37, 215, 215, 10, 144, 86, 74, 66, 111,
        169, 49, 242, 74, 16, 103, 235, 15, 126, 163, 215, 60, 138, 188, 14, 152, 228, 97, 142,
        234, 241, 92, 100, 97, 153, 255, 248, 175, 72, 70, 79, 34, 24, 86, 41, 23, 142, 34, 60,
        235, 110, 61, 89, 153, 252, 176, 58, 192, 45, 139, 167, 189, 100, 168, 143, 14, 76, 149,
        221, 62, 13, 132, 53, 200, 223, 138, 1, 46, 28, 239, 120, 2, 223, 191, 81, 53, 18, 20, 96,
        191, 89, 201, 218, 127, 125, 236, 132, 5, 60, 38, 54, 148, 75, 247, 168, 187, 75, 138, 79,
        58, 147, 109, 180, 3, 172, 175, 185, 76, 166, 66, 212, 206, 34, 192, 33, 200, 234, 29, 236,
        173, 138, 13, 255, 231, 156, 105, 2, 237, 156, 222, 156, 94, 38, 79, 155, 235, 236, 134,
        165, 88, 23, 158, 115, 95, 5, 185, 200, 194, 68, 220, 211, 16, 40, 143, 223, 1, 174, 137,
        145, 81, 69, 181, 95, 254, 193, 113, 202, 113, 110, 8, 56, 248, 207, 26, 127, 116, 143,
        176, 121, 201, 153, 218, 0, 87, 194, 129, 248, 48, 80, 91, 136, 186, 147, 252, 155, 119,
        48, 147, 140, 8, 87, 182, 90, 140, 59, 0, 180, 172, 138, 156, 199, 41, 207, 0, 154, 240,
        41, 67, 55, 67, 126, 46, 228, 175, 64, 57, 19, 50, 75, 192, 164, 29, 207, 184, 209, 218,
        226, 112, 9, 125, 46, 78, 86, 178, 237, 86, 96, 15, 200, 50, 169, 39, 10, 223, 43, 158,
        163, 27, 21, 42, 237, 1, 254, 155, 231, 102, 231, 253, 216, 113, 45, 47, 18, 34, 52, 39,
        113, 123, 255, 119, 121, 221, 167, 204, 41, 31, 186, 94, 73, 132, 91, 155, 243, 79, 189,
        22, 253, 64, 0, 113, 164, 8, 241, 206, 54, 36, 246, 142, 132, 132, 152, 246, 44, 36, 16,
        249, 12, 71, 198, 204, 253, 52, 218, 2, 89, 215, 90, 33, 137, 24, 59, 195, 199, 97, 125,
        168, 7, 131, 229, 81, 166, 83, 131, 14, 129, 38, 104, 96, 214, 57, 76, 79, 85, 182, 92,
        244, 46, 95, 44, 212, 192, 67, 200, 185, 214, 168, 165, 52, 177, 203, 218, 215, 22, 2, 34,
        61, 178, 233, 147, 108, 155, 151, 12, 151, 167, 193, 25, 10, 126, 83, 220, 15, 60, 186, 9,
        57, 15, 202, 249, 165, 78, 74, 250, 231, 192, 2, 43, 83, 243, 226, 116, 2, 157, 128, 174,
        196, 237, 190, 50, 186, 24, 154, 181, 46, 18, 73, 65, 230, 54, 10, 72, 182, 42, 107, 6,
        183, 74, 210, 219, 4, 79, 213, 217, 251, 72, 215, 45, 199, 244, 218, 235, 125, 161, 122,
        246, 94, 127, 235, 212, 199, 72, 75, 24, 183, 142, 55, 236, 252, 174, 189, 67, 95, 225,
        116, 143, 184, 240, 156, 86, 186, 12, 148, 224, 65, 204, 190, 114, 25, 57, 38, 208, 141,
        67, 154, 126, 99, 60, 204, 96, 34, 146, 90, 139, 127, 189, 232, 197, 65, 73, 232, 163, 55,
        122, 217, 232, 69, 1, 69, 44, 28, 150, 247, 229, 200, 53, 128, 60, 146, 235, 123, 49, 205,
        200, 160, 185, 6, 179, 8, 148, 152, 0, 113, 232, 107, 143, 236, 154, 67, 28, 209, 66, 240,
        181, 84, 146, 197, 187, 203, 150, 181, 129, 198, 18, 83, 204, 76, 197, 187, 75, 0, 93, 192,
        250, 73, 120, 127, 236, 59, 104, 152, 255, 188, 23, 24, 54, 97, 107, 56, 93, 188, 86, 147,
        150, 47, 75, 13, 169, 40, 51, 156, 183, 67, 240, 67, 29, 94, 218, 55, 164, 141, 185, 203,
        74, 39, 106, 95, 17, 54, 33, 66, 238, 190, 23, 120, 202, 159, 198, 249, 242, 112, 34, 6,
        134, 167, 246, 93, 95, 138, 133, 151, 47, 25, 93, 164, 149, 93, 148, 139, 191, 233, 7, 153,
        201, 16, 136, 107, 248, 61, 159, 88, 200, 137, 147, 99, 202, 219, 237, 180, 18, 50, 71, 97,
        178, 140, 43, 179, 248, 3, 14, 16, 103, 159, 71, 188, 23, 124, 142, 101, 242, 165, 141,
        255, 95, 42, 153, 88, 231, 54, 210, 198, 159, 197, 235, 60, 127, 221, 36, 36, 195, 18, 167,
        246, 24, 195, 244, 167, 55, 94, 32, 179, 129, 12, 186, 134, 207, 35, 44, 11, 182, 19, 182,
        80, 101, 23, 149, 93, 174, 178, 23, 53, 108, 132, 194, 10, 208, 232, 41, 161, 117, 10, 228,
        95, 33, 161, 10, 202, 249, 39, 131, 125, 7, 61, 124, 24, 176, 122, 146, 32, 246, 223, 142,
        100, 150, 254, 123, 22, 109, 153, 222, 73, 194, 168, 209, 249, 183, 98, 126, 102, 220, 174,
        204, 224, 94, 72, 194, 154, 141, 53, 110, 229, 41, 159, 148, 188, 112, 170, 122, 186, 113,
        186, 166, 39, 159, 248, 218, 60, 152, 195, 100, 32, 95, 5, 119, 11, 140, 34, 243, 50, 64,
        125, 95, 95, 53, 173, 106, 156, 95, 250, 63, 136, 234, 95, 216, 107, 160, 219, 142, 155,
        144, 102, 209, 255, 140, 127, 46, 112, 43, 126, 194, 34, 96, 178, 146, 124, 171, 194, 157,
        50, 103, 182, 243, 3, 18, 219, 83, 8, 147, 87, 137, 188, 198, 223, 72, 44, 227, 170, 113,
        47, 19, 77, 153, 112, 184, 126, 131, 107, 9, 164, 208, 221, 179, 178, 94, 215, 235, 74, 7,
        235, 225, 219, 29, 189, 37, 180, 189, 22, 217, 25, 121, 0, 32, 217, 70, 35, 199, 155, 204,
        234, 157, 66, 186, 29, 225, 215, 216, 191, 15, 9, 254, 101, 107, 35, 5, 212, 58, 94, 117,
        214, 150, 166, 131, 66, 127, 232, 117, 206, 8, 74, 207, 254, 44, 57, 177, 188, 145, 29,
        171, 16, 165, 25, 156, 116, 173, 190, 42, 211, 124, 225, 205, 41, 154, 223, 25, 77, 92, 47,
        32, 244, 84, 76, 158, 170, 188, 216, 113, 200, 44, 179, 178, 173, 145, 205, 85, 206, 65,
        109, 27, 103, 46, 177, 132, 23, 24, 112, 43, 25, 80, 215, 36, 133, 132, 57, 14, 96, 192,
        252, 80, 11, 90, 219, 194, 112, 194, 187, 26, 102, 221, 191, 234, 172, 215, 142, 199, 6,
        154, 122, 111, 116, 16, 80, 49, 228, 227, 189, 246, 182, 85, 238, 17, 108, 219, 188, 213,
        16, 88, 186, 35, 125, 81, 51, 40, 171, 41, 29, 100, 217, 4, 179, 154, 209, 11, 115, 188,
        90, 65, 36, 238, 242, 255, 26, 166, 6, 22, 190, 218, 22, 157, 203, 143, 176, 172, 117, 85,
        129, 56, 137, 194, 120, 57, 142, 40, 4, 135, 132, 110, 226, 186, 254, 31, 139, 159, 217,
        70, 1, 219, 87, 109, 37, 2, 249, 78, 141, 144, 139, 64, 153, 79, 55, 204, 42, 237, 166, 86,
        37, 152, 200, 206, 180, 231, 115, 127, 52, 76, 27, 123, 49, 220, 4, 161, 14, 184, 105, 46,
        139, 79, 54, 159, 91, 152, 236, 146, 202, 118, 84, 110, 33, 31, 7, 131, 239, 143, 104, 126,
        211, 190, 94, 57, 47, 197, 89, 241, 135, 14, 157, 23, 5, 64, 141, 238, 3, 146, 124, 82,
        107, 87, 101, 222, 11, 5, 2, 52, 183, 208, 45, 34, 43, 145, 71, 152, 36, 250, 60, 166, 113,
        233, 157, 25, 192, 240, 106, 29, 239, 131, 149, 59, 38, 37, 43, 42, 35, 94, 92, 45, 112,
        170, 178, 184, 224, 190, 21, 83, 154, 72, 203, 131, 14, 144, 190, 13, 13, 111, 136, 161,
        84, 68, 52, 104, 86, 89, 99, 232, 249, 138, 209, 244, 99, 205, 68, 28, 199, 57, 139, 162,
        27, 151, 124, 81, 14, 77, 29, 159, 152, 141, 238, 35, 167, 111, 44, 253, 129, 223, 25, 185,
        25, 87, 130, 135, 154, 133, 243, 247, 17, 162, 125, 3, 125, 55, 245, 65, 30, 186, 1, 74,
        152, 18, 223, 152, 74, 3, 115, 159, 188, 48, 67, 11, 44, 82, 111, 126, 75, 167, 116, 162,
        193, 206, 159, 87, 50, 98, 13, 152, 24, 56, 237, 126, 179, 120, 70, 225, 159, 183, 57, 163,
        2, 220, 179, 151, 147, 11, 19, 38, 249, 220, 114, 136, 208, 55, 91, 212, 153, 225, 229, 42,
        224, 43, 79, 129, 204, 190, 175, 248, 180, 186, 145, 225, 33, 183, 150, 135, 0, 240, 112,
        92, 214, 118, 184, 63, 51, 67, 207, 202, 167, 251, 140, 72, 207, 130, 201, 184, 19, 157,
        11, 124, 123, 164, 218, 131, 7, 170, 35, 239, 70, 132, 189, 36, 231, 175, 4, 102, 42, 175,
        163, 75, 187, 195, 74, 21, 12, 134, 22, 134, 127, 114, 163, 218, 82, 21, 25, 238, 42, 17,
        11, 248, 194, 168, 96, 6, 44, 170, 188, 124, 230, 166, 66, 4, 226, 167, 60, 61, 15, 0, 34,
        100, 62, 34, 93, 113, 87, 88, 159, 202, 127, 96, 177, 252, 7, 96, 229, 44, 178, 116, 52,
        170, 158, 208, 21, 155, 202, 61, 205, 18, 63, 87, 6, 15, 112, 40, 45, 95, 142, 210, 3, 127,
        164, 23, 195, 240, 168, 44, 114, 56, 27, 24, 136, 156, 28, 85, 204, 171, 250, 28, 54, 196,
        12, 93, 22, 186, 248, 163, 244, 112, 90, 65, 190, 3, 11, 192, 29, 141, 142, 234, 70, 93,
        143, 33, 21, 72, 243, 92, 189, 137, 141, 183, 120, 62, 62, 16, 210, 247, 188, 68, 248, 184,
        49, 52, 99, 59, 157, 160, 70, 218, 1, 95, 69, 48, 170, 143, 124, 44, 92, 255, 114, 5, 60,
        45, 249, 232, 112, 12, 211, 177, 228, 226, 56, 55, 244, 191, 31, 90, 132, 209, 92, 176, 67,
        208, 128, 8, 233, 74, 83, 104, 103, 26, 251, 158, 9, 22, 158, 82, 0, 214, 134, 183, 255,
        117, 152, 49, 222, 175, 206, 0, 197, 237, 78, 196, 142, 196, 235, 63, 18, 42, 69, 54, 56,
        202, 16, 56, 21, 106, 232, 70, 38, 8, 167, 47, 188, 168, 174, 245, 133, 165, 60, 219, 13,
        78, 12, 11, 15, 156, 7, 43, 6, 178, 57, 127, 178, 165, 80, 4, 245, 140, 102, 135, 152, 46,
        89, 70, 25, 38, 27, 240, 237, 132, 103, 145, 39, 57, 223, 252, 214, 249, 142, 180, 244,
        141, 251, 28, 42, 16, 248, 57, 238, 193, 48, 185, 23, 192, 182, 30, 23, 13, 55, 206, 251,
        38, 197, 192, 36, 60, 191, 172, 195, 19, 225, 129, 160, 244, 220, 213, 196, 232, 163, 56,
        135, 252, 94, 7, 107, 219, 155, 215, 204, 245, 235, 20, 72, 15, 157, 17, 205, 112, 195,
        199, 11, 218, 230, 232, 179, 246, 86, 0, 94, 84, 92, 56, 164, 236, 80, 149, 113, 216, 250,
        27, 103, 180, 94, 96, 8, 48, 7, 53, 7, 226, 68, 86, 32, 63, 232, 75, 95, 109, 111, 16, 170,
        210, 187, 61, 94, 81, 2, 164, 21, 92, 174, 80, 222, 198, 231, 160, 18, 229, 106, 244, 40,
        94, 8, 177, 229, 90, 162, 195, 92, 69, 63, 137, 108, 170, 9, 169, 22, 116, 124, 50, 34,
        255, 157, 220, 32, 169, 224, 106, 158, 237, 103, 203, 203, 94, 16, 186, 8, 84, 12, 173,
        109, 189, 18, 93, 117, 234, 27, 214, 3, 239, 58, 218, 169, 206, 154, 17, 222, 208, 64, 160,
        52, 246, 227, 108, 218, 165, 37, 75, 215, 238, 205, 68, 29, 45, 215, 250, 214, 5, 111, 209,
        142, 7, 190, 35, 19, 114, 81, 16, 238, 237, 252, 94, 156, 205, 181, 249, 164, 31, 51, 251,
        252, 176, 84, 122, 135, 215, 99, 253, 60, 21, 134, 73, 127, 107, 224, 148, 174, 101, 152,
        220, 241, 146, 24, 78, 252, 129, 148, 102, 43, 215, 163, 165, 14, 61, 24, 176, 145, 183,
        109, 40, 242, 187, 218, 38, 130, 121, 91, 40, 20, 216, 35, 139, 23, 83, 69, 207, 91, 199,
        19, 134, 98, 42, 19, 173, 144, 143, 93, 213, 123, 247, 140, 170, 250, 134, 195, 71, 229,
        179, 5, 27, 5, 78, 78, 63, 250, 92, 171, 101, 24, 199, 39, 117, 190, 7, 157, 16, 222, 28,
        122, 63, 168, 97, 93, 100, 183, 140, 178, 64, 92, 47, 73, 46, 6, 143, 39, 4, 16, 57, 200,
        80, 38, 186, 61, 96, 145, 168, 24, 47, 19, 164, 129, 203, 58, 17, 188, 137, 218, 115, 124,
        253, 164, 176, 247, 141, 194, 60, 3, 107, 130, 15, 137, 31, 247, 232, 189, 8, 147, 149,
        118, 153, 247, 175, 128, 4, 136, 52, 27, 71, 186, 140, 158, 243, 146, 46, 138, 36, 17, 209,
        59, 171, 189, 112, 199, 27, 125, 248, 12, 165, 86, 254, 149, 174, 163, 25, 222, 236, 254,
        51, 220, 111, 138, 154, 238, 234, 47, 88, 21, 94, 124, 118, 130, 234, 252, 199, 75, 203,
        149, 54, 115, 64, 231, 78, 141, 146, 6, 175, 80, 121, 189, 31, 54, 165, 113, 95, 44, 122,
        233, 2, 23, 212, 29, 84, 67, 98, 146, 10, 91, 25, 48, 58, 167, 242, 107, 47, 246, 195, 130,
        139, 221, 190, 153, 74, 250, 131, 44, 150, 122, 27, 41, 54, 84, 145, 19, 32, 81, 209, 99,
        169, 81, 74, 134, 34, 140, 120, 173, 109, 48, 157, 49, 90, 255, 243, 240, 40, 161, 49, 251,
        166, 196, 166, 146, 20, 89, 202, 2, 210, 198, 67, 237, 83, 57, 254, 10, 123, 195, 164, 129,
        128, 33, 203, 19, 202, 49, 17, 171, 197, 226, 189, 247, 236, 252, 88, 187, 61, 56, 104, 18,
        191, 239, 172, 75, 48, 16, 219, 114, 151, 35, 165, 247, 142, 217, 248, 162, 174, 218, 244,
        215, 230, 61, 142, 211, 124, 165, 148, 177, 126, 70, 114, 20, 202, 97, 17, 217, 188, 206,
        237, 80, 178, 99, 228, 33, 1, 12, 146, 89, 81, 185, 234, 112, 53, 170, 73, 243, 56, 235,
        165, 212, 126, 188, 200, 197, 63, 195, 58, 66, 251, 196, 201, 245, 127, 28, 231, 209, 225,
        186, 115, 4, 178, 37, 136, 11, 180, 64, 58, 43, 233, 199, 199, 6, 122, 88, 53, 110, 56, 32,
        231, 43, 214, 33, 54, 110, 185, 230, 143, 67, 186, 201, 133, 151, 168, 85, 244, 49, 92,
        163, 160, 160, 58, 128, 41, 202, 55, 40, 146, 8, 164, 128, 196, 174, 156, 9, 170, 188, 156,
        186, 177, 160, 189, 174, 22, 222, 192, 217, 52, 30, 22, 134, 10, 211, 123, 198, 107, 11,
        168, 185, 244, 171, 49, 249, 101, 141, 207, 120, 128, 222, 62, 70, 119, 71, 224, 116, 17,
        18, 227, 106, 51, 56, 164, 215, 71, 126, 110, 56, 29, 252, 177, 113, 202, 207, 243, 201,
        165, 131, 178, 188, 79, 87, 129, 76, 62, 86, 111, 194, 241, 167, 87, 82, 67, 178, 137, 101,
        183, 193, 3, 102, 46, 200, 52, 19, 51, 0, 163, 198, 138, 122, 57, 53, 157, 92, 136, 32, 13,
        157, 245, 19, 156, 198, 41, 219, 116, 26, 144, 106, 65, 232, 55, 212, 213, 177, 152, 32,
        185, 165, 45, 61, 26, 165, 14, 152, 143, 249, 88, 113, 89, 119, 234, 135, 212, 0, 66, 44,
        40, 212, 59, 57, 87, 44, 224, 247, 136, 41, 60, 74, 252, 147, 170, 45, 36, 97, 208, 182,
        40, 153, 85, 208, 236, 94, 103, 63, 129, 40, 73, 218, 207, 152, 30, 117, 13, 240, 41, 84,
        243, 97, 58, 12, 197, 10, 217, 218, 228, 183, 48, 90, 84, 38, 173, 111, 24, 62, 12, 121,
        171, 55, 75, 210, 11, 35, 248, 4, 88, 175, 35, 96, 11, 137, 56, 166, 224, 55, 173, 206, 50,
        17, 185, 145, 13, 235, 61, 41, 84, 94, 33, 154, 103, 19, 95, 138, 218, 16, 30, 119, 187,
        24, 58, 204, 48, 96, 216, 50, 129, 67, 51, 40, 114, 219, 231, 95, 174, 73, 197, 44, 246,
        113, 111, 98, 252, 152, 85, 62, 169, 187, 36, 32, 67, 124, 190, 244, 97, 194, 60, 122, 33,
        14, 128, 249, 33, 217, 14, 103, 199, 109, 145, 70, 190, 86, 183, 230, 15, 88, 111, 6, 90,
        55, 51, 62, 218, 68, 251, 171, 115, 13, 190, 213, 183, 180, 193, 31, 218, 139, 90, 45, 139,
        26, 191, 170, 213, 230, 1, 161, 181, 21, 236, 36, 197, 58, 250, 198, 65, 65, 77, 150, 52,
        138, 71, 47, 113, 196, 88, 92, 22, 190, 70, 90, 156, 12, 3, 116, 137, 83, 201, 145, 170,
        112, 42, 84, 239, 110, 238, 209, 203, 214, 235, 43, 134, 79, 219, 60, 225, 13, 89, 224,
        106, 141, 131, 147, 156, 252, 107, 245, 96, 249, 43, 132, 166, 95, 168, 36, 83, 116, 48,
        153, 26, 231, 117, 118, 100, 142, 86, 85, 113, 209, 110, 27, 203, 21, 68, 225, 188, 60, 92,
        22, 19, 97, 111, 200, 23, 16, 158, 127, 64, 145, 27, 54, 186, 212, 66, 7, 153, 5, 31, 72,
        80, 153, 24, 201, 11, 167, 80, 193, 58, 2, 75, 218, 156, 6, 245, 49, 0, 162, 161, 4, 104,
        181, 55, 145, 215, 60, 39, 110, 213, 242, 210, 61, 233, 3, 108, 75, 81, 199, 243, 77, 115,
        73, 244, 212, 88, 55, 13, 220, 126, 63, 219, 38, 127, 192, 164, 103, 213, 236, 42, 255,
        162, 241, 65, 147, 120, 93, 49, 44, 40, 253, 141, 78, 202, 191, 148, 168, 168, 197, 255,
        119, 66, 3, 173, 222, 124, 48, 137, 224, 203, 134, 210, 215, 254, 103, 135, 164, 155, 223,
        25, 117, 207, 34, 33, 138, 125, 25, 121, 170, 219, 140, 178, 235, 8, 212, 134, 111, 13, 48,
        127, 151, 118, 218, 154, 108, 140, 244, 215, 93, 206, 23, 149, 104, 122, 61, 230, 233, 124,
        107, 243, 145, 152, 33, 78, 211, 59, 237, 4, 217, 248, 3, 66, 215, 172, 81, 1, 117, 184,
        202, 129, 50, 59, 69, 146, 232, 136, 197, 211, 43, 142, 244, 181, 107, 202, 193, 65, 6,
        114, 11, 207, 125, 227, 22, 63, 4, 53, 166, 142, 212, 72, 165, 207, 2, 134, 113, 44, 41,
        186, 22, 18, 146, 137, 76, 74, 179, 70, 201, 15, 178, 155, 149, 218, 109, 229, 4, 242, 93,
        93, 176, 9, 217, 22, 235, 66, 30, 24, 20, 199, 43, 102, 199, 43, 129, 208, 171, 122, 248,
        229, 117, 189, 84, 62, 137, 193, 237, 138, 107, 146, 158, 228, 235, 134, 128, 193, 53, 79,
        145, 163, 32, 246, 205, 204, 18, 116, 163, 47, 8, 108, 224, 130, 56, 96, 47, 225, 25, 228,
        179, 96, 156, 130, 102, 240, 79, 39, 89, 32, 230, 26, 209, 109, 72, 150, 195, 104, 62, 152,
        156, 111, 206, 72, 198, 201, 142, 201, 251, 176, 219, 117, 171, 111, 246, 6, 109, 223, 64,
        11, 215, 222, 61, 58, 25, 1, 17, 181, 40, 57, 66, 190, 219, 247, 165, 30, 50, 123, 107,
        188, 16, 68, 175, 174, 214, 49, 95, 134, 216, 55, 85, 117, 72, 4, 128, 35, 106, 19, 29, 24,
        144, 73, 66, 240, 138, 186, 208, 253, 117, 73, 132, 64, 218, 144, 12, 59, 231, 173, 218,
        11, 150, 169, 96, 148, 117, 36, 1, 107, 218, 211, 13, 148, 186, 169, 95, 174, 33, 172, 67,
        243, 255, 6, 186, 48, 227, 14, 118, 233, 24, 99, 174, 161, 86, 122, 234, 165, 0, 204, 194,
        68, 246, 110, 12, 242, 207, 9, 215, 19, 156, 210, 28, 114, 238, 133, 229, 207, 5, 238, 244,
        151, 103, 101, 166, 67, 227, 108, 126, 74, 230, 44, 202, 187, 94, 198, 56, 58, 76, 216, 59,
        160, 116, 111, 171, 71, 121, 1, 207, 161, 103, 33, 8, 215, 137, 18, 194, 153, 227, 73, 238,
        62, 217, 59, 91, 24, 59, 232, 146, 152, 83, 18, 66, 221, 155, 37, 94, 23, 190, 215, 174,
        100, 93, 218, 165, 72, 166, 203, 73, 180, 59, 121, 206, 145, 226, 227, 84, 0, 107, 62, 2,
        131, 45, 135, 195, 51, 50, 36, 251, 55, 127, 53, 214, 129, 79, 196, 101, 248, 112, 99, 174,
        249, 31, 128, 35, 18, 189, 253, 87, 34, 60, 159, 196, 165, 233, 69, 196, 213, 190, 126,
        133, 63, 200, 237, 207, 85, 193, 209, 9, 150, 244, 138, 249, 128, 90, 98, 2, 129, 250, 226,
        119, 246, 31, 179, 76, 3, 119, 114, 206, 185, 112, 42, 212, 48, 58, 163, 129, 160, 167,
        252, 131, 1, 243, 55, 11, 206, 53, 233, 156, 161, 77, 188, 99, 93, 142, 210, 22, 55, 14,
        173, 195, 44, 10, 177, 93, 168, 240, 115, 227, 126, 78, 230, 48, 141, 123, 222, 168, 183,
        155, 210, 129, 57, 197, 14, 36, 77, 184, 16, 116, 219, 0, 166, 66, 180, 244, 15, 39, 36,
        87, 129, 55, 56, 124, 41, 3, 190, 202, 180, 42, 64, 95, 178, 210, 28, 5, 79, 105, 55, 76,
        165, 254, 194, 153, 240, 242, 188, 198, 84, 94, 246, 22, 78, 139, 211, 129, 217, 185, 235,
        143, 31, 35, 31, 100, 108, 42, 62, 113, 246, 29, 134, 215, 23, 17, 41, 221, 27, 42, 24, 61,
        231, 5, 240, 188, 154, 106, 65, 153, 215, 65, 38, 244, 46, 154, 59, 38, 20, 76, 155, 199,
        215, 204, 216, 254, 202, 140, 197, 143, 173, 93, 219, 130, 88, 211, 146, 220, 42, 123, 156,
        123, 138, 25, 233, 220, 191, 211, 83, 9, 168, 71, 103, 102, 222, 15, 233, 217, 157, 240,
        232, 42, 188, 107, 188, 191, 43, 56, 17, 173, 62, 145, 193, 168, 179, 223, 21, 209, 19,
        103, 253, 87, 197, 194, 99, 121, 84, 66, 228, 205, 116, 16, 154, 153, 230, 199, 238, 108,
        241, 169, 214, 5, 77, 68, 181, 203, 5, 119, 112, 76, 31, 182, 191, 247, 188, 198, 252, 106,
        177, 229, 25, 204, 157, 66, 169, 15, 127, 96, 120, 73, 53, 147, 30, 99, 238, 222, 43, 191,
        250, 22, 12, 146, 126, 227, 215, 46, 41, 192, 3, 4, 115, 14, 222, 12, 120, 142, 100, 39,
        63, 69, 127, 111, 71, 151, 211, 30, 204, 14, 61, 10, 27, 227, 221, 196, 19, 65, 122, 232,
        68, 160, 9, 48, 154, 227, 119, 216, 91, 11, 162, 230, 13, 178, 140, 10, 181, 201, 242, 249,
        77, 173, 121, 226, 138, 121, 212, 139, 34, 212, 247, 118, 71, 241, 220, 173, 7, 22, 66,
        184, 38, 80, 47, 98, 113, 45, 149, 169, 164, 86, 230, 246, 102, 67, 185, 222, 52, 8, 14,
        209, 207, 96, 72, 160, 135, 128, 0, 136, 181, 199, 58, 154, 235, 36, 252, 227, 225, 41,
        193, 203, 131, 29, 231, 212, 79, 169, 5, 225, 174, 115, 127, 96, 107, 153, 215, 119, 26,
        106, 204, 203, 245, 53, 241, 38, 131, 10, 130, 222, 74, 243, 170, 136, 107, 254, 242, 142,
        34, 11, 93, 69, 201, 116, 216, 117, 215, 48, 188, 41, 15, 84, 128, 142, 250, 34, 55, 2, 39,
        75, 253, 92, 195, 215, 118, 239, 67, 57, 203, 244, 141, 203, 40, 254, 22, 23, 190, 204,
        208, 78, 45, 60, 205, 46, 96, 177, 229, 57, 198, 18, 239, 169, 7, 123, 215, 35, 198, 62, 6,
        116, 45, 71, 241, 165, 181, 188, 71, 220, 225, 44, 195, 106, 194, 250, 182, 179, 233, 56,
        210, 42, 79, 71, 111, 20, 52, 22, 162, 92, 1, 127, 54, 28, 211, 60, 211, 148, 189, 192,
        227, 125, 130, 155, 123, 23, 10, 242, 53, 237, 159, 211, 50, 80, 9, 121, 45, 158, 99, 95,
        122, 240, 40, 236, 71, 205, 42, 90, 102, 170, 39, 247, 130, 24, 52, 79, 97, 80, 128, 39,
        85, 196, 206, 52, 125, 39, 252, 180, 226, 22, 3, 134, 40, 255, 26, 224, 110, 199, 155, 94,
        61, 40, 21, 45, 35, 243, 145, 223, 7, 167, 246, 199, 35, 21, 204, 98, 153, 114, 119, 20,
        232, 19, 185, 204, 83, 84, 101, 81, 171, 113, 224, 210, 151, 118, 51, 4, 228, 3, 94, 73,
        240, 196, 122, 126, 252, 111, 155, 162, 28, 75, 35, 15, 6, 168, 117, 158, 182, 96, 66, 75,
        184, 26, 117, 222, 9, 180, 22, 144, 206, 2, 59, 84, 225, 96, 93, 242, 252, 32, 155, 72,
        255, 121, 217, 159, 203, 125, 225, 18, 21, 196, 158, 210, 78, 224, 186, 125, 188, 214, 10,
        73, 79, 4, 213, 171, 245, 3, 119, 8, 69, 28, 72, 14, 37, 36, 133, 83, 144, 10, 14, 225, 56,
        71, 94, 167, 250, 133, 97, 161, 142, 199, 137, 15, 9, 227, 108, 74, 55, 110, 3, 207, 113,
        2, 61, 31, 37, 199, 107, 112, 52, 4, 233, 75, 193, 69, 242, 228, 158, 94, 49, 134, 206,
        140, 37, 219, 153, 1, 10, 66, 129, 48, 238, 69, 139, 248, 65, 125, 87, 41, 38, 106, 158,
        17, 101, 140, 118, 88, 21, 204, 245, 88, 14, 233, 31, 126, 129, 86, 34, 233, 120, 165, 253,
        117, 162, 44, 173, 107, 171, 113, 165, 131, 144, 121, 193, 13, 171, 145, 168, 123, 206,
        233, 78, 177, 138, 123, 229, 228, 10, 26, 30, 85, 40, 69, 90, 200, 69, 63, 159, 214, 177,
        232, 238, 252, 20, 104, 51, 15, 47, 44, 154, 182, 145, 6, 33, 12, 169, 14, 8, 215, 247,
        188, 210, 15, 93, 176, 89, 43, 24, 188, 86, 5, 118, 212, 4, 217, 151, 192, 73, 134, 110,
        241, 47, 18, 182, 7, 47, 104, 142, 71, 71, 127, 82, 124, 48, 2, 174, 177, 71, 152, 1, 36,
        33, 155, 184, 238, 238, 190, 109, 221, 4, 9, 161, 151, 114, 55, 42, 142, 98, 173, 219, 59,
        165, 126, 142, 103, 155, 144, 100, 48, 75, 253, 254, 138, 91, 55, 77, 230, 62, 47, 15, 144,
        189, 142, 140, 114, 188, 159, 153, 17, 177, 214, 79, 131, 108, 32, 139, 79, 105, 22, 43,
        160, 46, 214, 104, 112, 1, 82, 211, 208, 81, 253, 11, 187, 110, 163, 138, 212, 57, 180, 76,
        175, 255, 160, 82, 73, 85, 35, 128, 207, 36, 46, 99, 193, 255, 65, 205, 236, 168, 58, 229,
        239, 161, 194, 136, 140, 204, 15, 58, 11, 66, 52, 54, 167, 247, 240, 107, 237, 236, 226,
        57, 55, 66, 141, 86, 200, 138, 195, 234, 156, 170, 210, 253, 202, 100, 224, 122, 83, 98,
        75, 54, 163, 189, 200, 42, 227, 62, 78, 187, 216, 169, 159, 26, 144, 15, 13, 139, 27, 250,
        142, 133, 57, 147, 38, 175, 168, 253, 209, 89, 210, 44, 63, 92, 124, 5, 64, 40, 145, 230,
        69, 219, 187, 131, 186, 116, 114, 75, 110, 222, 211, 17, 97, 118, 85, 66, 9, 217, 245, 47,
        38, 147, 150, 65, 15, 199, 89, 12, 198, 26, 249, 113, 128, 88, 39, 240, 248, 255, 69, 187,
        125, 172, 41, 76, 39, 203, 173, 91, 39, 101, 141, 113, 195, 84, 117, 117, 27, 191, 62, 106,
        196, 78, 161, 186, 19, 98, 121, 71, 150, 180, 107, 210, 11, 166, 72, 65, 74, 219, 140, 83,
        131, 33, 221, 166, 185, 101, 46, 255, 158, 57, 95, 240, 150, 70, 109, 233, 88, 225, 212,
        152, 198, 35, 95, 115, 229, 243, 216, 79, 108, 203, 72, 192, 187, 199, 70, 129, 167, 163,
        179, 164, 24, 251, 20, 55, 163, 112, 71, 144, 60, 48, 14, 140, 78, 16, 48, 70, 179, 98, 68,
        196, 243, 249, 173, 162, 75, 17, 94, 95, 166, 81, 190, 228, 162, 140, 243, 131, 221, 176,
        234, 200, 215, 161, 182, 74, 250, 205, 168, 28, 24, 32, 211, 136, 40, 233, 254, 191, 187,
        58, 138, 93, 230, 55, 143, 103, 117, 141, 21, 187, 234, 104, 129, 149, 22, 26, 98, 114, 75,
        30, 233, 226, 70, 54, 181, 253, 72, 107, 120, 123, 220, 240, 232, 147, 6, 76, 224, 112, 5,
        233, 129, 37, 196, 120, 0, 86, 133, 56, 174, 163, 119, 209, 12, 123, 225, 116, 105, 108,
        231, 13, 173, 125, 116, 170, 146, 127, 231, 176, 143, 212, 238, 99, 14, 218, 10, 82, 123,
        4, 210, 49, 189, 35, 53, 72, 192, 88, 2, 250, 184, 6, 79, 219, 187, 76, 148, 166, 219, 40,
        188, 176, 94, 52, 109, 116, 57, 41, 19, 98, 46, 4, 131, 8, 49, 207, 69, 100, 34, 112, 215,
        71, 7, 98, 41, 77, 7, 36, 46, 249, 86, 192, 33, 131, 116, 163, 22, 34, 190, 168, 204, 81,
        73, 197, 131, 226, 156, 34, 176, 163, 201, 136, 103, 138, 251, 105, 191, 3, 236, 136, 123,
        31, 204, 179, 61, 8, 183, 255, 218, 98, 71, 62, 248, 204, 159, 169, 240, 205, 250, 185, 19,
        142, 181, 128, 3, 209, 123, 9, 63, 208, 149, 138, 42, 9, 198, 149, 194, 48, 222, 223, 55,
        21, 196, 10, 52, 58, 14, 190, 116, 176, 69, 184, 205, 25, 98, 220, 23, 198, 35, 124, 146,
        147, 219, 0, 70, 48, 217, 207, 187, 32, 89, 126, 14, 37, 130, 81, 56, 51, 252, 108, 137,
        52, 56, 69, 124, 99, 246, 50, 121, 193, 146, 186, 174, 0, 198, 156, 153, 123, 199, 190,
        249, 78, 188, 43, 236, 184, 125, 250, 143, 26, 211, 76, 63, 66, 34, 219, 255, 82, 70, 7,
        10, 168, 115, 117, 245, 180, 15, 120, 204, 51, 192, 244, 217, 65, 130, 160, 148, 92, 85,
        106, 177, 33, 225, 112, 83, 168, 81, 88, 17, 60, 50, 27, 199, 174, 74, 15, 157, 71, 177,
        84, 171, 95, 213, 84, 149, 72, 237, 134, 23, 40, 159, 15, 206, 151, 163, 59, 19, 33, 156,
        237, 149, 176, 9, 135, 143, 130, 89, 24, 177, 19, 22, 8, 116, 151, 35, 247, 72, 35, 57,
        218, 202, 59, 50, 2, 159, 51, 120, 108, 244, 141, 60, 86, 232, 178, 76, 76, 16, 162, 106,
        225, 164, 229, 14, 254, 89, 240, 5, 29, 167, 12, 238, 24, 25, 174, 29, 61, 8, 28, 203, 72,
        34, 126, 243, 166, 217, 71, 69, 49, 163, 34, 170, 198, 92, 231, 190, 216, 20, 135, 159,
        108, 29, 203, 133, 122, 0, 103, 70, 140, 26, 229, 253, 131, 145, 29, 17, 51, 169, 88, 102,
        171, 25, 195, 108, 87, 47, 111, 3, 139, 114, 34, 97, 73, 9, 193, 192, 189, 29, 45, 198,
        115, 50, 3, 179, 162, 180, 85, 25, 240, 82, 54, 110, 122, 18, 225, 113, 69, 143, 185, 34,
        198, 177, 72, 120, 190, 153, 30, 118, 132, 111, 173, 39, 107, 72, 185, 12, 146, 22, 53, 12,
        80, 159, 198, 181, 33, 127, 98, 131, 60, 60, 69, 225, 23, 55, 38, 216, 17, 56, 44, 120,
        140, 1, 66, 162, 134, 251, 168, 211, 199, 135, 210, 177, 16, 33, 57, 14, 36, 216, 1, 59,
        131, 173, 48, 62, 98, 39, 56, 13, 243, 59, 204, 142, 154, 177, 247, 49, 162, 142, 180, 94,
        15, 111, 32, 159, 156, 222, 238, 37, 131, 21, 160, 45, 214, 246, 18, 120, 203, 112, 247,
        251, 98, 251, 219, 204, 173, 241, 35, 162, 252, 251, 148, 121, 124, 43, 180, 143, 14, 214,
        171, 64, 170, 142, 155, 110, 70, 246, 69, 107, 7, 195, 10, 66, 120, 111, 106, 103, 203, 21,
        88, 155, 55, 12, 71, 18, 189, 82, 11, 46, 59, 215, 160, 91, 95, 74, 13, 208, 135, 204, 5,
        186, 176, 244, 22, 20, 104, 252, 250, 220, 9, 43, 27, 243, 78, 106, 221, 111, 25, 196, 155,
        56, 120, 136, 15, 186, 58, 7, 101, 254, 57, 0, 83, 160, 231, 46, 51, 221, 136, 84, 37, 5,
        17, 212, 86, 186, 240, 64, 87, 176, 16, 69, 105, 148, 86, 53, 182, 15, 222, 133, 232, 190,
        69, 234, 147, 179, 113, 255, 56, 95, 61, 198, 41, 184, 151, 24, 207, 214, 8, 251, 107, 125,
        154, 37, 184, 30, 73, 102, 140, 77, 217, 48, 131, 176, 210, 220, 228, 175, 57, 166, 101, 0,
        16, 243, 198, 237, 66, 110, 76, 80, 255, 247, 178, 17, 107, 39, 230, 93, 55, 133, 52, 58,
        15, 20, 15, 92, 142, 21, 91, 36, 184, 16, 77, 202, 199, 176, 23, 220, 52, 227, 52, 114,
        105, 41, 80, 90, 183, 85, 189, 172, 212, 235, 53, 183, 171, 161, 38, 129, 11, 87, 248, 13,
        162, 135, 30, 100, 172, 65, 238, 242, 143, 0, 32, 165, 128, 37, 170, 34, 87, 254, 172, 157,
        104, 80, 185, 196, 92, 54, 101, 249, 1, 226, 100, 4, 215, 199, 53, 47, 17, 72, 206, 145,
        64, 183, 170, 6, 127, 14, 47, 84, 182, 41, 0, 86, 9, 112, 26, 249, 70, 14, 96, 218, 170,
        120, 165, 80, 32, 42, 5, 17, 247, 131, 24, 139, 172, 152, 175, 217, 92, 84, 206, 106, 164,
        60, 187, 208, 131, 251, 210, 162, 205, 68, 172, 141, 68, 55, 33, 142, 135, 218, 124, 184,
        164, 142, 207, 44, 246, 2, 166, 162, 81, 163, 191, 184, 159, 40, 166, 228, 143, 58, 147,
        113, 16, 131, 186, 181, 0, 108, 123, 28, 225, 231, 106, 138, 20, 66, 188, 9, 145, 81, 95,
        153, 77, 219, 48, 212, 66, 185, 179, 27, 172, 200, 218, 168, 64, 14, 101, 101, 72, 169, 80,
        77, 22, 182, 181, 121, 146, 208, 60, 102, 75, 172, 38, 78, 131, 94, 204, 141, 25, 7, 214,
        224, 124, 79, 19, 96, 15, 10, 100, 148, 254, 118, 200, 239, 42, 202, 47, 3, 4, 0, 28, 98,
        44, 11, 203, 81, 23, 11, 234, 82, 56, 177, 23, 90, 146, 186, 218, 226, 213, 202, 209, 241,
        195, 238, 20, 133, 64, 10, 165, 196, 6, 231, 89, 79, 215, 133, 149, 50, 122, 127, 233, 253,
        61, 106, 11, 18, 236, 154, 183, 95, 238, 14, 39, 116, 10, 68, 157, 122, 99, 122, 126, 135,
        88, 5, 75, 236, 55, 166, 122, 80, 173, 16, 171, 102, 99, 143, 41, 99, 143, 83, 7, 247, 89,
        202, 190, 205, 187, 249, 40, 254, 4, 24, 36, 155, 200, 151, 153, 179, 251, 12, 132, 73,
        255, 140, 13, 180, 64, 109, 19, 237, 126, 109, 38, 140, 25, 97, 10, 79, 147, 166, 246, 19,
        95, 186, 66, 92, 74, 30, 94, 82, 76, 51, 91, 19, 119, 55, 155, 88, 53, 212, 240, 172, 178,
        112, 205, 132, 237, 15, 139, 163, 202, 79, 241, 29, 104, 66, 105, 115, 27, 115, 134, 201,
        192, 197, 20, 158, 215, 195, 27, 235, 136, 12, 147, 201, 83, 99, 143, 54, 120, 138, 163,
        64, 94, 156, 44, 255, 165, 192, 96, 80, 44, 43, 199, 145, 28, 4, 30, 148, 189, 239, 83,
        162, 34, 221, 30, 160, 207, 249, 136, 127, 196, 241, 140, 204, 92, 241, 201, 72, 26, 209,
        187, 181, 148, 93, 220, 55, 230, 249, 193, 76, 184, 81, 147, 242, 96, 53, 128, 35, 41, 25,
        0, 28, 125, 10, 133, 220, 125, 194, 114, 74, 176, 26, 87, 10, 25, 7, 59, 245, 249, 39, 165,
        228, 69, 162, 177, 76, 156, 131, 128, 135, 21, 199, 22, 87, 241, 252, 243, 78, 30, 144,
        154, 88, 112, 255, 205, 186, 148, 9, 132, 12, 98, 12, 182, 33, 44, 103, 171, 89, 249, 173,
        242, 191, 181, 204, 14, 105, 10, 233, 21, 122, 151, 139, 6, 213, 127, 114, 174, 41, 69,
        239, 221, 104, 167, 201, 38, 223, 224, 86, 71, 53, 245, 244, 110, 248, 134, 79, 155, 19,
        143, 5, 111, 206, 23, 156, 95, 60, 9, 196, 116, 163, 138, 43, 253, 117, 159, 141, 226, 50,
        141, 5, 80, 40, 37, 254, 129, 219, 8, 200, 56, 193, 227, 114, 123, 83, 87, 82, 147, 195,
        99, 240, 1, 52, 251, 234, 114, 151, 8, 19, 17, 133, 79, 6, 114, 117, 19, 117, 160, 79, 55,
        200, 243, 50, 135, 75, 89, 47, 98, 90, 80, 164, 59, 86, 232, 210, 231, 115, 251, 207, 250,
        67, 95, 254, 96, 218, 22, 184, 186, 254, 126, 11, 118, 26, 225, 199, 194, 23, 186, 220, 74,
        133, 207, 70, 225, 87, 169, 146, 20, 18, 58, 202, 151, 230, 208, 245, 142, 220, 61, 252, 5,
        48, 96, 153, 67, 251, 185, 5, 198, 52, 239, 116, 164, 210, 156, 199, 82, 38, 3, 15, 104,
        140, 149, 93, 28, 20, 71, 193, 86, 213, 137, 68, 131, 115, 174, 179, 5, 148, 123, 118, 196,
        99, 222, 179, 4, 220, 119, 218, 21, 237, 113, 185, 16, 196, 202, 21, 84, 99, 105, 219, 37,
        178, 74, 210, 228, 139, 44, 1, 195, 208, 109, 7, 254, 17, 96, 71, 82, 35, 116, 98, 158,
        149, 172, 86, 232, 114, 96, 4, 164, 21, 149, 239, 20, 114, 153, 52, 19, 107, 10, 151, 18,
        95, 80, 212, 75, 191, 232, 11, 178, 214, 85, 220, 136, 4, 17, 69, 172, 18, 125, 248, 10,
        23, 233, 215, 163, 4, 221, 106, 221, 109, 175, 212, 224, 98, 119, 104, 64, 198, 117, 118,
        13, 192, 146, 92, 44, 7, 77, 164, 19, 93, 60, 152, 216, 153, 11, 57, 22, 2, 227, 146, 219,
        250, 81, 110, 10, 172, 210, 53, 35, 0, 234, 38, 12, 45, 53, 93, 240, 205, 228, 83, 97, 70,
        20, 92, 175, 213, 20, 252, 148, 249, 99, 112, 60, 153, 82, 187, 178, 224, 22, 81, 37, 10,
        31, 54, 254, 233, 193, 149, 168, 167, 186, 11, 10, 27, 229, 237, 104, 22, 22, 137, 176,
        169, 215, 199, 60, 25, 171, 106, 18, 193, 137, 135, 147, 92, 4, 156, 172, 112, 141, 34, 94,
        223, 166, 57, 105, 254, 90, 56, 120, 110, 121, 180, 128, 47, 32, 100, 164, 236, 239, 44,
        70, 65, 227, 162, 197, 14, 233, 115, 239, 247, 124, 204, 140, 127, 111, 91, 32, 246, 110,
        96, 255, 90, 69, 251, 176, 129, 103, 0, 140, 80, 243, 159, 54, 110, 62, 216, 212, 214, 248,
        68, 105, 168, 100, 66, 53, 19, 13, 176, 142, 183, 100, 89, 164, 12, 125, 122, 186, 16, 243,
        22, 209, 22, 221, 247, 207, 58, 147, 211, 22, 212, 194, 91, 58, 14, 72, 168, 150, 50, 144,
        45, 227, 13, 78, 125, 245, 116, 179, 115, 168, 194, 133, 4, 98, 196, 170, 84, 69, 249, 209,
        226, 45, 2, 194, 28, 184, 137, 29, 121, 163, 184, 26, 36, 8, 252, 198, 132, 175, 27, 13,
        211, 0, 149, 103, 22, 62, 18, 199, 169, 189, 240, 136, 168, 114, 19, 58, 165, 78, 3, 85,
        44, 191, 6, 149, 138, 208, 128, 205, 89, 92, 24, 8, 106, 37, 150, 74, 2, 102, 109, 152, 54,
        178, 189, 50, 30, 182, 51, 123, 131, 31, 132, 117, 36, 179, 251, 35, 122, 15, 12, 80, 210,
        6, 234, 126, 76, 135, 166, 132, 42, 36, 7, 92, 143, 92, 60, 172, 181, 105, 24, 103, 245,
        114, 117, 225, 215, 194, 110, 174, 34, 120, 250, 18, 128, 162, 58, 10, 87, 142, 177, 48,
        67, 51, 207, 19, 246, 251, 61, 231, 227, 198, 193, 1, 151, 42, 221, 188, 2, 178, 167, 27,
        100, 13, 172, 126, 107, 32, 6, 4, 129, 71, 199, 15, 62, 2, 118, 10, 58, 117, 110, 160, 58,
        132, 185, 125, 162, 146, 147, 49, 115, 134, 67, 25, 230, 155, 0, 161, 231, 13, 137, 250,
        127, 231, 65, 162, 155, 78, 101, 162, 105, 13, 213, 64, 234, 86, 10, 169, 16, 166, 62, 228,
        16, 88, 154, 85, 171, 142, 13, 136, 194, 66, 155, 243, 158, 50, 252, 49, 211, 180, 211,
        211, 85, 208, 247, 194, 131, 64, 75, 234, 122, 47, 61, 232, 165, 29, 3, 212, 47, 80, 139,
        143, 118, 164, 7, 123, 218, 245, 50, 147, 60, 128, 247, 26, 223, 155, 146, 243, 86, 204,
        71, 57, 239, 197, 24, 68, 65, 102, 59, 97, 152, 175, 86, 141, 78, 245, 42, 13, 127, 8, 58,
        216, 147, 177, 47, 250, 157, 123, 3, 4, 156, 18, 4, 230, 40, 20, 136, 238, 2, 114, 64, 252,
        150, 104, 146, 141, 245, 211, 161, 123, 41, 98, 86, 168, 124, 31, 94, 159, 101, 23, 10,
        150, 246, 10, 95, 47, 226, 30, 25, 128, 222, 87, 139, 127, 160, 66, 194, 94, 164, 107, 4,
        65, 81, 132, 143, 93, 125, 107, 74, 201, 62, 30, 100, 10, 154, 200, 124, 180, 113, 97, 137,
        114, 10, 66, 9, 78, 65, 21, 251, 176, 49, 136, 223, 80, 242, 99, 111, 242, 116, 144, 124,
        226, 160, 201, 247, 192, 160, 253, 12, 10, 253, 62, 192, 141, 88, 11, 232, 185, 28, 58,
        141, 165, 176, 67, 236, 208, 12, 197, 178, 170, 26, 234, 190, 180, 18, 56, 117, 44, 153,
        115, 226, 7, 95, 193, 75, 134, 44, 226, 173, 223, 250, 139, 198, 65, 97, 110, 22, 167, 22,
        122, 217, 166, 201, 71, 39, 69, 24, 164, 54, 123, 206, 26, 20, 225, 175, 122, 37, 41, 64,
        239, 40, 73, 195, 130, 4, 51, 20, 87, 182, 44, 34, 209, 151, 196, 168, 240, 108, 208, 23,
        44, 204, 223, 181, 242, 13, 241, 225, 36, 79, 57, 193, 205, 223, 186, 75, 31, 189, 157, 22,
        234, 225, 132, 40, 77, 41, 90, 237, 236, 124, 157, 133, 212, 130, 57, 191, 151, 245, 235,
        154, 127, 97, 81, 48, 193, 143, 234, 228, 9, 80, 56, 34, 42, 17, 135, 36, 156, 166, 46,
        121, 65, 104, 19, 195, 233, 212, 253, 93, 255, 120, 89, 95, 35, 53, 0, 167, 151, 220, 210,
        133, 242, 46, 234, 230, 83, 87, 143, 129, 219, 135, 73, 25, 115, 245, 90, 194, 230, 7, 226,
        69, 132, 22, 176, 82, 98, 97, 162, 27, 99, 193, 200, 164, 31, 141, 179, 130, 232, 212, 51,
        70, 133, 115, 30, 108, 57, 69, 67, 241, 171, 162, 130, 183, 66, 174, 155, 132, 134, 209,
        172, 11, 149, 45, 101, 139, 178, 113, 114, 164, 199, 15, 248, 159, 126, 30, 168, 80, 81, 9,
        234, 197, 198, 114, 178, 54, 200, 91, 100, 10, 82, 86, 155, 108, 148, 212, 240, 124, 235,
        82, 207, 118, 143, 107, 5, 85, 44, 66, 209, 54, 112, 127, 151, 169, 250, 17, 78, 134, 10,
        14, 66, 185, 158, 102, 179, 93, 54, 31, 153, 164, 175, 196, 172, 215, 107, 211, 224, 104,
        239, 99, 47, 177, 97, 43, 101, 218, 220, 29, 14, 228, 162, 239, 110, 158, 191, 231, 78, 96,
        100, 1, 83, 82, 189, 234, 50, 7, 142, 3, 119, 82, 115, 144, 39, 212, 174, 195, 169, 97,
        203, 159, 76, 191, 30, 225, 177, 89, 243, 143, 17, 18, 162, 66, 188, 0, 60, 154, 18, 126,
        158, 45, 204, 87, 97, 156, 156, 96, 199, 21, 129, 1, 177, 191, 195, 222, 250, 19, 36, 218,
        79, 132, 49, 96, 237, 5, 40, 189, 49, 212, 248, 168, 227, 84, 117, 249, 158, 22, 131, 148,
        213, 4, 120, 126, 62, 117, 9, 158, 37, 55, 194, 251, 204, 193, 255, 121, 154, 102, 64, 34,
        148, 110, 36, 216, 117, 20, 129, 17, 87, 252, 226, 70, 91, 98, 243, 150, 255, 53, 18, 67,
        166, 75, 34, 16, 175, 92, 101, 41, 167, 239, 28, 88, 212, 57, 174, 125, 211, 251, 123, 47,
        43, 218, 25, 200, 147, 107, 108, 143, 146, 127, 23, 207, 209, 3, 117, 145, 74, 255, 246,
        188, 147, 216, 140, 44, 48, 86, 198, 168, 235, 248, 150, 99, 3, 187, 82, 126, 42, 6, 11,
        112, 130, 184, 136, 103, 205, 187, 0, 127, 28, 171, 119, 19, 64, 98, 73, 139, 166, 80, 29,
        79, 221, 8, 90, 230, 75, 107, 249, 114, 31, 248, 83, 127, 7, 215, 107, 155, 114, 211, 50,
        200, 35, 251, 41, 92, 3, 170, 190, 7, 73, 135, 219, 168, 225, 158, 61, 221, 213, 134, 175,
        193, 104, 93, 25, 216, 189, 127, 118, 2, 36, 14, 149, 105, 169, 6, 68, 134, 109, 165, 14,
        165, 22, 65, 1, 60, 119, 128, 82, 248, 34, 126, 227, 92, 139, 244, 109, 35, 128, 2, 133,
        125, 35, 33, 252, 50, 140, 201, 211, 247, 15, 132, 155, 15, 76, 124, 138, 222, 233, 3, 1,
        231, 77, 94, 65, 54, 212, 111, 35, 249, 145, 176, 186, 32, 237, 218, 179, 159, 230, 114,
        218, 88, 150, 173, 35, 203, 129, 42, 177, 60, 222, 78, 220, 219, 56, 45, 109, 57, 196, 146,
        186, 35, 198, 41, 28, 140, 56, 18, 239, 25, 101, 76, 211, 165, 244, 222, 116, 205, 219,
        149, 232, 210, 64, 239, 142, 157, 239, 85, 221, 137, 94, 180, 130, 33, 30, 38, 146, 142,
        59, 226, 153, 228, 88, 31, 137, 230, 105, 107, 9, 172, 97, 58, 55, 88, 118, 6, 141, 80,
        211, 29, 155, 36, 197, 186, 176, 186, 197, 212, 226, 160, 232, 212, 46, 12, 8, 34, 65, 127,
        239, 8, 68, 220, 45, 0, 144, 104, 226, 8, 185, 174, 202, 210, 158, 122, 174, 39, 5, 198,
        20, 212, 145, 142, 17, 18, 67, 121, 111, 32, 235, 20, 29, 23, 114, 100, 187, 216, 0, 76,
        196, 49, 99, 35, 188, 61, 188, 23, 72, 251, 212, 164, 32, 46, 224, 35, 114, 217, 156, 240,
        174, 51, 246, 166, 22, 184, 73, 60, 11, 119, 63, 66, 142, 24, 247, 234, 55, 188, 148, 146,
        111, 231, 24, 218, 68, 66, 104, 178, 164, 156, 220, 253, 70, 247, 228, 203, 217, 201, 176,
        59, 9, 126, 3, 122, 143, 208, 78, 175, 223, 59, 157, 21, 168, 119, 125, 3, 109, 8, 74, 184,
        11, 9, 71, 229, 171, 44, 80, 141, 201, 93, 46, 10, 100, 175, 164, 198, 121, 33, 141, 238,
        84, 132, 219, 69, 82, 93, 251, 148, 237, 113, 34, 251, 131, 236, 52, 233, 121, 163, 166,
        68, 251, 187, 108, 137, 245, 173, 174, 158, 19, 17, 63, 198, 138, 248, 126, 63, 237, 149,
        249, 193, 18, 219, 197, 81, 198, 49, 128, 224, 151, 27, 142, 213, 109, 84, 66, 166, 20, 9,
        29, 222, 110, 192, 67, 166, 9, 145, 18, 242, 114, 104, 20, 155, 117, 182, 218, 200, 35, 7,
        32, 152, 207, 154, 59, 114, 94, 15, 29, 228, 0, 16, 25, 183, 213, 175, 128, 47, 0, 129, 39,
        15, 133, 250, 56, 151, 98, 0, 93, 140, 71, 48, 235, 221, 19, 138, 155, 2, 92, 203, 192,
        172, 159, 116, 178, 175, 125, 12, 109, 87, 67, 28, 249, 125, 108, 55, 185, 41, 2, 173, 78,
        1, 38, 167, 4, 78, 56, 71, 82, 127, 35, 243, 29, 120, 31, 157, 116, 29, 146, 136, 120, 214,
        127, 87, 205, 57, 159, 252, 218, 185, 33, 120, 243, 254, 48, 14, 247, 91, 25, 139, 228,
        192, 113, 143, 230, 58, 136, 224, 241, 1, 6, 249, 158, 67, 229, 218, 253, 6, 221, 251, 95,
        169, 247, 240, 168, 104, 188, 40, 203, 185, 133, 187, 138, 234, 18, 205, 52, 190, 222, 206,
        158, 5, 122, 16, 172, 199, 100, 235, 132, 38, 143, 59, 216, 1, 210, 66, 39, 100, 177, 237,
        254, 46, 55, 70, 114, 27, 54, 224, 75, 219, 79, 121, 10, 101, 138, 217, 76, 10, 252, 180,
        54, 41, 107, 6, 10, 219, 218, 186, 47, 188, 242, 19, 100, 16, 141, 243, 124, 44, 16, 222,
        62, 69, 42, 111, 166, 210, 95, 149, 199, 111, 237, 89, 175, 115, 219, 12, 178, 166, 39, 59,
        25, 64, 125, 79, 52, 80, 90, 113, 148, 151, 51, 217, 210, 101, 176, 94, 172, 113, 188, 20,
        30, 69, 63, 183, 176, 7, 85, 19, 11, 99, 157, 168, 235, 233, 72, 56, 118, 144, 198, 239,
        67, 229, 240, 159, 163, 201, 56, 118, 13, 225, 106, 213, 143, 160, 201, 176, 40, 26, 83,
        210, 147, 109, 167, 71, 41, 116, 43, 11, 43, 118, 195, 189, 118, 17, 182, 78, 226, 203,
        223, 127, 171, 71, 38, 223, 19, 110, 246, 20, 208, 20, 254, 15, 107, 194, 74, 44, 181, 106,
        251, 6, 175, 94, 205, 33, 130, 224, 135, 37, 197, 227, 126, 6, 224, 95, 153, 11, 116, 162,
        231, 154, 122, 183, 69, 36, 251, 203, 61, 224, 240, 35, 182, 85, 56, 76, 49, 39, 35, 126,
        65, 37, 216, 216, 235, 236, 73, 228, 69, 189, 251, 223, 96, 72, 132, 95, 87, 69, 98, 129,
        227, 69, 15, 204, 65, 11, 131, 147, 35, 120, 254, 239, 175, 230, 5, 91, 123, 238, 195, 229,
        245, 40, 246, 82, 189, 242, 247, 252, 79, 214, 209, 20, 136, 34, 209, 169, 198, 13, 105,
        61, 202, 91, 72, 37, 2, 38, 197, 246, 201, 217, 207, 242, 169, 24, 55, 122, 25, 43, 107,
        33, 72, 169, 40, 46, 244, 56, 243, 185, 4, 140, 140, 178, 163, 72, 0, 168, 105, 84, 141,
        100, 197, 57, 190, 186, 238, 209, 220, 98, 34, 33, 12, 139, 85, 179, 131, 38, 229, 131,
        155, 155, 245, 25, 145, 220, 202, 170, 226, 49, 205, 37, 118, 101, 140, 197, 86, 36, 254,
        184, 234, 47, 145, 56, 64, 204, 169, 62, 92, 7, 147, 131, 229, 220, 160, 81, 119, 30, 53,
        147, 55, 93, 248, 128, 255, 99, 29, 19, 105, 155, 162, 21, 216, 95, 77, 69, 168, 149, 106,
        197, 90, 85, 251, 125, 55, 201, 212, 61, 175, 186, 132, 13, 196, 61, 68, 49, 73, 69, 228,
        30, 114, 84, 72, 252, 38, 152, 62, 125, 244, 35, 95, 194, 138, 108, 226, 176, 98, 84, 170,
        3, 124, 252, 63, 98, 50, 217, 231, 205, 64, 156, 85, 35, 26, 222, 20, 65, 105, 191, 181,
        142, 210, 171, 16, 51, 221, 70, 74, 240, 164, 78, 114, 137, 20, 28, 56, 84, 83, 68, 101,
        11, 175, 38, 97, 124, 4, 80, 221, 20, 42, 226, 131, 63, 157, 89, 122, 10, 6, 250, 249, 121,
        63, 177, 173, 71, 9, 228, 1, 148, 5, 19, 117, 126, 153, 201, 74, 101, 75, 101, 172, 134,
        168, 59, 48, 107, 189, 224, 129, 203, 133, 143, 170, 130, 32, 143, 244, 2, 24, 55, 54, 163,
        84, 68, 96, 142, 35, 55, 9, 47, 62, 142, 76, 163, 215, 223, 160, 164, 143, 148, 182, 238,
        143, 133, 219, 97, 126, 30, 252, 189, 57, 238, 210, 213, 189, 39, 95, 212, 143, 89, 5, 69,
        124, 63, 84, 17, 56, 160, 189, 169, 225, 79, 184, 213, 103, 70, 200, 34, 58, 72, 156, 13,
        195, 148, 118, 222, 150, 123, 74, 237, 72, 116, 162, 78, 1, 110, 91, 137, 188, 156, 102,
        192, 177, 157, 74, 16, 209, 31, 106, 56, 109, 10, 226, 4, 140, 247, 161, 57, 220, 168, 27,
        59, 123, 65, 159, 151, 155, 93, 83, 202, 251, 228, 191, 242, 25, 129, 136, 182, 71, 96,
        167, 65, 182, 121, 3, 177, 76, 39, 45, 23, 41, 161, 129, 193, 199, 28, 177, 60, 184, 160,
        87, 18, 16, 195, 38, 185, 190, 94, 210, 88, 118, 170, 212, 104, 215, 93, 74, 123, 250, 24,
        234, 36, 131, 30, 103, 64, 102, 57, 123, 44, 39, 222, 227, 66, 131, 57, 208, 39, 184, 228,
        113, 37, 154, 62, 24, 10, 39, 250, 175, 21, 215, 67, 35, 162, 243, 4, 198, 228, 90, 207,
        102, 174, 34, 61, 166, 189, 93, 34, 205, 28, 188, 125, 14, 228, 251, 110, 141, 209, 37, 91,
        113, 63, 30, 150, 206, 146, 248, 147, 199, 74, 193, 143, 4, 227, 95, 221, 28, 18, 188, 53,
        10, 196, 199, 223, 77, 65, 156, 120, 118, 71, 141, 207, 200, 198, 31, 8, 195, 134, 248, 34,
        191, 157, 133, 163, 39, 84, 244, 12, 162, 130, 34, 104, 231, 113, 41, 81, 219, 166, 237,
        75, 167, 76, 31, 92, 59, 11, 219, 216, 24, 0, 57, 88, 66, 100, 192, 22, 5, 253, 46, 146,
        105, 204, 175, 64, 13, 139, 111, 99, 90, 43, 211, 108, 55, 108, 65, 176, 91, 210, 57, 194,
        59, 7, 7, 167, 59, 127, 207, 79, 42, 58, 107, 173, 151, 20, 145, 81, 171, 172, 62, 160, 48,
        251, 195, 212, 47, 38, 82, 236, 191, 117, 80, 4, 77, 37, 129, 179, 215, 50, 64, 55, 76,
        206, 177, 246, 55, 210, 69, 56, 101, 29, 168, 90, 43, 167, 23, 183, 51, 196, 242, 39, 204,
        25, 243, 242, 210, 160, 251, 1, 42, 211, 108, 118, 12, 198, 69, 15, 83, 207, 206, 166, 143,
        65, 14, 170, 234, 132, 1, 29, 60, 199, 172, 107, 106, 245, 196, 81, 35, 108, 104, 6, 137,
        13, 66, 9, 127, 1, 11, 197, 90, 3, 83, 137, 225, 233, 202, 63, 15, 186, 184, 89, 195, 239,
        47, 132, 136, 205, 218, 183, 164, 224, 206, 243, 39, 9, 6, 50, 48, 133, 58, 108, 56, 200,
        71, 44, 248, 219, 67, 192, 108, 196, 203, 17, 76, 150, 108, 221, 88, 12, 217, 168, 130,
        223, 58, 222, 53, 151, 122, 202, 32, 147, 126, 251, 42, 107, 36, 210, 119, 173, 14, 44,
        187, 238, 225, 210, 176, 150, 81, 159, 194, 3, 202, 81, 83, 103, 151, 49, 45, 56, 246, 167,
        73, 33, 230, 74, 101, 1, 33, 206, 94, 107, 124, 83, 187, 9, 63, 90, 147, 117, 214, 30, 123,
        127, 212, 182, 191, 78, 185, 3, 63, 66, 96, 206, 35, 22, 134, 239, 59, 187, 173, 112, 84,
        109, 141, 193, 43, 168, 9, 36, 172, 84, 15, 93, 115, 2, 152, 54, 24, 21, 104, 222, 102,
        186, 160, 144, 110, 100, 41, 99, 127, 211, 72, 102, 236, 129, 67, 206, 50, 254, 79, 85, 27,
        122, 213, 204, 172, 122, 91, 102, 185, 100, 70, 231, 4, 111, 113, 148, 121, 43, 242, 93,
        80, 15, 187, 74, 89, 237, 107, 255, 62, 236, 70, 144, 255, 33, 42, 192, 247, 121, 114, 188,
        69, 91, 225, 200, 16, 45, 106, 235, 29, 7, 5, 10, 120, 106, 8, 9, 232, 103, 89, 211, 76,
        145, 34, 52, 191, 244, 226, 94, 216, 16, 227, 235, 57, 91, 114, 216, 181, 150, 229, 89, 12,
        33, 84, 198, 126, 89, 107, 194, 3, 163, 66, 108, 182, 104, 162, 131, 16, 69, 195, 213, 124,
        148, 135, 60, 187, 6, 193, 90, 154, 181, 101, 72, 144, 149, 232, 105, 155, 1, 250, 249,
        128, 151, 183, 233, 180, 184, 20, 242, 11, 138, 6, 98, 209, 86, 228, 75, 8, 126, 115, 142,
        240, 158, 145, 164, 105, 86, 119, 112, 177, 212, 207, 4, 111, 207, 219, 121, 204, 235, 28,
        223, 128, 39, 156, 132, 193, 22, 195, 20, 241, 241, 77, 245, 237, 164, 210, 91, 125, 250,
        207, 111, 79, 69, 194, 201, 78, 175, 204, 167, 167, 100, 151, 123, 42, 58, 85, 11, 200, 80,
        217, 116, 99, 230, 229, 39, 92, 107, 84, 195, 17, 50, 37, 203, 105, 21, 49, 191, 227, 22,
        158, 42, 3, 201, 97, 46, 255, 178, 66, 24, 184, 30, 17, 9, 65, 7, 154, 50, 165, 69, 238, 0,
        94, 192, 206, 198, 204, 249, 130, 107, 245, 58, 125, 145, 62, 53, 41, 221, 58, 222, 241,
        126, 238, 18, 165, 248, 250, 152, 8, 142, 96, 203, 255, 40, 125, 225, 25, 181, 233, 81, 70,
        90, 171, 63, 177, 245, 228, 111, 197, 101, 201, 203, 96, 221, 186, 233, 142, 42, 242, 226,
        228, 240, 75, 83, 95, 150, 167, 38, 118, 182, 112, 23, 200, 160, 204, 201, 172, 193, 149,
        56, 16, 151, 150, 172, 92, 28, 95, 31, 154, 160, 7, 116, 39, 19, 170, 150, 229, 136, 226,
        114, 218, 251, 81, 112, 237, 127, 237, 252, 157, 119, 107, 222, 52, 54, 191, 223, 153, 93,
        186, 13, 238, 154, 177, 195, 202, 199, 202, 200, 22, 83, 97, 36, 80, 105, 77, 25, 79, 207,
        172, 90, 198, 45, 138, 215, 1, 196, 59, 87, 150, 99, 84, 166, 172, 119, 200, 156, 176, 190,
        251, 146, 176, 114, 49, 171, 181, 183, 202, 17, 114, 106, 46, 73, 30, 30, 93, 171, 23, 227,
        121, 3, 215, 127, 202, 39, 128, 192, 21, 252, 44, 208, 84, 129, 226, 123, 73, 140, 113, 7,
        150, 21, 240, 129, 234, 81, 24, 85, 59, 64, 5, 35, 164, 231, 33, 163, 19, 4, 120, 125, 71,
        125, 72, 216, 140, 85, 41, 247, 203, 119, 54, 60, 136, 166, 97, 0, 78, 231, 22, 127, 53,
        136, 223, 199, 36, 152, 232, 166, 66, 27, 66, 147, 142, 123, 165, 108, 215, 170, 235, 33,
        94, 222, 237, 248, 6, 11, 147, 232, 195, 232, 191, 11, 178, 221, 200, 149, 91, 93, 40, 163,
        196, 217, 92, 173, 23, 203, 254, 47, 246, 219, 207, 43, 254, 56, 242, 148, 237, 232, 208,
        158, 177, 204, 14, 187, 151, 236, 213, 44, 134, 53, 91, 172, 5, 10, 249, 83, 153, 170, 152,
        54, 71, 119, 146, 58, 222, 249, 232, 41, 71, 0, 85, 228, 54, 211, 210, 62, 62, 32, 240,
        230, 13, 44, 102, 132, 153, 174, 151, 230, 113, 220, 162, 129, 196, 120, 245, 11, 153, 15,
        219, 134, 192, 11, 36, 204, 195, 130, 71, 111, 146, 235, 141, 80, 226, 107, 249, 174, 147,
        88, 206, 150, 239, 186, 24, 139, 201, 133, 56, 230, 78, 78, 190, 229, 35, 60, 78, 67, 32,
        138, 252, 161, 81, 58, 136, 49, 253, 96, 88, 222, 73, 20, 191, 36, 74, 178, 248, 101, 124,
        231, 199, 221, 108, 233, 21, 116, 35, 178, 64, 66, 91, 34, 217, 15, 64, 231, 199, 93, 164,
        249, 212, 84, 186, 172, 36, 186, 5, 236, 241, 20, 1, 235, 20, 175, 109, 18, 66, 32, 99, 2,
        234, 98, 220, 249, 156, 247, 92, 204, 141, 91, 20, 158, 143, 181, 139, 106, 5, 74, 110, 20,
        1, 126, 230, 36, 29, 76, 164, 186, 149, 159, 194, 131, 72, 178, 115, 93, 34, 67, 149, 215,
        217, 49, 193, 247, 145, 64, 69, 4, 118, 137, 245, 7, 107, 127, 88, 108, 97, 192, 175, 25,
        120, 35, 125, 75, 243, 109, 211, 183, 131, 233, 97, 224, 170, 157, 64, 178, 236, 154, 255,
        30, 5, 135, 48, 13, 108, 72, 68, 163, 110, 20, 143, 207, 201, 135, 29, 6, 252, 61, 142,
        175, 73, 109, 209, 36, 9, 1, 164, 23, 149, 125, 174, 70, 121, 21, 224, 23, 69, 17, 216,
        105, 182, 225, 162, 213, 167, 235, 10, 126, 204, 189, 238, 75, 88, 241, 13, 6, 21, 90, 103,
        182, 176, 8, 14, 23, 23, 92, 92, 114, 93, 199, 176, 137, 102, 44, 31, 41, 36, 148, 176, 52,
        148, 34, 221, 0, 211, 229, 114, 51, 78, 175, 73, 110, 83, 81, 95, 214, 200, 188, 74, 222,
        171, 104, 133, 16, 91, 155, 114, 161, 177, 163, 175, 11, 90, 254, 161, 17, 106, 188, 229,
        213, 165, 201, 209, 199, 30, 42, 6, 130, 181, 242, 62, 91, 194, 139, 152, 189, 7, 240, 35,
        34, 74, 45, 92, 64, 223, 25, 246, 23, 183, 178, 87, 84, 145, 227, 26, 91, 49, 28, 86, 9,
        66, 180, 84, 253, 213, 137, 189, 189, 25, 24, 63, 49, 212, 117, 124, 148, 111, 16, 152,
        108, 107, 205, 227, 145, 58, 143, 222, 1, 50, 188, 48, 238, 29, 104, 221, 175, 69, 166, 10,
        109, 135, 82, 102, 242, 241, 48, 95, 1, 44, 133, 193, 218, 36, 72, 251, 198, 208, 53, 123,
        46, 147, 101, 140, 122, 6, 47, 46, 120, 142, 181, 98, 184, 82, 82, 100, 39, 60, 1, 125, 5,
        72, 196, 0, 239, 172, 242, 27, 82, 42, 93, 226, 30, 88, 147, 121, 1, 95, 10, 229, 223, 9,
        204, 71, 69, 87, 31, 120, 197, 44, 76, 167, 62, 6, 107, 59, 15, 190, 206, 254, 192, 63,
        250, 23, 162, 30, 24, 54, 110, 176, 47, 39, 248, 255, 129, 84, 139, 220, 243, 101, 192,
        241, 35, 227, 12, 0, 14, 0, 227, 161, 45, 164, 53, 228, 27, 64, 11, 243, 233, 10, 55, 1,
        28, 255, 167, 248, 173, 169, 88, 197, 200, 101, 31, 44, 119, 243, 211, 108, 238, 24, 177,
        87, 190, 211, 219, 28, 197, 73, 224, 241, 148, 200, 19, 221, 62, 133, 156, 188, 203, 95,
        195, 255, 243, 110, 44, 140, 5, 87, 192, 11, 36, 107, 70, 34, 163, 127, 151, 211, 71, 75,
        226, 3, 38, 192, 196, 175, 39, 232, 85, 5, 241, 196, 135, 106, 92, 124, 102, 84, 213, 208,
        7, 81, 11, 226, 81, 104, 37, 12, 228, 175, 179, 227, 204, 54, 53, 228, 235, 11, 245, 201,
        230, 154, 106, 58, 49, 146, 6, 70, 132, 239, 245, 50, 81, 38, 175, 252, 145, 220, 233, 222,
        24, 156, 40, 96, 122, 188, 125, 99, 7, 108, 121, 146, 193, 191, 150, 68, 78, 206, 233, 201,
        30, 110, 6, 184, 74, 193, 180, 111, 34, 218, 109, 157, 142, 20, 167, 29, 169, 15, 45, 234,
        169, 208, 174, 4, 153, 220, 62, 245, 79, 159, 112, 92, 178, 83, 240, 220, 16, 224, 79, 59,
        95, 218, 173, 157, 218, 47, 138, 197, 5, 251, 148, 93, 71, 79, 215, 0, 127, 48, 184, 177,
        56, 54, 104, 101, 113, 93, 90, 172, 15, 95, 154, 204, 228, 44, 177, 37, 75, 243, 132, 198,
        182, 112, 134, 15, 5, 194, 71, 176, 233, 216, 184, 90, 90, 66, 168, 197, 65, 108, 196, 177,
        202, 241, 54, 156, 172, 176, 58, 34, 255, 186, 194, 199, 146, 184, 208, 92, 1, 159, 47,
        214, 154, 242, 255, 13, 214, 94, 234, 176, 220, 35, 66, 242, 11, 23, 214, 224, 80, 181,
        228, 50, 218, 29, 151, 62, 161, 225, 226, 109, 203, 139, 38, 106, 26, 131, 2, 235, 237, 93,
        212, 182, 12, 193, 203, 84, 129, 250, 66, 254, 103, 238, 37, 234, 123, 18, 0, 220, 145, 16,
        39, 178, 15, 117, 26, 37, 111, 135, 239, 73, 186, 215, 110, 54, 154, 28, 115, 172, 178,
        110, 60, 157, 95, 95, 120, 25, 1, 107, 14, 35, 210, 62, 216, 170, 52, 135, 187, 212, 145,
        80, 149, 121, 104, 114, 38, 164, 148, 17, 153, 234, 23, 36, 144, 206, 148, 197, 5, 196,
        106, 237, 168, 50, 101, 219, 201, 20, 184, 135, 168, 179, 142, 212, 21, 29, 142, 33, 7, 22,
        45, 159, 96, 83, 237, 74, 182, 234, 222, 187, 236, 226, 91, 68, 180, 163, 49, 167, 183,
        234, 8, 1, 85, 42, 128, 77, 26, 17, 134, 218, 242, 27, 76, 39, 207, 24, 203, 13, 103, 99,
        131, 110, 243, 107, 183, 19, 98, 35, 190, 235, 137, 130, 89, 122, 181, 222, 157, 189, 179,
        126, 162, 148, 250, 240, 255, 197, 65, 52, 16, 64, 192, 240, 100, 52, 17, 198, 206, 153,
        81, 51, 242, 173, 248, 142, 107, 46, 195, 150, 96, 181, 90, 197, 81, 174, 205, 211, 126,
        162, 200, 158, 253, 61, 41, 91, 248, 202, 177, 161, 141, 179, 170, 161, 198, 78, 85, 243,
        5, 87, 100, 228, 25, 209, 2, 51, 108, 55, 79, 193, 148, 134, 176, 141, 14, 79, 177, 143,
        67, 203, 40, 71, 74, 71, 223, 197, 125, 112, 154, 20, 27, 58, 38, 177, 12, 4, 135, 53, 13,
        242, 148, 26, 3, 56, 16, 115, 25, 109, 220, 33, 7, 78, 47, 184, 8, 185, 124, 231, 161, 74,
        206, 69, 3, 243, 165, 1, 51, 127, 19, 213, 56, 35, 183, 121, 90, 110, 38, 206, 58, 89, 251,
        74, 39, 89, 181, 126, 202, 51, 226, 203, 67, 24, 79, 46, 7, 208, 107, 209, 38, 189, 97, 38,
        247, 57, 168, 140, 36, 222, 235, 238, 45, 215, 196, 61, 102, 19, 229, 212, 139, 108, 115,
        16, 162, 173, 228, 245, 81, 195, 96, 159, 73, 160, 154, 199, 175, 137, 1, 87, 164, 44, 19,
        132, 11, 146, 213, 229, 100, 156, 114, 231, 189, 220, 57, 119, 110, 83, 186, 76, 146, 127,
        79, 98, 219, 93, 37, 91, 44, 84, 213, 227, 167, 190, 112, 169, 214, 112, 62, 233, 165, 170,
        99, 242, 158, 254, 138, 230, 125, 17, 52, 163, 12, 205, 170, 141, 222, 119, 46, 136, 109,
        130, 141, 36, 106, 2, 156, 224, 40, 196, 93, 111, 11, 94, 252, 193, 48, 181, 107, 96, 124,
        152, 231, 55, 188, 76, 39, 145, 227, 220, 153, 241, 81, 107, 199, 40, 0, 159, 237, 95, 10,
        165, 49, 148, 99, 136, 154, 161, 59, 101, 135, 28, 246, 60, 141, 198, 20, 34, 98, 17, 52,
        181, 114, 18, 30, 108, 5, 40, 45, 233, 163, 221, 180, 149, 235, 6, 10, 58, 91, 162, 57,
        136, 21, 142, 252, 217, 76, 190, 16, 129, 13, 204, 127, 78, 131, 130, 209, 175, 49, 11,
        226, 34, 75, 53, 84, 10, 39, 167, 224, 225, 88, 64, 71, 176, 167, 68, 105, 229, 50, 183,
        97, 109, 15, 9, 36, 140, 15, 215, 111, 26, 188, 109, 118, 114, 99, 194, 6, 86, 221, 189,
        47, 153, 6, 247, 184, 248, 114, 134, 17, 176, 179, 71, 25, 167, 133, 201, 12, 136, 213,
        219, 30, 11, 190, 31, 140, 94, 139, 120, 12, 69, 107, 224, 76, 14, 153, 67, 135, 59, 160,
        37, 126, 141, 142, 181, 16, 55, 117, 83, 177, 69, 31, 246, 253, 247, 148, 163, 121, 40, 48,
        59, 222, 112, 35, 3, 85, 210, 202, 113, 2, 83, 87, 122, 218, 198, 128, 37, 50, 200, 97,
        209, 105, 206, 167, 19, 59, 227, 188, 114, 76, 152, 239, 20, 19, 195, 249, 188, 218, 228,
        65, 187, 2, 53, 30, 16, 206, 233, 0, 52, 210, 87, 238, 238, 217, 166, 153, 169, 211, 123,
        104, 34, 104, 126, 175, 71, 248, 98, 95, 75, 183, 22, 203, 171, 7, 192, 216, 200, 206, 208,
        174, 107, 8, 217, 68, 43, 55, 0, 75, 245, 222, 87, 208, 168, 36, 183, 170, 10, 32, 187, 16,
        84, 6, 105, 33, 176, 40, 72, 119, 65, 242, 245, 101, 0, 127, 38, 157, 76, 25, 254, 190, 89,
        5, 255, 137, 150, 185, 220, 190, 50, 2, 48, 100, 110, 107, 49, 186, 64, 234, 172, 244, 113,
        103, 209, 21, 140, 48, 91, 217, 230, 196, 0, 108, 125, 160, 16, 60, 246, 243, 21, 20, 91,
        78, 244, 87, 7, 185, 136, 64, 90, 157, 74, 137, 74, 137, 0, 140, 57, 4, 76, 45, 54, 30, 83,
        56, 110, 92, 211, 93, 174, 53, 151, 162, 203, 244, 250, 126, 25, 158, 192, 243, 64, 220,
        253, 170, 185, 82, 140, 126, 184, 35, 239, 139, 253, 40, 188, 242, 201, 16, 210, 156, 58,
        25, 252, 12, 25, 20, 185, 129, 215, 164, 103, 137, 150, 90, 247, 3, 60, 23, 217, 179, 93,
        42, 85, 188, 30, 35, 80, 211, 145, 70, 61, 31, 108, 44, 108, 121, 65, 224, 222, 47, 65,
        189, 175, 118, 36, 221, 113, 36, 43, 132, 241, 200, 147, 1, 145, 88, 136, 72, 159, 89, 177,
        225, 241, 29, 138, 5, 229, 42, 170, 14, 216, 19, 174, 255, 33, 206, 39, 29, 226, 52, 209,
        211, 174, 208, 32, 116, 7, 61, 76, 49, 183, 226, 232, 169, 35, 207, 171, 11, 172, 122, 118,
        12, 199, 146, 148, 54, 163, 1, 173, 61, 136, 112, 137, 179, 142, 212, 204, 91, 71, 225, 67,
        118, 164, 137, 11, 167, 68, 139, 101, 166, 189, 215, 71, 51, 31, 112, 115, 23, 33, 83, 173,
        15, 92, 236, 133, 7, 72, 83, 0, 19, 243, 176, 221, 186, 204, 77, 146, 213, 232, 113, 148,
        245, 82, 81, 22, 218, 150, 170, 182, 241, 87, 55, 251, 11, 249, 95, 189, 80, 205, 220, 3,
        43, 17, 247, 146, 221, 67, 172, 126, 246, 208, 196, 130, 107, 179, 59, 68, 14, 239, 232,
        142, 3, 176, 114, 149, 71, 79, 79, 243, 87, 182, 43, 139, 15, 125, 163, 78, 215, 255, 49,
        64, 224, 96, 193, 50, 220, 180, 63, 115, 199, 19, 107, 137, 112, 187, 16, 103, 141, 207,
        175, 219, 1, 67, 23, 70, 17, 72, 233, 153, 137, 189, 236, 145, 250, 100, 247, 114, 184,
        245, 117, 182, 7, 8, 118, 195, 7, 81, 84, 244, 142, 200, 10, 113, 231, 107, 145, 101, 97,
        215, 221, 87, 181, 50, 39, 96, 186, 235, 149, 89, 183, 250, 58, 49, 18, 145, 52, 248, 211,
        106, 12, 166, 202, 157, 167, 232, 96, 197, 255, 186, 36, 113, 234, 110, 3, 102, 54, 228,
        222, 192, 144, 31, 163, 35, 26, 16, 83, 101, 48, 109, 138, 130, 52, 4, 123, 103, 248, 20,
        226, 54, 207, 19, 19, 48, 174, 95, 251, 80, 46, 105, 232, 153, 79, 212, 18, 87, 113, 144,
        21, 181, 77, 184, 202, 63, 146, 12, 121, 64, 141, 172, 127, 74, 97, 63, 190, 33, 210, 100,
        134, 100, 177, 189, 46, 4, 144, 223, 24, 238, 233, 53, 20, 158, 219, 83, 30, 99, 192, 154,
        243, 222, 19, 139, 126, 34, 110, 104, 122, 165, 65, 217, 125, 4, 70, 245, 102, 202, 180,
        187, 229, 99, 85, 246, 84, 80, 91, 79, 151, 65, 181, 224, 11, 83, 32, 182, 66, 105, 187,
        123, 13, 47, 238, 84, 228, 227, 136, 78, 208, 138, 224, 55, 138, 149, 142, 223, 1, 174,
        214, 39, 139, 60, 90, 18, 10, 191, 72, 173, 167, 36, 239, 107, 165, 39, 229, 192, 231, 226,
        194, 144, 93, 26, 163, 193, 16, 133, 191, 139, 5, 146, 15, 9, 38, 67, 75, 53, 161, 145,
        204, 178, 195, 173, 234, 44, 94, 134, 75, 126, 156, 42, 68, 106, 237, 124, 87, 115, 12,
        245, 85, 232, 52, 201, 129, 35, 174, 18, 7, 187, 170, 54, 245, 182, 67, 78, 190, 225, 0,
        190, 151, 21, 231, 70, 249, 207, 135, 47, 166, 122, 255, 9, 118, 144, 206, 65, 123, 22, 46,
        19, 115, 40, 22, 83, 9, 139, 8, 6, 64, 28, 78, 86, 132, 137, 183, 233, 25, 22, 178, 17,
        105, 121, 106, 62, 191, 130, 10, 7, 153, 117, 157, 167, 249, 251, 95, 21, 44, 103, 169,
        102, 177, 206, 89, 99, 127, 46, 143, 87, 16, 162, 3, 107, 185, 4, 112, 251, 75, 239, 201,
        140, 191, 54, 214, 96, 84, 193, 42, 128, 119, 96, 254, 229, 49, 160, 11, 157, 13, 48, 126,
        84, 123, 103, 186, 206, 194, 183, 132, 190, 120, 166, 228, 99, 8, 16, 21, 49, 69, 5, 114,
        169, 63, 235, 65, 243, 77, 98, 206, 136, 29, 64, 128, 9, 254, 113, 78, 136, 108, 156, 179,
        113, 144, 162, 9, 37, 132, 121, 52, 11, 76, 195, 97, 186, 233, 7, 37, 87, 9, 233, 193, 10,
        169, 64, 194, 40, 29, 65, 159, 149, 33, 186, 132, 118, 253, 43, 28, 59, 195, 15, 27, 120,
        5, 222, 107, 55, 3, 166, 74, 59, 141, 226, 24, 80, 234, 58, 172, 39, 128, 223, 195, 143,
        247, 121, 205, 142, 39, 210, 41, 24, 187, 149, 87, 146, 179, 75, 100, 188, 150, 154, 113,
        220, 167, 94, 73, 202, 109, 54, 73, 219, 170, 215, 133, 92, 20, 37, 28, 108, 249, 193, 0,
        39, 93, 75, 100, 71, 245, 213, 53, 116, 76, 154, 22, 67, 82, 236, 18, 204, 93, 105, 129,
        33, 216, 43, 157, 130, 241, 28, 201, 215, 24, 200, 113, 4, 216, 211, 88, 144, 48, 134, 213,
        186, 42, 188, 5, 80, 176, 208, 3, 205, 229, 65, 18, 220, 105, 113, 126, 131, 120, 13, 128,
        97, 40, 110, 126, 86, 63, 110, 209, 31, 176, 69, 254, 64, 23, 97, 115, 217, 215, 195, 9,
        117, 142, 107, 144, 2, 13, 186, 158, 216, 178, 151, 29, 83, 140, 118, 4, 80, 32, 131, 231,
        107, 110, 196, 229, 254, 91, 207, 99, 52, 167, 29, 181, 100, 180, 92, 168, 112, 66, 97,
        248, 163, 164, 184, 248, 127, 110, 118, 216, 42, 206, 88, 192, 85, 100, 238, 79, 134, 37,
        239, 135, 132, 180, 36, 1, 139, 1, 128, 30, 159, 169, 41, 144, 24, 206, 110, 54, 41, 248,
        67, 96, 145, 173, 123, 217, 181, 48, 224, 139, 156, 38, 57, 170, 46, 208, 194, 168, 173,
        60, 111, 100, 64, 1, 26, 27, 85, 155, 140, 109, 203, 54, 31, 16, 184, 219, 198, 179, 60,
        227, 254, 92, 21, 56, 6, 209, 123, 250, 59, 132, 147, 93, 236, 158, 53, 132, 148, 131, 101,
        149, 169, 151, 162, 3, 109, 12, 253, 90, 40, 193, 154, 187, 221, 242, 137, 191, 50, 244, 3,
        204, 243, 10, 104, 188, 75, 56, 137, 255, 30, 67, 127, 243, 163, 129, 161, 209, 83, 171,
        223, 73, 60, 106, 112, 204, 121, 216, 218, 206, 112, 204, 205, 61, 202, 14, 110, 241, 115,
        30, 226, 243, 188, 5, 25, 220, 96, 151, 133, 254, 52, 22, 99, 13, 52, 179, 61, 112, 80, 96,
        133, 149, 66, 238, 121, 179, 187, 110, 93, 1, 4, 40, 245, 29, 222, 18, 60, 172, 75, 172,
        104, 195, 26, 180, 4, 112, 50, 99, 234, 88, 95, 163, 17, 85, 216, 81, 73, 156, 100, 10,
        196, 148, 106, 237, 2, 115, 19, 226, 17, 90, 74, 120, 68, 41, 51, 216, 19, 195, 74, 15, 41,
        233, 244, 152, 166, 192, 10, 183, 188, 213, 145, 223, 16, 133, 173, 153, 76, 134, 79, 191,
        192, 87, 117, 5, 29, 138, 240, 15, 7, 132, 193, 99, 131, 225, 180, 193, 236, 253, 177, 251,
        77, 23, 13, 128, 129, 33, 103, 33, 126, 50, 114, 148, 80, 9, 112, 147, 13, 196, 105, 157,
        207, 69, 134, 212, 247, 238, 89, 213, 229, 240, 253, 183, 93, 181, 47, 14, 148, 227, 92,
        159, 69, 117, 152, 248, 82, 82, 177, 32, 174, 128, 78, 65, 127, 7, 102, 52, 168, 250, 48,
        29, 40, 212, 184, 60, 240, 179, 161, 179, 19, 100, 36, 232, 70, 205, 139, 34, 45, 254, 201,
        108, 120, 154, 168, 14, 242, 142, 203, 93, 163, 151, 236, 180, 65, 214, 174, 2, 0, 185, 80,
        110, 77, 150, 34, 84, 98, 70, 62, 196, 225, 80, 44, 240, 139, 36, 209, 182, 95, 110, 12,
        219, 121, 121, 10, 41, 19, 104, 25, 67, 218, 208, 28, 3, 152, 232, 144, 174, 125, 90, 227,
        169, 182, 22, 45, 214, 166, 152, 176, 52, 164, 222, 4, 212, 139, 46, 84, 8, 8, 243, 19, 24,
        158, 157, 82, 146, 157, 33, 146, 131, 58, 62, 66, 127, 216, 198, 200, 23, 16, 189, 120, 3,
        136, 71, 241, 159, 225, 168, 18, 187, 212, 153, 0, 201, 250, 79, 23, 180, 184, 211, 239,
        108, 102, 141, 253, 58, 149, 241, 48, 20, 178, 128, 30, 127, 180, 75, 104, 64, 235, 81, 37,
        123, 159, 231, 94, 227, 38, 45, 106, 13, 131, 121, 165, 219, 165, 104, 137, 117, 236, 27,
        83, 72, 131, 201, 159, 51, 209, 72, 147, 56, 16, 117, 42, 184, 126, 95, 202, 1, 227, 89,
        84, 241, 105, 36, 43, 95, 31, 216, 220, 147, 70, 98, 202, 228, 244, 198, 79, 0, 69, 18,
        181, 98, 231, 142, 135, 232, 248, 44, 2, 220, 225, 139, 2, 22, 29, 86, 72, 243, 51, 221,
        200, 11, 241, 88, 16, 211, 86, 34, 222, 117, 98, 137, 171, 73, 228, 185, 38, 85, 178, 36,
        241, 118, 227, 80, 190, 18, 83, 207, 94, 245, 31, 127, 199, 177, 107, 106, 222, 104, 88,
        103, 234, 36, 44, 233, 157, 172, 225, 174, 80, 222, 117, 247, 11, 139, 0, 247, 248, 169,
        176, 232, 50, 141, 195, 17, 89, 218, 23, 125, 158, 239, 252, 41, 27, 5, 200, 113, 239, 214,
        235, 210, 182, 209, 166, 148, 96, 130, 37, 217, 228, 214, 76, 73, 211, 161, 22, 119, 186,
        104, 96, 70, 177, 144, 188, 192, 62, 187, 97, 236, 170, 252, 149, 234, 109, 153, 121, 121,
        22, 254, 79, 116, 39, 16, 141, 103, 207, 174, 243, 219, 67, 65, 83, 231, 232, 5, 187, 83,
        197, 69, 41, 89, 234, 219, 58, 123, 50, 66, 66, 223, 54, 134, 107, 120, 216, 20, 250, 147,
        115, 195, 208, 140, 165, 144, 3, 86, 235, 80, 117, 54, 6, 8, 0, 145, 157, 113, 155, 223,
        82, 82, 89, 75, 65, 87, 133, 201, 211, 104, 115, 215, 73, 113, 152, 59, 201, 9, 192, 85,
        204, 200, 0, 11, 77, 89, 57, 184, 242, 142, 77, 178, 96, 157, 59, 200, 113, 220, 210, 180,
        71, 22, 140, 23, 101, 115, 166, 184, 84, 165, 248, 86, 176, 220, 47, 65, 22, 224, 119, 30,
        149, 149, 193, 88, 101, 25, 30, 69, 51, 234, 134, 219, 84, 0, 164, 6, 16, 44, 151, 132,
        190, 214, 220, 35, 185, 202, 37, 232, 242, 13, 107, 232, 161, 250, 77, 7, 173, 219, 195,
        185, 152, 137, 11, 18, 42, 238, 87, 87, 190, 48, 197, 118, 40, 207, 216, 88, 91, 24, 225,
        67, 41, 72, 210, 243, 53, 252, 253, 222, 157, 207, 2, 171, 253, 176, 17, 132, 76, 9, 84,
        169, 17, 54, 242, 103, 130, 228, 72, 17, 214, 2, 171, 5, 52, 245, 130, 8, 162, 236, 149,
        254, 212, 209, 236, 149, 55, 28, 23, 26, 71, 86, 50, 28, 225, 137, 225, 171, 240, 126, 96,
        216, 216, 126, 189, 192, 223, 6, 223, 8, 72, 155, 254, 217, 217, 189, 126, 170, 156, 39,
        134, 182, 220, 85, 40, 169, 145, 130, 37, 31, 93, 235, 36, 110, 49, 160, 225, 222, 126, 56,
        154, 193, 30, 136, 56, 106, 104, 121, 14, 85, 27, 226, 127, 124, 141, 4, 40, 247, 122, 113,
        13, 169, 154, 221, 163, 118, 182, 61, 111, 117, 53, 6, 45, 74, 15, 99, 224, 139, 162, 197,
        12, 131, 140, 145, 133, 225, 231, 243, 225, 40, 140, 43, 167, 213, 97, 80, 53, 164, 62, 41,
        198, 147, 61, 9, 198, 206, 158, 211, 135, 93, 196, 237, 132, 186, 243, 92, 205, 100, 136,
        75, 85, 67, 219, 14, 181, 20, 127, 57, 70, 32, 178, 179, 169, 85, 88, 49, 132, 57, 226, 38,
        54, 220, 82, 118, 184, 90, 63, 128, 179, 201, 194, 7, 74, 43, 3, 183, 228, 106, 84, 252,
        17, 69, 185, 128, 15, 75, 180, 220, 174, 202, 205, 9, 134, 214, 247, 219, 15, 253, 85, 165,
        213, 66, 151, 113, 39, 221, 155, 180, 98, 216, 136, 148, 223, 14, 208, 195, 142, 154, 63,
        16, 134, 246, 240, 129, 95, 129, 136, 136, 120, 23, 234, 95, 220, 53, 71, 71, 118, 86, 77,
        115, 185, 196, 237, 195, 198, 44, 113, 35, 193, 83, 234, 28, 73, 32, 176, 212, 42, 66, 81,
        102, 137, 201, 187, 90, 207, 101, 112, 1, 201, 191, 78, 15, 49, 39, 4, 234, 227, 64, 110,
        21, 182, 95, 167, 41, 154, 69, 17, 123, 1, 182, 87, 14, 141, 150, 10, 242, 128, 184, 90,
        81, 56, 236, 26, 191, 17, 46, 171, 200, 71, 16, 109, 40, 85, 185, 100, 10, 52, 66, 9, 169,
        164, 125, 112, 24, 141, 12, 135, 254, 165, 77, 22, 139, 4, 169, 186, 98, 57, 176, 56, 130,
        178, 35, 206, 48, 22, 91, 36, 151, 45, 59, 0, 173, 234, 49, 235, 186, 248, 50, 234, 144,
        121, 155, 219, 8, 85, 71, 169, 155, 253, 86, 106, 45, 68, 96, 199, 234, 235, 148, 90, 255,
        59, 120, 181, 142, 175, 219, 46, 117, 73, 114, 173, 13, 21, 30, 138, 208, 129, 30, 1, 245,
        68, 40, 206, 206, 109, 197, 137, 228, 4, 33, 210, 2, 166, 148, 105, 48, 87, 138, 142, 149,
        204, 234, 19, 139, 230, 27, 191, 62, 180, 239, 207, 129, 26, 126, 38, 206, 16, 105, 196,
        35, 22, 17, 105, 224, 56, 214, 198, 57, 175, 38, 222, 17, 147, 10, 125, 45, 1, 49, 95, 15,
        176, 169, 32, 137, 168, 86, 23, 233, 143, 124, 118, 137, 22, 40, 185, 168, 248, 112, 158,
        174, 27, 34, 201, 215, 55, 185, 16, 163, 30, 66, 197, 206, 11, 0, 212, 2, 1, 7, 129, 23,
        88, 94, 46, 63, 206, 133, 144, 23, 233, 60, 147, 42, 190, 222, 253, 210, 129, 110, 5, 33,
        79, 32, 73, 166, 98, 233, 168, 85, 78, 210, 194, 250, 65, 167, 204, 153, 141, 128, 3, 204,
        50, 83, 151, 21, 44, 86, 211, 246, 174, 83, 181, 139, 130, 58, 1, 12, 124, 243, 118, 100,
        41, 90, 230, 50, 196, 48, 92, 166, 227, 102, 91, 25, 101, 167, 68, 75, 129, 140, 98, 177,
        150, 99, 60, 165, 220, 162, 213, 177, 226, 181, 154, 79, 36, 54, 117, 27, 250, 188, 213,
        129, 122, 112, 22, 22, 31, 171, 251, 79, 133, 124, 115, 105, 1, 252, 139, 110, 164, 91, 34,
        148, 208, 211, 121, 135, 121, 42, 129, 182, 102, 45, 205, 121, 149, 57, 102, 208, 249, 255,
        123, 3, 116, 213, 103, 24, 204, 127, 217, 101, 254, 210, 173, 10, 175, 53, 93, 101, 205,
        38, 190, 217, 215, 123, 161, 223, 174, 185, 14, 116, 244, 16, 245, 148, 171, 0, 48, 29, 99,
        166, 159, 16, 96, 216, 250, 39, 235, 236, 76, 91, 57, 84, 201, 233, 97, 10, 122, 125, 46,
        195, 238, 10, 28, 85, 89, 99, 197, 227, 141, 35, 249, 205, 109, 207, 147, 108, 211, 139,
        210, 231, 78, 91, 244, 17, 131, 241, 6, 213, 22, 49, 23, 162, 20, 184, 16, 97, 184, 232,
        52, 57, 183, 78, 20, 101, 88, 245, 250, 28, 163, 10, 105, 63, 124, 113, 233, 74, 37, 203,
        114, 133, 243, 91, 134, 122, 81, 238, 69, 234, 124, 232, 131, 222, 83, 19, 163, 251, 177,
        116, 142, 45, 150, 167, 22, 163, 59, 200, 35, 229, 34, 139, 161, 242, 129, 252, 3, 5, 155,
        19, 241, 178, 73, 181, 61, 36, 148, 148, 18, 6, 151, 117, 169, 79, 10, 222, 47, 214, 31, 6,
        243, 19, 157, 78, 197, 242, 214, 75, 82, 181, 213, 87, 230, 28, 103, 239, 88, 182, 18, 185,
        234, 71, 222, 247, 42, 247, 94, 12, 61, 103, 133, 50, 142, 73, 213, 179, 22, 58, 161, 113,
        213, 35, 150, 26, 251, 176, 145, 189, 76, 81, 136, 118, 134, 153, 3, 199, 0, 71, 105, 80,
        215, 61, 75, 158, 40, 181, 233, 171, 28, 10, 67, 83, 238, 17, 95, 18, 106, 223, 91, 241, 7,
        84, 201, 116, 144, 167, 41, 175, 146, 237, 189, 168, 149, 191, 239, 236, 190, 95, 181, 188,
        188, 196, 48, 76, 61, 63, 155, 113, 140, 104, 73, 97, 7, 3, 148, 26, 60, 168, 23, 159, 190,
        39, 97, 17, 27, 43, 96, 24, 49, 21, 155, 29, 252, 220, 87, 24, 112, 101, 37, 5, 140, 149,
        232, 50, 101, 203, 209, 34, 36, 227, 154, 39, 49, 146, 57, 205, 228, 220, 124, 225, 60,
        162, 144, 13, 8, 78, 195, 142, 61, 0, 118, 24, 123, 72, 143, 70, 53, 146, 175, 231, 106,
        185, 111, 247, 12, 76, 215, 2, 10, 149, 207, 147, 73, 159, 40, 78, 228, 141, 169, 172, 133,
        212, 110, 110, 226, 209, 87, 204, 231, 79, 15, 206, 103, 210, 233, 3, 221, 1, 39, 8, 203,
        50, 192, 53, 166, 183, 138, 140, 190, 76, 176, 24, 99, 217, 82, 216, 185, 186, 25, 153, 42,
        216, 226, 40, 96, 46, 142, 123, 128, 109, 186, 3, 233, 132, 16, 16, 33, 65, 220, 216, 50,
        66, 222, 161, 112, 227, 32, 16, 215, 183, 24, 237, 242, 134, 62, 66, 4, 119, 111, 13, 40,
        231, 172, 101, 103, 105, 94, 184, 140, 160, 20, 0, 113, 253, 181, 214, 245, 117, 171, 86,
        1, 191, 65, 114, 12, 148, 147, 56, 206, 227, 183, 6, 177, 191, 45, 2, 165, 155, 187, 211,
        109, 48, 218, 170, 129, 143, 51, 28, 198, 6, 28, 24, 243, 215, 61, 41, 109, 224, 112, 235,
        190, 41, 136, 130, 101, 220, 27, 118, 23, 219, 98, 224, 42, 193, 56, 212, 113, 110, 178,
        187, 236, 184, 134, 0, 95, 202, 158, 23, 93, 95, 171, 226, 99, 230, 54, 98, 74, 40, 185,
        231, 202, 2, 102, 1, 215, 76, 127, 21, 189, 165, 233, 200, 254, 187, 144, 46, 102, 57, 148,
        89, 104, 24, 117, 182, 77, 224, 243, 12, 216, 155, 153, 8, 3, 142, 233, 80, 28, 41, 64,
        193, 110, 216, 216, 142, 120, 164, 80, 237, 129, 167, 176, 52, 91, 124, 255, 217, 73, 100,
        53, 19, 71, 212, 198, 129, 54, 137, 247, 7, 93, 110, 30, 54, 187, 210, 158, 181, 186, 69,
        142, 25, 197, 193, 250, 54, 53, 15, 69, 237, 66, 28, 195, 107, 192, 183, 153, 202, 103,
        230, 175, 48, 109, 106, 210, 247, 230, 99, 33, 158, 255, 83, 189, 60, 236, 142, 151, 182,
        107, 175, 70, 223, 167, 50, 87, 215, 221, 30, 134, 16, 104, 41, 75, 5, 55, 28, 53, 17, 125,
        134, 91, 101, 75, 153, 83, 142, 124, 246, 101, 232, 217, 8, 70, 202, 195, 20, 67, 49, 4,
        37, 185, 203, 31, 176, 12, 200, 146, 164, 8, 153, 206, 245, 251, 96, 136, 88, 13, 5, 68,
        209, 134, 130, 62, 227, 218, 240, 190, 20, 248, 119, 60, 110, 117, 26, 71, 32, 225, 194,
        241, 25, 121, 147, 241, 154, 28, 78, 20, 16, 17, 67, 181, 152, 47, 129, 182, 132, 30, 91,
        139, 248, 152, 204, 36, 6, 229, 19, 16, 206, 42, 58, 219, 62, 112, 79, 48, 60, 93, 146, 30,
        61, 248, 197, 21, 226, 115, 60, 184, 64, 129, 63, 173, 88, 12, 117, 160, 175, 219, 206, 79,
        88, 2, 17, 201, 132, 52, 68, 94, 51, 226, 168, 205, 150, 43, 19, 156, 129, 124, 38, 220,
        237, 93, 151, 43, 134, 135, 183, 134, 72, 189, 82, 149, 158, 27, 151, 125, 145, 42, 41, 68,
        4, 238, 209, 18, 28, 196, 159, 135, 221, 58, 140, 156, 124, 213, 49, 32, 68, 236, 174, 0,
        166, 181, 1, 193, 211, 182, 2, 60, 116, 38, 100, 240, 27, 126, 74, 156, 89, 185, 44, 138,
        163, 113, 162, 24, 233, 251, 196, 113, 175, 151, 82, 216, 135, 23, 20, 221, 104, 1, 121,
        17, 235, 102, 25, 186, 70, 132, 110, 127, 92, 4, 2, 19, 225, 96, 61, 153, 139, 207, 44,
        183, 45, 16, 78, 196, 177, 84, 223, 179, 107, 46, 121, 114, 54, 43, 236, 99, 178, 251, 132,
        89, 240, 157, 154, 239, 164, 234, 86, 183, 119, 167, 255, 85, 233, 49, 229, 250, 208, 112,
        1, 224, 138, 206, 47, 151, 241, 26, 203, 92, 145, 216, 69, 46, 23, 103, 100, 10, 241, 46,
        233, 96, 33, 185, 12, 111, 239, 3, 198, 194, 90, 123, 3, 146, 138, 207, 59, 252, 93, 72,
        246, 109, 104, 114, 32, 131, 200, 240, 22, 215, 166, 64, 250, 244, 66, 255, 86, 210, 211,
        178, 144, 5, 148, 186, 246, 205, 158, 88, 6, 195, 228, 13, 178, 131, 36, 118, 6, 134, 70,
        218, 214, 168, 134, 16, 148, 113, 191, 146, 157, 181, 156, 179, 233, 43, 230, 235, 0, 210,
        71, 174, 218, 223, 184, 226, 254, 26, 87, 167, 112, 167, 231, 165, 184, 120, 190, 11, 151,
        174, 40, 62, 183, 225, 27, 7, 243, 94, 164, 205, 67, 107, 153, 168, 14, 103, 108, 61, 141,
        63, 138, 29, 18, 122, 234, 225, 17, 252, 10, 38, 219, 249, 129, 21, 37, 149, 152, 76, 11,
        155, 0, 205, 97, 53, 1, 1, 98, 254, 63, 148, 254, 22, 83, 224, 32, 197, 28, 65, 88, 228,
        209, 244, 89, 3, 44, 231, 151, 194, 217, 112, 79, 164, 217, 161, 1, 30, 151, 140, 76, 185,
        18, 217, 2, 237, 89, 243, 243, 134, 106, 213, 82, 2, 143, 237, 209, 145, 85, 51, 194, 209,
        22, 160, 52, 123, 87, 70, 183, 63, 139, 19, 2, 181, 101, 35, 44, 179, 126, 211, 156, 198,
        252, 235, 16, 251, 214, 245, 30, 0, 216, 167, 131, 74, 251, 183, 147, 27, 141, 210, 216,
        64, 52, 8, 156, 69, 60, 25, 105, 218, 210, 73, 94, 50, 82, 125, 248, 143, 154, 185, 149,
        191, 51, 78, 19, 98, 106, 112, 13, 185, 140, 155, 2, 179, 36, 90, 178, 220, 184, 115, 196,
        99, 71, 196, 183, 234, 9, 20, 182, 189, 226, 184, 181, 64, 84, 59, 50, 96, 57, 193, 222,
        75, 157, 78, 55, 245, 139, 108, 113, 157, 63, 193, 179, 111, 60, 40, 72, 99, 25, 196, 25,
        174, 129, 101, 194, 130, 180, 94, 57, 5, 247, 132, 190, 49, 153, 31, 44, 23, 80, 104, 254,
        199, 139, 150, 196, 146, 155, 67, 64, 17, 97, 218, 82, 250, 249, 224, 13, 210, 215, 6, 39,
        173, 60, 129, 12, 79, 148, 124, 21, 57, 48, 130, 26, 209, 152, 114, 119, 135, 21, 239, 253,
        199, 29, 10, 123, 26, 204, 165, 28, 44, 140, 141, 8, 135, 129, 183, 92, 83, 19, 57, 225,
        177, 146, 88, 130, 164, 24, 155, 110, 184, 134, 217, 3, 251, 52, 188, 15, 246, 177, 231,
        227, 40, 90, 132, 24, 191, 65, 101, 23, 37, 44, 223, 196, 188, 57, 55, 170, 144, 230, 175,
        201, 67, 13, 139, 3, 57, 73, 40, 18, 36, 172, 62, 228, 229, 132, 184, 127, 74, 113, 237,
        119, 126, 72, 246, 5, 18, 134, 83, 3, 123, 12, 168, 255, 33, 235, 197, 50, 194, 213, 36,
        112, 141, 21, 34, 17, 115, 93, 185, 69, 22, 3, 12, 112, 119, 221, 193, 154, 205, 47, 197,
        255, 64, 253, 67, 189, 152, 211, 134, 99, 254, 177, 192, 3, 185, 145, 22, 49, 156, 102, 50,
        162, 159, 8, 117, 57, 193, 250, 78, 173, 131, 229, 231, 96, 122, 100, 254, 24, 28, 61, 241,
        219, 209, 173, 177, 123, 104, 89, 14, 129, 193, 109, 110, 126, 164, 49, 76, 68, 255, 214,
        7, 11, 212, 87, 134, 159, 139, 73, 163, 190, 157, 39, 186, 98, 212, 158, 223, 244, 115,
        169, 11, 73, 114, 47, 85, 168, 104, 64, 108, 59, 187, 37, 211, 226, 169, 37, 226, 71, 200,
        221, 121, 105, 222, 126, 98, 254, 189, 7, 50, 16, 178, 124, 86, 141, 153, 132, 109, 202,
        208, 251, 92, 184, 158, 128, 116, 32, 174, 242, 216, 239, 169, 241, 119, 16, 23, 49, 214,
        206, 121, 253, 1, 88, 251, 215, 155, 181, 75, 230, 42, 53, 178, 255, 54, 60, 163, 13, 94,
        13, 1, 4, 56, 219, 254, 77, 103, 187, 245, 141, 80, 17, 25, 58, 47, 188, 211, 157, 192, 21,
        114, 103, 218, 3, 189, 251, 11, 219, 99, 167, 72, 49, 2, 242, 185, 61, 29, 87, 23, 105,
        170, 122, 192, 85, 91, 196, 125, 13, 124, 83, 230, 148, 54, 157, 252, 109, 78, 165, 63, 72,
        149, 229, 223, 229, 255, 34, 0, 153, 248, 11, 1, 94, 71, 241, 249, 61, 128, 20, 37, 145,
        225, 4, 162, 37, 57, 161, 28, 240, 164, 2, 149, 82, 36, 117, 12, 18, 29, 155, 97, 31, 212,
        107, 58, 173, 91, 54, 135, 104, 194, 188, 238, 63, 72, 77, 197, 104, 192, 137, 28, 94, 82,
        102, 133, 43, 179, 194, 155, 107, 120, 54, 157, 89, 146, 31, 34, 38, 163, 10, 94, 164, 204,
        243, 151, 3, 42, 114, 83, 91, 81, 82, 77, 221, 84, 199, 118, 199, 66, 45, 223, 64, 225,
        188, 88, 209, 32, 187, 238, 180, 129, 127, 141, 216, 170, 34, 52, 13, 185, 67, 135, 213,
        193, 11, 150, 134, 207, 63, 82, 46, 182, 30, 68, 17, 1, 115, 90, 164, 24, 187, 119, 106,
        118, 199, 25, 192, 9, 189, 198, 92, 254, 179, 123, 153, 215, 55, 34, 176, 250, 130, 23, 13,
        92, 106, 21, 82, 212, 90, 115, 100, 95, 225, 11, 52, 189, 146, 192, 220, 200, 171, 98, 7,
        61, 101, 11, 235, 157, 87, 12, 11, 12, 35, 244, 174, 242, 157, 49, 216, 133, 92, 242, 243,
        37, 226, 175, 10, 82, 147, 152, 182, 87, 227, 53, 98, 183, 180, 13, 200, 159, 39, 138, 22,
        149, 221, 44, 175, 138, 50, 139, 25, 245, 69, 121, 176, 48, 46, 199, 107, 76, 233, 220,
        118, 152, 78, 140, 175, 247, 223, 151, 203, 108, 74, 17, 155, 39, 158, 151, 109, 7, 251,
        27, 163, 116, 226, 152, 195, 113, 7, 245, 6, 218, 148, 111, 210, 72, 24, 212, 25, 60, 240,
        185, 174, 177, 209, 227, 243, 169, 142, 126, 86, 55, 204, 246, 255, 52, 236, 131, 164, 213,
        185, 108, 124, 148, 26, 222, 123, 100, 174, 128, 48, 91, 82, 250, 198, 219, 25, 204, 44,
        18, 134, 165, 252, 186, 13, 62, 2, 72, 12, 193, 38, 58, 182, 212, 128, 248, 239, 72, 204,
        124, 18, 174, 206, 169, 56, 243, 227, 152, 182, 187, 237, 240, 153, 58, 195, 57, 197, 72,
        74, 95, 242, 190, 236, 245, 154, 36, 16, 123, 223, 88, 125, 158, 249, 56, 6, 59, 160, 245,
        63, 15, 35, 195, 219, 93, 245, 81, 167, 221, 165, 73, 179, 218, 89, 155, 219, 15, 220, 129,
        97, 25, 95, 187, 13, 167, 169, 81, 48, 150, 37, 56, 254, 49, 145, 96, 180, 12, 23, 101,
        186, 130, 229, 98, 23, 193, 246, 29, 247, 19, 219, 225, 192, 11, 15, 218, 46, 43, 69, 75,
        121, 82, 162, 42, 226, 209, 50, 157, 212, 223, 4, 63, 168, 186, 124, 107, 139, 199, 105,
        56, 156, 136, 55, 237, 63, 229, 252, 194, 63, 116, 100, 228, 9, 25, 56, 93, 201, 252, 4,
        192, 255, 204, 168, 197, 221, 223, 85, 154, 224, 77, 66, 46, 255, 25, 41, 122, 227, 233,
        97, 167, 221, 183, 117, 144, 95, 101, 61, 108, 65, 100, 213, 68, 108, 199, 47, 135, 83,
        121, 242, 13, 18, 60, 201, 39, 102, 50, 40, 80, 195, 157, 77, 71, 112, 3, 208, 205, 140,
        101, 227, 197, 29, 197, 30, 69, 88, 171, 103, 61, 141, 173, 31, 17, 197, 185, 201, 208,
        232, 55, 119, 6, 194, 77, 181, 101, 162, 96, 105, 35, 22, 161, 68, 25, 9, 7, 162, 58, 20,
        85, 168, 135, 200, 52, 28, 97, 14, 36, 145, 180, 74, 113, 66, 25, 55, 80, 184, 8, 65, 90,
        138, 2, 52, 78, 144, 122, 36, 193, 41, 11, 61, 96, 207, 79, 133, 154, 81, 38, 4, 82, 88,
        227, 62, 17, 127, 41, 33, 108, 146, 89, 246, 255, 228, 200, 234, 234, 111, 192, 152, 177,
        212, 168, 72, 193, 249, 189, 0, 168, 56, 138, 103, 83, 14, 188, 60, 176, 105, 34, 202, 38,
        196, 19, 139, 42, 214, 76, 1, 24, 77, 192, 14, 31, 70, 138, 206, 201, 242, 107, 180, 194,
        171, 39, 226, 141, 182, 40, 49, 108, 27, 240, 46, 85, 95, 199, 28, 241, 249, 220, 149, 48,
        102, 124, 120, 14, 82, 252, 151, 135, 5, 21, 155, 139, 217, 11, 12, 35, 39, 227, 70, 190,
        59, 127, 139, 164, 93, 63, 69, 32, 11, 192, 10, 46, 243, 143, 71, 240, 184, 118, 254, 157,
        230, 51, 40, 114, 150, 140, 156, 150, 176, 244, 254, 248, 92, 139, 46, 135, 89, 126, 8,
        230, 130, 239, 13, 139, 163, 249, 178, 70, 50, 226, 222, 35, 41, 139, 24, 200, 103, 247,
        141, 151, 197, 184, 247, 8, 230, 105, 109, 49, 129, 159, 118, 240, 199, 1, 218, 65, 142,
        162, 0, 18, 217, 187, 5, 4, 5, 74, 201, 211, 224, 22, 24, 238, 242, 176, 126, 205, 31, 96,
        245, 221, 134, 222, 89, 76, 91, 211, 113, 125, 178, 178, 189, 206, 168, 74, 241, 204, 155,
        198, 237, 176, 27, 244, 33, 20, 208, 87, 78, 205, 191, 146, 150, 252, 222, 44, 41, 13, 207,
        167, 24, 213, 250, 197, 184, 96, 199, 94, 119, 134, 189, 92, 97, 220, 240, 206, 125, 213,
        50, 223, 17, 190, 202, 34, 147, 223, 28, 62, 213, 101, 45, 25, 64, 137, 245, 166, 206, 79,
        248, 122, 221, 203, 2, 10, 157, 11, 200, 183, 11, 135, 185, 124, 17, 84, 2, 136, 125, 165,
        195, 8, 49, 201, 87, 114, 61, 230, 36, 170, 8, 29, 190, 99, 230, 120, 210, 161, 195, 251,
        246, 85, 84, 171, 251, 168, 210, 152, 101, 225, 23, 154, 1, 161, 83, 142, 212, 138, 18, 13,
        85, 72, 36, 52, 0, 59, 19, 122, 45, 48, 120, 35, 143, 42, 83, 136, 15, 134, 213, 95, 97,
        54, 24, 14, 237, 249, 106, 28, 116, 241, 203, 195, 181, 162, 143, 200, 120, 148, 104, 191,
        115, 119, 147, 217, 69, 24, 5, 221, 106, 109, 135, 234, 123, 189, 199, 91, 64, 214, 193,
        72, 192, 116, 29, 39, 254, 24, 70, 15, 158, 223, 57, 136, 51, 187, 161, 62, 233, 3, 244,
        244, 120, 59, 115, 42, 25, 155, 129, 16, 238, 226, 185, 60, 87, 110, 18, 47, 227, 68, 86,
        189, 157, 156, 245, 144, 71, 210, 42, 140, 139, 115, 69, 112, 105, 95, 52, 243, 241, 23,
        191, 90, 241, 186, 178, 2, 251, 166, 85, 118, 113, 93, 113, 4, 82, 103, 204, 108, 150, 154,
        108, 171, 171, 228, 2, 255, 115, 255, 114, 39, 173, 116, 119, 184, 239, 91, 121, 156, 130,
        146, 117, 137, 237, 8, 254, 219, 138, 27, 40, 205, 235, 234, 28, 97, 245, 121, 153, 35, 63,
        240, 165, 214, 67, 18, 143, 246, 237, 199, 237, 205, 156, 175, 13, 63, 86, 174, 164, 55, 0,
        187, 14, 140, 1, 157, 163, 151, 247, 141, 244, 93, 96, 153, 231, 228, 67, 93, 208, 173,
        224, 96, 91, 165, 154, 7, 188, 51, 213, 35, 229, 62, 218, 163, 205, 60, 234, 64, 3, 130,
        141, 233, 16, 90, 252, 102, 9, 238, 11, 89, 74, 166, 152, 62, 75, 5, 199, 138, 140, 241,
        245, 28, 147, 173, 134, 42, 82, 245, 205, 147, 103, 249, 97, 168, 227, 200, 106, 21, 193,
        222, 20, 179, 253, 113, 253, 219, 155, 54, 3, 240, 14, 14, 255, 230, 186, 60, 221, 8, 157,
        37, 220, 245, 117, 152, 25, 245, 234, 158, 142, 223, 172, 172, 93, 106, 145, 236, 240, 143,
        126, 164, 115, 16, 206, 37, 46, 11, 142, 29, 198, 237, 72, 148, 15, 88, 120, 156, 227, 118,
        12, 189, 147, 3, 8, 207, 187, 180, 187, 109, 10, 160, 174, 94, 97, 31, 23, 117, 53, 148, 7,
        91, 129, 29, 90, 144, 218, 74, 119, 161, 117, 87, 218, 167, 35, 221, 10, 81, 202, 237, 207,
        130, 64, 59, 203, 22, 72, 228, 13, 155, 171, 1, 155, 116, 15, 225, 138, 240, 49, 220, 137,
        176, 33, 167, 99, 249, 224, 144, 172, 43, 33, 196, 219, 76, 150, 117, 39, 85, 178, 89, 79,
        184, 238, 98, 162, 158, 18, 124, 78, 84, 54, 5, 156, 255, 130, 175, 24, 50, 112, 248, 82,
        216, 160, 241, 142, 96, 132, 227, 69, 41, 117, 4, 125, 244, 138, 213, 23, 129, 78, 159, 42,
        15, 179, 59, 140, 53, 110, 168, 70, 5, 57, 105, 165, 92, 231, 184, 203, 157, 130, 221, 92,
        238, 64, 252, 3, 217, 12, 243, 89, 38, 248, 216, 30, 230, 194, 92, 3, 171, 54, 87, 183,
        108, 223, 130, 231, 86, 22, 86, 65, 213, 149, 142, 143, 237, 98, 219, 129, 224, 186, 103,
        247, 255, 88, 234, 43, 128, 178, 77, 169, 125, 231, 20, 8, 135, 84, 92, 181, 124, 248, 134,
        166, 246, 246, 77, 193, 245, 251, 3, 153, 132, 230, 247, 78, 236, 37, 206, 201, 36, 198,
        47, 118, 18, 201, 64, 24, 53, 239, 149, 239, 190, 58, 176, 101, 6, 124, 203, 116, 12, 110,
        29, 20, 219, 246, 73, 31, 185, 158, 117, 227, 227, 74, 222, 94, 1, 88, 82, 25, 27, 116,
        237, 238, 76, 25, 37, 59, 142, 84, 165, 28, 144, 39, 62, 73, 6, 253, 47, 193, 129, 59, 138,
        119, 223, 37, 171, 0, 55, 180, 212, 2, 75, 214, 102, 67, 172, 59, 214, 162, 81, 122, 107,
        163, 103, 213, 89, 59, 118, 182, 36, 176, 49, 162, 0, 5, 19, 169, 190, 11, 183, 37, 205, 0,
        239, 20, 189, 22, 31, 54, 251, 95, 193, 200, 123, 142, 29, 223, 190, 0, 158, 149, 234, 242,
        182, 79, 121, 67, 67, 131, 146, 192, 5, 239, 191, 7, 187, 183, 248, 109, 120, 30, 226, 46,
        27, 220, 121, 199, 167, 111, 31, 81, 220, 222, 147, 147, 104, 128, 42, 239, 158, 134, 56,
        141, 49, 200, 94, 19, 159, 129, 44, 6, 140, 250, 115, 151, 31, 200, 136, 172, 10, 247, 158,
        27, 83, 110, 73, 206, 1, 19, 170, 145, 36, 43, 157, 134, 237, 30, 35, 73, 13, 214, 216,
        128, 127, 57, 196, 24, 104, 185, 94, 190, 136, 60, 41, 16, 75, 21, 19, 89, 80, 253, 63,
        182, 128, 83, 61, 203, 45, 192, 243, 12, 61, 186, 34, 106, 185, 129, 195, 125, 176, 52,
        101, 158, 112, 132, 210, 119, 166, 199, 202, 175, 66, 59, 232, 52, 125, 22, 183, 139, 77,
        197, 217, 9, 128, 98, 211, 85, 221, 197, 171, 196, 193, 130, 171, 179, 91, 83, 7, 67, 155,
        180, 23, 132, 179, 63, 7, 147, 32, 2, 244, 86, 22, 43, 170, 111, 13, 87, 50, 42, 197, 108,
        246, 89, 247, 143, 210, 13, 134, 128, 39, 12, 141, 21, 102, 66, 50, 242, 227, 45, 237, 88,
        110, 138, 200, 88, 154, 166, 29, 217, 32, 46, 96, 90, 191, 251, 154, 111, 83, 149, 81, 111,
        204, 249, 202, 5, 146, 5, 155, 252, 87, 176, 138, 143, 172, 65, 188, 156, 221, 24, 150,
        166, 203, 69, 135, 120, 131, 164, 106, 201, 30, 20, 254, 173, 33, 92, 30, 16, 116, 245,
        241, 97, 199, 160, 116, 25, 183, 139, 67, 182, 65, 42, 195, 57, 9, 154, 71, 235, 214, 250,
        160, 187, 193, 44, 27, 199, 101, 15, 172, 171, 159, 203, 192, 199, 89, 99, 240, 210, 58,
        67, 32, 172, 42, 92, 234, 97, 24, 148, 54, 24, 253, 81, 198, 255, 130, 114, 48, 149, 246,
        240, 134, 148, 48, 4, 115, 229, 46, 168, 229, 127, 81, 221, 128, 79, 118, 21, 142, 183, 22,
        76, 90, 133, 174, 249, 197, 115, 36, 103, 116, 228, 98, 86, 241, 82, 107, 66, 33, 166, 110,
        74, 95, 119, 123, 245, 71, 134, 162, 205, 78, 214, 39, 183, 196, 160, 40, 105, 153, 134,
        88, 212, 171, 213, 23, 13, 65, 48, 130, 200, 143, 71, 198, 110, 215, 47, 128, 55, 184, 200,
        207, 63, 178, 124, 253, 106, 21, 255, 21, 72, 255, 48, 153, 48, 201, 31, 7, 165, 19, 102,
        0, 226, 140, 201, 206, 231, 157, 198, 230, 223, 195, 160, 140, 4, 225, 125, 224, 182, 195,
        227, 210, 237, 78, 154, 185, 217, 123, 224, 190, 100, 16, 213, 198, 176, 250, 101, 40, 234,
        112, 3, 211, 7, 254, 140, 108, 38, 243, 143, 32, 191, 161, 79, 79, 149, 1, 56, 240, 21, 65,
        75, 41, 9, 107, 93, 218, 240, 151, 32, 41, 213, 203, 17, 163, 144, 136, 145, 85, 18, 217,
        183, 107, 135, 215, 178, 23, 138, 140, 223, 129, 31, 191, 10, 8, 205, 117, 208, 162, 9,
        169, 17, 164, 212, 18, 168, 252, 240, 135, 237, 157, 18, 103, 116, 208, 117, 79, 127, 123,
        108, 149, 185, 62, 193, 194, 85, 14, 87, 109, 223, 115, 26, 112, 20, 199, 242, 85, 197,
        228, 84, 229, 58, 220, 50, 62, 232, 235, 97, 156, 247, 191, 163, 34, 195, 193, 199, 84, 54,
        122, 9, 252, 141, 156, 40, 105, 67, 63, 238, 220, 242, 16, 226, 114, 211, 193, 103, 96, 41,
        248, 68, 16, 173, 11, 15, 63, 204, 91, 145, 35, 55, 254, 204, 10, 155, 154, 136, 29, 9, 21,
        58, 130, 38, 44, 114, 49, 210, 30, 15, 98, 60, 98, 142, 237, 126, 165, 74, 132, 115, 222,
        195, 76, 32, 93, 63, 56, 221, 78, 229, 190, 64, 31, 205, 75, 156, 96, 194, 238, 34, 38,
        139, 51, 176, 67, 31, 159, 18, 62, 159, 111, 112, 41, 255, 47, 30, 30, 21, 251, 195, 255,
        157, 39, 239, 41, 81, 246, 107, 117, 17, 193, 232, 169, 121, 100, 223, 151, 82, 15, 231,
        65, 11, 56, 117, 137, 23, 219, 233, 217, 49, 190, 119, 184, 43, 146, 230, 152, 78, 35, 36,
        25, 147, 222, 48, 235, 12, 61, 199, 96, 46, 65, 154, 39, 163, 199, 170, 85, 69, 12, 71,
        155, 240, 117, 69, 51, 67, 120, 48, 117, 201, 1, 52, 145, 78, 32, 34, 125, 219, 49, 119,
        142, 23, 137, 214, 252, 103, 71, 36, 28, 213, 242, 20, 3, 18, 9, 238, 226, 225, 157, 245,
        216, 89, 156, 159, 112, 163, 141, 60, 113, 252, 84, 28, 25, 32, 232, 22, 35, 206, 158, 101,
        11, 43, 226, 211, 93, 14, 165, 180, 46, 201, 154, 247, 165, 97, 71, 34, 245, 115, 76, 43,
        145, 23, 46, 95, 61, 139, 246, 139, 190, 79, 20, 249, 226, 114, 33, 193, 151, 126, 228, 28,
        224, 195, 189, 212, 117, 134, 175, 75, 123, 85, 69, 211, 200, 216, 73, 139, 80, 165, 177,
        116, 87, 33, 124, 19, 102, 33, 137, 154, 223, 5, 179, 81, 56, 155, 190, 74, 75, 154, 42,
        119, 191, 169, 153, 106, 13, 125, 129, 73, 38, 94, 192, 246, 165, 103, 169, 188, 235, 67,
        29, 65, 249, 160, 35, 75, 18, 244, 141, 82, 125, 77, 41, 154, 215, 44, 156, 67, 131, 4, 67,
        195, 120, 0, 235, 59, 171, 3, 238, 116, 83, 17, 31, 54, 252, 131, 168, 201, 238, 14, 252,
        119, 94, 147, 2, 68, 217, 38, 244, 218, 65, 90, 169, 136, 67, 238, 147, 196, 17, 41, 70,
        234, 76, 252, 63, 173, 66, 1, 106, 233, 68, 231, 89, 14, 253, 150, 71, 102, 61, 90, 2, 103,
        198, 78, 190, 114, 16, 57, 99, 115, 189, 17, 41, 215, 136, 115, 223, 66, 166, 139, 34, 1,
        86, 3, 160, 20, 133, 127, 132, 188, 183, 196, 23, 166, 255, 17, 90, 210, 255, 87, 46, 233,
        18, 3, 76, 74, 186, 216, 80, 123, 192, 163, 53, 118, 27, 71, 67, 140, 172, 34, 49, 27, 134,
        19, 27, 29, 149, 130, 58, 157, 227, 247, 136, 15, 16, 22, 204, 26, 211, 116, 39, 227, 31,
        3, 171, 99, 88, 45, 233, 53, 70, 198, 110, 15, 183, 129, 176, 90, 71, 184, 102, 176, 248,
        243, 99, 80, 0, 177, 189, 211, 215, 234, 196, 111, 180, 255, 149, 103, 178, 209, 5, 95, 13,
        238, 254, 175, 103, 77, 51, 104, 247, 22, 214, 109, 109, 86, 0, 52, 51, 165, 79, 30, 185,
        107, 161, 184, 111, 110, 114, 202, 195, 39, 121, 167, 191, 98, 35, 93, 65, 120, 57, 31,
        224, 120, 217, 125, 120, 198, 194, 57, 242, 42, 168, 47, 25, 94, 28, 190, 178, 3, 138, 125,
        163, 95, 149, 122, 143, 195, 112, 188, 37, 219, 115, 119, 229, 110, 164, 114, 202, 214, 54,
        19, 37, 173, 170, 73, 75, 229, 78, 255, 209, 81, 65, 169, 122, 248, 253, 55, 1, 137, 4,
        250, 238, 89, 93, 255, 224, 10, 116, 162, 44, 162, 97, 177, 59, 63, 179, 197, 227, 150,
        150, 83, 74, 124, 46, 192, 211, 254, 144, 191, 114, 95, 50, 92, 197, 13, 171, 104, 155,
        140, 184, 6, 141, 60, 52, 124, 101, 24, 182, 168, 4, 233, 84, 52, 105, 10, 63, 161, 114,
        13, 247, 81, 168, 181, 56, 252, 181, 208, 64, 5, 13, 87, 228, 140, 20, 35, 98, 37, 54, 214,
        242, 95, 48, 202, 129, 194, 227, 25, 64, 1, 182, 62, 71, 1, 27, 125, 97, 21, 229, 105, 44,
        9, 1, 5, 154, 26, 193, 61, 176, 214, 203, 85, 199, 181, 220, 137, 16, 168, 176, 12, 65, 16,
        114, 61, 110, 219, 75, 0, 139, 221, 119, 73, 249, 96, 108, 19, 235, 104, 74, 78, 160, 12,
        124, 63, 159, 105, 27, 225, 7, 113, 36, 24, 72, 61, 75, 49, 192, 237, 231, 203, 78, 45,
        221, 171, 170, 12, 91, 27, 126, 142, 232, 219, 69, 170, 46, 215, 45, 50, 4, 90, 141, 155,
        14, 140, 20, 221, 43, 141, 80, 224, 201, 151, 141, 44, 230, 17, 238, 49, 78, 11, 185, 163,
        93, 73, 145, 150, 86, 229, 150, 135, 202, 79, 120, 220, 252, 213, 67, 224, 212, 138, 45,
        146, 209, 200, 188, 130, 108, 3, 243, 242, 253, 196, 64, 55, 33, 76, 118, 114, 212, 144,
        222, 194, 0, 125, 76, 34, 130, 4, 126, 220, 248, 48, 223, 103, 28, 31, 253, 15, 13, 223,
        255, 177, 177, 15, 162, 132, 240, 251, 222, 50, 80, 217, 151, 250, 148, 236, 28, 106, 47,
        219, 191, 240, 16, 192, 55, 37, 168, 186, 21, 28, 244, 136, 85, 143, 80, 0, 30, 98, 5, 245,
        166, 49, 20, 197, 208, 151, 203, 183, 110, 193, 185, 234, 147, 2, 199, 75, 246, 12, 255,
        14, 189, 199, 194, 65, 207, 197, 42, 83, 170, 170, 28, 101, 239, 139, 64, 129, 5, 155, 61,
        200, 220, 99, 81, 14, 250, 244, 86, 102, 106, 127, 245, 86, 226, 95, 4, 155, 4, 84, 155,
        213, 88, 127, 21, 51, 10, 111, 155, 57, 235, 82, 32, 57, 179, 254, 119, 194, 123, 92, 33,
        232, 159, 7, 97, 166, 163, 66, 33, 195, 110, 188, 102, 1, 5, 127, 191, 197, 218, 9, 96, 23,
        192, 150, 68, 204, 164, 208, 27, 93, 44, 193, 0, 175, 122, 181, 153, 27, 12, 136, 135, 170,
        31, 120, 145, 103, 160, 85, 74, 8, 65, 236, 88, 31, 36, 179, 151, 187, 135, 244, 62, 11,
        80, 186, 4, 232, 178, 162, 204, 181, 216, 89, 29, 51, 42, 159, 29, 138, 94, 113, 245, 159,
        43, 23, 11, 78, 121, 15, 33, 187, 145, 46, 66, 54, 47, 45, 64, 252, 74, 26, 214, 222, 236,
        131, 134, 163, 60, 242, 66, 15, 7, 122, 47, 73, 190, 6, 103, 91, 164, 145, 54, 165, 8, 147,
        46, 190, 114, 97, 19, 132, 151, 83, 49, 93, 4, 11, 188, 224, 196, 178, 192, 29, 183, 59,
        141, 124, 68, 241, 142, 148, 246, 11, 83, 230, 190, 98, 133, 22, 0, 171, 131, 34, 4, 70,
        230, 19, 169, 45, 33, 159, 36, 154, 223, 210, 82, 18, 229, 44, 246, 168, 199, 59, 68, 26,
        105, 13, 233, 250, 0, 24, 69, 117, 222, 148, 3, 183, 55, 99, 150, 215, 56, 120, 184, 223,
        135, 15, 242, 208, 219, 147, 196, 211, 206, 207, 190, 36, 81, 212, 219, 254, 11, 220, 28,
        118, 37, 166, 217, 193, 254, 159, 29, 234, 6, 243, 67, 163, 85, 211, 81, 151, 97, 95, 1, 1,
        236, 96, 190, 77, 238, 254, 16, 104, 64, 2, 150, 240, 205, 231, 212, 203, 192, 181, 141,
        84, 223, 67, 236, 234, 188, 40, 46, 60, 67, 95, 202, 130, 206, 151, 66, 45, 251, 196, 105,
        44, 17, 201, 208, 29, 10, 183, 36, 123, 212, 241, 211, 187, 53, 83, 224, 81, 185, 11, 184,
        50, 51, 105, 42, 187, 4, 29, 14, 233, 197, 83, 11, 186, 19, 196, 44, 237, 115, 205, 14, 46,
        76, 130, 88, 91, 105, 34, 62, 111, 35, 10, 167, 146, 158, 108, 224, 254, 79, 215, 143, 1,
        57, 76, 121, 115, 210, 2, 111, 36, 148, 182, 156, 9, 80, 184, 44, 78, 117, 107, 153, 22,
        237, 73, 139, 215, 65, 235, 71, 16, 61, 3, 229, 43, 57, 56, 119, 25, 92, 163, 118, 111, 54,
        149, 137, 193, 166, 67, 112, 108, 215, 161, 120, 101, 2, 18, 167, 107, 151, 162, 90, 18,
        80, 96, 166, 157, 167, 182, 50, 234, 44, 117, 82, 144, 150, 207, 171, 15, 74, 107, 13, 240,
        198, 28, 27, 148, 255, 51, 208, 178, 112, 90, 113, 62, 77, 150, 74, 208, 83, 92, 207, 207,
        78, 22, 184, 92, 195, 9, 9, 19, 153, 217, 10, 0, 8, 166, 24, 234, 224, 14, 179, 2, 136, 59,
        181, 97, 56, 131, 207, 228, 196, 83, 200, 168, 168, 231, 14, 253, 8, 8, 23, 74, 55, 129,
        130, 172, 176, 105, 29, 145, 134, 0, 87, 201, 6, 27, 227, 202, 133, 215, 186, 54, 126, 35,
        113, 187, 14, 206, 2, 146, 31, 115, 52, 255, 243, 220, 193, 71, 79, 228, 181, 63, 56, 217,
        31, 119, 10, 133, 111, 213, 117, 231, 9, 8, 32, 14, 31, 185, 253, 25, 243, 112, 50, 78, 49,
        190, 44, 30, 64, 34, 164, 231, 240, 18, 29, 113, 146, 60, 204, 219, 176, 168, 19, 189, 208,
        44, 201, 193, 109, 121, 87, 184, 244, 18, 32, 215, 161, 183, 83, 40, 68, 120, 219, 20, 4,
        27, 130, 10, 153, 143, 105, 69, 131, 18, 0, 72, 74, 44, 41, 227, 194, 197, 62, 117, 12, 63,
        51, 199, 67, 71, 207, 90, 225, 127, 176, 142, 213, 242, 0, 98, 163, 219, 28, 26, 73, 255,
        93, 195, 207, 126, 180, 212, 10, 158, 162, 17, 12, 126, 187, 210, 35, 198, 77, 148, 137, 1,
        173, 1, 181, 119, 77, 230, 201, 252, 22, 222, 72, 100, 114, 55, 31, 231, 190, 153, 185, 69,
        170, 142, 154, 112, 22, 165, 34, 151, 144, 169, 31, 251, 163, 105, 97, 73, 143, 2, 111,
        236, 68, 14, 204, 34, 190, 230, 218, 229, 226, 184, 23, 200, 231, 47, 252, 26, 216, 230,
        79, 94, 53, 79, 43, 26, 91, 18, 155, 163, 118, 36, 17, 95, 3, 148, 196, 47, 194, 218, 29,
        164, 236, 248, 61, 49, 171, 19, 76, 246, 243, 184, 29, 195, 64, 67, 36, 207, 102, 169, 105,
        130, 221, 178, 246, 251, 177, 45, 67, 26, 52, 107, 240, 171, 1, 112, 190, 240, 131, 249,
        162, 189, 81, 208, 89, 20, 121, 173, 6, 215, 190, 137, 223, 160, 115, 15, 226, 6, 28, 78,
        13, 189, 98, 35, 124, 0, 129, 66, 36, 203, 195, 99, 171, 65, 84, 19, 90, 144, 15, 134, 85,
        17, 161, 246, 136, 44, 15, 170, 155, 110, 165, 85, 6, 41, 39, 213, 88, 243, 174, 183, 106,
        83, 85, 11, 184, 72, 57, 163, 31, 195, 30, 239, 160, 211, 249, 221, 89, 69, 19, 137, 135,
        32, 183, 35, 230, 4, 148, 111, 116, 154, 216, 107, 84, 118, 165, 196, 208, 199, 137, 123,
        166, 125, 228, 244, 69, 154, 219, 235, 41, 32, 248, 21, 136, 190, 197, 4, 224, 86, 39, 179,
        196, 63, 54, 26, 100, 19, 109, 102, 202, 50, 41, 208, 38, 201, 86, 201, 129, 77, 160, 200,
        105, 59, 37, 243, 75, 73, 144, 118, 177, 166, 24, 144, 186, 113, 230, 40, 74, 218, 25, 6,
        148, 39, 77, 196, 160, 236, 172, 229, 8, 75, 12, 112, 74, 117, 109, 82, 166, 50, 134, 204,
        40, 1, 234, 236, 110, 5, 9, 30, 169, 38, 103, 100, 8, 175, 11, 204, 112, 111, 197, 18, 214,
        191, 144, 208, 24, 233, 52, 22, 186, 74, 184, 235, 146, 140, 198, 66, 177, 251, 165, 107,
        239, 124, 201, 217, 43, 18, 103, 208, 35, 68, 171, 82, 53, 24, 93, 246, 191, 162, 197, 113,
        94, 244, 86, 112, 169, 192, 128, 233, 1, 99, 246, 30, 227, 244, 45, 22, 82, 30, 3, 126, 51,
        134, 202, 140, 104, 108, 212, 119, 231, 25, 158, 74, 188, 54, 188, 239, 128, 64, 182, 232,
        25, 116, 165, 38, 205, 213, 161, 58, 251, 199, 86, 88, 245, 247, 177, 60, 36, 142, 244,
        199, 237, 33, 73, 18, 13, 45, 119, 101, 103, 36, 89, 207, 203, 70, 97, 202, 139, 4, 167,
        205, 46, 181, 174, 199, 116, 169, 85, 53, 87, 121, 51, 130, 43, 63, 166, 242, 33, 62, 177,
        83, 73, 151, 14, 149, 138, 245, 14, 111, 57, 71, 220, 16, 127, 218, 143, 9, 20, 120, 183,
        64, 211, 159, 201, 4, 60, 89, 234, 232, 134, 199, 103, 252, 76, 181, 96, 33, 167, 69, 94,
        143, 251, 107, 156, 250, 198, 181, 217, 75, 196, 155, 22, 151, 16, 249, 8, 15, 18, 230, 61,
        20, 118, 223, 126, 58, 167, 249, 148, 85, 70, 39, 164, 229, 84, 220, 160, 28, 118, 120, 17,
        190, 198, 64, 33, 125, 214, 174, 179, 205, 16, 105, 69, 106, 83, 53, 102, 171, 153, 47, 51,
        246, 40, 183, 35, 148, 195, 132, 182, 14, 110, 74, 110, 185, 233, 47, 166, 221, 167, 47,
        109, 38, 25, 172, 179, 239, 161, 170, 51, 59, 6, 145, 215, 50, 153, 82, 8, 199, 247, 235,
        86, 55, 104, 79, 193, 255, 52, 52, 155, 37, 223, 156, 90, 118, 19, 9, 151, 4, 18, 27, 56,
        117, 126, 103, 126, 67, 100, 35, 90, 140, 200, 213, 21, 12, 61, 223, 104, 12, 71, 123, 248,
        191, 0, 112, 30, 22, 26, 156, 95, 180, 21, 0, 49, 189, 58, 19, 134, 55, 218, 32, 172, 174,
        94, 82, 196, 21, 80, 30, 225, 117, 97, 1, 68, 20, 176, 242, 232, 219, 213, 98, 60, 190, 31,
        5, 202, 116, 212, 1, 170, 196, 38, 52, 19, 90, 14, 6, 34, 58, 76, 125, 76, 99, 112, 77,
        217, 22, 246, 90, 218, 111, 101, 192, 169, 13, 142, 116, 117, 237, 6, 16, 167, 1, 251, 26,
        131, 223, 155, 203, 171, 139, 171, 191, 201, 64, 79, 147, 219, 184, 91, 234, 174, 80, 97,
        166, 214, 219, 237, 13, 111, 225, 132, 69, 139, 228, 125, 222, 176, 124, 83, 161, 150, 1,
        67, 44, 174, 142, 84, 205, 168, 82, 251, 20, 79, 64, 141, 119, 94, 52, 234, 123, 27, 125,
        226, 156, 68, 127, 227, 82, 125, 16, 12, 16, 81, 85, 202, 148, 3, 153, 12, 57, 145, 220,
        131, 14, 24, 147, 16, 241, 173, 6, 149, 181, 129, 75, 189, 183, 101, 178, 41, 103, 33, 27,
        21, 23, 3, 29, 141, 106, 3, 212, 222, 163, 140, 122, 193, 156, 237, 228, 161, 119, 6, 62,
        162, 12, 213, 167, 178, 183, 44, 134, 121, 24, 210, 77, 8, 143, 40, 1, 155, 25, 111, 27,
        59, 155, 152, 19, 235, 253, 121, 123, 209, 243, 249, 3, 34, 157, 193, 82, 245, 236, 174,
        81, 117, 207, 74, 235, 93, 184, 70, 116, 120, 212, 118, 140, 192, 106, 102, 172, 26, 198,
        41, 92, 231, 249, 230, 8, 135, 81, 219, 114, 218, 100, 81, 108, 91, 156, 46, 119, 231, 114,
        158, 20, 145, 95, 229, 129, 70, 207, 158, 41, 12, 175, 190, 217, 225, 29, 12, 46, 23, 77,
        162, 200, 146, 197, 61, 235, 196, 218, 203, 231, 220, 214, 152, 5, 117, 196, 22, 9, 213,
        210, 251, 156, 115, 53, 83, 243, 169, 126, 233, 225, 191, 184, 182, 228, 50, 101, 209, 93,
        15, 111, 176, 79, 226, 139, 7, 52, 47, 19, 214, 176, 243, 133, 72, 239, 214, 118, 40, 52,
        6, 75, 47, 13, 152, 230, 76, 220, 134, 229, 235, 114, 162, 185, 146, 226, 141, 99, 217, 98,
        42, 231, 67, 215, 225, 60, 19, 186, 125, 64, 94, 11, 185, 70, 171, 217, 45, 143, 115, 46,
        172, 159, 157, 87, 142, 114, 104, 157, 97, 224, 72, 20, 119, 191, 209, 9, 43, 136, 247,
        206, 177, 250, 19, 86, 59, 23, 191, 69, 21, 143, 11, 119, 87, 234, 48, 30, 140, 214, 102,
        48, 112, 192, 11, 99, 18, 165, 2, 54, 130, 140, 70, 9, 209, 230, 206, 213, 221, 218, 79,
        21, 216, 110, 229, 211, 110, 54, 112, 206, 81, 37, 199, 28, 23, 148, 239, 15, 130, 131,
        180, 129, 176, 84, 233, 47, 113, 229, 161, 131, 128, 16, 141, 177, 176, 10, 245, 20, 226,
        88, 214, 100, 230, 170, 74, 172, 67, 134, 179, 14, 42, 69, 130, 12, 246, 143, 222, 236,
        210, 137, 179, 211, 42, 210, 199, 141, 182, 172, 181, 97, 99, 173, 40, 194, 78, 7, 130,
        227, 199, 31, 30, 32, 27, 68, 221, 251, 26, 200, 219, 120, 98, 205, 239, 95, 68, 131, 139,
        14, 208, 76, 217, 59, 162, 100, 98, 201, 53, 83, 247, 197, 140, 226, 69, 191, 163, 109, 19,
        58, 93, 125, 15, 226, 120, 237, 130, 92, 184, 208, 120, 70, 86, 154, 54, 63, 222, 255, 13,
        6, 51, 5, 238, 33, 20, 91, 121, 5, 158, 114, 130, 70, 5, 100, 98, 248, 130, 74, 104, 96,
        119, 12, 249, 236, 186, 147, 233, 177, 176, 16, 235, 208, 249, 142, 93, 13, 70, 204, 249,
        80, 39, 95, 107, 21, 65, 228, 70, 108, 8, 122, 195, 188, 214, 255, 225, 10, 89, 162, 227,
        83, 161, 71, 80, 165, 76, 173, 49, 107, 145, 11, 54, 79, 30, 119, 94, 71, 180, 89, 116,
        103, 125, 116, 210, 56, 240, 103, 127, 161, 183, 24, 39, 214, 87, 161, 183, 70, 10, 253,
        127, 226, 68, 204, 234, 0, 241, 70, 187, 238, 236, 193, 149, 45, 227, 6, 44, 50, 56, 190,
        124, 86, 223, 176, 239, 233, 154, 176, 226, 86, 240, 159, 196, 219, 64, 105, 219, 57, 116,
        53, 76, 156, 135, 110, 44, 206, 163, 140, 221, 131, 214, 71, 19, 16, 72, 120, 245, 241, 20,
        97, 165, 33, 252, 119, 133, 229, 18, 18, 219, 61, 134, 41, 211, 103, 111, 209, 179, 168,
        66, 223, 93, 115, 12, 168, 41, 113, 112, 249, 184, 72, 202, 140, 129, 84, 22, 181, 201, 62,
        55, 65, 253, 0, 3, 195, 157, 157, 152, 120, 157, 150, 235, 193, 72, 148, 233, 139, 195,
        153, 213, 149, 96, 52, 79, 34, 149, 42, 72, 175, 121, 106, 63, 4, 74, 76, 252, 230, 21, 64,
        249, 162, 206, 23, 89, 233, 35, 83, 204, 182, 107, 13, 139, 219, 73, 200, 130, 70, 135, 85,
        139, 173, 136, 155, 115, 79, 155, 103, 158, 63, 53, 63, 38, 55, 44, 93, 33, 255, 250, 138,
        229, 227, 88, 152, 33, 84, 51, 191, 58, 137, 99, 45, 230, 77, 250, 176, 74, 35, 9, 0, 214,
        151, 205, 40, 132, 4, 40, 229, 183, 191, 28, 97, 27, 195, 189, 217, 200, 48, 128, 185, 141,
        227, 23, 3, 105, 195, 213, 206, 36, 121, 41, 222, 200, 216, 2, 59, 222, 36, 121, 163, 180,
        186, 183, 24, 225, 224, 211, 9, 202, 225, 135, 253, 236, 90, 74, 248, 209, 237, 22, 160,
        190, 150, 78, 14, 107, 203, 124, 14, 49, 219, 49, 170, 10, 119, 91, 226, 220, 232, 165,
        255, 213, 110, 200, 58, 212, 60, 190, 242, 198, 213, 213, 166, 144, 154, 199, 5, 194, 124,
        119, 12, 228, 224, 200, 106, 190, 107, 65, 204, 149, 181, 213, 146, 38, 125, 159, 204, 163,
        31, 78, 168, 175, 226, 81, 102, 12, 86, 36, 123, 160, 161, 213, 193, 193, 125, 65, 157, 88,
        238, 20, 20, 123, 62, 232, 7, 92, 56, 171, 46, 71, 114, 58, 44, 116, 96, 18, 223, 194, 118,
        73, 147, 185, 159, 217, 94, 16, 172, 14, 171, 254, 3, 83, 110, 184, 181, 31, 107, 213, 139,
        227, 238, 157, 159, 109, 167, 207, 128, 122, 59, 14, 159, 118, 11, 217, 157, 122, 118, 194,
        114, 10, 102, 80, 255, 149, 149, 8, 34, 254, 84, 163, 156, 0, 229, 71, 50, 250, 150, 120,
        162, 147, 129, 0, 48, 25, 175, 4, 189, 78, 44, 108, 245, 84, 19, 140, 220, 1, 46, 24, 241,
        28, 8, 252, 154, 248, 78, 218, 108, 20, 23, 1, 232, 180, 0, 120, 204, 71, 170, 221, 193,
        214, 133, 60, 178, 86, 184, 243, 167, 229, 16, 181, 192, 130, 84, 10, 50, 41, 178, 182,
        188, 173, 116, 65, 243, 133, 32, 37, 186, 7, 19, 40, 99, 201, 149, 240, 8, 0, 65, 252, 250,
        166, 68, 83, 238, 202, 66, 66, 243, 178, 45, 181, 216, 146, 204, 134, 34, 33, 30, 18, 146,
        15, 238, 137, 40, 243, 255, 103, 78, 247, 181, 44, 189, 86, 39, 146, 8, 122, 7, 239, 4, 84,
        20, 55, 0, 219, 134, 181, 46, 38, 100, 81, 182, 142, 56, 103, 5, 173, 82, 177, 218, 218,
        113, 46, 21, 174, 163, 16, 106, 39, 109, 213, 186, 5, 246, 36, 38, 188, 228, 157, 189, 251,
        60, 237, 126, 165, 15, 137, 166, 177, 49, 56, 34, 159, 191, 128, 214, 66, 84, 89, 167, 168,
        239, 99, 44, 110, 171, 191, 123, 198, 146, 212, 223, 103, 98, 142, 133, 232, 249, 40, 218,
        189, 164, 29, 200, 117, 54, 120, 112, 193, 207, 192, 229, 162, 23, 158, 247, 204, 59, 0,
        176, 174, 236, 122, 158, 216, 170, 123, 235, 202, 165, 152, 59, 174, 90, 7, 20, 172, 232,
        135, 106, 224, 54, 63, 45, 70, 191, 94, 118, 178, 66, 58, 221, 122, 107, 46, 181, 222, 204,
        23, 216, 218, 21, 191, 16, 241, 174, 133, 241, 109, 156, 196, 73, 162, 8, 196, 163, 47,
        186, 196, 97, 98, 126, 110, 152, 113, 43, 115, 54, 181, 105, 199, 96, 248, 193, 74, 102,
        64, 114, 102, 180, 40, 229, 147, 13, 151, 27, 87, 39, 111, 10, 247, 176, 16, 28, 173, 7,
        248, 173, 173, 95, 138, 4, 232, 176, 4, 65, 226, 130, 170, 39, 199, 77, 53, 96, 98, 244,
        16, 79, 16, 184, 40, 33, 4, 80, 115, 184, 250, 16, 5, 115, 90, 19, 4, 210, 42, 197, 209,
        10, 236, 74, 147, 113, 100, 123, 116, 255, 152, 100, 10, 144, 157, 233, 5, 136, 232, 109,
        106, 20, 185, 83, 55, 252, 82, 78, 12, 40, 125, 8, 79, 233, 157, 174, 182, 4, 61, 199, 17,
        157, 55, 24, 10, 161, 44, 44, 197, 15, 10, 41, 212, 55, 31, 103, 183, 167, 39, 163, 155,
        187, 72, 236, 12, 24, 22, 186, 132, 105, 25, 236, 60, 250, 17, 152, 82, 59, 89, 84, 242,
        44, 7, 46, 95, 222, 10, 10, 143, 31, 134, 170, 93, 80, 109, 99, 149, 20, 48, 73, 116, 3,
        117, 162, 134, 191, 18, 108, 79, 120, 199, 135, 21, 107, 220, 84, 214, 160, 120, 117, 21,
        79, 51, 79, 32, 95, 116, 132, 29, 251, 85, 58, 54, 15, 240, 139, 196, 179, 240, 114, 233,
        13, 167, 129, 142, 13, 212, 176, 105, 85, 119, 173, 1, 58, 246, 33, 137, 150, 207, 15, 184,
        120, 29, 66, 225, 61, 138, 90, 202, 39, 231, 165, 23, 88, 189, 156, 137, 231, 246, 64, 45,
        220, 249, 221, 64, 228, 246, 79, 239, 81, 133, 201, 125, 24, 7, 173, 118, 132, 116, 216,
        26, 238, 51, 87, 242, 68, 98, 192, 108, 205, 233, 241, 18, 69, 149, 57, 254, 173, 69, 207,
        194, 95, 249, 236, 223, 207, 127, 19, 195, 170, 137, 154, 103, 152, 73, 3, 206, 1, 74, 143,
        159, 0, 74, 128, 251, 197, 159, 82, 55, 150, 76, 249, 217, 177, 210, 42, 20, 59, 145, 78,
        165, 47, 238, 45, 208, 163, 40, 163, 15, 65, 86, 81, 213, 110, 91, 130, 99, 49, 99, 69, 5,
        171, 224, 99, 2, 139, 142, 50, 245, 3, 199, 211, 5, 73, 245, 164, 115, 148, 170, 86, 216,
        235, 224, 44, 71, 230, 146, 88, 42, 66, 171, 199, 41, 213, 254, 8, 188, 125, 110, 143, 10,
        24, 138, 209, 197, 11, 3, 10, 134, 30, 76, 192, 249, 113, 74, 198, 172, 22, 81, 127, 149,
        131, 158, 65, 193, 214, 88, 17, 33, 248, 103, 136, 156, 114, 69, 6, 88, 109, 197, 141, 154,
        13, 17, 228, 157, 60, 70, 230, 22, 137, 232, 49, 156, 153, 211, 254, 234, 192, 141, 68,
        169, 185, 232, 146, 2, 17, 0, 23, 100, 141, 248, 191, 159, 39, 242, 175, 211, 6, 249, 5,
        70, 8, 219, 196, 120, 124, 66, 213, 91, 203, 80, 137, 147, 40, 55, 59, 233, 192, 72, 200,
        149, 199, 250, 222, 40, 6, 175, 193, 110, 132, 109, 19, 196, 13, 189, 196, 49, 83, 13, 249,
        56, 122, 194, 206, 203, 252, 186, 131, 177, 246, 104, 211, 151, 53, 194, 59, 252, 66, 205,
        213, 113, 149, 238, 127, 134, 38, 76, 167, 61, 203, 80, 27, 38, 202, 92, 110, 182, 4, 128,
        247, 220, 3, 46, 222, 156, 56, 86, 4, 46, 211, 48, 35, 27, 84, 198, 140, 43, 11, 204, 198,
        239, 100, 148, 42, 178, 88, 101, 21, 61, 183, 107, 71, 178, 142, 254, 222, 42, 222, 150, 0,
        103, 29, 164, 94, 149, 230, 190, 151, 131, 7, 160, 171, 194, 4, 78, 105, 182, 15, 21, 224,
        239, 71, 117, 95, 223, 32, 199, 35, 243, 136, 191, 72, 118, 106, 141, 73, 31, 160, 57, 156,
        110, 251, 83, 31, 241, 150, 235, 199, 65, 177, 176, 195, 168, 182, 38, 98, 217, 1, 211,
        192, 139, 2, 59, 129, 180, 30, 127, 90, 236, 225, 210, 6, 170, 33, 32, 172, 46, 37, 251, 9,
        100, 69, 230, 236, 75, 37, 110, 222, 28, 19, 31, 198, 56, 226, 208, 11, 11, 223, 170, 212,
        107, 91, 144, 200, 243, 19, 91, 77, 219, 42, 89, 93, 182, 129, 171, 86, 36, 121, 213, 33,
        234, 247, 154, 50, 4, 73, 22, 31, 219, 142, 167, 250, 50, 95, 169, 50, 212, 201, 55, 20,
        128, 225, 183, 254, 21, 231, 137, 102, 239, 133, 81, 103, 41, 22, 207, 226, 195, 171, 78,
        187, 111, 239, 166, 98, 75, 60, 220, 171, 127, 34, 30, 241, 85, 88, 184, 191, 140, 68, 208,
        105, 191, 84, 188, 113, 128, 57, 44, 132, 166, 49, 251, 100, 12, 224, 212, 14, 166, 3, 23,
        244, 27, 17, 187, 98, 67, 1, 124, 72, 249, 89, 217, 168, 49, 245, 50, 60, 82, 50, 148, 199,
        2, 149, 142, 137, 106, 156, 187, 86, 37, 21, 127, 61, 110, 138, 74, 33, 87, 180, 129, 68,
        125, 20, 104, 241, 206, 177, 98, 150, 214, 5, 112, 198, 56, 131, 175, 245, 71, 81, 86, 44,
        251, 154, 51, 120, 14, 199, 40, 20, 228, 100, 67, 232, 88, 13, 27, 26, 13, 110, 136, 3, 3,
        111, 162, 167, 130, 215, 48, 123, 4, 7, 197, 245, 71, 233, 214, 2, 71, 12, 167, 163, 129,
        195, 4, 223, 163, 59, 232, 38, 139, 28, 211, 120, 6, 82, 69, 140, 216, 60, 234, 156, 2,
        136, 70, 80, 59, 222, 32, 189, 88, 40, 134, 174, 66, 137, 76, 32, 209, 7, 1, 207, 77, 22,
        244, 120, 21, 13, 217, 156, 245, 60, 147, 18, 187, 45, 40, 121, 43, 91, 163, 183, 44, 221,
        145, 93, 224, 143, 169, 167, 218, 33, 124, 25, 97, 172, 217, 244, 4, 116, 99, 67, 96, 244,
        228, 15, 239, 159, 243, 80, 183, 224, 196, 144, 55, 3, 251, 71, 239, 168, 29, 183, 41, 196,
        173, 159, 200, 16, 85, 115, 45, 24, 5, 111, 0, 42, 5, 26, 87, 143, 172, 75, 175, 225, 182,
        21, 167, 131, 115, 1, 5, 157, 120, 65, 161, 236, 185, 172, 127, 206, 217, 84, 167, 6, 131,
        17, 191, 206, 163, 84, 226, 92, 85, 43, 106, 135, 163, 2, 69, 109, 76, 192, 162, 88, 3,
        179, 177, 231, 116, 191, 4, 28, 120, 204, 150, 20, 214, 234, 34, 198, 100, 245, 255, 199,
        201, 143, 199, 115, 42, 214, 250, 8, 84, 212, 93, 235, 100, 121, 229, 157, 126, 106, 22,
        220, 163, 168, 112, 69, 230, 156, 3, 1, 86, 38, 156, 79, 165, 31, 177, 247, 83, 32, 158,
        166, 53, 166, 228, 134, 76, 44, 6, 221, 240, 231, 47, 183, 177, 100, 249, 16, 197, 2, 133,
        98, 238, 74, 157, 21, 184, 204, 185, 161, 134, 229, 141, 178, 146, 53, 60, 223, 23, 10,
        191, 20, 201, 219, 154, 254, 93, 160, 62, 163, 179, 9, 89, 37, 67, 45, 159, 214, 107, 247,
        152, 152, 183, 141, 246, 4, 54, 44, 97, 126, 242, 143, 74, 88, 88, 196, 171, 211, 254, 201,
        41, 8, 30, 92, 87, 157, 81, 44, 204, 107, 2, 160, 82, 156, 69, 98, 190, 73, 151, 191, 57,
        116, 234, 89, 111, 109, 230, 181, 119, 35, 63, 188, 222, 23, 116, 6, 237, 129, 54, 190,
        234, 92, 59, 17, 255, 8, 111, 217, 33, 87, 0, 75, 164, 220, 184, 0, 46, 237, 255, 225, 199,
        104, 97, 10, 51, 97, 67, 56, 118, 201, 152, 47, 84, 78, 255, 216, 121, 252, 193, 43, 87,
        23, 108, 53, 197, 225, 232, 25, 233, 16, 171, 107, 209, 64, 240, 193, 100, 46, 255, 199,
        52, 132, 196, 63, 230, 254, 54, 169, 28, 174, 19, 199, 84, 74, 71, 77, 215, 87, 20, 146,
        141, 84, 136, 56, 93, 228, 111, 50, 213, 0, 138, 169, 41, 227, 34, 131, 86, 16, 127, 163,
        219, 250, 138, 183, 186, 102, 89, 165, 22, 248, 20, 29, 221, 4, 100, 173, 51, 71, 234, 10,
        255, 69, 151, 216, 155, 215, 52, 100, 207, 15, 227, 201, 16, 77, 0, 131, 9, 7, 16, 53, 77,
        168, 82, 114, 11, 192, 199, 6, 159, 128, 74, 17, 237, 182, 107, 90, 124, 142, 143, 215, 87,
        100, 104, 41, 188, 120, 49, 81, 211, 195, 56, 89, 234, 212, 155, 43, 94, 255, 48, 187, 103,
        71, 138, 130, 30, 11, 112, 16, 68, 13, 47, 33, 156, 35, 93, 215, 62, 52, 147, 7, 85, 160,
        219, 155, 246, 185, 150, 14, 97, 172, 218, 137, 215, 255, 54, 238, 100, 197, 64, 228, 116,
        114, 85, 38, 59, 132, 28, 58, 167, 233, 196, 220, 241, 25, 22, 214, 66, 10, 228, 3, 242,
        178, 117, 146, 112, 109, 184, 228, 96, 155, 244, 94, 117, 38, 157, 26, 196, 96, 162, 148,
        103, 16, 40, 101, 243, 120, 251, 155, 32, 207, 52, 211, 39, 25, 237, 231, 133, 187, 120,
        107, 156, 22, 81, 182, 206, 21, 207, 245, 111, 220, 126, 74, 164, 156, 74, 158, 181, 97,
        82, 215, 248, 198, 82, 44, 11, 249, 5, 124, 163, 202, 235, 67, 233, 43, 112, 127, 30, 21,
        1, 153, 157, 135, 33, 203, 171, 92, 41, 210, 237, 2, 225, 44, 183, 81, 12, 158, 117, 198,
        152, 86, 73, 214, 248, 6, 5, 144, 122, 98, 18, 169, 58, 16, 86, 224, 90, 131, 15, 182, 101,
        13, 159, 54, 76, 204, 28, 161, 127, 73, 185, 108, 146, 176, 0, 77, 208, 52, 57, 8, 232,
        189, 71, 223, 204, 6, 93, 165, 179, 95, 113, 10, 55, 73, 210, 142, 196, 244, 86, 216, 198,
        138, 140, 173, 103, 226, 52, 233, 164, 1, 57, 44, 156, 209, 199, 185, 135, 190, 157, 212,
        156, 255, 49, 248, 91, 169, 203, 20, 75, 106, 163, 31, 157, 152, 213, 180, 62, 34, 203,
        125, 140, 12, 182, 103, 242, 54, 213, 214, 72, 100, 145, 62, 156, 160, 40, 87, 113, 230,
        243, 11, 181, 223, 215, 145, 110, 59, 48, 188, 13, 83, 150, 147, 236, 178, 246, 11, 251,
        217, 152, 99, 27, 48, 71, 134, 192, 67, 176, 82, 226, 154, 58, 248, 198, 156, 120, 17, 200,
        167, 52, 66, 37, 124, 181, 125, 66, 18, 169, 200, 245, 180, 157, 163, 220, 178, 217, 119,
        248, 38, 218, 25, 193, 85, 26, 8, 24, 66, 23, 111, 42, 125, 216, 110, 155, 10, 122, 178,
        160, 207, 141, 168, 73, 250, 145, 27, 89, 242, 51, 3, 102, 182, 140, 214, 31, 40, 29, 4,
        16, 194, 135, 193, 62, 166, 188, 109, 186, 141, 0, 111, 200, 52, 61, 21, 188, 190, 43, 163,
        106, 13, 214, 170, 74, 103, 211, 188, 165, 158, 205, 124, 166, 123, 234, 191, 181, 253,
        245, 208, 219, 29, 122, 160, 38, 152, 9, 35, 180, 101, 12, 232, 124, 183, 254, 167, 53,
        192, 107, 245, 232, 86, 111, 10, 244, 23, 182, 62, 101, 55, 218, 157, 158, 254, 251, 173,
        156, 128, 234, 182, 173, 114, 202, 105, 116, 45, 3, 15, 179, 104, 110, 164, 43, 193, 178,
        101, 178, 130, 36, 217, 52, 193, 255, 169, 78, 139, 114, 129, 81, 236, 227, 19, 41, 89,
        182, 209, 156, 55, 26, 41, 29, 148, 234, 173, 31, 151, 23, 10, 194, 26, 140, 147, 112, 0,
        93, 198, 204, 142, 160, 135, 86, 31, 74, 63, 245, 202, 111, 147, 146, 77, 227, 185, 167,
        15, 220, 244, 8, 187, 7, 13, 173, 231, 251, 198, 150, 63, 19, 20, 72, 102, 94, 238, 33,
        247, 100, 243, 105, 213, 108, 188, 58, 146, 65, 47, 25, 96, 122, 33, 163, 78, 175, 65, 136,
        92, 121, 198, 130, 84, 199, 223, 191, 238, 223, 77, 178, 2, 29, 3, 238, 14, 54, 1, 0, 165,
        180, 65, 71, 76, 140, 52, 124, 49, 166, 50, 88, 232, 39, 2, 86, 224, 243, 87, 69, 189, 7,
        157, 15, 49, 147, 220, 184, 54, 243, 43, 66, 144, 133, 135, 6, 206, 8, 222, 97, 178, 30, 9,
        193, 10, 68, 250, 142, 242, 65, 36, 184, 56, 189, 112, 247, 15, 3, 22, 215, 203, 175, 105,
        214, 245, 42, 158, 11, 158, 44, 177, 177, 118, 230, 125, 207, 102, 8, 64, 93, 211, 244,
        110, 55, 167, 100, 122, 233, 238, 138, 8, 116, 250, 80, 123, 191, 157, 230, 59, 166, 216,
        40, 239, 8, 215, 26, 159, 86, 229, 62, 132, 145, 202, 88, 152, 23, 122, 179, 99, 79, 123,
        150, 198, 103, 173, 145, 187, 171, 116, 18, 9, 10, 22, 158, 43, 12, 248, 27, 12, 171, 229,
        186, 241, 20, 109, 238, 21, 11, 248, 189, 67, 7, 109, 28, 204, 175, 180, 199, 15, 40, 234,
        204, 113, 117, 228, 23, 206, 9, 74, 109, 255, 90, 141, 233, 196, 227, 13, 94, 130, 16, 217,
        33, 114, 222, 112, 160, 11, 32, 188, 160, 149, 30, 22, 178, 245, 249, 182, 250, 228, 111,
        86, 242, 25, 95, 220, 233, 206, 176, 200, 236, 13, 122, 190, 24, 175, 134, 151, 55, 143,
        83, 203, 107, 160, 144, 39, 143, 132, 227, 8, 49, 53, 97, 165, 100, 1, 6, 96, 74, 114, 116,
        116, 128, 209, 35, 114, 183, 23, 165, 78, 22, 253, 145, 19, 152, 138, 99, 9, 45, 55, 205,
        60, 222, 181, 19, 252, 244, 155, 108, 135, 189, 219, 54, 92, 156, 187, 81, 25, 227, 196,
        159, 210, 185, 11, 157, 27, 108, 200, 165, 1, 66, 180, 72, 246, 247, 72, 103, 220, 91, 144,
        127, 222, 199, 183, 220, 254, 32, 27, 121, 1, 67, 242, 16, 68, 84, 94, 149, 233, 156, 165,
        32, 195, 132, 7, 148, 118, 47, 221, 174, 215, 93, 24, 253, 250, 171, 215, 43, 250, 243,
        190, 16, 102, 241, 10, 75, 190, 54, 47, 33, 195, 231, 67, 177, 9, 201, 103, 213, 172, 135,
        54, 46, 57, 150, 54, 132, 2, 238, 120, 175, 230, 151, 99, 127, 217, 211, 113, 41, 198, 174,
        21, 11, 10, 46, 228, 3, 152, 210, 108, 225, 198, 18, 80, 90, 56, 162, 2, 107, 98, 219, 204,
        152, 190, 170, 108, 161, 251, 30, 198, 135, 143, 107, 172, 121, 101, 252, 168, 184, 189,
        21, 223, 119, 238, 127, 44, 166, 36, 41, 9, 95, 65, 23, 211, 195, 34, 198, 220, 49, 55, 57,
        216, 5, 159, 85, 73, 117, 119, 201, 172, 128, 247, 209, 131, 212, 223, 146, 154, 200, 116,
        213, 34, 12, 62, 168, 232, 227, 238, 61, 124, 3, 166, 70, 74, 178, 110, 134, 18, 119, 249,
        42, 102, 248, 169, 108, 45, 244, 236, 234, 48, 201, 101, 127, 1, 104, 41, 217, 113, 80, 41,
        249, 108, 134, 90, 11, 227, 8, 189, 3, 194, 241, 124, 132, 181, 234, 24, 242, 153, 148,
        148, 57, 70, 201, 90, 76, 0, 44, 111, 92, 77, 36, 209, 210, 110, 227, 209, 140, 4, 17, 189,
        30, 126, 106, 39, 223, 150, 73, 103, 232, 35, 139, 200, 66, 30, 235, 25, 169, 137, 85, 146,
        216, 128, 83, 38, 144, 16, 63, 221, 61, 65, 217, 145, 117, 15, 27, 158, 81, 221, 240, 74,
        242, 186, 146, 198, 82, 36, 166, 134, 109, 25, 52, 236, 224, 254, 25, 246, 186, 33, 136,
        153, 7, 234, 19, 192, 23, 238, 106, 159, 206, 199, 210, 119, 176, 27, 220, 96, 101, 198,
        244, 86, 7, 19, 56, 151, 101, 119, 179, 59, 7, 43, 168, 8, 90, 132, 143, 138, 205, 245, 20,
        43, 91, 175, 81, 225, 1, 13, 11, 140, 83, 191, 231, 240, 217, 209, 249, 86, 137, 124, 215,
        28, 102, 157, 171, 237, 5, 170, 112, 106, 226, 6, 88, 86, 170, 91, 213, 233, 90, 247, 57,
        216, 154, 196, 162, 216, 243, 124, 64, 123, 64, 113, 102, 198, 54, 250, 65, 248, 176, 137,
        29, 189, 108, 5, 158, 238, 80, 218, 85, 177, 246, 76, 225, 101, 25, 100, 19, 43, 19, 6,
        128, 201, 187, 204, 202, 163, 141, 152, 114, 248, 154, 50, 232, 59, 140, 177, 186, 148, 87,
        149, 91, 129, 30, 222, 212, 117, 227, 153, 239, 15, 114, 68, 150, 2, 97, 115, 119, 177, 64,
        205, 106, 135, 140, 12, 84, 235, 133, 16, 120, 132, 92, 58, 181, 211, 67, 228, 53, 126,
        226, 3, 164, 110, 251, 141, 10, 148, 29, 77, 117, 108, 239, 224, 109, 166, 153, 80, 60,
        155, 152, 226, 123, 167, 95, 177, 64, 185, 171, 12, 56, 189, 252, 20, 53, 47, 4, 18, 183,
        66, 62, 110, 120, 26, 53, 184, 97, 128, 138, 254, 41, 124, 123, 169, 80, 94, 241, 97, 84,
        44, 83, 49, 104, 184, 250, 164, 225, 158, 135, 125, 42, 56, 90, 112, 173, 211, 57, 182, 73,
        192, 186, 162, 33, 109, 118, 14, 145, 112, 44, 32, 146, 136, 216, 193, 134, 30, 193, 228,
        41, 60, 249, 166, 147, 150, 233, 246, 127, 219, 60, 247, 252, 98, 199, 106, 122, 220, 192,
        239, 168, 20, 89, 80, 140, 208, 29, 22, 237, 120, 147, 182, 72, 138, 65, 0, 187, 158, 89,
        15, 114, 96, 138, 3, 167, 128, 233, 229, 159, 143, 90, 125, 4, 45, 200, 129, 50, 225, 215,
        167, 77, 153, 7, 158, 215, 97, 57, 126, 202, 68, 48, 223, 114, 108, 39, 85, 150, 33, 116,
        213, 200, 103, 156, 14, 1, 38, 161, 214, 140, 215, 142, 116, 37, 93, 103, 122, 161, 173,
        81, 182, 151, 195, 176, 24, 95, 106, 104, 157, 70, 103, 190, 170, 29, 8, 57, 51, 41, 66,
        82, 79, 222, 130, 112, 221, 151, 196, 105, 138, 24, 39, 31, 6, 248, 159, 169, 111, 113, 20,
        51, 54, 10, 190, 162, 113, 214, 106, 143, 53, 8, 171, 113, 237, 56, 242, 123, 244, 35, 28,
        23, 169, 90, 4, 88, 158, 152, 8, 128, 252, 140, 71, 92, 23, 157, 11, 150, 73, 169, 166,
        228, 25, 174, 154, 72, 224, 82, 228, 208, 61, 228, 177, 193, 186, 150, 90, 71, 31, 132, 4,
        65, 147, 195, 212, 21, 40, 180, 7, 212, 167, 109, 26, 177, 84, 189, 107, 10, 174, 62, 137,
        132, 0, 167, 189, 160, 138, 16, 164, 208, 20, 39, 73, 148, 21, 224, 161, 194, 169, 191, 33,
        187, 26, 184, 54, 253, 148, 157, 192, 100, 26, 227, 125, 117, 196, 29, 16, 185, 141, 53,
        53, 2, 55, 83, 250, 11, 51, 235, 200, 170, 178, 221, 191, 122, 185, 171, 47, 153, 12, 99,
        9, 58, 140, 236, 49, 191, 82, 255, 41, 71, 31, 134, 138, 87, 237, 216, 187, 103, 236, 38,
        98, 44, 96, 210, 195, 227, 46, 205, 25, 141, 253, 122, 13, 140, 24, 224, 237, 118, 136,
        136, 87, 54, 85, 123, 168, 168, 20, 186, 164, 87, 247, 234, 239, 29, 103, 173, 142, 100,
        133, 183, 147, 28, 32, 72, 118, 58, 200, 97, 183, 70, 191, 47, 6, 248, 118, 209, 72, 22,
        164, 254, 9, 47, 96, 80, 154, 184, 158, 116, 251, 12, 118, 97, 195, 54, 19, 103, 160, 42,
        127, 157, 97, 187, 3, 24, 79, 76, 24, 56, 10, 132, 174, 112, 248, 50, 165, 222, 146, 215,
        12, 124, 40, 76, 216, 108, 194, 70, 15, 16, 153, 139, 48, 73, 208, 208, 51, 219, 60, 129,
        58, 35, 196, 78, 15, 215, 175, 6, 70, 56, 254, 193, 33, 39, 149, 234, 211, 187, 158, 246,
        22, 237, 161, 247, 226, 93, 251, 217, 97, 217, 122, 235, 171, 55, 13, 134, 163, 60, 84,
        187, 165, 97, 33, 84, 242, 32, 140, 115, 101, 226, 24, 236, 20, 77, 78, 76, 109, 201, 180,
        103, 129, 18, 114, 236, 160, 13, 173, 50, 37, 61, 132, 69, 18, 93, 95, 140, 140, 11, 220,
        64, 229, 186, 121, 41, 146, 25, 248, 32, 130, 45, 209, 161, 215, 98, 43, 117, 156, 90, 134,
        71, 25, 197, 28, 203, 185, 1, 244, 130, 174, 55, 6, 81, 208, 28, 52, 84, 181, 217, 61, 26,
        237, 181, 250, 25, 238, 197, 111, 189, 110, 63, 96, 215, 144, 235, 37, 201, 62, 227, 118,
        181, 174, 106, 21, 18, 59, 23, 189, 21, 4, 156, 112, 226, 138, 7, 67, 18, 33, 146, 68, 3,
        49, 231, 34, 51, 70, 12, 159, 70, 163, 232, 251, 142, 61, 45, 61, 72, 193, 185, 170, 163,
        66, 216, 110, 98, 176, 9, 67, 55, 177, 26, 99, 86, 111, 135, 191, 223, 14, 84, 205, 235,
        118, 244, 180, 56, 66, 217, 86, 231, 194, 195, 205, 170, 94, 119, 69, 117, 190, 158, 24,
        226, 168, 189, 17, 212, 43, 169, 131, 81, 243, 58, 168, 165, 29, 16, 251, 228, 35, 189,
        123, 254, 164, 85, 70, 96, 16, 185, 11, 94, 228, 189, 211, 147, 157, 58, 0, 39, 2, 249,
        115, 207, 42, 29, 253, 44, 201, 75, 64, 205, 249, 100, 184, 155, 237, 162, 55, 48, 71, 89,
        122, 56, 157, 66, 179, 63, 154, 188, 201, 105, 65, 236, 168, 90, 4, 135, 216, 111, 11, 192,
        88, 18, 148, 149, 129, 91, 241, 50, 125, 240, 151, 111, 54, 245, 142, 32, 210, 83, 114,
        214, 83, 90, 75, 246, 8, 29, 101, 89, 207, 181, 93, 195, 15, 103, 156, 149, 211, 61, 88,
        192, 70, 124, 24, 51, 200, 210, 11, 185, 28, 61, 26, 242, 229, 216, 223, 77, 8, 71, 80,
        230, 123, 76, 56, 77, 40, 38, 80, 193, 197, 207, 78, 114, 65, 155, 219, 14, 217, 136, 121,
        26, 33, 77, 193, 189, 75, 212, 59, 22, 53, 224, 12, 204, 66, 225, 139, 165, 118, 63, 50,
        146, 169, 107, 134, 192, 125, 40, 81, 26, 139, 205, 171, 56, 75, 201, 111, 183, 51, 225,
        194, 224, 31, 203, 46, 20, 109, 118, 151, 141, 178, 36, 32, 11, 155, 137, 63, 200, 48, 122,
        22, 188, 35, 163, 217, 174, 79, 143, 239, 52, 226, 247, 240, 3, 51, 80, 5, 5, 172, 187, 17,
        141, 205, 64, 118, 203, 166, 188, 105, 159, 224, 64, 47, 63, 158, 65, 117, 109, 114, 113,
        179, 149, 208, 150, 74, 247, 76, 201, 21, 212, 175, 79, 159, 106, 42, 228, 9, 113, 35, 195,
        60, 61, 75, 215, 87, 162, 93, 40, 45, 223, 137, 86, 221, 171, 152, 92, 49, 121, 47, 32, 99,
        104, 194, 64, 252, 154, 233, 89, 146, 83, 250, 101, 45, 55, 207, 162, 11, 152, 6, 28, 239,
        75, 95, 231, 16, 163, 27, 46, 59, 43, 203, 149, 220, 167, 151, 5, 63, 56, 196, 186, 23, 25,
        58, 201, 235, 253, 218, 121, 121, 136, 165, 83, 48, 71, 134, 87, 233, 143, 173, 144, 145,
        165, 194, 9, 10, 192, 127, 190, 241, 195, 90, 231, 2, 108, 210, 186, 230, 97, 142, 57, 23,
        193, 148, 39, 249, 172, 198, 192, 48, 51, 126, 191, 82, 26, 151, 235, 45, 191, 230, 13,
        214, 152, 185, 54, 113, 184, 251, 253, 58, 240, 65, 57, 11, 20, 231, 16, 216, 4, 140, 223,
        185, 251, 250, 216, 245, 246, 111, 207, 75, 25, 89, 132, 111, 110, 138, 128, 107, 110, 196,
        45, 252, 217, 13, 213, 157, 148, 139, 239, 245, 52, 82, 20, 199, 110, 79, 18, 83, 244, 0,
        90, 18, 170, 93, 253, 104, 137, 182, 248, 251, 195, 15, 15, 174, 164, 206, 195, 50, 117,
        97, 182, 151, 228, 54, 9, 160, 17, 210, 64, 106, 138, 140, 225, 174, 98, 135, 162, 28, 12,
        134, 149, 149, 118, 211, 110, 229, 3, 86, 210, 3, 245, 85, 172, 71, 202, 174, 207, 35, 95,
        255, 254, 225, 232, 70, 19, 81, 112, 51, 196, 162, 100, 26, 82, 254, 156, 44, 212, 46, 162,
        226, 207, 81, 226, 229, 84, 12, 226, 57, 26, 157, 96, 154, 81, 49, 77, 161, 247, 16, 40,
        249, 55, 126, 104, 73, 50, 1, 100, 235, 144, 39, 83, 144, 16, 136, 70, 199, 7, 124, 219,
        75, 28, 134, 159, 29, 103, 214, 53, 18, 185, 119, 94, 247, 235, 186, 45, 99, 254, 35, 146,
        51, 115, 185, 136, 155, 212, 13, 92, 80, 79, 141, 204, 98, 239, 107, 196, 198, 119, 166,
        183, 79, 174, 243, 53, 46, 122, 63, 45, 72, 164, 163, 125, 193, 252, 17, 193, 168, 90, 70,
        106, 243, 255, 144, 87, 105, 143, 210, 104, 118, 45, 241, 17, 147, 58, 22, 221, 17, 202,
        197, 250, 148, 203, 246, 180, 120, 91, 51, 210, 217, 175, 46, 104, 58, 130, 70, 66, 46,
        203, 202, 16, 136, 231, 194, 47, 55, 126, 162, 158, 100, 148, 199, 11, 36, 148, 148, 136,
        191, 218, 64, 124, 189, 179, 2, 172, 59, 19, 188, 38, 231, 152, 219, 44, 124, 7, 14, 113,
        141, 184, 193, 195, 145, 170, 187, 81, 132, 0, 108, 104, 20, 150, 54, 233, 95, 97, 179,
        189, 14, 156, 25, 174, 23, 153, 94, 136, 89, 80, 162, 82, 66, 96, 170, 148, 240, 241, 245,
        108, 93, 59, 101, 41, 153, 238, 34, 85, 185, 94, 172, 76, 85, 212, 78, 135, 157, 125, 100,
        234, 101, 103, 108, 133, 58, 72, 215, 48, 93, 78, 227, 157, 141, 198, 77, 149, 11, 190,
        186, 167, 246, 114, 22, 173, 51, 65, 247, 26, 41, 194, 46, 37, 3, 18, 48, 98, 85, 226, 29,
        137, 114, 99, 206, 165, 27, 50, 187, 14, 67, 27, 187, 124, 36, 58, 25, 190, 149, 225, 196,
        160, 87, 154, 140, 135, 221, 116, 88, 136, 94, 41, 47, 129, 73, 169, 105, 204, 241, 42,
        197, 208, 156, 142, 156, 168, 175, 189, 115, 90, 192, 105, 39, 2, 201, 64, 200, 134, 16,
        218, 44, 159, 155, 93, 32, 188, 166, 242, 110, 164, 115, 29, 28, 170, 131, 96, 240, 248,
        251, 181, 126, 152, 121, 120, 120, 67, 223, 83, 54, 227, 194, 229, 168, 229, 7, 117, 120,
        52, 222, 197, 174, 215, 96, 251, 177, 194, 157, 82, 205, 64, 122, 190, 16, 176, 31, 37, 89,
        36, 51, 193, 227, 69, 72, 94, 2, 70, 83, 76, 229, 132, 205, 213, 170, 176, 213, 54, 124,
        229, 157, 157, 191, 128, 241, 1, 23, 41, 26, 36, 245, 219, 1, 98, 124, 6, 189, 7, 204, 177,
        45, 246, 112, 106, 102, 211, 150, 43, 157, 29, 201, 100, 79, 240, 59, 31, 43, 8, 47, 167,
        182, 207, 188, 226, 110, 111, 34, 111, 23, 9, 25, 251, 68, 87, 121, 54, 121, 195, 167, 10,
        232, 140, 149, 50, 13, 58, 147, 190, 115, 1, 54, 169, 22, 192, 3, 161, 34, 125, 184, 171,
        188, 206, 91, 39, 218, 185, 136, 174, 11, 55, 96, 244, 91, 100, 91, 39, 187, 100, 152, 0,
        143, 109, 201, 77, 89, 46, 200, 155, 230, 237, 7, 187, 162, 68, 26, 230, 118, 126, 145,
        217, 34, 45, 183, 28, 60, 152, 161, 22, 11, 237, 158, 108, 207, 24, 237, 143, 229, 186,
        125, 50, 158, 111, 200, 111, 245, 153, 133, 5, 85, 48, 13, 251, 63, 119, 184, 127, 23, 36,
        88, 179, 91, 246, 47, 3, 141, 176, 152, 16, 255, 247, 47, 104, 162, 16, 240, 194, 19, 154,
        32, 181, 10, 59, 223, 171, 7, 103, 109, 28, 32, 141, 68, 244, 117, 218, 161, 112, 49, 51,
        169, 45, 95, 142, 77, 236, 215, 54, 48, 142, 69, 71, 191, 60, 125, 129, 203, 147, 165, 201,
        241, 77, 118, 177, 0, 148, 99, 48, 79, 5, 183, 89, 136, 166, 223, 173, 36, 42, 143, 54, 29,
        46, 147, 233, 140, 239, 84, 176, 195, 248, 71, 31, 41, 26, 170, 111, 209, 146, 154, 26, 84,
        142, 209, 6, 148, 249, 64, 193, 88, 22, 145, 150, 236, 141, 26, 202, 127, 59, 170, 57, 90,
        141, 224, 237, 167, 77, 254, 129, 28, 137, 79, 163, 59, 22, 11, 119, 51, 62, 105, 246, 245,
        14, 185, 220, 102, 160, 76, 205, 115, 114, 48, 205, 5, 52, 69, 219, 125, 41, 93, 147, 30,
        105, 254, 177, 109, 134, 255, 37, 193, 146, 226, 126, 87, 52, 96, 230, 43, 140, 125, 179,
        60, 166, 195, 187, 32, 155, 180, 61, 130, 136, 208, 134, 30, 73, 253, 93, 35, 176, 252,
        127, 176, 74, 56, 161, 70, 248, 235, 75, 41, 87, 251, 30, 61, 60, 12, 78, 154, 161, 90, 52,
        122, 148, 249, 168, 84, 69, 215, 55, 225, 200, 232, 189, 42, 156, 186, 153, 125, 59, 113,
        156, 44, 242, 214, 153, 209, 29, 72, 201, 238, 127, 142, 195, 45, 7, 10, 74, 127, 242, 162,
        62, 235, 185, 41, 181, 107, 171, 188, 205, 183, 193, 185, 226, 148, 161, 58, 99, 60, 12,
        198, 248, 205, 35, 194, 170, 50, 179, 228, 87, 116, 39, 171, 79, 181, 227, 61, 45, 79, 126,
        99, 214, 160, 1, 135, 84, 44, 1, 13, 208, 193, 40, 124, 167, 7, 167, 34, 131, 25, 1, 200,
        19, 105, 214, 189, 199, 197, 112, 20, 173, 226, 9, 211, 13, 181, 32, 171, 80, 200, 71, 51,
        77, 37, 86, 206, 121, 194, 0, 69, 158, 62, 110, 80, 232, 227, 235, 66, 247, 203, 100, 226,
        205, 6, 164, 220, 93, 22, 90, 141, 41, 158, 252, 189, 202, 249, 80, 122, 131, 137, 28, 185,
        9, 154, 78, 234, 75, 163, 87, 19, 120, 122, 192, 70, 188, 215, 174, 99, 73, 137, 49, 152,
        179, 88, 15, 119, 49, 122, 136, 78, 180, 13, 143, 34, 61, 62, 81, 226, 73, 86, 249, 89,
        193, 198, 6, 218, 140, 13, 173, 237, 216, 55, 182, 111, 107, 131, 182, 83, 255, 255, 6, 61,
        198, 195, 18, 35, 171, 38, 7, 24, 183, 86, 213, 113, 86, 129, 16, 168, 27, 206, 147, 6, 6,
        190, 155, 100, 160, 38, 74, 131, 126, 34, 217, 251, 137, 101, 3, 84, 251, 189, 170, 60,
        202, 102, 17, 231, 113, 207, 151, 158, 228, 234, 32, 127, 166, 131, 21, 119, 188, 255, 179,
        251, 0, 234, 179, 3, 76, 146, 172, 198, 221, 73, 100, 137, 80, 19, 46, 161, 96, 72, 64, 48,
        33, 155, 71, 137, 162, 54, 74, 1, 77, 228, 76, 129, 129, 92, 9, 159, 80, 49, 237, 146, 93,
        109, 88, 205, 64, 56, 159, 141, 92, 106, 186, 35, 138, 239, 12, 188, 120, 202, 252, 71, 34,
        204, 67, 214, 40, 166, 189, 250, 107, 23, 176, 169, 201, 94, 15, 142, 240, 71, 154, 81, 17,
        228, 45, 38, 133, 28, 18, 233, 115, 253, 125, 4, 150, 212, 98, 121, 75, 35, 245, 15, 39,
        85, 180, 16, 138, 218, 196, 212, 134, 210, 39, 232, 192, 44, 119, 69, 193, 55, 50, 18, 1,
        242, 6, 66, 71, 109, 208, 93, 175, 128, 176, 233, 90, 239, 27, 159, 208, 140, 209, 115, 27,
        227, 144, 207, 21, 70, 96, 198, 49, 252, 179, 59, 83, 143, 4, 173, 131, 48, 169, 50, 16,
        248, 90, 208, 161, 162, 113, 173, 29, 225, 40, 78, 38, 84, 11, 31, 177, 7, 38, 73, 201, 63,
        215, 194, 157, 125, 0, 201, 227, 100, 253, 228, 64, 183, 243, 71, 198, 16, 25, 247, 158, 9,
        158, 132, 65, 89, 229, 203, 221, 113, 188, 182, 0, 208, 135, 216, 228, 133, 254, 233, 194,
        254, 120, 31, 231, 176, 73, 128, 48, 73, 58, 213, 124, 224, 151, 235, 211, 240, 141, 4,
        253, 234, 108, 131, 81, 223, 153, 212, 229, 106, 171, 201, 0, 167, 253, 130, 17, 236, 73,
        167, 216, 213, 164, 254, 131, 203, 163, 136, 44, 40, 145, 0, 216, 16, 155, 113, 41, 223,
        241, 99, 38, 27, 234, 218, 41, 147, 8, 65, 127, 179, 190, 117, 107, 148, 11, 179, 125, 58,
        168, 199, 50, 29, 45, 199, 37, 177, 45, 123, 49, 243, 186, 177, 211, 198, 40, 123, 111,
        215, 238, 188, 33, 132, 251, 27, 118, 233, 67, 9, 69, 163, 128, 127, 252, 60, 201, 49, 109,
        193, 119, 98, 162, 127, 148, 138, 82, 149, 161, 56, 7, 183, 243, 236, 188, 29, 12, 152,
        236, 85, 140, 226, 243, 11, 123, 51, 111, 110, 148, 255, 156, 26, 61, 57, 81, 123, 254,
        224, 62, 135, 129, 227, 219, 241, 32, 19, 49, 171, 186, 29, 130, 26, 170, 94, 241, 14, 176,
        143, 223, 75, 27, 15, 251, 73, 141, 80, 130, 15, 49, 86, 90, 106, 235, 253, 179, 46, 103,
        154, 21, 131, 147, 108, 149, 208, 94, 34, 155, 139, 166, 2, 105, 131, 175, 61, 52, 160,
        167, 50, 173, 189, 141, 55, 101, 19, 93, 31, 181, 4, 10, 40, 23, 244, 133, 249, 120, 253,
        18, 107, 77, 157, 100, 214, 138, 122, 104, 59, 153, 177, 52, 121, 230, 217, 72, 3, 117,
        241, 43, 120, 54, 123, 197, 69, 11, 142, 143, 72, 254, 220, 5, 84, 133, 107, 76, 103, 203,
        252, 127, 179, 105, 202, 230, 241, 211, 144, 136, 145, 17, 181, 156, 5, 93, 8, 237, 40,
        190, 245, 186, 164, 2, 6, 70, 115, 150, 175, 100, 170, 204, 37, 15, 106, 213, 211, 110,
        236, 227, 159, 178, 125, 30, 65, 41, 20, 21, 187, 154, 167, 50, 25, 231, 190, 5, 63, 13,
        199, 231, 33, 84, 211, 121, 182, 60, 23, 230, 41, 231, 103, 61, 87, 211, 165, 47, 141, 56,
        45, 113, 90, 107, 173, 110, 26, 74, 43, 114, 249, 12, 191, 72, 140, 254, 6, 31, 29, 231,
        241, 14, 219, 201, 254, 65, 230, 16, 188, 111, 241, 127, 72, 136, 209, 43, 130, 27, 141,
        232, 142, 237, 43, 226, 127, 225, 124, 77, 217, 109, 231, 238, 172, 84, 185, 214, 44, 154,
        75, 135, 236, 83, 78, 73, 171, 109, 29, 46, 250, 124, 34, 172, 184, 246, 251, 181, 118, 87,
        214, 149, 107, 252, 220, 242, 184, 65, 5, 193, 139, 123, 244, 72, 75, 156, 90, 144, 134,
        145, 34, 62, 114, 144, 72, 33, 192, 237, 168, 180, 62, 167, 2, 132, 239, 229, 229, 221,
        246, 196, 4, 181, 104, 36, 15, 72, 10, 98, 5, 77, 186, 133, 170, 47, 32, 73, 71, 56, 100,
        34, 116, 28, 219, 85, 116, 214, 178, 234, 191, 86, 253, 214, 69, 224, 19, 148, 13,
    ];

    // Re-construct the aggregate proof from the bytes, using the native deserialization method.
    let aggregate_proof: groth16::aggregate::AggregateProof<Bls12> =
        groth16::aggregate::AggregateProof::read(std::io::Cursor::new(&aggregate_proof_bytes))?;

    // Re-serialize the proof to ensure a round-trip match.
    let mut aggregate_proof_bytes2 = Vec::new();
    aggregate_proof.write(&mut aggregate_proof_bytes2)?;

    assert_eq!(aggregate_proof_bytes.len(), aggregate_proof_bytes2.len());
    assert_eq!(aggregate_proof_bytes, aggregate_proof_bytes2);

    // Note: the native serialization format is more compact than bincode serialization, so assert that here.
    let bincode_serialized_proof = serialize(&aggregate_proof)?;
    assert!(aggregate_proof_bytes2.len() < bincode_serialized_proof.len());

    Ok(())
}
