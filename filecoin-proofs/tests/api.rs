use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Once;

use anyhow::Result;
use bellperson::bls::Fr;
use ff::Field;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs::hasher::Hasher;
use storage_proofs::sector::*;
use tempfile::NamedTempFile;

use filecoin_proofs::*;

// Use a fixed PoRep ID, so that the parents cache can be re-used between some tests.
const ARBITRARY_POREP_ID: [u8; 32] = [28; 32];

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
    seal_lifecycle::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, &porep_id)
}

#[test]
#[ignore]
fn test_seal_lifecycle_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    seal_lifecycle::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, &porep_id)
}

#[test]
#[ignore]
fn test_seal_lifecycle_4kib_sub_8_2() -> Result<()> {
    seal_lifecycle::<SectorShape4KiB>(SECTOR_SIZE_4_KIB, &ARBITRARY_POREP_ID)
}

#[test]
#[ignore]
fn test_seal_lifecycle_16kib_sub_8_2() -> Result<()> {
    seal_lifecycle::<SectorShape16KiB>(SECTOR_SIZE_16_KIB, &ARBITRARY_POREP_ID)
}

#[test]
#[ignore]
fn test_seal_lifecycle_32kib_top_8_8_2() -> Result<()> {
    seal_lifecycle::<SectorShape32KiB>(SECTOR_SIZE_32_KIB, &ARBITRARY_POREP_ID)
}

// These tests are good to run, but take a long time.

//#[test]
//#[ignore]
//fn test_seal_lifecycle_512mib_porep_id_v1_top_8_0_0() -> Result<()> {
//    let porep_id_v1: u64 = 2; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
//    seal_lifecycle::<SectorShape512MiB>(SECTOR_SIZE_512_MIB, &porep_id)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_512mib_porep_id_v1_1_top_8_0_0() -> Result<()> {
//    let porep_id_v1_1: u64 = 7; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
//    seal_lifecycle::<SectorShape512MiB>(SECTOR_SIZE_512_MIB, &porep_id)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_32gib_porep_id_v1_top_8_8_0() -> Result<()> {
//    let porep_id_v1: u64 = 3; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
//    seal_lifecycle::<SectorShape32GiB>(SECTOR_SIZE_32_GIB, &porep_id)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_32gib_porep_id_v1_1_top_8_8_0() -> Result<()> {
//    let porep_id_v1_1: u64 = 8; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
//    seal_lifecycle::<SectorShape32GiB>(SECTOR_SIZE_32_GIB, &porep_id)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_64gib_porep_id_v1_top_8_8_2() -> Result<()> {
//    let porep_id_v1: u64 = 4; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
//    seal_lifecycle::<SectorShape64GiB>(SECTOR_SIZE_64_GIB, &porep_id)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_64gib_porep_id_v1_1_top_8_8_2() -> Result<()> {
//    let porep_id_v1_1: u64 = 9; // This is a RegisteredSealProof value
//
//    let mut porep_id = [0u8; 32];
//    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
//    seal_lifecycle::<SectorShape64GiB>(SECTOR_SIZE_64_GIB, &porep_id)
//}

fn seal_lifecycle<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    porep_id: &[u8; 32],
) -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    create_seal::<_, Tree>(rng, sector_size, prover_id, false, porep_id)?;
    Ok(())
}

fn get_layer_file_paths(cache_dir: &tempfile::TempDir) -> Vec<PathBuf> {
    fs::read_dir(&cache_dir)
        .expect("failed to read read directory ")
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
        .collect()
}

fn clear_cache_dir_keep_data_layer(cache_dir: &tempfile::TempDir) {
    for entry in fs::read_dir(&cache_dir).expect("faailed to read directory") {
        let entry_path = entry.expect("failed get directory entry").path();
        if entry_path.is_file() {
            // delete everything except the data-layers
            if !entry_path
                .to_str()
                .expect("failed to get string from path")
                .contains("data-layer")
            {
                fs::remove_file(entry_path).expect("failed to remove file")
            }
        }
    }
}

#[test]
fn test_resumable_seal_skip_proofs_v1() {
    let porep_id_v1: u64 = 0; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
    run_resumable_seal::<SectorShape2KiB>(true, 0, &porep_id);
    run_resumable_seal::<SectorShape2KiB>(true, 1, &porep_id);
}

#[test]
fn test_resumable_seal_skip_proofs_v1_1() {
    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    run_resumable_seal::<SectorShape2KiB>(true, 0, &porep_id);
    run_resumable_seal::<SectorShape2KiB>(true, 1, &porep_id);
}

#[test]
#[ignore]
fn test_resumable_seal_v1() {
    let porep_id_v1: u64 = 0; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
    run_resumable_seal::<SectorShape2KiB>(false, 0, &porep_id);
    run_resumable_seal::<SectorShape2KiB>(false, 1, &porep_id);
}

#[test]
#[ignore]
fn test_resumable_seal_v1_1() {
    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    run_resumable_seal::<SectorShape2KiB>(false, 0, &porep_id);
    run_resumable_seal::<SectorShape2KiB>(false, 1, &porep_id);
}

/// Create a seal, delete a layer and resume
///
/// The current code works on two layers only. The `layer_to_delete` specifies (zero-based) which
/// layer should be deleted.
fn run_resumable_seal<Tree: 'static + MerkleTreeTrait>(
    skip_proofs: bool,
    layer_to_delete: usize,
    porep_id: &[u8; 32],
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
    let cache_dir = tempfile::tempdir().expect("failed to create temp dir");

    let config = porep_config(sector_size, *porep_id);
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
    std::fs::remove_file(&layers[layer_to_delete]).expect("failed to remove layer");
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
    winning_post::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, false)?;
    winning_post::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, true)
}

#[test]
#[ignore]
fn test_winning_post_4kib_sub_8_2() -> Result<()> {
    winning_post::<SectorShape4KiB>(SECTOR_SIZE_4_KIB, false)?;
    winning_post::<SectorShape4KiB>(SECTOR_SIZE_4_KIB, true)
}

#[test]
#[ignore]
fn test_winning_post_16kib_sub_8_8() -> Result<()> {
    winning_post::<SectorShape16KiB>(SECTOR_SIZE_16_KIB, false)?;
    winning_post::<SectorShape16KiB>(SECTOR_SIZE_16_KIB, true)
}

#[test]
#[ignore]
fn test_winning_post_32kib_top_8_8_2() -> Result<()> {
    winning_post::<SectorShape32KiB>(SECTOR_SIZE_32_KIB, false)?;
    winning_post::<SectorShape32KiB>(SECTOR_SIZE_32_KIB, true)
}

#[test]
fn test_winning_post_empty_sector_challenge() -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let sector_count = 0;
    let sector_size = SECTOR_SIZE_2_KIB;

    let (_, _, _, _) =
        create_seal::<_, SectorShape2KiB>(rng, sector_size, prover_id, true, &ARBITRARY_POREP_ID)?;

    let random_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        typ: PoStType::Winning,
        priority: false,
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

fn winning_post<Tree: 'static + MerkleTreeTrait>(sector_size: u64, fake: bool) -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let (sector_id, replica, comm_r, cache_dir) = if fake {
        create_fake_seal::<_, Tree>(rng, sector_size, &ARBITRARY_POREP_ID)?
    } else {
        create_seal::<_, Tree>(rng, sector_size, prover_id, true, &ARBITRARY_POREP_ID)?
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
    let challenges = generate_fallback_sector_challenges::<Tree>(
        &config,
        &randomness,
        &vec![sector_id],
        prover_id,
    )?;

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

    window_post::<SectorShape2KiB>(sector_size, sector_count / 2, sector_count, false)?;
    window_post::<SectorShape2KiB>(sector_size, sector_count / 2, sector_count, true)
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

    window_post::<SectorShape2KiB>(sector_size, 2 * sector_count, sector_count, false)?;
    window_post::<SectorShape2KiB>(sector_size, 2 * sector_count, sector_count, true)
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

    window_post::<SectorShape4KiB>(sector_size, 2 * sector_count, sector_count, false)?;
    window_post::<SectorShape4KiB>(sector_size, 2 * sector_count, sector_count, true)
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

    window_post::<SectorShape16KiB>(sector_size, 2 * sector_count, sector_count, false)?;
    window_post::<SectorShape16KiB>(sector_size, 2 * sector_count, sector_count, true)
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

    window_post::<SectorShape32KiB>(sector_size, 2 * sector_count, sector_count, false)?;
    window_post::<SectorShape32KiB>(sector_size, 2 * sector_count, sector_count, true)
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

    window_post::<SectorShape2KiB>(sector_size, 2 * sector_count - 1, sector_count, false)?;
    window_post::<SectorShape2KiB>(sector_size, 2 * sector_count - 1, sector_count, true)
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

    window_post::<SectorShape2KiB>(sector_size, sector_count, sector_count, false)?;
    window_post::<SectorShape2KiB>(sector_size, sector_count, sector_count, true)
}

fn window_post<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    total_sector_count: usize,
    sector_count: usize,
    fake: bool,
) -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let mut sectors = Vec::with_capacity(total_sector_count);
    let mut pub_replicas = BTreeMap::new();
    let mut priv_replicas = BTreeMap::new();

    let prover_fr: <Tree::Hasher as Hasher>::Domain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    for _ in 0..total_sector_count {
        let (sector_id, replica, comm_r, cache_dir) = if fake {
            create_fake_seal::<_, Tree>(rng, sector_size, &ARBITRARY_POREP_ID)?
        } else {
            create_seal::<_, Tree>(rng, sector_size, prover_id, true, &ARBITRARY_POREP_ID)?
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
        .map(|_| rand::random::<u8>())
        .collect();

    let mut piece_file = NamedTempFile::new()?;
    piece_file.write_all(&piece_bytes)?;
    piece_file.as_file_mut().sync_all()?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    Ok((piece_file, piece_bytes))
}

fn porep_config(sector_size: u64, porep_id: [u8; 32]) -> PoRepConfig {
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
    }
}

fn run_seal_pre_commit_phase1<Tree: 'static + MerkleTreeTrait>(
    config: PoRepConfig,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: [u8; 32],
    cache_dir: &tempfile::TempDir,
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
    let comm_d = pre_commit_output.comm_d;
    let comm_r = pre_commit_output.comm_r;

    let mut unseal_file = NamedTempFile::new()?;
    let phase1_output = seal_commit_phase1::<_, Tree>(
        config,
        cache_dir_path,
        sealed_sector_file.path(),
        prover_id,
        sector_id,
        ticket,
        seed,
        pre_commit_output,
        &piece_infos,
    )?;

    clear_cache::<Tree>(cache_dir_path)?;

    let commit_output = seal_commit_phase2(config, phase1_output, prover_id, sector_id)?;

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

fn create_seal<R: Rng, Tree: 'static + MerkleTreeTrait>(
    rng: &mut R,
    sector_size: u64,
    prover_id: ProverId,
    skip_proof: bool,
    porep_id: &[u8; 32],
) -> Result<(SectorId, NamedTempFile, Commitment, tempfile::TempDir)> {
    init_logger();

    let (mut piece_file, piece_bytes) = generate_piece_file(sector_size)?;
    let sealed_sector_file = NamedTempFile::new()?;
    let cache_dir = tempfile::tempdir().expect("failed to create temp dir");

    let config = porep_config(sector_size, *porep_id);
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
        .expect("failed to proof");
    }

    Ok((sector_id, sealed_sector_file, comm_r, cache_dir))
}

fn create_fake_seal<R: rand::Rng, Tree: 'static + MerkleTreeTrait>(
    mut rng: &mut R,
    sector_size: u64,
    porep_id: &[u8; 32],
) -> Result<(SectorId, NamedTempFile, Commitment, tempfile::TempDir)> {
    init_logger();

    let sealed_sector_file = NamedTempFile::new()?;

    let config = PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS.read().unwrap().get(&sector_size).unwrap(),
        ),
        porep_id: *porep_id,
    };

    let cache_dir = tempfile::tempdir().unwrap();

    let sector_id = rng.gen::<u64>().into();

    let comm_r = fauxrep_aux::<_, _, _, Tree>(
        &mut rng,
        config,
        cache_dir.path(),
        sealed_sector_file.path(),
    )?;

    Ok((sector_id, sealed_sector_file, comm_r, cache_dir))
}
