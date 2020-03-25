use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use filecoin_proofs::constants::{POREP_PARTITIONS, POST_CHALLENGE_COUNT, SECTOR_SIZE_8_MIB};
use filecoin_proofs::types::{
    PaddedBytesAmount, PieceInfo, PoRepConfig, PoRepProofPartitions, PoStConfig,
    SealPreCommitOutput, SectorSize, UnpaddedBytesAmount,
};
use filecoin_proofs::{
    add_piece, clear_cache, generate_candidates, generate_election_post, generate_piece_commitment,
    seal_commit_phase1, seal_commit_phase2, seal_pre_commit_phase1, seal_pre_commit_phase2,
    validate_cache_for_commit, validate_cache_for_precommit_phase2, Candidate, PoStType,
    PrivateReplicaInfo,
};
use storage_proofs::sector::SectorId;
use tempfile::NamedTempFile;

// The seed for the rng used to generate which sectors to challenge.
const CHALLENGE_SEED: [u8; 32] = [0; 32];
const PROVER_ID: [u8; 32] = [0; 32];
const SECTOR_ID: u64 = 0;
const SECTOR_SIZE: u64 = SECTOR_SIZE_8_MIB;
//const SECTOR_SIZE: u64 = SECTOR_SIZE_ONE_KIB;
const SEED: [u8; 32] = [0; 32];
const TICKET: [u8; 32] = [0; 32];
const CHALLENGE_COUNT: u64 = 1;
const POST_CONFIG: PoStConfig = PoStConfig {
    sector_size: SectorSize(SECTOR_SIZE),
    challenge_count: POST_CHALLENGE_COUNT,
    sector_count: 1,
    typ: PoStType::Election,
    priority: false,
};

fn generate_piece_infos(mut staged_file: &NamedTempFile) -> Vec<PieceInfo> {
    let sector_size_unpadded_bytes_amount =
        UnpaddedBytesAmount::from(PaddedBytesAmount(SECTOR_SIZE));
    // Generate the data from which we will create a replica, we will then prove the continued
    // storage of that replica using the PoSt.
    let piece_bytes: Vec<u8> = (0..usize::from(sector_size_unpadded_bytes_amount))
        .map(|_| rand::random::<u8>())
        .collect();

    let mut piece_file = NamedTempFile::new().expect("could not create piece file");
    piece_file
        .write_all(&piece_bytes)
        .expect("could not write into piece file");
    piece_file
        .as_file_mut()
        .sync_all()
        .expect("could not sync price file");
    piece_file
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .expect("could not seek piece file");

    let piece_info =
        generate_piece_commitment(piece_file.as_file_mut(), sector_size_unpadded_bytes_amount)
            .expect("could not generate piece commitment");
    piece_file
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .expect("could not seek piece file");

    add_piece(
        &mut piece_file,
        &mut staged_file,
        sector_size_unpadded_bytes_amount,
        &[],
    )
    .expect("could not add pice file to stages file");

    vec![piece_info]
}

pub fn generate_seal_fixture(
    cache_dir_path: &Path,
    replica_path: &Path,
) -> (SealPreCommitOutput, Vec<PieceInfo>) {
    let staged_file = NamedTempFile::new().expect("could not create temp file for staged sector");

    let piece_infos = generate_piece_infos(&staged_file);

    let porep_config = PoRepConfig {
        sector_size: SectorSize(SECTOR_SIZE),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS.read().unwrap().get(&SECTOR_SIZE).unwrap(),
        ),
    };
    let phase1_output = seal_pre_commit_phase1(
        porep_config,
        cache_dir_path,
        staged_file.path(),
        replica_path,
        PROVER_ID,
        SectorId::from(SECTOR_ID),
        TICKET,
        &piece_infos,
    )
    .expect("could not pre seal commit phase1");

    validate_cache_for_precommit_phase2(cache_dir_path, replica_path, &phase1_output)
        .expect("could not validate cache for precommit phase2");

    let seal_pre_commit_output =
        seal_pre_commit_phase2(porep_config, phase1_output, cache_dir_path, replica_path)
            .expect("could not pre seal commit phase2");

    (seal_pre_commit_output, piece_infos)
}

pub fn do_generate_seal(
    cache_dir_path: &Path,
    replica_path: &Path,
    seal_pre_commit_output: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
) {
    let porep_config = PoRepConfig {
        sector_size: SectorSize(SECTOR_SIZE),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS.read().unwrap().get(&SECTOR_SIZE).unwrap(),
        ),
    };

    validate_cache_for_commit(cache_dir_path, replica_path)
        .expect("could not validate cache for commit");

    let phase1_output = seal_commit_phase1(
        porep_config,
        cache_dir_path,
        &replica_path.to_path_buf(),
        PROVER_ID,
        SectorId::from(SECTOR_ID),
        TICKET,
        SEED,
        seal_pre_commit_output,
        &piece_infos,
    )
    .expect("could not seal commit phase1");

    clear_cache(cache_dir_path).expect("could not clear cache");

    seal_commit_phase2(
        porep_config,
        phase1_output,
        PROVER_ID,
        SectorId::from(SECTOR_ID),
    )
    .expect("could not seal commit phase2");
}

pub fn generate_priv_replica_info_fixture() -> BTreeMap<SectorId, PrivateReplicaInfo> {
    let cache_dir = tempfile::tempdir().expect("could not create temp dir for cache");
    let replica_file = NamedTempFile::new().expect("could not create temp file for replica");
    // Persist the sealed replica.
    let (_, replica_path) = replica_file.keep().expect("failed to persist replica");

    let (seal_pre_commit_output, piece_infos) =
        generate_seal_fixture(cache_dir.path(), &replica_path);
    let comm_r = seal_pre_commit_output.comm_r;
    do_generate_seal(
        cache_dir.path(),
        &replica_path,
        seal_pre_commit_output,
        &piece_infos,
    );

    let priv_replica_info = PrivateReplicaInfo::new(replica_path, comm_r, cache_dir.into_path())
        .expect("could not create private replica info");

    let mut priv_replica_infos: BTreeMap<SectorId, PrivateReplicaInfo> = BTreeMap::new();
    priv_replica_infos.insert(SectorId::from(SECTOR_ID), priv_replica_info);
    priv_replica_infos
}

pub fn generate_candidates_fixture(
    priv_replica_info: &BTreeMap<SectorId, PrivateReplicaInfo>,
) -> Vec<Candidate> {
    generate_candidates(
        &POST_CONFIG,
        &CHALLENGE_SEED,
        CHALLENGE_COUNT,
        &priv_replica_info,
        PROVER_ID,
    )
    .expect("failed to generate candidates")
}

pub fn do_generate_post(
    priv_replica_info: &BTreeMap<SectorId, PrivateReplicaInfo>,
    candidates: &[Candidate],
) {
    generate_election_post(
        &POST_CONFIG,
        &CHALLENGE_SEED,
        &priv_replica_info,
        candidates
            .iter()
            .cloned()
            .map(Into::into)
            .collect::<Vec<_>>(),
        PROVER_ID,
    )
    .expect("failed to generate PoSt");
}

pub fn do_generate_post_in_priority(
    priv_replica_info: &BTreeMap<SectorId, PrivateReplicaInfo>,
    candidates: &[Candidate],
) {
    let mut post_config = POST_CONFIG;
    post_config.priority = true;
    //PoStConfig {
    //    sector_size: SectorSize(SECTOR_SIZE),
    //    challenge_count: POST_CHALLENGE_COUNT,
    //    challenged_nodes: POST_CHALLENGED_NODES,
    //    priority: false,
    //};
    generate_election_post(
        &post_config,
        &CHALLENGE_SEED,
        &priv_replica_info,
        candidates
            .iter()
            .cloned()
            .map(Into::into)
            .collect::<Vec<_>>(),
        PROVER_ID,
    )
    .expect("failed to generate PoSt with high priority");
}
