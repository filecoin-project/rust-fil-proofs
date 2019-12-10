use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use filecoin_proofs::constants::{DEFAULT_POREP_PROOF_PARTITIONS, SECTOR_SIZE_16_MIB};
use filecoin_proofs::types::{
    PaddedBytesAmount, PieceInfo, PoRepConfig, PoRepProofPartitions, PoStConfig,
    SealPreCommitOutput, SectorSize, UnpaddedBytesAmount,
};
use filecoin_proofs::Candidate;
use filecoin_proofs::{
    add_piece, generate_candidates, generate_piece_commitment, generate_post, seal_commit,
    seal_pre_commit, PrivateReplicaInfo,
};
use storage_proofs::sector::SectorId;
use tempfile::NamedTempFile;

// The seed for the rng used to generate which sectors to challenge.
const CHALLENGE_SEED: [u8; 32] = [0; 32];
const PROVER_ID: [u8; 32] = [0; 32];
const SECTOR_ID: u64 = 0;
const N_PARTITIONS: PoRepProofPartitions = DEFAULT_POREP_PROOF_PARTITIONS;
const SECTOR_SIZE: u64 = SECTOR_SIZE_16_MIB;
//const SECTOR_SIZE: u64 = SECTOR_SIZE_ONE_KIB;
const POREP_CONFIG: PoRepConfig = PoRepConfig {
    sector_size: SectorSize(SECTOR_SIZE),
    partitions: N_PARTITIONS,
};
const SEED: [u8; 32] = [0; 32];
const TICKET: [u8; 32] = [0; 32];
const CHALLENGE_COUNT: u64 = 1;
const POST_CONFIG: PoStConfig = PoStConfig {
    sector_size: SectorSize(SECTOR_SIZE),
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

pub fn generate_seal_fixture(cache_dir_path: &Path) -> (SealPreCommitOutput, Vec<PieceInfo>) {
    let staged_file = NamedTempFile::new().expect("could not create temp file for staged sector");
    let sealed_file = NamedTempFile::new().expect("could not create temp file for sealed sector");

    let piece_infos = generate_piece_infos(&staged_file);

    let seal_pre_commit_output = seal_pre_commit(
        POREP_CONFIG,
        cache_dir_path,
        staged_file.path(),
        sealed_file.path(),
        PROVER_ID,
        SectorId::from(SECTOR_ID),
        TICKET,
        &piece_infos,
    )
    .expect("could not pre seal commit");

    (seal_pre_commit_output, piece_infos)
}

pub fn do_generate_seal(
    cache_dir_path: &Path,
    seal_pre_commit_output: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
) {
    seal_commit(
        POREP_CONFIG,
        cache_dir_path,
        PROVER_ID,
        SectorId::from(SECTOR_ID),
        TICKET,
        SEED,
        seal_pre_commit_output,
        &piece_infos,
    )
    .expect("could not seal commit");
}

pub fn generate_priv_replica_info_fixture() -> BTreeMap<SectorId, PrivateReplicaInfo> {
    let cache_dir = tempfile::tempdir().expect("could not create temp dir for cache");

    let (seal_pre_commit_output, piece_infos) = generate_seal_fixture(cache_dir.path());
    let comm_r = seal_pre_commit_output.comm_r;
    do_generate_seal(cache_dir.path(), seal_pre_commit_output, &piece_infos);

    let sealed_file = NamedTempFile::new().expect("could not create temp file for sealed sector");
    let sealed_path_string = sealed_file
        .path()
        .to_str()
        .expect("file name is not a UTF-8 string")
        .to_string();
    let priv_replica_info =
        PrivateReplicaInfo::new(sealed_path_string, comm_r, cache_dir.into_path())
            .expect("could not create private replica info");

    let mut priv_replica_infos: BTreeMap<SectorId, PrivateReplicaInfo> = BTreeMap::new();
    priv_replica_infos.insert(SectorId::from(SECTOR_ID), priv_replica_info);
    priv_replica_infos
}

pub fn generate_candidates_fixture(
    priv_replica_info: &BTreeMap<SectorId, PrivateReplicaInfo>,
) -> Vec<Candidate> {
    generate_candidates(
        POST_CONFIG,
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
    generate_post(
        POST_CONFIG,
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
