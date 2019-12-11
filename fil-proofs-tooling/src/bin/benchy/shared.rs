use std::io::{Seek, SeekFrom, Write};

use tempfile::NamedTempFile;

use fil_proofs_tooling::{measure, FuncMeasurement};
use filecoin_proofs::constants::DEFAULT_POREP_PROOF_PARTITIONS;
use filecoin_proofs::types::{PaddedBytesAmount, PoRepConfig, SectorSize, UnpaddedBytesAmount};
use filecoin_proofs::{
    add_piece, generate_piece_commitment, seal_commit, seal_pre_commit, PieceInfo,
    PrivateReplicaInfo, PublicReplicaInfo, SealCommitOutput, SealPreCommitOutput,
};
use storage_proofs::sector::SectorId;

pub(super) const CHALLENGE_COUNT: u64 = 1;
pub(super) const PROVER_ID: [u8; 32] = [0; 32];
pub(super) const RANDOMNESS: [u8; 32] = [0; 32];
pub(super) const TICKET_BYTES: [u8; 32] = [1; 32];

pub struct PreCommitReplicaOutput {
    pub piece_info: Vec<PieceInfo>,
    pub private_replica_info: PrivateReplicaInfo,
    pub public_replica_info: PublicReplicaInfo,
    pub measurement: FuncMeasurement<SealPreCommitOutput>,
}

pub struct CommitReplicaOutput {
    pub measurement: FuncMeasurement<SealCommitOutput>,
}

pub fn create_piece(piece_bytes: UnpaddedBytesAmount) -> (NamedTempFile, PieceInfo) {
    let buf: Vec<u8> = (0..usize::from(piece_bytes))
        .map(|_| rand::random::<u8>())
        .collect();

    let mut file = NamedTempFile::new().expect("failed to create piece file");

    file.write_all(&buf)
        .expect("failed to write buffer to piece file");

    file.as_file_mut()
        .sync_all()
        .expect("failed to sync piece file");

    file.as_file_mut()
        .seek(SeekFrom::Start(0))
        .expect("failed to seek to beginning of piece file");

    let info = generate_piece_commitment(file.as_file_mut(), piece_bytes)
        .expect("failed to generate piece commitment");

    file.as_file_mut()
        .seek(SeekFrom::Start(0))
        .expect("failed to seek to beginning of piece file");

    (file, info)
}

pub fn create_replicas(
    sector_size_bytes: usize,
    qty_sectors: usize,
) -> (
    PoRepConfig,
    std::collections::BTreeMap<SectorId, PreCommitReplicaOutput>,
) {
    let sector_size_unpadded_bytes_ammount =
        UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size_bytes as u64));

    let porep_config = PoRepConfig {
        sector_size: SectorSize(sector_size_bytes as u64),
        partitions: DEFAULT_POREP_PROOF_PARTITIONS,
    };

    let mut out: std::collections::BTreeMap<SectorId, PreCommitReplicaOutput> = Default::default();

    for _ in 0..qty_sectors {
        let sector_id = SectorId::from(rand::random::<u64>());

        let cache_dir = tempfile::tempdir().expect("failed to create cache dir");

        let mut staged_file =
            NamedTempFile::new().expect("could not create temp file for staged sector");

        let sealed_file =
            NamedTempFile::new().expect("could not create temp file for sealed sector");

        let sealed_path_string = sealed_file
            .path()
            .to_str()
            .expect("file name is not a UTF-8 string");

        let (mut piece_file, piece_info) = create_piece(UnpaddedBytesAmount::from(
            PaddedBytesAmount(sector_size_bytes as u64),
        ));

        add_piece(
            &mut piece_file,
            &mut staged_file,
            sector_size_unpadded_bytes_ammount,
            &[],
        )
        .expect("failed to add piece to staged sector");

        let seal_pre_commit_output = measure(|| {
            seal_pre_commit(
                porep_config,
                cache_dir.path(),
                staged_file.path(),
                sealed_file.path(),
                PROVER_ID,
                sector_id,
                TICKET_BYTES,
                &[piece_info.clone()],
            )
        })
        .expect("seal_pre_commit produced an error");

        let priv_info = PrivateReplicaInfo::new(
            sealed_path_string.to_string(),
            seal_pre_commit_output.return_value.comm_r,
            cache_dir.into_path(),
        )
        .expect("failed to create PrivateReplicaInfo");

        let pub_info = PublicReplicaInfo::new(seal_pre_commit_output.return_value.comm_r)
            .expect("failed to create PublicReplicaInfo");

        out.insert(
            sector_id,
            PreCommitReplicaOutput {
                piece_info: vec![piece_info],
                measurement: seal_pre_commit_output,
                private_replica_info: priv_info,
                public_replica_info: pub_info,
            },
        );
    }

    (porep_config, out)
}

pub fn prove_replicas(
    cfg: PoRepConfig,
    input: &std::collections::BTreeMap<SectorId, PreCommitReplicaOutput>,
) -> std::collections::BTreeMap<SectorId, CommitReplicaOutput> {
    let mut out: std::collections::BTreeMap<SectorId, CommitReplicaOutput> = Default::default();

    for (k, v) in input.iter() {
        let m = measure(|| {
            seal_commit(
                cfg,
                v.private_replica_info.cache_dir_path(),
                PROVER_ID,
                *k,
                TICKET_BYTES,
                RANDOMNESS,
                v.measurement.return_value.clone(),
                &v.piece_info,
            )
        })
        .expect("failed to prove sector");

        out.insert(*k, CommitReplicaOutput { measurement: m });
    }

    out
}
