use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::sync::atomic::Ordering;

use tempfile::NamedTempFile;

use fil_proofs_tooling::{measure, FuncMeasurement};
use filecoin_proofs::constants::DEFAULT_POREP_PROOF_PARTITIONS;
use filecoin_proofs::types::{PaddedBytesAmount, PoRepConfig, SectorSize, UnpaddedBytesAmount};
use filecoin_proofs::{
    add_piece, generate_piece_commitment, seal_pre_commit, PieceInfo, PoRepProofPartitions,
    PrivateReplicaInfo, PublicReplicaInfo, SealPreCommitOutput,
};
use storage_proofs::sector::SectorId;

pub(super) const CHALLENGE_COUNT: u64 = 1;
pub(super) const PROVER_ID: [u8; 32] = [9; 32];
pub(super) const RANDOMNESS: [u8; 32] = [44; 32];
pub(super) const TICKET_BYTES: [u8; 32] = [1; 32];

pub struct PreCommitReplicaOutput {
    pub piece_info: Vec<PieceInfo>,
    pub private_replica_info: PrivateReplicaInfo,
    pub public_replica_info: PublicReplicaInfo,
    pub measurement: FuncMeasurement<SealPreCommitOutput>,
}

pub fn create_piece(piece_bytes: UnpaddedBytesAmount) -> (NamedTempFile, PieceInfo) {
    let mut file = NamedTempFile::new().expect("failed to create piece file");
    let mut writer = BufWriter::new(&mut file);

    for _ in 0..(u64::from(piece_bytes) as usize) {
        writer
            .write(&[rand::random::<u8>()][..])
            .expect("failed to write buffer");
    }
    drop(writer);

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
    sector_size: SectorSize,
    qty_sectors: usize,
) -> (PoRepConfig, Vec<(SectorId, PreCommitReplicaOutput)>) {
    let sector_size_unpadded_bytes_ammount =
        UnpaddedBytesAmount::from(PaddedBytesAmount::from(sector_size));

    let porep_config = PoRepConfig {
        sector_size,
        partitions: PoRepProofPartitions(DEFAULT_POREP_PROOF_PARTITIONS.load(Ordering::Relaxed)),
    };

    let mut out: Vec<(SectorId, PreCommitReplicaOutput)> = Default::default();

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
            PaddedBytesAmount::from(sector_size),
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

        out.push((
            sector_id,
            PreCommitReplicaOutput {
                piece_info: vec![piece_info],
                measurement: seal_pre_commit_output,
                private_replica_info: priv_info,
                public_replica_info: pub_info,
            },
        ));
    }

    (porep_config, out)
}
