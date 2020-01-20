use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::sync::atomic::Ordering;

use anyhow::Result;
use log::info;
use rayon::prelude::*;
use tempfile::NamedTempFile;

use fil_proofs_tooling::{measure, FuncMeasurement};
use filecoin_proofs::constants::DEFAULT_POREP_PROOF_PARTITIONS;
use filecoin_proofs::types::{PaddedBytesAmount, PoRepConfig, SectorSize, UnpaddedBytesAmount};
use filecoin_proofs::{
    add_piece, generate_piece_commitment, seal_pre_commit_many, PieceInfo, PoRepProofPartitions,
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
}

pub fn create_piece(piece_bytes: UnpaddedBytesAmount) -> (NamedTempFile, PieceInfo) {
    let mut file = NamedTempFile::new().expect("failed to create piece file");
    let mut writer = BufWriter::new(&mut file);

    for _ in 0..(u64::from(piece_bytes) as usize) {
        writer
            .write_all(&[rand::random::<u8>()][..])
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
) -> (
    PoRepConfig,
    Vec<(SectorId, PreCommitReplicaOutput)>,
    FuncMeasurement<Vec<SealPreCommitOutput>>,
) {
    info!("creating replicas: {:?} - {}", sector_size, qty_sectors);
    let sector_size_unpadded_bytes_ammount =
        UnpaddedBytesAmount::from(PaddedBytesAmount::from(sector_size));

    let porep_config = PoRepConfig {
        sector_size,
        partitions: PoRepProofPartitions(DEFAULT_POREP_PROOF_PARTITIONS.load(Ordering::Relaxed)),
    };

    let mut out: Vec<(SectorId, PreCommitReplicaOutput)> = Default::default();
    let mut sector_ids = Vec::new();
    let mut cache_dirs = Vec::new();
    let mut piece_infos = Vec::new();
    let mut staged_files = Vec::new();
    let mut sealed_files = Vec::new();
    let mut piece_files = Vec::new();

    for _ in 0..qty_sectors {
        sector_ids.push(SectorId::from(rand::random::<u64>()));
        cache_dirs.push(tempfile::tempdir().expect("failed to create cache dir"));

        let staged_file =
            NamedTempFile::new().expect("could not create temp file for staged sector");

        let sealed_file =
            NamedTempFile::new().expect("could not create temp file for sealed sector");

        let (piece_file, piece_info) = create_piece(UnpaddedBytesAmount::from(
            PaddedBytesAmount::from(sector_size),
        ));

        sealed_files.push(sealed_file);
        staged_files.push(staged_file);
        piece_infos.push(vec![piece_info]);
        piece_files.push(piece_file);
    }

    piece_files
        .into_par_iter()
        .zip(staged_files.par_iter_mut())
        .try_for_each(|(mut piece_file, mut staged_file)| -> Result<()> {
            add_piece(
                &mut piece_file,
                &mut staged_file,
                sector_size_unpadded_bytes_ammount,
                &[],
            )?;
            Ok(())
        })
        .expect("failed to add piece");

    let seal_pre_commit_outputs = measure(|| {
        seal_pre_commit_many(
            porep_config,
            &cache_dirs
                .iter()
                .map(|c| c.path().into())
                .collect::<Vec<_>>(),
            &staged_files
                .iter()
                .map(|c| c.path().into())
                .collect::<Vec<_>>(),
            &sealed_files
                .iter()
                .map(|c| c.path().into())
                .collect::<Vec<_>>(),
            &(0..qty_sectors).map(|_| PROVER_ID).collect::<Vec<_>>(),
            &sector_ids,
            &(0..qty_sectors).map(|_| TICKET_BYTES).collect::<Vec<_>>(),
            &piece_infos,
        )
    })
    .expect("seal_pre_commit produced an error");

    let priv_infos = sealed_files
        .iter()
        .zip(seal_pre_commit_outputs.return_value.iter())
        .zip(cache_dirs.into_iter())
        .map(|((sealed_file, seal_pre_commit_output), cache_dir)| {
            PrivateReplicaInfo::new(
                sealed_file.path().to_str().unwrap().to_string(),
                seal_pre_commit_output.comm_r,
                cache_dir.into_path(),
            )
            .expect("failed to create PrivateReplicaInfo")
        })
        .collect::<Vec<_>>();

    let pub_infos = seal_pre_commit_outputs
        .return_value
        .iter()
        .map(|sp| PublicReplicaInfo::new(sp.comm_r).expect("failed to create PublicReplicaInfo"))
        .collect::<Vec<_>>();

    for (((sector_id, piece_info), priv_info), pub_info) in sector_ids
        .into_iter()
        .zip(piece_infos.into_iter())
        .zip(priv_infos.into_iter())
        .zip(pub_infos.into_iter())
    {
        out.push((
            sector_id,
            PreCommitReplicaOutput {
                piece_info,
                private_replica_info: priv_info,
                public_replica_info: pub_info,
            },
        ));
    }

    (porep_config, out, seal_pre_commit_outputs)
}
