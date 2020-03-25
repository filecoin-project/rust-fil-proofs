use std::io::{BufWriter, Seek, SeekFrom, Write};

use log::info;
use rand::RngCore;
use rayon::prelude::*;
use tempfile::NamedTempFile;

use fil_proofs_tooling::{measure, FuncMeasurement};
use filecoin_proofs::constants::POREP_PARTITIONS;
use filecoin_proofs::types::{PaddedBytesAmount, PoRepConfig, SectorSize, UnpaddedBytesAmount};
use filecoin_proofs::{
    add_piece, seal_pre_commit_phase1, seal_pre_commit_phase2, validate_cache_for_precommit_phase2,
    PieceInfo, PoRepProofPartitions, PrivateReplicaInfo, PublicReplicaInfo, SealPreCommitOutput,
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

pub fn create_piece(piece_bytes: UnpaddedBytesAmount) -> NamedTempFile {
    info!("create_piece");
    let mut file = NamedTempFile::new().expect("failed to create piece file");
    {
        let mut writer = BufWriter::new(&mut file);
        let mut len = u64::from(piece_bytes) as usize;
        let chunk_size = 8 * 1024 * 1024;
        let mut buffer = vec![0u8; chunk_size];
        rand::thread_rng().fill_bytes(&mut buffer);

        while len > 0 {
            let to_write = std::cmp::min(len, chunk_size);
            writer
                .write_all(&buffer[..to_write])
                .expect("failed to write buffer");
            len -= to_write;
        }
    }
    assert_eq!(
        u64::from(piece_bytes),
        file.as_file().metadata().unwrap().len()
    );

    file.as_file_mut()
        .sync_all()
        .expect("failed to sync piece file");

    file.as_file_mut()
        .seek(SeekFrom::Start(0))
        .expect("failed to seek to beginning of piece file");

    file
}

#[allow(clippy::type_complexity)]
pub fn create_replicas(
    sector_size: SectorSize,
    qty_sectors: usize,
    only_add: bool,
) -> (
    PoRepConfig,
    Option<(
        Vec<(SectorId, PreCommitReplicaOutput)>,
        FuncMeasurement<Vec<SealPreCommitOutput>>,
    )>,
) {
    info!("creating replicas: {:?} - {}", sector_size, qty_sectors);
    let sector_size_unpadded_bytes_ammount =
        UnpaddedBytesAmount::from(PaddedBytesAmount::from(sector_size));

    let porep_config = PoRepConfig {
        sector_size,
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS
                .read()
                .unwrap()
                .get(&u64::from(sector_size))
                .expect("unknown sector size"),
        ),
    };

    let mut out: Vec<(SectorId, PreCommitReplicaOutput)> = Default::default();
    let mut sector_ids = Vec::new();
    let mut cache_dirs = Vec::new();
    let mut staged_files = Vec::new();
    let mut sealed_files = Vec::new();

    for i in 0..qty_sectors {
        info!("creating sector {}/{}", i, qty_sectors);

        sector_ids.push(SectorId::from(rand::random::<u64>()));
        cache_dirs.push(tempfile::tempdir().expect("failed to create cache dir"));

        let staged_file =
            NamedTempFile::new().expect("could not create temp file for staged sector");

        let sealed_file =
            NamedTempFile::new().expect("could not create temp file for sealed sector");
        // Persist the sealed replica.
        let (_, replica_path) = sealed_file.keep().expect("failed to persist replica");

        sealed_files.push(replica_path);
        staged_files.push(staged_file);
    }

    let piece_files: Vec<_> = (0..qty_sectors)
        .into_par_iter()
        .map(|_i| {
            create_piece(UnpaddedBytesAmount::from(PaddedBytesAmount::from(
                sector_size,
            )))
        })
        .collect();

    info!("adding pieces");
    let mut piece_infos = Vec::new();
    for (i, (mut piece_file, mut staged_file)) in piece_files
        .into_iter()
        .zip(staged_files.iter_mut())
        .enumerate()
    {
        info!("add piece {}", i);
        let (info, _) = add_piece(
            &mut piece_file,
            &mut staged_file,
            sector_size_unpadded_bytes_ammount,
            &[],
        )
        .unwrap();
        piece_infos.push(vec![info]);
    }

    if only_add {
        return (porep_config, None);
    }

    let seal_pre_commit_outputs = measure(|| {
        let phase1s = cache_dirs
            .par_iter()
            .zip(staged_files.par_iter())
            .zip(sealed_files.par_iter())
            .zip(sector_ids.par_iter())
            .zip(piece_infos.par_iter())
            .map(
                |((((cache_dir, staged_file), sealed_file), sector_id), piece_infos)| {
                    seal_pre_commit_phase1(
                        porep_config,
                        cache_dir,
                        staged_file,
                        sealed_file,
                        PROVER_ID,
                        *sector_id,
                        TICKET_BYTES,
                        piece_infos,
                    )
                },
            )
            .collect::<Result<Vec<_>, _>>()?;

        phase1s
            .into_iter()
            .enumerate()
            .map(|(i, phase1)| {
                validate_cache_for_precommit_phase2(&cache_dirs[i], &sealed_files[i], &phase1)?;
                seal_pre_commit_phase2(porep_config, phase1, &cache_dirs[i], &sealed_files[i])
            })
            .collect::<Result<Vec<_>, _>>()
    })
    .expect("seal_pre_commit produced an error");

    info!("collecting infos");

    let priv_infos = sealed_files
        .iter()
        .zip(seal_pre_commit_outputs.return_value.iter())
        .zip(cache_dirs.into_iter())
        .map(|((sealed_file, seal_pre_commit_output), cache_dir)| {
            PrivateReplicaInfo::new(
                sealed_file.to_path_buf(),
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

    (porep_config, Some((out, seal_pre_commit_outputs)))
}
