use std::cmp::min;
use std::fs::File;
use std::io::{BufWriter, Seek, Write};

use filecoin_proofs::{
    add_piece, clear_cache, fauxrep_aux, generate_synth_proofs, seal_pre_commit_phase1,
    seal_pre_commit_phase2, validate_cache_for_commit, validate_cache_for_precommit_phase2,
    MerkleTreeTrait, PaddedBytesAmount, PieceInfo, PoRepConfig, PrivateReplicaInfo,
    PublicReplicaInfo, SealPreCommitOutput, SealPreCommitPhase1Output, SectorSize,
    UnpaddedBytesAmount,
};
use log::info;
use merkletree::store::StoreConfig;
use rand::{random, thread_rng, RngCore};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use storage_proofs_core::{
    api_version::{ApiFeature, ApiVersion},
    sector::SectorId,
    util::NODE_SIZE,
};
use storage_proofs_porep::stacked::Labels;
use tempfile::{tempdir, NamedTempFile};

use crate::{measure, FuncMeasurement};

pub const PROVER_ID: [u8; 32] = [9; 32];
pub const RANDOMNESS: [u8; 32] = [44; 32];
pub const TICKET_BYTES: [u8; 32] = [1; 32];

pub struct PreCommitReplicaOutput<Tree: 'static + MerkleTreeTrait> {
    pub piece_info: Vec<PieceInfo>,
    pub private_replica_info: PrivateReplicaInfo<Tree>,
    pub public_replica_info: PublicReplicaInfo,
}

pub fn create_piece(piece_bytes: UnpaddedBytesAmount, use_random: bool) -> NamedTempFile {
    info!("create_piece");
    let mut file = NamedTempFile::new().expect("failed to create piece file");
    if use_random {
        let mut writer = BufWriter::new(&mut file);
        let mut len = u64::from(piece_bytes) as usize;
        let chunk_size = 256 * 1024 * 1024;
        let mut buffer = vec![0u8; chunk_size];
        thread_rng().fill_bytes(&mut buffer);

        while len > 0 {
            let to_write = min(len, chunk_size);
            writer
                .write_all(&buffer[..to_write])
                .expect("failed to write buffer");
            len -= to_write;
        }
    } else {
        let f = File::create(file.path()).expect("failed to create piece file");
        f.set_len(u64::from(piece_bytes))
            .expect("failed to set file length");
    }
    assert_eq!(
        u64::from(piece_bytes),
        file.as_file()
            .metadata()
            .expect("failed to get file metadata")
            .len()
    );

    file.as_file_mut()
        .sync_all()
        .expect("failed to sync piece file");

    file.as_file_mut()
        .rewind()
        .expect("failed to seek to beginning of piece file");

    file
}

/// Create a replica for a single sector
pub fn create_replica<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    fake_replica: bool,
    api_version: ApiVersion,
    api_features: Vec<ApiFeature>,
) -> (SectorId, PreCommitReplicaOutput<Tree>) {
    let (_porep_config, result) = create_replicas::<Tree>(
        SectorSize(sector_size),
        1,
        false,
        fake_replica,
        api_version,
        api_features,
    );
    // Extract the sector ID and replica output out of the result
    result
        .expect("create_replicas() failed when called with only_add==false")
        .0
        .pop()
        .expect("failed to create replica outputs")
}

#[allow(clippy::type_complexity)]
pub fn create_replicas<Tree: 'static + MerkleTreeTrait>(
    sector_size: SectorSize,
    qty_sectors: usize,
    only_add: bool,
    fake_replicas: bool,
    api_version: ApiVersion,
    api_features: Vec<ApiFeature>,
) -> (
    PoRepConfig,
    Option<(
        Vec<(SectorId, PreCommitReplicaOutput<Tree>)>,
        FuncMeasurement<Vec<SealPreCommitOutput>>,
    )>,
) {
    info!("creating replicas: {:?} - {}", sector_size, qty_sectors);
    let sector_size_unpadded_bytes_ammount =
        UnpaddedBytesAmount::from(PaddedBytesAmount::from(sector_size));

    let porep_config = get_porep_config(u64::from(sector_size), api_version, api_features);

    let mut out: Vec<(SectorId, PreCommitReplicaOutput<Tree>)> = Default::default();
    let mut sector_ids = Vec::new();
    let mut cache_dirs = Vec::new();
    let mut staged_files = Vec::new();
    let mut sealed_files = Vec::new();

    for i in 0..qty_sectors {
        info!("creating sector {}/{}", i, qty_sectors);

        sector_ids.push(SectorId::from(random::<u64>()));
        cache_dirs.push(tempdir().expect("failed to create cache dir"));

        let staged_file =
            NamedTempFile::new().expect("could not create temp file for staged sector");

        let sealed_file =
            NamedTempFile::new().expect("could not create temp file for sealed sector");
        // Prevent that the sealed sector file gets deleted when `sealed_file` runs out of scope
        let (_, sealed_path) = sealed_file
            .keep()
            .expect("failed to leep sealed sector file around");

        sealed_files.push(sealed_path);
        staged_files.push(staged_file);
    }

    let piece_files: Vec<_> = (0..qty_sectors)
        .into_par_iter()
        .map(|_i| {
            create_piece(
                UnpaddedBytesAmount::from(PaddedBytesAmount::from(sector_size)),
                !fake_replicas,
            )
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
        .expect("failed to add piece");
        piece_infos.push(vec![info]);
    }

    if only_add {
        return (porep_config, None);
    }

    let seal_pre_commit_outputs = measure(|| {
        if fake_replicas {
            let mut rng = thread_rng();

            let phase1s = cache_dirs
                .par_iter()
                .zip(sector_ids.par_iter())
                .map(|(cache_dir, sector_id)| {
                    let mut tmp_store_config =
                        StoreConfig::new(cache_dir.path(), format!("tmp-config-{}", sector_id), 0);
                    tmp_store_config.size = Some(u64::from(sector_size) as usize / NODE_SIZE);
                    let f = File::create(StoreConfig::data_path(
                        &tmp_store_config.path,
                        &tmp_store_config.id,
                    ))
                    .expect("failed to create tmp file for fake sealing");
                    f.set_len(u64::from(sector_size))
                        .expect("failed to set file length");

                    SealPreCommitPhase1Output {
                        labels: Labels::new(vec![tmp_store_config.clone(); cache_dirs.len()]),
                        config: tmp_store_config,
                        comm_d: [0; 32],
                    }
                })
                .collect::<Vec<_>>();

            phase1s
                .into_iter()
                .enumerate()
                .map(|(i, phase1)| {
                    validate_cache_for_precommit_phase2::<_, _, Tree>(
                        &cache_dirs[i],
                        &sealed_files[i],
                        &phase1,
                    )?;
                    let comm_r = fauxrep_aux::<_, _, _, Tree>(
                        &mut rng,
                        &porep_config,
                        &cache_dirs[i].path(),
                        &sealed_files[i],
                    )?;
                    Ok(SealPreCommitOutput {
                        comm_r,
                        comm_d: phase1.comm_d,
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        } else {
            let phase1s = cache_dirs
                .par_iter()
                .zip(staged_files.par_iter())
                .zip(sealed_files.par_iter())
                .zip(sector_ids.par_iter())
                .zip(piece_infos.par_iter())
                .map(
                    |((((cache_dir, staged_file), sealed_file), sector_id), piece_infos)| {
                        seal_pre_commit_phase1(
                            &porep_config,
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
                    validate_cache_for_precommit_phase2::<_, _, Tree>(
                        &cache_dirs[i],
                        &sealed_files[i],
                        &phase1,
                    )?;
                    let res = seal_pre_commit_phase2(
                        &porep_config,
                        phase1,
                        &cache_dirs[i],
                        &sealed_files[i],
                    )?;

                    if porep_config.feature_enabled(ApiFeature::SyntheticPoRep) {
                        info!("SyntheticPoRep is enabled");
                        generate_synth_proofs::<std::path::PathBuf, Tree>(
                            &porep_config,
                            cache_dirs[i].path().to_path_buf(),
                            sealed_files[i].clone(),
                            PROVER_ID,
                            sector_ids[i],
                            TICKET_BYTES,
                            res.clone(),
                            piece_infos[i].as_slice(),
                        )
                        .expect("failed to generate synthetic proofs");
                        clear_cache(cache_dirs[i].path())
                            .expect("failed to clear synthetic porep layer data");
                    } else {
                        info!("SyntheticPoRep is NOT enabled");
                        validate_cache_for_commit::<_, _, Tree>(&cache_dirs[i], &sealed_files[i])
                            .expect("failed to validate_cache_for_commit");
                    }

                    Ok(res)
                })
                .collect::<Result<Vec<_>, _>>()
        }
    })
    .expect("seal_pre_commit produced an error");

    info!("collecting infos");

    let priv_infos = sealed_files
        .iter()
        .zip(seal_pre_commit_outputs.return_value.iter())
        .zip(cache_dirs)
        .map(|((sealed_file, seal_pre_commit_output), cache_dir)| {
            PrivateReplicaInfo::new(
                sealed_file.to_path_buf(),
                seal_pre_commit_output.comm_r,
                cache_dir.keep(),
            )
            .expect("failed to create PrivateReplicaInfo")
        });

    let pub_infos = seal_pre_commit_outputs
        .return_value
        .iter()
        .map(|sp| PublicReplicaInfo::new(sp.comm_r).expect("failed to create PublicReplicaInfo"));

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

pub fn get_porep_config(
    sector_size: u64,
    api_version: ApiVersion,
    features: Vec<ApiFeature>,
) -> PoRepConfig {
    let arbitrary_porep_id = [99; 32];
    PoRepConfig::new_groth16_with_features(sector_size, arbitrary_porep_id, api_version, features)
        .expect("cannot set PoRep config")
}
