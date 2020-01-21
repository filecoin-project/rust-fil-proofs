use std::fs::{self, File, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use anyhow::{ensure, Context, Result};
use bincode::{deserialize, serialize};
use log::info;
use memmap::MmapOptions;
use merkletree::store::{StoreConfig, DEFAULT_CACHED_ABOVE_BASE_LAYER};
use paired::bls12_381::{Bls12, Fr};
use rayon::prelude::*;
use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::circuit::stacked::StackedCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgraph::{DefaultTreeHasher, Graph};
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::measurements::{measure_op, Operation::CommD};
use storage_proofs::merkle::create_merkle_tree;
use storage_proofs::sector::SectorId;
use storage_proofs::stacked::{
    self, generate_replica_id, CacheKey, ChallengeRequirements, StackedDrg, Tau, TemporaryAux,
    TemporaryAuxCache,
};

use crate::api::util::{as_safe_commitment, commitment_from_fr};
use crate::caches::{get_stacked_params, get_stacked_verifying_key};
use crate::constants::{DefaultPieceHasher, POREP_MINIMUM_CHALLENGES, SINGLE_PARTITION_PROOF_LEN};
use crate::parameters::setup_params;
pub use crate::pieces;
pub use crate::pieces::verify_pieces;
use crate::types::{
    Commitment, PaddedBytesAmount, PieceInfo, PoRepConfig, PoRepProofPartitions, ProverId,
    SealCommitOutput, SealPreCommitOutput, SectorSize, Ticket,
};

#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit(
    porep_config: PoRepConfig,
    cache_path: PathBuf,
    in_path: PathBuf,
    out_path: PathBuf,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: Vec<PieceInfo>,
) -> Result<SealPreCommitOutput> {
    info!("seal_pre_commit: start");

    // TODO: collect multiple to send to `_many`.
    let res = seal_pre_commit_many(
        porep_config,
        &[cache_path],
        &[in_path],
        &[out_path],
        &[prover_id],
        &[sector_id],
        &[ticket],
        &[piece_infos],
    )?;

    info!("seal_pre_commit: end");

    Ok(res
        .into_iter()
        .next()
        .expect("invalid result returned from seal_pre_commit_many"))
}

/// Seals the staged sector at `in_path` in place, saving the resulting replica to `out_path`.
///
/// # Arguments
///
/// * `porep_config` - porep configuration containing the number of bytes in this sector.
/// * `cache_path` - path to a directory in which the sector data's Merkle Tree can be written.
/// * `in_path` - the path where the unsealed sector data is read.
/// * `out_path` - the path where the sealed sector data will be written.
/// * `prover_id` - the prover-id that is sealing this sector.
/// * `sector_id` - the sector-id of this sector.
/// * `ticket` - the ticket that will be used to generate this sector's replica-id.
/// * `piece_infos` - each piece's info (number of bytes and commitment) in this sector.
#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit_many(
    porep_config: PoRepConfig,
    cache_paths: &[PathBuf],
    in_paths: &[PathBuf],
    out_paths: &[PathBuf],
    prover_ids: &[ProverId],
    sector_ids: &[SectorId],
    tickets: &[Ticket],
    piece_infos: &[Vec<PieceInfo>],
) -> Result<Vec<SealPreCommitOutput>> {
    info!("seal_pre_commit_many: start");
    ensure!(
        in_paths.len() == out_paths.len(),
        "inconsistent inputs, out_paths"
    );
    ensure!(
        in_paths.len() == prover_ids.len(),
        "inconsistent inputs, prover_ids"
    );
    ensure!(
        in_paths.len() == cache_paths.len(),
        "inconsistent inputs, cache_paths"
    );
    ensure!(
        in_paths.len() == tickets.len(),
        "inconsistent inputs, tickets"
    );
    ensure!(
        in_paths.len() == sector_ids.len(),
        "inconsistent inputs, sector_ids"
    );
    ensure!(
        in_paths.len() == piece_infos.len(),
        "inconsistent inputs, piece_infos"
    );

    let sector_bytes = usize::from(PaddedBytesAmount::from(porep_config));

    in_paths.par_iter().zip(out_paths.par_iter()).try_for_each(
        |(in_path, out_path)| -> Result<()> {
            fs::metadata(&in_path)
                .with_context(|| format!("could not read in_path={:?})", in_path))?;

            fs::metadata(&out_path)
                .with_context(|| format!("could not read out_path={:?}", out_path))?;

            // Copy unsealed data to output location, where it will be sealed in place.
            fs::copy(&in_path, &out_path).with_context(|| {
                format!(
                    "could not copy in_path={:?} to out_path={:?}",
                    in_path, out_path
                )
            })?;
            Ok(())
        },
    )?;

    let datas = out_paths
        .par_iter()
        .map(|out_path| {
            let f_data = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&out_path)
                .with_context(|| format!("could not open out_path={:?}", out_path))?;

            // Zero-pad the data to the requested size by extending the underlying file if needed.
            f_data.set_len(sector_bytes as u64)?;

            unsafe {
                MmapOptions::new()
                    .map_mut(&f_data)
                    .with_context(|| format!("could not mmap out_path={:?}", out_path))
            }
        })
        .collect::<Result<Vec<_>>>()?;

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params = <StackedCompound as CompoundProof<
        _,
        StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    info!("building merkle tree for the original data");
    let trees = measure_op(CommD, || {
        datas
            .into_par_iter()
            .zip(cache_paths.into_par_iter())
            .zip(out_paths.into_par_iter())
            .map(|((data, cache_path), out_path)| {
                // MT for original data is always named tree-d, and it will be
                // referenced later in the process as such.
                let config = StoreConfig::new(
                    cache_path,
                    CacheKey::CommDTree.to_string(),
                    DEFAULT_CACHED_ABOVE_BASE_LAYER,
                );
                let data_tree = create_merkle_tree::<DefaultPieceHasher>(
                    Some(config.clone()),
                    compound_public_params.vanilla_params.graph.size(),
                    &data,
                )?;

                let mut data: storage_proofs::porep::Data<'_> =
                    (data, PathBuf::from(out_path)).into();
                data.drop_data();

                let comm_d_root: Fr = data_tree.root().into();
                let comm_d = commitment_from_fr::<Bls12>(comm_d_root);

                Ok(((config, data_tree), (data, comm_d)))
            })
            .collect::<Result<Vec<_>>>()
    })?;

    let (a, b): (Vec<_>, Vec<_>) = trees.into_iter().unzip();
    let (configs, data_trees) = a.into_iter().unzip();
    let (datas, comm_ds): (Vec<_>, Vec<_>) = b.into_iter().unzip();

    info!("verifying pieces");

    comm_ds
        .par_iter()
        .zip(piece_infos.par_iter())
        .try_for_each(|(comm_d, piece_infos)| {
            ensure!(
                verify_pieces(&comm_d, piece_infos, porep_config.into())?,
                "pieces and comm_d do not match"
            );
            Ok(())
        })?;

    let replica_ids = prover_ids
        .iter()
        .zip(sector_ids.iter())
        .zip(tickets.iter())
        .zip(comm_ds.iter())
        .map(|(((prover_id, sector_id), ticket), comm_d)| {
            generate_replica_id::<DefaultTreeHasher, _>(
                &prover_id,
                (*sector_id).into(),
                &ticket,
                comm_d,
            )
        })
        .collect::<Vec<_>>();

    let (taus, auxs) = StackedDrg::<DefaultTreeHasher, DefaultPieceHasher>::replicate_many(
        &compound_public_params.vanilla_params,
        &replica_ids,
        datas,
        data_trees,
        configs,
    )?;

    let comm_rs = taus
        .iter()
        .map(|tau| commitment_from_fr::<Bls12>(tau.comm_r.into()))
        .collect::<Vec<_>>();

    ensure!(taus.len() == auxs.len(), "inconsistent outputs");
    ensure!(taus.len() == in_paths.len(), "inconsistent outputs");

    info!("seal_pre_commit_many: end");

    cache_paths
        .into_par_iter()
        .zip(auxs.into_par_iter())
        .try_for_each(|(cache_path, (p_aux, t_aux))| -> Result<()> {
            // Persist p_aux and t_aux here
            let p_aux_path = cache_path.join(CacheKey::PAux.to_string());
            let mut f_p_aux = File::create(&p_aux_path)
                .with_context(|| format!("could not create file p_aux={:?}", p_aux_path))?;
            let p_aux_bytes = serialize(&p_aux)?;
            f_p_aux
                .write_all(&p_aux_bytes)
                .with_context(|| format!("could not write to file p_aux={:?}", p_aux_path))?;

            let t_aux_path = cache_path.join(CacheKey::TAux.to_string());
            let mut f_t_aux = File::create(&t_aux_path)
                .with_context(|| format!("could not create file t_aux={:?}", t_aux_path))?;
            let t_aux_bytes = serialize(&t_aux)?;
            f_t_aux
                .write_all(&t_aux_bytes)
                .with_context(|| format!("could not write to file t_aux={:?}", t_aux_path))?;
            Ok(())
        })?;

    let outputs = comm_rs
        .into_iter()
        .zip(comm_ds.into_iter())
        .map(|(comm_r, comm_d)| SealPreCommitOutput { comm_r, comm_d })
        .collect();

    Ok(outputs)
}

/// Generates a proof for the pre committed sector.
///
/// # Arguments
///
/// * `porep_config` - porep configuration containing the number of bytes in this sector.
/// * `cache_path` - path to a directory in which the sector data's Merkle Tree can be written.
/// * `prover_id` - the prover-id that is sealing the sector.
/// * `sector_id` - the sector-id of this sector.
/// * `ticket` - the ticket that will be used to generate this sector's replica-id.
/// * `seed` - the seed used to derive the porep challenges.
/// * `pre_commit` - commitments to the sector data and its replica.
/// * `piece_infos` - each piece's info (number of bytes and commitment) in this sector.
#[allow(clippy::too_many_arguments)]
pub fn seal_commit<T: AsRef<Path>>(
    porep_config: PoRepConfig,
    cache_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    pre_commit: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
) -> Result<SealCommitOutput> {
    info!("seal_commit:start");

    let SealPreCommitOutput { comm_d, comm_r } = pre_commit;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.into())?,
        "pieces and comm_d do not match"
    );

    let p_aux = {
        let mut p_aux_bytes = vec![];
        let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
        let mut f_p_aux = File::open(&p_aux_path)
            .with_context(|| format!("could not open file p_aux={:?}", p_aux_path))?;
        f_p_aux.read_to_end(&mut p_aux_bytes)?;

        deserialize(&p_aux_bytes)
    }?;

    let t_aux = {
        let mut t_aux_bytes = vec![];
        let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
        let mut f_t_aux = File::open(&t_aux_path)
            .with_context(|| format!("could not open file t_aux={:?}", t_aux_path))?;
        f_t_aux.read_to_end(&mut t_aux_bytes)?;

        let mut res: TemporaryAux<_, _> = deserialize(&t_aux_bytes)?;

        // Switch t_aux to the passed in cache_path
        res.set_cache_path(cache_path);
        res
    };

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux_cache: TemporaryAuxCache<DefaultTreeHasher, DefaultPieceHasher> =
        TemporaryAuxCache::new(&t_aux).context("failed to restore contents of t_aux")?;

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = <DefaultPieceHasher as Hasher>::Domain::try_from_bytes(&comm_d)?;

    let replica_id = generate_replica_id::<DefaultTreeHasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d_safe,
    );

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let private_inputs = stacked::PrivateInputs::<DefaultTreeHasher, DefaultPieceHasher> {
        p_aux,
        t_aux: t_aux_cache,
    };

    let groth_params = get_stacked_params(porep_config)?;

    info!(
        "got groth params ({}) while sealing",
        u64::from(PaddedBytesAmount::from(porep_config))
    );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params = StackedCompound::setup(&compound_setup_params)?;

    let proof = StackedCompound::prove(
        &compound_public_params,
        &public_inputs,
        &private_inputs,
        &groth_params,
    )?;

    // Delete cached MTs that are no longer needed.
    TemporaryAux::<DefaultTreeHasher, DefaultPieceHasher>::delete(t_aux)?;

    let mut buf = Vec::with_capacity(
        SINGLE_PARTITION_PROOF_LEN * usize::from(PoRepProofPartitions::from(porep_config)),
    );

    proof.write(&mut buf)?;

    // Verification is cheap when parameters are cached,
    // and it is never correct to return a proof which does not verify.
    verify_seal(
        porep_config,
        comm_r,
        comm_d,
        prover_id,
        sector_id,
        ticket,
        seed,
        &buf,
    )
    .context("post-seal verification sanity check failed")?;

    info!("seal_commit:end");

    Ok(SealCommitOutput { proof: buf })
}

/// Computes a sectors's `comm_d` given its pieces.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `piece_infos` - the piece info (commitment and byte length) for each piece in this sector.
pub fn compute_comm_d(sector_size: SectorSize, piece_infos: &[PieceInfo]) -> Result<Commitment> {
    pieces::compute_comm_d(sector_size, piece_infos)
}

/// Verifies the output of some previously-run seal operation.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
/// * `comm_r_in` - commitment to the sector's replica (`comm_r`).
/// * `comm_d_in` - commitment to the sector's data (`comm_d`).
/// * `prover_id` - the prover-id that sealed this sector.
/// * `sector_id` - this sector's sector-id.
/// * `ticket` - the ticket that was used to generate this sector's replica-id.
/// * `seed` - the seed used to derive the porep challenges.
/// * `proof_vec` - the porep circuit proof serialized into a vector of bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_seal(
    porep_config: PoRepConfig,
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    proof_vec: &[u8],
) -> Result<bool> {
    ensure!(comm_d_in != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r_in != [0; 32], "Invalid all zero commitment (comm_r)");

    let sector_bytes = PaddedBytesAmount::from(porep_config);
    let comm_r = as_safe_commitment(&comm_r_in, "comm_r")?;
    let comm_d = as_safe_commitment(&comm_d_in, "comm_d")?;

    let replica_id =
        generate_replica_id::<DefaultTreeHasher, _>(&prover_id, sector_id.into(), &ticket, comm_d);

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        StackedDrg<'_, DefaultTreeHasher, DefaultPieceHasher>,
    > = StackedCompound::setup(&compound_setup_params)?;

    let public_inputs = stacked::PublicInputs::<
        <DefaultTreeHasher as Hasher>::Domain,
        <DefaultPieceHasher as Hasher>::Domain,
    > {
        replica_id,
        tau: Some(Tau { comm_r, comm_d }),
        seed,
        k: None,
    };

    let verifying_key = get_stacked_verifying_key(porep_config)?;

    info!(
        "got verifying key ({}) while verifying seal",
        u64::from(sector_bytes)
    );

    let proof = MultiProof::new_from_reader(
        Some(usize::from(PoRepProofPartitions::from(porep_config))),
        proof_vec,
        &verifying_key,
    )?;

    StackedCompound::verify(
        &compound_public_params,
        &public_inputs,
        &proof,
        &ChallengeRequirements {
            minimum_challenges: POREP_MINIMUM_CHALLENGES.load(Ordering::Relaxed) as usize,
        },
    )
    .map_err(Into::into)
}

/// Verifies a batch of outputs of some previously-run seal operations.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
/// * `[comm_r_ins]` - list of commitments to the sector's replica (`comm_r`).
/// * `[comm_d_ins]` - list of commitments to the sector's data (`comm_d`).
/// * `[prover_ids]` - list of prover-ids that sealed this sector.
/// * `[sector_ids]` - list of the sector's sector-id.
/// * `[tickets]` - list of tickets that was used to generate this sector's replica-id.
/// * `[seeds]` - list of seeds used to derive the porep challenges.
/// * `[proof_vecs]` - list of porep circuit proofs serialized into a vector of bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_batch_seal(
    porep_config: PoRepConfig,
    comm_r_ins: &[Commitment],
    comm_d_ins: &[Commitment],
    prover_ids: &[ProverId],
    sector_ids: &[SectorId],
    tickets: &[Ticket],
    seeds: &[Ticket],
    proof_vecs: &[&[u8]],
) -> Result<bool> {
    ensure!(!comm_r_ins.is_empty(), "Cannot prove empty batch");
    let l = comm_r_ins.len();
    ensure!(l == comm_d_ins.len(), "Inconsistent inputs");
    ensure!(l == prover_ids.len(), "Inconsistent inputs");
    ensure!(l == prover_ids.len(), "Inconsistent inputs");
    ensure!(l == sector_ids.len(), "Inconsistent inputs");
    ensure!(l == tickets.len(), "Inconsistent inputs");
    ensure!(l == seeds.len(), "Inconsistent inputs");
    ensure!(l == proof_vecs.len(), "Inconsistent inputs");

    for comm_d_in in comm_d_ins {
        ensure!(
            comm_d_in != &[0; 32],
            "Invalid all zero commitment (comm_d)"
        );
    }
    for comm_r_in in comm_r_ins {
        ensure!(
            comm_r_in != &[0; 32],
            "Invalid all zero commitment (comm_r)"
        );
    }

    let sector_bytes = PaddedBytesAmount::from(porep_config);

    let verifying_key = get_stacked_verifying_key(porep_config)?;
    info!(
        "got verifying key ({}) while verifying seal",
        u64::from(sector_bytes)
    );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        StackedDrg<'_, DefaultTreeHasher, DefaultPieceHasher>,
    > = StackedCompound::setup(&compound_setup_params)?;

    let mut public_inputs = Vec::with_capacity(l);
    let mut proofs = Vec::with_capacity(l);

    for i in 0..l {
        let comm_r = as_safe_commitment(&comm_r_ins[i], "comm_r")?;
        let comm_d = as_safe_commitment(&comm_d_ins[i], "comm_d")?;

        let replica_id = generate_replica_id::<DefaultTreeHasher, _>(
            &prover_ids[i],
            sector_ids[i].into(),
            &tickets[i],
            comm_d,
        );

        public_inputs.push(stacked::PublicInputs::<
            <DefaultTreeHasher as Hasher>::Domain,
            <DefaultPieceHasher as Hasher>::Domain,
        > {
            replica_id,
            tau: Some(Tau { comm_r, comm_d }),
            seed: seeds[i],
            k: None,
        });
        proofs.push(MultiProof::new_from_reader(
            Some(usize::from(PoRepProofPartitions::from(porep_config))),
            proof_vecs[i],
            &verifying_key,
        )?);
    }

    StackedCompound::batch_verify(
        &compound_public_params,
        &public_inputs,
        &proofs,
        &ChallengeRequirements {
            minimum_challenges: POREP_MINIMUM_CHALLENGES.load(Ordering::Relaxed) as usize, // TODO: what do we want here?
        },
    )
    .map_err(Into::into)
}
