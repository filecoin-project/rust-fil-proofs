use std::fs::{self, File, OpenOptions};
use std::io::prelude::*;
use std::path::Path;
use std::sync::atomic::Ordering;

use anyhow::{ensure, Context, Result};
use bincode::{deserialize, serialize};
use log::info;
use memmap::MmapOptions;
use merkletree::store::{StoreConfig, DEFAULT_CACHED_ABOVE_BASE_LAYER};
use paired::bls12_381::{Bls12, Fr};
use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::circuit::stacked_old::StackedCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgraph::{DefaultTreeHasher, Graph};
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::merkle::create_merkle_tree;
use storage_proofs::porep::PoRep;
use storage_proofs::sector::SectorId;
use storage_proofs::stacked_old::{
    self, generate_replica_id, CacheKey, ChallengeRequirements, StackedDrg, Tau, TemporaryAux,
    TemporaryAuxCache,
};

use crate::api::util::{as_safe_commitment, commitment_from_fr};
use crate::caches::{get_stacked_params, get_stacked_verifying_key};
use crate::constants::{
    DefaultPieceHasher, POREP_WINDOW_MINIMUM_CHALLENGES, SINGLE_PARTITION_PROOF_LEN,
};
use crate::parameters::setup_params;
pub use crate::pieces;
pub use crate::pieces::verify_pieces;
use crate::types::{
    Commitment, PaddedBytesAmount, PieceInfo, PoRepConfig, PoRepProofPartitions, ProverId,
    SealCommitOutput, SealPreCommitOutput, Ticket,
};

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
pub fn seal_pre_commit<R: AsRef<Path>, T: AsRef<Path>, S: AsRef<Path>>(
    porep_config: PoRepConfig,
    cache_path: R,
    in_path: T,
    out_path: S,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: &[PieceInfo],
) -> Result<SealPreCommitOutput> {
    info!("seal_pre_commit: start");
    let sector_bytes = usize::from(PaddedBytesAmount::from(porep_config));

    fs::metadata(&in_path)
        .with_context(|| format!("could not read in_path={:?})", in_path.as_ref()))?;

    fs::metadata(&out_path)
        .with_context(|| format!("could not read out_path={:?}", out_path.as_ref()))?;

    // Copy unsealed data to output location, where it will be sealed in place.
    fs::copy(&in_path, &out_path).with_context(|| {
        format!(
            "could not copy in_path={:?} to out_path={:?}",
            in_path.as_ref(),
            out_path.as_ref()
        )
    })?;
    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&out_path)
        .with_context(|| format!("could not open out_path={:?}", out_path.as_ref()))?;

    // Zero-pad the data to the requested size by extending the underlying file if needed.
    f_data.set_len(sector_bytes as u64)?;

    let mut data = unsafe {
        MmapOptions::new()
            .map_mut(&f_data)
            .with_context(|| format!("could mmap out_path={:?}", out_path.as_ref()))?
    };

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

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let config = StoreConfig::new(
        cache_path.as_ref(),
        CacheKey::CommDTree.to_string(),
        DEFAULT_CACHED_ABOVE_BASE_LAYER,
    );

    info!("building merkle tree for the original data");
    let data_tree = create_merkle_tree::<DefaultPieceHasher>(
        Some(config.clone()),
        compound_public_params.vanilla_params.graph.size(),
        &data,
    )?;

    let comm_d_root: Fr = data_tree.root().into();
    let comm_d = commitment_from_fr::<Bls12>(comm_d_root);

    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.into())?,
        "pieces and comm_d do not match"
    );

    let replica_id = generate_replica_id::<DefaultTreeHasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        data_tree.root(),
    );

    let (tau, (p_aux, t_aux)) = StackedDrg::<DefaultTreeHasher, DefaultPieceHasher>::replicate(
        &compound_public_params.vanilla_params,
        &replica_id,
        &mut data,
        Some(data_tree),
        Some(config),
    )?;

    let comm_r = commitment_from_fr::<Bls12>(tau.comm_r.into());

    info!("seal_pre_commit: end");

    // Persist p_aux and t_aux here
    let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
    let mut f_p_aux = File::create(&p_aux_path)
        .with_context(|| format!("could not create file p_aux={:?}", p_aux_path))?;
    let p_aux_bytes = serialize(&p_aux)?;
    f_p_aux
        .write_all(&p_aux_bytes)
        .with_context(|| format!("could not write to file p_aux={:?}", p_aux_path))?;

    let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
    let mut f_t_aux = File::create(&t_aux_path)
        .with_context(|| format!("could not create file t_aux={:?}", t_aux_path))?;
    let t_aux_bytes = serialize(&t_aux)?;
    f_t_aux
        .write_all(&t_aux_bytes)
        .with_context(|| format!("could not write to file t_aux={:?}", t_aux_path))?;

    Ok(SealPreCommitOutput { comm_r, comm_d })
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

    let public_inputs = stacked_old::PublicInputs {
        replica_id,
        tau: Some(stacked_old::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let private_inputs = stacked_old::PrivateInputs::<DefaultTreeHasher, DefaultPieceHasher> {
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
pub fn compute_comm_d(porep_config: PoRepConfig, piece_infos: &[PieceInfo]) -> Result<Commitment> {
    pieces::compute_comm_d(porep_config.sector_size, piece_infos)
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

    let public_inputs = stacked_old::PublicInputs::<
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
            minimum_challenges: POREP_WINDOW_MINIMUM_CHALLENGES.load(Ordering::Relaxed) as usize, // TODO: what do we want here?
        },
    )
    .map_err(Into::into)
}
