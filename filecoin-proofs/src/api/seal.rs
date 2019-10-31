use std::fs::{self, OpenOptions};
use std::path::Path;

use memmap::MmapOptions;
use paired::bls12_381::{Bls12, Fr};
use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::circuit::stacked::StackedCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::crypto::pedersen::JJ_PARAMS;
use storage_proofs::drgraph::{DefaultTreeHasher, Graph};
use storage_proofs::fr32::bytes_into_fr;
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::merkle::create_merkle_tree;
use storage_proofs::porep::PoRep;
use storage_proofs::sector::SectorId;
use storage_proofs::stacked::{self, generate_replica_id, ChallengeRequirements, StackedDrg, Tau};

use crate::api::util::{as_safe_commitment, commitment_from_fr};
use crate::caches::{get_stacked_params, get_stacked_verifying_key};
use crate::constants::{DefaultPieceHasher, POREP_MINIMUM_CHALLENGES, SINGLE_PARTITION_PROOF_LEN};
use crate::error;
use crate::parameters::setup_params;
pub use crate::pieces;
pub use crate::pieces::verify_pieces;
use crate::types::{
    Commitment, PaddedBytesAmount, PieceInfo, PoRepConfig, PoRepProofPartitions, ProverId,
    SealCommitOutput, SealPreCommitOutput, Ticket,
};

/// Seals the staged sector at `in_path` in place, saving the resulting replica to `out_path`.
#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit<R: AsRef<Path>, T: AsRef<Path>, S: AsRef<Path>>(
    porep_config: PoRepConfig,
    _cache_path: R,
    in_path: T,
    out_path: S,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: &[PieceInfo],
) -> error::Result<SealPreCommitOutput> {
    info!("seal_pre_commit: start");
    let sector_bytes = usize::from(PaddedBytesAmount::from(porep_config));

    if let Err(err) = std::fs::metadata(&in_path) {
        return Err(format_err!(
            "could not read in_path={:?} (err = {:?})",
            in_path.as_ref(),
            err
        ));
    }

    if let Err(ref err) = std::fs::metadata(&out_path) {
        return Err(format_err!(
            "could not read out_path={:?} (err = {:?})",
            in_path.as_ref(),
            err
        ));
    }

    // Copy unsealed data to output location, where it will be sealed in place.
    fs::copy(&in_path, &out_path)?;
    let f_data = OpenOptions::new().read(true).write(true).open(&out_path)?;

    // Zero-pad the data to the requested size by extending the underlying file if needed.
    f_data.set_len(sector_bytes as u64)?;

    let mut data = unsafe { MmapOptions::new().map_mut(&f_data).unwrap() };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        ),
        engine_params: &(*JJ_PARAMS),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params = <StackedCompound as CompoundProof<
        _,
        StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    info!("building merkle tree for the original data");
    let data_tree = create_merkle_tree::<DefaultPieceHasher>(
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
    )?;

    let comm_r = commitment_from_fr::<Bls12>(tau.comm_r.into());

    info!("seal_pre_commit: end");

    Ok(SealPreCommitOutput {
        comm_r,
        comm_d,
        p_aux,
        t_aux,
    })
}

/// Generates a proof for the pre committed sector.
#[allow(clippy::too_many_arguments)]
pub fn seal_commit<T: AsRef<Path>>(
    porep_config: PoRepConfig,
    _cache_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    pre_commit: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
) -> error::Result<SealCommitOutput> {
    info!("seal_commit:start");

    let SealPreCommitOutput {
        comm_d,
        comm_r,
        p_aux,
        t_aux,
    } = pre_commit;

    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.into())?,
        "pieces and comm_d do not match"
    );

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = <DefaultPieceHasher as Hasher>::Domain::try_from_bytes(&comm_d)?;

    let replica_id = generate_replica_id::<DefaultTreeHasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d_safe,
    );

    let seed_fr = bytes_into_fr::<Bls12>(&seed).map(Into::into)?;

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed: seed_fr,
    };

    let private_inputs =
        stacked::PrivateInputs::<DefaultTreeHasher, DefaultPieceHasher> { p_aux, t_aux };

    let groth_params = get_stacked_params(porep_config)?;

    info!(
        "got groth params ({}) while sealing",
        u64::from(PaddedBytesAmount::from(porep_config))
    );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        ),
        engine_params: &(*JJ_PARAMS),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params = StackedCompound::setup(&compound_setup_params)?;

    let proof = StackedCompound::prove(
        &compound_public_params,
        &public_inputs,
        &private_inputs,
        &groth_params,
    )?;

    let mut buf = Vec::with_capacity(
        SINGLE_PARTITION_PROOF_LEN * usize::from(PoRepProofPartitions::from(porep_config)),
    );

    proof.write(&mut buf)?;

    // Verification is cheap when parameters are cached,
    // and it is never correct to return a proof which does not verify.
    assert!(
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
        .expect("post-seal verification sanity check failed"),
        "invalid seal generated, bad things have happened"
    );

    info!("seal_commit:end");

    Ok(SealCommitOutput { proof: buf })
}

pub fn compute_comm_d(
    porep_config: PoRepConfig,
    piece_infos: &[PieceInfo],
) -> error::Result<Commitment> {
    pieces::compute_comm_d(porep_config.0, piece_infos)
}

/// Verifies the output of some previously-run seal operation.
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
) -> error::Result<bool> {
    let sector_bytes = PaddedBytesAmount::from(porep_config);
    let comm_r = as_safe_commitment(&comm_r_in, "comm_r")?;
    let comm_d = as_safe_commitment(&comm_d_in, "comm_d")?;

    let replica_id =
        generate_replica_id::<DefaultTreeHasher, _>(&prover_id, sector_id.into(), &ticket, comm_d);

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        ),
        engine_params: &(*JJ_PARAMS),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        Bls12,
        StackedDrg<'_, DefaultTreeHasher, DefaultPieceHasher>,
    > = StackedCompound::setup(&compound_setup_params)?;

    let seed_fr = bytes_into_fr::<Bls12>(&seed).map(Into::into)?;

    let public_inputs = stacked::PublicInputs::<
        <DefaultTreeHasher as Hasher>::Domain,
        <DefaultPieceHasher as Hasher>::Domain,
    > {
        replica_id,
        tau: Some(Tau { comm_r, comm_d }),
        seed: seed_fr,
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
            minimum_challenges: POREP_MINIMUM_CHALLENGES,
        },
    )
    .map_err(Into::into)
}
