use std::any::{Any, TypeId};
use std::fs::{self, metadata, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bellperson::groth16;
use bincode::{deserialize, serialize};
use blstrs::{Bls12, Scalar as Fr};
use ff::PrimeField;
use filecoin_hashers::{Domain, Groth16Hasher, Hasher, PoseidonArity};
use halo2_proofs::pasta::{Fp, Fq};
use log::{info, trace};
use memmap::MmapOptions;
use merkletree::store::{DiskStore, Store, StoreConfig};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    cache_key::CacheKey,
    compound_proof::{self, CompoundProof},
    drgraph::Graph,
    halo2::{self, Halo2Field, Halo2Proof},
    measurements::{measure_op, Operation},
    merkle::{create_base_merkle_tree, BinaryMerkleTree, MerkleTreeTrait, MerkleTreeWrapper},
    multi_proof::MultiProof,
    parameter_cache::SRS_MAX_PROOFS_TO_AGGREGATE,
    proof::ProofScheme,
    sector::SectorId,
    util::default_rows_to_discard,
    Data,
};
use storage_proofs_porep::stacked::{
    self, generate_replica_id,
    halo2::{
        constants::{
            SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_GIB,
            SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB, SECTOR_NODES_64_GIB,
            SECTOR_NODES_8_MIB,
        },
        SdrPorepCircuit,
    },
    ChallengeRequirements, StackedCompound, StackedDrg, Tau, TemporaryAux, TemporaryAuxCache,
};

use crate::{
    api::{
        as_safe_commitment, commitment_from_fr, get_base_tree_leafs, get_base_tree_size,
        get_proof_system, MockStore, PoseidonArityAllFields, ProofSystem,
    },
    caches::{
        get_stacked_params, get_stacked_srs_key, get_stacked_srs_verifier_key,
        get_stacked_verifying_key,
    },
    constants::{
        DefaultBinaryTree, DefaultPieceDomain, DefaultPieceHasher, DefaultTreeDomain,
        DefaultTreeHasher, POREP_MINIMUM_CHALLENGES, SINGLE_PARTITION_PROOF_LEN,
    },
    parameters::setup_params,
    pieces::{self, verify_pieces},
    types::{
        AggregateSnarkProof, CircuitPublicInputs, Commitment, PaddedBytesAmount, PieceInfo,
        PoRepConfig, PoRepProofPartitions, ProverId, SealCommitOutput, SealCommitPhase1Output,
        SealPreCommitOutput, SealPreCommitPhase1Output, SectorSize, SnarkProof, Ticket,
        VanillaSealProof, BINARY_ARITY,
    },
};

#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit_phase1<R, S, T, Tree>(
    porep_config: PoRepConfig,
    cache_path: R,
    in_path: S,
    out_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: &[PieceInfo],
) -> Result<SealPreCommitPhase1Output<Tree>>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    T: AsRef<Path>,
    Tree: 'static + MerkleTreeTrait,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    DefaultTreeHasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    info!("seal_pre_commit_phase1:start: {:?}", sector_id);

    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    // Sanity check all input path types.
    ensure!(
        metadata(in_path.as_ref())?.is_file(),
        "in_path must be a file"
    );
    ensure!(
        metadata(out_path.as_ref())?.is_file(),
        "out_path must be a file"
    );
    ensure!(
        metadata(cache_path.as_ref())?.is_dir(),
        "cache_path must be a directory"
    );

    let sector_bytes = usize::from(PaddedBytesAmount::from(porep_config));
    fs::metadata(&in_path)
        .with_context(|| format!("could not read in_path={:?})", in_path.as_ref().display()))?;

    fs::metadata(&out_path)
        .with_context(|| format!("could not read out_path={:?}", out_path.as_ref().display()))?;

    // Copy unsealed data to output location, where it will be sealed in place.
    fs::copy(&in_path, &out_path).with_context(|| {
        format!(
            "could not copy in_path={:?} to out_path={:?}",
            in_path.as_ref().display(),
            out_path.as_ref().display()
        )
    })?;

    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&out_path)
        .with_context(|| format!("could not open out_path={:?}", out_path.as_ref().display()))?;

    // Zero-pad the data to the requested size by extending the underlying file if needed.
    f_data.set_len(sector_bytes as u64)?;

    let data = unsafe {
        MmapOptions::new()
            .map_mut(&f_data)
            .with_context(|| format!("could not mmap out_path={:?}", out_path.as_ref().display()))?
    };

    let vanilla_setup_params = setup_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let vanilla_pub_params =
        StackedDrg::<'_, Tree, DefaultPieceHasher<Tree::Field>>::setup(&vanilla_setup_params)?;

    let graph_nodes = vanilla_pub_params.graph.size();

    trace!("building merkle tree for the original data");
    let (config, comm_d) = measure_op(Operation::CommD, || -> Result<_> {
        let base_tree_size =
            get_base_tree_size::<DefaultBinaryTree<Tree::Field>>(porep_config.sector_size)?;

        let base_tree_leafs =
            get_base_tree_leafs::<DefaultBinaryTree<Tree::Field>>(base_tree_size)?;

        ensure!(
            graph_nodes == base_tree_leafs,
            "graph size and leaf size don't match"
        );

        trace!(
            "seal phase 1: sector_size {}, base tree size {}, base tree leafs {}",
            u64::from(porep_config.sector_size),
            base_tree_size,
            base_tree_leafs,
        );

        let mut config = StoreConfig::new(
            cache_path.as_ref(),
            CacheKey::CommDTree.to_string(),
            default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
        );

        let data_tree = create_base_merkle_tree::<DefaultBinaryTree<Tree::Field>>(
            Some(config.clone()),
            base_tree_leafs,
            &data,
        )?;
        drop(data);

        config.size = Some(data_tree.len());
        let comm_d_root: Tree::Field = data_tree.root().into();
        let comm_d = commitment_from_fr(comm_d_root);

        drop(data_tree);

        Ok((config, comm_d))
    })?;

    trace!("verifying pieces");

    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.into())?,
        "pieces and comm_d do not match"
    );

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let labels = StackedDrg::<Tree, DefaultPieceHasher<Tree::Field>>::replicate_phase1(
        &vanilla_pub_params,
        &replica_id,
        config.clone(),
    )?;

    let out = SealPreCommitPhase1Output {
        labels,
        config,
        comm_d,
    };

    info!("seal_pre_commit_phase1:finish: {:?}", sector_id);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit_phase2<R, S, Tree>(
    porep_config: PoRepConfig,
    phase1_output: SealPreCommitPhase1Output<Tree>,
    cache_path: S,
    replica_path: R,
) -> Result<SealPreCommitOutput>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    Tree: 'static + MerkleTreeTrait,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    DefaultTreeHasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    info!("seal_pre_commit_phase2:start");

    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    // Sanity check all input path types.
    ensure!(
        metadata(cache_path.as_ref())?.is_dir(),
        "cache_path must be a directory"
    );
    ensure!(
        metadata(replica_path.as_ref())?.is_file(),
        "replica_path must be a file"
    );

    let SealPreCommitPhase1Output {
        mut labels,
        mut config,
        comm_d,
        ..
    } = phase1_output;

    labels.update_root(cache_path.as_ref());
    config.path = cache_path.as_ref().into();

    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&replica_path)
        .with_context(|| {
            format!(
                "could not open replica_path={:?}",
                replica_path.as_ref().display()
            )
        })?;
    let data = unsafe {
        MmapOptions::new().map_mut(&f_data).with_context(|| {
            format!(
                "could not mmap replica_path={:?}",
                replica_path.as_ref().display()
            )
        })?
    };
    let data: Data<'_> = (data, PathBuf::from(replica_path.as_ref())).into();

    // Load data tree from disk
    let data_tree = {
        let base_tree_size =
            get_base_tree_size::<DefaultBinaryTree<Tree::Field>>(porep_config.sector_size)?;
        let base_tree_leafs =
            get_base_tree_leafs::<DefaultBinaryTree<Tree::Field>>(base_tree_size)?;

        trace!(
            "seal phase 2: base tree size {}, base tree leafs {}, rows to discard {}",
            base_tree_size,
            base_tree_leafs,
            default_rows_to_discard(base_tree_leafs, BINARY_ARITY)
        );
        ensure!(
            config.rows_to_discard == default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
            "Invalid cache size specified"
        );

        let store = DiskStore::<DefaultPieceDomain<Tree::Field>>::new_from_disk(
            base_tree_size,
            BINARY_ARITY,
            &config,
        )?;
        BinaryMerkleTree::<DefaultPieceHasher<Tree::Field>>::from_data_store(
            store,
            base_tree_leafs,
        )?
    };

    let vanilla_setup_params = setup_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let vanilla_pub_params =
        StackedDrg::<'_, Tree, DefaultPieceHasher<Tree::Field>>::setup(&vanilla_setup_params)?;

    let (tau, (p_aux, t_aux)) =
        StackedDrg::<Tree, DefaultPieceHasher<Tree::Field>>::replicate_phase2(
            &vanilla_pub_params,
            labels,
            data,
            data_tree,
            config,
            replica_path.as_ref().to_path_buf(),
        )?;

    let comm_r = commitment_from_fr::<Tree::Field>(tau.comm_r.into());

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

    let out = SealPreCommitOutput { comm_r, comm_d };

    info!("seal_pre_commit_phase2:finish");
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_commit_phase1<T, Tree>(
    porep_config: PoRepConfig,
    cache_path: T,
    replica_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    pre_commit: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
) -> Result<SealCommitPhase1Output<Tree>>
where
    T: AsRef<Path>,
    Tree: 'static + MerkleTreeTrait,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    info!("seal_commit_phase1:start: {:?}", sector_id);

    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    // Sanity check all input path types.
    ensure!(
        metadata(cache_path.as_ref())?.is_dir(),
        "cache_path must be a directory"
    );
    ensure!(
        metadata(replica_path.as_ref())?.is_file(),
        "replica_path must be a file"
    );

    let SealPreCommitOutput { comm_d, comm_r } = pre_commit;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.into())?,
        "pieces and comm_d do not match"
    );

    let p_aux = {
        let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    let t_aux = {
        let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
        let t_aux_bytes = fs::read(&t_aux_path)
            .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

        let mut res: TemporaryAux<Tree, DefaultPieceHasher<Tree::Field>> =
            deserialize(&t_aux_bytes)?;

        // Switch t_aux to the passed in cache_path
        res.set_cache_path(cache_path);
        res
    };

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux_cache = TemporaryAuxCache::<Tree, DefaultPieceHasher<Tree::Field>>::new(
        &t_aux,
        replica_path.as_ref().to_path_buf(),
    )
    .context("failed to restore contents of t_aux")?;

    let comm_r_safe: <Tree::Hasher as Hasher>::Domain = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::<Tree::Field>::try_from_bytes(&comm_d)?;

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d_safe,
        &porep_config.porep_id,
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

    let private_inputs = stacked::PrivateInputs::<Tree, DefaultPieceHasher<Tree::Field>> {
        p_aux,
        t_aux: t_aux_cache,
    };

    let vanilla_setup_params = setup_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let vanilla_pub_params =
        StackedDrg::<'_, Tree, DefaultPieceHasher<Tree::Field>>::setup(&vanilla_setup_params)?;

    let partition_count = usize::from(PoRepProofPartitions::from(porep_config));

    let vanilla_proofs = StackedDrg::prove_all_partitions(
        &vanilla_pub_params,
        &public_inputs,
        &private_inputs,
        partition_count,
    )?;

    let sanity_check = StackedDrg::<Tree, DefaultPieceHasher<Tree::Field>>::verify_all_partitions(
        &vanilla_pub_params,
        &public_inputs,
        &vanilla_proofs,
    )?;
    ensure!(sanity_check, "Invalid vanilla proof generated");

    let out = SealCommitPhase1Output {
        vanilla_proofs,
        comm_r,
        comm_d,
        replica_id,
        seed,
        ticket,
    };

    info!("seal_commit_phase1:finish: {:?}", sector_id);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_commit_phase2<Tree>(
    porep_config: PoRepConfig,
    phase1_output: SealCommitPhase1Output<Tree>,
    prover_id: ProverId,
    sector_id: SectorId,
) -> Result<SealCommitOutput>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    info!("seal_commit_phase2:start: {:?}", sector_id);

    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    let proof_bytes = match get_proof_system::<Tree>() {
        ProofSystem::Groth => {
            groth16_seal_commit_phase2(porep_config, phase1_output, prover_id, sector_id)?
        }
        ProofSystem::HaloPallas => {
            halo2_seal_commit_phase2::<_, Fp>(porep_config, phase1_output, prover_id, sector_id)?
        }
        ProofSystem::HaloVesta => {
            halo2_seal_commit_phase2::<_, Fq>(porep_config, phase1_output, prover_id, sector_id)?
        }
    };

    info!("seal_commit_phase2:finish: {:?}", sector_id);
    Ok(SealCommitOutput { proof: proof_bytes })
}

#[allow(clippy::unwrap_used)]
fn groth16_seal_commit_phase2<Tree>(
    porep_config: PoRepConfig,
    phase1_output: SealCommitPhase1Output<Tree>,
    prover_id: ProverId,
    sector_id: SectorId,
) -> Result<SnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArity<Fr>,
    Tree::SubTreeArity: PoseidonArity<Fr>,
    Tree::TopTreeArity: PoseidonArity<Fr>,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    let SealCommitPhase1Output {
        vanilla_proofs,
        comm_d,
        comm_r,
        replica_id,
        seed,
        ticket,
    } = phase1_output;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

    let partition_count = PoRepProofPartitions::from(porep_config).into();

    let vanilla_setup_params = setup_params(
        PaddedBytesAmount::from(porep_config),
        partition_count,
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let vanilla_pub_params = StackedDrg::<
        '_,
        MerkleTreeWrapper<
            DefaultTreeHasher<Fr>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
        DefaultPieceHasher<Fr>,
    >::setup(&vanilla_setup_params)?;

    let comm_r_safe: DefaultTreeDomain<Fr> = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::<Fr>::try_from_bytes(&comm_d)?;

    let replica_id = *(&replica_id as &dyn Any)
        .downcast_ref::<DefaultTreeDomain<Fr>>()
        .unwrap();

    let vanilla_pub_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let vanilla_proofs: Vec<
        Vec<
            VanillaSealProof<
                MerkleTreeWrapper<
                    DefaultTreeHasher<Fr>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            >,
        >,
    > = unsafe { std::mem::transmute(vanilla_proofs) };

    let groth_params = get_stacked_params::<
        MerkleTreeWrapper<
            DefaultTreeHasher<Fr>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >(porep_config)?;

    trace!(
        "got groth params ({}) while sealing",
        u64::from(PaddedBytesAmount::from(porep_config))
    );

    trace!("snark_proof:start");
    let priority = false;
    let groth_proofs = StackedCompound::<
        MerkleTreeWrapper<
            DefaultTreeHasher<Fr>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
        DefaultPieceHasher<Fr>,
    >::circuit_proofs(
        &vanilla_pub_inputs,
        vanilla_proofs,
        &vanilla_pub_params,
        &groth_params,
        priority,
    )?;
    trace!("snark_proof:finish");

    let proof = MultiProof::new(groth_proofs, &groth_params.pvk);
    let mut buf = Vec::with_capacity(SINGLE_PARTITION_PROOF_LEN * partition_count);
    proof.write(&mut buf)?;

    // Verification is cheap when parameters are cached,
    // and it is never correct to return a proof which does not verify.
    groth16_verify_seal::<
        MerkleTreeWrapper<
            DefaultTreeHasher<Fr>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >(
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

    Ok(buf)
}

#[allow(clippy::unwrap_used)]
fn halo2_seal_commit_phase2<Tree, F>(
    porep_config: PoRepConfig,
    phase1_output: SealCommitPhase1Output<Tree>,
    prover_id: ProverId,
    sector_id: SectorId,
) -> Result<SnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    F: Halo2Field,
    Tree::Arity: PoseidonArity<F>,
    Tree::SubTreeArity: PoseidonArity<F>,
    Tree::TopTreeArity: PoseidonArity<F>,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    DefaultPieceHasher<F>: Hasher<Field = F>,
    DefaultTreeHasher<F>: Hasher<Field = F>,
{
    let SealCommitPhase1Output {
        vanilla_proofs,
        comm_d,
        comm_r,
        replica_id,
        seed,
        ticket,
    } = phase1_output;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

    let partition_count = PoRepProofPartitions::from(porep_config).into();
    let sector_bytes = PaddedBytesAmount::from(porep_config);

    let vanilla_setup_params = setup_params(
        sector_bytes,
        partition_count,
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let vanilla_pub_params = StackedDrg::<
        '_,
        MerkleTreeWrapper<
            DefaultTreeHasher<F>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
        DefaultPieceHasher<F>,
    >::setup(&vanilla_setup_params)?;

    let comm_r_safe: DefaultTreeDomain<F> = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::<F>::try_from_bytes(&comm_d)?;

    let replica_id = *(&replica_id as &dyn Any)
        .downcast_ref::<DefaultTreeDomain<F>>()
        .unwrap();

    let vanilla_pub_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let vanilla_proofs: Vec<
        Vec<
            VanillaSealProof<
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            >,
        >,
    > = unsafe { std::mem::transmute(vanilla_proofs) };

    let sector_nodes = vanilla_pub_params.graph.size();

    let proof_bytes: Vec<u8> = match sector_nodes {
        SECTOR_NODES_2_KIB => {
            let circ = SdrPorepCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_2_KIB,
            >::blank_circuit();

            trace!("creating halo2 params ({:?}) while sealing", sector_bytes);
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::create_keypair(
                &circ
            )?;

            trace!("got halo2 params ({:?}) while sealing", sector_bytes);

            trace!("snark_proof:start");
            let circ_partition_proofs = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_proofs,
                &keypair,
            )?;
            trace!("snark_proof:finish");

            circ_partition_proofs
                .iter()
                .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                .collect()
        }
        SECTOR_NODES_4_KIB => {
            let circ = SdrPorepCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_4_KIB,
            >::blank_circuit();

            trace!("creating halo2 params ({:?}) while sealing", sector_bytes);
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::create_keypair(
                &circ
            )?;

            trace!("got halo2 params ({:?}) while sealing", sector_bytes);

            trace!("snark_proof:start");
            let circ_partition_proofs = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_proofs,
                &keypair,
            )?;
            trace!("snark_proof:finish");

            circ_partition_proofs
                .iter()
                .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                .collect()
        }
        SECTOR_NODES_16_KIB => {
            let circ = SdrPorepCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_16_KIB,
            >::blank_circuit();

            trace!("creating halo2 params ({:?}) while sealing", sector_bytes);
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::create_keypair(
                &circ
            )?;

            trace!("got halo2 params ({:?}) while sealing", sector_bytes);

            trace!("snark_proof:start");
            let circ_partition_proofs = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_proofs,
                &keypair,
            )?;
            trace!("snark_proof:finish");

            circ_partition_proofs
                .iter()
                .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                .collect()
        }
        SECTOR_NODES_32_KIB => {
            let circ = SdrPorepCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_32_KIB,
            >::blank_circuit();

            trace!("creating halo2 params ({:?}) while sealing", sector_bytes);
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::create_keypair(
                &circ
            )?;

            trace!("got halo2 params ({:?}) while sealing", sector_bytes);

            trace!("snark_proof:start");
            let circ_partition_proofs = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_proofs,
                &keypair,
            )?;
            trace!("snark_proof:finish");

            circ_partition_proofs
                .iter()
                .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                .collect()
        }
        SECTOR_NODES_8_MIB => {
            let circ = SdrPorepCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_8_MIB,
            >::blank_circuit();

            trace!("creating halo2 params ({:?}) while sealing", sector_bytes);
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::create_keypair(
                &circ
            )?;

            trace!("got halo2 params ({:?}) while sealing", sector_bytes);

            trace!("snark_proof:start");
            let circ_partition_proofs = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_proofs,
                &keypair,
            )?;
            trace!("snark_proof:finish");

            circ_partition_proofs
                .iter()
                .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                .collect()
        }
        SECTOR_NODES_16_MIB => {
            let circ = SdrPorepCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_16_MIB,
            >::blank_circuit();

            trace!("creating halo2 params ({:?}) while sealing", sector_bytes);
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::create_keypair(
                &circ
            )?;

            trace!("got halo2 params ({:?}) while sealing", sector_bytes);

            trace!("snark_proof:start");
            let circ_partition_proofs = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_proofs,
                &keypair,
            )?;
            trace!("snark_proof:finish");

            circ_partition_proofs
                .iter()
                .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                .collect()
        }
        SECTOR_NODES_512_MIB => {
            let circ = SdrPorepCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_512_MIB,
            >::blank_circuit();

            trace!("creating halo2 params ({:?}) while sealing", sector_bytes);
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::create_keypair(
                &circ
            )?;

            trace!("got halo2 params ({:?}) while sealing", sector_bytes);

            trace!("snark_proof:start");
            let circ_partition_proofs = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_proofs,
                &keypair,
            )?;
            trace!("snark_proof:finish");

            circ_partition_proofs
                .iter()
                .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                .collect()
        }
        SECTOR_NODES_32_GIB => {
            let circ = SdrPorepCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_32_GIB,
            >::blank_circuit();

            trace!("creating halo2 params ({:?}) while sealing", sector_bytes);
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::create_keypair(
                &circ
            )?;

            trace!("got halo2 params ({:?}) while sealing", sector_bytes);

            trace!("snark_proof:start");
            let circ_partition_proofs = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_proofs,
                &keypair,
            )?;
            trace!("snark_proof:finish");

            circ_partition_proofs
                .iter()
                .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                .collect()
        }
        SECTOR_NODES_64_GIB => {
            let circ = SdrPorepCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_64_GIB,
            >::blank_circuit();

            trace!("creating halo2 params ({:?}) while sealing", sector_bytes);
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::create_keypair(
                &circ
            )?;

            trace!("got halo2 params ({:?}) while sealing", sector_bytes);

            trace!("snark_proof:start");
            let circ_partition_proofs = <StackedDrg<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_proofs,
                &keypair,
            )?;
            trace!("snark_proof:finish");

            circ_partition_proofs
                .iter()
                .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                .collect()
        }
        _ => unimplemented!(),
    };

    halo2_verify_seal::<F, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>(
        porep_config,
        comm_r,
        comm_d,
        prover_id,
        sector_id,
        ticket,
        seed,
        &proof_bytes,
    )
    .context("post-seal verification sanity check failed")?;

    Ok(proof_bytes)
}

/// Given the specified arguments, this method returns the inputs that were used to
/// generate the seal proof.  This can be useful for proof aggregation, as verification
/// requires these inputs.
///
/// This method allows them to be retrieved when needed, rather than storing them for
/// some amount of time.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `comm_r` - a commitment to a sector's replica.
/// * `comm_d` - a commitment to a sector's data.
/// * `prover_id` - the prover_id used to seal this sector.
/// * `sector_id` - the sector_id of this sector.
/// * `ticket` - the ticket used to generate this sector's replica-id.
/// * `seed` - the seed used to derive the porep challenges.
pub fn get_seal_inputs<Tree>(
    porep_config: PoRepConfig,
    comm_r: Commitment,
    comm_d: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
) -> Result<Vec<CircuitPublicInputs>>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
{
    trace!("get_seal_inputs:start");

    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

    let inputs = match get_proof_system::<Tree>() {
        ProofSystem::Groth => groth16_get_seal_inputs::<Tree>(
            porep_config,
            comm_r,
            comm_d,
            prover_id,
            sector_id,
            ticket,
            seed,
        )?,
        ProofSystem::HaloPallas => halo2_get_seal_inputs::<Fp>(
            porep_config,
            comm_r,
            comm_d,
            prover_id,
            sector_id,
            ticket,
            seed,
        )?,
        ProofSystem::HaloVesta => halo2_get_seal_inputs::<Fq>(
            porep_config,
            comm_r,
            comm_d,
            prover_id,
            sector_id,
            ticket,
            seed,
        )?,
    };

    trace!("get_seal_inputs:finish");

    Ok(inputs)
}

fn groth16_get_seal_inputs<Tree>(
    porep_config: PoRepConfig,
    comm_r: Commitment,
    comm_d: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
) -> Result<Vec<CircuitPublicInputs>>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArity<Fr>,
    Tree::SubTreeArity: PoseidonArity<Fr>,
    Tree::TopTreeArity: PoseidonArity<Fr>,
{
    let replica_id = generate_replica_id::<DefaultTreeHasher<Fr>, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::<Fr>::try_from_bytes(&comm_d)?;

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params = StackedCompound::<
        MerkleTreeWrapper<
            DefaultTreeHasher<Fr>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
        DefaultPieceHasher<Fr>,
    >::setup(&compound_setup_params)?;

    let partitions = StackedCompound::<
        MerkleTreeWrapper<
            DefaultTreeHasher<Fr>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
        DefaultPieceHasher<Fr>,
    >::partition_count(&compound_public_params);

    // These are returned for aggregated proof verification.
    (0..partitions)
        .into_par_iter()
        .map(|k| {
            StackedCompound::<
                MerkleTreeWrapper<
                    DefaultTreeHasher<Fr>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
                DefaultPieceHasher<Fr>,
            >::generate_public_inputs(
                &public_inputs,
                &compound_public_params.vanilla_params,
                Some(k),
            )
            .map(Into::into)
        })
        .collect::<Result<_>>()
}

fn halo2_get_seal_inputs<F>(
    porep_config: PoRepConfig,
    comm_r: Commitment,
    comm_d: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
) -> Result<Vec<CircuitPublicInputs>>
where
    F: Halo2Field,
    DefaultPieceHasher<F>: Hasher<Field = F>,
    DefaultTreeHasher<F>: Hasher<Field = F>,
{
    let sector_bytes: u64 = porep_config.sector_size.into();
    let sector_nodes = sector_bytes as usize >> 5;
    let partition_count: usize = porep_config.partitions.into();

    let vanilla_setup_params = setup_params(
        porep_config.sector_size.into(),
        partition_count,
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let replica_id = generate_replica_id::<DefaultTreeHasher<F>, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::<F>::try_from_bytes(&comm_d)?;

    use stacked::halo2::circuit::PublicInputs;

    let circ_pub_inputs: Vec<CircuitPublicInputs> = (0..partition_count)
        .map(|k| {
            let setup_params = vanilla_setup_params.clone();
            let pub_inputs = stacked::PublicInputs {
                replica_id,
                tau: Some(stacked::Tau {
                    comm_d: comm_d_safe,
                    comm_r: comm_r_safe,
                }),
                k: Some(k),
                seed,
            };
            match sector_nodes {
                SECTOR_NODES_2_KIB => {
                    PublicInputs::<F, SECTOR_NODES_2_KIB>::from(setup_params, pub_inputs)
                        .to_vec()
                        .into()
                }
                SECTOR_NODES_4_KIB => {
                    PublicInputs::<F, SECTOR_NODES_4_KIB>::from(setup_params, pub_inputs)
                        .to_vec()
                        .into()
                }
                SECTOR_NODES_16_KIB => {
                    PublicInputs::<F, SECTOR_NODES_16_KIB>::from(setup_params, pub_inputs)
                        .to_vec()
                        .into()
                }
                SECTOR_NODES_32_KIB => {
                    PublicInputs::<F, SECTOR_NODES_32_KIB>::from(setup_params, pub_inputs)
                        .to_vec()
                        .into()
                }
                SECTOR_NODES_8_MIB => {
                    PublicInputs::<F, SECTOR_NODES_8_MIB>::from(setup_params, pub_inputs)
                        .to_vec()
                        .into()
                }
                SECTOR_NODES_16_MIB => {
                    PublicInputs::<F, SECTOR_NODES_16_MIB>::from(setup_params, pub_inputs)
                        .to_vec()
                        .into()
                }
                SECTOR_NODES_512_MIB => {
                    PublicInputs::<F, SECTOR_NODES_512_MIB>::from(setup_params, pub_inputs)
                        .to_vec()
                        .into()
                }
                SECTOR_NODES_32_GIB => {
                    PublicInputs::<F, SECTOR_NODES_32_GIB>::from(setup_params, pub_inputs)
                        .to_vec()
                        .into()
                }
                SECTOR_NODES_64_GIB => {
                    PublicInputs::<F, SECTOR_NODES_64_GIB>::from(setup_params, pub_inputs)
                        .to_vec()
                        .into()
                }
                _ => unreachable!(),
            }
        })
        .collect();

    Ok(circ_pub_inputs)
}

/// Given a value, get one suitable for aggregation.
fn get_aggregate_target_len(len: usize) -> usize {
    if len == 1 {
        2
    } else {
        len.next_power_of_two()
    }
}

/// Given a list of proofs and a target_len, make sure that the proofs list is padded to the target_len size.
fn pad_proofs_to_target(proofs: &mut Vec<groth16::Proof<Bls12>>, target_len: usize) -> Result<()> {
    trace!(
        "pad_proofs_to_target target_len {}, proofs len {}",
        target_len,
        proofs.len()
    );
    ensure!(
        target_len >= proofs.len(),
        "target len must be greater than actual num proofs"
    );
    ensure!(
        proofs.last().is_some(),
        "invalid last proof for duplication"
    );

    let last = proofs
        .last()
        .expect("invalid last proof for duplication")
        .clone();
    let mut padding: Vec<groth16::Proof<Bls12>> = (0..target_len - proofs.len())
        .map(|_| last.clone())
        .collect();
    proofs.append(&mut padding);

    ensure!(
        proofs.len().next_power_of_two() == proofs.len(),
        "proof count must be a power of 2 for aggregation"
    );
    ensure!(
        proofs.len() <= SRS_MAX_PROOFS_TO_AGGREGATE,
        "proof count for aggregation is larger than the max supported value"
    );

    Ok(())
}

/// Given a list of public inputs and a target_len, make sure that the inputs list is padded to the target_len size.
fn pad_inputs_to_target(
    commit_inputs: &[Vec<Fr>],
    num_inputs_per_proof: usize,
    target_len: usize,
) -> Result<Vec<Vec<Fr>>> {
    ensure!(
        !commit_inputs.is_empty(),
        "cannot aggregate with empty public inputs"
    );

    let mut num_inputs = commit_inputs.len();
    let mut new_inputs = commit_inputs.to_owned();

    if target_len != num_inputs {
        ensure!(
            target_len > num_inputs,
            "target len must be greater than actual num inputs"
        );
        let duplicate_inputs = &commit_inputs[(num_inputs - num_inputs_per_proof)..num_inputs];

        trace!("padding inputs from {} to {}", num_inputs, target_len);
        while target_len != num_inputs {
            new_inputs.extend_from_slice(duplicate_inputs);
            num_inputs += num_inputs_per_proof;
        }
    }

    Ok(new_inputs)
}

/// Given a porep_config and a list of seal commit outputs, this method aggregates
/// those proofs (naively padding the count if necessary up to a power of 2) and
/// returns the aggregate proof bytes.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `seeds` - an ordered list of seeds used to derive the PoRep challenges.
/// * `commit_outputs` - an ordered list of seal proof outputs returned from 'seal_commit_phase2'.
pub fn aggregate_seal_commit_proofs<Tree>(
    porep_config: PoRepConfig,
    comm_rs: &[[u8; 32]],
    seeds: &[[u8; 32]],
    commit_outputs: &[SealCommitOutput],
    aggregate_version: groth16::aggregate::AggregateVersion,
) -> Result<AggregateSnarkProof>
where
    Tree: 'static + MerkleTreeTrait<Field = Fr>,
    Tree::Hasher: Groth16Hasher,
{
    info!("aggregate_seal_commit_proofs:start");

    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    ensure!(
        !commit_outputs.is_empty(),
        "cannot aggregate with empty outputs"
    );

    let partitions = usize::from(PoRepProofPartitions::from(porep_config));
    let verifying_key = get_stacked_verifying_key::<Tree>(porep_config)?;
    let mut proofs: Vec<_> =
        commit_outputs
            .iter()
            .try_fold(Vec::new(), |mut acc, commit_output| -> Result<_> {
                acc.extend(
                    MultiProof::new_from_reader(
                        Some(partitions),
                        &commit_output.proof[..],
                        &verifying_key,
                    )?
                    .circuit_proofs,
                );

                Ok(acc)
            })?;
    trace!(
        "aggregate_seal_commit_proofs called with {} commit_outputs containing {} proofs",
        commit_outputs.len(),
        proofs.len(),
    );

    let target_proofs_len = get_aggregate_target_len(proofs.len());
    ensure!(
        target_proofs_len > 1,
        "cannot aggregate less than two proofs"
    );
    trace!(
        "aggregate_seal_commit_proofs will pad proofs to target_len {}",
        target_proofs_len
    );

    // If we're not at the pow2 target, duplicate the last proof until we are.
    pad_proofs_to_target(&mut proofs, target_proofs_len)?;

    // Hash all of the seeds and comm_r's pair-wise into a digest for the aggregate proof method.
    let hashed_seeds_and_comm_rs: [u8; 32] = {
        let mut hasher = Sha256::new();
        for cur in seeds.iter().zip(comm_rs.iter()) {
            let (seed, comm_r) = cur;
            hasher.update(seed);
            hasher.update(comm_r);
        }
        hasher.finalize().into()
    };

    let srs_prover_key = get_stacked_srs_key::<Tree>(porep_config, proofs.len())?;
    let aggregate_proof = StackedCompound::<Tree, DefaultPieceHasher<Fr>>::aggregate_proofs(
        &srs_prover_key,
        &hashed_seeds_and_comm_rs,
        proofs.as_slice(),
        aggregate_version,
    )?;
    let mut aggregate_proof_bytes = Vec::new();
    aggregate_proof.write(&mut aggregate_proof_bytes)?;

    info!("aggregate_seal_commit_proofs:finish");

    Ok(aggregate_proof_bytes)
}

/// Given a porep_config, an aggregate proof, a list of seeds and a combined and flattened list
/// of public inputs, this method verifies the aggregate seal proof.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `seeds` - an ordered list of seeds used to derive the PoRep challenges.
/// * `aggregate_proof_bytes` - the returned aggregate proof from 'aggreate_seal_commit_proofs'.
/// * `commit_inputs` - a flattened/combined and ordered list of all public inputs, which must match
///    the ordering of the seal proofs when aggregated.
pub fn verify_aggregate_seal_commit_proofs<Tree>(
    porep_config: PoRepConfig,
    aggregate_proof_bytes: AggregateSnarkProof,
    comm_rs: &[[u8; 32]],
    seeds: &[[u8; 32]],
    commit_inputs: Vec<Vec<Fr>>,
    aggregate_version: groth16::aggregate::AggregateVersion,
) -> Result<bool>
where
    Tree: 'static + MerkleTreeTrait<Field = Fr>,
    Tree::Hasher: Groth16Hasher,
{
    info!("verify_aggregate_seal_commit_proofs:start");

    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    let aggregate_proof =
        groth16::aggregate::AggregateProof::read(std::io::Cursor::new(&aggregate_proof_bytes))?;

    let aggregated_proofs_len = aggregate_proof.tmipp.gipa.nproofs as usize;

    ensure!(aggregated_proofs_len != 0, "cannot verify zero proofs");
    ensure!(!commit_inputs.is_empty(), "cannot verify with empty inputs");
    ensure!(
        comm_rs.len() == seeds.len(),
        "invalid comm_rs and seeds len mismatch"
    );

    trace!(
        "verify_aggregate_seal_commit_proofs called with len {}",
        aggregated_proofs_len,
    );

    ensure!(
        aggregated_proofs_len > 1,
        "cannot verify less than two proofs"
    );
    ensure!(
        aggregated_proofs_len == aggregated_proofs_len.next_power_of_two(),
        "cannot verify non-pow2 aggregate seal proofs"
    );

    let num_inputs = commit_inputs.len();
    let num_inputs_per_proof = get_aggregate_target_len(num_inputs) / aggregated_proofs_len;
    let target_inputs_len = aggregated_proofs_len * num_inputs_per_proof;
    ensure!(
        target_inputs_len % aggregated_proofs_len == 0,
        "invalid number of inputs provided",
    );

    trace!(
        "verify_aggregate_seal_commit_proofs got {} inputs with {} inputs per proof",
        num_inputs,
        target_inputs_len / aggregated_proofs_len,
    );

    // Pad public inputs if needed.
    let commit_inputs =
        pad_inputs_to_target(&commit_inputs, num_inputs_per_proof, target_inputs_len)?;

    let verifying_key = get_stacked_verifying_key::<Tree>(porep_config)?;
    let srs_verifier_key =
        get_stacked_srs_verifier_key::<Tree>(porep_config, aggregated_proofs_len)?;

    // Hash all of the seeds and comm_r's pair-wise into a digest for the aggregate proof method.
    let hashed_seeds_and_comm_rs: [u8; 32] = {
        let mut hasher = Sha256::new();
        for cur in seeds.iter().zip(comm_rs.iter()) {
            let (seed, comm_r) = cur;
            hasher.update(seed);
            hasher.update(comm_r);
        }
        hasher.finalize().into()
    };

    trace!("start verifying aggregate proof");
    let result = StackedCompound::<Tree, DefaultPieceHasher<Fr>>::verify_aggregate_proofs(
        &srs_verifier_key,
        &verifying_key,
        &hashed_seeds_and_comm_rs,
        commit_inputs.as_slice(),
        &aggregate_proof,
        aggregate_version,
    )?;
    trace!("end verifying aggregate proof");

    info!("verify_aggregate_seal_commit_proofs:finish");

    Ok(result)
}

/// Computes a sectors's `comm_d` given its pieces.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `piece_infos` - the piece info (commitment and byte length) for each piece in this sector.
pub fn compute_comm_d<F>(sector_size: SectorSize, piece_infos: &[PieceInfo]) -> Result<Commitment>
where
    F: PrimeField,
    DefaultPieceHasher<F>: Hasher,
{
    trace!("compute_comm_d:start");

    let result = pieces::compute_comm_d::<F>(sector_size, piece_infos);

    trace!("compute_comm_d:finish");
    result
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
pub fn verify_seal<Tree>(
    porep_config: PoRepConfig,
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    proof_vec: &[u8],
) -> Result<bool>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
{
    info!("verify_seal:start: {:?}", sector_id);

    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    ensure!(comm_d_in != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r_in != [0; 32], "Invalid all zero commitment (comm_r)");
    ensure!(!proof_vec.is_empty(), "Invalid proof bytes (empty vector)");

    let result = match get_proof_system::<Tree>() {
        ProofSystem::Groth => groth16_verify_seal::<Tree>(
            porep_config,
            comm_r_in,
            comm_d_in,
            prover_id,
            sector_id,
            ticket,
            seed,
            proof_vec,
        ),
        ProofSystem::HaloPallas => {
            halo2_verify_seal::<Fp, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>(
                porep_config,
                comm_r_in,
                comm_d_in,
                prover_id,
                sector_id,
                ticket,
                seed,
                proof_vec,
            )
        }
        ProofSystem::HaloVesta => {
            halo2_verify_seal::<Fq, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>(
                porep_config,
                comm_r_in,
                comm_d_in,
                prover_id,
                sector_id,
                ticket,
                seed,
                proof_vec,
            )
        }
    };

    info!("verify_seal:finish: {:?}", sector_id);
    result
}

fn groth16_verify_seal<Tree>(
    porep_config: PoRepConfig,
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    proof_vec: &[u8],
) -> Result<bool>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArity<Fr>,
    Tree::SubTreeArity: PoseidonArity<Fr>,
    Tree::TopTreeArity: PoseidonArity<Fr>,
{
    let comm_r: DefaultTreeDomain<Fr> = as_safe_commitment(&comm_r_in, "comm_r")?;
    let comm_d: DefaultPieceDomain<Fr> = as_safe_commitment(&comm_d_in, "comm_d")?;

    let replica_id = generate_replica_id::<DefaultTreeHasher<Fr>, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        StackedDrg<
            '_,
            MerkleTreeWrapper<
                DefaultTreeHasher<Fr>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >,
            DefaultPieceHasher<Fr>,
        >,
    > = StackedCompound::setup(&compound_setup_params)?;

    let public_inputs = stacked::PublicInputs::<DefaultTreeDomain<Fr>, DefaultPieceDomain<Fr>> {
        replica_id,
        tau: Some(Tau { comm_r, comm_d }),
        seed,
        k: None,
    };

    let sector_bytes = PaddedBytesAmount::from(porep_config);
    let verifying_key = get_stacked_verifying_key::<
        MerkleTreeWrapper<
            DefaultTreeHasher<Fr>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >(porep_config)?;

    trace!(
        "got verifying key ({:?}) while verifying seal",
        sector_bytes
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
            minimum_challenges: *POREP_MINIMUM_CHALLENGES
                .read()
                .expect("POREP_MINIMUM_CHALLENGES poisoned")
                .get(&u64::from(SectorSize::from(porep_config)))
                .expect("unknown sector size") as usize,
        },
    )
}

fn halo2_verify_seal<F, U, V, W>(
    porep_config: PoRepConfig,
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    proof_bytes: &[u8],
) -> Result<bool>
where
    F: Halo2Field,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    DefaultPieceHasher<F>: Hasher<Field = F>,
    DefaultTreeHasher<F>: Hasher<Field = F>,
{
    let sector_bytes: u64 = porep_config.sector_size.into();
    let sector_nodes = sector_bytes as usize >> 5;
    let partition_count: usize = porep_config.partitions.into();

    let vanilla_setup_params = setup_params(
        porep_config.sector_size.into(),
        porep_config.partitions.into(),
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let comm_r: DefaultTreeDomain<F> = as_safe_commitment(&comm_r_in, "comm_r")?;
    let comm_d: DefaultPieceDomain<F> = as_safe_commitment(&comm_d_in, "comm_d")?;

    let replica_id = generate_replica_id::<DefaultTreeHasher<F>, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let vanilla_pub_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(Tau { comm_d, comm_r }),
        k: None,
        seed,
    };

    let proofs_byte_len = proof_bytes.len();
    assert_eq!(proofs_byte_len % partition_count, 0);
    let proof_byte_len = proofs_byte_len / partition_count;
    let proofs_bytes = proof_bytes.chunks(proof_byte_len).map(Vec::<u8>::from);

    match sector_nodes {
        SECTOR_NODES_2_KIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, SdrPorepCircuit<F, U, V, W, SECTOR_NODES_2_KIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = SdrPorepCircuit::<F, U, V, W, SECTOR_NODES_2_KIB>::blank_circuit();

            trace!(
                "creating halo2 params ({:?}) while verifying seal",
                sector_bytes
            );
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::create_keypair(
                &circ
            )?;

            trace!(
                "got verifying key ({:?}) while verifying seal",
                sector_bytes
            );

            <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_4_KIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, SdrPorepCircuit<F, U, V, W, SECTOR_NODES_4_KIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = SdrPorepCircuit::<F, U, V, W, SECTOR_NODES_4_KIB>::blank_circuit();

            trace!(
                "creating halo2 params ({:?}) while verifying seal",
                sector_bytes
            );
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::create_keypair(
                &circ
            )?;

            trace!(
                "got verifying key ({:?}) while verifying seal",
                sector_bytes
            );

            <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_16_KIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, SdrPorepCircuit<F, U, V, W, SECTOR_NODES_16_KIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = SdrPorepCircuit::<F, U, V, W, SECTOR_NODES_16_KIB>::blank_circuit();

            trace!(
                "creating halo2 params ({:?}) while verifying seal",
                sector_bytes
            );
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::create_keypair(
                &circ
            )?;

            trace!(
                "got verifying key ({:?}) while verifying seal",
                sector_bytes
            );

            <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_32_KIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, SdrPorepCircuit<F, U, V, W, SECTOR_NODES_32_KIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = SdrPorepCircuit::<F, U, V, W, SECTOR_NODES_32_KIB>::blank_circuit();

            trace!(
                "creating halo2 params ({:?}) while verifying seal",
                sector_bytes
            );
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::create_keypair(
                &circ
            )?;

            trace!(
                "got verifying key ({:?}) while verifying seal",
                sector_bytes
            );

            <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_8_MIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, SdrPorepCircuit<F, U, V, W, SECTOR_NODES_8_MIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = SdrPorepCircuit::<F, U, V, W, SECTOR_NODES_8_MIB>::blank_circuit();

            trace!(
                "creating halo2 params ({:?}) while verifying seal",
                sector_bytes
            );
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::create_keypair(
                &circ
            )?;

            trace!(
                "got verifying key ({:?}) while verifying seal",
                sector_bytes
            );

            <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_16_MIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, SdrPorepCircuit<F, U, V, W, SECTOR_NODES_16_MIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = SdrPorepCircuit::<F, U, V, W, SECTOR_NODES_16_MIB>::blank_circuit();

            trace!(
                "creating halo2 params ({:?}) while verifying seal",
                sector_bytes
            );
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::create_keypair(
                &circ
            )?;

            trace!(
                "got verifying key ({:?}) while verifying seal",
                sector_bytes
            );

            <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_512_MIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, SdrPorepCircuit<F, U, V, W, SECTOR_NODES_512_MIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = SdrPorepCircuit::<F, U, V, W, SECTOR_NODES_512_MIB>::blank_circuit();

            trace!(
                "creating halo2 params ({:?}) while verifying seal",
                sector_bytes
            );
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::create_keypair(
                &circ
            )?;

            trace!(
                "got verifying key ({:?}) while verifying seal",
                sector_bytes
            );

            <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_32_GIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, SdrPorepCircuit<F, U, V, W, SECTOR_NODES_32_GIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = SdrPorepCircuit::<F, U, V, W, SECTOR_NODES_32_GIB>::blank_circuit();

            trace!(
                "creating halo2 params ({:?}) while verifying seal",
                sector_bytes
            );
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::create_keypair(
                &circ
            )?;

            trace!(
                "got verifying key ({:?}) while verifying seal",
                sector_bytes
            );

            <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_64_GIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, SdrPorepCircuit<F, U, V, W, SECTOR_NODES_64_GIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = SdrPorepCircuit::<F, U, V, W, SECTOR_NODES_64_GIB>::blank_circuit();

            trace!(
                "creating halo2 params ({:?}) while verifying seal",
                sector_bytes
            );
            let keypair = <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::create_keypair(
                &circ
            )?;

            trace!(
                "got verifying key ({:?}) while verifying seal",
                sector_bytes
            );

            <StackedDrg<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
                DefaultPieceHasher<F>,
            > as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        _ => unimplemented!(),
    };

    Ok(true)
}
