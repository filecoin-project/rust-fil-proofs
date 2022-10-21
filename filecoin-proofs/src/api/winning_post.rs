use std::any::{Any, TypeId};
use std::marker::PhantomData;

use anyhow::{ensure, Context, Result};
use blstrs::Scalar as Fr;
use filecoin_hashers::{Hasher, PoseidonArity};
use generic_array::typenum::U8;
use halo2_proofs::pasta::{Fp, Fq};
use log::info;
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    halo2::{self, Halo2Field, Halo2Proof},
    merkle::{MerkleTreeTrait, MerkleTreeWrapper},
    multi_proof::MultiProof,
    proof::ProofScheme,
    sector::SectorId,
    SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_1_GIB, SECTOR_NODES_2_KIB,
    SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB,
    SECTOR_NODES_64_GIB, SECTOR_NODES_8_MIB,
};
use storage_proofs_post::{
    fallback::{
        self, generate_sector_challenges, FallbackPoSt, FallbackPoStCompound, PrivateSector,
        PublicSector,
    },
    halo2::{PostCircuit, WinningPostCircuit},
};

use crate::{
    api::{
        as_safe_commitment, get_proof_system, partition_vanilla_proofs, MockStore,
        PoseidonArityAllFields, ProofSystem,
    },
    caches::{get_post_params, get_post_verifying_key},
    constants::{
        DefaultOctTreeStore, DefaultTreeDomain, DefaultTreeHasher, WINNING_POST_CHALLENGE_COUNT,
        WINNING_POST_SECTOR_COUNT,
    },
    parameters::winning_post_setup_params,
    types::{
        ChallengeSeed, Commitment, FallbackPoStSectorProof, PersistentAux, PoStConfig,
        PrivateReplicaInfo, ProverId, PublicReplicaInfo, SnarkProof,
    },
    PoStType,
};

/// Generates a Winning proof-of-spacetime with provided vanilla proofs.
pub fn generate_winning_post_with_vanilla<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
) -> Result<SnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
{
    info!("generate_winning_post_with_vanilla:start");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    ensure!(
        post_config.sector_count == 1,
        "invalid Winning PoSt config -- sector_count must be 1"
    );

    // TODO (jake): is this correct? Winning-Post should always have a single vanilla (i.e.
    // partition) proof?
    /* SHAWN
    let partition_count = 1;
    ensure!(vanilla_proofs.len() == partition_count);
    ensure!(vanilla_proofs[0].vanilla_proof.sectors.len() == WINNING_POST_SECTOR_COUNT);
    ensure!(
        vanilla_proofs[0].vanilla_proof.sectors[0]
            .inclusion_proofs
            .len()
            == WINNING_POST_CHALLENGE_COUNT,
    );
    */
    ensure!(
        vanilla_proofs.len() == 1,
        "expected exactly one vanilla proof"
    );

    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    let proof_bytes = match get_proof_system::<Tree>() {
        ProofSystem::Groth => groth16_generate_winning_post_with_vanilla(
            post_config,
            randomness,
            prover_id,
            vanilla_proofs,
        )?,
        ProofSystem::HaloPallas => halo2_generate_winning_post_with_vanilla::<_, Fp>(
            post_config,
            randomness,
            prover_id,
            vanilla_proofs,
        )?,
        ProofSystem::HaloVesta => halo2_generate_winning_post_with_vanilla::<_, Fq>(
            post_config,
            randomness,
            prover_id,
            vanilla_proofs,
        )?,
    };

    info!("generate_winning_post_with_vanilla:finish");
    Ok(proof_bytes)
}

pub fn groth16_generate_winning_post_with_vanilla<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
) -> Result<SnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArity<Fr>,
    Tree::SubTreeArity: PoseidonArity<Fr>,
    Tree::TopTreeArity: PoseidonArity<Fr>,
{
    let randomness_safe: DefaultTreeDomain<Fr> = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: DefaultTreeDomain<Fr> = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_setup_params = winning_post_setup_params(post_config)?;

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: vanilla_setup_params,
        partitions: None,
        priority: post_config.priority,
    };

    let compound_pub_params: compound_proof::PublicParams<
        '_,
        FallbackPoSt<
            '_,
            MerkleTreeWrapper<
                DefaultTreeHasher<Fr>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >,
        >,
    > = FallbackPoStCompound::setup(&compound_setup_params)?;

    let groth_params = get_post_params::<
        MerkleTreeWrapper<
            DefaultTreeHasher<Fr>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >(post_config)?;

    let vanilla_proofs: Vec<
        FallbackPoStSectorProof<
            MerkleTreeWrapper<
                DefaultTreeHasher<Fr>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >,
        >,
    > = unsafe { std::mem::transmute(vanilla_proofs) };

    let mut pub_sectors = Vec::with_capacity(vanilla_proofs.len());
        for vanilla_proof in &vanilla_proofs {
            pub_sectors.push(PublicSector {
                id: vanilla_proof.sector_id,
                comm_r: vanilla_proof.comm_r,
            });
        }
    
    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let partitions = compound_pub_params.partitions.unwrap_or(1);
    // TODO (jake): is this correct?
    assert_eq!(partitions, 1);
    let partitioned_proofs = partition_vanilla_proofs(
        &compound_pub_params.vanilla_params,
        &pub_inputs,
        partitions,
        &vanilla_proofs,
    )?;
    // TODO (jake): is this correct?
    assert_eq!(partitioned_proofs.len(), 1);

    let proof = FallbackPoStCompound::prove_with_vanilla(
        &compound_pub_params,
        &pub_inputs,
        partitioned_proofs,
        &groth_params,
    )?;
    proof.to_vec()
}

fn halo2_generate_winning_post_with_vanilla<Tree, F>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
) -> Result<SnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    F: Halo2Field,
    Tree::Arity: PoseidonArity<F>,
    Tree::SubTreeArity: PoseidonArity<F>,
    Tree::TopTreeArity: PoseidonArity<F>,
    DefaultTreeHasher<F>: Hasher<Field = F>,
{
    let randomness_safe: DefaultTreeDomain<F> = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: DefaultTreeDomain<F> = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_setup_params = winning_post_setup_params(post_config)?;

    let vanilla_pub_params = FallbackPoSt::<
        MerkleTreeWrapper<
            DefaultTreeHasher<F>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >::setup(&vanilla_setup_params)?;

    let vanilla_proofs: Vec<
        FallbackPoStSectorProof<
            MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >,
        >,
    > = unsafe { std::mem::transmute(vanilla_proofs) };

    let mut pub_sectors = Vec::with_capacity(vanilla_proofs.len());
    for vanilla_proof in &vanilla_proofs {
        pub_sectors.push(PublicSector {
            id: vanilla_proof.sector_id,
            comm_r: vanilla_proof.comm_r,
        });
    }

    let vanilla_pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    // TODO (jake): is this correct?
    let partition_count = 1;
    assert_eq!(vanilla_proofs.len(), partition_count);
    let vanilla_partition_proofs = partition_vanilla_proofs(
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        partition_count,
        &vanilla_proofs,
    )?;
    // TODO (jake): is this correct?
    assert_eq!(vanilla_partition_proofs.len(), partition_count);

    let sector_nodes = vanilla_setup_params.sector_size as usize >> 5;

    match sector_nodes {
        SECTOR_NODES_2_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_2_KIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_4_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_4_KIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_16_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_16_KIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_32_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_32_KIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_8_MIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_8_MIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_16_MIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_16_MIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_512_MIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_512_MIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_1_GIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_1_GIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_1_GIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_1_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_32_GIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_32_GIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_64_GIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_64_GIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        _ => unreachable!(),
    }
}

/// Generates a Winning proof-of-spacetime.
pub fn generate_winning_post<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PrivateReplicaInfo<Tree>)],
    prover_id: ProverId,
) -> Result<SnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
    DefaultTreeHasher<Tree::Field>: Hasher,
{
    info!("generate_winning_post:start");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    ensure!(
        replicas.len() == post_config.sector_count,
        "invalid amount of replicas"
    );
    // TODO (jake): is this correct?
    ensure!(replicas.len() == WINNING_POST_SECTOR_COUNT);

    // Ensure that `Tree`'s associated types are as expected; necessary for changing `Tree::Field`
    // into a concrete field type (`Fr`, `Fp`,  or `Fq`).
    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );
    ensure!(
        TypeId::of::<Tree::Store>() == TypeId::of::<DefaultOctTreeStore<Tree::Field>>(),
        "tree store must be `LCStore`",
    );
    ensure!(
        TypeId::of::<Tree::Arity>() == TypeId::of::<U8>(),
        "tree base arity must be 8"
    );

    let proof_bytes = match get_proof_system::<Tree>() {
        ProofSystem::Groth => groth16_generate_winning_post_without_vanilla(
            post_config,
            randomness,
            replicas,
            prover_id,
        )?,
        ProofSystem::HaloPallas => halo2_generate_winning_post_without_vanilla::<_, Fp>(
            post_config,
            randomness,
            replicas,
            prover_id,
        )?,
        ProofSystem::HaloVesta => halo2_generate_winning_post_without_vanilla::<_, Fq>(
            post_config,
            randomness,
            replicas,
            prover_id,
        )?,
    };

    info!("generate_winning_post:finish");
    Ok(proof_bytes)
}

#[allow(clippy::unwrap_used)]
pub fn groth16_generate_winning_post_without_vanilla<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PrivateReplicaInfo<Tree>)],
    prover_id: ProverId,
) -> Result<SnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArity<Fr>,
    Tree::SubTreeArity: PoseidonArity<Fr>,
    Tree::TopTreeArity: PoseidonArity<Fr>,
{
    let randomness_safe: DefaultTreeDomain<Fr> = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: DefaultTreeDomain<Fr> = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_setup_params = winning_post_setup_params(post_config)?;
    let param_sector_count = vanilla_setup_params.sector_count;

    let compound_setup_params = compound_proof::SetupParams::<
        '_,
        FallbackPoSt<
            '_,
            MerkleTreeWrapper<
                DefaultTreeHasher<Fr>,
                DefaultOctTreeStore<Fr>,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >,
        >,
    > {
        vanilla_params: vanilla_setup_params,
        partitions: None,
        priority: post_config.priority,
    };

    let compound_pub_params = FallbackPoStCompound::setup(&compound_setup_params)?;

    let groth_params = get_post_params::<
        MerkleTreeWrapper<
            DefaultTreeHasher<Fr>,
            DefaultOctTreeStore<Fr>,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >(post_config)?;

    // Transmute `replicas`' `Tree` type.
    let mut replicas_transmuted = Vec::with_capacity(param_sector_count);

    let trees = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_c = *(&replica.aux.comm_c as &dyn Any)
                .downcast_ref::<DefaultTreeDomain<Fr>>()
                .unwrap();
            let comm_r_last = *(&replica.aux.comm_r_last as &dyn Any)
                .downcast_ref::<DefaultTreeDomain<Fr>>()
                .unwrap();

            let replica = PrivateReplicaInfo::<
                MerkleTreeWrapper<
                    DefaultTreeHasher<Fr>,
                    DefaultOctTreeStore<Fr>,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > {
                replica: replica.replica.clone(),
                comm_r: replica.comm_r,
                aux: PersistentAux {
                    comm_c,
                    comm_r_last,
                },
                cache_dir: replica.cache_dir.clone(),
                _t: PhantomData,
            };
            replicas_transmuted.push((*sector_id, replica.clone()));
            replica
                .merkle_tree(post_config.sector_size)
                .with_context(|| {
                    format!("generate_winning_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    let mut priv_sectors = Vec::with_capacity(param_sector_count);

    for _ in 0..param_sector_count {
        for ((sector_id, replica), tree) in replicas_transmuted.iter().zip(trees.iter()) {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("generate_winning_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            let comm_c = replica.safe_comm_c();
            let comm_r_last = replica.safe_comm_r_last();

            pub_sectors.push(PublicSector {
                id: *sector_id,
                comm_r,
            });
            priv_sectors.push(PrivateSector::<
                MerkleTreeWrapper<
                    DefaultTreeHasher<Fr>,
                    DefaultOctTreeStore<Fr>,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > {
                tree,
                comm_c,
                comm_r_last,
            });
        }
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs {
        sectors: &priv_sectors,
    };

    FallbackPoStCompound::prove(
        &compound_pub_params,
        &pub_inputs,
        &priv_inputs,
        &groth_params,
    )?
    .to_vec()
}

#[allow(clippy::unwrap_used)]
fn halo2_generate_winning_post_without_vanilla<Tree, F>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PrivateReplicaInfo<Tree>)],
    prover_id: ProverId,
) -> Result<SnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    F: Halo2Field,
    Tree::Arity: PoseidonArity<F>,
    Tree::SubTreeArity: PoseidonArity<F>,
    Tree::TopTreeArity: PoseidonArity<F>,
    DefaultTreeHasher<F>: Hasher<Field = F>,
{
    let randomness_safe: DefaultTreeDomain<F> = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: DefaultTreeDomain<F> = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_setup_params = winning_post_setup_params(post_config)?;
    let param_sector_count = vanilla_setup_params.sector_count;

    let vanilla_pub_params = FallbackPoSt::<
        MerkleTreeWrapper<
            DefaultTreeHasher<F>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >::setup(&vanilla_setup_params)?;

    // Store the replicas after changing their `Tree` to `MerkleTreeWrapper` and field to `F`.
    let mut replicas_transmuted = Vec::with_capacity(param_sector_count);

    let trees = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_r_last = *(&replica.aux.comm_r_last as &dyn Any)
                .downcast_ref::<DefaultTreeDomain<F>>()
                .unwrap();
            let comm_c = *(&replica.aux.comm_c as &dyn Any)
                .downcast_ref::<DefaultTreeDomain<F>>()
                .unwrap();

            let replica = PrivateReplicaInfo::<
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    DefaultOctTreeStore<F>,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > {
                replica: replica.replica.clone(),
                comm_r: replica.comm_r,
                aux: PersistentAux {
                    comm_c,
                    comm_r_last,
                },
                cache_dir: replica.cache_dir.clone(),
                _t: PhantomData,
            };
            replicas_transmuted.push((*sector_id, replica.clone()));
            replica
                .merkle_tree(vanilla_setup_params.sector_size.into())
                .with_context(|| {
                    format!("generate_winning_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    let mut priv_sectors = Vec::with_capacity(param_sector_count);

    // TODO (jake): is there is only one challenged winning-post sector, why are we doing this in
    // two two loops, rather than using `replicas[0]`?
    for _ in 0..param_sector_count {
        for ((sector_id, replica), tree) in replicas_transmuted.iter().zip(trees.iter()) {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("generate_winning_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            let comm_c = replica.safe_comm_c();
            let comm_r_last = replica.safe_comm_r_last();

            pub_sectors.push(PublicSector {
                id: *sector_id,
                comm_r,
            });
            priv_sectors.push(PrivateSector::<
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    DefaultOctTreeStore<F>,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > {
                tree,
                comm_c,
                comm_r_last,
            });
        }
    }

    let vanilla_pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let vanilla_priv_inputs = fallback::PrivateInputs {
        sectors: &priv_sectors,
    };

    // TODO (jake): is this correct?
    let partition_count = 1;
    let vanilla_partition_proofs = FallbackPoSt::prove_all_partitions(
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        &vanilla_priv_inputs,
        partition_count,
    )?;
    // TODO (jake): is this correct?
    assert_eq!(vanilla_partition_proofs.len(), partition_count);
    assert_eq!(
        vanilla_partition_proofs[0].sectors.len(),
        WINNING_POST_SECTOR_COUNT
    );
    assert_eq!(
        vanilla_partition_proofs[0].sectors[0]
            .inclusion_proofs
            .len(),
        WINNING_POST_CHALLENGE_COUNT,
    );

    let sector_nodes = vanilla_setup_params.sector_size as usize >> 5;

    match sector_nodes {
        SECTOR_NODES_2_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_2_KIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_4_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_4_KIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_16_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_16_KIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_32_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_32_KIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_8_MIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_8_MIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_16_MIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_16_MIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_512_MIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_512_MIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_1_GIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_1_GIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_1_GIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_1_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_32_GIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_32_GIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        SECTOR_NODES_64_GIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                F,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
                SECTOR_NODES_64_GIB,
            >::blank_circuit());

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::create_keypair(
                &circ
            )?;

            let circ_partition_proofs = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

            // TODO (jake): is this correct?
            assert_eq!(circ_partition_proofs.len(), partition_count);
            Ok(circ_partition_proofs[0].as_bytes().to_vec())
        }
        _ => unreachable!(),
    }
}

/// Given some randomness and the length of available sectors, generates the challenged sector.
///
/// The returned values are indices in the range of `0..sector_set_size`, requiring the caller
/// to match the index to the correct sector.
pub fn generate_winning_post_sector_challenge<Tree: MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    sector_set_size: u64,
    prover_id: Commitment,
) -> Result<Vec<u64>> {
    info!("generate_winning_post_sector_challenge:start");
    ensure!(sector_set_size != 0, "empty sector set is invalid");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let result = generate_sector_challenges(
        randomness_safe,
        post_config.sector_count,
        sector_set_size,
        prover_id_safe,
    );

    info!("generate_winning_post_sector_challenge:finish");

    result
}

/// Verifies a winning proof-of-spacetime.
///
/// The provided `replicas` must be the same ones as passed to `generate_winning_post`, and be based on
/// the indices generated by `generate_winning_post_sector_challenge`. It is the responsibility of the
/// caller to ensure this.
pub fn verify_winning_post<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PublicReplicaInfo)],
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
{
    info!("verify_winning_post:start");

    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );
    ensure!(
        post_config.sector_count == replicas.len(),
        "invalid amount of replicas provided"
    );
    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    match get_proof_system::<Tree>() {
        ProofSystem::Groth => groth16_verify_winning_post::<Tree>(
            post_config,
            randomness,
            replicas,
            prover_id,
            proof,
        )?,
        ProofSystem::HaloPallas => halo2_verify_winning_post::<
            Fp,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >(post_config, randomness, replicas, prover_id, proof)?,
        ProofSystem::HaloVesta => halo2_verify_winning_post::<
            Fq,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >(post_config, randomness, replicas, prover_id, proof)?,
    };

    info!("verify_winning_post:finish");
    Ok(true)
}

fn groth16_verify_winning_post<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PublicReplicaInfo)],
    prover_id: ProverId,
    proof_bytes: &[u8],
) -> Result<bool>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArity<Fr>,
    Tree::SubTreeArity: PoseidonArity<Fr>,
    Tree::TopTreeArity: PoseidonArity<Fr>,
{
    let vanilla_setup_params = winning_post_setup_params(post_config)?;

    let randomness_safe: DefaultTreeDomain<Fr> = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: DefaultTreeDomain<Fr> = as_safe_commitment(&prover_id, "prover_id")?;

    let param_sector_count = vanilla_setup_params.sector_count;

    let compound_setup_params = compound_proof::SetupParams::<
        '_,
        FallbackPoSt<
            '_,
            MerkleTreeWrapper<
                DefaultTreeHasher<Fr>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >,
        >,
    > {
        vanilla_params: vanilla_setup_params,
        partitions: None,
        priority: false,
    };

    let compound_pub_params = FallbackPoStCompound::setup(&compound_setup_params)?;

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    for _ in 0..param_sector_count {
        for (sector_id, replica) in replicas.iter() {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("verify_winning_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            pub_sectors.push(PublicSector::<DefaultTreeDomain<Fr>> {
                id: *sector_id,
                comm_r,
            });
        }
    }

    let vanilla_pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let verifying_key = get_post_verifying_key::<
        MerkleTreeWrapper<
            DefaultTreeHasher<Fr>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >(post_config)?;

    let single_proof = MultiProof::new_from_reader(None, proof_bytes, &verifying_key)?;
    if single_proof.len() != 1 {
        return Ok(false);
    }

    FallbackPoStCompound::verify(
        &compound_pub_params,
        &vanilla_pub_inputs,
        &single_proof,
        &fallback::ChallengeRequirements {
            minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
        },
    )
}

fn halo2_verify_winning_post<F, U, V, W>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PublicReplicaInfo)],
    prover_id: ProverId,
    proof_bytes: &[u8],
) -> Result<bool>
where
    F: Halo2Field,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    DefaultTreeHasher<F>: Hasher<Field = F>,
{
    let vanilla_setup_params = winning_post_setup_params(post_config)?;

    let sector_nodes = vanilla_setup_params.sector_size as usize >> 5;
    let param_sector_count = vanilla_setup_params.sector_count;

    let randomness_safe: DefaultTreeDomain<F> = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: DefaultTreeDomain<F> = as_safe_commitment(&prover_id, "prover_id")?;

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    for _ in 0..param_sector_count {
        for (sector_id, replica) in replicas.iter() {
            let comm_r = as_safe_commitment(&replica.comm_r, "comm_r")?;
            pub_sectors.push(PublicSector::<DefaultTreeDomain<F>> {
                id: *sector_id,
                comm_r,
            });
        }
    }

    let vanilla_pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    match sector_nodes {
        SECTOR_NODES_2_KIB => {
            let halo_proof =
                Halo2Proof::<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_2_KIB>>::from(
                    proof_bytes.to_vec(),
                );

            let circ = PostCircuit::from(
                WinningPostCircuit::<F, U, V, W, SECTOR_NODES_2_KIB>::blank_circuit(),
            );

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
            > as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::create_keypair(
                &circ
            )?;

            <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                U,
                V,
                W,
            >> as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::verify_partition(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &halo_proof,
                &keypair,
            )?;
        }
        SECTOR_NODES_4_KIB => {
            let halo_proof =
                Halo2Proof::<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_4_KIB>>::from(
                    proof_bytes.to_vec(),
                );

            let circ = PostCircuit::from(
                WinningPostCircuit::<F, U, V, W, SECTOR_NODES_4_KIB>::blank_circuit(),
            );

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
            > as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::create_keypair(
                &circ
            )?;

            <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                U,
                V,
                W,
            >> as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::verify_partition(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &halo_proof,
                &keypair,
            )?;
        }
        SECTOR_NODES_16_KIB => {
            let halo_proof =
                Halo2Proof::<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_16_KIB>>::from(
                    proof_bytes.to_vec(),
                );

            let circ = PostCircuit::from(
                WinningPostCircuit::<F, U, V, W, SECTOR_NODES_16_KIB>::blank_circuit(),
            );

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::create_keypair(
                &circ
            )?;

            <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                U,
                V,
                W,
            >> as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::verify_partition(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &halo_proof,
                &keypair,
            )?;
        }
        SECTOR_NODES_32_KIB => {
            let halo_proof =
                Halo2Proof::<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_32_KIB>>::from(
                    proof_bytes.to_vec(),
                );

            let circ = PostCircuit::from(
                WinningPostCircuit::<F, U, V, W, SECTOR_NODES_32_KIB>::blank_circuit(),
            );

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::create_keypair(
                &circ
            )?;

            <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                U,
                V,
                W,
            >> as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::verify_partition(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &halo_proof,
                &keypair,
            )?;
        }
        SECTOR_NODES_8_MIB => {
            let halo_proof =
                Halo2Proof::<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_8_MIB>>::from(
                    proof_bytes.to_vec(),
                );

            let circ = PostCircuit::from(
                WinningPostCircuit::<F, U, V, W, SECTOR_NODES_8_MIB>::blank_circuit(),
            );

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
            > as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::create_keypair(
                &circ
            )?;

            <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                U,
                V,
                W,
            >> as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::verify_partition(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &halo_proof,
                &keypair,
            )?;
        }
        SECTOR_NODES_16_MIB => {
            let halo_proof =
                Halo2Proof::<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_16_MIB>>::from(
                    proof_bytes.to_vec(),
                );

            let circ = PostCircuit::from(
                WinningPostCircuit::<F, U, V, W, SECTOR_NODES_16_MIB>::blank_circuit(),
            );

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::create_keypair(
                &circ
            )?;

            <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                U,
                V,
                W,
            >> as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::verify_partition(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &halo_proof,
                &keypair,
            )?;
        }
        SECTOR_NODES_512_MIB => {
            let halo_proof =
                Halo2Proof::<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_512_MIB>>::from(
                    proof_bytes.to_vec(),
                );

            let circ = PostCircuit::from(
                WinningPostCircuit::<F, U, V, W, SECTOR_NODES_512_MIB>::blank_circuit(),
            );

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
            > as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::create_keypair(
                &circ
            )?;

            <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                U,
                V,
                W,
            >> as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::verify_partition(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &halo_proof,
                &keypair,
            )?;
        }
        SECTOR_NODES_1_GIB => {
            let halo_proof =
                Halo2Proof::<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_1_GIB>>::from(
                    proof_bytes.to_vec(),
                );

            let circ = PostCircuit::from(
                WinningPostCircuit::<F, U, V, W, SECTOR_NODES_1_GIB>::blank_circuit(),
            );

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
            > as halo2::CompoundProof<F, SECTOR_NODES_1_GIB>>::create_keypair(
                &circ
            )?;

            <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                U,
                V,
                W,
            >> as halo2::CompoundProof<F, SECTOR_NODES_1_GIB>>::verify_partition(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &halo_proof,
                &keypair,
            )?;
        }
        SECTOR_NODES_32_GIB => {
            let halo_proof =
                Halo2Proof::<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_32_GIB>>::from(
                    proof_bytes.to_vec(),
                );

            let circ = PostCircuit::from(
                WinningPostCircuit::<F, U, V, W, SECTOR_NODES_32_GIB>::blank_circuit(),
            );

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::create_keypair(
                &circ
            )?;

            <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                U,
                V,
                W,
            >> as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::verify_partition(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &halo_proof,
                &keypair,
            )?;
        }
        SECTOR_NODES_64_GIB => {
            let halo_proof =
                Halo2Proof::<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_64_GIB>>::from(
                    proof_bytes.to_vec(),
                );

            let circ = PostCircuit::from(
                WinningPostCircuit::<F, U, V, W, SECTOR_NODES_64_GIB>::blank_circuit(),
            );

            let keypair = <FallbackPoSt<
                '_,
                MerkleTreeWrapper<DefaultTreeHasher<F>, MockStore, U, V, W>,
            > as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::create_keypair(
                &circ
            )?;

            <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                U,
                V,
                W,
            >> as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::verify_partition(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &halo_proof,
                &keypair,
            )?;
        }
        _ => unreachable!(),
    };

    Ok(true)
}
