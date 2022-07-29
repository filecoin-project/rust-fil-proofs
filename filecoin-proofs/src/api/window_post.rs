use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::marker::PhantomData;

use anyhow::{ensure, Context, Result};
use blstrs::Scalar as Fr;
use filecoin_hashers::{Hasher, PoseidonArity};
use generic_array::typenum::U8;
use halo2_proofs::pasta::{Fp, Fq};
use log::info;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    halo2::{self, Halo2Field, Halo2Proof},
    merkle::{MerkleTreeTrait, MerkleTreeWrapper},
    multi_proof::MultiProof,
    proof::ProofScheme,
    sector::SectorId,
};
use storage_proofs_post::{
    fallback::{self, FallbackPoSt, FallbackPoStCompound, PrivateSector, PublicSector},
    halo2::{
        constants::{
            SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_1_GIB, SECTOR_NODES_2_KIB,
            SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB,
            SECTOR_NODES_64_GIB, SECTOR_NODES_8_MIB,
        },
        PostCircuit, WindowPostCircuit,
    },
};

use crate::{
    api::{
        as_safe_commitment, get_partitions_for_window_post, get_proof_system,
        partition_vanilla_proofs, single_partition_vanilla_proofs, MockStore,
        PoseidonArityAllFields, ProofSystem,
    },
    caches::{get_post_params, get_post_verifying_key},
    constants::{DefaultOctTreeStore, DefaultTreeDomain, DefaultTreeHasher},
    parameters::window_post_setup_params,
    types::{
        ChallengeSeed, FallbackPoStSectorProof, PersistentAux, PoStConfig, PrivateReplicaInfo,
        ProverId, PublicReplicaInfo, SnarkProof,
    },
    PartitionSnarkProof, PoStType,
};

/// Generates a Window proof-of-spacetime with provided vanilla proofs.
pub fn generate_window_post_with_vanilla<Tree>(
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
    info!("generate_window_post_with_vanilla:start");
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );
    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    let proof_bytes = match get_proof_system::<Tree>() {
        ProofSystem::Groth => groth16_generate_window_post_with_vanilla::<Tree>(
            post_config,
            randomness,
            prover_id,
            vanilla_proofs,
        )?,
        ProofSystem::HaloPallas => halo2_generate_window_post_with_vanilla::<Tree, Fp>(
            post_config,
            randomness,
            prover_id,
            vanilla_proofs,
        )?,
        ProofSystem::HaloVesta => halo2_generate_window_post_with_vanilla::<Tree, Fq>(
            post_config,
            randomness,
            prover_id,
            vanilla_proofs,
        )?,
    };

    info!("generate_window_post_with_vanilla:finish");
    Ok(proof_bytes)
}

fn groth16_generate_window_post_with_vanilla<Tree>(
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

    let vanilla_params = window_post_setup_params(post_config);
    let partitions = get_partitions_for_window_post(vanilla_proofs.len(), post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let partitions = partitions.unwrap_or(1);

    let pub_params: compound_proof::PublicParams<
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
    > = FallbackPoStCompound::setup(&setup_params)?;

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

    let partitioned_proofs = partition_vanilla_proofs(
        post_config,
        &pub_params.vanilla_params,
        &pub_inputs,
        partitions,
        &vanilla_proofs,
    )?;

    let proof = FallbackPoStCompound::prove_with_vanilla(
        &pub_params,
        &pub_inputs,
        partitioned_proofs,
        &groth_params,
    )?;

    proof.to_vec()
}

fn halo2_generate_window_post_with_vanilla<Tree, F>(
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

    let vanilla_setup_params = window_post_setup_params(post_config);
    let partition_count =
        get_partitions_for_window_post(vanilla_proofs.len(), post_config).unwrap_or(1);

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

    let vanilla_partition_proofs = partition_vanilla_proofs(
        post_config,
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        partition_count,
        &vanilla_proofs,
    )?;

    let sector_nodes = vanilla_setup_params.sector_size as usize >> 5;

    let proof_bytes: Vec<u8> =
        match sector_nodes {
            SECTOR_NODES_2_KIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_4_KIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_16_KIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_32_KIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_8_MIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_16_MIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_512_MIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_1_GIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_1_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_32_GIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_64_GIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            _ => unreachable!(),
        };

    Ok(proof_bytes)
}

/// Generates a Window proof-of-spacetime.
pub fn generate_window_post<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo<Tree>>,
    prover_id: ProverId,
) -> Result<SnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
    DefaultTreeHasher<Tree::Field>: Hasher,
{
    info!("generate_window_post:start");
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );
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
        ProofSystem::Groth => groth16_generate_window_post_without_vanilla(
            post_config,
            randomness,
            replicas,
            prover_id,
        )?,
        ProofSystem::HaloPallas => halo2_generate_window_post_without_vanilla::<Tree, Fp>(
            post_config,
            randomness,
            replicas,
            prover_id,
        )?,
        ProofSystem::HaloVesta => halo2_generate_window_post_without_vanilla::<Tree, Fq>(
            post_config,
            randomness,
            replicas,
            prover_id,
        )?,
    };

    info!("generate_window_post:finish");
    Ok(proof_bytes)
}

#[allow(clippy::unwrap_used)]
fn groth16_generate_window_post_without_vanilla<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo<Tree>>,
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

    let vanilla_params = window_post_setup_params(post_config);
    let partitions = get_partitions_for_window_post(replicas.len(), post_config);

    let sector_count = vanilla_params.sector_count;
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let pub_params: compound_proof::PublicParams<
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
    > = FallbackPoStCompound::setup(&setup_params)?;

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
    let replicas_transmuted: Vec<_> = replicas
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
            (*sector_id, replica)
        })
        .collect();

    let trees: Vec<_> = replicas_transmuted
        .par_iter()
        .map(|(sector_id, replica)| {
            replica
                .merkle_tree(post_config.sector_size)
                .with_context(|| {
                    format!("generate_window_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut pub_sectors = Vec::with_capacity(sector_count);
    let mut priv_sectors = Vec::with_capacity(sector_count);

    for ((sector_id, replica), tree) in replicas_transmuted.iter().zip(trees.iter()) {
        let comm_r = replica.safe_comm_r().with_context(|| {
            format!("generate_window_post: safe_comm_r failed: {:?}", sector_id)
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

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs {
        sectors: &priv_sectors,
    };

    FallbackPoStCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &groth_params)?.to_vec()
}

#[allow(clippy::unwrap_used)]
fn halo2_generate_window_post_without_vanilla<Tree, F>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo<Tree>>,
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

    let vanilla_setup_params = window_post_setup_params(post_config);
    let sector_count = vanilla_setup_params.sector_count;

    let vanilla_pub_params = FallbackPoSt::<
        MerkleTreeWrapper<
            DefaultTreeHasher<F>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >::setup(&vanilla_setup_params)?;

    // Transmute `replicas`' `Tree` type.
    let replicas_transmuted: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_c = *(&replica.aux.comm_c as &dyn Any)
                .downcast_ref::<DefaultTreeDomain<F>>()
                .unwrap();
            let comm_r_last = *(&replica.aux.comm_r_last as &dyn Any)
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
            (*sector_id, replica)
        })
        .collect();

    let trees: Vec<_> = replicas_transmuted
        .par_iter()
        .map(|(sector_id, replica)| {
            replica
                .merkle_tree(post_config.sector_size)
                .with_context(|| {
                    format!("generate_window_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut pub_sectors = Vec::with_capacity(sector_count);
    let mut priv_sectors = Vec::with_capacity(sector_count);

    for ((sector_id, replica), tree) in replicas_transmuted.iter().zip(trees.iter()) {
        let comm_r = replica.safe_comm_r().with_context(|| {
            format!("generate_window_post: safe_comm_r failed: {:?}", sector_id)
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

    let vanilla_pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let vanilla_priv_inputs = fallback::PrivateInputs {
        sectors: &priv_sectors,
    };

    let partition_count = get_partitions_for_window_post(replicas.len(), post_config).unwrap_or(1);
    let vanilla_partition_proofs = FallbackPoSt::prove_all_partitions(
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        &vanilla_priv_inputs,
        partition_count,
    )?;

    let sector_nodes = vanilla_setup_params.sector_size as usize >> 5;

    let proof_bytes: Vec<u8> =
        match sector_nodes {
            SECTOR_NODES_2_KIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_4_KIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_16_KIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_32_KIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_8_MIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_16_MIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_512_MIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_1_GIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_1_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_32_GIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            SECTOR_NODES_64_GIB => {
                let circ = PostCircuit::from(WindowPostCircuit::<
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

                let circ_partition_proofs = <FallbackPoSt<'_, MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >> as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::prove_all_partitions_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proofs,
                &keypair,
            )?;

                circ_partition_proofs
                    .iter()
                    .flat_map(|halo_proof| halo_proof.as_bytes().to_vec())
                    .collect()
            }
            _ => unreachable!(),
        };

    Ok(proof_bytes)
}

/// Verifies a window proof-of-spacetime.
pub fn verify_window_post<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
{
    info!("verify_window_post:start");

    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );
    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    let is_valid = match get_proof_system::<Tree>() {
        ProofSystem::Groth => {
            groth16_verify_window_post::<Tree>(post_config, randomness, replicas, prover_id, proof)?
        }
        ProofSystem::HaloPallas => halo2_verify_window_post::<
            Fp,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >(post_config, randomness, replicas, prover_id, proof)?,
        ProofSystem::HaloVesta => halo2_verify_window_post::<
            Fq,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >(post_config, randomness, replicas, prover_id, proof)?,
    };

    if !is_valid {
        return Ok(false);
    }

    info!("verify_window_post:finish");
    Ok(true)
}

fn groth16_verify_window_post<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArity<Fr>,
    Tree::SubTreeArity: PoseidonArity<Fr>,
    Tree::TopTreeArity: PoseidonArity<Fr>,
{
    let randomness_safe: DefaultTreeDomain<Fr> = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: DefaultTreeDomain<Fr> = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(post_config);
    let partitions = get_partitions_for_window_post(replicas.len(), post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: false,
    };

    let pub_params: compound_proof::PublicParams<
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
    > = FallbackPoStCompound::setup(&setup_params)?;

    let pub_sectors: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_r: DefaultTreeDomain<Fr> = replica.safe_comm_r().with_context(|| {
                format!("verify_window_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            Ok(PublicSector {
                id: *sector_id,
                comm_r,
            })
        })
        .collect::<Result<_>>()?;

    let pub_inputs = fallback::PublicInputs {
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

    let multi_proof = MultiProof::new_from_reader(partitions, proof, &verifying_key)?;

    FallbackPoStCompound::verify(
        &pub_params,
        &pub_inputs,
        &multi_proof,
        &fallback::ChallengeRequirements {
            minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
        },
    )
}

fn halo2_verify_window_post<F, U, V, W>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool>
where
    F: Halo2Field,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    DefaultTreeHasher<F>: Hasher<Field = F>,
{
    let randomness_safe: DefaultTreeDomain<F> = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: DefaultTreeDomain<F> = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_setup_params = window_post_setup_params(post_config);
    let partition_count = get_partitions_for_window_post(replicas.len(), post_config).unwrap_or(1);

    let pub_sectors: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_r: DefaultTreeDomain<F> = replica.safe_comm_r().with_context(|| {
                format!("verify_window_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            Ok(PublicSector {
                id: *sector_id,
                comm_r,
            })
        })
        .collect::<Result<_>>()?;

    let vanilla_pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let proofs_byte_len = proof.len();
    assert_eq!(proofs_byte_len % partition_count, 0);
    let proof_byte_len = proofs_byte_len / partition_count;
    let proofs_bytes = proof.chunks(proof_byte_len).map(Vec::<u8>::from);

    let sector_nodes = vanilla_setup_params.sector_size as usize >> 5;

    match sector_nodes {
        SECTOR_NODES_2_KIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_2_KIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = PostCircuit::from(
                WindowPostCircuit::<F, U, V, W, SECTOR_NODES_2_KIB>::blank_circuit(),
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
            >> as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_4_KIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_4_KIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = PostCircuit::from(
                WindowPostCircuit::<F, U, V, W, SECTOR_NODES_4_KIB>::blank_circuit(),
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
            >> as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_16_KIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_16_KIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = PostCircuit::from(
                WindowPostCircuit::<F, U, V, W, SECTOR_NODES_16_KIB>::blank_circuit(),
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
            >> as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_32_KIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_32_KIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = PostCircuit::from(
                WindowPostCircuit::<F, U, V, W, SECTOR_NODES_32_KIB>::blank_circuit(),
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
            >> as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_8_MIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_8_MIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = PostCircuit::from(
                WindowPostCircuit::<F, U, V, W, SECTOR_NODES_8_MIB>::blank_circuit(),
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
            >> as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_16_MIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_16_MIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = PostCircuit::from(
                WindowPostCircuit::<F, U, V, W, SECTOR_NODES_16_MIB>::blank_circuit(),
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
            >> as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_512_MIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_512_MIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = PostCircuit::from(
                WindowPostCircuit::<F, U, V, W, SECTOR_NODES_512_MIB>::blank_circuit(),
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
            >> as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_1_GIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_1_GIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = PostCircuit::from(
                WindowPostCircuit::<F, U, V, W, SECTOR_NODES_1_GIB>::blank_circuit(),
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
            >> as halo2::CompoundProof<F, SECTOR_NODES_1_GIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_32_GIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_32_GIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = PostCircuit::from(
                WindowPostCircuit::<F, U, V, W, SECTOR_NODES_32_GIB>::blank_circuit(),
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
            >> as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        SECTOR_NODES_64_GIB => {
            let circ_partition_proofs: Vec<
                Halo2Proof<F::Affine, PostCircuit<F, U, V, W, SECTOR_NODES_64_GIB>>,
            > = proofs_bytes.map(Into::into).collect();

            let circ = PostCircuit::from(
                WindowPostCircuit::<F, U, V, W, SECTOR_NODES_64_GIB>::blank_circuit(),
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
            >> as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::verify_all_partitions(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &circ_partition_proofs,
                &keypair,
            )?;
        }
        _ => unreachable!(),
    };

    Ok(true)
}

/// Generates a Window proof-of-spacetime with provided vanilla proofs of a single partition.
pub fn generate_single_window_post_with_vanilla<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
    partition_index: usize,
) -> Result<PartitionSnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
{
    info!("generate_single_window_post_with_vanilla:start");
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );
    ensure!(
        TypeId::of::<Tree::Hasher>() == TypeId::of::<DefaultTreeHasher<Tree::Field>>(),
        "tree hasher must be poseidon",
    );

    let proof_bytes = match get_proof_system::<Tree>() {
        ProofSystem::Groth => groth16_generate_single_window_post_with_vanilla::<Tree>(
            post_config,
            randomness,
            prover_id,
            vanilla_proofs,
            partition_index,
        )?,
        ProofSystem::HaloPallas => halo2_generate_single_window_post_with_vanilla::<Tree, Fp>(
            post_config,
            randomness,
            prover_id,
            vanilla_proofs,
            partition_index,
        )?,
        ProofSystem::HaloVesta => halo2_generate_single_window_post_with_vanilla::<Tree, Fq>(
            post_config,
            randomness,
            prover_id,
            vanilla_proofs,
            partition_index,
        )?,
    };

    info!("generate_single_window_post_with_vanilla:finish");
    Ok(proof_bytes)
}

fn groth16_generate_single_window_post_with_vanilla<Tree>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
    partition_index: usize,
) -> Result<PartitionSnarkProof>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArity<Fr>,
    Tree::SubTreeArity: PoseidonArity<Fr>,
    Tree::TopTreeArity: PoseidonArity<Fr>,
{
    let randomness_safe: DefaultTreeDomain<Fr> = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: DefaultTreeDomain<Fr> = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(post_config);
    let partitions = get_partitions_for_window_post(vanilla_proofs.len(), post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let pub_params: compound_proof::PublicParams<
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
    > = FallbackPoStCompound::setup(&setup_params)?;

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
        k: Some(partition_index),
    };

    let partitioned_proofs = single_partition_vanilla_proofs(
        post_config,
        &pub_params.vanilla_params,
        &pub_inputs,
        &vanilla_proofs,
    )?;

    let proof = FallbackPoStCompound::prove_with_vanilla(
        &pub_params,
        &pub_inputs,
        vec![partitioned_proofs],
        &groth_params,
    )?;

    proof.to_vec().map(PartitionSnarkProof)
}

#[allow(clippy::unwrap_used)]
fn halo2_generate_single_window_post_with_vanilla<Tree, F>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_sector_proofs: Vec<FallbackPoStSectorProof<Tree>>,
    partition_index: usize,
) -> Result<PartitionSnarkProof>
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

    let vanilla_setup_params = window_post_setup_params(post_config);

    let vanilla_pub_params = FallbackPoSt::<
        MerkleTreeWrapper<
            DefaultTreeHasher<F>,
            MockStore,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >::setup(&vanilla_setup_params)?;

    let vanilla_sector_proofs: Vec<
        FallbackPoStSectorProof<
            MerkleTreeWrapper<
                DefaultTreeHasher<F>,
                MockStore,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >,
        >,
    > = unsafe { std::mem::transmute(vanilla_sector_proofs) };

    let pub_sectors: Vec<PublicSector<DefaultTreeDomain<F>>> = vanilla_sector_proofs
        .iter()
        .map(|sector_proof| {
            let comm_r = *(&sector_proof.comm_r as &dyn Any)
                .downcast_ref::<DefaultTreeDomain<F>>()
                .unwrap();
            PublicSector {
                id: sector_proof.sector_id,
                comm_r,
            }
        })
        .collect();

    let vanilla_pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: Some(partition_index),
    };

    let vanilla_partition_proof = single_partition_vanilla_proofs(
        post_config,
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        &vanilla_sector_proofs,
    )?;

    let sector_nodes = vanilla_setup_params.sector_size as usize >> 5;

    let proof_bytes: Vec<u8> = match sector_nodes {
        SECTOR_NODES_2_KIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
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

            <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_2_KIB>>::prove_partition_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
                &keypair,
            )?
            .as_bytes()
            .to_vec()
        }
        SECTOR_NODES_4_KIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
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

            <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_4_KIB>>::prove_partition_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
                &keypair,
            )?
            .as_bytes()
            .to_vec()
        }
        SECTOR_NODES_16_KIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
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

            <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_KIB>>::prove_partition_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
                &keypair,
            )?
            .as_bytes()
            .to_vec()
        }
        SECTOR_NODES_32_KIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
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

            <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_KIB>>::prove_partition_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
                &keypair,
            )?
            .as_bytes()
            .to_vec()
        }
        SECTOR_NODES_8_MIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
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

            <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_8_MIB>>::prove_partition_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
                &keypair,
            )?
            .as_bytes()
            .to_vec()
        }
        SECTOR_NODES_16_MIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
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

            <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_16_MIB>>::prove_partition_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
                &keypair,
            )?
            .as_bytes()
            .to_vec()
        }
        SECTOR_NODES_512_MIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
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

            <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_512_MIB>>::prove_partition_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
                &keypair,
            )?
            .as_bytes()
            .to_vec()
        }
        SECTOR_NODES_1_GIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
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

            <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_1_GIB>>::prove_partition_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
                &keypair,
            )?
            .as_bytes()
            .to_vec()
        }
        SECTOR_NODES_32_GIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
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

            <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_32_GIB>>::prove_partition_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
                &keypair,
            )?
            .as_bytes()
            .to_vec()
        }
        SECTOR_NODES_64_GIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
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

            <FallbackPoSt<
                '_,
                MerkleTreeWrapper<
                    DefaultTreeHasher<F>,
                    MockStore,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >,
            > as halo2::CompoundProof<F, SECTOR_NODES_64_GIB>>::prove_partition_with_vanilla(
                &vanilla_setup_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
                &keypair,
            )?
            .as_bytes()
            .to_vec()
        }
        _ => unreachable!(),
    };

    Ok(PartitionSnarkProof(proof_bytes))
}
