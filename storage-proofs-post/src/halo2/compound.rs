use filecoin_hashers::{poseidon::PoseidonHasher, Hasher};
use halo2_proofs::plonk::Error;
use rand::rngs::OsRng;
use storage_proofs_core::{
    halo2::{
        create_batch_proof, create_proof, verify_batch_proof, verify_proof, CompoundProof, Halo2Field, Halo2Keypair,
        Halo2Proof,
    },
    merkle::MerkleTreeTrait,
};

use crate::{
    fallback::{FallbackPoSt, SetupParams},
    halo2::{
        circuit::PostCircuit,
        constants::{
            SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_1_GIB, SECTOR_NODES_2_KIB,
            SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB,
            SECTOR_NODES_64_GIB, SECTOR_NODES_8_MIB,
        },
        window::{self, WindowPostCircuit},
        winning::{self, WinningPostCircuit},
    },
};

fn is_winning<const SECTOR_NODES: usize>(setup_params: &SetupParams) -> bool {
    assert_eq!(setup_params.sector_size >> 5, SECTOR_NODES as u64);
    match (setup_params.challenge_count, setup_params.sector_count) {
        (winning::CHALLENGE_COUNT, 1) => true,
        (window::SECTOR_CHALLENGES, sectors)
            if sectors == window::sectors_challenged_per_partition::<SECTOR_NODES>() =>
        {
            false
        }
        _ => panic!("setup params do not match winning or window post params"),
    }
}

macro_rules! impl_compound_proof {
    ($($sector_nodes:expr),*) => {
        $(
            impl<'a, F, TreeR> CompoundProof<'a, F, $sector_nodes> for FallbackPoSt<'a, TreeR>
            where
                F: Halo2Field,
                TreeR: MerkleTreeTrait<Field = F, Hasher = PoseidonHasher<F>>,
                PoseidonHasher<F>: Hasher<Field = F>,
            {
                type Circuit = PostCircuit<F, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity, $sector_nodes>;

                fn prove_partition_with_vanilla(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &Self::PublicInputs,
                    vanilla_partition_proof: &Self::Proof,
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<Halo2Proof<F::Affine, Self::Circuit>, Error> {
                    let is_winning = is_winning::<$sector_nodes>(setup_params);

                    let (circ, pub_inputs_vec) = if is_winning {
                        let pub_inputs =
                            winning::PublicInputs::<F, $sector_nodes>::from(vanilla_pub_inputs.clone());

                        let pub_inputs_vec = pub_inputs.to_vec();

                        let priv_inputs = winning::PrivateInputs::<F, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity, $sector_nodes>::from(
                            &vanilla_partition_proof.sectors[0],
                        );

                        let circ = PostCircuit::from(WinningPostCircuit {
                            pub_inputs,
                            priv_inputs,
                        });

                        (circ, pub_inputs_vec)
                    } else {
                        let pub_inputs =
                            window::PublicInputs::<F, $sector_nodes>::from(vanilla_pub_inputs.clone());

                        let pub_inputs_vec = pub_inputs.to_vec();

                        let priv_inputs = window::PrivateInputs::<F, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity, $sector_nodes>::from(
                            &vanilla_partition_proof.sectors,
                        );

                        let circ = PostCircuit::from(WindowPostCircuit {
                            pub_inputs,
                            priv_inputs,
                        });

                        (circ, pub_inputs_vec)
                    };

                    create_proof(keypair, circ, &pub_inputs_vec, &mut OsRng)
                }

                fn prove_all_partitions_with_vanilla(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &Self::PublicInputs,
                    vanilla_proofs: &[Self::Proof],
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<Vec<Halo2Proof<F::Affine, Self::Circuit>>, Error> {
                    let is_winning = is_winning::<$sector_nodes>(setup_params);

                    let partition_count = if is_winning {
                        1
                    } else {
                        let total_prover_sectors = vanilla_pub_inputs.sectors.len();
                        let sectors_challenged_per_partition =
                            window::sectors_challenged_per_partition::<$sector_nodes>();
                        total_prover_sectors / sectors_challenged_per_partition
                    };

                    assert_eq!(vanilla_proofs.len(), partition_count);

                    let mut vanilla_pub_inputs = vanilla_pub_inputs.clone();

                    vanilla_proofs
                        .iter()
                        .enumerate()
                        .map(|(k, partition_proof)| {
                            // The only public input field which should change is `k`.
                            vanilla_pub_inputs.k = Some(k);
                            <Self as CompoundProof<'_, F, $sector_nodes>>::prove_partition_with_vanilla(
                                setup_params,
                                &vanilla_pub_inputs,
                                partition_proof,
                                keypair,
                            )
                        })
                        .collect()
                }

                fn batch_prove_all_partitions_with_vanilla(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &Self::PublicInputs,
                    vanilla_proofs: &[Self::Proof],
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<Halo2Proof<F::Affine, Self::Circuit>, Error> {
                    let is_winning = is_winning::<$sector_nodes>(setup_params);

                    let partition_count = if is_winning {
                        1
                    } else {
                        let total_prover_sectors = vanilla_pub_inputs.sectors.len();
                        let sectors_challenged_per_partition =
                            window::sectors_challenged_per_partition::<$sector_nodes>();
                        total_prover_sectors / sectors_challenged_per_partition
                    };

                    assert_eq!(vanilla_proofs.len(), partition_count);

                    let mut circ_pub_inputs_vecs = Vec::with_capacity(partition_count);

                    let circs: Vec<Self::Circuit> = if is_winning {
                        let pub_inputs = winning::PublicInputs::from(vanilla_pub_inputs.clone());
                        circ_pub_inputs_vecs.push(pub_inputs.to_vec());

                        let priv_inputs = winning::PrivateInputs::from(&vanilla_proofs[0].sectors[0]);

                        let circ = PostCircuit::Winning(WinningPostCircuit {
                            pub_inputs,
                            priv_inputs,
                        });
                        vec![circ]
                    } else {
                        vanilla_proofs
                            .iter()
                            .enumerate()
                            .map(|(k, vanilla_proof)| {
                                // The only public input field which should change is `k`.
                                let mut vanilla_pub_inputs = vanilla_pub_inputs.clone();
                                vanilla_pub_inputs.k = Some(k);

                                let pub_inputs = window::PublicInputs::from(vanilla_pub_inputs);
                                circ_pub_inputs_vecs.push(pub_inputs.to_vec());

                                let priv_inputs =
                                    window::PrivateInputs::from(&vanilla_proof.sectors);

                                PostCircuit::Window(WindowPostCircuit {
                                    pub_inputs,
                                    priv_inputs,
                                })
                            })
                            .collect()
                    };

                    create_batch_proof(keypair, &circs, &circ_pub_inputs_vecs, &mut OsRng)
                }

                fn verify_partition(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &Self::PublicInputs,
                    circ_proof: &Halo2Proof<F::Affine, Self::Circuit>,
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<(), Error> {
                    let is_winning = is_winning::<$sector_nodes>(setup_params);

                    let pub_inputs_vec = if is_winning {
                        winning::PublicInputs::<F, $sector_nodes>::from(vanilla_pub_inputs.clone())
                            .to_vec()
                    } else {
                        window::PublicInputs::<F, $sector_nodes>::from(vanilla_pub_inputs.clone()).to_vec()
                    };

                    verify_proof(keypair, circ_proof, &pub_inputs_vec)
                }

                fn verify_all_partitions(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &Self::PublicInputs,
                    circ_proofs: &[Halo2Proof<F::Affine, Self::Circuit>],
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<(), Error> {
                    let is_winning = is_winning::<$sector_nodes>(setup_params);

                    let partition_count = if is_winning {
                        1
                    } else {
                        let total_prover_sectors = vanilla_pub_inputs.sectors.len();
                        let sectors_challenged_per_partition =
                            window::sectors_challenged_per_partition::<$sector_nodes>();
                        total_prover_sectors / sectors_challenged_per_partition
                    };

                    assert_eq!(circ_proofs.len(), partition_count);

                    let mut vanilla_pub_inputs = vanilla_pub_inputs.clone();

                    for (k, partition_proof) in circ_proofs.iter().enumerate() {
                        // The only public input field which should change is `k`.
                        vanilla_pub_inputs.k = Some(k);
                        <Self as CompoundProof<'_, F, $sector_nodes>>::verify_partition(
                            setup_params,
                            &vanilla_pub_inputs,
                            partition_proof,
                            keypair,
                        )?;
                    }
                    Ok(())
                }

                fn batch_verify_all_partitions(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &Self::PublicInputs,
                    batch_proof: &Halo2Proof<F::Affine, Self::Circuit>,
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<(), Error> {
                    let is_winning = is_winning::<$sector_nodes>(setup_params);

                    let circ_pub_inputs_vecs: Vec<Vec<Vec<F>>> = if is_winning {
                        let pub_inputs = winning::PublicInputs::<F, $sector_nodes>::from(
                            vanilla_pub_inputs.clone(),
                        );
                        vec![pub_inputs.to_vec()]
                    } else {
                        let total_prover_sectors = vanilla_pub_inputs.sectors.len();
                        let sectors_challenged_per_partition =
                            window::sectors_challenged_per_partition::<$sector_nodes>();
                        let partition_count =
                            total_prover_sectors / sectors_challenged_per_partition;
                        (0..partition_count)
                            .map(|k| {
                                // The only public input field which should change is `k`.
                                let mut vanilla_pub_inputs = vanilla_pub_inputs.clone();
                                vanilla_pub_inputs.k = Some(k);
                                window::PublicInputs::<F, $sector_nodes>::from(vanilla_pub_inputs)
                                    .to_vec()
                            })
                            .collect()
                    };

                    verify_batch_proof(keypair, batch_proof, &circ_pub_inputs_vecs, &mut OsRng)
                }
            }
        )*
    }
}

impl_compound_proof!(
    SECTOR_NODES_2_KIB,
    SECTOR_NODES_4_KIB,
    SECTOR_NODES_16_KIB,
    SECTOR_NODES_32_KIB,
    SECTOR_NODES_8_MIB,
    SECTOR_NODES_16_MIB,
    SECTOR_NODES_512_MIB,
    SECTOR_NODES_1_GIB,
    SECTOR_NODES_32_GIB,
    SECTOR_NODES_64_GIB
);

// TODO (jake): remove this?
/*
pub fn winning_post_prove_all<'a, TreeR, const SECTOR_NODES: usize>(
    vanilla_setup_params: &<FallbackPoSt::<'a, TreeR> as ProofScheme<'a>>::SetupParams,
    vanilla_pub_inputs: &<FallbackPoSt::<'a, TreeR> as ProofScheme<'a>>::PublicInputs,
    vanilla_partition_proofs: &[<FallbackPoSt::<'a, TreeR> as ProofScheme<'a>>::Proof],
) -> Result<Vec<u8>, Error>
where
    TreeR: 'a + MerkleTreeTrait,
    <<TreeR::Hasher as Hasher>::Domain as Domain>::Field: FieldExt + Halo2Field,
    PoseidonHasher<<<TreeR::Hasher as Hasher>::Domain as Domain>::Field>: Hasher,
    <PoseidonHasher<<<TreeR::Hasher as Hasher>::Domain as Domain>::Field> as Hasher>::Domain:
        Domain<Field = <<TreeR::Hasher as Hasher>::Domain as Domain>::Field>,
    FallbackPoSt<'a, TreeR>: CompoundProof<
        'a,
        <<TreeR::Hasher as Hasher>::Domain as Domain>::Field,
        SECTOR_NODES,
        Circuit = PostCircuit<
            <<TreeR::Hasher as Hasher>::Domain as Domain>::Field,
            TreeR::Arity,
            TreeR::SubTreeArity,
            TreeR::TopTreeArity,
            SECTOR_NODES,
        >,
    >,
{
    let circ = PostCircuit::from(WinningPostCircuit::<
        <<TreeR::Hasher as Hasher>::Domain as Domain>::Field,
        TreeR::Arity,
        TreeR::SubTreeArity,
        TreeR::TopTreeArity,
        SECTOR_NODES,
    >::blank_circuit());

    let keypair = <FallbackPoSt<'a, TreeR> as CompoundProof<
        'a,
        <<TreeR::Hasher as Hasher>::Domain as Domain>::Field,
        SECTOR_NODES,
    >>::create_keypair(&circ)?;

    let halo_proofs = <FallbackPoSt<'a, TreeR> as CompoundProof<
        'a,
        <<TreeR::Hasher as Hasher>::Domain as Domain>::Field,
        SECTOR_NODES,
    >>::prove_all_partitions_with_vanilla(
        vanilla_setup_params,
        vanilla_pub_inputs,
        vanilla_partition_proofs,
        &keypair,
    )?;

    let proof_byte_len = halo_proofs[0].as_bytes().len();
    // TODO (jake): remove this assert
    assert!(halo_proofs[1..].iter().all(|proof| proof.as_bytes().len() == proof_byte_len));
    let mut proof_bytes = Vec::<u8>::with_capacity(halo_proofs.len() * proof_byte_len);
    for halo_proof in halo_proofs.iter() {
        proof_bytes.extend_from_slice(halo_proof.as_bytes());
    }

    Ok(proof_bytes)
}
*/
