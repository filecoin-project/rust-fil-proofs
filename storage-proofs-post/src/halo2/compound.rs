use filecoin_hashers::{poseidon::PoseidonHasher, Hasher};
use halo2_proofs::plonk::Error;
use rand::rngs::OsRng;
use storage_proofs_core::{
    halo2::{
        create_batch_proof, create_proof, verify_batch_proof, verify_proof, CompoundProof,
        Halo2Field, Halo2Keypair, Halo2Proof,
    },
    merkle::MerkleTreeTrait,
};

use crate::{
    fallback::{self as vanilla, FallbackPoSt, SetupParams},
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
            impl<F, TreeR> CompoundProof<F, $sector_nodes> for FallbackPoSt<'_, TreeR>
            where
                F: Halo2Field,
                TreeR: 'static + MerkleTreeTrait<Field = F, Hasher = PoseidonHasher<F>>,
                PoseidonHasher<F>: Hasher<Field = F>,
            {
                type VanillaSetupParams = SetupParams;
                type VanillaPublicInputs =
                    vanilla::PublicInputs<<PoseidonHasher<F> as Hasher>::Domain>;
                type VanillaPartitionProof = vanilla::Proof<TreeR::Proof>;
                type Circuit = PostCircuit<F, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity, $sector_nodes>;

                fn prove_partition_with_vanilla(
                    setup_params: &Self::VanillaSetupParams,
                    vanilla_pub_inputs: &Self::VanillaPublicInputs,
                    vanilla_partition_proof: &Self::VanillaPartitionProof,
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
                    setup_params: &Self::VanillaSetupParams,
                    vanilla_pub_inputs: &Self::VanillaPublicInputs,
                    vanilla_proofs: &[Self::VanillaPartitionProof],
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<Vec<Halo2Proof<F::Affine, Self::Circuit>>, Error> {
                    let is_winning = is_winning::<$sector_nodes>(setup_params);

                    let partition_count = if is_winning {
                        1
                    } else {
                        let total_prover_sectors = vanilla_pub_inputs.sectors.len();
                        let sectors_challenged_per_partition =
                            window::sectors_challenged_per_partition::<$sector_nodes>();
                        // The prover's sector set length may not be divsible by the number of
                        // sectors challenged per partition; calling `ceil` accounts for this case
                        // where we pad the last partition with the prover's last sector.
                        (total_prover_sectors as f32 / sectors_challenged_per_partition as f32)
                            .ceil() as usize
                    };

                    assert_eq!(vanilla_proofs.len(), partition_count);

                    let mut vanilla_pub_inputs = vanilla_pub_inputs.clone();

                    vanilla_proofs
                        .iter()
                        .enumerate()
                        .map(|(k, partition_proof)| {
                            // The only public input field which should change is `k`.
                            vanilla_pub_inputs.k = Some(k);
                            <Self as CompoundProof<F, $sector_nodes>>::prove_partition_with_vanilla(
                                setup_params,
                                &vanilla_pub_inputs,
                                partition_proof,
                                keypair,
                            )
                        })
                        .collect()
                }

                fn batch_prove_all_partitions_with_vanilla(
                    setup_params: &Self::VanillaSetupParams,
                    vanilla_pub_inputs: &Self::VanillaPublicInputs,
                    vanilla_proofs: &[Self::VanillaPartitionProof],
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<Halo2Proof<F::Affine, Self::Circuit>, Error> {
                    let is_winning = is_winning::<$sector_nodes>(setup_params);

                    let partition_count = if is_winning {
                        1
                    } else {
                        let total_prover_sectors = vanilla_pub_inputs.sectors.len();
                        let sectors_challenged_per_partition =
                            window::sectors_challenged_per_partition::<$sector_nodes>();
                        // The prover's sector set length may not be divsible by the number of
                        // sectors challenged per partition; calling `ceil` accounts for this case
                        // where we pad the last partition with the prover's last sector.
                        (total_prover_sectors as f32 / sectors_challenged_per_partition as f32)
                            .ceil() as usize
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
                    setup_params: &Self::VanillaSetupParams,
                    vanilla_pub_inputs: &Self::VanillaPublicInputs,
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
                    setup_params: &Self::VanillaSetupParams,
                    vanilla_pub_inputs: &Self::VanillaPublicInputs,
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
                        // The prover's sector set length may not be divsible by the number of
                        // sectors challenged per partition; calling `ceil` accounts for this case
                        // where we pad the last partition with the prover's last sector.
                        (total_prover_sectors as f32 / sectors_challenged_per_partition as f32)
                            .ceil() as usize
                    };

                    assert_eq!(circ_proofs.len(), partition_count);

                    let mut vanilla_pub_inputs = vanilla_pub_inputs.clone();

                    for (k, partition_proof) in circ_proofs.iter().enumerate() {
                        // The only public input field which should change is `k`.
                        vanilla_pub_inputs.k = Some(k);
                        <Self as CompoundProof<F, $sector_nodes>>::verify_partition(
                            setup_params,
                            &vanilla_pub_inputs,
                            partition_proof,
                            keypair,
                        )?;
                    }
                    Ok(())
                }

                fn batch_verify_all_partitions(
                    setup_params: &Self::VanillaSetupParams,
                    vanilla_pub_inputs: &Self::VanillaPublicInputs,
                    batch_proof: &Halo2Proof<F::Affine, Self::Circuit>,
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> bool {
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
                        // The prover's sector set length may not be divsible by the number of
                        // sectors challenged per partition; calling `ceil` accounts for this case
                        // where we pad the last partition with the prover's last sector.
                        let partition_count =
                            (total_prover_sectors as f32 / sectors_challenged_per_partition as f32)
                                .ceil() as usize;
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

                    verify_batch_proof(keypair, batch_proof, &circ_pub_inputs_vecs)
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
