use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher};
use halo2_proofs::plonk::Error;
use rand::rngs::OsRng;
use storage_proofs_core::{
    halo2::{
        create_batch_proof, create_proof, verify_batch_proof, verify_proof, CompoundProof,
        Halo2Field, Halo2Keypair, Halo2Proof,
    },
    merkle::MerkleTreeTrait,
    SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_GIB,
    SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB, SECTOR_NODES_64_GIB,
    SECTOR_NODES_8_KIB, SECTOR_NODES_8_MIB,
};

use crate::stacked::{
    self as vanilla,
    halo2::{
        circuit::{self, SdrPorepCircuit, SDR_POREP_CIRCUIT_ID},
        constants::partition_count,
    },
    StackedDrg,
};

macro_rules! impl_compound_proof {
    ($($sector_nodes:expr),*) => {
        $(
            impl<F, TreeR> CompoundProof<F, $sector_nodes> for StackedDrg<'_, TreeR, Sha256Hasher<F>>
            where
                F: Halo2Field,
                TreeR: 'static + MerkleTreeTrait<Field = F, Hasher = PoseidonHasher<F>>,
                Sha256Hasher<F>: Hasher<Field = F>,
                PoseidonHasher<F>: Hasher<Field = F>,
            {
                type VanillaSetupParams = vanilla::SetupParams;
                type VanillaPublicInputs = vanilla::PublicInputs<
                    <PoseidonHasher<F> as Hasher>::Domain,
                    <Sha256Hasher<F> as Hasher>::Domain,
                >;
                type VanillaPartitionProof = Vec<vanilla::Proof<TreeR, Sha256Hasher<F>>>;
                type Circuit = SdrPorepCircuit<F, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity, $sector_nodes>;

                fn prove_partition_with_vanilla(
                    setup_params: &Self::VanillaSetupParams,
                    vanilla_pub_inputs: &Self::VanillaPublicInputs,
                    vanilla_partition_proof: &Self::VanillaPartitionProof,
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<Halo2Proof<F::Affine, Self::Circuit>, Error> {
                    let pub_inputs =
                        circuit::PublicInputs::<F, $sector_nodes>::from(setup_params.clone(),
                        vanilla_pub_inputs.clone());

                    let pub_inputs_vec = pub_inputs.to_vec();

                    let priv_inputs =
                        circuit::PrivateInputs::<F, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity, $sector_nodes>::from(vanilla_partition_proof);

                    let circ = SdrPorepCircuit {
                        id: SDR_POREP_CIRCUIT_ID.to_string(),
                        pub_inputs,
                        priv_inputs,
                    };

                    create_proof(keypair, circ, &pub_inputs_vec, &mut OsRng)
                }

                fn prove_all_partitions_with_vanilla(
                    setup_params: &Self::VanillaSetupParams,
                    vanilla_pub_inputs: &Self::VanillaPublicInputs,
                    vanilla_proofs: &[Self::VanillaPartitionProof],
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<Vec<Halo2Proof<F::Affine, Self::Circuit>>, Error> {
                    let partition_count = partition_count($sector_nodes);
                    assert_eq!(vanilla_proofs.len(), partition_count);

                    let mut vanilla_pub_inputs = vanilla_pub_inputs.clone();

                    vanilla_proofs
                        .iter()
                        .enumerate()
                        .map(|(k, partition_proof)| {
                            // The only public input field which should change is `k`.
                            vanilla_pub_inputs.k = Some(k);
                            <Self as CompoundProof<
                                F,
                                $sector_nodes,
                            >>::prove_partition_with_vanilla(
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
                    let partition_count = partition_count($sector_nodes);
                    assert_eq!(vanilla_proofs.len(), partition_count);

                    let mut circ_pub_inputs_vecs = Vec::with_capacity(partition_count);

                    let circs: Vec<Self::Circuit> = vanilla_proofs
                        .iter()
                        .enumerate()
                        .map(|(k, vanilla_proof)| {
                            // The only public input field which should change is `k`.
                            let mut vanilla_pub_inputs = vanilla_pub_inputs.clone();
                            vanilla_pub_inputs.k = Some(k);

                            let pub_inputs = circuit::PublicInputs::from(
                                setup_params.clone(),
                                vanilla_pub_inputs,
                            );

                            circ_pub_inputs_vecs.push(pub_inputs.to_vec());

                            let priv_inputs = circuit::PrivateInputs::from(vanilla_proof);

                            SdrPorepCircuit {
                                id: SDR_POREP_CIRCUIT_ID.to_string(),
                                pub_inputs,
                                priv_inputs,
                            }
                        })
                        .collect();

                    create_batch_proof(keypair, &circs, &circ_pub_inputs_vecs, &mut OsRng)
                }

                fn verify_partition(
                    setup_params: &Self::VanillaSetupParams,
                    vanilla_pub_inputs: &Self::VanillaPublicInputs,
                    circ_proof: &Halo2Proof<F::Affine, Self::Circuit>,
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<(), Error> {
                    let pub_inputs = circuit::PublicInputs::<F, $sector_nodes>::from(
                        setup_params.clone(),
                        vanilla_pub_inputs.clone(),
                    );
                    let pub_inputs_vec = pub_inputs.to_vec();
                    verify_proof(keypair, circ_proof, &pub_inputs_vec)
                }

                fn verify_all_partitions(
                    setup_params: &Self::VanillaSetupParams,
                    vanilla_pub_inputs: &Self::VanillaPublicInputs,
                    circ_proofs: &[Halo2Proof<F::Affine, Self::Circuit>],
                    keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
                ) -> Result<(), Error> {
                    let partition_count = partition_count($sector_nodes);
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
                    let partition_count = partition_count($sector_nodes);

                    let circ_pub_inputs_vecs: Vec<Vec<Vec<F>>> = (0..partition_count)
                        .map(|k| {
                            // The only public input field which should change is `k`.
                            let mut vanilla_pub_inputs = vanilla_pub_inputs.clone();
                            vanilla_pub_inputs.k = Some(k);
                            let pub_inputs = circuit::PublicInputs::<F, $sector_nodes>::from(
                                setup_params.clone(),
                                vanilla_pub_inputs,
                            );
                            pub_inputs.to_vec()
                        })
                        .collect();

                    verify_batch_proof(keypair, batch_proof, &circ_pub_inputs_vecs)
                }
            }
        )*
    }
}

impl_compound_proof!(
    SECTOR_NODES_2_KIB,
    SECTOR_NODES_4_KIB,
    SECTOR_NODES_8_KIB,
    SECTOR_NODES_16_KIB,
    SECTOR_NODES_32_KIB,
    SECTOR_NODES_8_MIB,
    SECTOR_NODES_16_MIB,
    SECTOR_NODES_512_MIB,
    SECTOR_NODES_32_GIB,
    SECTOR_NODES_64_GIB
);
