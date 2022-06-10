use filecoin_hashers::{
    poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain, Hasher, PoseidonArity,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};
use rand::rngs::OsRng;
use storage_proofs_core::{
    halo2::{create_proof, verify_proof, CompoundProof, FieldProvingCurves, Halo2Keypair, Halo2Proof},
    merkle::MerkleTreeTrait,
};

use crate::stacked::{
    halo2::{
        circuit::{self, SdrPorepCircuit},
        constants::{
            SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_GIB,
            SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB, SECTOR_NODES_64_GIB,
            SECTOR_NODES_8_MIB,
        },
    },
    StackedDrg,
};

macro_rules! impl_compound_proof {
    ($($sector_nodes:expr),*) => {
        $(
            impl<F, U, V, W, TreeR> CompoundProof<'_, F, $sector_nodes>
                for StackedDrg<'static, TreeR, Sha256Hasher<F>>
            where
                F: FieldExt + FieldProvingCurves,
                U: PoseidonArity<F>,
                V: PoseidonArity<F>,
                W: PoseidonArity<F>,
                Sha256Hasher<F>: Hasher,
                <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
                PoseidonHasher<F>: Hasher,
                <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
                TreeR:
                    MerkleTreeTrait<Hasher = PoseidonHasher<F>, Arity = U, SubTreeArity = V, TopTreeArity = W>,
            {
                type Circuit = SdrPorepCircuit<F, U, V, W, $sector_nodes>;

                fn prove_partition_with_vanilla(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &Self::PublicInputs,
                    vanilla_partition_proof: &Self::Proof,
                    keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
                ) -> Result<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>, Error> {
                    let pub_inputs =
                        circuit::PublicInputs::<F, $sector_nodes>::from(setup_params.clone(),
                        vanilla_pub_inputs.clone());

                    let pub_inputs_vec = pub_inputs.to_vec();

                    let priv_inputs =
                        circuit::PrivateInputs::<F, U, V, W, $sector_nodes>::from(vanilla_partition_proof);

                    let circ = SdrPorepCircuit {
                        pub_inputs,
                        priv_inputs,
                    };

                    create_proof(keypair, circ, &pub_inputs_vec, &mut OsRng)
                }

                fn prove_all_partitions_with_vanilla(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &[&Self::PublicInputs],
                    vanilla_proofs: &[&Self::Proof],
                    keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
                ) -> Result<Vec<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>>, Error> {
                    assert_eq!(vanilla_pub_inputs.len(), vanilla_proofs.len());
                    vanilla_pub_inputs
                        .iter()
                        .zip(vanilla_proofs.iter())
                        .map(|(pub_inputs, partition_proof)| {
                            <Self as CompoundProof<'_, F, $sector_nodes>>::prove_partition_with_vanilla(
                                setup_params,
                                pub_inputs,
                                partition_proof,
                                keypair,
                            )
                        })
                        .collect()
                }

                fn verify_partition(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &Self::PublicInputs,
                    circ_proof: &Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>,
                    keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
                ) -> Result<(), Error> {
                    let pub_inputs = circuit::PublicInputs::<F, $sector_nodes>::from(
                        setup_params.clone(),
                        vanilla_pub_inputs.clone(),
                    );
                    let pub_inputs_vec = pub_inputs.to_vec();
                    verify_proof(keypair, circ_proof, &pub_inputs_vec)
                }

                fn verify_all_partitions(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &[&Self::PublicInputs],
                    circ_proofs: &[&Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>],
                    keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
                ) -> Result<(), Error> {
                    assert_eq!(vanilla_pub_inputs.len(), circ_proofs.len());
                    for (vanilla_pub_inputs, circ_proof) in vanilla_pub_inputs.iter().zip(circ_proofs.iter()) {
                        <Self as CompoundProof<'_, F, $sector_nodes>>::verify_partition(setup_params, vanilla_pub_inputs, circ_proof, keypair)?;
                    }
                    Ok(())
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
    SECTOR_NODES_32_GIB,
    SECTOR_NODES_64_GIB
);
