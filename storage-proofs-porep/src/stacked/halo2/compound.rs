use filecoin_hashers::{
    poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain, Hasher, PoseidonArity,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};
use rand::rngs::OsRng;
use storage_proofs_core::{
    halo2_proofs::{create_proof, CompoundProof, FieldProvingCurves, Halo2Proof},
    merkle::MerkleTreeTrait,
};

use crate::stacked::{
    halo2::{
        circuit::{self, SdrPorepCircuit},
        constants::SECTOR_NODES_2_KIB,
    },
    StackedDrg,
};

// TODO (jake): implement for all sector sizes.

impl<F, U, V, W, TreeR> CompoundProof<'_, F, SECTOR_NODES_2_KIB>
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
    const K: u32 = 18;

    type Circuit = SdrPorepCircuit<F, U, V, W, SECTOR_NODES_2_KIB>;

    fn prove_with_vanilla_partition(
        setup_params: Self::SetupParams,
        vanilla_pub_inputs: Self::PublicInputs,
        vanilla_partition_proof: Self::Proof,
    ) -> Result<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>, Error> {
        let pub_inputs =
            circuit::PublicInputs::<F, SECTOR_NODES_2_KIB>::from(setup_params, vanilla_pub_inputs);

        let pub_inputs_vec = pub_inputs.to_vec();

        let priv_inputs =
            circuit::PrivateInputs::<F, U, V, W, SECTOR_NODES_2_KIB>::from(vanilla_partition_proof);

        let circ = SdrPorepCircuit {
            pub_inputs,
            priv_inputs,
        };

        let keypair = Self::keypair(&circ)?;
        create_proof(&keypair, circ, &pub_inputs_vec, &mut OsRng)
    }
}
