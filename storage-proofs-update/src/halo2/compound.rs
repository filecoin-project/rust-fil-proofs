// TODO (jake): remove once `CompoundProof` api is finished.
#![allow(unused_imports)]

use filecoin_hashers::{Domain, FieldArity, HaloHasher, Hasher, PoseidonArity, POSEIDON_CONSTANTS};
use ff::PrimeFieldBits;
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};
use rand::rngs::OsRng;
use storage_proofs_core::{
    halo2_proofs::{create_proof, CompoundProof, FieldProvingCurves, Halo2Keypair, Halo2Proof},
    merkle::MerkleProofTrait,
    proof::ProofScheme,
};

use crate::{
    constants::{TreeDArity, TreeDDomain, TreeDHasher, TreeRDomain, TreeRHasher, SECTOR_SIZE_1_KIB},
    halo2::circuit::{ChallengeProof, EmptySectorUpdateCircuit, PrivateInputs, PublicInputs},
    vanilla::{self, phi},
    Challenges, EmptySectorUpdate,
};

impl<'a, F, U, V, W> CompoundProof<'a, F, SECTOR_SIZE_1_KIB> for EmptySectorUpdate<F, U, V, W>
where
    F: FieldExt + PrimeFieldBits + FieldProvingCurves,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDArity: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Domain = TreeDDomain<F>>,
    TreeDDomain<F>: Domain<Field = F>,
    TreeRHasher<F>: Hasher<Domain = TreeRDomain<F>>,
    TreeRDomain<F>: Domain<Field = F>,
{
    type Circuit = EmptySectorUpdateCircuit<F, U, V, W, SECTOR_SIZE_1_KIB>;

    fn prove_with_vanilla_partition(
        setup_params: Self::SetupParams,
        vanilla_pub_inputs: Self::PublicInputs,
        vanilla_proof: Self::Proof,
        // TODO (jake): allow loading keypair from disk.
        // keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
    ) -> Result<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>, Error> {
        assert_eq!(
            setup_params.sector_bytes as usize,
            SECTOR_SIZE_1_KIB << 5,
            "setup params contain incorrect sector size",
        );

        let vanilla::PublicInputs {
            k,
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h,
        } = vanilla_pub_inputs;

        let challenges = Challenges::vec(SECTOR_SIZE_1_KIB, comm_r_new, k);
        let phi = phi(&comm_d_new, &comm_r_old);
        let rhos = Challenges::rhos(SECTOR_SIZE_1_KIB, &challenges, h, &phi);

        let circ_pub_inputs = PublicInputs::<F, SECTOR_SIZE_1_KIB>::new(
            k,
            comm_r_old.into(),
            comm_d_new.into(),
            comm_r_new.into(),
            challenges,
            rhos,
        );

        let circ_pub_inputs_vec = circ_pub_inputs.to_vec();

        let comm_c: F = vanilla_proof.comm_c.into();
        let root_r_old: F = vanilla_proof.challenge_proofs[0].proof_r_old.root().into();
        let root_r_new: F = vanilla_proof.challenge_proofs[0].proof_r_new.root().into();

        let apex_leafs: Vec<Option<F>> =
            vanilla_proof.apex_leafs.iter().copied().map(Into::into).map(Some).collect();

        let challenge_proofs: Vec<ChallengeProof<F, U, V, W, SECTOR_SIZE_1_KIB>> =
            vanilla_proof.challenge_proofs.iter().cloned().map(Into::into).collect();

        let circ_priv_inputs = PrivateInputs {
            comm_c: Some(comm_c),
            root_r_old: Some(root_r_old),
            root_r_new: Some(root_r_new),
            apex_leafs,
            challenge_proofs,
        };

        let circ = EmptySectorUpdateCircuit {
            pub_inputs: circ_pub_inputs,
            priv_inputs: circ_priv_inputs,
        };

        let keypair = Self::keypair(&circ)?;
        create_proof(&keypair, circ, &circ_pub_inputs_vec, &mut OsRng)
    }
}
