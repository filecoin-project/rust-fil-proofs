use std::marker::PhantomData;

use blstrs::Scalar as Fr;

use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    error::Result,
    merkle::{MerkleProofTrait, MerkleTreeTrait},
    parameter_cache::CacheableParameters,
};

use crate::{
    circuit, constants::TreeRHasher, ChallengeProof, EmptySectorUpdate, EmptySectorUpdateCircuit,
    PartitionProof, PublicInputs, PublicParams,
};

pub struct EmptySectorUpdateCompound<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    pub _tree_r: PhantomData<TreeR>,
}

impl<TreeR> CacheableParameters<EmptySectorUpdateCircuit<TreeR>, PublicParams>
    for EmptySectorUpdateCompound<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    fn cache_prefix() -> String {
        format!("empty-sector-update-{}", TreeR::display())
    }
}

impl<'a, TreeR> CompoundProof<'a, EmptySectorUpdate<TreeR>, EmptySectorUpdateCircuit<TreeR>>
    for EmptySectorUpdateCompound<TreeR>
where
    TreeR: 'static + MerkleTreeTrait<Hasher = TreeRHasher>,
{
    // Generates a partition circuit's public-inputs. If the `k` argument is `Some` we overwrite
    // `pub_inputs.k` with the `k` argument's value, otherwise if the `k` argument is `None` we use
    // `pub_inputs.k` as the circuit's public-input.
    fn generate_public_inputs(
        pub_inputs: &PublicInputs,
        pub_params: &PublicParams,
        k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        // Prioritize the partition-index provided via the `k` argument; default to `pub_inputs.k`.
        let k = k.unwrap_or(pub_inputs.k);

        let PublicInputs {
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h,
            ..
        } = *pub_inputs;

        let pub_inputs_circ = circuit::PublicInputs::new(
            pub_params.sector_nodes,
            k,
            h,
            comm_r_old,
            comm_d_new,
            comm_r_new,
        );

        Ok(pub_inputs_circ.to_vec())
    }

    // Generates a partition's circuit. If the `k` argument is `Some` we overwrite `pub_inputs.k`
    // with the `k` argument's value, otherwise if the `k` argument is `None` we use `pub_inputs.k`
    // as the circuit's public-input.
    fn circuit(
        pub_inputs: &PublicInputs,
        _priv_inputs: <EmptySectorUpdateCircuit<TreeR> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &PartitionProof<TreeR>,
        pub_params: &PublicParams,
        k: Option<usize>,
    ) -> Result<EmptySectorUpdateCircuit<TreeR>> {
        // Prioritize the partition-index provided via the `k` argument; default to `pub_inputs.k`.
        let k = k.unwrap_or(pub_inputs.k);

        let PublicInputs {
            comm_c,
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h,
            ..
        } = *pub_inputs;

        let pub_inputs_circ = circuit::PublicInputs::new(
            pub_params.sector_nodes,
            k,
            h,
            comm_r_old,
            comm_d_new,
            comm_r_new,
        );

        let comm_r_last_old = vanilla_proof.challenge_proofs[0].proof_r_old.root();
        let comm_r_last_new = vanilla_proof.challenge_proofs[0].proof_r_new.root();

        let apex_leafs: Vec<Option<Fr>> = vanilla_proof
            .apex_leafs
            .iter()
            .copied()
            .map(|leaf| Some(leaf.into()))
            .collect();

        let challenge_proofs: Vec<circuit::ChallengeProof<TreeR>> = vanilla_proof
            .challenge_proofs
            .iter()
            .cloned()
            .map(|challenge_proof| {
                let ChallengeProof {
                    proof_r_old,
                    proof_d_new,
                    proof_r_new,
                } = challenge_proof;
                circuit::ChallengeProof::from_merkle_proofs(proof_r_old, proof_d_new, proof_r_new)
            })
            .collect();

        Ok(EmptySectorUpdateCircuit {
            pub_params: pub_params.clone(),
            k_and_h_select: pub_inputs_circ.k_and_h_select,
            comm_r_old: pub_inputs_circ.comm_r_old,
            comm_d_new: pub_inputs_circ.comm_d_new,
            comm_r_new: pub_inputs_circ.comm_r_new,
            comm_c: Some(comm_c.into()),
            comm_r_last_old: Some(comm_r_last_old.into()),
            comm_r_last_new: Some(comm_r_last_new.into()),
            apex_leafs,
            challenge_proofs,
        })
    }

    fn blank_circuit(pub_params: &PublicParams) -> EmptySectorUpdateCircuit<TreeR> {
        EmptySectorUpdateCircuit::blank(pub_params.clone())
    }
}
