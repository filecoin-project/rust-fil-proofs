use std::marker::PhantomData;

use blstrs::Scalar as Fr;

use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    error::Result,
    merkle::MerkleTreeTrait,
    parameter_cache::CacheableParameters,
};

use crate::{
    circuit, constants::TreeRHasher, EmptySectorUpdate, EmptySectorUpdateCircuit, PartitionProof,
    PublicInputs, PublicParams,
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
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h,
            ..
        } = *pub_inputs;

        let pub_inputs = circuit::PublicInputs::new(
            pub_params.sector_nodes,
            k,
            h,
            comm_r_old,
            comm_d_new,
            comm_r_new,
        );

        let priv_inputs = circuit::PrivateInputs::new(
            vanilla_proof.comm_c,
            &vanilla_proof.apex_leafs,
            &vanilla_proof.challenge_proofs,
        );

        Ok(EmptySectorUpdateCircuit {
            pub_params: pub_params.clone(),
            pub_inputs,
            priv_inputs,
        })
    }

    fn blank_circuit(pub_params: &PublicParams) -> EmptySectorUpdateCircuit<TreeR> {
        EmptySectorUpdateCircuit::blank(pub_params.clone())
    }
}
