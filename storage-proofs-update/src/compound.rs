use std::marker::PhantomData;

use blstrs::Scalar as Fr;
use ff::PrimeField;
use filecoin_hashers::PoseidonArity;
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    error::Result,
    merkle::MerkleTreeTrait,
    parameter_cache::CacheableParameters,
};

use crate::{
    circuit, constants::TreeR, EmptySectorUpdate, EmptySectorUpdateCircuit, PartitionProof,
    PublicInputs, PublicParams,
};

pub struct EmptySectorUpdateCompound<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
{
    pub _tree_r: PhantomData<(F, U, V, W)>,
}

// Only implement for `Fr` because `CacheableParameters` is Groth16 specific.
impl<U, V, W> CacheableParameters<EmptySectorUpdateCircuit<Fr, U, V, W>, PublicParams>
    for EmptySectorUpdateCompound<Fr, U, V, W>
where
    U: PoseidonArity<Fr>,
    V: PoseidonArity<Fr>,
    W: PoseidonArity<Fr>,
{
    fn cache_prefix() -> String {
        format!("empty-sector-update-{}", TreeR::<Fr, U, V, W>::display())
    }
}

// Only implement for `Fr` because `CompoundProof` is Groth16 specific.
impl<'a, U, V, W>
    CompoundProof<'a, EmptySectorUpdate<Fr, U, V, W>, EmptySectorUpdateCircuit<Fr, U, V, W>>
    for EmptySectorUpdateCompound<Fr, U, V, W>
where
    U: PoseidonArity<Fr>,
    V: PoseidonArity<Fr>,
    W: PoseidonArity<Fr>,
{
    #[inline]
    fn generate_public_inputs(
        pub_inputs: &PublicInputs<Fr>,
        pub_params: &PublicParams,
        k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        EmptySectorUpdateCircuit::<Fr, U, V, W>::generate_public_inputs(pub_params, pub_inputs, k)
    }

    // Generates a partition's circuit. If the `k` argument is `Some` we overwrite `pub_inputs.k`
    // with the `k` argument's value, otherwise if the `k` argument is `None` we use `pub_inputs.k`
    // as the circuit's public-input.
    fn circuit(
        pub_inputs: &PublicInputs<Fr>,
        _priv_inputs: <EmptySectorUpdateCircuit<Fr, U, V, W> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &PartitionProof<Fr, U, V, W>,
        pub_params: &PublicParams,
        k: Option<usize>,
    ) -> Result<EmptySectorUpdateCircuit<Fr, U, V, W>> {
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

    fn blank_circuit(pub_params: &PublicParams) -> EmptySectorUpdateCircuit<Fr, U, V, W> {
        EmptySectorUpdateCircuit::blank(pub_params.clone())
    }
}
