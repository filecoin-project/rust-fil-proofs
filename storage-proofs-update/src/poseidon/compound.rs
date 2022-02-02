use std::marker::PhantomData;

use anyhow::ensure;
use blstrs::Scalar as Fr;
use filecoin_hashers::PoseidonArity;
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    error::Result,
    merkle::MerkleTreeTrait,
    parameter_cache::CacheableParameters,
};

use crate::{
    constants::TreeR,
    poseidon::{
        circuit, EmptySectorUpdate, EmptySectorUpdateCircuit, PartitionProof, PublicInputs,
    },
    PublicParams,
};

pub struct EmptySectorUpdateCompound<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    pub _tree_r: PhantomData<(U, V, W)>,
}

impl<U, V, W> CacheableParameters<EmptySectorUpdateCircuit<U, V, W>, PublicParams>
    for EmptySectorUpdateCompound<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    fn cache_prefix() -> String {
        format!(
            "empty-sector-update-poseidon-{}",
            TreeR::<Fr, U, V, W>::display()
        )
    }
}

impl<'a, U, V, W>
    CompoundProof<'a, EmptySectorUpdate<Fr, U, V, W>, EmptySectorUpdateCircuit<U, V, W>>
    for EmptySectorUpdateCompound<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    fn generate_public_inputs(
        pub_inputs: &PublicInputs<Fr>,
        pub_params: &PublicParams,
        k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        // Ensure correctness of arguments.
        let sector_bytes = (pub_params.sector_nodes as u64) << 5;
        ensure!(
            *pub_params == PublicParams::from_sector_size_poseidon(sector_bytes),
            "invalid EmptySectorUpdate-Poseidon public-params",
        );
        if let Some(k) = k {
            ensure!(
                k == 0,
                "nonzero partition-index in EmptySectorUpdate-Poseidon `k` argument (found: {})",
                k,
            );
        }

        let PublicInputs {
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h,
        } = *pub_inputs;

        let pub_inputs_circ = circuit::PublicInputs::new(
            pub_params.sector_nodes,
            h,
            comm_r_old,
            comm_d_new,
            comm_r_new,
        );

        Ok(pub_inputs_circ.to_vec())
    }

    fn circuit(
        pub_inputs: &PublicInputs<Fr>,
        _priv_inputs: <EmptySectorUpdateCircuit<U, V, W> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &PartitionProof<Fr, U, V, W>,
        pub_params: &PublicParams,
        k: Option<usize>,
    ) -> Result<EmptySectorUpdateCircuit<U, V, W>> {
        // Ensure correctness of arguments.
        let sector_bytes = (pub_params.sector_nodes as u64) << 5;
        ensure!(
            *pub_params == PublicParams::from_sector_size_poseidon(sector_bytes),
            "invalid EmptySectorUpdate-Poseidon public-params",
        );
        if let Some(k) = k {
            ensure!(
                k == 0,
                "nonzero partition-index in EmptySectorUpdate-Poseidon `k` argument (found: {})",
                k,
            );
        }
        ensure!(
            vanilla_proof.challenge_proofs.len() == pub_params.challenge_count,
            "invalid EmptySectorUpdate-Poseidon public-params",
        );

        let PublicInputs {
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h,
        } = *pub_inputs;

        let pub_inputs = circuit::PublicInputs::new(
            pub_params.sector_nodes,
            h,
            comm_r_old,
            comm_d_new,
            comm_r_new,
        );

        let priv_inputs =
            circuit::PrivateInputs::new(vanilla_proof.comm_c, &vanilla_proof.challenge_proofs);

        Ok(EmptySectorUpdateCircuit {
            pub_params: pub_params.clone(),
            pub_inputs,
            priv_inputs,
        })
    }

    fn blank_circuit(pub_params: &PublicParams) -> EmptySectorUpdateCircuit<U, V, W> {
        EmptySectorUpdateCircuit::blank(pub_params.clone())
    }
}
