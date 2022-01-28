use std::marker::PhantomData;

use anyhow::ensure;
use blstrs::Scalar as Fr;

use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    error::Result,
    merkle::MerkleTreeTrait,
    parameter_cache::CacheableParameters,
};

use crate::{
    constants::TreeRHasher,
    poseidon::{
        circuit::{self, EmptySectorUpdateCircuit},
        vanilla::{EmptySectorUpdate, PartitionProof, PublicInputs},
    },
    PublicParams,
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
        format!("empty-sector-update-poseidon-{}", TreeR::display())
    }
}

impl<'a, TreeR> CompoundProof<'a, EmptySectorUpdate<TreeR>, EmptySectorUpdateCircuit<TreeR>>
    for EmptySectorUpdateCompound<TreeR>
where
    TreeR: 'static + MerkleTreeTrait<Hasher = TreeRHasher>,
{
    fn generate_public_inputs(
        pub_inputs: &PublicInputs,
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
        pub_inputs: &PublicInputs,
        _priv_inputs: <EmptySectorUpdateCircuit<TreeR> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &PartitionProof<TreeR>,
        pub_params: &PublicParams,
        k: Option<usize>,
    ) -> Result<EmptySectorUpdateCircuit<TreeR>> {
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

    fn blank_circuit(pub_params: &PublicParams) -> EmptySectorUpdateCircuit<TreeR> {
        EmptySectorUpdateCircuit::blank(pub_params.clone())
    }
}
