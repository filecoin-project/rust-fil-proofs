use anyhow::{ensure, Result};
use bellperson::Circuit;
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    hasher::Hasher,
    merkle::MerkleTreeTrait,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    proof::ProofScheme,
};

use super::{LayerProof, NseCircuit};
use crate::nse::NarrowStackedExpander;

#[derive(Debug)]
pub struct NseCompound {}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata> CacheableParameters<C, P> for NseCompound {
    fn cache_prefix() -> String {
        format!("nse-proof-of-replication",)
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher>
    CompoundProof<'a, NarrowStackedExpander<'a, Tree, G>, NseCircuit<'a, Tree, G>> for NseCompound
{
    fn generate_public_inputs(
        pub_in: &<NarrowStackedExpander<Tree, G> as ProofScheme>::PublicInputs,
        pub_params: &<NarrowStackedExpander<Tree, G> as ProofScheme>::PublicParams,
        k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        todo!()
    }

    fn circuit<'b>(
        public_inputs: &'b <NarrowStackedExpander<Tree, G> as ProofScheme>::PublicInputs,
        _component_private_inputs: <NseCircuit<Tree, G> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &'b <NarrowStackedExpander<Tree, G> as ProofScheme>::Proof,
        public_params: &'b <NarrowStackedExpander<Tree, G> as ProofScheme>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<NseCircuit<'a, Tree, G>> {
        ensure!(
            !vanilla_proof.layer_proofs.is_empty(),
            "Cannot create a circuit with no vanilla proofs"
        );

        Ok(NseCircuit {
            public_params: public_params.clone(),
            replica_id: Some(public_inputs.replica_id),
            comm_r: Some(public_inputs.tau.comm_r),
            layer_proofs: vanilla_proof
                .layer_proofs
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
            comm_layers: vanilla_proof
                .comm_layers
                .iter()
                .cloned()
                .map(Some)
                .collect(),
        })
    }

    fn blank_circuit(
        public_params: &<NarrowStackedExpander<Tree, G> as ProofScheme>::PublicParams,
    ) -> NseCircuit<'a, Tree, G> {
        let config = &public_params.config;

        NseCircuit {
            public_params: public_params.clone(),
            replica_id: None,
            comm_r: None,
            layer_proofs: (0..public_params.num_layer_challenges)
                .map(|_| LayerProof::blank(config))
                .collect(),
            comm_layers: (0..config.num_layers()).map(|_| None).collect(),
        }
    }
}
