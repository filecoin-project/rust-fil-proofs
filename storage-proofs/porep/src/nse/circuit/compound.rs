use anyhow::Result;
use bellperson::Circuit;
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    hasher::Hasher,
    merkle::MerkleTreeTrait,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    proof::ProofScheme,
};

use super::NseCircuit;
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
        todo!();
    }

    fn circuit<'b>(
        public_inputs: &'b <NarrowStackedExpander<Tree, G> as ProofScheme>::PublicInputs,
        _component_private_inputs: <NseCircuit<Tree, G> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &'b <NarrowStackedExpander<Tree, G> as ProofScheme>::Proof,
        public_params: &'b <NarrowStackedExpander<Tree, G> as ProofScheme>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<NseCircuit<'a, Tree, G>> {
        todo!()
    }

    fn blank_circuit(
        public_params: &<NarrowStackedExpander<Tree, G> as ProofScheme>::PublicParams,
    ) -> NseCircuit<'a, Tree, G> {
        todo!()
    }
}
