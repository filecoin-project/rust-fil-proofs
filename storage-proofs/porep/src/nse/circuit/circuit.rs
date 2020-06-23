use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use paired::bls12_381::Bls12;
use storage_proofs_core::{
    compound_proof::CircuitComponent, hasher::Hasher, merkle::MerkleTreeTrait, proof::ProofScheme,
};

use crate::nse::NarrowStackedExpander;

use super::LayerProof;

/// NSE Circuit.
pub struct NseCircuit<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> {
    public_params: <NarrowStackedExpander<'a, Tree, G> as ProofScheme<'a>>::PublicParams,
    replica_id: Option<<Tree::Hasher as Hasher>::Domain>,

    proofs: Vec<LayerProof<Tree, G>>,
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> CircuitComponent
    for NseCircuit<'a, Tree, G>
{
    type ComponentPrivateInputs = ();
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> Circuit<Bls12>
    for NseCircuit<'a, Tree, G>
{
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        todo!()
    }
}
