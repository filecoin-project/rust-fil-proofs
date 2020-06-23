use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use paired::bls12_381::Bls12;
use storage_proofs_core::{
    compound_proof::CircuitComponent, hasher::Hasher, merkle::MerkleTreeTrait, proof::ProofScheme,
};

use super::{LayerProof, Proof};
use crate::nse::NarrowStackedExpander;

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
        let Self { proofs, .. } = self;

        // replica id
        // TODO

        // comm_d
        // TODO

        // comm_r
        // TODO

        // Verify each layer proof
        for layer_proof in proofs.into_iter() {
            layer_proof.synthesize(cs)?;
        }

        Ok(())
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> LayerProof<Tree, G> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let Self {
            first_layer_proof,
            expander_layer_proofs,
            butterfly_layer_proofs,
            last_layer_proof,
        } = self;

        first_layer_proof.synthesize(&mut cs.namespace(|| "first_layer"))?;

        for (i, proof) in expander_layer_proofs.into_iter().enumerate() {
            proof.synthesize(&mut cs.namespace(|| format!("expander_layer_{}", i)))?;
        }

        for (i, proof) in butterfly_layer_proofs.into_iter().enumerate() {
            proof.synthesize(&mut cs.namespace(|| format!("butterfly_layer_{}", i)))?;
        }

        last_layer_proof.synthesize(&mut cs.namespace(|| "last_layer"))?;

        Ok(())
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> Proof<Tree, G> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        todo!()
    }
}
