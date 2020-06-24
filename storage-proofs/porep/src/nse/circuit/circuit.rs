use bellperson::{gadgets::num, Circuit, ConstraintSystem, SynthesisError};
use ff::Field;
use generic_array::typenum::Unsigned;
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    compound_proof::CircuitComponent,
    gadgets::constraint,
    hasher::{HashFunction, Hasher, PoseidonFunction, PoseidonMDArity},
    merkle::MerkleTreeTrait,
    proof::ProofScheme,
};

use super::{LayerProof, NodeProof};
use crate::nse::NarrowStackedExpander;

/// NSE Circuit.
pub struct NseCircuit<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> {
    pub(crate) public_params: <NarrowStackedExpander<'a, Tree, G> as ProofScheme<'a>>::PublicParams,
    pub(crate) replica_id: Option<<Tree::Hasher as Hasher>::Domain>,
    pub(crate) comm_r: Option<<Tree::Hasher as Hasher>::Domain>,

    pub(crate) layer_proofs: Vec<LayerProof<Tree, G>>,
    pub(crate) comm_layers: Vec<Option<<Tree::Hasher as Hasher>::Domain>>,
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
        let Self {
            replica_id,
            comm_r,
            layer_proofs,
            comm_layers,
            ..
        } = self;

        // Allocate replica_id
        let replica_id_num = num::AllocatedNum::alloc(cs.namespace(|| "replica_id"), || {
            replica_id
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // make replica_id a public input
        replica_id_num.inputize(cs.namespace(|| "replica_id_input"))?;

        // comm_d
        // TODO

        // Allocate comm_r as Fr
        let comm_r_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_r"), || {
            comm_r
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // make comm_r a public input
        comm_r_num.inputize(cs.namespace(|| "comm_r_input"))?;

        // Allocate comm_layers
        let mut comm_layers_nums = comm_layers
            .into_iter()
            .enumerate()
            .map(|(i, comm)| {
                num::AllocatedNum::alloc(cs.namespace(|| format!("comm_layer_{}", i)), || {
                    comm.map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let arity = PoseidonMDArity::to_usize();
        while comm_layers_nums.len() % arity != 0 {
            comm_layers_nums.push(num::AllocatedNum::alloc(
                cs.namespace(|| format!("padding_{}", comm_layers_nums.len())),
                || Ok(Fr::zero()),
            )?);
        }

        // Verify hash(comm_layers) == comm_r
        {
            let hash_num = PoseidonFunction::hash_md_circuit::<_>(
                &mut cs.namespace(|| "comm_layers_hash"),
                &comm_layers_nums,
            )?;
            constraint::equal(
                cs,
                || "enforce comm_r = H(comm_layers)",
                &comm_r_num,
                &hash_num,
            );
        }

        // Verify each layer proof
        for layer_proof in layer_proofs.into_iter() {
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

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> NodeProof<Tree, G> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        todo!()
    }
}
