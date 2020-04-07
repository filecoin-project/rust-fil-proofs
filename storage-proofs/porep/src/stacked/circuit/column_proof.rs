use bellperson::gadgets::num;
use bellperson::{ConstraintSystem, SynthesisError};
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    gadgets::constraint,
    hasher::{Hasher, PoseidonArity},
    merkle::{MerkleProofTrait, MerkleTreeTrait, Store},
};

use super::{column::Column, params::InclusionPath};
use crate::stacked::{ColumnProof as VanillaColumnProof, PublicParams};

#[derive(Debug, Clone)]
pub struct ColumnProof<
    H: Hasher,
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
> {
    column: Column,
    inclusion_path: InclusionPath<H, U, V, W>,
}

impl<
        H: 'static + Hasher,
        U: 'static + PoseidonArity,
        V: 'static + PoseidonArity,
        W: 'static + PoseidonArity,
    > ColumnProof<H, U, V, W>
{
    /// Create an empty `ColumnProof`, used in `blank_circuit`s.
    pub fn empty<
        S: Store<H::Domain>,
        Tree: MerkleTreeTrait<Hasher = H, Store = S, Arity = U, SubTreeArity = V, TopTreeArity = W>,
    >(
        params: &PublicParams<Tree>,
    ) -> Self {
        ColumnProof {
            column: Column::empty(params),
            inclusion_path: InclusionPath::empty(&params.graph),
        }
    }

    pub fn get_node_at_layer(&self, layer: usize) -> &Option<Fr> {
        self.column.get_node_at_layer(layer)
    }

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        comm_c: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let ColumnProof {
            inclusion_path,
            column,
        } = self;

        let c_i = column.hash(cs.namespace(|| "column_hash"))?;

        let leaf_num = inclusion_path.alloc_value(cs.namespace(|| "leaf"))?;

        constraint::equal(&mut cs, || "enforce column_hash = leaf", &c_i, &leaf_num);

        // TODO: currently allocating the leaf twice, inclusion path should take the already allocated leaf.
        inclusion_path.synthesize(
            cs.namespace(|| "column_proof_all_inclusion"),
            comm_c.clone(),
            leaf_num,
        )?;

        Ok(())
    }
}

impl<Proof: MerkleProofTrait> From<VanillaColumnProof<Proof>>
    for ColumnProof<Proof::Hasher, Proof::Arity, Proof::SubTreeArity, Proof::TopTreeArity>
{
    fn from(vanilla_proof: VanillaColumnProof<Proof>) -> Self {
        let VanillaColumnProof {
            column,
            inclusion_proof,
        } = vanilla_proof;

        ColumnProof {
            column: column.into(),
            inclusion_path: inclusion_proof.into(),
        }
    }
}
