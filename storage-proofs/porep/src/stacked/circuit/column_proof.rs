use bellperson::bls::Bls12;
use bellperson::{ConstraintSystem, SynthesisError};
use filecoin_hashers::Hasher;
use storage_proofs_core::{
    drgraph::Graph,
    gadgets::por::AuthPath,
    merkle::{MerkleArity, MerkleProofTrait, MerkleTreeTrait, Store},
};

use super::column::{AllocatedColumn, Column};
use crate::stacked::{ColumnProof as VanillaColumnProof, PublicParams};

#[derive(Debug, Clone)]
pub struct ColumnProof<
    H: Hasher,
    U: 'static + MerkleArity,
    V: 'static + MerkleArity,
    W: 'static + MerkleArity,
> {
    column: Column,
    inclusion_path: AuthPath<H, U, V, W>,
}

impl<
        H: 'static + Hasher,
        U: 'static + MerkleArity,
        V: 'static + MerkleArity,
        W: 'static + MerkleArity,
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
            inclusion_path: AuthPath::blank(params.graph.size()),
        }
    }

    /// Allocate the private inputs for this column proof, and return the inclusion path for verification.
    pub fn alloc<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
    ) -> Result<(AllocatedColumn, AuthPath<H, U, V, W>), SynthesisError> {
        let ColumnProof {
            inclusion_path,
            column,
        } = self;

        let column = column.alloc(cs.namespace(|| "column"))?;

        Ok((column, inclusion_path))
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
            inclusion_path: inclusion_proof.as_options().into(),
        }
    }
}
