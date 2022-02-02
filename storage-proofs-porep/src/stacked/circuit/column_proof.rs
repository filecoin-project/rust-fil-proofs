use bellperson::{ConstraintSystem, SynthesisError};
use blstrs::Scalar as Fr;
use filecoin_hashers::{Domain, Hasher, PoseidonArity};
use storage_proofs_core::{
    drgraph::Graph,
    gadgets::por::AuthPath,
    merkle::{MerkleProofTrait, MerkleTreeTrait, Store},
};

use crate::stacked::{
    circuit::column::{AllocatedColumn, Column},
    vanilla::{ColumnProof as VanillaColumnProof, PublicParams},
};

#[derive(Debug, Clone)]
pub struct ColumnProof<H, U, V, W>
where
    H: Hasher,
    H::Domain: Domain<Field = Fr>,
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
{
    column: Column,
    inclusion_path: AuthPath<H, U, V, W>,
}

impl<H, U, V, W> ColumnProof<H, U, V, W>
where
    H: 'static + Hasher,
    H::Domain: Domain<Field = Fr>,
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
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
    pub fn alloc<CS: ConstraintSystem<Fr>>(
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

impl<Proof> From<VanillaColumnProof<Proof>>
    for ColumnProof<Proof::Hasher, Proof::Arity, Proof::SubTreeArity, Proof::TopTreeArity>
where
    Proof: MerkleProofTrait,
    <Proof::Hasher as Hasher>::Domain: Domain<Field = Fr>,
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
