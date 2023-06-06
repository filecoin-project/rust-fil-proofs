use bellperson::{ConstraintSystem, SynthesisError};
use filecoin_hashers::{Hasher, PoseidonArity};
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
pub struct ColumnProof<
    H: Hasher,
    U: 'static + PoseidonArity<H::Field>,
    V: 'static + PoseidonArity<H::Field>,
    W: 'static + PoseidonArity<H::Field>,
> {
    column: Column<H::Field>,
    inclusion_path: AuthPath<H, U, V, W>,
}

impl<
        H: 'static + Hasher,
        U: 'static + PoseidonArity<H::Field>,
        V: 'static + PoseidonArity<H::Field>,
        W: 'static + PoseidonArity<H::Field>,
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

    #[inline]
    pub fn mock(sector_nodes: usize, num_layers: usize) -> Self {
        ColumnProof {
            column: Column::mock(num_layers),
            inclusion_path: AuthPath::mock(sector_nodes),
        }
    }

    /// Allocate the private inputs for this column proof, and return the inclusion path for verification.
    pub fn alloc<CS: ConstraintSystem<H::Field>>(
        self,
        mut cs: CS,
    ) -> Result<(AllocatedColumn<H::Field>, AuthPath<H, U, V, W>), SynthesisError> {
        let ColumnProof {
            inclusion_path,
            column,
        } = self;

        let column = column.alloc(cs.namespace(|| "column"))?;

        Ok((column, inclusion_path))
    }

    #[inline]
    pub fn challenge(&self) -> usize {
        self.inclusion_path.challenge()
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
