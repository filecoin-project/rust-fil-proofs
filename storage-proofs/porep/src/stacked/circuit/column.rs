use bellperson::bls::{Bls12, Fr};
use bellperson::gadgets::num;
use bellperson::{ConstraintSystem, SynthesisError};
use storage_proofs_core::{hasher::Hasher, merkle::MerkleTreeTrait};

use super::hash::hash_single_column;
use crate::stacked::{Column as VanillaColumn, PublicParams};

#[derive(Debug, Clone)]
pub struct Column {
    rows: Vec<Option<Fr>>,
}

#[derive(Clone)]
pub struct AllocatedColumn {
    rows: Vec<num::AllocatedNum<Bls12>>,
}

impl<H: Hasher> From<VanillaColumn<H>> for Column {
    fn from(other: VanillaColumn<H>) -> Self {
        let VanillaColumn { rows, .. } = other;

        Column {
            rows: rows.into_iter().map(|r| Some(r.into())).collect(),
        }
    }
}

impl Column {
    /// Create an empty `Column`, used in `blank_circuit`s.
    pub fn empty<Tree: MerkleTreeTrait>(params: &PublicParams<Tree>) -> Self {
        Column {
            rows: vec![None; params.layer_challenges.layers()],
        }
    }

    /// Consume this column, and allocate its values in the circuit.
    pub fn alloc<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
    ) -> Result<AllocatedColumn, SynthesisError> {
        let Self { rows } = self;

        let rows = rows
            .into_iter()
            .enumerate()
            .map(|(i, val)| {
                num::AllocatedNum::alloc(cs.namespace(|| format!("column_num_row_{}", i)), || {
                    val.ok_or_else(|| SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(AllocatedColumn { rows })
    }
}

impl AllocatedColumn {
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Creates the column hash of this column.
    pub fn hash<CS: ConstraintSystem<Bls12>>(
        &self,
        cs: CS,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        hash_single_column(cs, &self.rows)
    }

    pub fn get_value(&self, layer: usize) -> &num::AllocatedNum<Bls12> {
        assert!(layer > 0, "layers are 1 indexed");
        assert!(
            layer <= self.rows.len(),
            "layer {} out of range: 1..={}",
            layer,
            self.rows.len()
        );
        &self.rows[layer - 1]
    }
}
