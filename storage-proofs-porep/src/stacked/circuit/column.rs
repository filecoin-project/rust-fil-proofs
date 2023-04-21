use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use filecoin_hashers::Hasher;
use storage_proofs_core::merkle::MerkleTreeTrait;

use crate::stacked::{circuit::hash::hash_single_column, Column as VanillaColumn, PublicParams};

#[derive(Debug, Clone)]
pub struct Column<F: PrimeField> {
    rows: Vec<Option<F>>,
}

#[derive(Clone)]
pub struct AllocatedColumn<F: PrimeField> {
    rows: Vec<AllocatedNum<F>>,
}

impl<H: Hasher> From<VanillaColumn<H>> for Column<H::Field> {
    fn from(other: VanillaColumn<H>) -> Self {
        let VanillaColumn { rows, .. } = other;

        Column {
            rows: rows.into_iter().map(|r| Some(r.into())).collect(),
        }
    }
}

impl<F: PrimeField> Column<F> {
    /// Create an empty `Column`, used in `blank_circuit`s.
    pub fn empty<Tree: MerkleTreeTrait>(params: &PublicParams<Tree>) -> Self {
        Column {
            rows: vec![None; params.layer_challenges.layers()],
        }
    }

    /// Consume this column, and allocate its values in the circuit.
    pub fn alloc<CS: ConstraintSystem<F>>(
        self,
        mut cs: CS,
    ) -> Result<AllocatedColumn<F>, SynthesisError> {
        let Self { rows } = self;

        let rows = rows
            .into_iter()
            .enumerate()
            .map(|(i, val)| {
                AllocatedNum::alloc(cs.namespace(|| format!("column_num_row_{}", i)), || {
                    val.ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(AllocatedColumn { rows })
    }
}

impl<F: PrimeField> AllocatedColumn<F> {
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Creates the column hash of this column.
    pub fn hash<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        hash_single_column(cs, &self.rows)
    }

    pub fn get_value(&self, layer: usize) -> &AllocatedNum<F> {
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
