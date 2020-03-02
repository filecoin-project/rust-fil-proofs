use paired::bls12_381::Fr;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::{column_proof::ColumnProof, hash::hash_single_column, params::OctTree};

use crate::error::Result;
use crate::hasher::Hasher;
use crate::merkle::MerkleProof;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Column<H: Hasher> {
    pub(crate) index: u32,
    pub(crate) rows: Vec<H::Domain>,
    _h: PhantomData<H>,
}

impl<H: Hasher> Column<H> {
    pub fn new(index: u32, rows: Vec<H::Domain>) -> Result<Self> {
        Ok(Column {
            index,
            rows,
            _h: PhantomData,
        })
    }

    pub fn with_capacity(index: u32, capacity: usize) -> Result<Self> {
        Column::new(index, Vec::with_capacity(capacity))
    }

    pub fn rows(&self) -> &[H::Domain] {
        &self.rows
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// Calculate the column hashes `C_i = H(E_i, O_i)` for the passed in column.
    pub fn hash(&self) -> Fr {
        hash_single_column(
            &self
                .rows
                .iter()
                .copied()
                .map(Into::into)
                .collect::<Vec<_>>(),
        )
    }

    pub fn get_node_at_layer(&self, layer: usize) -> Result<&H::Domain> {
        assert!(layer > 0, "layer must be greater than 0");
        let row_index = layer - 1;

        Ok(&self.rows[row_index])
    }

    /// Create a column proof for this column.
    pub fn into_proof(self, tree_c: &OctTree<H>) -> Result<ColumnProof<H>> {
        let inclusion_proof =
            MerkleProof::new_from_proof(&tree_c.gen_proof(self.index() as usize)?);
        ColumnProof::<H>::from_column(self, inclusion_proof)
    }
}
