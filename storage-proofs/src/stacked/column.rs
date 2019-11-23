use std::marker::PhantomData;

use crate::hasher::pedersen::PedersenDomain;
use crate::hasher::Hasher;
use crate::merkle::MerkleProof;
use crate::stacked::{column_proof::ColumnProof, hash::hash_single_column, params::Tree};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Column<H: Hasher> {
    pub(crate) index: u32,
    pub(crate) layers: usize,
    pub(crate) rows: Vec<H::Domain>,
    _h: PhantomData<H>,
}

impl<H: Hasher> Column<H> {
    pub fn new(index: u32, layers: usize, rows: Vec<H::Domain>) -> Self {
        assert_eq!(rows.len() % layers, 0);

        Column {
            index,
            rows,
            layers,
            _h: PhantomData,
        }
    }

    pub fn with_capacity(index: u32, layers: usize, capacity: usize) -> Self {
        Column::new(index, layers, Vec::with_capacity(capacity))
    }

    pub fn rows(&self) -> &[H::Domain] {
        &self.rows
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// Calculate the column hashes `C_i = H(E_i, O_i)` for the passed in column.
    pub fn hash(&self) -> PedersenDomain {
        hash_single_column(&self.rows[..])
    }

    pub fn get_node_at_layer(&self, window_index: usize, layer: usize) -> &H::Domain {
        assert!(layer > 0, "layer must be greater than 0");
        let row_layer_index = layer - 1;
        let index = window_index * self.layers + row_layer_index;

        &self.rows[index]
    }

    /// Create a column proof for this column.
    pub fn into_proof(self, tree_c: &Tree<H>) -> ColumnProof<H> {
        let inclusion_proof = MerkleProof::new_from_proof(&tree_c.gen_proof(self.index() as usize));
        ColumnProof::<H>::from_column(self, inclusion_proof)
    }
}
