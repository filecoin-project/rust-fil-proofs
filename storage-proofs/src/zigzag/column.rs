use std::marker::PhantomData;

use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::hasher::pedersen::PedersenDomain;
use crate::hasher::Hasher;
use crate::merkle::MerkleProof;
use crate::zigzag::{
    column_proof::ColumnProof,
    graph::ZigZagBucketGraph,
    hash::{hash1, hash2, hash_single_column},
    params::Tree,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Column<H: Hasher> {
    #[serde(bound(
        serialize = "RawColumn<H>: Serialize",
        deserialize = "RawColumn<H>: Deserialize<'de>"
    ))]
    All(RawColumn<H>),
    #[serde(bound(
        serialize = "RawColumn<H>: Serialize",
        deserialize = "RawColumn<H>: Deserialize<'de>"
    ))]
    Odd(RawColumn<H>),
    #[serde(bound(
        serialize = "RawColumn<H>: Serialize",
        deserialize = "RawColumn<H>: Deserialize<'de>"
    ))]
    Even(RawColumn<H>),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawColumn<H: Hasher> {
    pub(crate) index: usize,
    pub(crate) rows: Vec<H::Domain>,
    _h: PhantomData<H>,
}

impl<H: Hasher> RawColumn<H> {
    fn new(index: usize, rows: Vec<H::Domain>) -> Self {
        RawColumn {
            index,
            rows,
            _h: PhantomData,
        }
    }

    fn with_capacity(index: usize, rows: usize) -> Self {
        RawColumn::new(index, Vec::with_capacity(rows))
    }
}

impl<H: Hasher> Column<H> {
    pub fn new_all(index: usize, rows: Vec<H::Domain>) -> Self {
        Column::All(RawColumn::new(index, rows))
    }

    pub fn new_even(index: usize, rows: Vec<H::Domain>) -> Self {
        Column::Even(RawColumn::new(index, rows))
    }

    pub fn new_odd(index: usize, rows: Vec<H::Domain>) -> Self {
        Column::Odd(RawColumn::new(index, rows))
    }

    pub fn all_with_capacity(index: usize, capacity: usize) -> Self {
        Column::All(RawColumn::with_capacity(index, capacity))
    }

    pub fn odd_with_capacity(index: usize, capacity: usize) -> Self {
        Column::Odd(RawColumn::with_capacity(index, capacity))
    }

    pub fn even_with_capacity(index: usize, capacity: usize) -> Self {
        Column::Even(RawColumn::with_capacity(index, capacity))
    }

    pub fn rows(&self) -> &[H::Domain] {
        match self {
            Column::All(inner) => &inner.rows,
            Column::Odd(inner) => &inner.rows,
            Column::Even(inner) => &inner.rows,
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Column::All(inner) => inner.index,
            Column::Odd(inner) => inner.index,
            Column::Even(inner) => inner.index,
        }
    }

    /// Calculate the column hashes `C_i = H(E_i, O_i)` for the passed in column.
    pub fn hash(&self) -> PedersenDomain {
        match self {
            Column::All(inner) => {
                let mut even_buffer = Vec::new();
                let mut odd_buffer = Vec::new();

                for (i, row) in inner.rows.iter().enumerate() {
                    // adjust index, as the column stored at index 0 is layer 1 => odd
                    if (i + 1) % 2 == 0 {
                        even_buffer.extend_from_slice(row.as_ref());
                    } else {
                        odd_buffer.extend_from_slice(row.as_ref());
                    }
                }

                let o_i = hash1(&odd_buffer);
                let e_i = hash1(&even_buffer);

                hash2(o_i, e_i)
            }
            Column::Even(inner) => hash_single_column(&inner.rows),
            Column::Odd(inner) => hash_single_column(&inner.rows),
        }
    }

    pub fn is_all(&self) -> bool {
        match self {
            Column::All(_) => true,
            _ => false,
        }
    }

    pub fn is_even(&self) -> bool {
        match self {
            Column::Even(_) => true,
            _ => false,
        }
    }

    pub fn is_odd(&self) -> bool {
        match self {
            Column::Odd(_) => true,
            _ => false,
        }
    }

    pub fn get_node_at_layer(&self, layer: usize) -> &H::Domain {
        match self {
            Column::All(inner) => {
                assert!(layer > 0, "layer must be greater than 0");
                let row_index = layer - 1;
                &inner.rows[row_index]
            }
            Column::Odd(inner) => {
                assert!(layer > 0, "layer must be greater than 0");
                assert!(layer % 2 != 0, "layer must be odd");

                // layer | row_index
                //   1   | 0
                //   3   | 1
                //   5   | 2

                let row_index = (layer - 1) / 2;
                &inner.rows[row_index]
            }
            Column::Even(inner) => {
                assert!(layer > 0, "layer must be greater than 0");
                assert!(layer % 2 == 0, "layer must be even");

                // layer | row_index
                //   2   | 0
                //   4   | 1
                //   6   | 2

                let row_index = (layer / 2) - 1;
                &inner.rows[row_index]
            }
        }
    }

    /// Create a column proof for this column.
    pub fn into_proof_all(self, tree_c: &Tree<H>) -> ColumnProof<H> {
        assert!(self.is_all());

        let inclusion_proof = MerkleProof::new_from_proof(&tree_c.gen_proof(self.index()));
        ColumnProof::<H>::all_from_column(self, inclusion_proof)
    }

    /// Create an even column proof for this column.
    pub fn into_proof_odd(self, tree_c: &Tree<H>, e_i: H::Domain) -> ColumnProof<H> {
        assert!(self.is_odd());

        let inclusion_proof = MerkleProof::new_from_proof(&tree_c.gen_proof(self.index()));
        ColumnProof::<H>::odd_from_column(self, inclusion_proof, e_i)
    }

    /// Create an odd column proof for this column.
    pub fn into_proof_even(
        self,
        tree_c: &Tree<H>,
        graph: &ZigZagBucketGraph<H>,
        o_i: H::Domain,
    ) -> ColumnProof<H> {
        assert!(self.is_even());

        let inclusion_proof =
            MerkleProof::new_from_proof(&tree_c.gen_proof(graph.inv_index(self.index())));
        ColumnProof::<H>::even_from_column(self, inclusion_proof, o_i)
    }
}
