use std::marker::PhantomData;

use blake2s_simd::Params as Blake2s;
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::hasher::Hasher;
use crate::util::NODE_SIZE;
use crate::zigzag::hash::{hash2, hash_single_column};

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
    index: usize,
    rows: Vec<H::Domain>,
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
    pub fn hash(&self) -> Vec<u8> {
        match self {
            Column::All(inner) => {
                let mut even_hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
                let mut odd_hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();

                for (i, row) in inner.rows.iter().enumerate() {
                    // adjust index, as the column stored at index 0 is layer 1 => odd
                    if (i + 1) % 2 == 0 {
                        even_hasher.update(row.as_ref());
                    } else {
                        odd_hasher.update(row.as_ref());
                    }
                }

                hash2(
                    odd_hasher.finalize().as_ref(),
                    even_hasher.finalize().as_ref(),
                )
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
}
