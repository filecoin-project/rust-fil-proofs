use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::hasher::Hasher;
use crate::merkle::{IncludedNode, MerkleProof};
use crate::zigzag::column::Column;
use crate::zigzag::hash::hash2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ColumnProof<H: Hasher> {
    All {
        #[serde(bound(
            serialize = "Column<H>: Serialize",
            deserialize = "Column<H>: Deserialize<'de>"
        ))]
        column: Column<H>,
        #[serde(bound(
            serialize = "MerkleProof<H>: Serialize",
            deserialize = "MerkleProof<H>: Deserialize<'de>"
        ))]
        inclusion_proof: MerkleProof<H>,
    },
    Even {
        #[serde(bound(
            serialize = "Column<H>: Serialize",
            deserialize = "Column<H>: Deserialize<'de>"
        ))]
        column: Column<H>,
        #[serde(bound(
            serialize = "MerkleProof<H>: Serialize",
            deserialize = "MerkleProof<H>: Deserialize<'de>"
        ))]
        inclusion_proof: MerkleProof<H>,
        o_i: Vec<u8>,
    },
    Odd {
        #[serde(bound(
            serialize = "Column<H>: Serialize",
            deserialize = "Column<H>: Deserialize<'de>"
        ))]
        column: Column<H>,
        #[serde(bound(
            serialize = "MerkleProof<H>: Serialize",
            deserialize = "MerkleProof<H>: Deserialize<'de>"
        ))]
        inclusion_proof: MerkleProof<H>,
        e_i: Vec<u8>,
    },
}

impl<H: Hasher> ColumnProof<H> {
    pub fn all_from_column(column: Column<H>, inclusion_proof: MerkleProof<H>) -> Self {
        assert!(column.is_all());

        let res = ColumnProof::All {
            column,
            inclusion_proof,
        };
        debug_assert!(res.verify());

        res
    }

    pub fn even_from_column(
        column: Column<H>,
        inclusion_proof: MerkleProof<H>,
        o_i: &[u8],
    ) -> Self {
        assert!(column.is_even());

        let res = ColumnProof::Even {
            column,
            inclusion_proof,
            o_i: o_i.to_vec(),
        };
        debug_assert!(res.verify());

        res
    }

    pub fn odd_from_column(column: Column<H>, inclusion_proof: MerkleProof<H>, e_i: &[u8]) -> Self {
        assert!(column.is_odd());

        let res = ColumnProof::Odd {
            column,
            inclusion_proof,
            e_i: e_i.to_vec(),
        };

        debug_assert!(res.verify());

        res
    }

    fn column(&self) -> &Column<H> {
        match self {
            ColumnProof::All { column, .. } => &column,
            ColumnProof::Odd { column, .. } => &column,
            ColumnProof::Even { column, .. } => &column,
        }
    }

    pub fn get_node_at_layer(&self, layer: usize) -> &H::Domain {
        self.column().get_node_at_layer(layer)
    }

    pub fn get_verified_node_at_layer(&self, layer: usize) -> IncludedNode<H> {
        let value = self.get_node_at_layer(layer);
        IncludedNode::new(value.clone())
    }

    pub fn column_hash(&self) -> Vec<u8> {
        self.column().hash()
    }

    pub fn verify(&self) -> bool {
        match self {
            ColumnProof::All {
                inclusion_proof, ..
            } => {
                let c_i = self.column_hash();

                check!(inclusion_proof.validate_data(&c_i));

                true
            }
            ColumnProof::Even {
                inclusion_proof,
                o_i,
                ..
            } => {
                let e_i = self.column_hash();
                let c_i = hash2(&o_i, &e_i);

                check!(inclusion_proof.validate_data(&c_i));

                true
            }
            ColumnProof::Odd {
                inclusion_proof,
                e_i,
                ..
            } => {
                let o_i = self.column_hash();
                let c_i = hash2(&o_i, &e_i);

                check!(inclusion_proof.validate_data(&c_i));

                true
            }
        }
    }
}
