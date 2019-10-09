use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::hasher::pedersen::PedersenDomain;
use crate::hasher::Hasher;
use crate::merkle::{IncludedNode, MerkleProof};
use crate::stacked::column::Column;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnProof<H: Hasher> {
    #[serde(bound(
        serialize = "Column<H>: Serialize",
        deserialize = "Column<H>: Deserialize<'de>"
    ))]
    pub(crate) column: Column<H>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub(crate) inclusion_proof: MerkleProof<H>,
}

impl<H: Hasher> ColumnProof<H> {
    pub fn from_column(column: Column<H>, inclusion_proof: MerkleProof<H>) -> Self {
        let res = ColumnProof {
            column,
            inclusion_proof,
        };
        debug_assert!(res.verify());

        res
    }

    pub fn root(&self) -> &H::Domain {
        self.inclusion_proof.root()
    }

    fn column(&self) -> &Column<H> {
        &self.column
    }

    pub fn get_node_at_layer(&self, layer: usize) -> &H::Domain {
        self.column().get_node_at_layer(layer)
    }

    pub fn get_verified_node_at_layer(&self, layer: usize) -> IncludedNode<H> {
        let value = self.get_node_at_layer(layer);
        IncludedNode::new(*value)
    }

    pub fn column_hash(&self) -> PedersenDomain {
        self.column().hash()
    }

    pub fn verify(&self) -> bool {
        let c_i = self.column_hash();

        check!(self.inclusion_proof.validate_data(c_i.as_ref()));

        true
    }
}
