use log::trace;
use serde::{Deserialize, Serialize};

use crate::error::Result;
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
        ColumnProof {
            column,
            inclusion_proof,
        }
    }

    pub fn root(&self) -> &H::Domain {
        self.inclusion_proof.root()
    }

    fn column(&self) -> &Column<H> {
        &self.column
    }

    pub fn get_node_at_layer(&self, window_index: usize, layer: usize) -> Result<&H::Domain> {
        self.column().get_node_at_layer(window_index, layer)
    }

    pub fn get_verified_node_at_layer(
        &self,
        window_index: usize,
        layer: usize,
    ) -> Result<IncludedNode<H>> {
        let value = self.get_node_at_layer(window_index, layer)?;
        Ok(IncludedNode::new(*value))
    }

    pub fn column_hash(&self) -> PedersenDomain {
        self.column.hash()
    }

    pub fn verify(&self, challenge: u32, expected_root: &H::Domain) -> Result<bool> {
        let c_i = self.column_hash();

        check_eq!(self.inclusion_proof.root(), expected_root);
        check!(self.inclusion_proof.validate_data(c_i.as_ref()));
        check!(self.inclusion_proof.validate(challenge as usize));

        Ok(true)
    }
}
