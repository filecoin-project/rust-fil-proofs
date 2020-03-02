use generic_array::typenum;
use log::trace;
use paired::bls12_381::Fr;
use serde::{Deserialize, Serialize};

use super::column::Column;

use crate::error::Result;
use crate::hasher::Hasher;
use crate::merkle::{IncludedNode, MerkleProof};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnProof<H: Hasher> {
    #[serde(bound(
        serialize = "Column<H>: Serialize",
        deserialize = "Column<H>: Deserialize<'de>"
    ))]
    pub(crate) column: Column<H>,
    #[serde(bound(
        serialize = "MerkleProof<H, typenum::U8>: Serialize",
        deserialize = "MerkleProof<H, typenum::U8>: Deserialize<'de>"
    ))]
    pub(crate) inclusion_proof: MerkleProof<H, typenum::U8>,
}

impl<H: Hasher> ColumnProof<H> {
    pub fn from_column(
        column: Column<H>,
        inclusion_proof: MerkleProof<H, typenum::U8>,
    ) -> Result<Self> {
        Ok(ColumnProof {
            column,
            inclusion_proof,
        })
    }

    pub fn root(&self) -> &H::Domain {
        self.inclusion_proof.root()
    }

    fn column(&self) -> &Column<H> {
        &self.column
    }

    pub fn get_node_at_layer(&self, layer: usize) -> Result<&H::Domain> {
        self.column().get_node_at_layer(layer)
    }

    pub fn get_verified_node_at_layer(&self, layer: usize) -> IncludedNode<H> {
        let value = self.get_node_at_layer(layer).unwrap(); // FIXME: error handling
        IncludedNode::new(*value)
    }

    pub fn column_hash(&self) -> Fr {
        self.column.hash()
    }

    pub fn verify(&self, challenge: u32, expected_root: &H::Domain) -> bool {
        let c_i = self.column_hash();

        check_eq!(self.inclusion_proof.root(), expected_root);
        check!(self.inclusion_proof.validate_data(c_i.into()));
        check!(self.inclusion_proof.validate(challenge as usize));

        true
    }
}
