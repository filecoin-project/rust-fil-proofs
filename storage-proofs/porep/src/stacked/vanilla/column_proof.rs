use bellperson::bls::Fr;
use log::trace;
use serde::{Deserialize, Serialize};
use storage_proofs_core::{error::Result, hasher::Hasher, merkle::MerkleProofTrait};

use super::column::Column;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnProof<Proof: MerkleProofTrait> {
    #[serde(bound(
        serialize = "Column<Proof::Hasher>: Serialize",
        deserialize = "Column<Proof::Hasher>: Deserialize<'de>"
    ))]
    pub(crate) column: Column<Proof::Hasher>,
    #[serde(bound(
        serialize = "Proof: Serialize",
        deserialize = "Proof: serde::de::DeserializeOwned"
    ))]
    pub(crate) inclusion_proof: Proof,
}

impl<Proof: MerkleProofTrait> ColumnProof<Proof> {
    pub fn from_column(column: Column<Proof::Hasher>, inclusion_proof: Proof) -> Result<Self> {
        Ok(ColumnProof {
            column,
            inclusion_proof,
        })
    }

    pub fn root(&self) -> <Proof::Hasher as Hasher>::Domain {
        self.inclusion_proof.root()
    }

    fn column(&self) -> &Column<Proof::Hasher> {
        &self.column
    }

    pub fn get_node_at_layer(&self, layer: usize) -> Result<&<Proof::Hasher as Hasher>::Domain> {
        self.column().get_node_at_layer(layer)
    }

    pub fn column_hash(&self) -> Fr {
        self.column.hash()
    }

    pub fn verify(
        &self,
        challenge: u32,
        expected_root: &<Proof::Hasher as Hasher>::Domain,
    ) -> bool {
        let c_i = self.column_hash();

        check_eq!(&self.inclusion_proof.root(), expected_root);
        check!(self.inclusion_proof.validate_data(c_i.into()));
        check!(self.inclusion_proof.validate(challenge as usize));

        true
    }
}
