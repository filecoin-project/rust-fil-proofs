use std::marker::PhantomData;

use log::trace;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::Hasher;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelingProof<H: Hasher> {
    pub(crate) parents: Vec<H::Domain>,
    pub(crate) window_index: Option<u64>,
    pub(crate) node: u64,
    #[serde(skip)]
    _h: PhantomData<H>,
}

impl<H: Hasher> LabelingProof<H> {
    pub fn new(window_index: Option<u64>, node: u64, parents: Vec<H::Domain>) -> Self {
        LabelingProof {
            node,
            window_index,
            parents,
            _h: PhantomData,
        }
    }

    fn create_label(&self, replica_id: &H::Domain) -> H::Domain {
        let mut hasher = Sha256::new();

        // replica_id
        hasher.input(AsRef::<[u8]>::as_ref(replica_id));

        if let Some(w) = self.window_index {
            // window index
            hasher.input(&w.to_be_bytes());
        }

        // node id
        hasher.input(&self.node.to_be_bytes());

        for parent in &self.parents {
            hasher.input(AsRef::<[u8]>::as_ref(parent));
        }

        bytes_into_fr_repr_safe(hasher.result().as_ref()).into()
    }

    pub fn verify(&self, replica_id: &H::Domain, expected_label: &H::Domain) -> Result<bool> {
        let label = self.create_label(replica_id);
        check_eq!(expected_label, &label);

        Ok(true)
    }
}
