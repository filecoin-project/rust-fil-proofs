use std::marker::PhantomData;

use log::trace;
use paired::bls12_381::Fr;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encode::encode;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::Hasher;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingProof<H: Hasher> {
    pub(crate) parents: Vec<H::Domain>,
    pub(crate) window_index: u64,
    pub(crate) node: u64,
    #[serde(skip)]
    _h: PhantomData<H>,
}

impl<H: Hasher> EncodingProof<H> {
    pub fn new(window_index: u64, node: u64, parents: Vec<H::Domain>) -> Self {
        EncodingProof {
            window_index,
            node,
            parents,
            _h: PhantomData,
        }
    }

    fn create_key(&self, replica_id: &H::Domain) -> H::Domain {
        let mut hasher = Sha256::new();

        // replica_id
        hasher.input(AsRef::<[u8]>::as_ref(replica_id));

        // window_index
        hasher.input(&self.window_index.to_be_bytes());

        // node id
        hasher.input(&self.node.to_be_bytes());

        for parent in &self.parents {
            hasher.input(AsRef::<[u8]>::as_ref(parent));
        }

        bytes_into_fr_repr_safe(hasher.result().as_ref()).into()
    }

    pub fn verify<G: Hasher>(
        &self,
        replica_id: &H::Domain,
        exp_encoded_node: &H::Domain,
        decoded_node: &G::Domain,
    ) -> Result<bool> {
        let key = self.create_key(replica_id);

        let fr: Fr = (*decoded_node).into();
        let encoded_node = encode(key, fr.into());

        check_eq!(exp_encoded_node, &encoded_node);

        Ok(true)
    }
}
