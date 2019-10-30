use std::marker::PhantomData;

use blake2s_simd::Params as Blake2s;
use paired::bls12_381::Fr;

use crate::hasher::{Domain, Hasher};
use crate::stacked::encode::encode;
use crate::util::NODE_SIZE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingProof<H: Hasher> {
    pub(crate) parents: Vec<H::Domain>,
    pub(crate) node: u64,
    #[serde(skip)]
    _h: PhantomData<H>,
}

impl<H: Hasher> EncodingProof<H> {
    pub fn new(node: u64, parents: Vec<H::Domain>) -> Self {
        EncodingProof {
            node,
            parents,
            _h: PhantomData,
        }
    }

    fn create_key(&self, replica_id: &H::Domain) -> H::Domain {
        let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();

        // replica_id
        hasher.update(AsRef::<[u8]>::as_ref(replica_id));

        // node id
        let mut node_bytes = [0u8; 32];
        node_bytes[..8].copy_from_slice(&(self.node as u64).to_le_bytes());
        hasher.update(&node_bytes);

        for parent in &self.parents {
            hasher.update(AsRef::<[u8]>::as_ref(parent));
        }

        let mut key = *hasher.finalize().as_array();
        // strip last two bits, to ensure result is in Fr.
        key[31] &= 0b0011_1111;

        H::Domain::try_from_bytes(&key).expect("manually validated")
    }

    pub fn verify<G: Hasher>(
        &self,
        replica_id: &H::Domain,
        exp_encoded_node: &H::Domain,
        decoded_node: Option<&G::Domain>,
    ) -> bool {
        let key = self.create_key(replica_id);

        let encoded_node = if let Some(decoded_node) = decoded_node {
            let fr: Fr = (*decoded_node).into();
            encode(key, fr.into())
        } else {
            key
        };

        check_eq!(exp_encoded_node, &encoded_node);

        true
    }
}
