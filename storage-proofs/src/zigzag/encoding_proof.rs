use std::marker::PhantomData;

use blake2s_simd::Params as Blake2s;
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::Hasher;
use crate::merkle::IncludedNode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingProof<H: Hasher> {
    #[serde(bound(
        serialize = "IncludedNode<H>: Serialize",
        deserialize = "IncludedNode<H>: Deserialize<'de>"
    ))]
    pub(crate) encoded_node: IncludedNode<H>,
    #[serde(bound(
        serialize = "IncludedNode<H>: Serialize",
        deserialize = "IncludedNode<H>: Deserialize<'de>"
    ))]
    pub(crate) decoded_node: IncludedNode<H>,
    pub(crate) parents: Vec<H::Domain>,
    #[serde(skip)]
    _h: PhantomData<H>,
}

impl<H: Hasher> EncodingProof<H> {
    pub fn new(
        encoded_node: IncludedNode<H>,
        decoded_node: IncludedNode<H>,
        parents: Vec<H::Domain>,
    ) -> Self {
        EncodingProof {
            encoded_node,
            decoded_node,
            parents,
            _h: PhantomData,
        }
    }

    pub fn verify(
        &self,
        replica_id: &H::Domain,
        expected_encoded_node: &H::Domain,
        expected_decoded_node: &H::Domain,
    ) -> bool {
        // create the key = H(tau || (e_k^(j))_{k in Parents(x, 1)})
        let key = {
            let mut hasher = Blake2s::new().hash_length(32).to_state();
            hasher.update(replica_id.as_ref());
            for parent in &self.parents {
                hasher.update(parent.as_ref());
            }

            let hash = hasher.finalize();
            bytes_into_fr_repr_safe(hash.as_ref()).into()
        };

        // decode:
        let decoded = H::sloth_decode(&key, &self.encoded_node);
        let decoded_node: &H::Domain = &self.decoded_node;
        let encoded_node: &H::Domain = &self.encoded_node;

        check_eq!(&decoded, decoded_node);
        check_eq!(decoded_node, expected_decoded_node);
        check_eq!(expected_encoded_node, encoded_node);

        true
    }
}
