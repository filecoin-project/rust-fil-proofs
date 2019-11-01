use std::marker::PhantomData;

use blake2s_simd::Params as Blake2s;

use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::Hasher;
use crate::util::NODE_SIZE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelingProof<H: Hasher> {
    pub(crate) parents: Vec<H::Domain>,
    pub(crate) node: u64,
    #[serde(skip)]
    _h: PhantomData<H>,
}

impl<H: Hasher> LabelingProof<H> {
    pub fn new(node: u64, parents: Vec<H::Domain>) -> Self {
        LabelingProof {
            node,
            parents,
            _h: PhantomData,
        }
    }

    fn create_label(&self, replica_id: &H::Domain) -> H::Domain {
        let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();

        // replica_id
        hasher.update(AsRef::<[u8]>::as_ref(replica_id));

        // node id
        hasher.update(&(self.node as u64).to_le_bytes());

        for parent in &self.parents {
            hasher.update(AsRef::<[u8]>::as_ref(parent));
        }

        bytes_into_fr_repr_safe(hasher.finalize().as_ref()).into()
    }

    pub fn verify(&self, replica_id: &H::Domain, expected_label: &H::Domain) -> bool {
        let label = self.create_label(replica_id);
        check_eq!(expected_label, &label);

        true
    }
}
