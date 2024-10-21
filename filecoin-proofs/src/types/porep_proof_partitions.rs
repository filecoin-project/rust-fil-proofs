use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PoRepProofPartitions(pub u8);

impl From<PoRepProofPartitions> for usize {
    fn from(x: PoRepProofPartitions) -> Self {
        x.0 as usize
    }
}
