use crate::constants::SINGLE_PARTITION_PROOF_LEN;
use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct PoStProofPartitions(pub u8);

impl From<PoStProofPartitions> for PoStProofBytesAmount {
    fn from(x: PoStProofPartitions) -> Self {
        PoStProofBytesAmount(SINGLE_PARTITION_PROOF_LEN * usize::from(x))
    }
}

impl From<PoStProofPartitions> for usize {
    fn from(x: PoStProofPartitions) -> Self {
        x.0 as usize
    }
}
