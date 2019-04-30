use crate::api::bytes_amount::PoRepProofBytesAmount;
use crate::api::SINGLE_PARTITION_PROOF_LEN;

#[derive(Clone, Copy, Debug)]
pub struct PoRepProofPartitions(pub u8);

impl From<PoRepProofPartitions> for usize {
    fn from(x: PoRepProofPartitions) -> Self {
        x.0 as usize
    }
}

impl From<PoRepProofPartitions> for PoRepProofBytesAmount {
    fn from(x: PoRepProofPartitions) -> Self {
        PoRepProofBytesAmount(usize::from(x) * SINGLE_PARTITION_PROOF_LEN)
    }
}
