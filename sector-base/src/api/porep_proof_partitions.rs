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

pub fn try_from_bytes(bytes: &[u8]) -> ::std::result::Result<PoRepProofPartitions, failure::Error> {
    let n = bytes.len();

    if n % SINGLE_PARTITION_PROOF_LEN == 0 {
        Ok(PoRepProofPartitions((n / SINGLE_PARTITION_PROOF_LEN) as u8))
    } else {
        Err(format_err!(
            "no PoRepProofPartitions mapping for {:x?}",
            bytes
        ))
    }
}
