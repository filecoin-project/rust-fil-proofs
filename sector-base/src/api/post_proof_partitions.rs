use crate::api::bytes_amount::PoStProofBytesAmount;
use crate::api::SINGLE_PARTITION_PROOF_LEN;

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

pub fn try_from_bytes(bytes: &[u8]) -> ::std::result::Result<PoStProofPartitions, failure::Error> {
    let n = bytes.len();

    ensure!(
        n % SINGLE_PARTITION_PROOF_LEN == 0,
        "no PoStProofPartitions mapping for {:x?}",
        bytes
    );

    Ok(PoStProofPartitions((n / SINGLE_PARTITION_PROOF_LEN) as u8))
}
