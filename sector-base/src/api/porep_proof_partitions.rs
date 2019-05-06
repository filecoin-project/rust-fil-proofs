use crate::api::SINGLE_PARTITION_PROOF_LEN;

#[derive(Clone, Copy, Debug)]
pub struct PoRepProofPartitions(pub u8);

impl From<PoRepProofPartitions> for usize {
    fn from(x: PoRepProofPartitions) -> Self {
        x.0 as usize
    }
}

pub fn try_from_bytes(bytes: &[u8]) -> ::std::result::Result<PoRepProofPartitions, failure::Error> {
    let n = bytes.len();

    ensure!(
        n % SINGLE_PARTITION_PROOF_LEN == 0,
        "no PoRepProofPartitions mapping for {:x?}",
        bytes
    );

    Ok(PoRepProofPartitions((n / SINGLE_PARTITION_PROOF_LEN) as u8))
}
