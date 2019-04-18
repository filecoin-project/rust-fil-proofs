use crate::api::bytes_amount::PoRepProofBytesAmount;
use crate::api::SINGLE_PARTITION_PROOF_LEN;

// When modifying, update internal::tests::partition_layer_challenges_test to reflect supported PoRepProofPartitions.
#[derive(Clone, Copy, Debug)]
pub enum PoRepProofPartitions {
    Two,
}

pub const POREP_PROOF_PARTITION_CHOICES: [PoRepProofPartitions; 1] = [PoRepProofPartitions::Two];

impl From<PoRepProofPartitions> for usize {
    fn from(x: PoRepProofPartitions) -> Self {
        match x {
            PoRepProofPartitions::Two => 2,
        }
    }
}

impl From<PoRepProofPartitions> for PoRepProofBytesAmount {
    fn from(x: PoRepProofPartitions) -> Self {
        PoRepProofBytesAmount(SINGLE_PARTITION_PROOF_LEN * usize::from(x))
    }
}

pub fn try_from_u8(n: u8) -> ::std::result::Result<PoRepProofPartitions, failure::Error> {
    match n {
        2 => Ok(PoRepProofPartitions::Two),
        n => Err(format_err!("no PoRepProofPartitions mapping for {}", n)),
    }
}
