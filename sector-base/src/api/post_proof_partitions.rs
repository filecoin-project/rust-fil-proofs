use crate::api::bytes_amount::PoStProofBytesAmount;
use crate::api::SINGLE_PARTITION_PROOF_LEN;

#[derive(Clone, Copy, Debug)]
pub enum PoStProofPartitions {
    One,
}

impl From<PoStProofPartitions> for PoStProofBytesAmount {
    fn from(x: PoStProofPartitions) -> Self {
        PoStProofBytesAmount(SINGLE_PARTITION_PROOF_LEN * usize::from(x))
    }
}

impl From<PoStProofPartitions> for usize {
    fn from(x: PoStProofPartitions) -> Self {
        match x {
            PoStProofPartitions::One => 1,
        }
    }
}

pub fn try_from_u8(n: u8) -> ::std::result::Result<PoStProofPartitions, failure::Error> {
    match n {
        1 => Ok(PoStProofPartitions::One),
        n => Err(format_err!("no PoStProofPartitions mapping for {}", n)),
    }
}

pub fn try_from_bytes(bytes: &[u8]) -> ::std::result::Result<PoStProofPartitions, failure::Error> {
    let n = bytes.len();

    let mkerr = || {
        Err(format_err!(
            "no PoStProofPartitions mapping for {:x?}",
            bytes
        ))
    };

    if n % SINGLE_PARTITION_PROOF_LEN == 0 {
        match n / SINGLE_PARTITION_PROOF_LEN {
            1 => Ok(PoStProofPartitions::One),
            _ => mkerr(),
        }
    } else {
        mkerr()
    }
}
