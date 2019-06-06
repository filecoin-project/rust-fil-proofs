use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct PoStConfig(pub SectorSize, pub PoStProofPartitions);

impl From<PoStConfig> for PaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig(s, _) => PaddedBytesAmount::from(s),
        }
    }
}

impl From<PoStConfig> for UnpaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig(s, _) => PaddedBytesAmount::from(s).into(),
        }
    }
}

impl From<PoStConfig> for PoStProofPartitions {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig(_, p) => p,
        }
    }
}
