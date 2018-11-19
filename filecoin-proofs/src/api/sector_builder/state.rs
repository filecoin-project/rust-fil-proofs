use api::sector_builder::metadata::{SealedSectorMetadata, StagedSectorMetadata};
use api::sector_builder::SectorId;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

#[derive(Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct StagedState {
    pub sector_id_nonce: SectorId,
    pub sectors: HashMap<SectorId, StagedSectorMetadata>,
    pub sectors_accepting_data: HashSet<SectorId>,
}

#[derive(Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct SealedState {
    pub sectors: HashMap<SectorId, SealedSectorMetadata>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SectorBuilderState {
    pub prover_id: [u8; 31],
    pub staged: Mutex<StagedState>,
    pub sealed: Mutex<SealedState>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct StateSnapshot {
    pub prover_id: [u8; 31],
    pub staged: StagedState,
    pub sealed: SealedState,
}

impl Into<SectorBuilderState> for StateSnapshot {
    fn into(self) -> SectorBuilderState {
        SectorBuilderState {
            prover_id: self.prover_id,
            staged: Mutex::new(self.staged),
            sealed: Mutex::new(self.sealed),
        }
    }
}
