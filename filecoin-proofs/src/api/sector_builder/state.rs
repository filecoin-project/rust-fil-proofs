use api::sector_builder::metadata::{SealedSectorMetadata, StagedSectorMetadata};
use api::sector_builder::SectorId;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct StagedState {
    pub sector_id_nonce: SectorId,
    pub sectors: HashMap<SectorId, StagedSectorMetadata>,
    pub sectors_accepting_data: HashSet<SectorId>,
}

#[derive(Default)]
pub struct SealedState {
    pub sectors: HashMap<SectorId, SealedSectorMetadata>,
}

pub struct SectorBuilderState {
    pub _metadata_dir: String,
    pub prover_id: [u8; 31],
    pub staged: Mutex<StagedState>,
    pub sealed: Mutex<SealedState>,
}
