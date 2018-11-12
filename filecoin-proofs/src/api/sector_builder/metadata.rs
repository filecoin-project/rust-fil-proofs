use api::sector_builder::SectorId;

#[derive(Debug, Clone)]
pub struct StagedSectorMetadata {
    pub sector_id: SectorId,
    pub sector_access: String,
    pub pieces: Vec<PieceMetadata>,
}

#[derive(Clone)]
pub struct SealedSectorMetadata {
    pub sector_id: SectorId,
    pub sector_access: String,
    pub pieces: Vec<PieceMetadata>,
    pub comm_r_star: [u8; 32],
    pub comm_r: [u8; 32],
    pub comm_d: [u8; 32],
    pub snark_proof: [u8; 384],
}

#[derive(Debug, Clone)]
pub struct PieceMetadata {
    pub key: String,
    pub num_bytes: u64,
}
