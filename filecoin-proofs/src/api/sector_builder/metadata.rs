use api::sector_builder::SectorId;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use error;

#[derive(Default, Clone)]
pub struct StagedSectorMetadata {
    pub sector_id: SectorId,
    pub sector_access: String,
    pub pieces: Vec<PieceMetadata>,
    pub sealing_error: Option<String>,
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

impl Default for SealedSectorMetadata {
    fn default() -> SealedSectorMetadata {
        SealedSectorMetadata {
            sector_id: Default::default(),
            sector_access: Default::default(),
            pieces: Default::default(),
            comm_r_star: Default::default(),
            comm_r: Default::default(),
            comm_d: Default::default(),
            snark_proof: [0; 384],
        }
    }
}

#[derive(Clone)]
pub struct PieceMetadata {
    pub piece_key: String,
    pub num_bytes: u64,
}

pub enum SealStatus {
    Failed(String),
    Pending,
    Sealed(Box<SealedSectorMetadata>),
    Sealing,
}

pub fn sum_piece_bytes(s: &StagedSectorMetadata) -> u64 {
    s.pieces.iter().map(|x| x.num_bytes).sum()
}

pub fn sector_id_as_bytes(sector_id: u64) -> error::Result<[u8; 31]> {
    // Transmute a u64 sector id to a zero-padded byte array.
    let mut sector_id_as_bytes = [0u8; 31];
    sector_id_as_bytes
        .as_mut()
        .write_u64::<LittleEndian>(sector_id)?;

    Ok(sector_id_as_bytes)
}
