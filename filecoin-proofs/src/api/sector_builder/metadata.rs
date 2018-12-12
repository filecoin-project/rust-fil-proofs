use crate::api::sector_builder::SectorId;
use crate::error;
use crate::serde_big_array::BigArray;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct StagedSectorMetadata {
    pub sector_id: SectorId,
    pub sector_access: String,
    pub pieces: Vec<PieceMetadata>,
    pub seal_status: SealStatus,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SealedSectorMetadata {
    pub sector_id: SectorId,
    pub sector_access: String,
    pub pieces: Vec<PieceMetadata>,
    pub comm_r_star: [u8; 32],
    pub comm_r: [u8; 32],
    pub comm_d: [u8; 32],

    #[serde(with = "BigArray")]
    pub snark_proof: [u8; 384],
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct PieceMetadata {
    pub piece_key: String,
    pub num_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum SealStatus {
    Failed(String),
    Pending,
    Sealed(Box<SealedSectorMetadata>),
    Sealing,
}

impl PartialEq for SealedSectorMetadata {
    fn eq(&self, other: &SealedSectorMetadata) -> bool {
        self.sector_id == other.sector_id
            && self.sector_access == other.sector_access
            && self.pieces == other.pieces
            && self.comm_r_star == other.comm_r_star
            && self.comm_r == other.comm_r
            && self.comm_d == other.comm_d
            && self.snark_proof.iter().eq(other.snark_proof.iter())
    }
}

impl Default for StagedSectorMetadata {
    fn default() -> StagedSectorMetadata {
        StagedSectorMetadata {
            sector_id: Default::default(),
            sector_access: Default::default(),
            pieces: Default::default(),
            seal_status: SealStatus::Pending,
        }
    }
}

impl fmt::Debug for SealedSectorMetadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SealedSectorMetadata {{ sector_id: {}, sector_access: {}, pieces: {:?}, comm_r_star: {:?}, comm_r: {:?}, comm_d: {:?} }}", self.sector_id, self.sector_access, self.pieces, self.comm_r_star, self.comm_r, self.comm_d)
    }
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

pub fn sum_piece_bytes(s: &StagedSectorMetadata) -> u64 {
    s.pieces.iter().map(|x| x.num_bytes).sum()
}

pub fn sector_id_as_bytes(sector_id: SectorId) -> error::Result<[u8; 31]> {
    // Transmute a u64 sector id to a zero-padded byte array.
    let mut sector_id_as_bytes = [0u8; 31];
    sector_id_as_bytes
        .as_mut()
        .write_u64::<LittleEndian>(sector_id)?;

    Ok(sector_id_as_bytes)
}
