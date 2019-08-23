use byteorder::ByteOrder;

#[derive(Debug, Clone, Copy, PartialOrd, PartialEq, Eq)]
pub struct SectorId(u64);

impl From<u64> for SectorId {
    fn from(n: u64) -> Self {
        SectorId(n)
    }
}

impl From<SectorId> for u64 {
    fn from(n: SectorId) -> Self {
        n.0
    }
}

impl std::cmp::Ord for SectorId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl SectorId {
    pub fn as_fr_safe(&self) -> [u8; 31] {
        let mut buf: [u8; 31] = [0; 31];
        byteorder::LittleEndian::write_u64(&mut buf[0..8], self.0);
        buf
    }
}
