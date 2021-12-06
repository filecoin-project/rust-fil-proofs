// For production, h_select corresponds to the third element in
// storage_proofs_update::constants::hs i.e. h_select = 1 << 2 for h =
// hs(nodes_count)[2]
//
// hs is a vector containing all allowed values of h for a given
// sector size.
#[derive(Clone, Copy, Debug)]
pub struct HSelect(pub u8);

impl From<HSelect> for u64 {
    fn from(x: HSelect) -> Self {
        x.0 as u64
    }
}

impl From<HSelect> for usize {
    fn from(x: HSelect) -> Self {
        x.0 as usize
    }
}

impl From<usize> for HSelect {
    fn from(x: usize) -> Self {
        HSelect(x as u8)
    }
}

impl HSelect {
    pub fn from_nodes(nodes_count: usize) -> Self {
        HSelect::from(storage_proofs_update::constants::hs(nodes_count)[3])
    }
}
