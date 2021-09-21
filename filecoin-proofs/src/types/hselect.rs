#[derive(Clone, Copy, Debug)]
pub struct HSelect(pub u8);

impl From<HSelect> for u64 {
    fn from(x: HSelect) -> Self {
        x.0 as u64
    }
}

impl From<usize> for HSelect {
    fn from(x: usize) -> Self {
        HSelect::from(x)
    }
}
