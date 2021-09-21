#[derive(Clone, Copy, Debug)]
pub struct UpdateProofPartitions(pub u8);

impl From<UpdateProofPartitions> for usize {
    fn from(x: UpdateProofPartitions) -> Self {
        x.0 as usize
    }
}

impl From<usize> for UpdateProofPartitions {
    fn from(x: usize) -> Self {
        UpdateProofPartitions::from(x)
    }
}
