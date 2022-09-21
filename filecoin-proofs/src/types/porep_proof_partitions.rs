#[derive(Clone, Copy, Debug)]
pub struct PoRepProofPartitions(pub usize);

impl From<PoRepProofPartitions> for usize {
    fn from(x: PoRepProofPartitions) -> Self {
        x.0
    }
}

impl From<usize> for PoRepProofPartitions {
    fn from(partition_count: usize) -> Self {
        PoRepProofPartitions(partition_count)
    }
}
