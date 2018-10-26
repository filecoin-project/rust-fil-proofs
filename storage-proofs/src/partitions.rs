pub type Partitions = Option<usize>;

pub fn partition_count(partitions: Partitions) -> usize {
    match partitions {
        None => 1,
        Some(0) => panic!("cannot specify zero partitions"),
        Some(k) => k,
    }
}
