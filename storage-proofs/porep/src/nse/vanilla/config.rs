/// The configuration parameters for NSE.
#[derive(Debug, Clone)]
pub struct Config {
    /// Batch hashing factor.
    pub k: u32,
    /// Window size in bytes.
    pub n: usize,
    /// Degree of the expander graph.
    pub degree_expander: usize,
    /// Degree of the butterfly graph.
    pub degree_butterfly: usize,
    /// Number of expander layers.
    pub num_expander_layers: usize,
    /// Number of butterfly layers.
    pub num_butterfly_layers: usize,
}

impl Config {
    /// Total number of layers.
    pub fn num_layers(&self) -> usize {
        self.num_expander_layers + self.num_butterfly_layers
    }
}
