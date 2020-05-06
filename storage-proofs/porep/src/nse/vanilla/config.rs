use storage_proofs_core::util::NODE_SIZE;

/// The configuration parameters for NSE.
#[derive(Debug, Clone)]
pub struct Config {
    /// Batch hashing factor.
    pub k: u32,
    /// Number of nodes per window.
    pub num_nodes_window: usize,
    /// Degree of the expander graph.
    pub degree_expander: usize,
    /// Degree of the butterfly graph.
    pub degree_butterfly: usize,
    /// Number of expander layers.
    pub num_expander_layers: usize,
    /// Number of butterfly layers.
    pub num_butterfly_layers: usize,
    /// Sector size in bytes.
    pub sector_size: usize,
}

impl Config {
    /// Total number of layers.
    pub fn num_layers(&self) -> usize {
        self.num_expander_layers + self.num_butterfly_layers
    }

    /// Number of bytes in a single window.
    pub fn window_size(&self) -> usize {
        self.num_nodes_window * NODE_SIZE
    }

    /// Number of windows.
    pub fn num_windows(&self) -> usize {
        self.sector_size / self.window_size()
    }
}
