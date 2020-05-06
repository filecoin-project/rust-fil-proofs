use super::config::Config;
use super::Parent;

/// The butterfly graph which provides the parents for the butterfly layers.
#[derive(Debug)]
pub struct ButterflyGraph {
    /// The degree of the graph.
    pub degree: usize,
    /// The number of nodes in a window. Must be a power of 2.
    pub num_nodes_window: u32,
    /// Total number of layers.
    pub num_layers: u32,
    /// Number of butterfly layers.
    pub num_butterfly_layers: u32,
}

impl ButterflyGraph {
    /// Calculates the parents for the node at the given `index`, at the
    /// given `layer`.
    pub fn parents(&self, index: u32, layer: u32) -> ButterflyGraphParentsIter {
        assert!(layer <= self.num_layers);
        assert!(layer >= self.num_layers - self.num_butterfly_layers);
        ButterflyGraphParentsIter::new(self, index, layer)
    }
}

/// Iterator created by the [`parents`] method.
#[derive(Debug)]
pub struct ButterflyGraphParentsIter<'a> {
    graph: &'a ButterflyGraph,
    /// The index of the node.
    node: u32,
    /// The index of the parent to yield next.
    pos: u32,
    /// The constant factor of `butterfly_degree ** L - l`
    factor: u32,
}

impl<'a> ButterflyGraphParentsIter<'a> {
    fn new(graph: &'a ButterflyGraph, node: u32, layer: u32) -> Self {
        let factor = graph.degree.pow(graph.num_layers - layer) as u32;

        ButterflyGraphParentsIter {
            graph,
            node,
            pos: 0,
            factor,
        }
    }
}

impl<'a> Iterator for ButterflyGraphParentsIter<'a> {
    type Item = Parent;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.graph.degree as u32 {
            return None;
        }

        let parent_raw = self.node + self.pos * self.factor;
        // mod N
        let parent = parent_raw & (self.graph.num_nodes_window - 1);

        self.pos += 1;
        Some(parent)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.graph.degree, Some(self.graph.degree))
    }
}

impl From<&Config> for ButterflyGraph {
    fn from(config: &Config) -> Self {
        assert!(config.num_nodes_window < std::u32::MAX as usize);
        assert!(config.num_nodes_window.is_power_of_two());

        let num_layers = config.num_butterfly_layers + config.num_expander_layers;
        assert!(num_layers < std::u32::MAX as usize);
        let num_butterfly_layers = config.num_butterfly_layers;
        assert!(num_butterfly_layers < std::u32::MAX as usize);

        Self {
            degree: config.degree_butterfly,
            num_nodes_window: config.num_nodes_window as u32,
            num_layers: num_layers as u32,
            num_butterfly_layers: num_butterfly_layers as u32,
        }
    }
}

impl From<Config> for ButterflyGraph {
    fn from(config: Config) -> Self {
        (&config).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_config() {
        let config = Config {
            k: 8,
            num_nodes_window: (4 * 1024 * 1024 * 1024) / 32,
            degree_expander: 384,
            degree_butterfly: 16,
            num_expander_layers: 8,
            num_butterfly_layers: 7,
            sector_size: 1024 * 1024 * 1024 * 1024,
        };

        let graph: ButterflyGraph = config.into();

        assert_eq!(graph.degree, 16, "invalid degree");
        assert_eq!(graph.num_layers, 15, "invalid degree");
    }

    #[test]
    fn test_parents() {
        let config = Config {
            k: 8,
            num_nodes_window: (4 * 1024 * 1024 * 1024) / 32,
            degree_expander: 384,
            degree_butterfly: 16,
            num_expander_layers: 8,
            num_butterfly_layers: 7,
            sector_size: 1024 * 1024 * 1024 * 1024,
        };

        let graph: ButterflyGraph = config.into();

        let parents0_9: Vec<Parent> = graph.parents(0, 9).collect();
        let parents1_9: Vec<Parent> = graph.parents(1, 9).collect();
        let parents0_15: Vec<Parent> = graph.parents(0, 15).collect();

        assert_eq!(parents0_9.len(), graph.degree);
        assert_eq!(parents1_9.len(), graph.degree);
        assert_eq!(parents0_15.len(), graph.degree);
        assert_ne!(&parents0_9, &parents1_9, "must not be equal");
        assert_ne!(&parents0_9, &parents0_15, "must not be equal");

        for ((a, b), c) in parents0_9
            .iter()
            .zip(parents1_9.iter())
            .zip(parents0_15.iter())
        {
            assert!(*a < graph.num_nodes_window);
            assert!(*b < graph.num_nodes_window);
            assert!(*c < graph.num_nodes_window);
        }
    }
}
