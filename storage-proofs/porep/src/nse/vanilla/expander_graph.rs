use sha2raw::Sha256;

use super::config::Config;
use super::Parent;

/// The expander graph which provides the parents for the expander layers.
#[derive(Debug)]
pub struct ExpanderGraph {
    /// The number of bits required to identify a single parent.
    pub bits: u32,
    /// Batching hashing factor.
    pub k: u32,
    /// The degree of the graph.
    pub degree: usize,
}

impl ExpanderGraph {
    /// Calculates the parents for the node at the given `index`.
    pub fn parents(&self, index: u32) -> ExpanderGraphParentsIter {
        ExpanderGraphParentsIter::new(self, index)
    }

    /// Calculates the expanded parents for the node at the given `index`.
    pub fn expanded_parents(&self, index: u32) -> impl Iterator<Item = Parent> + '_ {
        let k = self.k;
        let p = self.parents(index);
        p.flat_map(move |parent| (0..k).map(move |i| parent * k + i))
    }
}

/// Iterator created by the [`parents`] method.
#[derive(Debug)]
pub struct ExpanderGraphParentsIter<'a> {
    graph: &'a ExpanderGraph,
    /// The index of the node.
    node: u32,
    /// The index of the parent to yield next.
    pos: usize,
    /// The current index into the stream.
    counter: u32,
    /// Index into the hash.
    hash_index: usize,
    /// The current hash.
    hash: [u8; 32],
}

impl<'a> ExpanderGraphParentsIter<'a> {
    fn new(graph: &'a ExpanderGraph, node: u32) -> Self {
        assert!(graph.bits < 32 * 8, "too many btis in the requested graph");

        let mut iter = ExpanderGraphParentsIter {
            graph,
            node,
            pos: 0,
            counter: 0,
            hash_index: 0,
            hash: [0u8; 32],
        };
        iter.update_hash();
        iter
    }

    /// Update the current hash value, based on the current `pos`.
    fn update_hash(&mut self) {
        // node index - 4 bytes
        self.hash[..4].copy_from_slice(&self.node.to_be_bytes());
        // counter - 4 bytes
        self.hash[4..8].copy_from_slice(&self.counter.to_be_bytes());
        // padding 0 - 24 bytes
        for i in 8..32 {
            self.hash[i] = 0;
        }

        let mut hasher = Sha256::new();
        hasher.input(&[&self.hash[..], &[0u8; 32]]);
        self.hash = hasher.finish();

        // update inner counter
        self.counter += 1;
        self.hash_index = 0;
    }
}

impl<'a> Iterator for ExpanderGraphParentsIter<'a> {
    type Item = Parent;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.graph.degree {
            // The iterator yields exactly degree number parents.
            return None;
        }

        const INDEX_BYTES: usize = 4;
        const HASH_BYTES: usize = 32;
        let parent_bytes = (self.graph.bits as usize / 8).max(1);
        debug_assert!(parent_bytes > 0);
        debug_assert!(parent_bytes <= INDEX_BYTES);

        // Need more bits, all in the next hash.
        if self.hash_index == HASH_BYTES {
            self.update_hash();
        }

        let hash_end = HASH_BYTES - self.hash_index;

        let mut parent = if parent_bytes <= hash_end {
            // Enough bits in the current hash.
            let mut parent = [0u8; INDEX_BYTES];

            parent[..parent_bytes]
                .copy_from_slice(&self.hash[self.hash_index..self.hash_index + parent_bytes]);
            self.hash_index += parent_bytes;
            u32::from_le_bytes(parent)
        } else {
            let mut parent = [0u8; INDEX_BYTES];
            // Copy rest from the current value.
            debug_assert!(hash_end > 0);
            debug_assert!(hash_end <= INDEX_BYTES);

            parent[..hash_end].copy_from_slice(&self.hash[self.hash_index..]);

            self.update_hash();

            // Copy the second part.
            let len = parent_bytes - hash_end;
            parent[hash_end..parent_bytes].copy_from_slice(&self.hash[..len]);
            self.hash_index += len;
            u32::from_le_bytes(parent)
        };

        if self.graph.bits < 8 {
            // Smaller than 1 byte, need to manually mod
            parent = parent % (2u64.pow(self.graph.bits) as u32);
        }

        // The parent should already be in the correct range based on the construction.
        debug_assert!(
            parent <= (2u64.pow(self.graph.bits) - 1) as u32,
            "{} <= {}",
            parent,
            (2u64.pow(self.graph.bits) - 1) as u32
        );

        self.pos += 1;

        Some(parent)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.graph.degree, Some(self.graph.degree))
    }
}

impl From<&Config> for ExpanderGraph {
    fn from(config: &Config) -> Self {
        let bits = (config.num_nodes_window as f64 / config.k as f64).log2() as u32;
        assert!(bits > 0);
        Self {
            bits,
            k: config.k,
            degree: config.degree_expander,
        }
    }
}

impl From<Config> for ExpanderGraph {
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

        let egraph: ExpanderGraph = config.into();

        assert_eq!(egraph.k, 8, "invalid k");
        assert_eq!(egraph.degree, 384, "invalid degree");
        assert_eq!(egraph.bits, 24, "invalid bits");
    }

    #[test]
    fn test_parents() {
        let graph = ExpanderGraph {
            k: 8,
            bits: 24,
            degree: 384,
        };

        let parents0: Vec<Parent> = graph.parents(0).collect();
        let parents1: Vec<Parent> = graph.parents(1).collect();

        assert_eq!(parents0.len(), graph.degree);
        assert_eq!(parents1.len(), graph.degree);
        assert_ne!(&parents0, &parents1, "must not be equal");

        let l = (graph.bits as usize * graph.degree) / 32;
        let expected_parents_hash: Vec<u8> = (0..l)
            .flat_map(|i| {
                let mut input = [0u8; 32];
                input[..4].copy_from_slice(&0u32.to_be_bytes());
                input[4..8].copy_from_slice(&(i as u32).to_be_bytes());
                Sha256::digest(&[&input[..], &[0u8; 32][..]]).to_vec()
            })
            .collect();
        assert_eq!(
            expected_parents_hash.len(),
            graph.degree * graph.bits as usize
        );

        for (actual_parent, expected_parent_hash) in parents0
            .into_iter()
            .zip(expected_parents_hash.chunks(24 / 8))
        {
            let mut raw = [0u8; 4];
            raw[..3].copy_from_slice(expected_parent_hash);
            let expected_parent = u32::from_le_bytes(raw);
            assert_eq!(actual_parent, expected_parent);
        }
    }

    #[test]
    fn test_expanded_parents() {
        let graph = ExpanderGraph {
            k: 8,
            bits: 24,
            degree: 384,
        };

        let parents0: Vec<Parent> = graph.expanded_parents(0).collect();
        let parents1: Vec<Parent> = graph.expanded_parents(1).collect();

        assert_eq!(parents0.len(), graph.degree * graph.k as usize);
        assert_eq!(parents1.len(), graph.degree * graph.k as usize);
        assert_ne!(&parents0, &parents1, "must not be equal");
    }

    #[test]
    fn test_expand_flatten() {
        let graphs = [
            ExpanderGraph {
                k: 8,
                bits: 24,
                degree: 384,
            },
            ExpanderGraph {
                k: 2,
                bits: 8,
                degree: 12,
            },
        ];
        for graph in &graphs {
            for i in 0..graph.degree {
                let parents: Vec<Parent> = graph.parents(i as u32).collect();
                let exp_parents: Vec<Parent> = graph.expanded_parents(i as u32).collect();

                let m = graph.degree as usize;
                let k = graph.k as usize;

                for j in 0..k {
                    let y = i + (j * m);
                    assert_eq!(parents[y / k] as usize * k + y % k, exp_parents[y] as usize);
                }

                assert!(
                    !parents.iter().all(|p| p == &0),
                    "parents must not be all 0"
                );
                assert!(
                    !graph.expanded_parents(i as u32).all(|p| p == 0),
                    "exp parents must not be all 0"
                );
            }
        }
    }
}
