use crypto::feistel;
use drgraph::{BucketGraph, Graph};
use layered_drgporep::Layerable;
use parameter_cache::ParameterSetIdentifier;

pub const DEFAULT_EXPANSION_DEGREE: usize = 8;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZigZagGraph<G: Graph>
where
    G: 'static,
{
    expansion_degree: usize,
    base_graph: G,
    pub reversed: bool,
}

pub type ZigZagBucketGraph = ZigZagGraph<BucketGraph>;

impl<'a, G: Graph> Layerable for ZigZagGraph<G> {}

impl<G: Graph> ZigZagGraph<G> {
    pub fn new(nodes: usize, base_degree: usize, expansion_degree: usize, seed: [u32; 7]) -> Self {
        ZigZagGraph {
            base_graph: G::new(nodes, base_degree, 0, seed),
            expansion_degree,
            reversed: false,
        }
    }
}

impl<G> ParameterSetIdentifier for ZigZagGraph<G>
where
    G: Graph + ParameterSetIdentifier,
{
    fn parameter_set_identifier(&self) -> String {
        format!(
            "zigzag_graph::ZigZagGraph{{expansion_degree: {} base_graph: {} }}",
            self.expansion_degree,
            self.base_graph.parameter_set_identifier()
        )
    }
}

pub trait ZigZag: ::std::fmt::Debug + Clone + PartialEq + Eq {
    type BaseGraph: Graph;

    /// zigzag returns a new graph with expansion component inverted and a distinct
    /// base DRG graph -- with the direction of drg connections reversed. (i.e. from high-to-low nodes).
    /// The name is 'weird', but so is the operation -- hence the choice.
    fn zigzag(&self) -> Self;
    /// Constructs a new graph.
    fn base_graph(&self) -> Self::BaseGraph;
    fn expansion_degree(&self) -> usize;
    fn reversed(&self) -> bool;
    fn expanded_parents(&self, node: usize) -> Vec<usize>;
    fn real_index(&self, i: usize) -> usize;
    fn new_zigzag(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        seed: [u32; 7],
    ) -> Self;
}

impl<Z: ZigZag> Graph for Z {
    fn size(&self) -> usize {
        self.base_graph().size()
    }

    fn degree(&self) -> usize {
        self.base_graph().degree() + self.expansion_degree()
    }

    #[inline]
    fn parents(&self, raw_node: usize) -> Vec<usize> {
        // If graph is reversed, use real_index to convert index to reversed index.
        // So we convert a raw reversed node to an unreversed node, calculate its parents,
        // then convert the parents to reversed.

        let drg_parents = self
            .base_graph()
            .parents(self.real_index(raw_node))
            .iter()
            .map(|i| self.real_index(*i))
            .collect::<Vec<_>>();

        let mut parents = drg_parents;
        // expanded_parents takes raw_node
        let expanded_parents = self.expanded_parents(raw_node);

        parents.extend(expanded_parents.iter());

        // Pad so all nodes have correct degree.
        for _ in 0..(self.degree() - parents.len()) {
            if self.reversed() {
                parents.push(self.size() - 1);
            } else {
                parents.push(0);
            }
        }
        assert!(parents.len() == self.degree());
        parents.sort();

        assert!(parents.iter().all(|p| if self.forward() {
            *p <= raw_node
        } else {
            *p >= raw_node
        }));

        parents
    }

    fn seed(&self) -> [u32; 7] {
        self.base_graph().seed()
    }

    fn new(nodes: usize, base_degree: usize, expansion_degree: usize, seed: [u32; 7]) -> Self {
        Z::new_zigzag(nodes, base_degree, expansion_degree, seed)
    }

    fn forward(&self) -> bool {
        !self.reversed()
    }
}

impl<'a, G: Graph> ZigZagGraph<G> {
    fn correspondent(&self, node: usize, i: usize) -> usize {
        let a = (node * self.expansion_degree) as u32 + i as u32;
        let feistel_keys = &[1, 2, 3, 4];

        let transformed = if self.reversed {
            feistel::invert_permute(
                self.size() as u32 * self.expansion_degree as u32,
                a,
                feistel_keys,
            )
        } else {
            feistel::permute(
                self.size() as u32 * self.expansion_degree as u32,
                a,
                feistel_keys,
            )
        };
        transformed as usize / self.expansion_degree
    }
}

impl<'a, G: Graph> ZigZag for ZigZagGraph<G> {
    type BaseGraph = G;

    fn new_zigzag(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        seed: [u32; 7],
    ) -> Self {
        Self::new(nodes, base_degree, expansion_degree, seed)
    }

    /// To zigzag a graph, we just toggle its reversed field.
    /// All the real work happens when we calculate node parents on-demand.
    fn zigzag(&self) -> Self {
        ZigZagGraph {
            base_graph: self.base_graph.clone(),
            expansion_degree: self.expansion_degree,
            reversed: !self.reversed,
        }
    }

    fn base_graph(&self) -> Self::BaseGraph {
        self.base_graph.clone()
    }

    fn expansion_degree(&self) -> usize {
        self.expansion_degree
    }

    fn reversed(&self) -> bool {
        self.reversed
    }

    #[inline]
    fn expanded_parents(&self, node: usize) -> Vec<usize> {
        (0..self.expansion_degree)
            .filter_map(|i| {
                let other = self.correspondent(node, i);
                if self.reversed {
                    if other > node {
                        Some(other)
                    } else {
                        None
                    }
                } else if other < node {
                    Some(other)
                } else {
                    None
                }
            })
            .collect()
    }

    #[inline]
    fn real_index(&self, i: usize) -> usize {
        if self.reversed {
            (self.size() - 1) - i
        } else {
            i
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use drgraph::new_seed;
    use std::collections::HashMap;

    fn assert_graph_ascending<G: Graph>(g: G) {
        for i in 0..g.size() {
            for p in g.parents(i) {
                if i == 0 {
                    assert!(p == i);
                } else {
                    assert!(p < i);
                }
            }
        }
    }

    fn assert_graph_descending<G: Graph>(g: G) {
        for i in 0..g.size() {
            let parents = g.parents(i);
            for p in parents {
                if i == g.size() - 1 {
                    assert!(p == i);
                } else {
                    assert!(p > i);
                }
            }
        }
    }

    #[test]
    fn zigzag_graph_zigzags() {
        let g = ZigZagBucketGraph::new(50, 5, DEFAULT_EXPANSION_DEGREE, new_seed());
        let gz = g.zigzag();

        assert_graph_ascending(g);
        assert_graph_descending(gz);
    }

    #[test]
    fn expansion() {
        // We need a graph.
        let g = ZigZagBucketGraph::new(25, 5, DEFAULT_EXPANSION_DEGREE, new_seed());

        // We're going to fully realize the expansion-graph component, in a HashMap.
        let mut gcache: HashMap<usize, Vec<usize>> = HashMap::new();

        // Populate the HashMap with each node's 'expanded parents'.
        for i in 0..g.size() {
            let parents = g.expanded_parents(i);
            gcache.insert(i, parents);
        }

        // Here's the zigzag version of the graph.
        let gz = g.zigzag();

        // And a HashMap to hold the expanded parents.
        let mut gzcache: HashMap<usize, Vec<usize>> = HashMap::new();

        for i in 0..gz.size() {
            let parents = gz.expanded_parents(i);

            // Check to make sure all (expanded) node-parent relationships also exist in reverse,
            // in the original graph's Hashmap.
            for p in &parents {
                assert!(gcache[&p].contains(&i));
            }
            // And populate the zigzag's HashMap.
            gzcache.insert(i, parents);
        }

        // And then do the same check to make sure all (expanded) node-parent relationships from the original
        // are present in the zigzag, just reversed.
        for i in 0..g.size() {
            let parents = g.expanded_parents(i);
            for p in parents {
                assert!(gzcache[&p].contains(&i));
            }
        }
        // Having checked both ways, we know the graph and its zigzag counterpart have 'expanded' components
        // which are each other's inverses. It's important that this be true.
    }
}
