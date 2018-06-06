use error::Result;
use hasher;
use merkle_light::{merkle, proof};
use rand::{thread_rng, Rng};
use std::cmp;
use std::collections::HashMap;
use std::iter::FromIterator;
use util::data_at_node;

type TREE_HASH_TYPE = hasher::RingSHA256Hash;
pub type TREE_ALGORITHM = hasher::SHA256Algorithm;

pub type MerkleTree = merkle::MerkleTree<TREE_HASH_TYPE, TREE_ALGORITHM>;
pub type MerkleProof = proof::Proof<TREE_HASH_TYPE>;

/// A DAG.
pub struct Graph {
    /// How many nodes are in this graph.
    pub nodes: usize,
    /// List of predecessors. An entry `(v, vec![u, w])` means
    /// there is an edge from `v -> u` and `v -> w`.
    pub pred: HashMap<usize, Vec<usize>>,
}

pub enum Sampling {
    DR,
    Bucket(usize),
}

impl Graph {
    /// Creates a new graph. If no sampling is passed, it does not contain any edges.
    pub fn new(nodes: usize, sampling: Option<Sampling>) -> Graph {
        match sampling {
            Some(Sampling::DR) => dr_sample(nodes),
            Some(Sampling::Bucket(m)) => bucket_sample(nodes, m),
            None => {
                Graph {
                    nodes: nodes,
                    // TODO: use int optimized hash function
                    // TODO: estimate capacity based on nodes
                    pred: HashMap::new(),
                }
            }
        }
    }

    /// Inserts a directed edge from u -> v.
    pub fn add_edge(&mut self, u: usize, v: usize) {
        self.pred.entry(u).or_insert(Vec::new());
        if let Some(edges) = self.pred.get_mut(&u) {
            edges.push(v);
        }
    }

    /// Returns the expected size of all nodes in the graph.
    pub fn expected_size(&self, node_size: usize) -> usize {
        self.nodes * node_size
    }

    /// Returns the commitment hash for the given data.
    pub fn commit(&self, data: &[u8], node_size: usize) -> Result<Vec<u8>> {
        let t = self.merkle_tree(data, node_size)?;
        Ok(t.root().to_vec())
    }

    /// Builds a merkle tree based on the given data.
    pub fn merkle_tree<'a>(&self, data: &'a [u8], node_size: usize) -> Result<MerkleTree> {
        if data.len() != node_size * self.nodes {
            return Err(format_err!("missmatch of data, node_size and nodes"));
        }

        Ok(merkle::MerkleTree::from_data((0..self.nodes).map(|i| {
            data_at_node(data, i + 1, node_size).expect("data_at_node math failed")
        })))
    }

    pub fn parents(&self, node: usize) -> Vec<usize> {
        self.pred
            .get(&node)
            .map(|p| (*p).clone())
            .unwrap_or(Vec::new())
    }

    pub fn size(&self) -> usize {
        self.nodes
    }
}

fn dr_sample(n: usize) -> Graph {
    assert!(n > 1, "graph too small");

    let mut graph = Graph::new(n, None);

    graph.add_edge(2, 1);

    for v in 3..graph.nodes {
        graph.add_edge(v, v - 1);
        graph.add_edge(v, get_random_parent(v));
    }

    graph
}

fn get_random_parent(v: usize) -> usize {
    let mut rng = thread_rng();
    let j: usize = rng.gen_range(1, floor_log2(v) + 1);
    let g = cmp::min(v - 1, 2_usize.pow(j as u32));
    let min = cmp::max(g / 2, 2);
    let r = if min == g { min } else { rng.gen_range(min, g) };

    v - r
}

#[inline]
fn floor_log2(i: usize) -> usize {
    ((i as f64).log2() + 0.5).floor() as usize
}

fn bucket_sample(n: usize, m: usize) -> Graph {
    let g_dash = dr_sample(n * m);

    let mut graph = Graph::new(n, None);

    let mut cache: HashMap<(usize, usize), bool> = HashMap::new();
    let size = g_dash.nodes + 1;

    for v in 1..size {
        if let Some(edges) = g_dash.pred.get(&v) {
            for u in edges {
                let i = ((u - 1) / m) + 1;
                let j = ((v - 1) / m) + 1;

                let cache_hit = {
                    let cache_entry = cache.get(&(i, j));
                    if let Some(c) = cache_entry {
                        *c
                    } else {
                        false
                    }
                };
                if i != j && !cache_hit {
                    cache.insert((j, i), true);
                    graph.add_edge(j, i);
                }
            }
        }
    }

    // reorder
    for v in 1..size {
        if let Some(edges) = graph.pred.get_mut(&v) {
            edges.sort();
        }
    }

    graph
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_graph_dr_sampling() {
        let g = Graph::new(10, Some(Sampling::DR));
        assert_eq!(g.nodes, 10);

        assert_eq!(g.pred.len(), 8);
    }

    #[test]
    fn test_graph_bucket_sampling() {
        let g = Graph::new(10, Some(Sampling::Bucket(3)));
        assert_eq!(g.nodes, 10);
    }

    #[test]
    fn test_graph_add_edge() {
        let mut g = Graph::new(10, None);

        g.add_edge(1, 2);
        g.add_edge(1, 3);

        let edges1 = g.pred.get(&1).unwrap();
        assert_eq!(*edges1, vec![2, 3]);

        assert_eq!(g.pred.get(&2), None);
        assert_eq!(g.pred.get(&3), None);

        assert_eq!(g.parents(1), vec![2, 3]);
        assert_eq!(g.parents(2), Vec::new());
    }

    #[test]
    fn test_graph_commit() {
        let mut g = Graph::new(10, None);

        g.add_edge(1, 2);
        g.add_edge(1, 3);

        let data = vec![1u8; 20];
        assert_eq!(g.commit(data.as_slice(), 2).unwrap().len(), 32);
    }

    #[test]
    fn test_prove_verify() {
        let g = Graph::new(5, Some(Sampling::Bucket(3)));
        let data = vec![2u8; 16 * 5];

        let tree = g.merkle_tree(data.as_slice(), 16).unwrap();
        let proof = tree.gen_proof(2);
        assert!(proof.validate::<TREE_ALGORITHM>());
    }
}
