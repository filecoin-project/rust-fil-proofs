use crypto::feistel;
use error::Result;
use hasher::pedersen;
use merkle_light::hash::{Algorithm, Hashable};
use merkle_light::{merkle, proof};
use pairing::bls12_381::Fr;
use rand::{thread_rng, Rng};
use std::cmp;
use std::collections::{HashMap, HashSet};
use util::data_at_node;

pub type TreeHash = pedersen::PedersenHash;
pub type TreeAlgorithm = pedersen::PedersenAlgorithm;

// NOTE: Swapping in SHA256 is so much faster that this is effectively necessary when
// developing/debugging and running tests repeatedly.

//use hasher;
//pub type TreeHash = hasher::sha256::RingSHA256Hash;
//pub type TreeAlgorithm = hasher::sha256::SHA256Algorithm;

pub type MerkleTree = merkle::MerkleTree<TreeHash, TreeAlgorithm>;

/// Representation of a merkle proof.
/// Each element in the `path` vector consists of a tuple `(hash, is_right)`, with `hash` being the the hash of the node at the current level and `is_right` a boolean indicating if the path is taking the right path.
/// The first element is the hash of leaf itself, and the last is the root hash.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    path: Vec<(TreeHash, bool)>,
    root: TreeHash,
    leaf: TreeHash,
}

impl MerkleProof {
    /// Convert the merkle path into the format expected by the circuits, which is a vector of options of the tuples.
    /// This does __not__ include the root and the leaf.
    pub fn as_options(&self) -> Vec<Option<(Fr, bool)>> {
        self.path
            .iter()
            .map(|v| Some((v.0.into(), v.1)))
            .collect::<Vec<_>>()
    }

    /// Validates the MerkleProof
    pub fn validate(&self) -> bool {
        let mut a = TreeAlgorithm::default();

        self.root() == (0..self.path.len()).fold(self.leaf, |h, i| {
            a.reset();
            let is_right = self.path[i].1;

            let (left, right) = if is_right {
                (self.path[i].0, h)
            } else {
                (h, self.path[i].0)
            };

            a.node(left, right, i)
        })
    }

    /// Validates that the data, hashes to the leave of the merkel path.
    pub fn validate_data(&self, data: &Hashable<TreeAlgorithm>) -> bool {
        let mut a = TreeAlgorithm::default();
        data.hash(&mut a);
        let item_hash = a.hash();
        let leaf_hash = a.leaf(item_hash);

        leaf_hash == self.leaf()
    }

    /// Returns the hash of leaf that this MerkleProof represents.
    pub fn leaf(&self) -> TreeHash {
        self.leaf
    }

    /// Returns the root hash
    pub fn root(&self) -> TreeHash {
        self.root
    }

    /// Returns the length of the proof. That is all path elements plus 1 for the
    /// leaf and 1 for the root.
    pub fn len(&self) -> usize {
        self.path.len() + 2
    }
}

impl Into<MerkleProof> for proof::Proof<TreeHash> {
    fn into(self) -> MerkleProof {
        MerkleProof {
            path: self
                .lemma()
                .iter()
                .skip(1)
                .zip(self.path().iter())
                .map(|(hash, is_left)| (*hash, !is_left))
                .collect::<Vec<_>>(),
            root: self.root(),
            leaf: self.item(),
        }
    }
}

pub fn proof_into_options(p: proof::Proof<TreeHash>) -> Vec<Option<(Fr, bool)>> {
    let p: MerkleProof = p.into();
    p.as_options()
}

/// A DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graph {
    /// How many nodes are in this graph.
    nodes: usize,
    /// List of predecessors. An entry `(v, vec![u, w])` means
    /// there is an edge from `v -> u` and `v -> w`.
    pub pred: HashMap<usize, HashSet<usize>>,
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
                    nodes,
                    // TODO: use int optimized hash function
                    // TODO: estimate capacity based on nodes
                    pred: HashMap::new(),
                }
            }
        }
    }

    /// Inserts a directed edge from u -> v.
    pub fn add_edge(&mut self, u: usize, v: usize) {
        self.pred
            .entry(u)
            .or_insert_with(|| HashSet::with_capacity(1));

        if let Some(edges) = self.pred.get_mut(&u) {
            edges.insert(v);
        }
    }

    /// Returns the expected size of all nodes in the graph.
    pub fn expected_size(&self, node_size: usize) -> usize {
        self.nodes * node_size
    }

    /// Returns the commitment hash for the given data.
    pub fn commit(&self, data: &[u8], node_size: usize) -> Result<TreeHash> {
        let t = self.merkle_tree(data, node_size)?;
        Ok(t.root())
    }

    /// Builds a merkle tree based on the given data.
    pub fn merkle_tree<'a>(&self, data: &'a [u8], node_size: usize) -> Result<MerkleTree> {
        if data.len() != node_size * self.nodes {
            return Err(format_err!("missmatch of data, node_size and nodes"));
        }

        if !(node_size == 16 || node_size == 32 || node_size == 64) {
            return Err(format_err!("invalid node size, must be 16, 32 or 64"));
        }

        Ok(MerkleTree::from_data((0..self.nodes).map(|i| {
            data_at_node(data, i + 1, node_size).expect("data_at_node math failed")
        })))
    }

    /// Returns a sorted list of all parents of this node.
    pub fn parents(&self, node: usize) -> Vec<usize> {
        self.pred
            .get(&node)
            .map(|p| {
                let mut res = p.iter().cloned().collect::<Vec<_>>();
                res.sort();
                res
            })
            .unwrap_or_else(Vec::new)
    }

    /// Returns the size of the node.
    pub fn size(&self) -> usize {
        self.nodes
    }
    pub fn permute(&self, keys: &[u32]) -> Graph {
        let mut tmp: HashMap<usize, HashSet<usize>> = HashMap::new();
        let nodes: u32 = self.nodes as u32;
        let p: HashMap<usize, usize> = (0..self.nodes)
            .map(|i| (i + 1, feistel::permute(nodes, i as u32, keys) as usize + 1))
            .collect();

        for (key, preds) in &self.pred {
            for pred in preds {
                tmp.entry(p[key]).or_insert_with(HashSet::new);

                if let Some(val) = tmp.get_mut(&p[key]) {
                    val.insert(p[pred]);
                }
            }
        }

        let mut permuted = Graph::new(self.nodes, None);
        permuted.pred = tmp;
        permuted
    }
    pub fn invert_permute(&self, keys: &[u32]) -> Graph {
        let nodes: u32 = self.nodes as u32;
        let p: HashMap<usize, usize> = (0..self.nodes)
            .map(|i| {
                (
                    i + 1,
                    feistel::invert_permute(nodes, i as u32, keys) as usize + 1,
                )
            })
            .collect();

        // This is just a deep copy with transformation.
        let mut tmp: HashMap<usize, HashSet<usize>> = HashMap::new();
        for (key, preds) in &self.pred {
            for pred in preds {
                tmp.entry(p[key]).or_insert_with(HashSet::new);

                if let Some(val) = tmp.get_mut(&p[key]) {
                    val.insert(p[pred]);
                }
            }
        }

        let mut permuted = Graph::new(self.nodes, None);
        permuted.pred = tmp;
        permuted
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

    graph
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{self, Rng};

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

        let edges1 = g.parents(1);
        assert_eq!(edges1, vec![2, 3]);

        assert_eq!(g.parents(2).len(), 0);
        assert_eq!(g.parents(3).len(), 0);

        assert_eq!(g.parents(1), vec![2, 3]);
        assert_eq!(g.parents(2), Vec::new());

        // double insert
        g.add_edge(1, 4);
        g.add_edge(1, 4);

        let edges2 = g.parents(1);

        assert_eq!(edges2, vec![2, 3, 4]);

        // sorted parents

        g.add_edge(2, 7);
        g.add_edge(2, 1);

        assert_eq!(g.parents(2), vec![1, 7]);
    }

    #[test]
    fn test_graph_commit() {
        let mut g = Graph::new(3, None);

        g.add_edge(1, 2);
        g.add_edge(1, 3);

        let data = vec![1u8; 3 * 16];
        g.commit(data.as_slice(), 16).unwrap();
        // TODO: add assertion
    }

    #[test]
    fn test_gen_proof() {
        let g = Graph::new(5, Some(Sampling::Bucket(3)));
        let data = vec![2u8; 16 * 5];

        let tree = g.merkle_tree(data.as_slice(), 16).unwrap();
        let proof = tree.gen_proof(2);

        assert!(proof.validate::<TreeAlgorithm>());
    }

    #[test]
    fn test_permute() {
        let keys = vec![1, 2, 3, 4];
        let graph = Graph::new(5, Some(Sampling::Bucket(3)));
        let permuted_graph = graph.permute(keys.as_slice());

        assert_eq!(graph.size(), permuted_graph.size());

        // TODO: this is not a great test, but at least we know they were mutated
        assert_ne!(graph, permuted_graph);

        // going back
        let permuted_twice_graph = permuted_graph.permute(keys.as_slice());

        assert_eq!(graph, permuted_twice_graph);
    }

    #[test]
    fn test_merklepath() {
        let g = Graph::new(10, Some(Sampling::Bucket(5)));
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..16 * 10).map(|_| rng.gen()).collect();

        let tree = g.merkle_tree(data.as_slice(), 16).unwrap();
        for i in 0..10 {
            let proof = tree.gen_proof(i);

            assert!(proof.validate::<TreeAlgorithm>());
            let len = proof.lemma().len();
            let mp: MerkleProof = proof.into();

            assert_eq!(mp.len(), len);

            assert!(mp.validate(), "failed to validate valid merkle path");
            let data_slice = &data[i * 16..(i + 1) * 16].to_vec();
            assert!(
                mp.validate_data(&data_slice),
                "failed to validate valid data"
            );
        }
    }
}
