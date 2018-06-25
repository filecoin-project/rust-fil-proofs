#![cfg_attr(feature = "cargo-clippy", allow(len_without_is_empty))]

use crypto::feistel;
use error::Result;
use hasher::pedersen;
use merkle_light::hash::{Algorithm, Hashable};
use merkle_light::{merkle, proof};
use pairing::bls12_381::Fr;
use rand::{thread_rng, Rng};
use std::cmp;
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

    pub fn as_pairs(&self) -> Vec<(Fr, bool)> {
        self.path
            .iter()
            .map(|v| (v.0.into(), v.1))
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

    /// Serialize into bytes.
    /// TODO: probably improve
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        for (hash, is_right) in &self.path {
            out.extend(hash.as_ref());
            out.push(*is_right as u8);
        }
        out.extend(self.leaf().as_ref());
        out.extend(self.root().as_ref());

        out
    }

    pub fn path(&self) -> &Vec<(TreeHash, bool)> {
        &self.path
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
    /// List of predecessors.
    /// For each node the parents are in  `node * degree` to `(node + 1) * degree`.
    /// An entry `v` for node `u`, means there is an edge from `u -> v`.
    pred: Vec<usize>,
    /// The degree of the graph (you can assume it is the _same_ for every node).
    degree: usize,
}

pub enum Sampling {
    DR,
    Bucket(usize),
}

impl Graph {
    /// Creates a new graph. If no sampling is passed, it does not contain any edges.
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn new(nodes: usize, sampling: Sampling) -> Graph {
        // unwrapping the sampling methods, because it would be an implementation error
        // if those fail.
        match sampling {
            Sampling::DR => dr_sample(nodes).unwrap(),
            Sampling::Bucket(m) => bucket_sample(nodes, m).unwrap(),
        }
    }

    pub fn new_empty(nodes: usize, degree: usize) -> Graph {
        Graph {
            nodes,
            pred: vec![0; nodes * degree],
            degree,
        }
    }

    /// Inserts a directed edge from u -> v.
    pub fn add_edge(&mut self, u: usize, v: usize) -> Result<()> {
        self.add_edges(u, &[v])
    }

    /// Inserts directed edges from `u -> v_i` for each element `v_i` in `vs`.
    pub fn add_edges(&mut self, u: usize, vs: &[usize]) -> Result<()> {
        if u > self.nodes || u < 1 {
            return Err(format_err!("u: {} is not a valid node", u));
        }
        for v in vs {
            if *v > self.nodes || *v < 1 {
                return Err(format_err!("v: {} is not a valid node", v));
            }
        }

        let degree = self.degree();

        if vs.len() > degree {
            return Err(format_err!(
                "can not add more edges than the degree of the graph: {} > {}",
                vs.len(),
                degree
            ));
        }

        let start = (u - 1) * degree;
        let end = u * degree;
        let edges = &mut self.pred[start..end];
        let first = match edges.iter().position(|edge| *edge == 0) {
            Some(el) => el,
            None => {
                return Err(format_err!(
                    "can not add anymore edges: {:?} {}",
                    edges,
                    degree
                ))
            }
        };

        edges[first..first + vs.len()].copy_from_slice(vs);

        // sort on insert, so we only ever do it once
        // but need to skip 0s from being sorted in
        edges[0..first + vs.len()].sort();
        Ok(())
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
            return Err(format_err!(
                "missmatch of data, node_size and nodes {} != {} * {}",
                data.len(),
                node_size,
                self.nodes
            ));
        }

        if !(node_size == 16 || node_size == 32 || node_size == 64) {
            return Err(format_err!("invalid node size, must be 16, 32 or 64"));
        }

        Ok(MerkleTree::from_data((0..self.nodes).map(|i| {
            data_at_node(data, i + 1, node_size).expect("data_at_node math failed")
        })))
    }

    /// Returns a sorted list of all parents of this node.
    pub fn parents(&self, node: usize) -> &[usize] {
        let degree = self.degree;
        let start = (node - 1) * degree;
        let end = node * degree;

        let edges = &self.pred[start..end];

        match edges.iter().position(|edge| *edge == 0) {
            Some(el) => &edges[0..el],
            None => edges,
        }
    }

    /// Returns the size of the node.
    pub fn size(&self) -> usize {
        self.nodes
    }

    /// Returns the tree depth.
    pub fn depth(&self) -> u64 {
        (self.size() as f64).log2().ceil() as u64
    }

    /// Returns the degree of the graph.
    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn permute(&self, keys: &[u32]) -> Graph {
        let nodes = self.nodes as u32;
        let mut permuted = Graph::new_empty(self.nodes, self.degree);

        let p: Vec<usize> = (0..self.nodes)
            .map(|i| feistel::permute(nodes, i as u32, keys) as usize + 1)
            .collect();

        for (key, preds) in self.pred.chunks(self.degree).enumerate() {
            let edges: Vec<_> = preds.iter().map(|pred| p[pred - 1]).collect();
            permuted.add_edges(p[key], edges.as_slice()).unwrap();
        }

        permuted
    }

    pub fn invert_permute(&self, keys: &[u32]) -> Graph {
        let nodes = self.nodes as u32;
        let mut permuted = Graph::new_empty(self.nodes, self.degree);

        let p: Vec<usize> = (0..self.nodes)
            .map(|i| feistel::invert_permute(nodes, i as u32, keys) as usize + 1)
            .collect();

        for (key, preds) in self.pred.chunks(self.degree).enumerate() {
            let edges: Vec<_> = preds.iter().map(|pred| p[pred - 1]).collect();
            permuted.add_edges(p[key], edges.as_slice()).unwrap();
        }

        permuted
    }
}

fn dr_sample(n: usize) -> Result<Graph> {
    assert!(n > 1, "graph too small");

    let mut graph = Graph::new_empty(n, 2);

    // TODO: unsuck
    // enforce every node to have two edges
    graph.add_edges(1, &[1, 1])?;
    graph.add_edges(2, &[1, 1])?;

    for v in 3..graph.nodes + 1 {
        graph.add_edges(v, &[v - 1, get_random_parent(v)])?;
    }

    Ok(graph)
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

// TODO: unsuck
fn bucket_sample(n: usize, m: usize) -> Result<Graph> {
    assert!(m > 1, "m must be larger than 1");

    let g_dash = dr_sample(n * m)?;
    let mut g = Graph::new_empty(n, m);

    let size = g_dash.nodes;

    // tmp: special fix for the first node
    g.add_edges(1, &vec![1; m])?;

    // TODO: check wether degree d is with self loops or not.
    for v in 2..size + 1 {
        let u = g_dash.parents(v)[0];

        let i = ((u - 1) / m) + 1;
        let j = ((v - 1) / m) + 1;

        if j != i {
            g.add_edge(j, i)?;
        }
    }

    // tmp fix: pad all parents
    for v in 2..g.nodes + 1 {
        let parents = g.parents(v).to_vec();

        let parents_len = parents.len();
        let el = parents[parents_len - 1];

        if parents.len() < g.degree() {
            g.add_edges(v, &vec![el; m - parents_len])?;
        }
    }

    Ok(g)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{self, Rng};

    #[test]
    fn graph_dr_sampling() {
        for size in 2..12 {
            let g = Graph::new(size, Sampling::DR);
            assert_eq!(g.nodes, size);

            for i in 1..size {
                assert_eq!(g.parents(i).len(), 2);
            }
        }
    }

    #[test]
    fn graph_bucket_sample() {
        for size in vec![3, 10, 200, 2000] {
            for m in 2..12 {
                let g = Graph::new(size, Sampling::Bucket(m));
                assert_eq!(g.nodes, size, "wrong nodes count");

                for i in 1..(size + 1) {
                    let parents = g.parents(i);
                    assert_eq!(parents.len(), m, "wrong number of parents");

                    if i != 1 {
                        for parent in parents {
                            assert_ne!(i, *parent);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn graph_add_edge() {
        let mut g = Graph::new_empty(10, 10);

        g.add_edge(1, 2).unwrap();
        g.add_edge(1, 3).unwrap();

        assert_eq!(g.parents(1).to_vec(), vec![2, 3]);

        assert_eq!(g.parents(2).len(), 0);
        assert_eq!(g.parents(3).len(), 0);

        assert_eq!(g.parents(1).to_vec(), vec![2, 3]);
        assert_eq!(g.parents(2).len(), 0);

        // double insert
        g.add_edge(1, 4).unwrap();
        g.add_edge(1, 4).unwrap();

        assert_eq!(g.parents(1).to_vec(), vec![2, 3, 4, 4]);

        // sorted parents

        g.add_edge(2, 7).unwrap();
        g.add_edge(2, 1).unwrap();

        assert_eq!(g.parents(2).to_vec(), vec![1, 7]);
    }

    #[test]
    fn add_edges() {
        let mut g = Graph::new_empty(3, 0);

        assert_eq!(g.degree(), 0);
        assert!(g.add_edges(1, &[2]).is_err());

        g.degree = 3;
        g.pred = vec![0; g.nodes * 3];
        g.add_edges(1, &[2, 3]).unwrap();
        g.add_edges(1, &[2]).unwrap();

        assert!(g.add_edges(1, &[4]).is_err());
    }

    #[test]
    fn graph_commit() {
        let mut g = Graph::new_empty(3, 10);

        g.add_edge(1, 2).unwrap();
        g.add_edge(1, 3).unwrap();

        let data = vec![1u8; 3 * 16];
        g.commit(data.as_slice(), 16).unwrap();
        // TODO: add assertion
    }

    #[test]
    fn gen_proof() {
        let g = Graph::new(5, Sampling::Bucket(3));
        let data = vec![2u8; 16 * 5];

        let tree = g.merkle_tree(data.as_slice(), 16).unwrap();
        let proof = tree.gen_proof(2);

        assert!(proof.validate::<TreeAlgorithm>());
    }

    #[test]
    fn permute() {
        let keys = vec![1, 2, 3, 4];
        let graph = Graph::new(5, Sampling::Bucket(3));

        let permuted_graph = graph.permute(keys.as_slice());

        assert_eq!(
            graph.size(),
            permuted_graph.size(),
            "graphs are not the same size"
        );

        // TODO: this is not a great test, but at least we know they were mutated
        assert_ne!(graph, permuted_graph, "graph was not permuted");

        // going back
        let permuted_twice_graph = permuted_graph.permute(keys.as_slice());

        assert_eq!(
            graph, permuted_twice_graph,
            "graph was not the same after permuation back"
        );
    }

    #[test]
    fn merklepath() {
        let g = Graph::new(10, Sampling::Bucket(5));
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
