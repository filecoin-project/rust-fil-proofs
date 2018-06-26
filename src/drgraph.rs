#![cfg_attr(feature = "cargo-clippy", allow(len_without_is_empty))]

use crypto::feistel;
use error::Result;
use hasher::pedersen;
use merkle_light::hash::{Algorithm, Hashable};
use merkle_light::{merkle, proof};
use pairing::bls12_381::Fr;
use rand::{ChaChaRng, OsRng, Rng, SeedableRng};
use std::cmp;
use std::collections::HashMap;
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

fn path_index(path: &[(TreeHash, bool)]) -> usize {
    path.iter().rev().fold(0, |acc, (_, is_right)| {
        (acc << 1) + if *is_right { 1 } else { 0 }
    })
}

pub fn hash_leaf(data: &Hashable<TreeAlgorithm>) -> TreeHash {
    let mut a = TreeAlgorithm::default();
    data.hash(&mut a);
    let item_hash = a.hash();
    let leaf_hash = a.leaf(item_hash);

    leaf_hash
}

pub fn hash_node(data: &Hashable<TreeAlgorithm>) -> TreeHash {
    let mut a = TreeAlgorithm::default();
    data.hash(&mut a);
    let item_hash = a.hash();

    item_hash
}

pub fn make_proof_for_test(
    root: TreeHash,
    leaf: TreeHash,
    path: Vec<(TreeHash, bool)>,
) -> MerkleProof {
    MerkleProof {
        path: path,
        root: root,
        leaf: leaf,
    }
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

    /// Validates the MerkleProof and that it corresponds to the supplied node.
    pub fn validate(&self, node: usize) -> bool {
        let mut a = TreeAlgorithm::default();

        if path_index(&self.path) != node {
            return false;
        }

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

    /// Validates that the data hashes to the leaf of the merkle path.
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

/// A depth robust graph.
pub trait Graph: ::std::fmt::Debug + Clone + PartialEq + Eq {
    /// Returns the expected size of all nodes in the graph.
    fn expected_size(&self, node_size: usize) -> usize {
        self.size() * node_size
    }

    /// Returns the commitment hash for the given data.
    fn commit(&self, data: &[u8], node_size: usize) -> Result<TreeHash> {
        let t = self.merkle_tree(data, node_size)?;
        Ok(t.root())
    }

    /// Builds a merkle tree based on the given data.
    fn merkle_tree<'a>(&self, data: &'a [u8], node_size: usize) -> Result<MerkleTree> {
        if data.len() != (node_size * self.size()) as usize {
            return Err(format_err!(
                "missmatch of data, node_size and nodes {} != {} * {}",
                data.len(),
                node_size,
                self.size()
            ));
        }

        if !(node_size == 16 || node_size == 32 || node_size == 64) {
            return Err(format_err!("invalid node size, must be 16, 32 or 64"));
        }

        Ok(MerkleTree::from_data((0..self.size()).map(|i| {
            data_at_node(data, i, node_size).expect("data_at_node math failed")
        })))
    }

    /// Returns the merkle tree depth.
    fn merkle_tree_depth(&self) -> u64 {
        (self.size() as f64).log2().ceil() as u64
    }

    // zigzag returns a new graph with expansion component inverted and a distinct
    // base DRG graph -- with the direction of drg connections reversed. (i.e. from high-to-low nodes).
    // The name is 'weird', but so is the operation -- hence the choice.
    fn zigzag(&self) -> Self {
        unimplemented!();
    }

    /// Returns a sorted list of all parents of this node.
    fn parents(&self, node: usize) -> Vec<usize>;

    /// Returns the size of the node.
    fn size(&self) -> usize;

    /// Returns the degree of the graph.
    fn degree(&self) -> usize;

    /// Constructs a new graph.
    fn new(nodes: usize, degree: usize, expansion_degree: usize) -> Self;
}

pub const DEFAULT_EXPANSION_DEGREE: usize = 8;

/// Bucket sampling algorithm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketGraph {
    nodes: usize,
    base_degree: usize,
    expansion_degree: usize,
    seed: [u32; 7],
    reversed: bool,
}

impl BucketGraph {
    #[inline]
    fn parents_aux(&self, node: usize) -> Vec<usize> {
        let m = self.base_degree;

        match node {
            // Special case for the first node, it self references.
            0 => vec![0; m as usize],
            // Special case for the second node, it references only the first one.
            1 => vec![0; m as usize],
            _ => {
                // seed = self.seed | node
                let mut seed = [0u32; 8];
                seed[0..7].copy_from_slice(&self.seed);
                seed[7] = node as u32;
                let mut rng = ChaChaRng::from_seed(&seed);

                let mut parents: Vec<_> = (0..m)
                    .map(|k| {
                        // iterate over m meta nodes of the ith real node
                        // simulate the edges that we would add from previous graph nodes
                        // if any edge is added from a meta node of jth real node then add edge (j,i)
                        let logi = ((node * m) as f32).log2().floor() as usize;
                        let j = rng.gen::<usize>() % logi;
                        let jj = cmp::min(node * m + k, 1 << (j + 1));
                        let back_dist = rng.gen_range(cmp::max(jj >> 1, 2), jj + 1);
                        let out = (node * m + k - back_dist) / m;

                        // remove self references and replace with reference to previous node
                        if out == node {
                            return node - 1;
                        }

                        assert!(out <= node);

                        out
                    })
                    .collect();
                parents
            }
        }
    }

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
        let b = transformed as usize / self.expansion_degree;

        b
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
                } else {
                    if other < node {
                        Some(other)
                    } else {
                        None
                    }
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

impl Graph for BucketGraph {
    fn new(nodes: usize, base_degree: usize, expansion_degree: usize) -> Self {
        BucketGraph {
            nodes,
            base_degree,
            expansion_degree,
            seed: OsRng::new().unwrap().gen(),
            reversed: false,
        }
    }

    #[inline]
    fn parents(&self, raw_node: usize) -> Vec<usize> {
        // If graph is reversed, use real_index to convert index to reversed index.
        // So we convert a raw reversed node to an unreversed node, calculate its parents,
        // then convert the parents to reversed.

        let drg_parents = self
            .parents_aux(self.real_index(raw_node))
            .iter()
            .map(|i| self.real_index(*i))
            .collect::<Vec<_>>();

        let mut parents = drg_parents;
        // expanded_parents takes raw_node
        let expanded_parents = self.expanded_parents(raw_node);

        parents.extend(expanded_parents.iter());

        // Pad so all nodes have correct degree.
        for _ in 0..(self.degree() - parents.len()) {
            if self.reversed {
                parents.push(self.size() - 1);
            } else {
                parents.push(0);
            }
        }
        assert!(parents.len() == self.degree());
        parents.sort();
        parents
    }

    #[inline]
    fn size(&self) -> usize {
        self.nodes
    }

    #[inline]
    fn degree(&self) -> usize {
        self.base_degree + self.expansion_degree
    }

    // To zigzag a graph, we just toggle its reversed field.
    // All the real work happens when we calculate node parents on-demand.
    fn zigzag(&self) -> Self {
        BucketGraph {
            nodes: self.nodes,
            base_degree: self.base_degree,
            expansion_degree: self.expansion_degree,
            seed: self.seed,
            reversed: !self.reversed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{self, Rng};

    #[test]
    fn graph_bucket() {
        for size in vec![3, 10, 200, 2000] {
            for degree in 2..12 {
                let g = BucketGraph::new(size, degree, DEFAULT_EXPANSION_DEGREE);

                assert_eq!(g.size(), size, "wrong nodes count");

                assert_eq!(g.parents_aux(0), vec![0; degree as usize]);
                assert_eq!(g.parents_aux(1), vec![0; degree as usize]);

                for i in 2..size {
                    let pa1 = g.parents_aux(i);
                    let pa2 = g.parents_aux(i);

                    assert_eq!(pa1.len(), degree);
                    assert_eq!(pa1, pa2, "different parents on the same node");

                    let p1 = g.parents(i);
                    let p2 = g.parents(i);

                    for parent in p1 {
                        // TODO: fix me
                        assert_ne!(i, parent, "self reference found");
                    }

                    let mut p1 = p2.clone();
                    p1.sort();
                    assert_eq!(p1, p2, "not sorted");
                }
            }
        }
    }

    #[test]
    fn graph_commit() {
        let g = BucketGraph::new(3, 10, DEFAULT_EXPANSION_DEGREE);

        let data = vec![1u8; 3 * 16];
        g.commit(data.as_slice(), 16).unwrap();
        // TODO: add assertion
    }

    #[test]
    fn gen_proof() {
        let g = BucketGraph::new(5, 3, DEFAULT_EXPANSION_DEGREE);
        let data = vec![2u8; 16 * 5];

        let tree = g.merkle_tree(data.as_slice(), 16).unwrap();
        let proof = tree.gen_proof(2);

        assert!(proof.validate::<TreeAlgorithm>());
    }

    #[test]
    fn merklepath() {
        let g = BucketGraph::new(10, 5, DEFAULT_EXPANSION_DEGREE);
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..16 * 10).map(|_| rng.gen()).collect();

        let tree = g.merkle_tree(data.as_slice(), 16).unwrap();
        for i in 0..10 {
            let proof = tree.gen_proof(i);

            assert!(proof.validate::<TreeAlgorithm>());
            let len = proof.lemma().len();
            let mp: MerkleProof = proof.into();

            assert_eq!(mp.len(), len);

            assert!(mp.validate(i), "failed to validate valid merkle path");
            let data_slice = &data[i * 16..(i + 1) * 16].to_vec();
            assert!(
                mp.validate_data(&data_slice),
                "failed to validate valid data"
            );
        }
    }

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
    fn bucketgraph_zigzags() {
        let g = BucketGraph::new(50, 5, 8);
        let gz = g.zigzag();

        assert_graph_ascending(g);
        assert_graph_descending(gz);
    }

    #[test]
    fn expansion() {
        // We need a graph.
        let g = BucketGraph::new(25, 5, 8);

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
