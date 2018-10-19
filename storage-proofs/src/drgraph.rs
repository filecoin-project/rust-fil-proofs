use std::cmp;
use std::marker::PhantomData;

use merkle_light::hash::{Algorithm, Hashable};
use rand::{ChaChaRng, OsRng, Rng, SeedableRng};

use error::*;
use hasher::pedersen::PedersenHasher;
use hasher::Hasher;
use merkle::MerkleTree;
use parameter_cache::ParameterSetIdentifier;
use util::data_at_node;

/// The default hasher currently in use.
pub type DefaultTreeHasher = PedersenHasher;

/// A depth robust graph.
pub trait Graph<H: Hasher>: ::std::fmt::Debug + Clone + PartialEq + Eq {
    /// Returns the expected size of all nodes in the graph.
    fn expected_size(&self, node_size: usize) -> usize {
        self.size() * node_size
    }

    /// Builds a merkle tree based on the given data.
    fn merkle_tree<'a>(
        &self,
        data: &'a [u8],
        node_size: usize,
    ) -> Result<MerkleTree<H::Domain, H::Function>> {
        if data.len() != (node_size * self.size()) as usize {
            return Err(Error::InvalidMerkleTreeArgs(
                data.len(),
                node_size,
                self.size(),
            ));
        }

        if !(node_size == 16 || node_size == 32 || node_size == 64) {
            return Err(Error::InvalidNodeSize(node_size));
        }

        let mut a = H::Function::default();
        Ok(MerkleTree::new((0..self.size()).map(|i| {
            let d = data_at_node(&data, i, node_size).expect("data_at_node math failed");
            d.hash(&mut a);
            let h = a.hash();
            a.reset();
            h
        })))
    }

    /// Returns the merkle tree depth.
    fn merkle_tree_depth(&self) -> u64 {
        graph_height(self.size()) as u64
    }

    /// Returns a sorted list of all parents of this node.
    fn parents(&self, node: usize) -> Vec<usize>;

    /// Returns the size of the node.
    fn size(&self) -> usize;

    /// Returns the degree of the graph.
    fn degree(&self) -> usize;

    fn new(nodes: usize, base_degree: usize, expansion_degree: usize, seed: [u32; 7]) -> Self;
    fn seed(&self) -> [u32; 7];

    // Returns true if a node's parents have lower index than the node.
    fn forward(&self) -> bool {
        true
    }
}

pub fn graph_height(size: usize) -> usize {
    (size as f64).log2().ceil() as usize
}

/// Bucket sampling algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct BucketGraph<H: Hasher> {
    nodes: usize,
    base_degree: usize,
    seed: [u32; 7],
    _h: PhantomData<H>,
}

impl<H: Hasher> ParameterSetIdentifier for BucketGraph<H> {
    fn parameter_set_identifier(&self) -> String {
        // NOTE: Seed is not included because it does not influence parameter generation.
        format!(
            "drgraph::BucketGraph{{size: {}; degree: {}}}",
            self.nodes, self.base_degree,
        )
    }
}

impl<H: Hasher> Graph<H> for BucketGraph<H> {
    #[inline]
    fn parents(&self, node: usize) -> Vec<usize> {
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

                parents.sort_unstable();

                parents
            }
        }
    }

    #[inline]
    fn size(&self) -> usize {
        self.nodes
    }

    #[inline]
    fn degree(&self) -> usize {
        self.base_degree
    }

    fn seed(&self) -> [u32; 7] {
        self.seed
    }

    fn new(nodes: usize, base_degree: usize, expansion_degree: usize, seed: [u32; 7]) -> Self {
        assert_eq!(expansion_degree, 0);
        BucketGraph {
            nodes,
            base_degree,
            seed,
            _h: PhantomData,
        }
    }
}

pub fn new_seed() -> [u32; 7] {
    OsRng::new().unwrap().gen()
}

#[cfg(test)]
mod tests {
    use super::*;

    use memmap::MmapMut;
    use memmap::MmapOptions;

    use drgraph::new_seed;
    use hasher::{PedersenHasher, Sha256Hasher};

    // Create and return an object of MmapMut backed by in-memory copy of data.
    pub fn mmap_from(data: &[u8]) -> MmapMut {
        let mut mm = MmapOptions::new().len(data.len()).map_anon().unwrap();
        mm.copy_from_slice(data);
        mm
    }

    fn graph_bucket<H: Hasher>() {
        for size in vec![3, 10, 200, 2000] {
            for degree in 2..12 {
                let g = BucketGraph::<H>::new(size, degree, 0, new_seed());

                assert_eq!(g.size(), size, "wrong nodes count");

                assert_eq!(g.parents(0), vec![0; degree as usize]);
                assert_eq!(g.parents(1), vec![0; degree as usize]);

                for i in 2..size {
                    let pa1 = g.parents(i);
                    let pa2 = g.parents(i);

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
    fn graph_bucket_sha256() {
        graph_bucket::<Sha256Hasher>();
    }

    #[test]
    fn graph_bucket_pedersen() {
        graph_bucket::<PedersenHasher>();
    }

    fn gen_proof<H: Hasher>() {
        let g = BucketGraph::<H>::new(5, 3, 0, new_seed());
        let data = vec![2u8; 16 * 5];

        let mmapped = &mmap_from(&data);
        let tree = g.merkle_tree(mmapped, 16).unwrap();
        let proof = tree.gen_proof(2);

        assert!(proof.validate::<H::Function>());
    }

    #[test]
    fn gen_proof_pedersen() {
        gen_proof::<PedersenHasher>()
    }

    #[test]
    fn gen_proof_sha256() {
        gen_proof::<Sha256Hasher>()
    }
}
