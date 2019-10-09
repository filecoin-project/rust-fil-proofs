use std::cmp;
use std::marker::PhantomData;

use blake2s_simd::Params as Blake2s;
use rand::{ChaChaRng, OsRng, Rng, SeedableRng};
use rayon::prelude::*;

use crate::error::*;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::pedersen::PedersenHasher;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleStore, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::util::{data_at_node, data_at_node_offset, NODE_SIZE};
use merkletree::merkle::FromIndexedParallelIterator;

/// The default hasher currently in use.
pub type DefaultTreeHasher = PedersenHasher;

pub const PARALLEL_MERKLE: bool = true;

/// The base degree used for all DRG graphs. One degree from this value is used to ensure that a
/// given node always has its immediate predecessor as a parent, thus ensuring unique topological
/// ordering of the graph nodes.
pub const BASE_DEGREE: usize = 6;

/// A depth robust graph.
pub trait Graph<H: Hasher>: ::std::fmt::Debug + Clone + PartialEq + Eq {
    type Key: std::fmt::Debug;

    /// Returns the expected size of all nodes in the graph.
    fn expected_size(&self) -> usize {
        self.size() * NODE_SIZE
    }

    /// Builds a merkle tree based on the given data.
    fn merkle_tree<'a>(&self, data: &'a [u8]) -> Result<MerkleTree<H::Domain, H::Function>> {
        self.merkle_tree_aux(data, PARALLEL_MERKLE)
    }

    /// Builds a merkle tree based on the given data.
    fn merkle_tree_aux<'a>(
        &self,
        data: &'a [u8],
        parallel: bool,
    ) -> Result<MerkleTree<H::Domain, H::Function>> {
        if data.len() != (NODE_SIZE * self.size()) as usize {
            return Err(Error::InvalidMerkleTreeArgs(
                data.len(),
                NODE_SIZE,
                self.size(),
            ));
        }

        let f = |i| {
            let d = data_at_node(&data, i).expect("data_at_node math failed");
            // TODO/FIXME: This can panic. FOR NOW, let's leave this since we're experimenting with
            // optimization paths. However, we need to ensure that bad input will not lead to a panic
            // that isn't caught by the FPS API.
            // Unfortunately, it's not clear how to perform this error-handling in the parallel
            // iterator case.
            H::Domain::try_from_bytes(d).expect("failed to convert node data to domain element")
        };

        if parallel {
            Ok(MerkleTree::from_par_iter(
                (0..self.size()).into_par_iter().map(f),
            ))
        } else {
            Ok(MerkleTree::new((0..self.size()).map(f)))
        }
    }

    /// Builds a merkle tree based on the given leaves store.
    // FIXME: Add the parallel case (if it's worth it).
    fn merkle_tree_from_leaves(
        &self,
        leaves: MerkleStore<H::Domain>,
        leafs_number: usize,
    ) -> Result<MerkleTree<H::Domain, H::Function>> {
        Ok(MerkleTree::from_leaves_store(leaves, leafs_number))
    }

    /// Returns the merkle tree depth.
    fn merkle_tree_depth(&self) -> u64 {
        graph_height(self.size()) as u64
    }

    /// Returns a sorted list of all parents of this node. The parents may be repeated.
    ///
    /// If a node doesn't have any parents, then this vector needs to return a vector where
    /// the first element is the requested node. This will be used as indicator for nodes
    /// without parents.
    ///
    /// The `parents` parameter is used to store the result. This is done fore performance
    /// reasons, so that the vector can be allocated outside this call.
    fn parents(&self, node: usize, parents: &mut [usize]);

    /// Returns the size of the graph (number of nodes).
    fn size(&self) -> usize;

    /// Returns the number of parents of each node in the graph.
    fn degree(&self) -> usize;

    fn new(nodes: usize, base_degree: usize, expansion_degree: usize, seed: [u32; 7]) -> Self;
    fn seed(&self) -> [u32; 7];

    /// Creates the encoding key.
    /// The algorithm for that is `Blake2s(id | encodedParentNode1 | encodedParentNode1 | ...)`.
    fn create_key(
        &self,
        id: &H::Domain,
        node: usize,
        parents: &[usize],
        parents_data: &[u8],
        exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key>;
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

impl<H: Hasher> ParameterSetMetadata for BucketGraph<H> {
    fn identifier(&self) -> String {
        // NOTE: Seed is not included because it does not influence parameter generation.
        format!(
            "drgraph::BucketGraph{{size: {}; degree: {}; hasher: {}}}",
            self.nodes,
            self.degree(),
            H::name(),
        )
    }

    fn sector_size(&self) -> u64 {
        (self.nodes * 32) as u64
    }
}

impl<H: Hasher> Graph<H> for BucketGraph<H> {
    type Key = H::Domain;

    fn create_key(
        &self,
        id: &H::Domain,
        node: usize,
        parents: &[usize],
        base_parents_data: &[u8],
        _exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key> {
        let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
        hasher.update(AsRef::<[u8]>::as_ref(id));

        // The hash is about the parents, hence skip if a node doesn't have any parents
        if node != parents[0] {
            for parent in parents.iter() {
                let offset = data_at_node_offset(*parent);
                hasher.update(&base_parents_data[offset..offset + NODE_SIZE]);
            }
        }

        let hash = hasher.finalize();
        Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
    }

    #[inline]
    fn parents(&self, node: usize, parents: &mut [usize]) {
        let m = self.degree();

        match node {
            // There are special cases for the first and second node: the first node self
            // references, the second node only references the first node.
            0 | 1 => {
                // Use the degree of the current graph (`m`) as `parents.len()` might be bigger than
                // that (that's the case for Stacked Graph).
                for parent in parents.iter_mut().take(m) {
                    *parent = 0;
                }
            }
            _ => {
                // The degree `m` minus 1; the degree without the immediate predecessor node.
                let m_prime = m - 1;

                // seed = self.seed | node
                let mut seed = [0u32; 8];
                seed[0..7].copy_from_slice(&self.seed);
                seed[7] = node as u32;
                let mut rng = ChaChaRng::from_seed(&seed);

                for (k, parent) in parents.iter_mut().take(m_prime).enumerate() {
                    // Iterate over `m_prime` number of meta nodes for the i-th real node. Simulate
                    // the edges that we would add from previous graph nodes. If any edge is added
                    // from a meta node of j-th real node then add edge (j,i).
                    let logi = ((node * m_prime) as f32).log2().floor() as usize;
                    let j = rng.gen::<usize>() % logi;
                    let jj = cmp::min(node * m_prime + k, 1 << (j + 1));
                    let back_dist = rng.gen_range(cmp::max(jj >> 1, 2), jj + 1);
                    let out = (node * m_prime + k - back_dist) / m_prime;

                    // remove self references and replace with reference to previous node
                    if out == node {
                        *parent = node - 1;
                    } else {
                        assert!(out <= node);
                        *parent = out;
                    }
                }

                // Add the immediate predecessor as a parent to ensure unique topological ordering.
                parents[m_prime] = node - 1;
            }
        }
    }

    #[inline]
    fn size(&self) -> usize {
        self.nodes
    }

    /// Returns the degree of the graph.
    #[inline]
    fn degree(&self) -> usize {
        self.base_degree
    }

    fn seed(&self) -> [u32; 7] {
        self.seed
    }

    fn new(nodes: usize, base_degree: usize, expansion_degree: usize, seed: [u32; 7]) -> Self {
        if !cfg!(feature = "unchecked-degrees") {
            assert_eq!(base_degree, BASE_DEGREE);
        }

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
    OsRng::new().expect("Failed to create `OsRng`").gen()
}

#[cfg(test)]
mod tests {
    use super::*;

    use memmap::MmapMut;
    use memmap::MmapOptions;

    use crate::drgraph::new_seed;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};

    // Create and return an object of MmapMut backed by in-memory copy of data.
    pub fn mmap_from(data: &[u8]) -> MmapMut {
        let mut mm = MmapOptions::new()
            .len(data.len())
            .map_anon()
            .expect("Failed to create memory map");
        mm.copy_from_slice(data);
        mm
    }

    fn graph_bucket<H: Hasher>() {
        let degree = BASE_DEGREE;

        for size in vec![3, 10, 200, 2000] {
            let g = BucketGraph::<H>::new(size, degree, 0, new_seed());

            assert_eq!(g.size(), size, "wrong nodes count");

            let mut parents = vec![0; degree];
            g.parents(0, &mut parents);
            assert_eq!(parents, vec![0; degree as usize]);
            parents = vec![0; degree];
            g.parents(1, &mut parents);
            assert_eq!(parents, vec![0; degree as usize]);

            for i in 2..size {
                let mut pa1 = vec![0; degree];
                g.parents(i, &mut pa1);
                let mut pa2 = vec![0; degree];
                g.parents(i, &mut pa2);

                assert_eq!(pa1.len(), degree);
                assert_eq!(pa1, pa2, "different parents on the same node");

                let mut p1 = vec![0; degree];
                g.parents(i, &mut p1);
                let mut p2 = vec![0; degree];
                g.parents(i, &mut p2);

                for parent in p1 {
                    // TODO: fix me
                    assert_ne!(i, parent, "self reference found");
                }
            }
        }
    }

    #[test]
    fn graph_bucket_sha256() {
        graph_bucket::<Sha256Hasher>();
    }

    #[test]
    fn graph_bucket_blake2s() {
        graph_bucket::<Blake2sHasher>();
    }

    #[test]
    fn graph_bucket_pedersen() {
        graph_bucket::<PedersenHasher>();
    }

    fn gen_proof<H: Hasher>(parallel: bool) {
        let g = BucketGraph::<H>::new(5, BASE_DEGREE, 0, new_seed());
        let data = vec![2u8; NODE_SIZE * 5];

        let mmapped = &mmap_from(&data);
        let tree = g.merkle_tree_aux(mmapped, parallel).unwrap();
        let proof = tree.gen_proof(2);

        assert!(proof.validate::<H::Function>());
    }

    #[test]
    fn gen_proof_pedersen() {
        gen_proof::<PedersenHasher>(true);
        gen_proof::<PedersenHasher>(false);
    }

    #[test]
    fn gen_proof_sha256() {
        gen_proof::<Sha256Hasher>(true);
        gen_proof::<Sha256Hasher>(false);
    }

    #[test]
    fn gen_proof_blake2s() {
        gen_proof::<Blake2sHasher>(true);
        gen_proof::<Blake2sHasher>(false);
    }
}
