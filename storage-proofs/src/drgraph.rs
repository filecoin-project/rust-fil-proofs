use std::cmp;
use std::marker::PhantomData;

use rand::{ChaChaRng, OsRng, Rng, SeedableRng};
use rayon::prelude::*;
#[cfg(feature = "disk-trees")]
use std::path::Path;
// FIXME: Figure out what to do with all the conditional `use`es.

use crate::error::*;
use crate::hasher::pedersen::PedersenHasher;
use crate::hasher::{Domain, Hasher};
#[cfg(feature = "disk-trees")]
use crate::merkle::DiskMmapStore;
use crate::merkle::MerkleTree;
use crate::parameter_cache::ParameterSetIdentifier;
use crate::util::{data_at_node, NODE_SIZE};
#[cfg(feature = "disk-trees")]
use crate::SP_LOG;
/// The default hasher currently in use.
pub type DefaultTreeHasher = PedersenHasher;

pub const PARALLEL_MERKLE: bool = true;

/// A depth robust graph.
pub trait Graph<H: Hasher>: ::std::fmt::Debug + Clone + PartialEq + Eq {
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
            H::Domain::try_from_bytes(d).unwrap()
        };

        if parallel {
            Ok(MerkleTree::from_par_iter(
                (0..self.size()).into_par_iter().map(f),
            ))
        } else {
            Ok(MerkleTree::new((0..self.size()).map(f)))
        }
    }

    /// Builds a merkle tree based on the given data and stores it in `path`
    /// (if set).
    // FIXME: If the `path` is set to `None` should we still create a temporary
    //  file somewhere? (at the moment we don't)
    // FIXME: Check if the path version should be integrated with the original
    //  (and then we should refactor all the calls to it, leave this for last).
    #[cfg(feature = "disk-trees")]
    fn merkle_tree_path<'a>(
        &self,
        data: &'a [u8],
        path: Option<&Path>,
    ) -> Result<MerkleTree<H::Domain, H::Function>> {
        self.merkle_tree_aux_path(data, PARALLEL_MERKLE, path)
    }

    #[cfg(feature = "disk-trees")]
    fn merkle_tree_aux_path<'a>(
        &self,
        data: &'a [u8],
        parallel: bool,
        path: Option<&Path>,
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
            H::Domain::try_from_bytes(d).unwrap()
        };

        if let Some(path) = path {
            info!(SP_LOG, "creating tree mmap-file"; "path" => &path.to_str());

            let mut disk_mmap = DiskMmapStore::new_with_path(self.size(), path);
            // FIXME: `new_with_path` is using the `from_iter` implementation,
            //  instead the `parallel` flag should be passed also as argument
            //  and decide *there* which code to use (merging this into the
            //  `if` logic below).

            Ok(MerkleTree::from_data_with_store(
                (0..self.size()).map(f),
                &mut disk_mmap,
            ))
        } else if parallel {
            Ok(MerkleTree::from_par_iter(
                (0..self.size()).into_par_iter().map(f),
            ))
        } else {
            Ok(MerkleTree::new((0..self.size()).map(f)))
        }
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
            "drgraph::BucketGraph{{size: {}; degree: {}; hasher: {}}}",
            self.nodes,
            self.base_degree,
            H::name(),
        )
    }
}

impl<H: Hasher> Graph<H> for BucketGraph<H> {
    #[inline]
    fn parents(&self, node: usize, parents: &mut [usize]) {
        let m = self.base_degree;

        match node {
            // Special case for the first node, it self references.
            // Special case for the second node, it references only the first one.
            0 | 1 => {
                // Use the degree of the curren graph (`m`), as parents.len() might be bigger
                // than that (that's the case for ZigZag Graph)
                for parent in parents.iter_mut().take(m) {
                    *parent = 0;
                }
            }
            _ => {
                // seed = self.seed | node
                let mut seed = [0u32; 8];
                seed[0..7].copy_from_slice(&self.seed);
                seed[7] = node as u32;
                let mut rng = ChaChaRng::from_seed(&seed);

                for (k, parent) in parents.iter_mut().take(m).enumerate() {
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
                        *parent = node - 1;
                    } else {
                        assert!(out <= node);
                        *parent = out;
                    }
                }

                // Use the degree of the curren graph (`m`), as parents.len() might be bigger
                // than that (that's the case for ZigZag Graph)
                parents[0..m].sort_unstable();
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

    use crate::drgraph::new_seed;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};

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
    fn graph_bucket_blake2s() {
        graph_bucket::<Blake2sHasher>();
    }

    #[test]
    fn graph_bucket_pedersen() {
        graph_bucket::<PedersenHasher>();
    }

    fn gen_proof<H: Hasher>(parallel: bool) {
        let g = BucketGraph::<H>::new(5, 3, 0, new_seed());
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
