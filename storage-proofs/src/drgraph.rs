use std::cmp;
use std::fmt::Debug;
use std::marker::PhantomData;

use rand::{ChaChaRng, OsRng, Rng, SeedableRng};
use rayon::iter::{FromParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::error::*;
use crate::hasher::blake2s::Blake2sHasher;
use crate::hasher::pedersen::PedersenHasher;
use crate::hasher::{Domain, Hasher};
use crate::hybrid_merkle::HybridMerkleTree;
use crate::merkle::MerkleTree;
use crate::parameter_cache::ParameterSetMetadata;
use crate::util::{data_at_node, NODE_SIZE};

#[cfg(feature = "disk-trees")]
use crate::merkle::DiskMmapStore;
#[cfg(feature = "disk-trees")]
use crate::SP_LOG;
#[cfg(feature = "disk-trees")]
use merkletree::merkle::next_pow2;
#[cfg(feature = "disk-trees")]
use std::path::Path;
#[cfg(feature = "disk-trees")]
use std::path::PathBuf;

// (jake) TODO - remove
/// The default hasher currently in use.
pub type DefaultTreeHasher = PedersenHasher;

pub type DefaultAlphaHasher = PedersenHasher;
pub type DefaultBetaHasher = Blake2sHasher;

pub const PARALLEL_MERKLE: bool = true;

/// A depth robust graph.
pub trait Graph<AH, BH>: Clone + Debug + Eq + PartialEq
where
    AH: Hasher,
    BH: Hasher,
{
    /// Returns the expected size in bytes of all nodes in the graph.
    fn expected_size(&self) -> usize {
        self.size() * NODE_SIZE
    }

    /// Builds a merkle tree based on the given data.
    fn merkle_tree<'a>(&self, data: &'a [u8]) -> Result<MerkleTree<AH::Domain, AH::Function>> {
        self.merkle_tree_aux(data, PARALLEL_MERKLE)
    }

    /// Builds a merkle tree based on the given data.
    fn merkle_tree_aux<'a>(
        &self,
        data: &'a [u8],
        parallel: bool,
    ) -> Result<MerkleTree<AH::Domain, AH::Function>> {
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
            // optimization paths. However, we need to ensure that bad input will not lead to a
            // panic that isn't caught by the FPS API. Unfortunately, it's not clear how to perform
            // this error-handling in the parallel iterator case.
            AH::Domain::try_from_bytes(d).expect("failed to convert node data to domain element")
        };

        if parallel {
            Ok(MerkleTree::from_par_iter(
                (0..self.size()).into_par_iter().map(f),
            ))
        } else {
            Ok(MerkleTree::new((0..self.size()).map(f)))
        }
    }

    /// Builds a merkle tree based on the given data and stores it in `path` (if set).
    #[cfg(feature = "disk-trees")]
    fn merkle_tree_path<'a>(
        &self,
        data: &'a [u8],
        path: Option<&Path>,
    ) -> Result<MerkleTree<AH::Domain, AH::Function>> {
        self.merkle_tree_aux_path(data, PARALLEL_MERKLE, path)
    }

    #[cfg(feature = "disk-trees")]
    fn merkle_tree_aux_path<'a>(
        &self,
        data: &'a [u8],
        parallel: bool,
        path: Option<&Path>,
    ) -> Result<MerkleTree<AH::Domain, AH::Function>> {
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
            // optimization paths. However, we need to ensure that bad input will not lead to a
            // panic that isn't caught by the FPS API. Unfortunately, it's not clear how to perform
            // this error-handling in the parallel iterator case.
            AH::Domain::try_from_bytes(d).expect("failed to convert node data to domain element")
        };

        if let Some(path) = path {
            let path_prefix = path.to_str().expect("couldn't convert path to string");
            let leaves_path = &PathBuf::from([path_prefix, "leaves"].join("-"));
            let top_half_path = &PathBuf::from([path_prefix, "top-half"].join("-"));

            // FIXME: There is probably a more direct way of doing this without reconverting to
            // string.

            info!(SP_LOG, "creating leaves tree mmap-file"; "path-prefix" => leaves_path.to_str());
            info!(SP_LOG, "creating top half tree mmap-file"; "path-prefix" => top_half_path.to_str());

            let leaves_disk_mmap =
                DiskMmapStore::new_with_path(next_pow2(self.size()), leaves_path);
            let top_half_disk_mmap =
                DiskMmapStore::new_with_path(next_pow2(self.size()), top_half_path);

            // FIXME: `new_with_path` is using the `from_iter` implementation, instead the
            // `parallel` flag should be passed also as argument and decide *there* which code to
            // use (merging this into the `if` logic below).

            Ok(MerkleTree::from_data_with_store(
                (0..self.size()).map(f),
                leaves_disk_mmap,
                top_half_disk_mmap,
            ))
        } else if parallel {
            Ok(MerkleTree::from_par_iter(
                (0..self.size()).into_par_iter().map(f),
            ))
        } else {
            Ok(MerkleTree::new((0..self.size()).map(f)))
        }
    }

    /// Builds a Hybrid Merkle Tree based on the given data.
    fn hybrid_merkle_tree<'a>(&self, data: &'a [u8]) -> Result<HybridMerkleTree<AH, BH>> {
        self.hybrid_merkle_tree_aux(data, PARALLEL_MERKLE)
    }

    /// Builds a Hybrid Merkle Tree based on the given data. Optionally constructs the Hybrid
    /// Merkle Tree's leaf trees in parallel if the `parallel` argument is set.
    fn hybrid_merkle_tree_aux<'a>(
        &self,
        data: &'a [u8],
        parallel: bool,
    ) -> Result<HybridMerkleTree<AH, BH>> {
        if data.len() != self.expected_size() {
            return Err(Error::InvalidMerkleTreeArgs(
                data.len(),
                NODE_SIZE,
                self.size(),
            ));
        }

        let leaves = (0..self.size()).map(|i| {
            let d = data_at_node(&data, i).expect("data_at_node math failed");
            // TODO/FIXME: This can panic. FOR NOW, let's leave this since we're experimenting with
            // optimization paths. However, we need to ensure that bad input will not lead to a
            // panic that isn't caught by the FPS API.
            BH::Domain::try_from_bytes(d).expect("failed to convert node data to domain element")
        });

        let tree = if parallel {
            HybridMerkleTree::from_leaves_par(leaves)
        } else {
            HybridMerkleTree::from_leaves(leaves)
        };

        Ok(tree)
    }

    /// Builds a merkle tree based on the given data and stores it in `path` (if set).
    #[cfg(feature = "disk-trees")]
    fn hybrid_merkle_tree_path<'a>(
        &self,
        data: &'a [u8],
        path: Option<&Path>,
    ) -> Result<HybridMerkleTree<AH, BH>> {
        self.hybrid_merkle_tree_aux_path(data, PARALLEL_MERKLE, path)
    }

    #[cfg(feature = "disk-trees")]
    fn hybrid_merkle_tree_aux_path<'a>(
        &self,
        data: &'a [u8],
        parallel: bool,
        path: Option<&Path>,
    ) -> Result<HybridMerkleTree<AH, BH>> {
        if data.len() != self.expected_size() {
            return Err(Error::InvalidMerkleTreeArgs(
                data.len(),
                NODE_SIZE,
                self.size(),
            ));
        }

        let leaves = (0..self.size()).map(|i| {
            let d = data_at_node(&data, i).expect("data_at_node math failed");
            // TODO/FIXME: This can panic. FOR NOW, let's leave this since we're experimenting with
            // optimization paths. However, we need to ensure that bad input will not lead to a
            // panic that isn't caught by the FPS API.
            BH::Domain::try_from_bytes(d).expect("failed to convert node data to domain element")
        });

        let tree = if let Some(path) = path {
            let path_prefix = path.to_str().expect("couldn't convert path to string");
            // FIXME: `DiskMmapStore::new_with_path` is using the `from_iter` implementation,
            // instead the `parallel` flag should be passed also as argument and decide *there*
            // which code to use (merging this into the `if` logic below).
            HybridMerkleTree::from_leaves_with_path(leaves, path_prefix)
        } else if parallel {
            // If path is `None` use the existing code that will eventually call the default
            // `DiskMmapStore::new` creating a temporary file.
            HybridMerkleTree::from_leaves_par(leaves)
        } else {
            HybridMerkleTree::from_leaves(leaves)
        };

        Ok(tree)
    }

    /// Returns the merkle tree depth/height (the number of layers - 1).
    fn merkle_tree_depth(&self) -> u64 {
        graph_height(self.size()) as u64
    }

    /// Returns a sorted list of all parents of this node. The parents may be repeated.
    ///
    /// If a node doesn't have any parents, then this vector needs to return a vector where
    /// the first element is the requested node. This will be used as indicator for nodes
    /// without parents.
    ///
    /// The `parents` parameter is used to store the result. This is done for performance
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
///
/// `BucketGraph` is generic over two type parameters `AH` and `BH` which stand for "Alpha Hasher"
/// and "Beta Hasher" respectively. If the beta hasher `BH` is not specified, its type will default
/// to the alpha hasher's type. This is meant to accomidate the use case where a user only needs to
/// generate a Merkle Tree using the `BucketGraph` (Merkle Tree's use a single hasher) rather than a
/// Hybrid Merkle Tree (which use two hashers).
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct BucketGraph<AH, BH = AH>
where
    AH: Hasher,
    BH: Hasher,
{
    nodes: usize,
    base_degree: usize,
    seed: [u32; 7],
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

impl<AH, BH> ParameterSetMetadata for BucketGraph<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    fn identifier(&self) -> String {
        // NOTE: Seed is not included because it does not influence parameter generation.
        format!(
            "drgraph::BucketGraph{{size: {}; degree: {}; alpha_hasher: {}, beta_hasher: {}}}",
            self.nodes,
            self.base_degree,
            AH::name(),
            BH::name(),
        )
    }

    fn sector_size(&self) -> u64 {
        unimplemented!("required for parameter metadata file generation")
    }
}

impl<AH, BH> Graph<AH, BH> for BucketGraph<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
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
            _ah: PhantomData,
            _bh: PhantomData,
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
    use crate::hybrid_merkle::MIN_N_LEAVES;

    // Create and return an object of MmapMut backed by in-memory copy of data.
    pub fn mmap_from(data: &[u8]) -> MmapMut {
        let mut mm = MmapOptions::new()
            .len(data.len())
            .map_anon()
            .expect("Failed to create memory map");
        mm.copy_from_slice(data);
        mm
    }

    // Checks that a bucket graph is generating correct parents.
    fn test_parents<H>()
    where
        H: Hasher,
    {
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
        test_parents::<Sha256Hasher>();
    }

    #[test]
    fn graph_bucket_blake2s() {
        test_parents::<Blake2sHasher>();
    }

    #[test]
    fn graph_bucket_pedersen() {
        test_parents::<PedersenHasher>();
    }

    fn test_gen_merkle_proof_from_graph<H>(parallel: bool)
    where
        H: Hasher,
    {
        let data = vec![2u8; NODE_SIZE * 5];
        let mmapped = &mmap_from(&data);
        let g = BucketGraph::<H>::new(5, 3, 0, new_seed());
        let tree = g.merkle_tree_aux(mmapped, parallel).unwrap();
        let proof = tree.gen_proof(2);
        assert!(proof.validate::<H::Function>());
    }

    fn test_gen_hybrid_merkle_proof_from_graph<AH, BH>(parallel: bool)
    where
        AH: Hasher,
        BH: Hasher,
    {
        const CHALLENGE_NODE_INDEX: usize = 2;

        let data = vec![2u8; NODE_SIZE * MIN_N_LEAVES];
        let mmapped = &mmap_from(&data);
        let g = BucketGraph::<AH, BH>::new(MIN_N_LEAVES, 3, 0, new_seed());
        let tree = g.hybrid_merkle_tree_aux(mmapped, parallel).unwrap();
        let proof = tree.gen_proof(CHALLENGE_NODE_INDEX);
        assert!(proof.validate(CHALLENGE_NODE_INDEX));
    }

    #[test]
    fn gen_proof_pedersen() {
        test_gen_merkle_proof_from_graph::<PedersenHasher>(true);
        test_gen_merkle_proof_from_graph::<PedersenHasher>(false);
    }

    #[test]
    fn gen_proof_sha256() {
        test_gen_merkle_proof_from_graph::<Sha256Hasher>(true);
        test_gen_merkle_proof_from_graph::<Sha256Hasher>(false);
    }

    #[test]
    fn gen_proof_blake2s() {
        test_gen_merkle_proof_from_graph::<Blake2sHasher>(true);
        test_gen_merkle_proof_from_graph::<Blake2sHasher>(false);
    }

    #[test]
    fn gen_hybrid_proof_pedersen_blake2s() {
        test_gen_hybrid_merkle_proof_from_graph::<PedersenHasher, Blake2sHasher>(true);
        test_gen_hybrid_merkle_proof_from_graph::<PedersenHasher, Blake2sHasher>(false);
    }
}
