use std::cmp::{max, min};
use std::marker::PhantomData;

use anyhow::ensure;
use generic_array::typenum;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

use crate::crypto::{derive_porep_domain_seed, DRSAMPLE_DST};
use crate::error::*;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Hasher, PoseidonArity};
use crate::parameter_cache::ParameterSetMetadata;
use crate::util::{data_at_node_offset, NODE_SIZE};
use crate::{is_legacy_porep_id, PoRepID};

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

    /// Returns the merkle tree depth.
    fn merkle_tree_depth<U: 'static + PoseidonArity>(&self) -> u64 {
        graph_height::<U>(self.size()) as u64
    }

    /// Returns a sorted list of all parents of this node. The parents may be repeated.
    ///
    /// If a node doesn't have any parents, then this vector needs to return a vector where
    /// the first element is the requested node. This will be used as indicator for nodes
    /// without parents.
    ///
    /// The `parents` parameter is used to store the result. This is done fore performance
    /// reasons, so that the vector can be allocated outside this call.
    fn parents(&self, node: usize, parents: &mut [u32]) -> Result<()>;

    /// Returns the size of the graph (number of nodes).
    fn size(&self) -> usize;

    /// Returns the number of parents of each node in the graph.
    fn degree(&self) -> usize;

    fn new(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
    ) -> Result<Self>;
    fn seed(&self) -> [u8; 28];

    /// Creates the encoding key.
    /// The algorithm for that is `Sha256(id | encodedParentNode1 | encodedParentNode1 | ...)`.
    fn create_key(
        &self,
        id: &H::Domain,
        node: usize,
        parents: &[u32],
        parents_data: &[u8],
        exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key>;
}

pub fn graph_height<U: typenum::Unsigned>(number_of_leafs: usize) -> usize {
    merkletree::merkle::get_merkle_tree_row_count(number_of_leafs, U::to_usize())
}

/// Bucket sampling algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct BucketGraph<H: Hasher> {
    nodes: usize,
    base_degree: usize,
    seed: [u8; 28],
    is_legacy: bool,
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
        (self.nodes * NODE_SIZE) as u64
    }
}

impl<H: Hasher> Graph<H> for BucketGraph<H> {
    type Key = H::Domain;

    fn create_key(
        &self,
        id: &H::Domain,
        node: usize,
        parents: &[u32],
        base_parents_data: &[u8],
        _exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key> {
        let mut hasher = Sha256::new();
        hasher.update(AsRef::<[u8]>::as_ref(id));

        // The hash is about the parents, hence skip if a node doesn't have any parents
        if node != parents[0] as usize {
            for parent in parents.iter() {
                let offset = data_at_node_offset(*parent as usize);
                hasher.update(&base_parents_data[offset..offset + NODE_SIZE]);
            }
        }

        let hash = hasher.finalize();
        Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
    }

    #[inline]
    fn parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
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
                Ok(())
            }
            _ => {
                // DRG node indexes are guaranteed to fit within a `u32`.
                let node = node as u32;

                let mut seed = [0u8; 32];
                seed[..28].copy_from_slice(&self.seed);
                seed[28..].copy_from_slice(&node.to_le_bytes());
                let mut rng = ChaCha8Rng::from_seed(seed);

                let m_prime = m - 1;
                // Large sector sizes require that metagraph node indexes are `u64`.
                let metagraph_node = node as u64 * m_prime as u64;
                let n_buckets = (metagraph_node as f64).log2().ceil() as u64;

                let (predecessor_index, other_drg_parents) = if self.is_legacy {
                    (m_prime, &mut parents[..])
                } else {
                    (0, &mut parents[1..])
                };

                for parent in other_drg_parents.iter_mut().take(m_prime) {
                    let bucket_index = (rng.gen::<u64>() % n_buckets) + 1;
                    let largest_distance_in_bucket = min(metagraph_node, 1 << bucket_index);
                    let smallest_distance_in_bucket = max(2, largest_distance_in_bucket >> 1);

                    // Add 1 becuase the number of distances in the bucket is inclusive.
                    let n_distances_in_bucket =
                        largest_distance_in_bucket - smallest_distance_in_bucket + 1;

                    let distance =
                        smallest_distance_in_bucket + (rng.gen::<u64>() % n_distances_in_bucket);

                    let metagraph_parent = metagraph_node - distance;

                    // Any metagraph node mapped onto the DRG can be safely cast back to `u32`.
                    let mapped_parent = (metagraph_parent / m_prime as u64) as u32;

                    *parent = if mapped_parent == node {
                        node - 1
                    } else {
                        mapped_parent
                    };
                }

                // Immediate predecessor must be the first parent, so hashing cannot begin early.
                parents[predecessor_index] = node - 1;
                Ok(())
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

    fn seed(&self) -> [u8; 28] {
        self.seed
    }

    fn new(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
    ) -> Result<Self> {
        ensure!(expansion_degree == 0, "Expension degree must be zero.");

        // The number of metagraph nodes must be less than `2u64^54` as to not incur rounding errors
        // when casting metagraph node indexes from `u64` to `f64` during parent generation.
        let m_prime = base_degree - 1;
        let n_metagraph_nodes = nodes as u64 * m_prime as u64;
        ensure!(
            n_metagraph_nodes <= 1u64 << 54,
            "The number of metagraph nodes must be precisely castable to `f64`"
        );

        let drg_seed = derive_drg_seed(porep_id);

        Ok(BucketGraph {
            nodes,
            base_degree,
            seed: drg_seed,
            is_legacy: is_legacy_porep_id(porep_id),
            _h: PhantomData,
        })
    }
}

pub fn derive_drg_seed(porep_id: PoRepID) -> [u8; 28] {
    let mut drg_seed = [0; 28];
    let raw_seed = derive_porep_domain_seed(DRSAMPLE_DST, porep_id);
    drg_seed.copy_from_slice(&raw_seed[..28]);
    drg_seed
}

#[cfg(test)]
mod tests {
    use super::*;

    use memmap::MmapMut;
    use memmap::MmapOptions;
    use merkletree::store::StoreConfig;

    use crate::hasher::{Blake2sHasher, PoseidonArity, PoseidonHasher, Sha256Hasher};
    use crate::merkle::{
        create_base_merkle_tree, DiskStore, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper,
    };

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
        // These PoRepIDs do not correspond to the small-sized graphs used in
        // the tests. However, they are sufficient to distinguish legacy vs new
        // behavior of parent ordering.
        let porep_id = |id: u8| {
            let mut porep_id = [0u8; 32];
            porep_id[0] = id;

            porep_id
        };

        let legacy_porep_id = porep_id(0);
        let new_porep_id = porep_id(5);

        graph_bucket_aux::<H>(legacy_porep_id);
        graph_bucket_aux::<H>(new_porep_id);
    }

    fn graph_bucket_aux<H: Hasher>(porep_id: PoRepID) {
        let degree = BASE_DEGREE;

        for &size in &[4, 16, 256, 2048] {
            let g = BucketGraph::<H>::new(size, degree, 0, porep_id).unwrap();

            assert_eq!(g.size(), size, "wrong nodes count");

            let mut parents = vec![0; degree];
            g.parents(0, &mut parents).unwrap();
            assert_eq!(parents, vec![0; degree as usize]);
            parents = vec![0; degree];
            g.parents(1, &mut parents).unwrap();
            assert_eq!(parents, vec![0; degree as usize]);

            for i in 1..size {
                let mut pa1 = vec![0; degree];
                g.parents(i, &mut pa1).unwrap();
                let mut pa2 = vec![0; degree];
                g.parents(i, &mut pa2).unwrap();

                assert_eq!(pa1.len(), degree);
                assert_eq!(pa1, pa2, "different parents on the same node");

                let mut p1 = vec![0; degree];
                g.parents(i, &mut p1).unwrap();
                let mut p2 = vec![0; degree];
                g.parents(i, &mut p2).unwrap();

                for parent in p1 {
                    // TODO: fix me
                    assert_ne!(i, parent as usize, "self reference found");
                }

                if is_legacy_porep_id(porep_id) {
                    assert_eq!(
                        i - 1,
                        pa1[degree - 1] as usize,
                        "immediate predecessor was not last DRG parent"
                    );
                } else {
                    assert_eq!(
                        i - 1,
                        pa1[0] as usize,
                        "immediate predecessor was not first parent"
                    );
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

    fn gen_proof<H: 'static + Hasher, U: 'static + PoseidonArity>(config: Option<StoreConfig>) {
        let leafs = 64;
        let porep_id = [1; 32];
        let g = BucketGraph::<H>::new(leafs, BASE_DEGREE, 0, porep_id).unwrap();
        let data = vec![2u8; NODE_SIZE * leafs];

        let mmapped = &mmap_from(&data);
        let tree = create_base_merkle_tree::<
            MerkleTreeWrapper<H, DiskStore<H::Domain>, U, typenum::U0, typenum::U0>,
        >(config, g.size(), mmapped)
        .unwrap();
        let proof = tree.gen_proof(2).unwrap();

        assert!(proof.verify());
    }

    #[test]
    fn gen_proof_poseidon_binary() {
        gen_proof::<PoseidonHasher, typenum::U2>(None);
    }

    #[test]
    fn gen_proof_sha256_binary() {
        gen_proof::<Sha256Hasher, typenum::U2>(None);
    }

    #[test]
    fn gen_proof_blake2s_binary() {
        gen_proof::<Blake2sHasher, typenum::U2>(None);
    }

    #[test]
    fn gen_proof_poseidon_quad() {
        gen_proof::<PoseidonHasher, typenum::U4>(None);
    }

    #[test]
    fn gen_proof_sha256_quad() {
        gen_proof::<Sha256Hasher, typenum::U4>(None);
    }

    #[test]
    fn gen_proof_blake2s_quad() {
        gen_proof::<Blake2sHasher, typenum::U4>(None);
    }

    #[test]
    fn gen_proof_poseidon_oct() {
        gen_proof::<PoseidonHasher, typenum::U8>(None);
    }
}
