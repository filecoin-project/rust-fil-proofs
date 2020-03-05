use std::cmp;
use std::marker::PhantomData;
use std::path::PathBuf;

use anyhow::ensure;
use generic_array::typenum;
use merkletree::store::StoreConfig;
use rand::{rngs::OsRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use sha2::{Digest, Sha256};

use crate::error::*;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::Hasher;
use crate::merkle::{
    create_lcmerkle_tree, create_merkle_tree, open_lcmerkle_tree, LCMerkleTree, MerkleTree,
};
use crate::parameter_cache::ParameterSetMetadata;
use crate::util::{data_at_node_offset, NODE_SIZE};

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
    fn merkle_tree<'a, U: typenum::Unsigned>(
        &self,
        config: Option<StoreConfig>,
        data: &'a [u8],
    ) -> Result<MerkleTree<H::Domain, H::Function, U>> {
        create_merkle_tree::<H, U>(config, self.size(), data)
    }

    /// Builds a merkle tree based on the given data and level cache
    /// data.
    fn lcmerkle_tree<'a, U: typenum::Unsigned>(
        &self,
        config: StoreConfig,
        data: &'a [u8],
        replica_path: &PathBuf,
    ) -> Result<LCMerkleTree<H::Domain, H::Function, U>> {
        create_lcmerkle_tree::<H, U>(config, self.size(), data, replica_path)
    }

    /// Returns a merkle tree based on the given config, replica and
    /// level cache data.
    fn lcmerkle_open<U: typenum::Unsigned>(
        &self,
        config: StoreConfig,
        replica_path: &PathBuf,
    ) -> Result<LCMerkleTree<H::Domain, H::Function, U>> {
        open_lcmerkle_tree::<H, U>(config, self.size(), replica_path)
    }

    /// Returns the merkle tree depth.
    fn merkle_tree_depth<U: typenum::Unsigned>(&self) -> u64 {
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
        seed: [u8; 28],
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
    merkletree::merkle::get_merkle_tree_height(number_of_leafs, U::to_usize())
}

/// Bucket sampling algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct BucketGraph<H: Hasher> {
    nodes: usize,
    base_degree: usize,
    seed: [u8; 28],
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
        hasher.input(AsRef::<[u8]>::as_ref(id));

        // The hash is about the parents, hence skip if a node doesn't have any parents
        if node != parents[0] as usize {
            for parent in parents.iter() {
                let offset = data_at_node_offset(*parent as usize);
                hasher.input(&base_parents_data[offset..offset + NODE_SIZE]);
            }
        }

        let hash = hasher.result();
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
                // The degree `m` minus 1; the degree without the immediate predecessor node.
                let m_prime = m - 1;

                // seed = self.seed | node
                let mut seed = [0u8; 32];
                seed[..28].copy_from_slice(&self.seed);
                seed[28..].copy_from_slice(&(node as u32).to_le_bytes());
                let mut rng = ChaChaRng::from_seed(seed);

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
                        *parent = (node - 1) as u32;
                    } else {
                        ensure!(
                            out <= node,
                            "Parent node must be smaller than current node."
                        );
                        *parent = out as u32;
                    }
                }

                // Add the immediate predecessor as a parent to ensure unique topological ordering.
                parents[m_prime] = (node - 1) as u32;
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
        seed: [u8; 28],
    ) -> Result<Self> {
        ensure!(expansion_degree == 0, "Expension degree must be zero.");

        Ok(BucketGraph {
            nodes,
            base_degree,
            seed,
            _h: PhantomData,
        })
    }
}

pub fn new_seed() -> [u8; 28] {
    OsRng.gen()
}

#[cfg(test)]
mod tests {
    use super::*;

    use memmap::MmapMut;
    use memmap::MmapOptions;

    use crate::drgraph::new_seed;
    use crate::hasher::{Blake2sHasher, PedersenHasher, PoseidonHasher, Sha256Hasher};

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

        for size in vec![4, 16, 256, 2048] {
            let g = BucketGraph::<H>::new(size, degree, 0, new_seed()).unwrap();

            assert_eq!(g.size(), size, "wrong nodes count");

            let mut parents = vec![0; degree];
            g.parents(0, &mut parents).unwrap();
            assert_eq!(parents, vec![0; degree as usize]);
            parents = vec![0; degree];
            g.parents(1, &mut parents).unwrap();
            assert_eq!(parents, vec![0; degree as usize]);

            for i in 2..size {
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

    fn gen_proof<H: Hasher, U: typenum::Unsigned>(config: Option<StoreConfig>) {
        let leafs = 64;
        let g = BucketGraph::<H>::new(leafs, BASE_DEGREE, 0, new_seed()).unwrap();
        let data = vec![2u8; NODE_SIZE * leafs];

        let mmapped = &mmap_from(&data);
        let tree = g.merkle_tree::<U>(config, mmapped).unwrap();
        let proof = tree.gen_proof(2).unwrap();

        assert!(proof.validate::<H::Function>());
    }

    #[test]
    fn gen_proof_pedersen_binary() {
        gen_proof::<PedersenHasher, typenum::U2>(None);
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
    fn gen_proof_pedersen_quad() {
        gen_proof::<PedersenHasher, typenum::U4>(None);
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
    fn gen_proof_pedersen_oct() {
        gen_proof::<PedersenHasher, typenum::U8>(None);
    }

    #[test]
    fn gen_proof_poseidon_oct() {
        gen_proof::<PoseidonHasher, typenum::U8>(None);
    }
}
