use std::iter;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};

use merkletree::hash::Algorithm;
#[cfg(feature = "disk-trees")]
use merkletree::merkle::DiskMmapStore;
#[cfg(not(feature = "disk-trees"))]
use merkletree::merkle::MmapStore;
use merkletree::merkle::{Element, Store};
use paired::bls12_381::Fr;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSlice;

use crate::hasher::hybrid::HybridDomain;
use crate::hasher::{Domain, Hasher};

#[cfg(feature = "disk-trees")]
type HybridStore<AD, BD> = DiskMmapStore<HybridDomain<AD, BD>>;

#[cfg(not(feature = "disk-trees"))]
type HybridStore<AD, BD> = MmapStore<HybridDomain<AD, BD>>;

const SMALL_TREE_BUILD: usize = 1024;

const N_NODES_PER_CHUNK: usize = 1024;

const N_CHILDREN_PER_FULL_CHUNK: usize = N_NODES_PER_CHUNK / 2;

/// Returns `true` is `node_index` is the left input to a Merkle hash; all even node indices are
/// left inputs.
#[inline(always)]
fn is_left_input(node_index: usize) -> bool {
    node_index & 1 == 0
}

#[inline(always)]
fn is_right_input(node_index: usize) -> bool {
    node_index & 1 == 1
}

/// Returns `node_index`'s Merkle hash partner's node index (the node that `node_index` is paired
/// with during Merkle hashing).
#[inline(always)]
fn get_sibling(node_index: usize) -> usize {
    if is_left_input(node_index) {
        node_index + 1
    } else {
        node_index - 1
    }
}

#[derive(Clone, Debug)]
pub struct HybridMerkleTree<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    n_leaves: usize,
    height: usize,
    beta_height: usize,
    n_beta_nodes: usize,
    leaves_store: HybridStore<AH::Domain, BH::Domain>,
    top_half_store: HybridStore<AH::Domain, BH::Domain>,
    root: HybridDomain<AH::Domain, BH::Domain>,
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

impl<AH, BH> HybridMerkleTree<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    pub fn from_leaves<I>(leaves: I, beta_height: usize) -> Self
    where
        I: IntoIterator<Item = HybridDomain<AH::Domain, BH::Domain>>,
    {
        let leaves = leaves.into_iter();
        let n_leaves = leaves
            .size_hint()
            .1
            .expect("non-deterministically sized leaves iterator");

        assert!(n_leaves > 1);
        assert!(n_leaves.is_power_of_two());

        let mut leaves_store = HybridStore::new(n_leaves);
        let top_half_store = HybridStore::new(n_leaves);

        let tree_is_alpha = beta_height == 0;

        for leaf in leaves {
            if tree_is_alpha {
                assert!(leaf.is_alpha());
            } else {
                assert!(leaf.is_beta());
            }
            leaves_store.push(leaf);
        }

        let n_beta_nodes = (0..beta_height).fold(0, |mut acc, layer_index| {
            let n_nodes_in_layer = n_leaves >> layer_index;
            acc += n_nodes_in_layer;
            acc
        });

        HybridMerkleTree::build(
            leaves_store,
            top_half_store,
            n_leaves,
            beta_height,
            n_beta_nodes,
        )
    }

    #[cfg(feature = "disk-trees")]
    pub fn from_leaves_with_store<I>(
        leaves: I,
        beta_height: usize,
        mut leaves_store: HybridStore<AH::Domain, BH::Domain>,
        top_half_store: HybridStore<AH::Domain, BH::Domain>,
    ) -> Self
    where
        I: IntoIterator<Item = HybridDomain<AH::Domain, BH::Domain>>,
    {
        let leaves = leaves.into_iter();
        let n_leaves = leaves
            .size_hint()
            .1
            .expect("non-deterministically sized leaves iterator");

        assert!(n_leaves > 1);
        assert!(n_leaves.is_power_of_two());

        let tree_is_alpha = beta_height == 0;

        for leaf in leaves {
            if tree_is_alpha {
                assert!(leaf.is_alpha());
            } else {
                assert!(leaf.is_beta());
            }
            leaves_store.push(leaf);
        }

        let n_beta_nodes = (0..beta_height).fold(0, |mut acc, layer_index| {
            let n_nodes_in_layer = n_leaves >> layer_index;
            acc += n_nodes_in_layer;
            acc
        });

        HybridMerkleTree::build(
            leaves_store,
            top_half_store,
            n_leaves,
            beta_height,
            n_beta_nodes,
        )
    }

    pub fn from_leaves_par_iter<I>(leaves: I, beta_height: usize) -> Self
    where
        I: IntoParallelIterator<Item = HybridDomain<AH::Domain, BH::Domain>>,
    {
        // Hybrid Merkle Trees do not re-hash the leaves; we assume the user has passed in the
        // correct leaf nodes.
        let leaves: Vec<HybridDomain<AH::Domain, BH::Domain>> = leaves.into_par_iter().collect();
        let n_leaves = leaves.len();

        assert!(n_leaves > 1);
        assert!(n_leaves.is_power_of_two());

        let mut leaves_store = HybridStore::new(n_leaves);
        let top_half_store = HybridStore::new(n_leaves);

        let tree_is_alpha = beta_height == 0;

        for leaf in leaves {
            if tree_is_alpha {
                assert!(leaf.is_alpha());
            } else {
                assert!(leaf.is_beta());
            }
            leaves_store.push(leaf);
        }

        let n_beta_nodes = (0..beta_height).fold(0, |mut acc, layer_index| {
            let n_nodes_in_layer = n_leaves >> layer_index;
            acc += n_nodes_in_layer;
            acc
        });

        HybridMerkleTree::build(
            leaves_store,
            top_half_store,
            n_leaves,
            beta_height,
            n_beta_nodes,
        )
    }

    pub fn from_leaf_preimages<'a, I>(preimages: I, beta_height: usize) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let preimages = preimages.into_iter();

        let n_leaves = preimages
            .size_hint()
            .1
            .expect("non-deterministically sized preimages iterator");

        assert!(n_leaves > 1);
        assert!(n_leaves.is_power_of_two());

        let mut leaves_store = HybridStore::new(n_leaves);
        let top_half_store = HybridStore::new(n_leaves);

        let tree_is_alpha = beta_height == 0;

        for leaf_preimage in preimages {
            let leaf = if tree_is_alpha {
                AH::Domain::try_from_bytes(leaf_preimage)
                    .map(HybridDomain::Alpha)
                    .expect("failed to create alpha domain from leaf preimage")
            } else {
                BH::Domain::try_from_bytes(leaf_preimage)
                    .map(HybridDomain::Beta)
                    .expect("failed to create beta domain from leaf preimage")
            };
            leaves_store.push(leaf);
        }

        let n_beta_nodes = (0..beta_height).fold(0, |mut acc, layer_index| {
            let n_nodes_in_layer = n_leaves >> layer_index;
            acc += n_nodes_in_layer;
            acc
        });

        HybridMerkleTree::build(
            leaves_store,
            top_half_store,
            n_leaves,
            beta_height,
            n_beta_nodes,
        )
    }

    fn build(
        leaves_store: HybridStore<AH::Domain, BH::Domain>,
        top_half_store: HybridStore<AH::Domain, BH::Domain>,
        n_leaves: usize,
        beta_height: usize,
        n_beta_nodes: usize,
    ) -> Self {
        if n_leaves <= SMALL_TREE_BUILD {
            return Self::build_small_tree(
                leaves_store,
                top_half_store,
                n_leaves,
                beta_height,
                n_beta_nodes,
            );
        }

        let height = (n_leaves as f32).log2() as usize;
        let n_layers = height + 1;
        let n_bytes_per_node = HybridDomain::<AH::Domain, BH::Domain>::byte_len();

        let leaves_store = Arc::new(RwLock::new(leaves_store));
        let top_half_store = Arc::new(RwLock::new(top_half_store));

        let layer_index = 0;
        let next_layer_is_seam = beta_height == 1;

        // If the number of nodes in the leaves layer is not divisible by `N_NODES_PER_CHUNK` then
        // set `partial_last_chunk` to `true`.
        let (n_chunks, partial_last_chunk) = {
            let n_chunks = n_leaves as f32 / N_NODES_PER_CHUNK as f32;
            let partial_last_chunk = n_chunks.fract() != 0.0;
            let n_chunks = n_chunks.ceil() as usize;
            (n_chunks, partial_last_chunk)
        };

        (0..n_chunks).into_par_iter().for_each(|chunk_index| {
            let is_last_chunk = chunk_index == n_chunks - 1;

            // If the number of nodes in the layer being read is not divisible by
            // `N_NODES_PER_CHUNK` then the last chunk will have fewer nodes than
            // `N_NODES_PER_CHUNK`.
            let n_nodes_in_chunk = if is_last_chunk && partial_last_chunk {
                n_leaves % N_NODES_PER_CHUNK
            } else {
                N_NODES_PER_CHUNK
            };

            let read_start = chunk_index * N_NODES_PER_CHUNK;
            let read_stop = read_start + n_nodes_in_chunk;
            let write_start = chunk_index * N_CHILDREN_PER_FULL_CHUNK;

            let nodes = leaves_store
                .read()
                .unwrap()
                .read_range(read_start..read_stop);

            let n_children = n_nodes_in_chunk / 2;
            let n_children_bytes = n_children * n_bytes_per_node;
            let mut children_bytes = Vec::<u8>::with_capacity(n_children_bytes);

            for pair in nodes.chunks(2) {
                let child = if next_layer_is_seam {
                    // `Store.read_range()` always returns `HybridDomain::Alpha`s (because it
                    // call `HybridDomain::from_slice` under the hood) so we must convert the
                    // alphas to betas before passing them into the beta hasher.
                    let left_beta = *pair[0].into_beta().beta_value();
                    let right_beta = *pair[1].into_beta().beta_value();
                    let child_beta =
                        BH::Function::default().node(left_beta, right_beta, layer_index);
                    let child_alpha = AH::Domain::from_slice(child_beta.as_ref());
                    HybridDomain::Alpha(child_alpha)
                } else if layer_index < beta_height {
                    // `Store.read_range()` always returns `HybridDomain::Alpha`s (because it
                    // call `HybridDomain::from_slice` under the hood) so we must convert the
                    // alphas to betas before passing them into the beta hasher.
                    let left_beta = *pair[0].into_beta().beta_value();
                    let right_beta = *pair[1].into_beta().beta_value();
                    let child_beta =
                        BH::Function::default().node(left_beta, right_beta, layer_index);
                    HybridDomain::Beta(child_beta)
                } else {
                    let left_alpha = *pair[0].alpha_value();
                    let right_alpha = *pair[1].alpha_value();
                    let child_alpha =
                        AH::Function::default().node(left_alpha, right_alpha, layer_index);
                    HybridDomain::Alpha(child_alpha)
                };

                children_bytes.extend_from_slice(child.as_ref());
            }

            top_half_store
                .write()
                .unwrap()
                .copy_from_slice(&children_bytes, write_start);
        });

        for layer_index in 1..n_layers - 1 {
            let n_nodes_in_layer = n_leaves >> layer_index;
            let n_nodes_written_in_top_half = top_half_store.read().unwrap().len();
            let next_layer_is_seam = layer_index + 1 == beta_height;

            let (n_chunks, partial_last_chunk) = {
                let n_chunks = n_nodes_in_layer as f32 / N_NODES_PER_CHUNK as f32;
                let partial_last_chunk = n_chunks.fract() != 0.0;
                let n_chunks = n_chunks.ceil() as usize;
                (n_chunks, partial_last_chunk)
            };

            (0..n_chunks).into_par_iter().for_each(|chunk_index| {
                let is_last_chunk = chunk_index == n_chunks - 1;

                let n_nodes_in_chunk = if is_last_chunk && partial_last_chunk {
                    n_nodes_in_layer % N_NODES_PER_CHUNK
                } else {
                    N_NODES_PER_CHUNK
                };

                let read_start = {
                    let read_start_layer = n_nodes_written_in_top_half - n_nodes_in_layer;
                    read_start_layer + chunk_index * N_NODES_PER_CHUNK
                };

                let read_stop = read_start + n_nodes_in_chunk;

                let write_start =
                    n_nodes_written_in_top_half + chunk_index * N_CHILDREN_PER_FULL_CHUNK;

                let nodes = top_half_store
                    .read()
                    .unwrap()
                    .read_range(read_start..read_stop);

                let n_children = n_nodes_in_chunk / 2;
                let n_children_bytes = n_children * n_bytes_per_node;
                let mut children_bytes = Vec::<u8>::with_capacity(n_children_bytes);

                for pair in nodes.chunks(2) {
                    let child = if next_layer_is_seam {
                        // `Store.read_range()` always returns `HybridDomain::Alpha`s (because
                        // it call `HybridDomain::from_slice` under the hood) so we must convert
                        // the alphas to betas before passing them into the beta hasher.
                        let left_beta = *pair[0].into_beta().beta_value();
                        let right_beta = *pair[1].into_beta().beta_value();
                        let child_beta =
                            BH::Function::default().node(left_beta, right_beta, layer_index);
                        let child_alpha = AH::Domain::from_slice(child_beta.as_ref());
                        HybridDomain::Alpha(child_alpha)
                    } else if layer_index < beta_height {
                        // `Store.read_range()` always returns `HybridDomain::Alpha`s (because
                        // it call `HybridDomain::from_slice` under the hood) so we must convert
                        // the alphas to betas before passing them into the beta hasher.
                        let left_beta = *pair[0].into_beta().beta_value();
                        let right_beta = *pair[1].into_beta().beta_value();
                        let child_beta =
                            BH::Function::default().node(left_beta, right_beta, layer_index);
                        HybridDomain::Beta(child_beta)
                    } else {
                        let left_alpha = *pair[0].alpha_value();
                        let right_alpha = *pair[1].alpha_value();
                        let child_alpha =
                            AH::Function::default().node(left_alpha, right_alpha, layer_index);
                        HybridDomain::Alpha(child_alpha)
                    };

                    children_bytes.extend_from_slice(child.as_ref());
                }

                top_half_store
                    .write()
                    .unwrap()
                    .copy_from_slice(&children_bytes, write_start);
            });
        }

        let leaves_store = Arc::try_unwrap(leaves_store).unwrap().into_inner().unwrap();

        let top_half_store = Arc::try_unwrap(top_half_store)
            .unwrap()
            .into_inner()
            .unwrap();

        // `Store.read_at()` always returns `HybridDomain::Alpha`, if necessary convert it to
        // `HybridDomain::Beta`.
        let root = {
            let read_at = top_half_store.len() - 1;
            let root_alpha = top_half_store.read_at(read_at);

            if beta_height > height {
                root_alpha.into_beta()
            } else {
                root_alpha
            }
        };

        HybridMerkleTree {
            n_leaves,
            height,
            beta_height,
            n_beta_nodes,
            leaves_store,
            top_half_store,
            root,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    fn build_small_tree(
        leaves_store: HybridStore<AH::Domain, BH::Domain>,
        mut top_half_store: HybridStore<AH::Domain, BH::Domain>,
        n_leaves: usize,
        beta_height: usize,
        n_beta_nodes: usize,
    ) -> Self {
        let height = (n_leaves as f32).log2() as usize;
        let n_layers = height + 1;

        let layer_index = 0;
        let second_layer_is_seam = beta_height == 1;

        let second_layer: Vec<HybridDomain<AH::Domain, BH::Domain>> = leaves_store
            .read_range(0..n_leaves)
            .par_chunks(2)
            .map(|pair| {
                if second_layer_is_seam {
                    // `Store.read_range()` always returns `HybridDomain::Alpha`s (because it call
                    // `HybridDomain::from_slice` under the hood) so we must convert the alphas to
                    // betas before passing them into the beta hasher.
                    let left_beta = *pair[0].into_beta().beta_value();
                    let right_beta = *pair[1].into_beta().beta_value();
                    let child_beta =
                        BH::Function::default().node(left_beta, right_beta, layer_index);
                    let child_alpha = AH::Domain::from_slice(child_beta.as_ref());
                    HybridDomain::Alpha(child_alpha)
                } else if layer_index < beta_height {
                    // `Store.read_range()` always returns `HybridDomain::Alpha`s (because it call
                    // `HybridDomain::from_slice` under the hood) so we must convert the alphas to
                    // betas before passing them into the beta hasher.
                    let left_beta = *pair[0].into_beta().beta_value();
                    let right_beta = *pair[1].into_beta().beta_value();
                    let child_beta =
                        BH::Function::default().node(left_beta, right_beta, layer_index);
                    HybridDomain::Beta(child_beta)
                } else {
                    let left_alpha = *pair[0].alpha_value();
                    let right_alpha = *pair[1].alpha_value();
                    let child_alpha =
                        AH::Function::default().node(left_alpha, right_alpha, layer_index);
                    HybridDomain::Alpha(child_alpha)
                }
            })
            .collect();

        for (i, node) in second_layer.into_iter().enumerate() {
            top_half_store.write_at(node, i);
        }

        for layer_index in 1..n_layers - 1 {
            let n_nodes_written_in_top_half = top_half_store.len();
            let n_nodes_in_layer = n_leaves >> layer_index;

            let read_start = n_nodes_written_in_top_half - n_nodes_in_layer;
            let read_stop = n_nodes_written_in_top_half;
            let write_start = n_nodes_written_in_top_half;

            let next_layer_is_seam = layer_index + 1 == beta_height;

            let next_layer: Vec<HybridDomain<AH::Domain, BH::Domain>> = top_half_store
                .read_range(read_start..read_stop)
                .par_chunks(2)
                .map(|pair| {
                    if next_layer_is_seam {
                        // `Store.read_range()` always returns `HybridDomain::Alpha`s (because it
                        // call `HybridDomain::from_slice` under the hood) so we must convert the
                        // alphas to betas before passing them into the beta hasher.
                        let left_beta = *pair[0].into_beta().beta_value();
                        let right_beta = *pair[1].into_beta().beta_value();
                        let child_beta =
                            BH::Function::default().node(left_beta, right_beta, layer_index);
                        let child_alpha = AH::Domain::from_slice(child_beta.as_ref());
                        HybridDomain::Alpha(child_alpha)
                    } else if layer_index < beta_height {
                        // `Store.read_range()` always returns `HybridDomain::Alpha`s (because it
                        // call `HybridDomain::from_slice` under the hood) so we must convert the
                        // alphas to betas before passing them into the beta hasher.
                        let left_beta = *pair[0].into_beta().beta_value();
                        let right_beta = *pair[1].into_beta().beta_value();
                        let child_beta =
                            BH::Function::default().node(left_beta, right_beta, layer_index);
                        HybridDomain::Beta(child_beta)
                    } else {
                        let left_alpha = *pair[0].alpha_value();
                        let right_alpha = *pair[1].alpha_value();
                        let child_alpha =
                            AH::Function::default().node(left_alpha, right_alpha, layer_index);
                        HybridDomain::Alpha(child_alpha)
                    }
                })
                .collect();

            for (i, node) in next_layer.into_iter().enumerate() {
                top_half_store.write_at(node, write_start + i);
            }
        }

        // `Store.read_at()` always returns `HybridDomain::Alpha`, if necessary convert it to
        // `HybridDomain::Beta`.
        let root = {
            let read_at = top_half_store.len() - 1;
            let root_alpha = top_half_store.read_at(read_at);

            if beta_height > height {
                root_alpha.into_beta()
            } else {
                root_alpha
            }
        };

        HybridMerkleTree {
            n_leaves,
            height,
            beta_height,
            n_beta_nodes,
            leaves_store,
            top_half_store,
            root,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    pub fn read_at(&self, node_index: usize) -> HybridDomain<AH::Domain, BH::Domain> {
        // Calling `Store.read_at()` always returns an `HybridDomain::Alpha`.
        let alpha_node = if self.is_leaf(node_index) {
            self.leaves_store.read_at(node_index)
        } else {
            self.top_half_store.read_at(node_index - self.n_leaves)
        };

        let convert_to_beta = node_index < self.n_beta_nodes;

        if convert_to_beta {
            alpha_node.into_beta()
        } else {
            alpha_node
        }
    }

    pub fn read_into(&self, node_index: usize, dest: &mut [u8]) {
        // `self.read_at()` returns the correct variant of `HybridDomain` (unlike
        // `Store::read_at()`) so no `HybridDomain` variant conversion is necessary.
        self.read_at(node_index).copy_to_slice(dest)
    }

    pub fn gen_proof(&self, challenge_index: usize) -> HybridMerkleProof<AH, BH> {
        assert!(self.is_leaf(challenge_index));

        let challenge_value = self.read_at(challenge_index);

        let path_len = self.height;
        let mut path = Vec::with_capacity(path_len);

        let first_sibling_index = get_sibling(challenge_index);
        let first_sibling_value = self.read_at(first_sibling_index);
        let first_sibling_is_left = is_left_input(first_sibling_index);
        path.push((first_sibling_value, first_sibling_is_left));

        let mut first_node_in_next_layer = self.n_leaves;
        let mut child_index = first_node_in_next_layer + challenge_index / 2;

        for layer_index in 1..path_len {
            let curr_index = child_index;
            let sibling_index = get_sibling(curr_index);
            let sibling_value = self.read_at(sibling_index);
            let sibling_is_left = is_left_input(sibling_index);
            path.push((sibling_value, sibling_is_left));

            let n_nodes_in_layer = self.n_leaves >> layer_index;
            let index_in_layer = curr_index % n_nodes_in_layer;
            first_node_in_next_layer += n_nodes_in_layer;
            child_index = first_node_in_next_layer + index_in_layer / 2;
        }

        HybridMerkleProof {
            challenge_value,
            path,
            root: self.root,
            beta_height: self.beta_height,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    pub fn try_offload_store(&self) -> bool {
        self.leaves_store.try_offload() && self.top_half_store.try_offload()
    }

    #[inline]
    pub fn root(&self) -> HybridDomain<AH::Domain, BH::Domain> {
        self.root
    }

    #[inline]
    pub fn height(&self) -> usize {
        self.height
    }

    #[inline]
    pub fn beta_height(&self) -> usize {
        self.beta_height
    }

    #[inline]
    pub fn n_nodes(&self) -> usize {
        self.leaves_store.len() + self.top_half_store.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.n_nodes()
    }

    #[inline]
    pub fn n_leaves(&self) -> usize {
        self.n_leaves
    }

    #[inline]
    pub fn leafs(&self) -> usize {
        self.n_leaves
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.leaves_store.is_empty() && self.top_half_store.is_empty()
    }

    /// Returns whether or not the node at `node_index` is a leaf in the tree.
    #[inline]
    fn is_leaf(&self, node_index: usize) -> bool {
        node_index < self.n_leaves
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HybridMerkleProof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    challenge_value: HybridDomain<AH::Domain, BH::Domain>,
    #[allow(clippy::type_complexity)]
    path: Vec<(HybridDomain<AH::Domain, BH::Domain>, bool)>,
    root: HybridDomain<AH::Domain, BH::Domain>,
    beta_height: usize,

    #[serde(skip)]
    _ah: PhantomData<AH>,

    #[serde(skip)]
    _bh: PhantomData<BH>,
}

impl<AH, BH> HybridMerkleProof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    // Used in tests. Equivalent to `crate::merkle::make_proof_for_test`.
    #[allow(clippy::type_complexity)]
    pub fn new(
        challenge_value: HybridDomain<AH::Domain, BH::Domain>,
        path: Vec<(HybridDomain<AH::Domain, BH::Domain>, bool)>,
        root: HybridDomain<AH::Domain, BH::Domain>,
        beta_height: usize,
    ) -> Self {
        HybridMerkleProof {
            challenge_value,
            path,
            root,
            beta_height,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    pub fn new_empty(height: usize) -> Self {
        let path = vec![(HybridDomain::default(), false); height];
        HybridMerkleProof {
            path,
            ..Default::default()
        }
    }

    /// Given the challenge's node index, returns whether or not the "is_left" bits in the proof's
    /// path are correct.
    fn left_bits_match_challenge(&self, challenge_index: usize) -> bool {
        let mut index_in_layer = challenge_index;

        for (_, path_elem_is_left) in self.path.iter() {
            if is_right_input(index_in_layer) != *path_elem_is_left {
                return false;
            }
            index_in_layer >>= 1;
        }

        true
    }

    /// Checks if the path in this proof corresponds to the challenge leaf `challenge_index` and
    /// checks that reconstructing the path results in the this proof's root.
    pub fn validate(&self, challenge_index: usize) -> bool {
        if !self.left_bits_match_challenge(challenge_index) {
            return false;
        }

        let layer_index = 0;
        let (sibling, sibling_is_left) = self.path[0];

        let (left, right) = if sibling_is_left {
            (sibling, self.challenge_value)
        } else {
            (self.challenge_value, sibling)
        };

        let mut child = if self.beta_height == 0 {
            let left_alpha = *left.alpha_value();
            let right_alpha = *right.alpha_value();
            let child_alpha = AH::Function::default().node(left_alpha, right_alpha, layer_index);
            HybridDomain::Alpha(child_alpha)
        } else if self.beta_height == 1 {
            let left_beta = *left.beta_value();
            let right_beta = *right.beta_value();
            let child_beta = BH::Function::default().node(left_beta, right_beta, layer_index);
            let child_alpha = AH::Domain::from_slice(child_beta.as_ref());
            HybridDomain::Alpha(child_alpha)
        } else {
            let left_beta = *left.beta_value();
            let right_beta = *right.beta_value();
            let child_beta = BH::Function::default().node(left_beta, right_beta, layer_index);
            HybridDomain::Beta(child_beta)
        };

        for (layer_index, (sibling, sibling_is_left)) in self.path.iter().enumerate().skip(1) {
            let (left, right) = if *sibling_is_left {
                (sibling, &child)
            } else {
                (&child, sibling)
            };

            let next_layer_is_seam = self.beta_height == layer_index + 1;

            child = if next_layer_is_seam {
                let left_beta = *left.beta_value();
                let right_beta = *right.beta_value();
                let child_beta = BH::Function::default().node(left_beta, right_beta, layer_index);
                let child_alpha = AH::Domain::from_slice(child_beta.as_ref());
                HybridDomain::Alpha(child_alpha)
            } else if layer_index < self.beta_height {
                let left_beta = *left.beta_value();
                let right_beta = *right.beta_value();
                let child_beta = BH::Function::default().node(left_beta, right_beta, layer_index);
                HybridDomain::Beta(child_beta)
            } else {
                let left_alpha = *left.alpha_value();
                let right_alpha = *right.alpha_value();
                let child_alpha =
                    AH::Function::default().node(left_alpha, right_alpha, layer_index);
                HybridDomain::Alpha(child_alpha)
            };
        }

        let calculated_root = child;
        self.root == calculated_root
    }

    /// Checks that `data` matches the challenge leaf's value in the tree. Equivalent to
    /// `crate::merkle::MerkleProof::validate_data()`.
    pub fn challenge_value_matches_bytes(&self, bytes: &[u8]) -> bool {
        self.challenge_value.as_ref() == bytes
    }

    pub fn leaf(&self) -> &HybridDomain<AH::Domain, BH::Domain> {
        &self.challenge_value
    }

    pub fn root(&self) -> &HybridDomain<AH::Domain, BH::Domain> {
        &self.root
    }

    #[allow(clippy::type_complexity)]
    pub fn path(&self) -> &[(HybridDomain<AH::Domain, BH::Domain>, bool)] {
        &self.path
    }

    pub fn beta_height(&self) -> usize {
        self.beta_height
    }

    /// Returns the number of elements in the proof; the number of path elements plus 2 for the leaf
    /// and root elements.
    pub fn path_len(&self) -> usize {
        self.path.len()
    }

    /// Serializes this proof into bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];

        for (path_elem, path_elem_is_left) in self.path.iter() {
            bytes.extend_from_slice(path_elem.as_ref());
            bytes.push(*path_elem_is_left as u8);
        }

        bytes.extend_from_slice(self.challenge_value.as_ref());
        bytes.extend_from_slice(self.root.as_ref());
        bytes
    }

    /// Convert the path into the format expected by the circuits; a vector of `Option`s of tuples.
    /// The returned vector does not include the challenge leaf and root values.
    ///
    /// Equivalent to `crate::merkle::MerkleProof::as_options()`.
    pub fn as_circuit_auth_path(&self) -> Vec<Option<(Fr, bool)>> {
        self.path
            .iter()
            .enumerate()
            .map(|(layer_index, (path_elem, path_elem_is_left))| {
                let path_elem = if layer_index < self.beta_height {
                    (*path_elem.beta_value()).into()
                } else {
                    (*path_elem.alpha_value()).into()
                };
                Some((path_elem, *path_elem_is_left))
            })
            .collect()
    }

    /// Iterates over the proof path bookended with the root. Only used in Piece Inclusion Proofs.
    pub fn path_with_root(&self) -> impl Iterator<Item = &HybridDomain<AH::Domain, BH::Domain>> {
        self.path
            .iter()
            .map(|(path_elem, _)| path_elem)
            .chain(iter::once(&self.root))
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use merkletree::hash::Algorithm;
    use merkletree::merkle::Element;
    use rand::{thread_rng, Rng};

    use crate::hasher::blake2s::{Blake2sDomain, Blake2sFunction, Blake2sHasher};
    use crate::hasher::hybrid::HybridDomain;
    use crate::hasher::pedersen::{PedersenDomain, PedersenFunction, PedersenHasher};
    use crate::hybrid_merkle::HybridMerkleTree;

    const N_LEAVES: usize = 16;
    const HEIGHT: usize = 4;
    const N_NODES: usize = 31;
    const CHALLENGES: [usize; 4] = [0, 7, 10, 15];

    lazy_static! {
        static ref ALPHA_LEAVES: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = {
            let mut rng = thread_rng();
            (0..N_LEAVES)
                .map(|_| HybridDomain::Alpha(rng.gen()))
                .collect()
        };
        static ref BETA_LEAVES: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = {
            let mut rng = thread_rng();
            (0..N_LEAVES)
                .map(|_| HybridDomain::Beta(rng.gen()))
                .collect()
        };
    }

    fn expected_alpha_only_nodes() -> Vec<HybridDomain<PedersenDomain, Blake2sDomain>> {
        let layer_0 = ALPHA_LEAVES.clone();

        let layer_1: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = layer_0
            .chunks(2)
            .map(|pair| {
                let left = pair[0].alpha_value().clone();
                let right = pair[1].alpha_value().clone();
                let alpha_value = PedersenFunction::default().node(left, right, 0);
                HybridDomain::Alpha(alpha_value)
            })
            .collect();

        let layer_2: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = layer_1
            .chunks(2)
            .map(|pair| {
                let left = pair[0].alpha_value().clone();
                let right = pair[1].alpha_value().clone();
                let alpha_value = PedersenFunction::default().node(left, right, 1);
                HybridDomain::Alpha(alpha_value)
            })
            .collect();

        let layer_3: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = layer_2
            .chunks(2)
            .map(|pair| {
                let left = pair[0].alpha_value().clone();
                let right = pair[1].alpha_value().clone();
                let alpha_value = PedersenFunction::default().node(left, right, 2);
                HybridDomain::Alpha(alpha_value)
            })
            .collect();

        let root: HybridDomain<PedersenDomain, Blake2sDomain> = {
            let layer_3_len = layer_3.len();
            let left = layer_3[layer_3_len - 2].alpha_value().clone();
            let right = layer_3[layer_3_len - 1].alpha_value().clone();
            let alpha_value = PedersenFunction::default().node(left, right, 3);
            HybridDomain::Alpha(alpha_value)
        };

        layer_0
            .into_iter()
            .chain(layer_1.into_iter())
            .chain(layer_2.into_iter())
            .chain(layer_3.into_iter())
            .chain(iter::once(root))
            .collect()
    }

    fn expected_beta_only_nodes() -> Vec<HybridDomain<PedersenDomain, Blake2sDomain>> {
        let layer_0 = BETA_LEAVES.clone();

        let layer_1: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = layer_0
            .chunks(2)
            .map(|pair| {
                let left = pair[0].beta_value().clone();
                let right = pair[1].beta_value().clone();
                let beta_value = Blake2sFunction::default().node(left, right, 0);
                HybridDomain::Beta(beta_value)
            })
            .collect();

        let layer_2: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = layer_1
            .chunks(2)
            .map(|pair| {
                let left = pair[0].beta_value().clone();
                let right = pair[1].beta_value().clone();
                let beta_value = Blake2sFunction::default().node(left, right, 1);
                HybridDomain::Beta(beta_value)
            })
            .collect();

        let layer_3: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = layer_2
            .chunks(2)
            .map(|pair| {
                let left = pair[0].beta_value().clone();
                let right = pair[1].beta_value().clone();
                let beta_value = Blake2sFunction::default().node(left, right, 2);
                HybridDomain::Beta(beta_value)
            })
            .collect();

        let root: HybridDomain<PedersenDomain, Blake2sDomain> = {
            let layer_3_len = layer_3.len();
            let left = layer_3[layer_3_len - 2].beta_value().clone();
            let right = layer_3[layer_3_len - 1].beta_value().clone();
            let beta_value = Blake2sFunction::default().node(left, right, 3);
            HybridDomain::Beta(beta_value)
        };

        layer_0
            .into_iter()
            .chain(layer_1.into_iter())
            .chain(layer_2.into_iter())
            .chain(layer_3.into_iter())
            .chain(iter::once(root))
            .collect()
    }

    fn expected_nodes_with_beta_height_2() -> Vec<HybridDomain<PedersenDomain, Blake2sDomain>> {
        let layer_0 = BETA_LEAVES.clone();

        let layer_1: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = layer_0
            .chunks(2)
            .map(|pair| {
                let left = pair[0].beta_value().clone();
                let right = pair[1].beta_value().clone();
                let beta_value = Blake2sFunction::default().node(left, right, 0);
                HybridDomain::Beta(beta_value)
            })
            .collect();

        let layer_2: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = layer_1
            .chunks(2)
            .map(|pair| {
                let left = pair[0].beta_value().clone();
                let right = pair[1].beta_value().clone();
                let beta_value = Blake2sFunction::default().node(left, right, 1);
                let alpha_value = PedersenDomain::from_slice(beta_value.as_ref());
                HybridDomain::Alpha(alpha_value)
            })
            .collect();

        let layer_3: Vec<HybridDomain<PedersenDomain, Blake2sDomain>> = layer_2
            .chunks(2)
            .map(|pair| {
                let left = pair[0].alpha_value().clone();
                let right = pair[1].alpha_value().clone();
                let alpha_value = PedersenFunction::default().node(left, right, 2);
                HybridDomain::Alpha(alpha_value)
            })
            .collect();

        let root: HybridDomain<PedersenDomain, Blake2sDomain> = {
            let layer_3_len = layer_3.len();
            let left = layer_3[layer_3_len - 2].alpha_value().clone();
            let right = layer_3[layer_3_len - 1].alpha_value().clone();
            let alpha_value = PedersenFunction::default().node(left, right, 3);
            HybridDomain::Alpha(alpha_value)
        };

        layer_0
            .into_iter()
            .chain(layer_1.into_iter())
            .chain(layer_2.into_iter())
            .chain(layer_3.into_iter())
            .chain(iter::once(root))
            .collect()
    }

    #[test]
    fn test_hybrid_merkle_tree_alpha_only() {
        let leaves = (*ALPHA_LEAVES).clone();
        let tree = HybridMerkleTree::<PedersenHasher, Blake2sHasher>::from_leaves(leaves, 0);
        assert_eq!(tree.n_nodes(), N_NODES);

        let expected_nodes = expected_alpha_only_nodes();

        for node_index in 0..N_NODES {
            let tree_node = tree.read_at(node_index);
            let expected_node = expected_nodes[node_index];
            assert_eq!(tree_node, expected_node);
        }

        for challenge_index in CHALLENGES.iter() {
            let proof = tree.gen_proof(*challenge_index);
            assert!(proof.validate(*challenge_index));
        }
    }

    #[test]
    fn test_hybrid_merkle_tree_beta_only() {
        let leaves = (*BETA_LEAVES).clone();
        let tree =
            HybridMerkleTree::<PedersenHasher, Blake2sHasher>::from_leaves(leaves, HEIGHT + 1);
        assert_eq!(tree.n_nodes(), N_NODES);

        let expected_nodes = expected_beta_only_nodes();

        for node_index in 0..N_NODES {
            let tree_node = tree.read_at(node_index);
            let expected_node = expected_nodes[node_index];
            assert_eq!(tree_node, expected_node);
        }

        for challenge_index in CHALLENGES.iter() {
            let proof = tree.gen_proof(*challenge_index);
            assert!(proof.validate(*challenge_index));
        }
    }

    #[test]
    fn test_hybrid_merkle_tree_seam_root() {
        let leaves = (*BETA_LEAVES).clone();
        let tree = HybridMerkleTree::<PedersenHasher, Blake2sHasher>::from_leaves(leaves, HEIGHT);
        assert_eq!(tree.n_nodes(), N_NODES);

        let expected_nodes = expected_beta_only_nodes();

        for node_index in 0..N_NODES - 1 {
            let tree_node = tree.read_at(node_index);
            let expected_node = expected_nodes[node_index];
            assert_eq!(tree_node, expected_node);
        }

        let expected_alpha_root = expected_nodes[N_NODES - 1].into_alpha();
        assert_eq!(tree.root(), expected_alpha_root);

        for challenge_index in CHALLENGES.iter() {
            let proof = tree.gen_proof(*challenge_index);
            assert!(proof.validate(*challenge_index));
        }
    }

    #[test]
    fn test_hybrid_merkle_tree_with_seam() {
        const BETA_HEIGHT: usize = 2;

        let leaves = (*BETA_LEAVES).clone();
        let tree =
            HybridMerkleTree::<PedersenHasher, Blake2sHasher>::from_leaves(leaves, BETA_HEIGHT);
        assert_eq!(tree.n_nodes(), N_NODES);

        let expected_nodes = expected_nodes_with_beta_height_2();

        for node_index in 0..N_NODES {
            let tree_node = tree.read_at(node_index);
            let expected_node = expected_nodes[node_index];
            assert_eq!(tree_node, expected_node);
        }

        for challenge_index in CHALLENGES.iter() {
            let proof = tree.gen_proof(*challenge_index);
            assert!(proof.validate(*challenge_index));
        }
    }
}
