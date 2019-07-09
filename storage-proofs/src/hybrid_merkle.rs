use std::cmp::PartialEq;
use std::fmt::{self, Debug, Formatter};
use std::iter::IntoIterator;
use std::marker::PhantomData;
#[cfg(feature = "disk-trees")]
use std::path::PathBuf;

use merkletree::hash::{Algorithm, Hashable};
use paired::bls12_381::Fr;
use rayon::prelude::{ParallelIterator, ParallelSlice};

use crate::hasher::{Domain, Hasher};
#[cfg(feature = "disk-trees")]
use crate::merkle::DiskMmapStore;
use crate::merkle::MerkleTree;
#[cfg(feature = "disk-trees")]
use crate::SP_LOG;

/// (jake) TODO: optimize and add warning "changing this constant will require changing the
/// published groth params".
pub const ALPHA_TREE_HEIGHT: usize = 3;

/// The minimum number of leaves in a Hybrid Merkle Tree. A Hybrid Merkle Tree requires
/// `ALPHA_TREE_HEIGHT` number of layers using the alpha hasher and at least one layer using the
/// beta hasher.
pub const MIN_N_LEAVES: usize = 16;

/// Returns whether or not the Merkle Tree node positioned at `node_index` is a left input to to
/// the Merkle hash function. Even node indices are left inputs, odd indices are right.
#[inline(always)]
fn is_left_input(node_index: usize) -> bool {
    node_index & 1 == 0
}

#[inline(always)]
fn is_right_input(node_index: usize) -> bool {
    node_index & 1 == 1
}

/// Returns true if `x` is a power of two.
///
/// How it works:
///
/// If some positive integer is a power of two, then it has the binary form of a single bit `1`
/// followed by some number of zeros (e.g. 8 == 0b1000, 16 == 0b10000). If a given positive integer
/// is a power of two, then one less than that number has a binary representation containing all
/// ones (e.g. 7 == 0b111, 15 == 0b1111). Therefore, bitwise AND-ing any positive interger `x` that
/// is a power of two with `x - 1` results in zero.
///
/// For every positive integer `x` that is not a power of two, the integer one less than it will
/// have the same most significant bit set (e.g. 13 = 0b1101, 12 = 0b1100), therefore AND-ing the
/// two together will result in a non-zero number.
fn is_pow2(x: usize) -> bool {
    if x == 0 {
        return false;
    }
    x & (x - 1) == 0
}

/// Returns `node_index`'s hash partner (the node that `node_index` is paired with during Merkle
/// hashing).
#[inline(always)]
fn get_sibling(node_index: usize) -> usize {
    if is_left_input(node_index) {
        node_index + 1
    } else {
        node_index - 1
    }
}

/// Converts an element from one hasher's domain into an element of a second hasher's domain.
fn convert_hasher_domain<A, B>(elem: A) -> B
where
    A: Domain,
    B: Domain,
{
    let fr: Fr = elem.into();
    B::from(fr)
}

/// Copies the functionality used by `merkle_light::merkle::MerkleTree` to hash a node (non-leaf) in
/// the tree.
pub fn hash_node<H>(left: H::Domain, right: H::Domain, layer: usize) -> H::Domain
where
    H: Hasher,
{
    let mut alg = H::Function::default();
    alg.node(left, right, layer)
}

/// Stores the value for a node in a Hybrid Merkle Tree . If an node is in one of the beta hasher's
/// trees, then the field `beta` will be `Some`, likewise if the element is found in the alpha
/// hasher's tree, then `alpha` will be set to `Some`. If an element is the root of a beta tree/leaf
/// of the alpha tree, then both `beta` and `alpha` will be set.
///
/// This type is returned by `HybridMerkleTree::read_at()`. `HybridMerkleTree` does not use
/// `HybridNode` internally to store elements.
#[derive(Debug, Default)]
pub struct HybridNode<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    pub beta: Option<BH::Domain>,
    pub alpha: Option<AH::Domain>,
}

/// Represents the positional information associated with a node in a `HybridMerkleTree`.
///
/// A `HybridMerkleTree` is composed of smaller subtrees (many beta trees and one alpha tree). These
/// subtrees are abstracted away from the user. The user views a Hybrid Merkle Tree the same as they
/// would a regular Merkle Tree. A user references a node in a Hybrid Merkle Tree using a node's
/// "abstracted" node index, however nodes are not actually stored at that index (because Hybrid
/// Merkle Trees are composed of many smaller subtrees). Therefore, some node index
/// arithmetic/conversion must happen to convert the abstracted user-facing node index to a node
/// index in a subtree. The output of some of these arithmetic steps are utilized in multiple
/// `HybridMerkleTree` methods, we compute these values once and use this structure to pass the
/// values around.
#[derive(Debug)]
struct NodeInfo {
    /// This node's abstracted node index in a Hybrid Merkle Tree.
    node_index: usize,

    /// The Hybrid Merkle Tree layer that contains the node (layer 0 is the base/leaf layer, layer 1
    /// is the layer above it, etc...).
    layer: usize,

    /// Is this node part of a beta subtree.
    is_in_beta_tree: bool,

    /// Is this node part of the alpha subtree.
    is_in_alpha_tree: bool,

    /// If this node is part of a beta tree then this field gives the index in
    /// `HybridMerkleTree.beta_trees` for the beta tree containing this node.
    beta_tree_index: Option<usize>,

    /// If this node is part of a beta tree, then this field gives the node's node index in the beta
    /// tree.
    beta_tree_node_index: Option<usize>,

    /// If this node is part of the alpha tree, then this field gives the node's node index in the
    /// alpha tree.
    alpha_tree_node_index: Option<usize>,

    /// The abstracted Hybrid Merkle Tree node index for this node's child node (the child node is
    /// the node that results from hashing this node together with its sibling).
    child_node_index: usize,
}

/// A wrapper around a Merkle Tree's root to provide pretty debug printing.
struct MerkleTreeRootDebug<T>(T)
where
    T: Domain;

impl<T> Debug for MerkleTreeRootDebug<T>
where
    T: Domain,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "MerkleTree(root={:?})", self.0)
    }
}

/// Stores a Hybrid Merkle Tree's size information.
struct TreeInfo {
    n_leaves: usize,
    height: usize,
    n_layers: usize,
    alpha_tree_height: usize,
    beta_tree_height: usize,
    n_leaves_per_beta_tree: usize,
    n_beta_trees: usize,
    n_nodes: usize,
    last_node_index_per_layer: Vec<usize>,
}

fn get_tree_info(n_leaves: usize) -> TreeInfo {
    let height = (n_leaves as f32).log2() as usize;
    let n_layers = height + 1;
    let alpha_tree_height = ALPHA_TREE_HEIGHT;
    let beta_tree_height = height - alpha_tree_height;
    let n_leaves_per_beta_tree = 2usize.pow(beta_tree_height as u32);
    let n_beta_trees = n_leaves / n_leaves_per_beta_tree;
    let n_nodes = 2 * n_leaves - 1;

    let last_node_index_per_layer: Vec<usize> = (0..n_layers)
        .scan(0, |first_node_in_layer, layer_index| {
            let n_nodes_in_layer = n_leaves >> layer_index;
            let first_node_in_next_layer = *first_node_in_layer + n_nodes_in_layer;
            let last_node_in_this_layer = first_node_in_next_layer - 1;
            *first_node_in_layer = first_node_in_next_layer;
            Some(last_node_in_this_layer)
        })
        .collect();

    TreeInfo {
        n_leaves,
        height,
        n_layers,
        alpha_tree_height,
        beta_tree_height,
        n_leaves_per_beta_tree,
        n_beta_trees,
        n_nodes,
        last_node_index_per_layer,
    }
}

/// Creates the disk-backed Mmap file for a beta tree.
#[cfg(feature = "disk-trees")]
fn create_stores_for_beta_tree<D>(
    path_prefix: &str,
    beta_tree_index: usize,
    tree_info: &TreeInfo,
) -> (DiskMmapStore<D>, DiskMmapStore<D>)
where
    D: Domain,
{
    let leaves_path_str = format!("{}-beta-leaves-{}", path_prefix, beta_tree_index);
    let top_half_path_str = format!("{}-beta-top-half-{}", path_prefix, beta_tree_index);

    let leaves_path = PathBuf::from(leaves_path_str);
    let top_half_path = PathBuf::from(top_half_path_str);

    info!(SP_LOG, "creating beta tree's leaves mmap-file"; "path-prefix" => leaves_path.to_str());
    info!(
        SP_LOG,
        "creating beta tree's top-half mmap-file";
        "path-prefix" => top_half_path.to_str()
    );

    let leaves_store = DiskMmapStore::new_with_path(tree_info.n_leaves_per_beta_tree, &leaves_path);
    let top_half_store =
        DiskMmapStore::new_with_path(tree_info.n_leaves_per_beta_tree, &top_half_path);

    (leaves_store, top_half_store)
}

/// Creates the disk-backet Mmap file for an alpha tree.
#[cfg(feature = "disk-trees")]
fn create_stores_for_alpha_tree<D>(
    path_prefix: &str,
    tree_info: &TreeInfo,
) -> (DiskMmapStore<D>, DiskMmapStore<D>)
where
    D: Domain,
{
    let leaves_path_str = format!("{}-alpha-leaves", path_prefix);
    let top_half_path_str = format!("{}-alpha-top-half", path_prefix);

    let leaves_path = PathBuf::from(leaves_path_str);
    let top_half_path = PathBuf::from(top_half_path_str);

    info!(SP_LOG, "creating alpha tree's leaves mmap-file"; "path-prefix" => leaves_path.to_str());
    info!(SP_LOG, "creating alpha tree's top-half mmap-file"; "path-prefix" => top_half_path.to_str());

    let n_leaves_per_alpha_tree = tree_info.n_beta_trees;
    let leaves_store = DiskMmapStore::new_with_path(n_leaves_per_alpha_tree, &leaves_path);
    let top_half_store = DiskMmapStore::new_with_path(n_leaves_per_alpha_tree, &top_half_path);

    (leaves_store, top_half_store)
}

/// An alternative implementation to `merkle_light::merkle::MerkleTree` using two hasher's rather
/// than one. Leaf values are always `BH::Domain` elements, and the Hybrid Merkle Tree's root is
/// always an `AH::Domain` element. A Hybrid Merkle Tree is composed of many subtrees using the beta
/// hasher and a single tree using the alpha hasher.
///
/// A Hybrid Merkle Tree that uses the same hasher for its alpha and beta hashers does not result in
/// the same tree generated by a non-hybrid Merkle Tree. This is because the `height` parameter in
/// each layer's hash function is different between Merkle Trees and Hybrid Merkle Trees.
///
/// # Padding
///
/// For now, we forbid creating Hybrid Merkle Trees with a non-power-of-two number of leaves. When a
/// `merkle_light::merkle::MerkleTree` is created using a non-power-of-two number of leaves, each
/// layer gets padded to the nearest even number of leaves using the last allocated node value in
/// that layer. In the case for Hybrid Merkle Trees that are instantiated using a non-power-of-two
/// number of leaves, padding would be required.  However, because Hybrid Merkle Tree's are composed
/// of many Merkle Trees, a subtree's padding value may be dependent on the last allocated value in
/// the previous subtree.  Currently, there is no API in `merkle_light` for adding custom pad value
/// at a specific layer.
#[derive(Clone)]
pub struct HybridMerkleTree<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    beta_trees: Vec<MerkleTree<BH::Domain, BH::Function>>,
    alpha_tree: MerkleTree<AH::Domain, AH::Function>,
    root: AH::Domain,
    n_layers: usize,
    height: usize,
    alpha_tree_height: usize,
    beta_tree_height: usize,
    n_leaves: usize,
    n_leaves_per_beta_tree: usize,
    n_beta_trees: usize,
    n_nodes: usize,
    last_node_index_per_layer: Vec<usize>,
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

impl<AH, BH> Debug for HybridMerkleTree<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let beta_trees_debug: Vec<MerkleTreeRootDebug<BH::Domain>> = self
            .beta_trees
            .iter()
            .map(|beta_tree| MerkleTreeRootDebug(beta_tree.root()))
            .collect();

        let alpha_tree_debug = MerkleTreeRootDebug(self.root);

        f.debug_struct("HybridMerkleTree")
            .field("beta_trees", &beta_trees_debug)
            .field("alpha_tree", &alpha_tree_debug)
            .field("root", &self.root)
            .field("height", &self.height)
            .field("alpha_tree_height", &self.alpha_tree_height)
            .field("beta_tree_height", &self.beta_tree_height)
            .field("n_leaves", &self.n_leaves)
            .field("n_leaves_per_beta_tree", &self.n_leaves_per_beta_tree)
            .field("n_beta_trees", &self.n_beta_trees)
            .field("n_nodes", &self.n_nodes)
            .field("last_node_index_per_layer", &self.last_node_index_per_layer)
            .finish()
    }
}

impl<AH, BH> PartialEq for HybridMerkleTree<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}

impl<AH, BH> HybridMerkleTree<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    pub fn from_leaves<I>(leaves: I) -> Self
    where
        I: IntoIterator<Item = BH::Domain>,
    {
        let leaves: Vec<BH::Domain> = leaves.into_iter().collect();
        let n_leaves = leaves.len();

        if n_leaves < MIN_N_LEAVES {
            panic!(
                "Cannot create a Hybrid Merkle Tree with {} leaves",
                n_leaves
            );
        }

        if !is_pow2(n_leaves) {
            panic!("Cannot create a Hybrid Merkle Tree with a non-power-of-two number of leaves")
        }

        let TreeInfo {
            n_layers,
            height,
            alpha_tree_height,
            beta_tree_height,
            n_leaves,
            n_leaves_per_beta_tree,
            n_beta_trees,
            n_nodes,
            last_node_index_per_layer,
        } = get_tree_info(n_leaves);

        // Create the beta hasher's subtrees.
        let beta_trees: Vec<MerkleTree<BH::Domain, BH::Function>> = leaves
            .chunks(n_leaves_per_beta_tree)
            .map(|beta_tree_leaves| {
                let beta_tree_leaves = beta_tree_leaves.iter().cloned();
                MerkleTree::new(beta_tree_leaves)
            })
            .collect();

        // Convert each beta tree's root (`BH::Domain`) into an alpha tree leaf (`AH::Domain`).
        let alpha_tree_leaves = beta_trees.iter().map(|beta_tree| {
            let beta_tree_root = beta_tree.root();
            convert_hasher_domain::<BH::Domain, AH::Domain>(beta_tree_root)
        });

        // Calculate the alpha hasher's tree.
        let alpha_tree = MerkleTree::<AH::Domain, AH::Function>::new(alpha_tree_leaves);
        let root = alpha_tree.root();

        HybridMerkleTree {
            beta_trees,
            alpha_tree,
            root,
            n_layers,
            height,
            alpha_tree_height,
            beta_tree_height,
            n_leaves,
            n_leaves_per_beta_tree,
            n_beta_trees,
            n_nodes,
            last_node_index_per_layer,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    /// Creates a new `HybridMerkleTree` by creating the beta hasher's subtrees in parallel.
    pub fn from_leaves_par<I>(leaves: I) -> Self
    where
        I: IntoIterator<Item = BH::Domain>,
    {
        let leaves: Vec<BH::Domain> = leaves.into_iter().collect();
        let n_leaves = leaves.len();

        if n_leaves < MIN_N_LEAVES {
            panic!(
                "Cannot create a Hybrid Merkle Tree with {} leaves",
                n_leaves
            );
        }

        if !is_pow2(n_leaves) {
            panic!("Cannot create a Hybrid Merkle Tree with a non-power-of-two number of leaves")
        }

        let TreeInfo {
            n_layers,
            height,
            alpha_tree_height,
            beta_tree_height,
            n_leaves,
            n_leaves_per_beta_tree,
            n_beta_trees,
            n_nodes,
            last_node_index_per_layer,
        } = get_tree_info(n_leaves);

        let beta_trees: Vec<MerkleTree<BH::Domain, BH::Function>> = leaves
            .par_chunks(n_leaves_per_beta_tree)
            .map(|beta_tree_leaves| {
                let beta_tree_leaves = beta_tree_leaves.iter().cloned();
                MerkleTree::new(beta_tree_leaves)
            })
            .collect();

        // Convert each beta tree root (`BH::Domain`) into a alpha tree leaf (`AH::Domain`).
        let alpha_tree_leaves = beta_trees.iter().map(|beta_tree| {
            let beta_tree_root = beta_tree.root();
            convert_hasher_domain::<BH::Domain, AH::Domain>(beta_tree_root)
        });

        let alpha_tree: MerkleTree<AH::Domain, AH::Function> = MerkleTree::new(alpha_tree_leaves);

        let root = alpha_tree.root();

        HybridMerkleTree {
            beta_trees,
            alpha_tree,
            root,
            n_layers,
            height,
            alpha_tree_height,
            beta_tree_height,
            n_leaves,
            n_leaves_per_beta_tree,
            n_beta_trees,
            n_nodes,
            last_node_index_per_layer,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    /// Creates a `HybridMerkleTree` given an iterator of `Hashable` items. Each item from the
    /// `data` iterator will be hashed into the beta hasher's domain, the result of each hash is a
    /// leaf in the Hybrid Merkle Tree.
    pub fn from_leaf_preimages<I, D>(data: I) -> Self
    where
        I: IntoIterator<Item = D>,
        D: Hashable<BH::Function>,
    {
        let mut beta_hashing_alg = BH::Function::default();

        let leaves = data.into_iter().map(|leaf_data| {
            leaf_data.hash(&mut beta_hashing_alg);
            let leaf = beta_hashing_alg.hash();
            beta_hashing_alg.reset();
            leaf
        });

        HybridMerkleTree::from_leaves(leaves)
    }

    /// Equivalent to `merkle_light::merkle::MerkleTree::from_data_with_store()`.
    #[cfg(feature = "disk-trees")]
    pub fn from_leaves_with_path<I>(leaves: I, path_prefix: &str) -> Self
    where
        I: IntoIterator<Item = BH::Domain>,
    {
        let leaves: Vec<BH::Domain> = leaves.into_iter().collect();
        let n_leaves = leaves.len();

        if n_leaves < MIN_N_LEAVES {
            panic!(
                "Cannot create a Hybrid Merkle Tree with {} leaves",
                n_leaves
            );
        }

        if !is_pow2(n_leaves) {
            panic!("Cannot create a Hybrid Merkle Tree with a non-power-of-two number of leaves")
        }

        let tree_info = get_tree_info(n_leaves);

        // Create the beta hasher's subtrees.
        let beta_trees: Vec<MerkleTree<BH::Domain, BH::Function>> = leaves
            .chunks(tree_info.n_leaves_per_beta_tree)
            .enumerate()
            .map(|(beta_tree_index, beta_tree_leaves)| {
                let beta_tree_leaves = beta_tree_leaves.iter().map(|leaf| *leaf);
                let (leaves_store, top_half_store) = create_stores_for_beta_tree::<BH::Domain>(
                    path_prefix,
                    beta_tree_index,
                    &tree_info,
                );
                MerkleTree::from_data_with_store(beta_tree_leaves, leaves_store, top_half_store)
            })
            .collect();

        // Convert each beta tree's root (`BH::Domain`) into an alpha tree leaf (`AH::Domain`).
        let alpha_tree_leaves = beta_trees.iter().map(|beta_tree| {
            let beta_tree_root = beta_tree.root();
            convert_hasher_domain::<BH::Domain, AH::Domain>(beta_tree_root)
        });

        // Calculate the alpha hasher's tree.
        let (alpha_leaves_store, alpha_top_half_store) =
            create_stores_for_alpha_tree::<AH::Domain>(path_prefix, &tree_info);

        let alpha_tree = MerkleTree::<AH::Domain, AH::Function>::from_data_with_store(
            alpha_tree_leaves,
            alpha_leaves_store,
            alpha_top_half_store,
        );

        let root = alpha_tree.root();

        let TreeInfo {
            n_layers,
            height,
            alpha_tree_height,
            beta_tree_height,
            n_leaves,
            n_leaves_per_beta_tree,
            n_beta_trees,
            n_nodes,
            last_node_index_per_layer,
        } = tree_info;

        HybridMerkleTree {
            beta_trees,
            alpha_tree,
            root,
            n_layers,
            height,
            alpha_tree_height,
            beta_tree_height,
            n_leaves,
            n_leaves_per_beta_tree,
            n_beta_trees,
            n_nodes,
            last_node_index_per_layer,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    pub fn try_offload_store(&self) -> bool {
        let mut ret = true;
        for beta_tree in self.beta_trees.iter() {
            let success = beta_tree.try_offload_store();
            ret &= success;
        }
        ret & self.alpha_tree.try_offload_store()
    }

    pub fn root(&self) -> AH::Domain {
        self.root
    }

    pub fn leaves(&self) -> Vec<BH::Domain> {
        let mut leaves: Vec<BH::Domain> = vec![];
        let n_leaves_per_beta_tree = self.n_leaves / self.beta_trees.len();
        for beta_tree in self.beta_trees.iter() {
            for node_index in 0..n_leaves_per_beta_tree {
                leaves.push(beta_tree.read_at(node_index));
            }
        }
        leaves
    }

    /// Returns the number of layers minus 1 (excludes the base/leaf layer).
    pub fn height(&self) -> usize {
        self.height
    }

    pub fn n_layers(&self) -> usize {
        self.n_layers
    }

    /// Returns the total number of nodes in this tree. Nodes that appear in both a beta subtree and
    /// the alpha subtree tree (i.e. the root of each beta tree) are not counted twice.
    pub fn n_nodes(&self) -> usize {
        self.n_nodes
    }

    /// Returns the total number of nodes in this tree.
    ///
    /// This method is identical to `HybridMerkleTree::n_nodes(&self)`. These methods are duplicated
    /// to provide API compatibility between `HybridMerkleTree` and `MerkleTree`.
    pub fn len(&self) -> usize {
        self.n_nodes
    }

    pub fn is_empty(&self) -> bool {
        self.n_nodes == 0
    }

    /// Returns the number of leaves in this tree.
    pub fn n_leaves(&self) -> usize {
        self.n_leaves
    }

    /// Returns the number of leaves in this tree.
    ///
    /// This method is the same as `HybridMerkleTree::n_leaves()`. We duplicate this method to
    /// maintain API compatibility with `MerkleTree::leafs()`.
    pub fn leafs(&self) -> usize {
        self.n_leaves
    }

    pub fn last_node_index_per_layer(&self) -> &[usize] {
        &self.last_node_index_per_layer
    }

    pub fn beta_tree_height(&self) -> usize {
        self.beta_tree_height
    }

    pub fn alpha_tree_height(&self) -> usize {
        self.alpha_tree_height
    }

    /// Returns whether or not the node at `node_index` is a leaf in the tree.
    #[inline]
    fn is_leaf(&self, node_index: usize) -> bool {
        node_index < self.n_leaves
    }

    /// Converts a node index in this Hybrid Merkle Tree into the node's subtree positional
    /// information. A `HyrbidMerkleTree` is composed of many subtrees (`MerkleTree`s) which are
    /// abstracted away from the user, it is necessary for the user to be able to refer to nodes in
    /// a Hybrid Merkle Tree by their high-level/abstracted node index while it is also necessary
    /// for the `HyridMerkleTree` to internally refer to nodes by their subtree position(s). This
    /// method derives the subtree positional information used internally by a `HyrbidMerkleTree`
    /// from the abstracted user-facing node index.
    fn get_node_info(&self, node_index: usize) -> NodeInfo {
        if node_index >= self.n_nodes {
            panic!("Hybrid Merkle Tree does not contain node");
        }

        // Calculate which layer in the abstracted Hybrid Merkle Tree the node is in.
        // It is safe to unwrap here because we (from the above check) know that `node_index` is a
        // valid node index.
        let layer = self
            .last_node_index_per_layer
            .iter()
            .position(|layer_last_node_index| *layer_last_node_index >= node_index)
            .unwrap();

        let n_nodes_in_layer = self.n_leaves >> layer;

        // Record whether or not the node is in a beta tree and/or the alpha tree.
        let is_in_beta_tree = layer <= self.beta_tree_height;
        let is_in_alpha_tree = layer >= self.beta_tree_height;

        // How far to the right is the node in its abstracted Hybrid Merkle Tree layer.
        let index_in_layer = node_index % n_nodes_in_layer;

        // Get the node index in the abstracted Hybrid Merkle Tree for `node_index`'s child.
        let child_node_index = {
            // Because every node has in-degree 2, dividing a node's index in a layer by 2 gives
            // it's child's index in the next layer.
            let child_index_in_next_layer = index_in_layer >> 1;
            let first_node_index_in_next_layer = self.last_node_index_per_layer[layer] + 1;
            first_node_index_in_next_layer + child_index_in_next_layer
        };

        // If the node is in a beta tree, record which beta tree it is in and the node's node index
        // within the the beta tree.
        let (beta_tree_index, beta_tree_node_index) = if is_in_beta_tree {
            let n_nodes_in_beta_tree_layer = n_nodes_in_layer / self.n_beta_trees;
            let beta_tree_index = index_in_layer / n_nodes_in_beta_tree_layer;
            let n_leaves_per_beta_tree = self.n_leaves / self.n_beta_trees;
            let index_in_beta_tree_layer = index_in_layer % n_nodes_in_beta_tree_layer;

            let beta_tree_node_index = (0..=layer).fold(0, |mut acc, layer_index| {
                if layer_index < layer {
                    let n_nodes_in_beta_tree_layer = n_leaves_per_beta_tree << layer_index;
                    acc += n_nodes_in_beta_tree_layer;
                } else {
                    acc += index_in_beta_tree_layer;
                }
                acc
            });

            (Some(beta_tree_index), Some(beta_tree_node_index))
        } else {
            (None, None)
        };

        // If the node is in the alpha tree, record its index within the alpha tree.
        let alpha_tree_node_index = if is_in_alpha_tree {
            let first_node_index_in_alpha_tree =
                self.last_node_index_per_layer[self.beta_tree_height - 1] + 1;
            let alpha_tree_node_index = node_index - first_node_index_in_alpha_tree;
            Some(alpha_tree_node_index)
        } else {
            None
        };

        NodeInfo {
            node_index,
            layer,
            is_in_beta_tree,
            is_in_alpha_tree,
            beta_tree_index,
            beta_tree_node_index,
            alpha_tree_node_index,
            child_node_index,
        }
    }

    /// Returns a node's value at the given node index in the abstracted Hybrid Merkle Tree. This
    /// method returns a `HyrbidNode` because nodes that are roots for a beta tree are also leaves
    /// for the alpha tree, therefore they have both beta and alpha tree values.
    pub fn read_at(&self, node_index: usize) -> HybridNode<AH, BH> {
        let node_info = self.get_node_info(node_index);
        self.read_at_node_info(&node_info)
    }

    fn read_at_node_info(&self, node_info: &NodeInfo) -> HybridNode<AH, BH> {
        let beta_tree_value = if node_info.is_in_beta_tree {
            let beta_tree_index = node_info.beta_tree_index.unwrap();
            let beta_tree_node_index = node_info.beta_tree_node_index.unwrap();
            let value = self.beta_trees[beta_tree_index].read_at(beta_tree_node_index);
            Some(value)
        } else {
            None
        };

        let alpha_tree_value = if node_info.is_in_alpha_tree {
            let alpha_tree_node_index = node_info.alpha_tree_node_index.unwrap();
            let value = self.alpha_tree.read_at(alpha_tree_node_index);
            Some(value)
        } else {
            None
        };

        HybridNode {
            beta: beta_tree_value,
            alpha: alpha_tree_value,
        }
    }

    /// Write a node's value in the Hybrid Merkle Tree to the `dest` buffer. If a node is present in
    /// both a beta tree and the alpha tree write the node's beta tree value.
    pub fn read_into(&self, node_index: usize, dest: &mut [u8]) {
        let value = self.read_at(node_index);

        if let Some(beta_value) = value.beta {
            beta_value
                .write_bytes(dest)
                .expect("failed to write node data");
        } else if let Some(alpha_value) = value.alpha {
            alpha_value
                .write_bytes(dest)
                .expect("failed to write node data");
        } else {
            panic!("Tree does not contain node");
        }
    }

    /// Returns the Merkle proof for the Hybrid Merkle Tree leaf at the node index `challenge_index`.
    pub fn gen_proof(&self, challenge_index: usize) -> HybridMerkleProof<AH, BH> {
        if !self.is_leaf(challenge_index) {
            panic!("Hybrid Merkle Tree challenge is not a leaf");
        }

        let beta_path_len = self.beta_tree_height;
        let alpha_path_len = self.alpha_tree_height;

        let mut beta_path: Vec<(BH::Domain, bool)> = Vec::with_capacity(beta_path_len);
        let mut alpha_path: Vec<(AH::Domain, bool)> = Vec::with_capacity(alpha_path_len);

        let challenge_info = self.get_node_info(challenge_index);
        let challenge_value = self.read_at_node_info(&challenge_info).beta.unwrap();

        // Add the challenge's sibling (Merkle hash partner) as the first value in the beta path.
        let sibling_index = get_sibling(challenge_index);
        // Unwrapping here is safe because we've already checked that the challenge is a leaf (all
        // leaf nodes fall into a beta tree).
        let sibling_value = self.read_at(sibling_index).beta.unwrap();
        let sibling_is_left = is_left_input(sibling_index);
        beta_path.push((sibling_value, sibling_is_left));

        // Add the remaining values to the beta path.
        let mut child_index = challenge_info.child_node_index;

        for _ in 0..(beta_path_len - 1) {
            let sibling_index = get_sibling(child_index);
            let sibling_info = self.get_node_info(sibling_index);
            let sibling_value = self.read_at_node_info(&sibling_info).beta.unwrap();
            let sibling_is_left = is_left_input(sibling_index);
            beta_path.push((sibling_value, sibling_is_left));
            child_index = sibling_info.child_node_index;
        }

        // Create the alpha path (excluding the root).
        for _ in 0..alpha_path_len {
            let sibling_index = get_sibling(child_index);
            let sibling_info = self.get_node_info(sibling_index);
            let sibling_value = self.read_at_node_info(&sibling_info).alpha.unwrap();
            let sibling_is_left = is_left_input(sibling_index);
            alpha_path.push((sibling_value, sibling_is_left));
            child_index = sibling_info.child_node_index;
        }

        let root = self.root;

        HybridMerkleProof {
            challenge_value,
            beta_path,
            alpha_path,
            root,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    /// Pretty prints this tree as a table of node indices mapped to each's corresponding alpha
    /// hasher and/or beta hasher value. The layer that contains nodes that have both alpha and beta
    /// values is printed twice. The table is of the form:
    ///
    /// Layer #0 (beta):
    ///     0 => {first node value as beta hasher domain element}
    ///     1 => {second node value as beta hasher domain element}
    ///     2 => {third node value as beta hasher domain element}
    ///     ...
    ///
    /// Layer #1 ({hasher id: beta, alpha}):
    ///     ...
    #[allow(clippy::needless_range_loop)]
    pub fn pretty_print(&self) {
        let last_beta_layer = self.beta_tree_height;
        let first_alpha_layer = last_beta_layer;
        let last_node_index_per_layer = self.last_node_index_per_layer();
        let mut first_node_in_layer = 0;

        for layer_index in 0..=last_beta_layer {
            println!("\n\nLayer #{} (beta):", layer_index);
            let last_node_in_layer = last_node_index_per_layer[layer_index];
            for node_index in first_node_in_layer..=last_node_in_layer {
                println!(
                    "\t{} => {:?}",
                    node_index,
                    self.read_at(node_index).beta.unwrap()
                );
            }
            if layer_index != last_beta_layer {
                first_node_in_layer = last_node_in_layer + 1;
            }
        }

        for layer_index in first_alpha_layer..=self.height {
            println!("\n\nLayer #{} (alpha):", layer_index);
            let last_node_in_layer = last_node_index_per_layer[layer_index];
            for node_index in first_node_in_layer..=last_node_in_layer {
                println!(
                    "\t{} => {:?}",
                    node_index,
                    self.read_at(node_index).alpha.unwrap()
                );
            }
            first_node_in_layer = last_node_in_layer + 1;
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct HybridMerkleProof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    challenge_value: BH::Domain,
    beta_path: Vec<(BH::Domain, bool)>,
    alpha_path: Vec<(AH::Domain, bool)>,
    root: AH::Domain,

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
    pub fn new_empty(height: usize) -> Self {
        let beta_path_len = height - ALPHA_TREE_HEIGHT;
        let beta_path = vec![(BH::Domain::default(), false); beta_path_len];
        let alpha_path = vec![(AH::Domain::default(), false); ALPHA_TREE_HEIGHT];

        HybridMerkleProof {
            beta_path,
            alpha_path,
            ..Default::default()
        }
    }

    #[allow(clippy::explicit_counter_loop)]
    fn calculate_beta_root(&self) -> BH::Domain {
        let mut tree_layer = 0;
        let (sibling, sibling_is_left) = self.beta_path[0];

        let mut child = if sibling_is_left {
            hash_node::<BH>(sibling, self.challenge_value, tree_layer)
        } else {
            hash_node::<BH>(self.challenge_value, sibling, tree_layer)
        };

        for (sibling, sibling_is_left) in &self.beta_path[1..] {
            tree_layer += 1;

            child = if *sibling_is_left {
                hash_node::<BH>(*sibling, child, tree_layer)
            } else {
                hash_node::<BH>(child, *sibling, tree_layer)
            };
        }

        child
    }

    #[allow(clippy::explicit_counter_loop)]
    fn calculate_alpha_root(&self, calculated_leaf: AH::Domain) -> AH::Domain {
        let mut tree_layer = 0;
        let (sibling, sibling_is_left) = self.alpha_path[0];

        let mut child = if sibling_is_left {
            hash_node::<AH>(sibling, calculated_leaf, tree_layer)
        } else {
            hash_node::<AH>(calculated_leaf, sibling, tree_layer)
        };

        for (sibling, sibling_is_left) in &self.alpha_path[1..] {
            tree_layer += 1;

            child = if *sibling_is_left {
                hash_node::<AH>(*sibling, child, tree_layer)
            } else {
                hash_node::<AH>(child, *sibling, tree_layer)
            };
        }

        child
    }

    /// Equivalent to `merkle_light::proof::Proof::validate()` and
    /// `merkle::MerkleProof::validate()`.
    pub fn validate(&self, challenge_index: usize) -> bool {
        if !self.validate_is_left_bits_match_challenge(challenge_index) {
            return false;
        }
        let beta_tree_root = self.calculate_beta_root();
        let alpha_tree_leaf = convert_hasher_domain::<BH::Domain, AH::Domain>(beta_tree_root);
        let calculated_root = self.calculate_alpha_root(alpha_tree_leaf);
        self.root == calculated_root
    }

    /// Given the challenge's node index, returns whether or not the "is_left" bits in the proof's
    /// paths are correct.
    fn validate_is_left_bits_match_challenge(&self, challenge_index: usize) -> bool {
        let mut index_in_layer = challenge_index;

        for (_path_elem, path_elem_is_left) in self.beta_path.iter() {
            if is_right_input(index_in_layer) != *path_elem_is_left {
                return false;
            }
            index_in_layer >>= 1;
        }

        for (_path_elem, path_elem_is_left) in self.alpha_path.iter() {
            if is_right_input(index_in_layer) != *path_elem_is_left {
                return false;
            }
            index_in_layer >>= 1;
        }

        true
    }

    /// Checks that `data` matches the challenge leaf's value in the tree. Equivalent to
    /// `merkle::MerkleProof::validate_data()`.
    pub fn validate_challenge_value_as_bytes(&self, data: &[u8]) -> bool {
        self.challenge_value.as_ref() == data
    }

    pub fn leaf(&self) -> &BH::Domain {
        &self.challenge_value
    }

    pub fn root(&self) -> &AH::Domain {
        &self.root
    }

    pub fn beta_path(&self) -> &[(BH::Domain, bool)] {
        &self.beta_path
    }

    pub fn alpha_path(&self) -> &[(AH::Domain, bool)] {
        &self.alpha_path
    }

    /// Returns the number of elements in the proof; the number of path elements plus 2 for the leaf
    /// and root elements.
    pub fn path_len(&self) -> usize {
        self.beta_path.len() + self.alpha_path.len()
    }

    /// Serialize into bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];

        for (path_elem, path_elem_is_left) in self.beta_path.iter() {
            bytes.extend(path_elem.serialize());
            bytes.push(*path_elem_is_left as u8);
        }

        for (path_elem, path_elem_is_left) in self.alpha_path.iter() {
            bytes.extend(path_elem.serialize());
            bytes.push(*path_elem_is_left as u8);
        }

        bytes.extend(self.challenge_value.serialize());
        bytes.extend(self.root.serialize());
        bytes
    }

    /// Convert the path into the format expected by the circuits, which is a vector of `Option`s of
    /// tuples. This does not include the root and the leaf values.
    ///
    /// Equivalent to `merkle::MerkleProof::as_options()`.
    pub fn as_circuit_auth_path(&self) -> Vec<Option<(Fr, bool)>> {
        let mut path: Vec<Option<(Fr, bool)>> = vec![];

        for (path_elem, is_left) in self.beta_path.iter() {
            let path_elem: Fr = (*path_elem).into();
            path.push(Some((path_elem, *is_left)));
        }

        for (path_elem, is_left) in self.alpha_path.iter() {
            let path_elem: Fr = (*path_elem).into();
            path.push(Some((path_elem, *is_left)));
        }

        path
    }
}

#[cfg(test)]
mod tests {
    use merkletree::hash::{Algorithm, Hashable};

    use crate::hasher::blake2s::Blake2sDomain;
    use crate::hasher::pedersen::PedersenDomain;
    use crate::hasher::{Blake2sHasher, Hasher, PedersenHasher};
    use crate::hybrid_merkle::{
        convert_hasher_domain, hash_node, HybridMerkleTree, ALPHA_TREE_HEIGHT,
    };

    // The data that we are commiting to in each `HybridMerkleTree`. Each elemen in `DATA` is a
    // leaf's data/preimage.
    const DATA: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    // The expected Hybrid Merkle proof path lengths for a tree containing 16 leaves (the length of
    // `DATA`).
    const ALPHA_PATH_LEN: usize = ALPHA_TREE_HEIGHT;
    const BETA_PATH_LEN: usize = 1;

    // Hashes an element from `DATA` (each element being a leaf node's raw data) in the Hybrid
    // Merkle Tree to the beta hasher's domain.
    fn hash_leaf<H>(leaf_data: u8) -> H::Domain
    where
        H: Hasher,
    {
        let mut hashing_alg = H::Function::default();
        leaf_data.hash(&mut hashing_alg);
        hashing_alg.hash()
    }

    #[test]
    fn test_hybrid_merkle_read_at() {
        let tree = HybridMerkleTree::<PedersenHasher, Blake2sHasher>::from_leaf_preimages(&DATA);

        // Check that the leaves are being read correctly.
        let value = tree.read_at(0);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[0].read_at(0));

        let value = tree.read_at(1);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[0].read_at(1));

        let value = tree.read_at(2);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[1].read_at(0));

        let value = tree.read_at(3);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[1].read_at(1));

        let value = tree.read_at(4);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[2].read_at(0));

        let value = tree.read_at(5);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[2].read_at(1));

        let value = tree.read_at(6);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[3].read_at(0));

        let value = tree.read_at(7);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[3].read_at(1));

        let value = tree.read_at(8);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[4].read_at(0));

        let value = tree.read_at(9);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[4].read_at(1));

        let value = tree.read_at(10);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[5].read_at(0));

        let value = tree.read_at(11);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[5].read_at(1));

        let value = tree.read_at(12);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[6].read_at(0));

        let value = tree.read_at(13);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[6].read_at(1));

        let value = tree.read_at(14);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[7].read_at(0));

        let value = tree.read_at(15);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_none());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[7].read_at(1));

        // Check that values from the second layer are being read correctly. The Hyrbid Merkle
        // Tree's second layer contains the roots of the beta trees/the leaves of the alpha tree.
        let value = tree.read_at(16);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_some());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[0].read_at(2));
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(0));

        let value = tree.read_at(17);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_some());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[1].read_at(2));
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(1));

        let value = tree.read_at(18);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_some());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[2].read_at(2));
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(2));

        let value = tree.read_at(19);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_some());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[3].read_at(2));
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(3));

        let value = tree.read_at(20);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_some());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[4].read_at(2));
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(4));

        let value = tree.read_at(21);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_some());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[5].read_at(2));
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(5));

        let value = tree.read_at(22);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_some());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[6].read_at(2));
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(6));

        let value = tree.read_at(23);
        assert!(value.beta.is_some());
        assert!(value.alpha.is_some());
        assert_eq!(value.beta.unwrap(), tree.beta_trees[7].read_at(2));
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(7));

        // Verify that nodes from the Hyrbid Merkle Tree's thrid layer are being read correctly.
        let value = tree.read_at(24);
        assert!(value.beta.is_none());
        assert!(value.alpha.is_some());
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(8));

        let value = tree.read_at(25);
        assert!(value.beta.is_none());
        assert!(value.alpha.is_some());
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(9));

        let value = tree.read_at(26);
        assert!(value.beta.is_none());
        assert!(value.alpha.is_some());
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(10));

        let value = tree.read_at(27);
        assert!(value.beta.is_none());
        assert!(value.alpha.is_some());
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(11));

        // Verify that nodes from the Hybrid Merkle Tree's fourth layer are being read correctly.
        let value = tree.read_at(28);
        assert!(value.beta.is_none());
        assert!(value.alpha.is_some());
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(12));

        let value = tree.read_at(29);
        assert!(value.beta.is_none());
        assert!(value.alpha.is_some());
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(13));

        // Verify that the root is being read correctly.
        let value = tree.read_at(30);
        assert!(value.beta.is_none());
        assert!(value.alpha.is_some());
        assert_eq!(value.alpha.unwrap(), tree.alpha_tree.read_at(14));
    }

    #[test]
    fn test_hybrid_merkle_gen_proof() {
        let tree = HybridMerkleTree::<PedersenHasher, Blake2sHasher>::from_leaf_preimages(&DATA);

        // Manually calculate each leaf value.
        let calculated_leaves: Vec<Blake2sDomain> = DATA
            .iter()
            .map(|leaf_data| hash_leaf::<Blake2sHasher>(*leaf_data))
            .collect();

        // Manually calculate each beta tree's root.
        let calculated_beta_roots: [Blake2sDomain; 8] = [
            hash_node::<Blake2sHasher>(calculated_leaves[0], calculated_leaves[1], 0),
            hash_node::<Blake2sHasher>(calculated_leaves[2], calculated_leaves[3], 0),
            hash_node::<Blake2sHasher>(calculated_leaves[4], calculated_leaves[5], 0),
            hash_node::<Blake2sHasher>(calculated_leaves[6], calculated_leaves[7], 0),
            hash_node::<Blake2sHasher>(calculated_leaves[8], calculated_leaves[9], 0),
            hash_node::<Blake2sHasher>(calculated_leaves[10], calculated_leaves[11], 0),
            hash_node::<Blake2sHasher>(calculated_leaves[12], calculated_leaves[13], 0),
            hash_node::<Blake2sHasher>(calculated_leaves[14], calculated_leaves[15], 0),
        ];

        // Convert each beta tree's root to an alpha tree leaf.
        let calculated_alpha_leaves: [PedersenDomain; 8] = [
            convert_hasher_domain::<Blake2sDomain, PedersenDomain>(calculated_beta_roots[0]),
            convert_hasher_domain::<Blake2sDomain, PedersenDomain>(calculated_beta_roots[1]),
            convert_hasher_domain::<Blake2sDomain, PedersenDomain>(calculated_beta_roots[2]),
            convert_hasher_domain::<Blake2sDomain, PedersenDomain>(calculated_beta_roots[3]),
            convert_hasher_domain::<Blake2sDomain, PedersenDomain>(calculated_beta_roots[4]),
            convert_hasher_domain::<Blake2sDomain, PedersenDomain>(calculated_beta_roots[5]),
            convert_hasher_domain::<Blake2sDomain, PedersenDomain>(calculated_beta_roots[6]),
            convert_hasher_domain::<Blake2sDomain, PedersenDomain>(calculated_beta_roots[7]),
        ];

        // Manually calculate the node values for the Hybrid Merkle Tree's third layer.
        let calculated_third_layer: [PedersenDomain; 4] = [
            hash_node::<PedersenHasher>(calculated_alpha_leaves[0], calculated_alpha_leaves[1], 0),
            hash_node::<PedersenHasher>(calculated_alpha_leaves[2], calculated_alpha_leaves[3], 0),
            hash_node::<PedersenHasher>(calculated_alpha_leaves[4], calculated_alpha_leaves[5], 0),
            hash_node::<PedersenHasher>(calculated_alpha_leaves[6], calculated_alpha_leaves[7], 0),
        ];

        // Manually calculate the node values for the Hybrid Merkle Tree's fourth layer.
        let calculated_fourth_layer: [PedersenDomain; 2] = [
            hash_node::<PedersenHasher>(calculated_third_layer[0], calculated_third_layer[1], 1),
            hash_node::<PedersenHasher>(calculated_third_layer[2], calculated_third_layer[3], 1),
        ];

        // Manually calculate the root.
        let calculated_root =
            hash_node::<PedersenHasher>(calculated_fourth_layer[0], calculated_fourth_layer[1], 2);

        // -- Verify the proof generated for node #0.
        let challenge_node_index = 0;
        let proof = tree.gen_proof(challenge_node_index);
        assert_eq!(proof.beta_path.len(), BETA_PATH_LEN);
        assert_eq!(proof.alpha_path.len(), ALPHA_PATH_LEN);
        assert_eq!(
            proof.challenge_value,
            calculated_leaves[challenge_node_index]
        );
        assert_eq!(proof.beta_path[0], (calculated_leaves[1], false));
        assert_eq!(proof.alpha_path[0], (calculated_alpha_leaves[1], false));
        assert_eq!(proof.alpha_path[1], (calculated_third_layer[1], false));
        assert_eq!(proof.alpha_path[2], (calculated_fourth_layer[1], false));
        assert_eq!(proof.root, calculated_root);

        // -- Verify the proof generated for node #5.
        let challenge_node_index = 5;
        let proof = tree.gen_proof(challenge_node_index);
        assert_eq!(proof.beta_path.len(), BETA_PATH_LEN);
        assert_eq!(proof.alpha_path.len(), ALPHA_PATH_LEN);
        assert_eq!(
            proof.challenge_value,
            calculated_leaves[challenge_node_index]
        );
        assert_eq!(proof.beta_path[0], (calculated_leaves[4], true));
        assert_eq!(proof.alpha_path[0], (calculated_alpha_leaves[3], false));
        assert_eq!(proof.alpha_path[1], (calculated_third_layer[0], true));
        assert_eq!(proof.alpha_path[2], (calculated_fourth_layer[1], false));
        assert_eq!(proof.root, calculated_root);

        // -- Verify the proof generated for node #10.
        let challenge_node_index = 10;
        let proof = tree.gen_proof(challenge_node_index);
        assert_eq!(proof.beta_path.len(), BETA_PATH_LEN);
        assert_eq!(proof.alpha_path.len(), ALPHA_PATH_LEN);
        assert_eq!(
            proof.challenge_value,
            calculated_leaves[challenge_node_index]
        );
        assert_eq!(proof.beta_path[0], (calculated_leaves[11], false));
        assert_eq!(proof.alpha_path[0], (calculated_alpha_leaves[4], true));
        assert_eq!(proof.alpha_path[1], (calculated_third_layer[3], false));
        assert_eq!(proof.alpha_path[2], (calculated_fourth_layer[0], true));
        assert_eq!(proof.root, calculated_root);

        // -- Verify the proof generated for node #15.
        let challenge_node_index = 15;
        let proof = tree.gen_proof(challenge_node_index);
        assert_eq!(proof.beta_path.len(), BETA_PATH_LEN);
        assert_eq!(proof.alpha_path.len(), ALPHA_PATH_LEN);
        assert_eq!(
            proof.challenge_value,
            calculated_leaves[challenge_node_index]
        );
        assert_eq!(proof.beta_path[0], (calculated_leaves[14], true));
        assert_eq!(proof.alpha_path[0], (calculated_alpha_leaves[6], true));
        assert_eq!(proof.alpha_path[1], (calculated_third_layer[2], true));
        assert_eq!(proof.alpha_path[2], (calculated_fourth_layer[0], true));
        assert_eq!(proof.root, calculated_root);
    }

    #[test]
    fn test_hybrid_merkle_proof_validate() {
        const CHALLENGE_NODE_INDEX: usize = 0;
        let tree = HybridMerkleTree::<PedersenHasher, Blake2sHasher>::from_leaf_preimages(&DATA);
        let proof = tree.gen_proof(CHALLENGE_NODE_INDEX);
        assert!(proof.validate(CHALLENGE_NODE_INDEX));
    }

    #[test]
    fn test_hybrid_merkle_constructors() {
        let tree_from_data =
            HybridMerkleTree::<PedersenHasher, Blake2sHasher>::from_leaf_preimages(&DATA);

        let leaves: Vec<Blake2sDomain> = DATA
            .iter()
            .map(|leaf_data| hash_leaf::<Blake2sHasher>(*leaf_data))
            .collect();

        let tree_from_leaves =
            HybridMerkleTree::<PedersenHasher, Blake2sHasher>::from_leaves(leaves.clone());

        let tree_par = HybridMerkleTree::<PedersenHasher, Blake2sHasher>::from_leaves_par(leaves);

        assert_eq!(tree_from_data, tree_from_leaves);
        assert_eq!(tree_from_data, tree_par);
    }
}
