use filecoin_hashers::{sha256::Sha256Hasher, Hasher};
use generic_array::typenum::Unsigned;
use storage_proofs_core::merkle::{BinaryMerkleTree, MerkleTreeTrait};

// Allowed sector-sizes, measured in number of nodes.
// pub const ALLOWED_SECTOR_SIZES: [usize; 5] = [1 << 5, 1 << 18, 1 << 24, 1 << 30, 1 << 31];

// pub const ALLOWED_SECTOR_SIZES: [usize; 5] = [1 << 5, 1 << 18, 1 << 24, 1 << 30, 1 << 31];

const SECTOR_SIZE_1_KIB: usize = 1 << 5;
const SECTOR_SIZE_2_KIB: usize = 1 << 6;
const SECTOR_SIZE_4_KIB: usize = 1 << 7;
const SECTOR_SIZE_8_KIB: usize = 1 << 8;
const SECTOR_SIZE_16_KIB: usize = 1 << 9;
const SECTOR_SIZE_32_KIB: usize = 1 << 10;
const SECTOR_SIZE_8_MIB: usize = 1 << 18;
const SECTOR_SIZE_16_MIB: usize = 1 << 19;
const SECTOR_SIZE_512_MIB: usize = 1 << 24;
const SECTOR_SIZE_32_GIB: usize = 1 << 30;
const SECTOR_SIZE_64_GIB: usize = 1 << 31;

pub const ALLOWED_SECTOR_SIZES: [usize; 11] = [
    // Testing sector-sizes
    SECTOR_SIZE_1_KIB,
    SECTOR_SIZE_2_KIB,
    SECTOR_SIZE_4_KIB,
    SECTOR_SIZE_8_KIB,
    SECTOR_SIZE_16_KIB,
    SECTOR_SIZE_32_KIB,
    SECTOR_SIZE_8_MIB,
    SECTOR_SIZE_16_MIB,
    SECTOR_SIZE_512_MIB,
    // Published sector-sizes
    SECTOR_SIZE_32_GIB,
    SECTOR_SIZE_64_GIB,
];

pub const BINARY_ARITY: usize = 2;

pub type TreeD = BinaryMerkleTree<Sha256Hasher>;
pub type TreeDArity = <TreeD as MerkleTreeTrait>::Arity;
pub type TreeDHasher = <TreeD as MerkleTreeTrait>::Hasher;
pub type TreeDDomain = <TreeDHasher as Hasher>::Domain;

// The number of partitions for the given sector-size.
pub fn partition_count(sector_nodes: usize) -> usize {
    if sector_nodes <= SECTOR_SIZE_8_KIB {
        1
    } else if sector_nodes <= SECTOR_SIZE_32_KIB {
        2
    } else if sector_nodes <= SECTOR_SIZE_16_MIB {
        4
    } else {
        16
    }
}

// The number of challenges per partition proof.
pub fn challenge_count(sector_nodes: usize) -> usize {
    if sector_nodes <= SECTOR_SIZE_16_MIB {
        10
    } else {
        86
    }
}

// Returns the six `h` values allowed for the given sector-size. Each `h` value is a possible number
// of high bits taken from each generated challenge `c`. The circuit takes `h_select = 2^i` as a
// public input which is used to choose a value for the constant `h` via `h = hs[i]`.
pub fn hs(sector_nodes: usize) -> [usize; 6] {
    if sector_nodes <= SECTOR_SIZE_32_KIB {
        [1; 6]
    } else {
        [7, 8, 9, 10, 11, 12]
    }
}

// The number of leafs in each partition's apex-tree.
pub fn apex_leaf_count(sector_nodes: usize) -> usize {
    if sector_nodes <= SECTOR_SIZE_8_KIB {
        8
    } else {
        128
    }
}

pub fn tree_shape_is_valid<TreeR: MerkleTreeTrait>(sector_nodes: usize) -> bool {
    let base_arity = TreeR::Arity::to_usize();
    let sub_arity = TreeR::SubTreeArity::to_usize();
    let top_arity = TreeR::TopTreeArity::to_usize();
    let arities = (base_arity, sub_arity, top_arity);

    let arities_expected = match sector_nodes {
        SECTOR_SIZE_1_KIB => (8, 4, 0),
        SECTOR_SIZE_2_KIB => (8, 0, 0),
        SECTOR_SIZE_4_KIB => (8, 2, 0),
        SECTOR_SIZE_8_KIB => (8, 0, 0),
        SECTOR_SIZE_16_KIB => (8, 8, 0),
        SECTOR_SIZE_32_KIB => (8, 8, 2),
        SECTOR_SIZE_8_MIB => (8, 0, 0),
        SECTOR_SIZE_16_MIB => (8, 2, 0),
        SECTOR_SIZE_512_MIB => (8, 0, 0),
        SECTOR_SIZE_32_GIB => (8, 8, 0),
        SECTOR_SIZE_64_GIB => (8, 8, 2),
        _ => unreachable!(),
    };

    arities == arities_expected
}
