use blstrs::Scalar as Fr;
use filecoin_hashers::{
    poseidon::{PoseidonDomain, PoseidonHasher},
    sha256::{Sha256Domain, Sha256Hasher},
};
use generic_array::typenum::{Unsigned, U0, U2, U8};
use lazy_static::lazy_static;
use merkletree::store::DiskStore;
use neptune::{
    hash_type::{CType, HashType},
    poseidon::PoseidonConstants,
    Strength,
};
use storage_proofs_core::merkle::{BinaryMerkleTree, LCStore, LCTree, MerkleTreeTrait};

// Use a custom domain separation tag when generating randomness phi, rho, and challenges bits.
pub const HASH_TYPE_GEN_RANDOMNESS: HashType<Fr, U2> = HashType::Custom(CType::Arbitrary(1));

lazy_static! {
    pub static ref POSEIDON_CONSTANTS_GEN_RANDOMNESS: PoseidonConstants::<Fr, U2> =
        PoseidonConstants::new_with_strength_and_type(Strength::Standard, HASH_TYPE_GEN_RANDOMNESS);
}

// Sector-sizes measured in nodes.
pub const SECTOR_SIZE_1_KIB: usize = 1 << 5;
pub const SECTOR_SIZE_2_KIB: usize = 1 << 6;
pub const SECTOR_SIZE_4_KIB: usize = 1 << 7;
pub const SECTOR_SIZE_8_KIB: usize = 1 << 8;
pub const SECTOR_SIZE_16_KIB: usize = 1 << 9;
pub const SECTOR_SIZE_32_KIB: usize = 1 << 10;
pub const SECTOR_SIZE_8_MIB: usize = 1 << 18;
pub const SECTOR_SIZE_16_MIB: usize = 1 << 19;
pub const SECTOR_SIZE_512_MIB: usize = 1 << 24;
pub const SECTOR_SIZE_32_GIB: usize = 1 << 30;
pub const SECTOR_SIZE_64_GIB: usize = 1 << 31;

pub const ALLOWED_SECTOR_SIZES: [usize; 11] = [
    // testing sector-sizes
    SECTOR_SIZE_1_KIB,
    SECTOR_SIZE_2_KIB,
    SECTOR_SIZE_4_KIB,
    SECTOR_SIZE_8_KIB,
    SECTOR_SIZE_16_KIB,
    SECTOR_SIZE_32_KIB,
    SECTOR_SIZE_8_MIB,
    SECTOR_SIZE_16_MIB,
    SECTOR_SIZE_512_MIB,
    // published sector-sizes
    SECTOR_SIZE_32_GIB,
    SECTOR_SIZE_64_GIB,
];

pub type TreeD = BinaryMerkleTree<TreeDHasher>;
pub type TreeDHasher = Sha256Hasher;
pub type TreeDDomain = Sha256Domain;
pub type TreeDStore = DiskStore<TreeDDomain>;
pub type TreeDArity = U2;

pub type TreeRHasher = PoseidonHasher;
pub type TreeRDomain = PoseidonDomain;
pub type TreeRStore = LCStore<TreeRDomain>;
// All valid TreeR's have the same base-tree shape.
pub type TreeRBaseTree = LCTree<TreeRHasher, U8, U0, U0>;

// The number of partitions for the given sector-size.
pub const fn partition_count(sector_nodes: usize) -> usize {
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
pub const fn challenge_count(sector_nodes: usize) -> usize {
    if sector_nodes <= SECTOR_SIZE_16_MIB {
        10
    } else {
        86
    }
}

// Number of challenges per EmtpySectorUpdate-Poseidon partition proof; note
// EmptySectorUpdate-Poseidon proofs are single partition.
pub const fn challenge_count_poseidon(sector_nodes: usize) -> usize {
    challenge_count(sector_nodes) * partition_count(sector_nodes)
}

// Returns the `h` values allowed for the given sector-size. Each `h` value is a possible number of
// high bits taken from each challenge `c`. A single value of `h = hs[i]` is taken from `hs` for
// each proof; the circuit takes `h_select = 2^i` as a public input.
pub const fn hs(sector_nodes: usize) -> [usize; 6] {
    if sector_nodes <= SECTOR_SIZE_32_KIB {
        [1; 6]
    } else {
        [7, 8, 9, 10, 11, 12]
    }
}

// The number of leafs in each partition's apex-tree.
pub const fn apex_leaf_count(sector_nodes: usize) -> usize {
    if sector_nodes <= SECTOR_SIZE_8_KIB {
        8
    } else {
        128
    }
}

pub fn validate_tree_r_shape<TreeR: MerkleTreeTrait>(sector_nodes: usize) {
    let base_arity = TreeR::Arity::to_usize();
    let sub_arity = TreeR::SubTreeArity::to_usize();
    let top_arity = TreeR::TopTreeArity::to_usize();
    let arities = (base_arity, sub_arity, top_arity);

    let arities_expected = match sector_nodes {
        SECTOR_SIZE_1_KIB => (8, 4, 0),
        SECTOR_SIZE_2_KIB => (8, 0, 0),
        SECTOR_SIZE_4_KIB => (8, 2, 0),
        SECTOR_SIZE_8_KIB => (8, 4, 0),
        SECTOR_SIZE_16_KIB => (8, 8, 0),
        SECTOR_SIZE_32_KIB => (8, 8, 2),
        SECTOR_SIZE_8_MIB => (8, 0, 0),
        SECTOR_SIZE_16_MIB => (8, 2, 0),
        SECTOR_SIZE_512_MIB => (8, 0, 0),
        SECTOR_SIZE_32_GIB => (8, 8, 0),
        SECTOR_SIZE_64_GIB => (8, 8, 2),
        _ => unreachable!(),
    };

    assert_eq!(arities, arities_expected);
}
