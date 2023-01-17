use blstrs::Scalar as Fr;
use filecoin_hashers::{
    poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher, PoseidonLookup, GROTH16_STRENGTH,
    HALO2_STRENGTH,
};
use generic_array::typenum::{Unsigned, U0, U2, U8};
use halo2_proofs::pasta::{Fp, Fq};
use lazy_static::lazy_static;
use merkletree::store::DiskStore;
use neptune::{
    hash_type::{CType, HashType},
    poseidon::PoseidonConstants,
};
use storage_proofs_core::{
    merkle::{BinaryMerkleTree, LCTree},
    SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_1_KIB, SECTOR_NODES_2_KIB,
    SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB,
    SECTOR_NODES_64_GIB, SECTOR_NODES_8_KIB, SECTOR_NODES_8_MIB,
};
use typemap::ShareMap;

// Use a custom domain separation tag when generating randomness phi, rho, and challenges bits.
pub const HASH_TYPE_GEN_RANDOMNESS: HashType<Fr, U2> = HashType::Custom(CType::Arbitrary(1));

lazy_static! {
    // Use a custom domain separation tag `HashType` when using Poseidon to generate randomness
    // (i.e. phi, rho, and challenges bits).
    pub static ref POSEIDON_CONSTANTS_GEN_RANDOMNESS_BLS: PoseidonConstants<Fr, U2> =
        PoseidonConstants::new_with_strength_and_type(
            GROTH16_STRENGTH,
            HashType::Custom(CType::Arbitrary(1)),
        );

    pub static ref POSEIDON_CONSTANTS_GEN_RANDOMNESS_PALLAS: PoseidonConstants<Fp, U2> =
        PoseidonConstants::new_with_strength_and_type(
            HALO2_STRENGTH,
            HashType::Custom(CType::Arbitrary(1)),
        );

    pub static ref POSEIDON_CONSTANTS_GEN_RANDOMNESS_VESTA: PoseidonConstants<Fq, U2> =
        PoseidonConstants::new_with_strength_and_type(
            HALO2_STRENGTH,
            HashType::Custom(CType::Arbitrary(1)),
        );

    pub static ref POSEIDON_CONSTANTS_GEN_RANDOMNESS: ShareMap = {
        let mut tm = ShareMap::custom();
        tm.insert::<PoseidonLookup<Fr, U2>>(&*POSEIDON_CONSTANTS_GEN_RANDOMNESS_BLS);
        tm.insert::<PoseidonLookup<Fp, U2>>(&*POSEIDON_CONSTANTS_GEN_RANDOMNESS_PALLAS);
        tm.insert::<PoseidonLookup<Fq, U2>>(&*POSEIDON_CONSTANTS_GEN_RANDOMNESS_VESTA);
        tm
    };
}

pub const ALLOWED_SECTOR_SIZES: [usize; 11] = [
    // testing sector-sizes
    SECTOR_NODES_1_KIB,
    SECTOR_NODES_2_KIB,
    SECTOR_NODES_4_KIB,
    SECTOR_NODES_8_KIB,
    SECTOR_NODES_16_KIB,
    SECTOR_NODES_32_KIB,
    SECTOR_NODES_8_MIB,
    SECTOR_NODES_16_MIB,
    SECTOR_NODES_512_MIB,
    // production sector-sizes
    SECTOR_NODES_32_GIB,
    SECTOR_NODES_64_GIB,
];

// Note: these TreeD constants are only valid for the non-Poseidon version of EmptySectorUpdate;
// EmptySectorUpdate-Poseidon uses TreeR for its TreeD.
pub type TreeDHasher<F> = Sha256Hasher<F>;
pub type TreeDDomain<F> = <TreeDHasher<F> as Hasher>::Domain;
pub type TreeD<F> = BinaryMerkleTree<TreeDHasher<F>>;
pub type TreeDStore<F> = DiskStore<TreeDDomain<F>>;
pub type TreeDArity = U2;

pub type TreeRHasher<F> = PoseidonHasher<F>;
pub type TreeRDomain<F> = <TreeRHasher<F> as Hasher>::Domain;
pub type TreeR<F, U, V, W> = LCTree<TreeRHasher<F>, U, V, W>;
// All valid TreeR shapes have the same base-tree shape.
pub type TreeRBase<F> = LCTree<TreeRHasher<F>, U8, U0, U0>;

// The number of groth16 partitions for the given sector size.
pub const fn partition_count(sector_nodes: usize) -> usize {
    if sector_nodes <= SECTOR_NODES_8_KIB {
        1
    } else if sector_nodes <= SECTOR_NODES_32_KIB {
        2
    } else if sector_nodes <= SECTOR_NODES_16_MIB {
        4
    } else {
        16
    }
}

// The number of challenges per groth16 partition proof.
pub const fn challenge_count(sector_nodes: usize) -> usize {
    if sector_nodes <= SECTOR_NODES_16_MIB {
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
    if sector_nodes <= SECTOR_NODES_32_KIB {
        [1; 6]
    } else {
        [7, 8, 9, 10, 11, 12]
    }
}

// The number of leafs in each partition's apex-tree.
pub const fn apex_leaf_count(sector_nodes: usize) -> usize {
    if sector_nodes <= SECTOR_NODES_8_KIB {
        8
    } else {
        128
    }
}

pub fn validate_tree_r_shape<U, V, W>(sector_nodes: usize)
where
    // Use `Unsigned` rather than `PoseidonArity<F>` because `PoseidonArity` requires adding an
    // additional type parameter `F: PrimeField` to this function (which we don't need).
    U: Unsigned,
    V: Unsigned,
    W: Unsigned,
{
    let base_arity = U::to_usize();
    let sub_arity = V::to_usize();
    let top_arity = W::to_usize();
    let arities = (base_arity, sub_arity, top_arity);

    let arities_expected = match sector_nodes {
        SECTOR_NODES_1_KIB => (8, 4, 0),
        SECTOR_NODES_2_KIB => (8, 0, 0),
        SECTOR_NODES_4_KIB => (8, 2, 0),
        SECTOR_NODES_8_KIB => (8, 4, 0),
        SECTOR_NODES_16_KIB => (8, 8, 0),
        SECTOR_NODES_32_KIB => (8, 8, 2),
        SECTOR_NODES_8_MIB => (8, 0, 0),
        SECTOR_NODES_16_MIB => (8, 2, 0),
        SECTOR_NODES_512_MIB => (8, 0, 0),
        SECTOR_NODES_32_GIB => (8, 8, 0),
        SECTOR_NODES_64_GIB => (8, 8, 2),
        _ => unimplemented!("sector-size not supported"),
    };

    assert_eq!(arities, arities_expected);
}
