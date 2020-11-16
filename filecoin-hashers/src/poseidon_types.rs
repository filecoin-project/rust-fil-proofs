use bellperson::bls::Bls12;
use generic_array::typenum::{U11, U16, U2, U24, U36, U4, U8};
use lazy_static::lazy_static;
use neptune::poseidon::PoseidonConstants;

pub type PoseidonBinaryArity = U2;
pub type PoseidonQuadArity = U4;
pub type PoseidonOctArity = U8;

/// Arity to use by default for `hash_md` with poseidon.
pub type PoseidonMDArity = U36;

/// Arity to use for hasher implementations (Poseidon) which are specialized at compile time.
pub const MERKLE_TREE_ARITY: usize = 2;

lazy_static! {
    pub static ref POSEIDON_CONSTANTS_2: PoseidonConstants::<Bls12, U2> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_4: PoseidonConstants::<Bls12, U4> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_8: PoseidonConstants::<Bls12, U8> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_16: PoseidonConstants::<Bls12, U16> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_24: PoseidonConstants::<Bls12, U24> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_36: PoseidonConstants::<Bls12, U36> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_11: PoseidonConstants::<Bls12, U11> =
        PoseidonConstants::new();
    pub static ref POSEIDON_MD_CONSTANTS: PoseidonConstants::<Bls12, PoseidonMDArity> =
        PoseidonConstants::new();
}
