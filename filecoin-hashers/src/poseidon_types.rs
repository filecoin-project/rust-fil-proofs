use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use blstrs::Scalar as Fr;
use lazy_static::lazy_static;
use neptune::{circuit::poseidon_hash, poseidon::PoseidonConstants};

pub const PoseidonBinaryArity: usize = 2;
pub const PoseidonBinaryWidth: usize = PoseidonBinaryArity + 1;
pub const PoseidonQuadArity: usize = 4;
pub const PoseidonQuadWidth: usize = PoseidonQuadArity + 1;
pub const PoseidonOctArity: usize = 8;
pub const PoseidonOctWidth: usize = PoseidonOctArity + 1;

/// Arity to use by default for `hash_md` with poseidon.
pub const PoseidonMDArity: usize = 36;
pub const PoseidonMDWidth: usize = PoseidonMDArity + 1;

/// Arity to use for hasher implementations (Poseidon) which are specialized at compile time.
/// Must match PoseidonArity
pub const MERKLE_TREE_ARITY: usize = 2;

lazy_static! {
    pub static ref POSEIDON_CONSTANTS_2: PoseidonConstants::<Fr, 2, 3> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_4: PoseidonConstants::<Fr, 4, 5> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_8: PoseidonConstants::<Fr, 8, 9> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_16: PoseidonConstants::<Fr, 16, 17> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_24: PoseidonConstants::<Fr, 24, 25> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_36: PoseidonConstants::<Fr, 36, 37> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_11: PoseidonConstants::<Fr, 11, 12> =
        PoseidonConstants::new();
    pub static ref POSEIDON_MD_CONSTANTS: &'static PoseidonConstants<Fr, PoseidonMDArity, PoseidonMDWidth> =
        &*POSEIDON_CONSTANTS_36;
}

pub fn poseidon_circuit_hash<CS: ConstraintSystem<Fr>, const ARITY: usize>(
    cs: CS,
    leaves: &[AllocatedNum<Fr>],
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    match ARITY {
        2 => poseidon_hash::<CS, Fr, 2, 3>(cs, leaves.to_vec(), &*POSEIDON_CONSTANTS_2),
        4 => poseidon_hash::<CS, Fr, 4, 5>(cs, leaves.to_vec(), &*POSEIDON_CONSTANTS_4),
        8 => poseidon_hash::<CS, Fr, 8, 9>(cs, leaves.to_vec(), &*POSEIDON_CONSTANTS_8),
        11 => poseidon_hash::<CS, Fr, 11, 12>(cs, leaves.to_vec(), &*POSEIDON_CONSTANTS_11),
        16 => poseidon_hash::<CS, Fr, 16, 17>(cs, leaves.to_vec(), &*POSEIDON_CONSTANTS_16),
        24 => poseidon_hash::<CS, Fr, 24, 25>(cs, leaves.to_vec(), &*POSEIDON_CONSTANTS_24),
        36 => poseidon_hash::<CS, Fr, 36, 37>(cs, leaves.to_vec(), &*POSEIDON_CONSTANTS_36),
        _ => panic!("unsupported arity for poseidon hasher: {}", ARITY),
    }
}
