use lazy_static::lazy_static;
use neptune::poseidon::{Poseidon, PoseidonConstants};
use paired::bls12_381::Fr;

lazy_static! {
    pub static ref POSEIDON_CONSTANTS_1: PoseidonConstants::<paired::bls12_381::Bls12, typenum::U1> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_2: PoseidonConstants::<paired::bls12_381::Bls12, typenum::U2> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_11: PoseidonConstants::<paired::bls12_381::Bls12, typenum::U11> =
        PoseidonConstants::new();
}

/// Hash all elements in the given column.
pub fn hash_single_column(column: &[Fr]) -> Fr {
    match column.len() {
        1 => {
            let mut hasher = Poseidon::new_with_preimage(column, &*POSEIDON_CONSTANTS_1);
            hasher.hash()
        }
        2 => {
            let mut hasher = Poseidon::new_with_preimage(column, &*POSEIDON_CONSTANTS_2);
            hasher.hash()
        }
        11 => {
            let mut hasher = Poseidon::new_with_preimage(column, &*POSEIDON_CONSTANTS_11);
            hasher.hash()
        }
        _ => panic!("unsupported column size: {}", column.len()),
    }
}
