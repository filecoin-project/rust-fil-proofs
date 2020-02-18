use crate::hasher::types::{POSEIDON_CONSTANTS_1, POSEIDON_CONSTANTS_11, POSEIDON_CONSTANTS_2};
use neptune::poseidon::Poseidon;
use paired::bls12_381::Fr;

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
