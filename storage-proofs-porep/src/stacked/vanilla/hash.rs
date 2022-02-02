use ff::PrimeField;
use filecoin_hashers::{FieldArity, POSEIDON_CONSTANTS};
use generic_array::typenum::{U11, U2};
use neptune::poseidon::Poseidon;

/// Hash all elements in the given column.
pub fn hash_single_column<F: PrimeField>(column: &[F]) -> F {
    match column.len() {
        2 => {
            let consts = &POSEIDON_CONSTANTS
                .get::<FieldArity<F, U2>>()
                .expect("Poseidon constants not found for field and arity-2");
            Poseidon::new_with_preimage(column, consts).hash()
        }
        11 => {
            let consts = &POSEIDON_CONSTANTS
                .get::<FieldArity<F, U11>>()
                .expect("Poseidon constants not found for field and arity-11");
            Poseidon::new_with_preimage(column, consts).hash()
        }
        _ => panic!("unsupported column size: {}", column.len()),
    }
}
