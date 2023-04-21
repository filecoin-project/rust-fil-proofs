use ff::PrimeField;
use filecoin_hashers::get_poseidon_constants;
use generic_array::typenum::{U11, U2};
use neptune::poseidon::Poseidon;

/// Hash all elements in the given column.
pub fn hash_single_column<F: PrimeField>(column: &[F]) -> F {
    match column.len() {
        2 => {
            let consts = get_poseidon_constants::<F, U2>();
            Poseidon::new_with_preimage(column, consts).hash()
        }
        11 => {
            let consts = get_poseidon_constants::<F, U11>();
            Poseidon::new_with_preimage(column, consts).hash()
        }
        _ => panic!("unsupported column size: {}", column.len()),
    }
}
