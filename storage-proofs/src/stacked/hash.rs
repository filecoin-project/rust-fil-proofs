use lazy_static::lazy_static;
use neptune::poseidon::{HashMode, Poseidon, PoseidonConstants};
use paired::bls12_381::Fr;

lazy_static! {
    pub static ref POSEIDON_CONSTANTS_11: PoseidonConstants::<paired::bls12_381::Bls12, typenum::U11> =
        PoseidonConstants::new();
}

/// Hash all elements in the given column.
pub fn hash_single_column<T: Into<Fr> + Copy>(column: &[T]) -> Fr {
    assert_eq!(column.len(), 11, "invalid column size");

    let mut hasher = Poseidon::new(&*POSEIDON_CONSTANTS_11);
    for t in column {
        let t_fr: Fr = (*t).into();
        hasher.input(t_fr).unwrap();
    }

    hasher.hash_in_mode(HashMode::OptimizedStatic)
}
