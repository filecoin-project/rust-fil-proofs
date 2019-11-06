use bellperson::{ConstraintSystem, SynthesisError};
use ff::{BitIterator, PrimeField};
use fil_sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
use paired::Engine;

pub fn field_into_boolean_vec_be<E: Engine, CS: ConstraintSystem<E>, F: PrimeField>(
    cs: CS,
    value: Option<F>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let v = field_into_allocated_bits_be::<E, CS, F>(cs, value)?;

    Ok(v.into_iter().map(|e| Boolean::from(e)).collect())
}

pub fn field_into_allocated_bits_be<E: Engine, CS: ConstraintSystem<E>, F: PrimeField>(
    mut cs: CS,
    value: Option<F>,
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    // Deconstruct in big-endian bit order
    let num_bits = F::NUM_BITS as usize;
    let num_bits_bytes = num_bits + (8 - (num_bits % 8));
    assert!(num_bits_bytes % 8 == 0);

    let values = match value {
        Some(ref value) => {
            let tmp: Vec<Option<bool>> = BitIterator::new(value.into_repr())
                .into_iter()
                .map(|b| Some(b))
                .collect();

            assert_eq!(tmp.len(), num_bits_bytes);

            tmp
        }
        None => vec![None; num_bits_bytes],
    };

    // Allocate
    let bits = values
        .into_iter()
        .enumerate()
        .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("bit {}", i)), b))
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
}
