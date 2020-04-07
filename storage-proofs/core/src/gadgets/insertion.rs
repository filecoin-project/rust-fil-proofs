//! Insertion Permutation
//!
//! Insert an `AllocatedNum` into a sequence of `AllocatedNums` at an arbitrary position.
//! This can be thought of as a generalization of `AllocatedNum::conditionally_reverse` and reduces to it in the binary case.

use bellperson::gadgets::boolean::Boolean;
use bellperson::gadgets::num::AllocatedNum;
use bellperson::{ConstraintSystem, SynthesisError};
use ff::Field;
use paired::Engine;

/// Insert `element` after the nth 1-indexed element of `elements`, where `path_bits` represents n, least-significant bit first.
/// The returned result contains a new vector of `AllocatedNum`s with `element` inserted, and constraints are enforced.
/// `elements.len() + 1` must be a power of two.
pub fn insert<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    element: &AllocatedNum<E>,
    bits: &[Boolean],
    elements: &[AllocatedNum<E>],
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
    let size = elements.len() + 1;
    assert_eq!(1 << bits.len(), size);

    // Running example choices, represent inserting x into [1, 2, 3].

    // An indexed sequence of correct results, one of which (the indexed one) will be selected.
    let mut potential_results = Vec::new();
    for index in 0..size {
        // These are the results when bits corresponds to index.
        //
        // index | result
        //-------+-------
        // 0     | x 1 2 3
        // 1     | 1 x 2 3
        // 2     | 1 2 x 3
        // 3     | 1 2 3 x
        let mut result = Vec::new();
        (0..index).for_each(|i| result.push(elements[i].clone()));
        result.push(element.clone());
        (index..elements.len()).for_each(|i| result.push(elements[i].clone()));

        potential_results.push(result);
    }

    let mut result = Vec::new();
    for pos in 0..size {
        // These are the choices needed such that for each position in the selected result,
        // the value is column-for-pos[index].
        //
        // This table is constructed by reading columns from the index-result table above.
        // Reading columns from this table yields the result table.

        // pos   column
        // 0     x 1 1 1
        // 1     1 x 2 2
        // 2     2 2 x 3
        // 3     3 3 3 x
        let choices = (0..size)
            .map(|index| potential_results[index][pos].clone())
            .collect::<Vec<_>>();

        result.push(select(
            cs.namespace(|| format!("choice at {}", pos)),
            &choices,
            bits,
        )?);
    }

    Ok(result)
}

/// Select the nth element of `from`, where `path_bits` represents n, least-significant bit first.
/// The returned result contains the selected element, and constraints are enforced.
/// `from.len()` must be a power of two.
pub fn select<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    from: &[AllocatedNum<E>],
    path_bits: &[Boolean],
) -> Result<AllocatedNum<E>, SynthesisError> {
    let pathlen = path_bits.len();
    assert_eq!(1 << pathlen, from.len());

    let mut state = Vec::new();
    for elt in from {
        state.push(elt.clone())
    }
    let mut half_size = from.len() / 2;

    // We reverse the path bits because the contained algorithm consumes most significant bit first.
    for (i, bit) in path_bits.iter().rev().enumerate() {
        let mut new_state = Vec::new();
        for j in 0..half_size {
            new_state.push(pick(
                cs.namespace(|| format!("pick {}, {}", i, j)),
                bit,
                &state[half_size + j],
                &state[j],
            )?);
        }
        state = new_state;
        half_size /= 2;
    }

    Ok(state.remove(0))
}

/// Takes two allocated numbers (`a`, `b`) and returns `a` if the condition is true, and `b` otherwise.
pub fn pick<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    condition: &Boolean,
    a: &AllocatedNum<E>,
    b: &AllocatedNum<E>,
) -> Result<AllocatedNum<E>, SynthesisError>
where
    CS: ConstraintSystem<E>,
{
    let c = AllocatedNum::alloc(cs.namespace(|| "pick result"), || {
        if condition
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?
        {
            Ok(a.get_value().ok_or(SynthesisError::AssignmentMissing)?)
        } else {
            Ok(b.get_value().ok_or(SynthesisError::AssignmentMissing)?)
        }
    })?;

    cs.enforce(
        || "pick",
        |lc| lc + b.get_variable() - a.get_variable(),
        |_| condition.lc(CS::one(), E::Fr::one()),
        |lc| lc + b.get_variable() - c.get_variable(),
    );

    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::gadgets::TestConstraintSystem;
    use bellperson::gadgets::boolean::AllocatedBit;
    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_select() {
        for log_size in 1..5 {
            let size = 1 << log_size;
            for index in 0..size {
                // Initialize rng in loop to simplify debugging with consistent elements.
                let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
                let mut cs = TestConstraintSystem::new();

                let elements: Vec<_> = (0..size)
                    .map(|i| {
                        AllocatedNum::<Bls12>::alloc(
                            &mut cs.namespace(|| format!("element {}", i)),
                            || {
                                let elt = <Fr as Field>::random(rng);
                                Ok(elt)
                            },
                        )
                        .unwrap()
                    })
                    .collect();

                let path_bits = (0..log_size)
                    .map(|i| {
                        <Boolean as std::convert::From<AllocatedBit>>::from(
                            AllocatedBit::alloc(cs.namespace(|| format!("index bit {}", i)), {
                                let bit = ((index >> i) & 1) == 1;
                                Some(bit)
                            })
                            .unwrap(),
                        )
                    })
                    .collect::<Vec<_>>();

                let test_constraints = cs.num_constraints();
                assert_eq!(log_size, test_constraints);

                let selected = select(cs.namespace(|| "select"), &elements, &path_bits).unwrap();

                assert!(cs.is_satisfied());
                assert_eq!(elements[index].get_value(), selected.get_value());

                // One constraint per non-leaf node of a binary tree with `size` leaves.
                let expected_constraints = size - 1;

                let actual_constraints = cs.num_constraints() - test_constraints;
                assert_eq!(expected_constraints, actual_constraints);
            }
        }
    }

    #[test]
    fn test_insert() {
        for log_size in 1..=3 {
            let size = 1 << log_size;
            for index in 0..size {
                // Initialize rng in loop to simplify debugging with consistent elements.
                let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
                let mut cs = TestConstraintSystem::new();

                let elements: Vec<_> = (0..size - 1)
                    .map(|i| {
                        AllocatedNum::<Bls12>::alloc(
                            &mut cs.namespace(|| format!("element {}", i)),
                            || {
                                let elt = <Fr as Field>::random(rng);
                                Ok(elt)
                            },
                        )
                        .unwrap()
                    })
                    .collect();

                let to_insert =
                    AllocatedNum::<Bls12>::alloc(&mut cs.namespace(|| "insert"), || {
                        Ok(<Fr as Field>::random(rng))
                    })
                    .unwrap();

                let index_bits = (0..log_size)
                    .map(|i| {
                        <Boolean as std::convert::From<AllocatedBit>>::from(
                            AllocatedBit::alloc(cs.namespace(|| format!("index bit {}", i)), {
                                let bit = ((index >> i) & 1) == 1;
                                Some(bit)
                            })
                            .unwrap(),
                        )
                    })
                    .collect::<Vec<_>>();

                let test_constraints = cs.num_constraints();
                assert_eq!(log_size, test_constraints);

                let mut inserted = insert(
                    &mut cs,
                    &to_insert.clone(),
                    index_bits.as_slice(),
                    &elements.as_slice(),
                )
                .unwrap();

                assert!(cs.is_satisfied());

                let extracted = inserted.remove(index);
                assert_eq!(to_insert.get_value(), extracted.get_value(),);

                for i in 0..size - 1 {
                    let a = elements[i].get_value();
                    let b = inserted[i].get_value();

                    assert_eq!(a, b)
                }

                // One selection for each element of the result.
                let expected_constraints = size * (size - 1);

                let actual_constraints = cs.num_constraints() - test_constraints;
                assert_eq!(expected_constraints, actual_constraints);
            }
        }
    }
}
