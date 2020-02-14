//! Insertion Permutation
//!
//! Implements support for this plan. First line is context, and preimage is input to `insert`.
//! ** Construct a default preimage: [ACC, Fr2, …, FrB]
//! ** Use B bits to permute default preimage.
//! *** Interpret bits (perhaps reversed?) as follows:
//! **** If first bit is 1, swap first and second elements.
//! **** Then, if second bit is 1, swap first two elements with next two.
//! **** Then, if third bit is 1, swap first four elements with next four.
//! **** etc.
//! ** Set ACC = Hash(permuted preimage)

use bellperson::gadgets::boolean::Boolean;
use bellperson::gadgets::num::AllocatedNum;
use bellperson::{ConstraintSystem, SynthesisError};
use ff::Field;
use paired::Engine;

pub fn insert<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    element: &AllocatedNum<E>,
    bits: &[Boolean],
    elements: &[AllocatedNum<E>],
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
    let size = elements.len() + 1;
    assert_eq!(1 << bits.len(), size);

    let mut result = Vec::new();

    // Example choices, when insert x into [1, 2, 3]:

    let mut rows = Vec::new();
    for i in 0..size {
        // i     row
        // 0     x 1 2 3
        // 1     1 x 2 3
        // 2     1 2 x 3
        // 3     1 2 3 x
        let mut row = Vec::new();
        (0..i).for_each(|i| row.push(elements[i].clone()));
        row.push(element.clone());
        (i..elements.len()).for_each(|i| row.push(elements[i].clone()));

        rows.push(row);
    }
    for i in 0..size {
        // Reading columns,

        // 0     x 1 1 1
        // 1     1 x 2 2
        // 2     2 2 x 3
        // 3     3 3 3 x

        let mut choices = Vec::new();
        for j in 0..size {
            choices.push(rows[j][i].clone());
        }

        choices.iter().for_each(|c| {
            dbg!(&c.get_value());
        });

        result.push(select(
            cs.namespace(|| format!("choice {}", i)),
            &choices,
            bits,
        )?);
    }

    Ok(result)
}

pub fn select<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    from: &[AllocatedNum<E>],
    path_bits: &[Boolean],
) -> Result<AllocatedNum<E>, SynthesisError> {
    let pathlen = path_bits.len();
    assert_eq!(1 << pathlen, from.len());

    // Start with most-significant bit. If that is inconveneint for callers,
    // we can reverse here.

    let mut state = Vec::new();
    for elt in from {
        state.push(elt.clone())
    }
    let mut half_size = from.len() / 2;
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

/// Takes two allocated numbers (a, b) and returns
/// a if the condition is true, and b otherwise.
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
    use crate::circuit::test::*;
    use bellperson::gadgets::boolean::AllocatedBit;
    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_select() {
        let log_size = 2;
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

            let selected = select(cs.namespace(|| "select"), &elements, &path_bits).unwrap();

            assert_eq!(elements[index].get_value(), selected.get_value());
        }
    }

    #[test]
    fn test_insert() {
        let log_size = 1;
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

            let to_insert = AllocatedNum::<Bls12>::alloc(&mut cs.namespace(|| "insert"), || {
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

            let mut inserted = insert(
                &mut cs,
                &to_insert.clone(),
                index_bits.as_slice(),
                &elements.as_slice(),
            )
            .unwrap();

            let extracted = inserted.remove(index);

            assert_eq!(to_insert.get_value(), extracted.get_value(),);

            for i in 0..size - 1 {
                let a = elements[i].get_value();
                let b = inserted[i].get_value();

                assert_eq!(a, b)
            }
        }
    }
}
