//! Insertion Permutation
//!
//! Insert an `AllocatedNum` into a sequence of `AllocatedNums` at an arbitrary position.
//! This can be thought of as a generalization of `AllocatedNum::conditionally_reverse` and reduces to it in the binary case.

use bellperson::gadgets::boolean::{AllocatedBit, Boolean};
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

    // For the sizes we know we need, we can take advantage of redundancy in the candidate selection at each position.
    // This allows us to accomplish insertion with fewer constraints, if we hand-optimize.
    // We don't need a special case for size 2 because the general algorithm
    // collapses to `conditionally_reverse` when size = 2.
    //
    // If no special cases have been hand-coded, use the general algorithm.
    // This costs size * (size - 1) constraints.
    //
    // Future work: In theory, we could compile arbitrary lookup tables to minimize constraints and avoid
    // the most general case except when actually required — which it never is for simple insertion.
    if size == 2 {
        return insert_2(cs, element, bits, elements);
    } else if size == 4 {
        return insert_4(cs, element, bits, elements);
    } else if size == 8 {
        return insert_8(cs, element, bits, elements);
    };

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

pub fn insert_2<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    element: &AllocatedNum<E>,
    bits: &[Boolean],
    elements: &[AllocatedNum<E>],
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
    assert_eq!(elements.len() + 1, 2);
    assert_eq!(bits.len(), 1);

    Ok(vec![
        pick(
            cs.namespace(|| "binary insert 0"),
            &bits[0],
            &elements[0],
            &element,
        )?,
        pick(
            cs.namespace(|| "binary insert 1"),
            &bits[0],
            &element,
            &elements[0],
        )?,
    ])
}

pub fn insert_4<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    element: &AllocatedNum<E>,
    bits: &[Boolean],
    elements: &[AllocatedNum<E>],
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
    assert_eq!(elements.len() + 1, 4);
    assert_eq!(bits.len(), 2);

    /*
    To insert A into [b, c, d] at position n of bits, represented by booleans [b0, b1, b2].
    n [b0, b1] pos 0 1 2 3
    0 [0, 0]       A b c d
    1 [1, 0]       b A c d
    2 [0, 1]       b c A d
    3 [1, 1]       b c d A

    A = element
    b = elements[0]
    c = elements[1]
    d = elements[2]
     */
    let (b0, b1) = (&bits[0], &bits[1]);
    let (a, b, c, d) = (&element, &elements[0], &elements[1], &elements[2]);

    /// Define witness macro to allow legible definition of positional constraints.
    /// See example expansions in comment to first usages below.
    macro_rules! witness {
        ( $var:ident <== if $cond:ident { $a:expr } else { $b:expr }) => {
            let $var = pick(cs.namespace(|| stringify!($var)), $cond, $a, $b)?;
        };
    }

    // Witness naming convention:
    // `p0_x0` means "Output position 0 when b0 is unknown (x) and b1 is 0."

    // Declaration:
    witness!(p0_x0 <== if b0 { b } else { a });
    witness!(p0 <== if b1 { b } else { &p0_x0 });
    // Expansion:
    // let p0_x0 = pick(cs.namespace(|| "p0_x0"), b0, b, a)?;
    // let p0 = pick(cs.namespace(|| "p0"), b1, b, &p0_x0)?;

    witness!(p1_x0 <== if b0 { a } else { b });
    witness!(p1 <== if b1 { c } else { &p1_x0 });

    witness!(p2_x1 <== if b0 { d } else { a });
    witness!(p2 <== if b1 { &p2_x1 } else {c });

    witness!(p3_x1 <== if b0 { a } else { d });
    witness!(p3 <== if b1 { &p3_x1 } else { d });

    Ok(vec![p0, p1, p2, p3])
}

#[allow(clippy::many_single_char_names)]
pub fn insert_8<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    element: &AllocatedNum<E>,
    bits: &[Boolean],
    elements: &[AllocatedNum<E>],
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
    assert_eq!(elements.len() + 1, 8);
    assert_eq!(bits.len(), 3);
    /*
    To insert A into [b, c, d, e, f, g, h] at position n of bits, represented by booleans [b0, b1, b2].
    n [b0, b1, b2] pos 0 1 2 3 4 5 6 7
    0 [0, 0, 0]        A b c d e f g h
    1 [1, 0, 0]        b A c d e f g h
    2 [0, 1, 0]        b c A d e f g h
    3 [1, 1, 0]        b c d A e f g h
    4 [0, 0, 1]        b c d e A f g h
    5 [1, 0, 1]        b c d e f A g h
    6 [0, 1, 1]        b c d e f g A h
    7 [1, 1, 1]        b c d e f g h A


    A = element
    b = elements[0]
    c = elements[1]
    d = elements[2]
    e = elements[3]
    f = elements[4]
    g = elements[5]
    h = elements[6]
     */

    let (b0, b1, b2) = (&bits[0], &bits[1], &bits[2]);
    let (a, b, c, d, e, f, g, h) = (
        &element,
        &elements[0],
        &elements[1],
        &elements[2],
        &elements[3],
        &elements[4],
        &elements[5],
        &elements[6],
    );

    // true if booleans b0 and b1 are both false: `(not b0) and (not b1)`
    // (1 - b0) * (1 - b1) = 1
    let b0_nor_b1 = match (b0, b1) {
        (Boolean::Is(ref b0), Boolean::Is(ref b1)) => {
            Boolean::Is(AllocatedBit::nor(cs.namespace(|| "b0 nor b1"), b0, b1)?)
        }
        _ => panic!("bits must be allocated and unnegated"),
    };

    // true if booleans b0 and b1 are both true: `b0 and b1`
    // b0 * b1 = 1
    let b0_and_b1 = match (&bits[0], &bits[1]) {
        (Boolean::Is(ref b0), Boolean::Is(ref b1)) => {
            Boolean::Is(AllocatedBit::and(cs.namespace(|| "b0 and b1"), b0, b1)?)
        }
        _ => panic!("bits must be allocated and unnegated"),
    };

    /// Define witness macro to allow legible definition of positional constraints.
    /// See example expansions in comment to first usages below.
    macro_rules! witness {
        ( $var:ident <== if $cond:ident { $a:expr } else { $b:expr }) => {
            let $var = pick(cs.namespace(|| stringify!($var)), $cond, $a, $b)?;
        };

        // Match condition terms which are explict syntactic references.
        ( $var:ident <== if &$cond:ident { $a:expr } else { $b:expr }) => {
            let $var = pick(cs.namespace(|| stringify!($var)), &$cond, $a, $b)?;
        };
    }

    // Declaration:
    witness!(p0_xx0 <== if &b0_nor_b1 { a } else { b });
    witness!(p0 <== if b2 { b } else { &p0_xx0 });
    // Expansion:
    // let p0_xx0 = pick(cs.namespace(|| "p0_xx0"), &b0_nor_b1, a, b)?;
    // let p0 = pick(cs.namespace(|| "p0"), b2, b, &p0_xx0)?;

    witness!(p1_x00 <== if b0 { a } else { b });
    witness!(p1_xx0 <== if b1 { c } else { &p1_x00 });
    witness!(p1 <== if b2 { c } else { &p1_xx0 });

    witness!(p2_x10 <== if b0 { d } else { a });
    witness!(p2_xx0 <== if b1 { &p2_x10 } else { c });
    witness!(p2 <== if b2 { d } else { &p2_xx0 });

    witness!(p3_xx0 <== if &b0_and_b1 { a } else { d });
    witness!(p3 <== if b2 { e } else { &p3_xx0 });

    witness!(p4_xx1 <== if &b0_nor_b1 { a } else { f });
    witness!(p4 <== if b2 { &p4_xx1 } else { e });

    witness!(p5_x01 <== if b0 { a } else { f });
    witness!(p5_xx1 <== if b1 { g } else { &p5_x01 });
    witness!(p5 <== if b2 { &p5_xx1 } else { f });

    witness!(p6_x11 <== if b0 { h } else { a });
    witness!(p6_xx1 <== if b1 { &p6_x11 } else { g });
    witness!(p6 <== if b2 { &p6_xx1 } else { g });

    witness!(p7_xx1 <== if &b0_and_b1 { a } else { h });
    witness!(p7 <== if b2 { &p7_xx1 } else { h });

    Ok(vec![p0, p1, p2, p3, p4, p5, p6, p7])
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

    // Constrain (b - a) * condition = (b - c), ensuring c = a iff
    // condition is true, otherwise c = b.
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

    use bellperson::gadgets::boolean::AllocatedBit;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
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
        for log_size in 1..=4 {
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
                        let elt_to_insert = <Fr as Field>::random(rng);
                        Ok(elt_to_insert)
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
                let expected_constraints = match size {
                    8 => 22, // unoptimized, would be 56
                    4 => 8,  // unoptimized, would be 12
                    _ => size * (size - 1),
                };

                let actual_constraints = cs.num_constraints() - test_constraints;
                assert_eq!(expected_constraints, actual_constraints);
            }
        }
    }
}
