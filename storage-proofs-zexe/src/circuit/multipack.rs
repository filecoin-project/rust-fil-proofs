use algebra::fields::{Field, PrimeField};
use algebra::PairingEngine as Engine;
use dpc::gadgets::Assignment;
use snark::{ConstraintSystem, LinearCombination, SynthesisError};
use snark_gadgets::boolean::Boolean;
use snark_gadgets::fields::fp::FpGadget;

use algebra::fields::FpParameters;
use snark_gadgets::fields::FieldGadget;
use snark_gadgets::utils::AllocGadget;
use std::ops::AddAssign;
use std::ops::Mul;

/// Takes a sequence of booleans and exposes them as compact
/// public inputs
pub fn pack_into_inputs<E, CS>(mut cs: CS, bits: &[Boolean]) -> Result<(), SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    for (i, bits) in bits
        .chunks(<E::Fr as PrimeField>::Params::CAPACITY as usize)
        .enumerate()
    {
        let mut lc = LinearCombination::<E>::zero();
        let mut coeff = E::Fr::one();
        let mut acc = E::Fr::zero();
        let one = CS::one();

        for b in bits {
            let value = b.get_value();
            let fr = match value.get() {
                Ok(v) => {
                    if *v {
                        Some(E::Fr::one())
                    } else {
                        Some(E::Fr::zero())
                    }
                },
                Err(e) => None,
            };

            lc = lc + b.lc(one, coeff);
            
            if let Some(x) = &fr.map(|v| v.mul(&coeff)) {
                acc += x;
            }

            coeff.double_in_place();
        }

        let input = FpGadget::alloc_input(cs.ns(|| format!("input {}", i)), || Ok(acc))?;

        lc = &input.variable - lc;
        cs.enforce(
            || format!("packing constraint {}", i),
            |lc| lc,
            |lc| lc,
            |_| lc,
        );
    }

    Ok(())
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&v| (0..8).rev().map(move |i| (v >> i) & 1 == 1))
        .collect()
}

pub fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&v| (0..8).map(move |i| (v >> i) & 1 == 1))
        .collect()
}

pub fn compute_multipacking<E: Engine>(bits: &[bool]) -> Vec<E::Fr> {
    let mut result = vec![];

    for bits in bits.chunks(<E::Fr as PrimeField>::Params::CAPACITY as usize) {
        let mut cur = E::Fr::zero();
        let mut coeff = E::Fr::one();

        for bit in bits {
            if *bit {
                cur.add_assign(&coeff);
            }

            coeff.double_in_place();
        }

        result.push(cur);
    }

    result
}

#[test]
fn test_multipacking() {
    use super::test::*;
    use algebra::curves::bls12_381::Bls12_381 as Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use snark::ConstraintSystem;
    use snark_gadgets::bits::boolean::{AllocatedBit, Boolean};

    let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for num_bits in (0..1500).into_iter().step_by(100) {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let bits: Vec<bool> = (0..num_bits).map(|_| rng.gen()).collect();

        let circuit_bits = bits
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                Boolean::from(
                    AllocatedBit::alloc(cs.ns(|| format!("bit {}", i)), || Ok(b)).unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let expected_inputs = compute_multipacking::<Bls12>(&bits);

        pack_into_inputs(cs.ns(|| "pack"), &circuit_bits).unwrap();

        assert!(cs.is_satisfied());
        assert!(cs.verify(&expected_inputs));
    }
}
