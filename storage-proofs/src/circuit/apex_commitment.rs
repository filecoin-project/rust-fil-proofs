//! ApexCommitment
//!
//! ApexCommitment is a vector commitment which can be verified in a circuit more cheaply than a
//! merkle tree, provided that there will be many inclusion proofs, and that each element is likely
//! to be included in at least one proof.
//!
//! The name and interface reflect the intended purpose, as a replacement for the top (apex) of a merkle tree.
//! Instead of proving inclusion of a leaf within a singular root, prove the leaf is included in the apex commitment
//! at a given position. The 'position' is specified as the unused remainder of the merkle path once the merkle
//! inclusion proof has reached the apex row included in the commitment.
//!
//! A one-time hashing cost of all the values is amortized over cheaper individual inclusion proofs,
//! which require no hashing. See tests for more detail, but the short version is that each proof uses
//! a number of constraints which is exponential in the length of the elided path:
//! (2 * size + length) - 1 = (2^L + L) - 1.
//!
//! This sets an uppper bound on the size of the apex. When the cost of including another row in the apex
//! exceeds the cost (in constraints) of one hash, there's no potential savings. (Reference: 1 32-byte pedersen hash
//! requires ~1152 constraints).

use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::boolean::Boolean;
use fil_sapling_crypto::circuit::num;
use fil_sapling_crypto::circuit::num::AllocatedNum;
use fil_sapling_crypto::jubjub::JubjubEngine;

use crate::circuit::constraint;
use crate::circuit::pedersen::pedersen_md_no_padding;

pub trait ApexCommitment<E: JubjubEngine> {
    fn new(allocated_nums: &[AllocatedNum<E>]) -> Self;

    fn commit<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        allocated_nums: &[AllocatedNum<E>],
        params: &E::Params,
    ) -> Result<(Self, AllocatedNum<E>), SynthesisError>
    where
        Self: Sized,
    {
        // pedersen_md_no_padding requires at least two elements
        assert!(
            allocated_nums.len() > 1,
            "cannot commit only a single value"
        );
        let mut preimage_boolean = Vec::new();

        for (i, comm) in (&allocated_nums).iter().enumerate() {
            preimage_boolean
                .extend(comm.into_bits_le(cs.namespace(|| format!("preimage-bits-{}", i)))?);
            // sad padding is sad
            while preimage_boolean.len() % 256 != 0 {
                preimage_boolean.push(Boolean::Constant(false));
            }
        }

        // Calculate the pedersen hash.
        let computed_commitment = pedersen_md_no_padding(
            cs.namespace(|| "apex-commitment"),
            params,
            &preimage_boolean[..],
        )?;

        Ok((Self::new(allocated_nums), computed_commitment))
    }

    fn includes<A, AR, CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        annotation: A,
        num: &num::AllocatedNum<E>,
        path: &[Boolean],
    ) -> Result<(), SynthesisError>
    where
        A: FnOnce() -> AR,
        AR: Into<String>;
}

#[derive(Clone)]
pub enum BinaryApexCommitment<E: JubjubEngine> {
    Leaf(AllocatedNum<E>),
    Branch(Box<BinaryApexCommitment<E>>, Box<BinaryApexCommitment<E>>),
}

impl<E: JubjubEngine> ApexCommitment<E> for BinaryApexCommitment<E> {
    #[allow(dead_code)]
    fn new(allocated_nums: &[AllocatedNum<E>]) -> Self {
        let commitments = allocated_nums;

        let size = allocated_nums.len();
        assert!(size > 0, "BinaryCommitment must not be empty.");

        if size == 1 {
            return BinaryApexCommitment::Leaf(commitments[0].clone());
        }

        assert_eq!(
            size.count_ones(),
            1,
            "BinaryCommitment size must be a power of two."
        );

        let half_size = size / 2;
        let left = Self::new(&commitments[0..half_size]);
        let right = Self::new(&commitments[half_size..]);

        BinaryApexCommitment::Branch(Box::new(left), Box::new(right))
    }

    // Initial recursive implementation of `includes` which generates (too) many constraints.
    fn includes<A, AR, CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        annotation: A,
        num: &num::AllocatedNum<E>,
        path: &[Boolean],
    ) -> Result<(), SynthesisError>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let cs = &mut cs.namespace(|| "binary_commitment_inclusion");
        let num_at_path = self.at_path(cs, path)?;

        constraint::equal(cs, annotation, num, &num_at_path);
        Ok(())
    }
}

impl<E: JubjubEngine> BinaryApexCommitment<E> {
    fn at_path<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        path: &[Boolean],
    ) -> Result<AllocatedNum<E>, SynthesisError> {
        let length = path.len();

        match self {
            BinaryApexCommitment::Leaf(allocated_num) => {
                assert_eq!(length, 0, "Path too long for BinaryCommitment size.");

                Ok((*allocated_num).clone())
            }
            BinaryApexCommitment::Branch(left_boxed, right_boxed) => {
                assert!(length > 0, "Path too short for BinaryCommitment size.");
                let curr_is_right = &path[0];
                let cs = &mut cs.namespace(|| {
                    format!(
                        "path-{}",
                        if curr_is_right.get_value().unwrap() {
                            "1"
                        } else {
                            "0"
                        }
                    )
                });

                let (left, right) = match ((**left_boxed).clone(), (**right_boxed).clone()) {
                    (BinaryApexCommitment::Leaf(left), BinaryApexCommitment::Leaf(right)) => {
                        (left, right)
                    }
                    (left_comm, right_comm) => {
                        let next_path = &path[1..];
                        let left = left_comm.at_path(&mut cs.namespace(|| "left"), next_path)?;
                        let right = right_comm.at_path(&mut cs.namespace(|| "right"), next_path)?;
                        (left, right)
                    }
                };

                let (xl, _xr) = num::AllocatedNum::conditionally_reverse(
                    cs.namespace(|| "conditional reversal of BinaryCommitment elements"),
                    &left,
                    &right,
                    &curr_is_right,
                )?;

                Ok(xl)
            }
        }
    }
}

pub struct FlatApexCommitment<E: JubjubEngine> {
    allocated_nums: Vec<AllocatedNum<E>>,
}

impl<E: JubjubEngine> ApexCommitment<E> for FlatApexCommitment<E> {
    fn new(allocated_nums: &[AllocatedNum<E>]) -> Self {
        assert_eq!(allocated_nums.len().count_ones(), 1);
        FlatApexCommitment::<E> {
            allocated_nums: allocated_nums.to_vec(),
        }
    }

    fn includes<A, AR, CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        annotation: A,
        num: &num::AllocatedNum<E>,
        path: &[Boolean],
    ) -> Result<(), SynthesisError>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let size = self.allocated_nums.len();

        if path.is_empty() {
            assert_eq!(size, 1);

            constraint::equal(cs, annotation, num, &self.allocated_nums[0]);
            Ok(())
        } else {
            let reduced_size = size / 2; // Must divide evenly because size must be power of 2.
            let mut new_allocated = Vec::with_capacity(reduced_size);
            let curr_is_right = &path[0];
            let mut cs = &mut cs.namespace(|| {
                format!(
                    "path-{}",
                    if curr_is_right.get_value().unwrap() {
                        "1"
                    } else {
                        "0"
                    }
                )
            });

            for i in 0..reduced_size {
                let left = &self.allocated_nums[i];
                let right = &self.allocated_nums[i + reduced_size];
                let (xl, _xr) = num::AllocatedNum::conditionally_reverse(
                    cs.namespace(|| {
                        format!("conditional reversal of FlatCommitment elements ({})", i)
                    }),
                    &left,
                    &right,
                    &curr_is_right,
                )?;

                new_allocated.push(xl);
            }

            let reduced_apex = FlatApexCommitment::new(&new_allocated);

            reduced_apex.includes(&mut cs, annotation, num, &path[1..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::ConstraintSystem;
    use ff::ScalarEngine;
    use fil_sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
    use fil_sapling_crypto::circuit::num::AllocatedNum;
    use fil_sapling_crypto::jubjub::JubjubBls12;
    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::circuit::constraint;
    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto;
    use crate::fr32::fr_into_bytes;

    fn path_from_index<E: JubjubEngine, CS: ConstraintSystem<E>>(
        cs: &mut CS,
        index: usize,
        size: usize,
    ) -> Vec<Boolean> {
        let mut path = Vec::new();
        for i in 0..size {
            let boolean = <Boolean as std::convert::From<AllocatedBit>>::from(
                AllocatedBit::alloc(cs.namespace(|| format!("position bit {}", i)), {
                    let bit = ((index >> i) & 1) == 1;
                    Some(bit)
                })
                .unwrap(),
            );

            path.push(boolean);
        }
        // TODO: Can we avoid this reversal?
        path.reverse();

        path
    }

    fn test_apex_commitment_circuit<T: ApexCommitment<Bls12>>() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let max_len = 8;
        let params = JubjubBls12::new();

        for n in 1..max_len {
            let size = 1 << n;
            let mut outer_cs = TestConstraintSystem::<Bls12>::new();
            let mut nums = Vec::with_capacity(size);
            let mut bytes = Vec::<u8>::with_capacity(size);
            for i in 0..size {
                let val: <Bls12 as ScalarEngine>::Fr = rng.gen();
                let cs = &mut outer_cs.namespace(|| format!("num-{}", i));
                let num = AllocatedNum::alloc(cs, || Ok(val)).unwrap();

                bytes.extend(fr_into_bytes::<Bls12>(&val));
                nums.push(num);
            }

            let non_circuit_calculated_root =
                crypto::pedersen::pedersen_md_no_padding(bytes.as_slice());
            let allocated_root =
                AllocatedNum::alloc(outer_cs.namespace(|| "allocated_root"), || {
                    Ok(non_circuit_calculated_root)
                })
                .unwrap();

            let (bc, root) =
                T::commit(&mut outer_cs.namespace(|| "apex_commit"), &nums, &params).unwrap();

            constraint::equal(
                &mut outer_cs,
                //&mut outer_cs.namespace(|| "root check"),
                || "enforce roots are equal",
                &root,
                &allocated_root,
            );

            for (i, num) in nums.iter().enumerate() {
                let starting_constraints = outer_cs.num_constraints();
                {
                    let cs = &mut outer_cs.namespace(|| format!("test index {}", i));
                    let path = path_from_index(cs, i, n);

                    bc.includes(cs, || format!("apex inclusion check {}", i), num, &path)
                        .unwrap();
                }
                let num_constraints = outer_cs.num_constraints() - starting_constraints;
                // length, size: constraints
                //  0,   1: 1
                //  1,   2: 4
                //  2,   4: 9
                //  3,   8: 18
                //  4,  16: 35
                //  5,  32: 68
                //  6,  64: 133
                //  7, 128: 262
                //  This is (2 * size + length) - 1 = (2^L + L) - 1.
                let expected_inclusion_constraints = (2 * size + n) - 1;
                assert_eq!(num_constraints, expected_inclusion_constraints);
            }

            assert!(outer_cs.is_satisfied(), "constraints not satisfied");
        }
    }

    #[test]
    fn binary_commitment_circuit() {
        test_apex_commitment_circuit::<BinaryApexCommitment<Bls12>>();
    }

    #[test]
    fn flat_commitment_circuit() {
        test_apex_commitment_circuit::<FlatApexCommitment<Bls12>>();
    }

}
