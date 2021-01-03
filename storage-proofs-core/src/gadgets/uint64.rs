use bellperson::gadgets::boolean::{AllocatedBit, Boolean};
use bellperson::gadgets::multipack::pack_into_inputs;
use bellperson::{bls::Engine, ConstraintSystem, SynthesisError};

/// Represents an interpretation of 64 `Boolean` objects as an unsigned integer.
#[derive(Clone)]
pub struct UInt64 {
    // Least significant bit first
    bits: Vec<Boolean>,
    value: Option<u64>,
}

impl UInt64 {
    /// Construct a constant `UInt64` from a `u64`
    pub fn constant(value: u64) -> Self {
        let mut bits = Vec::with_capacity(64);

        let mut tmp = value;
        for _ in 0..64 {
            if tmp & 1 == 1 {
                bits.push(Boolean::constant(true))
            } else {
                bits.push(Boolean::constant(false))
            }

            tmp >>= 1;
        }

        UInt64 {
            bits,
            value: Some(value),
        }
    }

    pub fn get_value(&self) -> Option<u64> {
        self.value
    }

    pub fn pack_into_input<E, CS>(&self, cs: CS) -> Result<(), SynthesisError>
    where
        E: Engine,
        CS: ConstraintSystem<E>,
    {
        pack_into_inputs(cs, &self.bits)
    }

    /// Allocate a `UInt64` in the constraint system
    pub fn alloc<E, CS>(mut cs: CS, value: Option<u64>) -> Result<Self, SynthesisError>
    where
        E: Engine,
        CS: ConstraintSystem<E>,
    {
        let values = match value {
            Some(mut val) => {
                let mut v = Vec::with_capacity(64);

                for _ in 0..64 {
                    v.push(Some(val & 1 == 1));
                    val >>= 1;
                }

                v
            }
            None => vec![None; 64],
        };

        let bits = values
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                Ok(Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("allocated bit {}", i)),
                    v,
                )?))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        Ok(UInt64 { bits, value })
    }

    pub fn to_bits_be(&self) -> Vec<Boolean> {
        self.bits.iter().rev().cloned().collect()
    }

    pub fn from_bits_be(bits: &[Boolean]) -> Self {
        assert_eq!(bits.len(), 64);

        let mut value = Some(0u64);
        for b in bits {
            if let Some(v) = value.as_mut() {
                *v <<= 1;
            }

            match b.get_value() {
                Some(true) => {
                    if let Some(v) = value.as_mut() {
                        *v |= 1;
                    }
                }
                Some(false) => {}
                None => {
                    value = None;
                }
            }
        }

        UInt64 {
            value,
            bits: bits.iter().rev().cloned().collect(),
        }
    }

    /// Turns this `UInt64` into its little-endian byte order representation.
    pub fn to_bits_le(&self) -> Vec<Boolean> {
        self.bits.clone()
    }

    /// Converts a little-endian byte order representation of bits into a
    /// `UInt64`.
    pub fn from_bits(bits: &[Boolean]) -> Self {
        assert_eq!(bits.len(), 64);

        let new_bits = bits.to_vec();

        let mut value = Some(0u64);
        for b in new_bits.iter().rev() {
            if let Some(v) = value.as_mut() {
                *v <<= 1;
            }

            match *b {
                Boolean::Constant(b) => {
                    if b {
                        if let Some(v) = value.as_mut() {
                            *v |= 1
                        }
                    }
                }
                Boolean::Is(ref b) => match b.get_value() {
                    Some(true) => {
                        if let Some(v) = value.as_mut() {
                            *v |= 1;
                        }
                    }
                    Some(false) => {}
                    None => value = None,
                },
                Boolean::Not(ref b) => match b.get_value() {
                    Some(false) => {
                        if let Some(v) = value.as_mut() {
                            *v |= 1;
                        }
                    }
                    Some(true) => {}
                    None => value = None,
                },
            }
        }

        UInt64 {
            value,
            bits: new_bits,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_uint64_from_bits_be() {
        let mut rng = XorShiftRng::from_seed(crate::TEST_SEED);

        for _ in 0..1000 {
            let v = (0..64)
                .map(|_| Boolean::constant(rng.gen()))
                .collect::<Vec<_>>();

            let b = UInt64::from_bits_be(&v);

            for (i, bit) in b.bits.iter().enumerate() {
                match *bit {
                    Boolean::Constant(bit) => {
                        assert!(bit == ((b.value.unwrap() >> i) & 1 == 1));
                    }
                    _ => unreachable!(),
                }
            }

            let expected_to_be_same = b.to_bits_be();

            for x in v.iter().zip(expected_to_be_same.iter()) {
                match x {
                    (&Boolean::Constant(true), &Boolean::Constant(true)) => {}
                    (&Boolean::Constant(false), &Boolean::Constant(false)) => {}
                    _ => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn test_uint64_from_bits() {
        let mut rng = XorShiftRng::from_seed(crate::TEST_SEED);

        for _ in 0..1000 {
            let v = (0..64)
                .map(|_| Boolean::constant(rng.gen()))
                .collect::<Vec<_>>();

            let b = UInt64::from_bits(&v);

            for (i, bit) in b.bits.iter().enumerate() {
                match *bit {
                    Boolean::Constant(bit) => {
                        assert!(bit == ((b.value.unwrap() >> i) & 1 == 1));
                    }
                    _ => unreachable!(),
                }
            }

            let expected_to_be_same = b.to_bits_le();

            for x in v.iter().zip(expected_to_be_same.iter()) {
                match x {
                    (&Boolean::Constant(true), &Boolean::Constant(true)) => {}
                    (&Boolean::Constant(false), &Boolean::Constant(false)) => {}
                    _ => unreachable!(),
                }
            }
        }
    }
}
