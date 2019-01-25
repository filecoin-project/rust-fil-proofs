use bellman::{ConstraintSystem, SynthesisError};
use pairing::Engine;
use sapling_crypto::circuit::boolean::{self, AllocatedBit, Boolean};

use crate::error;

pub const NODE_SIZE: usize = 32;

/// Returns the start position of the data, 0-indexed.
pub fn data_at_node_offset(v: usize) -> usize {
    v * NODE_SIZE
}

/// Returns the byte slice representing one node (of uniform size, NODE_SIZE) at position v in data.
pub fn data_at_node(data: &[u8], v: usize) -> error::Result<&[u8]> {
    let offset = data_at_node_offset(v);

    if offset + NODE_SIZE > data.len() {
        return Err(error::Error::OutOfBounds(offset + NODE_SIZE, data.len()));
    }

    Ok(&data[offset..offset + NODE_SIZE])
}

/// Converts bytes into their bit representation, in little endian format.
pub fn bytes_into_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
        .collect()
}

/// Converts the bytes into a boolean vector, in little endian format.
pub fn bytes_into_boolean_vec<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    value: Option<&[u8]>,
    size: usize,
) -> Result<Vec<boolean::Boolean>, SynthesisError> {
    let values = match value {
        Some(value) => bytes_into_bits(value).into_iter().map(Some).collect(),
        None => vec![None; size],
    };

    let bits = values
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            Ok(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("bit {}", i)),
                b,
            )?))
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
}

#[allow(dead_code)]
#[inline]
fn bool_to_u8(bit: bool, offset: usize) -> u8 {
    if bit {
        1u8 << offset
    } else {
        0u8
    }
}

/// Converts a slice of bools into their byte representation, in little endian.
#[allow(dead_code)]
pub fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|bits| {
            bool_to_u8(bits[7], 7)
                | bool_to_u8(bits[6], 6)
                | bool_to_u8(bits[5], 5)
                | bool_to_u8(bits[4], 4)
                | bool_to_u8(bits[3], 3)
                | bool_to_u8(bits[2], 2)
                | bool_to_u8(bits[1], 1)
                | bool_to_u8(bits[0], 0)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::test::*;
    use pairing::bls12_381::*;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_bytes_into_boolean_vec() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 0..100 {
            let data: Vec<u8> = (0..i + 10).map(|_| rng.gen()).collect();
            let bools = {
                let mut cs = cs.namespace(|| format!("round: {}", i));
                bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), 8).unwrap()
            };

            let bytes_actual: Vec<u8> = bits_to_bytes(
                bools
                    .iter()
                    .map(|b| b.get_value().unwrap())
                    .collect::<Vec<bool>>()
                    .as_slice(),
            );

            assert_eq!(data, bytes_actual);
        }
    }

    #[test]
    fn test_bool_to_u8() {
        assert_eq!(bool_to_u8(false, 2), 0b0000_0000);
        assert_eq!(bool_to_u8(true, 0), 0b0000_0001);
        assert_eq!(bool_to_u8(true, 1), 0b0000_0010);
        assert_eq!(bool_to_u8(true, 7), 0b1000_0000);
    }

    #[test]
    fn test_bits_into_bytes() {
        assert_eq!(
            bits_to_bytes(&[true, false, false, false, false, false, false, false]),
            vec![1]
        );
        assert_eq!(
            bits_to_bytes(&[true, true, true, true, true, true, true, true]),
            vec![255]
        );
    }

    #[test]
    fn test_bytes_into_bits() {
        assert_eq!(
            bytes_into_bits(&[1u8]),
            vec![true, false, false, false, false, false, false, false]
        );

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 10..100 {
            let bytes: Vec<u8> = (0..i).map(|_| rng.gen()).collect();

            let bits = bytes_into_bits(bytes.as_slice());
            assert_eq!(bits_to_bytes(bits.as_slice()), bytes);
        }
    }
}
