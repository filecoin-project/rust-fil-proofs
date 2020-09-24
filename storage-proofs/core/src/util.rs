use crate::error;
use anyhow::ensure;
use bellperson::gadgets::boolean::{self, AllocatedBit, Boolean};
use bellperson::{bls::Engine, ConstraintSystem, SynthesisError};
use merkletree::merkle::get_merkle_tree_row_count;

use super::settings;

pub const NODE_SIZE: usize = 32;

/// Returns the start position of the data, 0-indexed.
pub fn data_at_node_offset(v: usize) -> usize {
    v * NODE_SIZE
}

/// Returns the byte slice representing one node (of uniform size, NODE_SIZE) at position v in data.
pub fn data_at_node(data: &[u8], v: usize) -> error::Result<&[u8]> {
    let offset = data_at_node_offset(v);

    ensure!(
        offset + NODE_SIZE <= data.len(),
        error::Error::OutOfBounds(offset + NODE_SIZE, data.len())
    );

    Ok(&data[offset..offset + NODE_SIZE])
}

/// Converts bytes into their bit representation, in little endian format.
pub fn bytes_into_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
        .collect()
}

/// Converts bytes into their bit representation, in little endian format.
pub fn bytes_into_bits_opt(bytes: &[u8]) -> Vec<Option<bool>> {
    bytes
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| Some((byte >> i) & 1u8 == 1u8)))
        .collect()
}

/// Converts bytes into their bit representation, in big endian format.
pub fn bytes_into_bits_be(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
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

/// Converts the bytes into a boolean vector, in big endian format.
pub fn bytes_into_boolean_vec_be<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    value: Option<&[u8]>,
    size: usize,
) -> Result<Vec<boolean::Boolean>, SynthesisError> {
    let values = match value {
        Some(value) => bytes_into_bits_be(value).into_iter().map(Some).collect(),
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

/// Reverse the order of bits within each byte (bit numbering), but without altering the order of bytes
/// within the array (endianness) — when bit array is viewed as a flattened sequence of octets.
/// Before intra-byte bit reversal begins, zero-bit padding is added so every byte is full.
pub fn reverse_bit_numbering(bits: Vec<boolean::Boolean>) -> Vec<boolean::Boolean> {
    let mut padded_bits = bits;
    // Pad partial bytes
    while padded_bits.len() % 8 != 0 {
        padded_bits.push(boolean::Boolean::Constant(false));
    }

    padded_bits
        .chunks(8)
        .map(|chunk| chunk.iter().rev())
        .flatten()
        .cloned()
        .collect()
}

// If the tree is large enough to use the default value (per-arity), use it.  If it's too small to cache anything (i.e. not enough rows), don't discard any.
pub fn default_rows_to_discard(leafs: usize, arity: usize) -> usize {
    let row_count = get_merkle_tree_row_count(leafs, arity);
    if row_count <= 2 {
        // If a tree only has a root row and/or base, there is
        // nothing to discard.
        return 0;
    } else if row_count == 3 {
        // If a tree only has 1 row between the base and root,
        // it's all that can be discarded.
        return 1;
    }

    // row_count - 2 discounts the base layer (1) and root (1)
    let max_rows_to_discard = row_count - 2;

    // This configurable setting is for a default oct-tree
    // rows_to_discard value, which defaults to 2.
    let rows_to_discard = settings::SETTINGS.rows_to_discard as usize;

    // Discard at most 'constant value' rows (coded below,
    // differing by arity) while respecting the max number that
    // the tree can support discarding.
    match arity {
        2 => std::cmp::min(max_rows_to_discard, 7),
        4 => std::cmp::min(max_rows_to_discard, 5),
        _ => std::cmp::min(max_rows_to_discard, rows_to_discard),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fr32::fr_into_bytes;
    use bellperson::bls::*;
    use bellperson::gadgets::num;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use ff::Field;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_bytes_into_boolean_vec() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for i in 0..100 {
            let data: Vec<u8> = (0..i + 10).map(|_| rng.gen()).collect();
            let bools = {
                let mut cs = cs.namespace(|| format!("round: {}", i));
                bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), 8)
                    .expect("bytes into boolean vec failure")
            };

            let bytes_actual: Vec<u8> = bits_to_bytes(
                bools
                    .iter()
                    .map(|b| b.get_value().expect("get_value failure"))
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

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for i in 10..100 {
            let bytes: Vec<u8> = (0..i).map(|_| rng.gen()).collect();

            let bits = bytes_into_bits(bytes.as_slice());
            assert_eq!(bits_to_bytes(bits.as_slice()), bytes);
        }
    }

    #[test]
    fn test_reverse_bit_numbering() {
        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

            let val_fr = Fr::random(rng);
            let val_vec = fr_into_bytes(&val_fr);

            let val_num = num::AllocatedNum::alloc(cs.namespace(|| "val_num"), || Ok(val_fr))
                .expect("alloc failure");
            let val_num_bits = val_num
                .to_bits_le(cs.namespace(|| "val_bits"))
                .expect("to_bits_le failure");

            let bits =
                bytes_into_boolean_vec_be(cs.namespace(|| "val_bits_2"), Some(&val_vec), 256)
                    .expect("bytes_into_boolean_vec_be failure");

            let val_num_reversed_bit_numbering = reverse_bit_numbering(val_num_bits);

            let a_values: Vec<bool> = val_num_reversed_bit_numbering
                .iter()
                .map(|v| v.get_value().expect("get_value failure"))
                .collect();

            let b_values: Vec<bool> = bits
                .iter()
                .map(|v| v.get_value().expect("get_value failure"))
                .collect();
            assert_eq!(&a_values[..], &b_values[..]);
        }
    }
}
