use bellperson::gadgets::{
    boolean::Boolean,
    sha256::sha256 as sha256_circuit,
    {multipack, num},
};
use bellperson::{ConstraintSystem, SynthesisError};
use ff::PrimeField;
use fil_sapling_crypto::jubjub::JubjubEngine;

use crate::gadgets::uint64;

use super::super::vanilla::TOTAL_PARENTS;

/// Compute a single label.
pub fn create_label_circuit<E, CS>(
    mut cs: CS,
    replica_id: &[Boolean],
    parents: Vec<Vec<Boolean>>,
    node: uint64::UInt64,
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    assert!(replica_id.len() <= 256, "replica id is too large");
    assert_eq!(parents.len(), TOTAL_PARENTS, "invalid sized parents");

    // ciphertexts will become a buffer of the layout
    // id | node | parent_node_0 | parent_node_1 | ...

    let mut ciphertexts = replica_id.to_vec();

    // pad to 32 bytes
    while ciphertexts.len() < 256 {
        ciphertexts.push(Boolean::constant(false));
    }

    ciphertexts.extend_from_slice(&node.to_bits_be());
    // pad to 64 bytes
    while ciphertexts.len() < 512 {
        ciphertexts.push(Boolean::constant(false));
    }

    for parent in parents.iter() {
        ciphertexts.extend_from_slice(parent);

        // pad such that each parents take 32 bytes
        while ciphertexts.len() % 256 != 0 {
            ciphertexts.push(Boolean::constant(false));
        }
    }

    // 32b replica id
    // 32b node
    // 37 * 32b  = 1184b parents
    assert_eq!(ciphertexts.len(), (1 + 1 + TOTAL_PARENTS) * 32 * 8);

    // Compute Sha256
    let alloc_bits = sha256_circuit(cs.namespace(|| "hash"), &ciphertexts[..])?;

    // Convert the hash result into a single Fr.
    let fr = if alloc_bits[0].get_value().is_some() {
        let be_bits = alloc_bits
            .iter()
            .map(|v| v.get_value().ok_or(SynthesisError::AssignmentMissing))
            .collect::<Result<Vec<bool>, SynthesisError>>()?;

        let le_bits = be_bits
            .chunks(8)
            .flat_map(|chunk| chunk.iter().rev())
            .copied()
            .take(E::Fr::CAPACITY as usize)
            .collect::<Vec<bool>>();

        Ok(multipack::compute_multipacking::<E>(&le_bits)[0])
    } else {
        Err(SynthesisError::AssignmentMissing)
    };

    num::AllocatedNum::<E>::alloc(cs.namespace(|| "result_num"), || fr)
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::super::vanilla::{StackedBucketGraph, EXP_DEGREE, TOTAL_PARENTS};
    use crate::drgraph::{new_seed, Graph, BASE_DEGREE};
    use crate::fr32::{bytes_into_fr, fr_into_bytes};
    use crate::gadgets::TestConstraintSystem;
    use crate::hasher::Sha256Hasher;
    use crate::util::bytes_into_boolean_vec_be;
    use crate::util::{data_at_node, NODE_SIZE};

    use bellperson::gadgets::boolean::Boolean;
    use bellperson::ConstraintSystem;
    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_create_label() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let size = 64;

        let graph = StackedBucketGraph::<Sha256Hasher>::new_stacked(
            size,
            BASE_DEGREE,
            EXP_DEGREE,
            new_seed(),
        )
        .unwrap();

        let id_fr = Fr::random(rng);
        let id: Vec<u8> = fr_into_bytes::<Bls12>(&id_fr);
        let node = 22;

        let mut data: Vec<u8> = (0..2 * size)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let mut parents = vec![0; BASE_DEGREE + EXP_DEGREE];
        graph.parents(node, &mut parents).unwrap();

        let raw_parents_bytes: Vec<Vec<u8>> = parents
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if i < BASE_DEGREE {
                    // base
                    data_at_node(&data[..size * NODE_SIZE], *p as usize)
                        .unwrap()
                        .to_vec()
                } else {
                    // exp
                    data_at_node(&data[size * NODE_SIZE..], *p as usize)
                        .unwrap()
                        .to_vec()
                }
            })
            .collect();

        let mut parents_bytes = raw_parents_bytes.clone(); // 14
        parents_bytes.extend_from_slice(&raw_parents_bytes); // 28
        parents_bytes.extend_from_slice(&raw_parents_bytes[..9]); // 37

        assert_eq!(parents_bytes.len(), TOTAL_PARENTS);
        let parents_bits: Vec<Vec<Boolean>> = parents_bytes
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut cs = cs.namespace(|| format!("parents {}", i));
                bytes_into_boolean_vec_be(&mut cs, Some(p), p.len()).unwrap()
            })
            .collect();

        let id_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "id");
            bytes_into_boolean_vec_be(&mut cs, Some(id.as_slice()), id.len()).unwrap()
        };

        let node_alloc = uint64::UInt64::constant(node as u64);

        let out = create_label_circuit(
            cs.namespace(|| "create_label"),
            &id_bits,
            parents_bits.clone(),
            node_alloc,
        )
        .expect("key derivation function failed");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 532_024);

        let (l1, l2) = data.split_at_mut(size * NODE_SIZE);
        super::super::super::vanilla::create_label_exp(&graph, &id_fr.into(), &*l2, l1, node)
            .unwrap();
        let expected_raw = data_at_node(&l1, node).unwrap();
        let expected = bytes_into_fr::<Bls12>(expected_raw).unwrap();

        assert_eq!(
            expected,
            out.get_value().unwrap(),
            "circuit and non circuit do not match"
        );
    }
}
