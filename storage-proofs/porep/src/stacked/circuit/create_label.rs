use bellperson::gadgets::{boolean::Boolean, num, sha256::sha256 as sha256_circuit, uint32};
use bellperson::{bls::Engine, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use storage_proofs_core::{gadgets::multipack, gadgets::uint64, util::reverse_bit_numbering};

use crate::stacked::vanilla::TOTAL_PARENTS;

/// Compute a single label.
pub fn create_label_circuit<E, CS>(
    mut cs: CS,
    replica_id: &[Boolean],
    parents: Vec<Vec<Boolean>>,
    layer_index: uint32::UInt32,
    node: uint64::UInt64,
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    assert!(replica_id.len() >= 32, "replica id is too small");
    assert!(replica_id.len() <= 256, "replica id is too large");
    assert_eq!(parents.len(), TOTAL_PARENTS, "invalid sized parents");

    // ciphertexts will become a buffer of the layout
    // id | node | parent_node_0 | parent_node_1 | ...

    let mut ciphertexts = replica_id.to_vec();

    // pad to 32 bytes
    while ciphertexts.len() < 256 {
        ciphertexts.push(Boolean::constant(false));
    }

    ciphertexts.extend_from_slice(&layer_index.into_bits_be());
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
    // 32b layer_index + node
    // 37 * 32b  = 1184b parents
    assert_eq!(ciphertexts.len(), (1 + 1 + TOTAL_PARENTS) * 32 * 8);

    // Compute Sha256
    let alloc_bits = sha256_circuit(cs.namespace(|| "hash"), &ciphertexts[..])?;

    // Convert the hash result into a single Fr.
    let bits = reverse_bit_numbering(alloc_bits);
    multipack::pack_bits(
        cs.namespace(|| "result_num"),
        &bits[0..(E::Fr::CAPACITY as usize)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::bls::{Bls12, Fr};
    use bellperson::gadgets::boolean::Boolean;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use ff::Field;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        drgraph::{Graph, BASE_DEGREE},
        fr32::{bytes_into_fr, fr_into_bytes},
        hasher::Sha256Hasher,
        util::bytes_into_boolean_vec_be,
        util::{data_at_node, NODE_SIZE},
    };

    use crate::stacked::vanilla::{create_label, StackedBucketGraph, EXP_DEGREE, TOTAL_PARENTS};

    #[test]
    fn test_create_label() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let size = 64;
        let porep_id = [32; 32];

        let graph = StackedBucketGraph::<Sha256Hasher>::new_stacked(
            size,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
        )
        .unwrap();

        let id_fr = Fr::random(rng);
        let id: Vec<u8> = fr_into_bytes(&id_fr);
        let layer = 3;
        let node = 22;

        let mut data: Vec<u8> = (0..2 * size)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
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

        let layer_alloc = uint32::UInt32::constant(layer as u32);
        let node_alloc = uint64::UInt64::constant(node as u64);

        let out = create_label_circuit(
            cs.namespace(|| "create_label"),
            &id_bits,
            parents_bits,
            layer_alloc,
            node_alloc,
        )
        .expect("key derivation function failed");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 532_025);

        let (l1, l2) = data.split_at_mut(size * NODE_SIZE);
        create_label::single::create_label_exp(
            &graph,
            None,
            fr_into_bytes(&id_fr),
            &*l2,
            l1,
            layer,
            node,
        )
        .unwrap();

        let expected_raw = data_at_node(&l1, node).unwrap();
        let expected = bytes_into_fr(expected_raw).unwrap();

        assert_eq!(
            expected,
            out.get_value().unwrap(),
            "circuit and non circuit do not match"
        );
    }
}
