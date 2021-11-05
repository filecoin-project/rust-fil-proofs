use bellperson::{
    bls::Engine,
    gadgets::{
        boolean::Boolean, multipack, num::AllocatedNum, sha256::sha256 as sha256_circuit,
        uint32::UInt32,
    },
    ConstraintSystem, SynthesisError,
};
use ff::PrimeField;
use storage_proofs_core::{gadgets::uint64::UInt64, util::reverse_bit_numbering};

use crate::stacked::vanilla::TOTAL_PARENTS;

/// Compute a single label.
pub fn create_label_circuit<E, CS>(
    mut cs: CS,
    replica_id: &[Boolean],
    parents: Vec<Vec<Boolean>>,
    layer_index: UInt32,
    node: UInt64,
) -> Result<AllocatedNum<E>, SynthesisError>
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

    use bellperson::{
        bls::{Bls12, Fr},
        util_cs::test_cs::TestConstraintSystem,
    };
    use ff::Field;
    use filecoin_hashers::sha256::Sha256Hasher;
    use fr32::{bytes_into_fr, fr_into_bytes};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        api_version::ApiVersion,
        drgraph::{Graph, BASE_DEGREE},
        util::{bytes_into_boolean_vec_be, data_at_node, NODE_SIZE},
        TEST_SEED,
    };

    use crate::stacked::vanilla::{create_label, StackedBucketGraph, EXP_DEGREE};

    #[test]
    fn test_create_label() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let rng = &mut XorShiftRng::from_seed(TEST_SEED);

        let size = 64;
        let porep_id = [32; 32];

        let graph = StackedBucketGraph::<Sha256Hasher>::new_stacked(
            size,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            ApiVersion::V1_1_0,
        )
        .expect("stacked bucket graph new_stacked failed");

        let id_fr = Fr::random(rng);
        let id: Vec<u8> = fr_into_bytes(&id_fr);
        let layer = 3;
        let node = 22;

        let mut data: Vec<u8> = (0..2 * size)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        let mut parents = vec![0; BASE_DEGREE + EXP_DEGREE];
        graph.parents(node, &mut parents).expect("parents failed");

        let raw_parents_bytes: Vec<Vec<u8>> = parents
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if i < BASE_DEGREE {
                    // base
                    data_at_node(&data[..size * NODE_SIZE], *p as usize)
                        .expect("data_at_node failed")
                        .to_vec()
                } else {
                    // exp
                    data_at_node(&data[size * NODE_SIZE..], *p as usize)
                        .expect("data_at_node failed")
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
                bytes_into_boolean_vec_be(&mut cs, Some(p), p.len())
                    .expect("bytes_into_boolean_vec_be failed")
            })
            .collect();

        let id_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "id");
            bytes_into_boolean_vec_be(&mut cs, Some(id.as_slice()), id.len())
                .expect("bytes_into_boolean_vec_be failed")
        };

        let layer_alloc = UInt32::constant(layer as u32);
        let node_alloc = UInt64::constant(node as u64);

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
        .expect("create_label_exp failed");

        let expected_raw = data_at_node(&l1, node).expect("data_at_node failed");
        let expected = bytes_into_fr(expected_raw).expect("bytes_into_fr failed");

        assert_eq!(
            expected,
            out.get_value().expect("get_value failed"),
            "circuit and non circuit do not match"
        );
    }
}
