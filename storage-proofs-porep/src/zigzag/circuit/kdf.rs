use bellperson::{
    gadgets::{boolean::Boolean, multipack, num::AllocatedNum, sha256::sha256 as sha256_circuit},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use storage_proofs_core::util::reverse_bit_numbering;

/// In-circuit ZigZag KDF: `SHA256(replica_id | parent_0 | parent_1 | ...)`, reduced to a field
/// element by packing the low 254 bits.
///
/// This mirrors the vanilla `zigzag::vanilla::vde::create_key`: the same SHA256 preimage (each input
/// is a 32-byte field-element serialization) and the same LE-254 reduction that
/// `fr32::bytes_into_fr_repr_safe` performs by clearing the top two bits.
///
/// `replica_id` and each `parents` entry must be provided as 256 big-endian-per-byte bits (as
/// produced by `bytes_into_boolean_vec_be` over the 32-byte serialization, or by
/// `reverse_bit_numbering` over a `to_bits_le` decomposition padded to 256 bits).
pub fn kdf<CS>(
    mut cs: CS,
    replica_id: &[Boolean],
    parents: Vec<Vec<Boolean>>,
) -> Result<AllocatedNum<Fr>, SynthesisError>
where
    CS: ConstraintSystem<Fr>,
{
    assert_eq!(replica_id.len(), 256, "replica_id must be 256 bits");
    assert!(!parents.is_empty(), "kdf needs at least one parent");

    let mut preimage = replica_id.to_vec();
    for parent in parents.iter() {
        assert_eq!(parent.len(), 256, "each parent must be 256 bits");
        preimage.extend_from_slice(parent);
    }

    let alloc_bits = sha256_circuit(cs.namespace(|| "sha256"), &preimage[..])?;

    // Match the vanilla reduction: interpret the digest little-endian and keep the low 254 bits.
    let bits = reverse_bit_numbering(alloc_bits);
    multipack::pack_bits(
        cs.namespace(|| "pack_key"),
        &bits[0..(Fr::CAPACITY as usize)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use filecoin_hashers::{
        poseidon::{PoseidonDomain, PoseidonHasher},
        Domain,
    };
    use storage_proofs_core::{
        api_version::ApiVersion,
        drgraph::{Graph, BASE_DEGREE},
        util::{bytes_into_boolean_vec_be, data_at_node, NODE_SIZE},
    };

    use crate::zigzag::vanilla::{create_key, ZigZagBucketGraph, ZigZagGraph, EXP_DEGREE};

    #[test]
    fn zigzag_kdf_circuit_matches_vanilla() {
        let nodes = 32;
        let porep_id = [5u8; 32];

        let graph: ZigZagBucketGraph<PoseidonHasher> = ZigZagGraph::new_zigzag(
            None,
            nodes,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            ApiVersion::V1_2_0,
        )
        .expect("graph creation failed");

        let replica_id = PoseidonDomain::from([7u8; 32]);

        // Deterministic, field-valid data: node i's bytes are `i` in the low byte.
        let mut data = vec![0u8; nodes * NODE_SIZE];
        for i in 0..nodes {
            data[i * NODE_SIZE] = (i as u8).wrapping_mul(3).wrapping_add(1);
        }

        let node = 7;
        let mut parents = vec![0u32; graph.degree()];
        graph.parents(node, &mut parents).expect("parents failed");

        // Vanilla key.
        let expected = create_key::<PoseidonHasher>(&replica_id, node, &parents, &data)
            .expect("vanilla create_key failed");

        // Circuit key.
        let mut cs = TestConstraintSystem::<Fr>::new();

        let replica_id_bits = {
            let mut cs = cs.namespace(|| "replica_id_bits");
            bytes_into_boolean_vec_be(&mut cs, Some(replica_id.into_bytes().as_slice()), 256)
                .expect("replica_id bits failed")
        };

        let parent_bits: Vec<Vec<Boolean>> = parents
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut cs = cs.namespace(|| format!("parent_bits_{}", i));
                let bytes = data_at_node(&data, *p as usize).expect("data_at_node failed");
                bytes_into_boolean_vec_be(&mut cs, Some(bytes), 256).expect("parent bits failed")
            })
            .collect();

        let out = kdf(cs.namespace(|| "kdf"), &replica_id_bits, parent_bits).expect("kdf failed");

        assert!(cs.is_satisfied(), "kdf constraints not satisfied");

        let expected_fr: Fr = expected.into();
        assert_eq!(
            out.get_value().expect("no value"),
            expected_fr,
            "circuit KDF does not match vanilla KDF"
        );
    }
}
