use bellperson::{
    gadgets::{boolean::Boolean, num, sha256::sha256 as sha256_circuit, uint32::UInt32},
    ConstraintSystem, SynthesisError,
};
use ff::PrimeField;
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    gadgets::{constraint, encode, multipack, uint64::UInt64},
    util::reverse_bit_numbering,
};

use super::super::vanilla::Config;

pub fn derive_first_layer_leaf<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    replica_id: &[Boolean],
    challenge_index_num: &UInt64,
    layer: u32,
) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
    // TODO: can we reuse this allocation accross challenges?
    let layer_index = UInt32::alloc(cs.namespace(|| "layer_index"), Some(layer))?;

    // prefix
    let mut ciphertexts = hash_prefix(challenge_index_num, layer_index)?;

    // replica id
    ciphertexts.extend_from_slice(replica_id);

    // no parents in the first layer, so the hash is done

    hash_sha256(cs, &ciphertexts)
}

pub fn derive_expander_layer_leaf<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    replica_id: &[Boolean],
    challenge_index_num: &UInt64,
    layer: u32,
    config: &Config,
    parents_data: &[num::AllocatedNum<Bls12>],
) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
    // TODO: can we reuse this allocation accross challenges?
    let layer_index = UInt32::alloc(cs.namespace(|| "layer_index"), Some(layer))?;

    // prefix
    let mut ciphertexts = hash_prefix(challenge_index_num, layer_index)?;

    // replica id
    ciphertexts.extend_from_slice(replica_id);

    // batch parents
    ciphertexts.extend_from_slice(&batch_expansion(
        cs.namespace(|| "batch_expansion"),
        config.k as usize,
        config.degree_expander,
        parents_data,
    )?);

    // sha256
    hash_sha256(cs, &ciphertexts)
}

pub fn derive_butterfly_layer_leaf<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    replica_id: &[Boolean],
    challenge_index_num: &UInt64,
    layer: u32,
    parents_data: &[num::AllocatedNum<Bls12>],
) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
    // TODO: can we reuse this allocation accross challenges?
    let layer_index = UInt32::alloc(cs.namespace(|| "layer_index"), Some(layer))?;

    // prefix
    let mut ciphertexts = hash_prefix(challenge_index_num, layer_index)?;

    // replica id
    ciphertexts.extend_from_slice(replica_id);

    // hash parents
    ciphertexts.extend(expand_nums_to_bools(
        cs.namespace(|| "expand_nums"),
        parents_data,
    )?);

    // sha256
    hash_sha256(cs, &ciphertexts)
}

pub fn derive_last_layer_leaf<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    replica_id: &[Boolean],
    challenge_index_num: &UInt64,
    layer: u32,
    data_node: &num::AllocatedNum<Bls12>,
    parents_data: &[num::AllocatedNum<Bls12>],
) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
    // derive regular label
    let key = derive_butterfly_layer_leaf(
        cs.namespace(|| "butterfly_label"),
        replica_id,
        challenge_index_num,
        layer,
        parents_data,
    )?;

    // encode
    encode::encode(cs.namespace(|| "encode"), &key, data_node)
}

/// Sha256
fn hash_sha256<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    ciphertexts: &[Boolean],
) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
    // Compute Sha256
    let alloc_bits = sha256_circuit(cs.namespace(|| "sha256"), &ciphertexts[..])?;

    // Convert the hash result into a single Fr.
    let bits = reverse_bit_numbering(alloc_bits);
    multipack::pack_bits(
        cs.namespace(|| "sha256_result_num"),
        &bits[0..(Fr::CAPACITY as usize)],
    )
}

/// Calculates the common prefix for the hash.
fn hash_prefix(challenge_index: &UInt64, layer: UInt32) -> Result<Vec<Boolean>, SynthesisError> {
    // The prefix is 32 bytes long
    const PREFIX_LEN: usize = 32 * 8;

    let mut ciphertexts = Vec::with_capacity(PREFIX_LEN);

    ciphertexts.extend_from_slice(&layer.into_bits_be());

    ciphertexts.extend_from_slice(&challenge_index.to_bits_be());

    // the rest is padded with 0s
    while ciphertexts.len() < PREFIX_LEN {
        ciphertexts.push(Boolean::constant(false));
    }

    Ok(ciphertexts)
}

/// Expands parents_data according to the batch hashing algorithm.
fn batch_expansion<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    k: usize,
    degree: usize,
    parents_data: &[num::AllocatedNum<Bls12>],
) -> Result<Vec<Boolean>, SynthesisError> {
    assert!(
        parents_data.len() % 2 == 0,
        "number of parents must be even"
    );
    assert_eq!(degree % 2, 0, "degree must be even");
    assert_eq!(parents_data.len(), degree * k, "invalid number of parents");

    let mut expanded = Vec::new();
    let k = k as u32;

    for i in 0..degree {
        // the first element is at `i`.
        let mut el = parents_data[i].clone();

        for l in 1..k {
            let y = i + (l as usize * degree as usize);
            el = constraint::add(
                cs.namespace(|| format!("add_{}_{}", i, l)),
                &el,
                &parents_data[y],
            )?;
        }

        expanded.extend(reverse_bit_numbering(
            el.to_bits_le(cs.namespace(|| format!("el_to_bits_{}", i)))?,
        ));
    }

    Ok(expanded)
}

/// Expands the given list of `AllocatedNum`s into their expanded boolean representation.
fn expand_nums_to_bools<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    nums: &[num::AllocatedNum<Bls12>],
) -> Result<Vec<Boolean>, SynthesisError> {
    assert!(nums.len() % 2 == 0, "parents number must be even");

    let mut bools = Vec::new();
    for (i, num) in nums.iter().enumerate() {
        bools.extend(reverse_bit_numbering(
            num.to_bits_le(cs.namespace(|| format!("num_to_bits_{}", i)))?,
        ));
    }

    debug_assert_eq!(bools.len(), nums.len() * 4 * 64);

    Ok(bools)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::nse::vanilla::{hash_prefix, truncate_hash};

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use sha2raw::Sha256;
    use storage_proofs_core::hasher::{Domain, PedersenDomain};

    #[test]
    fn test_derive_butterfly_layer_leaf() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let layer = 5;
        let challenge = 8;
        let replica_id = PedersenDomain::random(rng);
        let replica_id_num = num::AllocatedNum::alloc(cs.namespace(|| "replica_id"), || {
            Ok(replica_id.clone().into())
        })
        .unwrap();
        let replica_id_bits = reverse_bit_numbering(
            replica_id_num
                .to_bits_le(cs.namespace(|| "replica_id_bits"))
                .unwrap(),
        );

        let challenge_index_num =
            UInt64::alloc(cs.namespace(|| "challenge_num"), Some(challenge)).unwrap();
        let data: Vec<_> = (0..6).map(|_| PedersenDomain::random(rng)).collect();
        let parents_data: Vec<_> = data
            .iter()
            .enumerate()
            .map(|(i, p)| {
                num::AllocatedNum::alloc(cs.namespace(|| format!("parent_{}", i)), || {
                    Ok((*p).into())
                })
                .unwrap()
            })
            .collect();

        let leaf = derive_butterfly_layer_leaf(
            cs,
            &replica_id_bits,
            &challenge_index_num,
            layer,
            &parents_data,
        )
        .unwrap();

        let expected_leaf = {
            let prefix = hash_prefix(layer as u32, challenge);

            let mut hasher = Sha256::new();
            // Hash prefix + replica id, each 32 bytes.
            hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(&replica_id)]);

            // Butterfly hashing
            for chunk in data.chunks(2) {
                hasher.input(&[
                    AsRef::<[u8]>::as_ref(&chunk[0]),
                    AsRef::<[u8]>::as_ref(&chunk[1]),
                ]);
            }
            let mut label = hasher.finish();
            truncate_hash(&mut label);
            label
        };

        let domain_leaf: PedersenDomain = leaf.get_value().unwrap().into();
        assert_eq!(expected_leaf, AsRef::<[u8]>::as_ref(&domain_leaf));
    }
}
