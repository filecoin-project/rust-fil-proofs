use bellperson::{
    gadgets::{boolean::Boolean, num, sha256::sha256 as sha256_circuit, uint32::UInt32},
    ConstraintSystem, SynthesisError,
};
use ff::{Field, PrimeField};
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    gadgets::{constraint, multipack, uint64::UInt64},
    util::reverse_bit_numbering,
};

use super::super::Config;

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
) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
    // TODO: can we reuse this allocation accross challenges?
    let layer_index = UInt32::alloc(cs.namespace(|| "layer_index"), Some(layer))?;

    // prefix
    let mut ciphertexts = hash_prefix(challenge_index_num, layer_index)?;

    // replica id
    ciphertexts.extend_from_slice(replica_id);

    // hash parents

    // sha256
    todo!()
}

pub fn derive_last_layer_leaf<CS: ConstraintSystem<Bls12>>(
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

    // hash parents

    // encode

    // sha256
    todo!()
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
    assert_eq!(parents_data.len(), degree * k, "invalid number of parents");

    let mut expanded = Vec::new();
    let k = k as u32;

    for i in 0..degree {
        let mut el = num::AllocatedNum::alloc(&mut cs, || Ok(Fr::zero())).unwrap();
        for l in 0..k {
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
