use std::fmt::Debug;
use std::hash::Hash as StdHash;

#[cfg(feature = "poseidon")]
pub use crate::poseidon_types::*;

use bellperson::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use merkletree::{
    hash::{Algorithm as LightAlgorithm, Hashable as LightHashable},
    merkle::Element,
};
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};

pub trait Domain:
    Ord
    + Copy
    + Clone
    + AsRef<[u8]>
    + Default
    + Debug
    + Eq
    + Send
    + Sync
    + From<Fr>
    + From<<Fr as PrimeField>::Repr>
    + Into<Fr>
    + Serialize
    + DeserializeOwned
    + Element
    + StdHash
{
    #[allow(clippy::wrong_self_convention)]
    fn into_bytes(&self) -> Vec<u8>;
    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self>;
    /// Write itself into the given slice, LittleEndian bytes.
    fn write_bytes(&self, _: &mut [u8]) -> anyhow::Result<()>;

    fn random<R: RngCore>(rng: &mut R) -> Self;
}

pub trait HashFunction<T: Domain>: Clone + Debug + Send + Sync + LightAlgorithm<T> {
    fn hash(data: &[u8]) -> T;
    fn hash2(a: &T, b: &T) -> T;
    fn hash_md(input: &[T]) -> T {
        // Default to binary.
        assert!(input.len() > 1, "hash_md needs more than one element.");
        input
            .iter()
            .skip(1)
            .fold(input[0], |acc, elt| Self::hash2(&acc, elt))
    }

    fn hash_leaf(data: &dyn LightHashable<Self>) -> T {
        let mut a = Self::default();
        data.hash(&mut a);
        let item_hash = a.hash();
        a.leaf(item_hash)
    }

    fn hash_single_node(data: &dyn LightHashable<Self>) -> T {
        let mut a = Self::default();
        data.hash(&mut a);
        a.hash()
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        mut cs: CS,
        left: &AllocatedNum<Fr>,
        right: &AllocatedNum<Fr>,
        height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let left_bits = left.to_bits_le(cs.namespace(|| "left num into bits"))?;
        let right_bits = right.to_bits_le(cs.namespace(|| "right num into bits"))?;

        Self::hash_leaf_bits_circuit(cs, &left_bits, &right_bits, height)
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity, CS: ConstraintSystem<Fr>>(
        cs: CS,
        leaves: &[AllocatedNum<Fr>],
        height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError>;

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!();
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!();
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        cs: CS,
        bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError>;

    fn hash2_circuit<CS>(
        cs: CS,
        a: &AllocatedNum<Fr>,
        b: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError>
    where
        CS: ConstraintSystem<Fr>;
}

pub trait Hasher: Clone + Debug + Eq + Default + Send + Sync {
    type Domain: Domain + LightHashable<Self::Function> + AsRef<Self::Domain>;
    type Function: HashFunction<Self::Domain>;

    fn name() -> String;
}
