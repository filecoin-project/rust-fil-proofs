use std::fmt::Debug;
use std::hash::Hash as StdHash;

#[cfg(feature = "poseidon")]
pub use crate::poseidon_types::*;

use bellperson::{
    bls::{Bls12, Fr, FrRepr},
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};
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
    + From<FrRepr>
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

    fn hash_leaf_circuit<CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        left: &AllocatedNum<Bls12>,
        right: &AllocatedNum<Bls12>,
        height: usize,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError> {
        let left_bits = left.to_bits_le(cs.namespace(|| "left num into bits"))?;
        let right_bits = right.to_bits_le(cs.namespace(|| "right num into bits"))?;

        Self::hash_leaf_bits_circuit(cs, &left_bits, &right_bits, height)
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity, CS: ConstraintSystem<Bls12>>(
        cs: CS,
        leaves: &[AllocatedNum<Bls12>],
        height: usize,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError>;

    fn hash_md_circuit<CS: ConstraintSystem<Bls12>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Bls12>],
    ) -> Result<AllocatedNum<Bls12>, SynthesisError> {
        unimplemented!();
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Bls12>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError> {
        unimplemented!();
    }

    fn hash_circuit<CS: ConstraintSystem<Bls12>>(
        cs: CS,
        bits: &[Boolean],
    ) -> Result<AllocatedNum<Bls12>, SynthesisError>;

    fn hash2_circuit<CS>(
        cs: CS,
        a: &AllocatedNum<Bls12>,
        b: &AllocatedNum<Bls12>,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError>
    where
        CS: ConstraintSystem<Bls12>;
}

pub trait Hasher: Clone + Debug + Eq + Default + Send + Sync {
    type Domain: Domain + LightHashable<Self::Function> + AsRef<Self::Domain>;
    type Function: HashFunction<Self::Domain>;

    fn name() -> String;
}
