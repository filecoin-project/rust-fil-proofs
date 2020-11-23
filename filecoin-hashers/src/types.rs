use anyhow::Result;
use bellperson::bls::{Bls12, Fr, FrRepr};
use bellperson::gadgets::{boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use merkletree::hash::{Algorithm as LightAlgorithm, Hashable as LightHashable};
use merkletree::merkle::Element;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

#[cfg(feature = "poseidon")]
pub use crate::poseidon_types::*;

pub trait Domain:
    Ord
    + Copy
    + Clone
    + AsRef<[u8]>
    + Default
    + ::std::fmt::Debug
    + Eq
    + Send
    + Sync
    + From<Fr>
    + From<FrRepr>
    + Into<Fr>
    + Serialize
    + DeserializeOwned
    + Element
    + std::hash::Hash
{
    fn into_bytes(&self) -> Vec<u8>;
    fn try_from_bytes(raw: &[u8]) -> Result<Self>;
    /// Write itself into the given slice, LittleEndian bytes.
    fn write_bytes(&self, _: &mut [u8]) -> Result<()>;

    fn random<R: rand::RngCore>(rng: &mut R) -> Self;
}

pub trait HashFunction<T: Domain>:
    Clone + ::std::fmt::Debug + Send + Sync + LightAlgorithm<T>
{
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
        left: &num::AllocatedNum<Bls12>,
        right: &num::AllocatedNum<Bls12>,
        height: usize,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let left_bits = left.to_bits_le(cs.namespace(|| "left num into bits"))?;
        let right_bits = right.to_bits_le(cs.namespace(|| "right num into bits"))?;

        Self::hash_leaf_bits_circuit(cs, &left_bits, &right_bits, height)
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity, CS: ConstraintSystem<Bls12>>(
        cs: CS,
        leaves: &[num::AllocatedNum<Bls12>],
        height: usize,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError>;

    fn hash_md_circuit<CS: ConstraintSystem<Bls12>>(
        _cs: &mut CS,
        _elements: &[num::AllocatedNum<Bls12>],
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        unimplemented!();
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Bls12>>(
        _cs: CS,
        _left: &[boolean::Boolean],
        _right: &[boolean::Boolean],
        _height: usize,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        unimplemented!();
    }

    fn hash_circuit<CS: ConstraintSystem<Bls12>>(
        cs: CS,
        bits: &[boolean::Boolean],
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError>;

    fn hash2_circuit<CS>(
        cs: CS,
        a: &num::AllocatedNum<Bls12>,
        b: &num::AllocatedNum<Bls12>,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError>
    where
        CS: ConstraintSystem<Bls12>;
}

pub trait Hasher: Clone + ::std::fmt::Debug + Eq + Default + Send + Sync {
    type Domain: Domain + LightHashable<Self::Function> + AsRef<Self::Domain>;
    type Function: HashFunction<Self::Domain>;

    fn name() -> String;
}
