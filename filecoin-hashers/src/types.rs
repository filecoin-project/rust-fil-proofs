use std::fmt::Debug;
use std::hash::Hash as StdHash;

#[cfg(feature = "poseidon")]
pub use crate::poseidon_types::*;

use anyhow::ensure;
use bellperson::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};
use ff::{Field, PrimeField};
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
    + From<Self::Field>
    + Into<Self::Field>
    + From<[u8; 32]>
    + Serialize
    + DeserializeOwned
    + Element
    + StdHash
{
    type Field: PrimeField;

    #[allow(clippy::wrong_self_convention)]
    fn into_bytes(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }

    fn try_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() == Self::byte_len(), "invalid number of bytes");
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(array.into())
    }

    /// Write itself into the given slice, LittleEndian bytes.
    fn write_bytes(&self, dest: &mut [u8]) -> anyhow::Result<()> {
        let n = Self::byte_len();
        ensure!(dest.len() >= n, "invalid number of bytes");
        dest[..n].copy_from_slice(self.as_ref());
        Ok(())
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        // Generating a field element then converting it ensures that we stay within the field.
        Self::Field::random(rng).into()
    }
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

    fn hash_leaf_circuit<CS: ConstraintSystem<T::Field>>(
        cs: CS,
        left: &AllocatedNum<T::Field>,
        right: &AllocatedNum<T::Field>,
        height: usize,
    ) -> Result<AllocatedNum<T::Field>, SynthesisError>;

    #[cfg(not(feature = "poseidon"))]
    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<T::Field>>(
        cs: CS,
        leaves: &[AllocatedNum<T::Field>],
        height: usize,
    ) -> Result<AllocatedNum<T::Field>, SynthesisError>;

    #[cfg(feature = "poseidon")]
    fn hash_multi_leaf_circuit<Arity, CS>(
        cs: CS,
        leaves: &[AllocatedNum<T::Field>],
        height: usize,
    ) -> Result<AllocatedNum<T::Field>, SynthesisError>
    where
        Arity: 'static + PoseidonArity<T::Field>,
        CS: ConstraintSystem<T::Field>;

    fn hash_md_circuit<CS: ConstraintSystem<T::Field>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<T::Field>],
    ) -> Result<AllocatedNum<T::Field>, SynthesisError> {
        unimplemented!();
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<T::Field>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<T::Field>, SynthesisError> {
        unimplemented!();
    }

    fn hash_circuit<CS: ConstraintSystem<T::Field>>(
        cs: CS,
        bits: &[Boolean],
    ) -> Result<AllocatedNum<T::Field>, SynthesisError>;

    fn hash2_circuit<CS>(
        cs: CS,
        a: &AllocatedNum<T::Field>,
        b: &AllocatedNum<T::Field>,
    ) -> Result<AllocatedNum<T::Field>, SynthesisError>
    where
        CS: ConstraintSystem<T::Field>;
}

pub trait Hasher: Clone + Debug + Eq + Default + Send + Sync {
    #[cfg(not(any(feature = "cuda", feature = "opencl")))]
    type Field: PrimeField;
    #[cfg(any(feature = "cuda", feature = "opencl"))]
    type Field: PrimeField + ec_gpu::GpuName;

    type Domain: Domain<Field = Self::Field> + LightHashable<Self::Function> + AsRef<Self::Domain>;
    type Function: HashFunction<Self::Domain>;

    fn name() -> String;
}

macro_rules! impl_hasher_for_field {
    ($hasher:ident, $domain:ident, $func:ident, $name:expr, $($f:ty),*) => {
        $(
            impl From<$f> for $domain<$f> {
                fn from(f: $f) -> Self {
                    Self::from(f.to_repr())
                }
            }

            impl From<$domain<$f>> for $f {
                fn from(val: $domain<$f>) -> $f {
                    <$f>::from_repr_vartime(val.into()).expect("from_repr failure")
                }
            }

            impl Domain for $domain<$f> {
                type Field = $f;
            }

            impl Hasher for $hasher<$f> {
                type Field = $f;
                type Domain = $domain<Self::Field>;
                type Function = $func<Self::Field>;

                fn name() -> String {
                    $name.into()
                }
            }
        )*
    };
}

pub(crate) use impl_hasher_for_field;
