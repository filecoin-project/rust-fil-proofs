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
    + Into<[u8; 32]>
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

pub trait R1CSHasher: Hasher {
    fn hash_leaf_circuit<CS: ConstraintSystem<Self::Field>>(
        cs: CS,
        left: &AllocatedNum<Self::Field>,
        right: &AllocatedNum<Self::Field>,
        height: usize,
    ) -> Result<AllocatedNum<Self::Field>, SynthesisError>;

    #[cfg(feature = "poseidon")]
    fn hash_multi_leaf_circuit<
        Arity: PoseidonArity<Self::Field>,
        CS: ConstraintSystem<Self::Field>,
    >(
        cs: CS,
        leaves: &[AllocatedNum<Self::Field>],
        height: usize,
    ) -> Result<AllocatedNum<Self::Field>, SynthesisError>;

    #[cfg(not(feature = "poseidon"))]
    fn hash_multi_leaf_circuit<
        Arity: generic_array::typenum::Unsigned,
        CS: ConstraintSystem<Self::Field>,
    >(
        cs: CS,
        leaves: &[AllocatedNum<Self::Field>],
        height: usize,
    ) -> Result<AllocatedNum<Self::Field>, SynthesisError>;

    fn hash_md_circuit<CS: ConstraintSystem<Self::Field>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Self::Field>],
    ) -> Result<AllocatedNum<Self::Field>, SynthesisError> {
        unimplemented!();
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Self::Field>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Self::Field>, SynthesisError> {
        unimplemented!();
    }

    fn hash_circuit<CS: ConstraintSystem<Self::Field>>(
        cs: CS,
        bits: &[Boolean],
    ) -> Result<AllocatedNum<Self::Field>, SynthesisError>;

    fn hash2_circuit<CS: ConstraintSystem<Self::Field>>(
        cs: CS,
        a: &AllocatedNum<Self::Field>,
        b: &AllocatedNum<Self::Field>,
    ) -> Result<AllocatedNum<Self::Field>, SynthesisError>;
}

#[cfg(feature = "halo2")]
pub use self::halo2::{Halo2Hasher, HashInstructions};

#[cfg(feature = "halo2")]
mod halo2 {
    use super::*;

    use fil_halo2_gadgets::ColumnCount;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Layouter},
        plonk::{self, Advice, Column, Fixed},
    };

    pub trait HashInstructions<F: FieldExt> {
        fn hash(
            &self,
            layouter: impl Layouter<F>,
            preimage: &[AssignedCell<F, F>],
        ) -> Result<AssignedCell<F, F>, plonk::Error>;
    }

    // The `A` type parameter is necessary because we may need to specify a unique halo2 chip and
    // config for each preimage length `A`.
    pub trait Halo2Hasher<A>: Hasher
    where
        Self::Field: FieldExt,
        A: PoseidonArity<Self::Field>,
    {
        type Chip: HashInstructions<Self::Field> + ColumnCount;
        type Config: Clone;

        fn load(
            _layouter: &mut impl Layouter<Self::Field>,
            _config: &Self::Config,
        ) -> Result<(), plonk::Error> {
            Ok(())
        }

        fn construct(config: Self::Config) -> Self::Chip;

        fn configure(
            meta: &mut plonk::ConstraintSystem<Self::Field>,
            advice_eq: &[Column<Advice>],
            advice_neq: &[Column<Advice>],
            fixed_eq: &[Column<Fixed>],
            fixed_neq: &[Column<Fixed>],
        ) -> Self::Config;

        // Changes the chip config's arity from `A` to `B`. This is safe only when arities `A` and `B`
        // are known to have the same constraint system configuration.
        fn transmute_arity<B>(
            config: <Self as Halo2Hasher<A>>::Config,
        ) -> <Self as Halo2Hasher<B>>::Config
        where
            B: PoseidonArity<Self::Field>,
            Self: Halo2Hasher<B>;
    }
}
