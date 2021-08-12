#![allow(unused_imports)]

pub mod blake2s;
pub mod poseidon;
pub mod sha256;

use std::fmt::{self, Debug, Formatter};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use std::marker::PhantomData;
use std::panic::panic_any;

use anyhow::ensure;
use blake2s_simd::{Hash as Blake2sHash, Params as Blake2s, State};
use bellperson::{
    bls::{Bls12, Fr},
    gadgets::{
        blake2s::blake2s as blake2s_circuit, boolean::Boolean, multipack, num::AllocatedNum,
        sha256::sha256 as sha256_circuit,
    },
    ConstraintSystem, SynthesisError,
};
use ff::{Field, PrimeField};
use generic_array::typenum::{Unsigned, U2};
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use neptune::{
    circuit::poseidon_hash as poseidon_circuit,
    poseidon::{Arity, Poseidon, PoseidonConstants},
};
use pasta_curves::{Fp, Fq};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::poseidon_types::*;

pub trait Domain<F: PrimeField>:
    Ord
    + Copy
    + Clone
    + AsRef<[u8]>
    + Default
    + Debug
    + Eq
    + Send
    + Sync
    + From<F>
    + Into<F>
    + From<[u8; 32]>
    + Serialize
    + DeserializeOwned
    + Element
    + StdHash
{
    #[allow(clippy::wrong_self_convention)]
    fn into_bytes(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }

    fn try_from_bytes(src: &[u8]) -> anyhow::Result<Self> {
        ensure!(src.len() == 32, "invalid number of bytes");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(src);
        Ok(Self::from(bytes))
    }

    fn write_bytes(&self, dst: &mut [u8]) -> anyhow::Result<()> {
        ensure!(dst.len() == 32, "invalid amount of bytes");
        dst.copy_from_slice(self.as_ref());
        Ok(())
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        // generate a field element then convert it to ensure we stay in the field
        F::random(rng).into()
    }
}

pub trait HashFunction<T, F>: Clone + Debug + Send + Sync + Algorithm<T>
where
    T: Domain<F>,
    F: PrimeField,
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

    fn hash_leaf(data: &dyn Hashable<Self>) -> T {
        let mut a = Self::default();
        data.hash(&mut a);
        let item_hash = a.hash();
        a.leaf(item_hash)
    }

    fn hash_single_node(data: &dyn Hashable<Self>) -> T {
        let mut a = Self::default();
        data.hash(&mut a);
        a.hash()
    }
}

pub trait Hasher<F: PrimeField>: Clone + Debug + Eq + Default + Send + Sync {
    type Domain: Domain<F> + Hashable<Self::Function>;
    type Function: HashFunction<Self::Domain, F>;

    fn name() -> String;
}

trait GrothHasher: Hasher<Fr> {
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

    fn hash_multi_leaf_circuit<A: 'static + PoseidonArity, CS: ConstraintSystem<Bls12>>(
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

    fn hash2_circuit<CS: ConstraintSystem<Bls12>>(
        cs: CS,
        a: &AllocatedNum<Bls12>,
        b: &AllocatedNum<Bls12>,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError>;
}
