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

use crate::halo::{Domain, GrothHasher, Hasher, HashFunction};
use crate::poseidon_types::*;

#[derive(
    Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Default, Serialize, Deserialize, Hash,
)]
pub struct Blake2sDomain(pub [u8; 32]);

impl AsRef<[u8]> for Blake2sDomain {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Fr> for Blake2sDomain {
    fn from(val: Fr) -> Self {
        Blake2sDomain(val.to_repr())
    }
}

impl From<Blake2sDomain> for Fr {
    fn from(val: Blake2sDomain) -> Self {
        Fr::from_repr(val.0).expect("from_repr failure")
    }
}

impl From<Fp> for Blake2sDomain {
    fn from(val: Fp) -> Self {
        Blake2sDomain(val.to_repr())
    }
}

impl From<Blake2sDomain> for Fp {
    fn from(val: Blake2sDomain) -> Self {
        Fp::from_repr(val.0).expect("from_repr failure")
    }
}

impl From<Fq> for Blake2sDomain {
    fn from(val: Fq) -> Self {
        Blake2sDomain(val.to_repr())
    }
}

impl From<Blake2sDomain> for Fq {
    fn from(val: Blake2sDomain) -> Self {
        Fq::from_repr(val.0).expect("from_repr failure")
    }
}

impl From<[u8; 32]> for Blake2sDomain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        Blake2sDomain(val)
    }
}

impl Element for Blake2sDomain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(src: &[u8]) -> Self {
        assert_eq!(src.len(), 32, "invalid number of bytes");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&src);
        Self(bytes)
    }

    fn copy_to_slice(&self, dst: &mut [u8]) {
        assert_eq!(dst.len(), 32, "invalid number of bytes");
        dst.copy_from_slice(self.as_ref());
    }
}

impl Domain<Fr> for Blake2sDomain {}
impl Domain<Fp> for Blake2sDomain {}
impl Domain<Fq> for Blake2sDomain {}

impl Blake2sDomain {
    pub fn trim_to_fr32(&mut self) {
        // strip last two bits, to ensure result is in a prime field
        self.0[31] &= 0b0011_1111;
    }
}

#[derive(Clone)]
pub struct Blake2sFunction(State);

impl Default for Blake2sFunction {
    fn default() -> Self {
        Blake2sFunction(Blake2s::new().hash_length(32).to_state())
    }
}

impl PartialEq for Blake2sFunction {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self) == format!("{:?}", other)
    }
}

impl Eq for Blake2sFunction {}

impl Debug for Blake2sFunction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Blake2sFunction({:?})", self.0)
    }
}

impl StdHasher for Blake2sFunction {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

impl Hashable<Blake2sFunction> for Blake2sDomain {
    fn hash(&self, state: &mut Blake2sFunction) {
        state.write(self.as_ref())
    }
}

impl Algorithm<Blake2sDomain> for Blake2sFunction {
    #[inline]
    fn hash(&mut self) -> Blake2sDomain {
        self.0.clone().finalize().into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Blake2s::new().hash_length(32).to_state()
    }

    fn leaf(&mut self, leaf: Blake2sDomain) -> Blake2sDomain {
        leaf
    }

    fn node(&mut self, left: Blake2sDomain, right: Blake2sDomain, _height: usize) -> Blake2sDomain {
        <Blake2sDomain as Hashable<Blake2sFunction>>::hash(&left, self);
        <Blake2sDomain as Hashable<Blake2sFunction>>::hash(&right, self);
        <Self as Algorithm<Blake2sDomain>>::hash(self)
    }

    fn multi_node(&mut self, parts: &[Blake2sDomain], _height: usize) -> Blake2sDomain {
        for part in parts {
            <Blake2sDomain as Hashable<Blake2sFunction>>::hash(&part, self);
        }
        self.hash()
    }
}

#[allow(clippy::from_over_into)]
impl Into<Blake2sDomain> for Blake2sHash {
    fn into(self) -> Blake2sDomain {
        let mut res = Blake2sDomain::default();
        res.0[..].copy_from_slice(self.as_ref());
        res.trim_to_fr32();

        res
    }
}

impl HashFunction<Blake2sDomain, Fr> for Blake2sFunction {
    fn hash(data: &[u8]) -> Blake2sDomain {
        Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(data)
            .finalize()
            .into()
    }

    fn hash2(a: &Blake2sDomain, b: &Blake2sDomain) -> Blake2sDomain {
        Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(a.as_ref())
            .update(b.as_ref())
            .finalize()
            .into()
    }
}

impl HashFunction<Blake2sDomain, Fp> for Blake2sFunction {
    fn hash(data: &[u8]) -> Blake2sDomain {
        Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(data)
            .finalize()
            .into()
    }

    fn hash2(a: &Blake2sDomain, b: &Blake2sDomain) -> Blake2sDomain {
        Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(a.as_ref())
            .update(b.as_ref())
            .finalize()
            .into()
    }
}

impl HashFunction<Blake2sDomain, Fq> for Blake2sFunction {
    fn hash(data: &[u8]) -> Blake2sDomain {
        Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(data)
            .finalize()
            .into()
    }

    fn hash2(a: &Blake2sDomain, b: &Blake2sDomain) -> Blake2sDomain {
        Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(a.as_ref())
            .update(b.as_ref())
            .finalize()
            .into()
    }
}

#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Blake2sHasher;

impl Hasher<Fr> for Blake2sHasher {
    type Domain = Blake2sDomain;
    type Function = Blake2sFunction;

    fn name() -> String {
        "blake2s_hasher_bls12".into()
    }
}

impl Hasher<Fp> for Blake2sHasher {
    type Domain = Blake2sDomain;
    type Function = Blake2sFunction;

    fn name() -> String {
        "blake2s_hasher_pallas".into()
    }
}

impl Hasher<Fq> for Blake2sHasher {
    type Domain = Blake2sDomain;
    type Function = Blake2sFunction;

    fn name() -> String {
        "blake2s_hasher_vesta".into()
    }
}
