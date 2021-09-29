use std::fmt::{self, Debug, Formatter};
use std::hash::Hasher as StdHasher;
use std::panic::panic_any;

use anyhow::ensure;
use bellperson::{
    gadgets::{
        blake2s::blake2s as blake2s_circuit, boolean::Boolean, multipack, num::AllocatedNum,
    },
    ConstraintSystem, SynthesisError,
};
use blake2s_simd::{Hash as Blake2sHash, Params as Blake2s, State};
use blstrs::Scalar as Fr;
use ff::{Field, PrimeField};
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::types::{Domain, HashFunction, Hasher};

#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Blake2sHasher {}

impl Hasher for Blake2sHasher {
    type Domain = Blake2sDomain;
    type Function = Blake2sFunction;

    fn name() -> String {
        "Blake2sHasher".into()
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

#[derive(
    Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Default, Serialize, Deserialize, Hash,
)]
pub struct Blake2sDomain(pub [u8; 32]);

impl AsRef<Blake2sDomain> for Blake2sDomain {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Blake2sDomain {
    pub fn trim_to_fr32(&mut self) {
        // strip last two bits, to ensure result is in Fr.
        self.0[31] &= 0b0011_1111;
    }
}

impl AsRef<[u8]> for Blake2sDomain {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Hashable<Blake2sFunction> for Blake2sDomain {
    fn hash(&self, state: &mut Blake2sFunction) {
        state.write(self.as_ref())
    }
}

impl From<Fr> for Blake2sDomain {
    fn from(val: Fr) -> Self {
        Blake2sDomain(val.to_repr())
    }
}

impl Element for Blake2sDomain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match Blake2sDomain::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic_any(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.0);
    }
}

impl From<Blake2sDomain> for Fr {
    fn from(val: Blake2sDomain) -> Self {
        Fr::from_repr_vartime(val.0).expect("from_repr failure")
    }
}

impl Domain for Blake2sDomain {
    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            raw.len() == 32 && u32::from(raw[31]) <= Fr::NUM_BITS,
            "invalid amount of bytes"
        );

        let mut res = Blake2sDomain::default();
        res.0.copy_from_slice(&raw[0..32]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> anyhow::Result<()> {
        ensure!(dest.len() >= 32, "too many bytes");
        dest[0..32].copy_from_slice(&self.0[..]);
        Ok(())
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        Fr::random(rng).into()
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

impl HashFunction<Blake2sDomain> for Blake2sFunction {
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

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<Fr>>(
        mut cs: CS,
        leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let mut bits = Vec::with_capacity(leaves.len() * Fr::CAPACITY as usize);
        for (i, leaf) in leaves.iter().enumerate() {
            bits.extend_from_slice(
                &leaf.to_bits_le(cs.namespace(|| format!("{}_num_into_bits", i)))?,
            );
            while bits.len() % 8 != 0 {
                bits.push(Boolean::Constant(false));
            }
        }
        Self::hash_circuit(cs, &bits)
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Fr>>(
        cs: CS,
        left: &[Boolean],
        right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let mut preimage: Vec<Boolean> = vec![];

        preimage.extend_from_slice(left);
        while preimage.len() % 8 != 0 {
            preimage.push(Boolean::Constant(false));
        }

        preimage.extend_from_slice(right);
        while preimage.len() % 8 != 0 {
            preimage.push(Boolean::Constant(false));
        }

        Self::hash_circuit(cs, &preimage[..])
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        mut cs: CS,
        bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let personalization = vec![0u8; 8];
        let alloc_bits = blake2s_circuit(cs.namespace(|| "hash"), bits, &personalization)?;

        multipack::pack_bits(cs.namespace(|| "pack"), &alloc_bits)
    }

    fn hash2_circuit<CS>(
        mut cs: CS,
        a_num: &AllocatedNum<Fr>,
        b_num: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError>
    where
        CS: ConstraintSystem<Fr>,
    {
        // Allocate as booleans
        let a = a_num.to_bits_le(cs.namespace(|| "a_bits"))?;
        let b = b_num.to_bits_le(cs.namespace(|| "b_bits"))?;

        let mut preimage: Vec<Boolean> = vec![];

        preimage.extend_from_slice(&a);
        while preimage.len() % 8 != 0 {
            preimage.push(Boolean::Constant(false));
        }

        preimage.extend_from_slice(&b);
        while preimage.len() % 8 != 0 {
            preimage.push(Boolean::Constant(false));
        }

        Self::hash_circuit(cs, &preimage[..])
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
        left.hash(self);
        right.hash(self);
        self.hash()
    }

    fn multi_node(&mut self, parts: &[Blake2sDomain], _height: usize) -> Blake2sDomain {
        for part in parts {
            part.hash(self)
        }
        self.hash()
    }
}

impl From<[u8; 32]> for Blake2sDomain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        Blake2sDomain(val)
    }
}

impl From<Blake2sDomain> for [u8; 32] {
    #[inline]
    fn from(val: Blake2sDomain) -> Self {
        val.0
    }
}
