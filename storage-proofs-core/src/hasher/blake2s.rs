use std::fmt;
use std::hash::Hasher as StdHasher;

use anyhow::ensure;
use bellperson::gadgets::{blake2s as blake2s_circuit, boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use blake2s_simd::{Hash as Blake2sHash, Params as Blake2s, State};
use ff::{Field, PrimeField, PrimeFieldRepr};
use merkletree::hash::{Algorithm, Hashable};
use merkletree::merkle::Element;
use paired::bls12_381::{Bls12, Fr, FrRepr};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::{Domain, HashFunction, Hasher};
use crate::crypto::sloth;
use crate::error::*;
use crate::gadgets::multipack;

#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Blake2sHasher {}

impl Hasher for Blake2sHasher {
    type Domain = Blake2sDomain;
    type Function = Blake2sFunction;

    fn name() -> String {
        "Blake2sHasher".into()
    }

    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain> {
        // TODO: validate this is how sloth should work in this case
        let k = (*key).into();
        let c = (*ciphertext).into();

        Ok(sloth::encode(&k, &c).into())
    }

    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain> {
        // TODO: validate this is how sloth should work in this case
        Ok(sloth::decode(&(*key).into(), &(*ciphertext).into()).into())
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

impl fmt::Debug for Blake2sFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
        let mut res = Self::default();
        val.into_repr()
            .write_le(&mut res.0[0..32])
            .expect("write_le failure");

        res
    }
}

impl From<FrRepr> for Blake2sDomain {
    fn from(val: FrRepr) -> Self {
        let mut res = Self::default();
        val.write_le(&mut res.0[0..32]).expect("write_le failure");

        res
    }
}

impl Element for Blake2sDomain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match Blake2sDomain::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic!(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.0);
    }
}

impl From<Blake2sDomain> for Fr {
    fn from(val: Blake2sDomain) -> Self {
        let mut res = FrRepr::default();
        res.read_le(&val.0[0..32]).expect("read_le failure");

        Fr::from_repr(res).expect("from_repr failure")
    }
}

impl Domain for Blake2sDomain {
    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        ensure!(
            raw.len() == 32 && u32::from(raw[31]) <= Fr::NUM_BITS,
            Error::InvalidInputSize
        );

        let mut res = Blake2sDomain::default();
        res.0.copy_from_slice(&raw[0..32]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        ensure!(dest.len() >= 32, Error::InvalidInputSize);
        dest[0..32].copy_from_slice(&self.0[..]);
        Ok(())
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        Fr::random(rng).into()
    }
}

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

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        leaves: &[num::AllocatedNum<Bls12>],
        _height: usize,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let mut bits = Vec::with_capacity(leaves.len() * Fr::CAPACITY as usize);
        for (i, leaf) in leaves.iter().enumerate() {
            bits.extend_from_slice(
                &leaf.to_bits_le(cs.namespace(|| format!("{}_num_into_bits", i)))?,
            );
            while bits.len() % 8 != 0 {
                bits.push(boolean::Boolean::Constant(false));
            }
        }
        Self::hash_circuit(cs, &bits)
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Bls12>>(
        cs: CS,
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        _height: usize,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let mut preimage: Vec<boolean::Boolean> = vec![];

        preimage.extend_from_slice(left);
        while preimage.len() % 8 != 0 {
            preimage.push(boolean::Boolean::Constant(false));
        }

        preimage.extend_from_slice(right);
        while preimage.len() % 8 != 0 {
            preimage.push(boolean::Boolean::Constant(false));
        }

        Self::hash_circuit(cs, &preimage[..])
    }

    fn hash_circuit<CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        bits: &[boolean::Boolean],
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let personalization = vec![0u8; 8];
        let alloc_bits =
            blake2s_circuit::blake2s(cs.namespace(|| "hash"), &bits[..], &personalization)?;

        multipack::pack_bits(cs.namespace(|| "pack"), &alloc_bits)
    }

    fn hash2_circuit<CS>(
        mut cs: CS,
        a_num: &num::AllocatedNum<Bls12>,
        b_num: &num::AllocatedNum<Bls12>,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        // Allocate as booleans
        let a = a_num.to_bits_le(cs.namespace(|| "a_bits"))?;
        let b = b_num.to_bits_le(cs.namespace(|| "b_bits"))?;

        let mut preimage: Vec<boolean::Boolean> = vec![];

        preimage.extend_from_slice(&a);
        while preimage.len() % 8 != 0 {
            preimage.push(boolean::Boolean::Constant(false));
        }

        preimage.extend_from_slice(&b);
        while preimage.len() % 8 != 0 {
            preimage.push(boolean::Boolean::Constant(false));
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
