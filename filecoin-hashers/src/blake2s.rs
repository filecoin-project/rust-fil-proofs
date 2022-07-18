use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use bellperson::{
    gadgets::{
        blake2s::blake2s as blake2s_circuit, boolean::Boolean, multipack, num::AllocatedNum,
    },
    ConstraintSystem, SynthesisError,
};
use blake2s_simd::{Hash as Blake2sHash, Params as Blake2sBuilder, State};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use halo2_proofs::pasta::{Fp, Fq};
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Domain, Groth16Hasher, HashFunction, Hasher};

#[derive(Copy, Clone, Default)]
pub struct Blake2sDomain<F> {
    pub state: [u8; 32],
    _f: PhantomData<F>,
}

impl<F> Debug for Blake2sDomain<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Blake2sDomain({})", hex::encode(&self.state))
    }
}

// Can't blanket `impl<F> From<F> for Blake2sDomain<F> where F: PrimeField` because it can conflict
// with `impl<F> From<[u8; 32]> for Blake2sDomain<F>`, i.e. `[u8; 32]` is an external type which may
// already implement the external trait `PrimeField`, which causes a "conflicting implementation"
// compiler error.
impl From<Fr> for Blake2sDomain<Fr> {
    fn from(f: Fr) -> Self {
        Blake2sDomain {
            state: f.to_repr(),
            _f: PhantomData,
        }
    }
}
impl From<Fp> for Blake2sDomain<Fp> {
    fn from(f: Fp) -> Self {
        Blake2sDomain {
            state: f.to_repr(),
            _f: PhantomData,
        }
    }
}
impl From<Fq> for Blake2sDomain<Fq> {
    fn from(f: Fq) -> Self {
        Blake2sDomain {
            state: f.to_repr(),
            _f: PhantomData,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<Fr> for Blake2sDomain<Fr> {
    fn into(self) -> Fr {
        Fr::from_repr_vartime(self.state).expect("from_repr failure")
    }
}
#[allow(clippy::from_over_into)]
impl Into<Fp> for Blake2sDomain<Fp> {
    fn into(self) -> Fp {
        Fp::from_repr_vartime(self.state).expect("from_repr failure")
    }
}
#[allow(clippy::from_over_into)]
impl Into<Fq> for Blake2sDomain<Fq> {
    fn into(self) -> Fq {
        Fq::from_repr_vartime(self.state).expect("from_repr failure")
    }
}

impl<F> From<[u8; 32]> for Blake2sDomain<F> {
    fn from(bytes: [u8; 32]) -> Self {
        Blake2sDomain {
            state: bytes,
            _f: PhantomData,
        }
    }
}

#[allow(clippy::from_over_into)]
impl<F> Into<[u8; 32]> for Blake2sDomain<F> {
    fn into(self) -> [u8; 32] {
        self.state
    }
}

impl<F> From<Blake2sHash> for Blake2sDomain<F> {
    fn from(digest: Blake2sHash) -> Self {
        let mut domain = Blake2sDomain {
            state: *digest.as_array(),
            _f: PhantomData,
        };
        domain.trim_to_fr32();
        domain
    }
}

impl<F> AsRef<[u8]> for Blake2sDomain<F> {
    fn as_ref(&self) -> &[u8] {
        &self.state
    }
}

impl<F> AsRef<Self> for Blake2sDomain<F> {
    fn as_ref(&self) -> &Self {
        self
    }
}

// Implement comparison traits by hand because we have not bound `F` to have those traits.
impl<F> PartialEq for Blake2sDomain<F> {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl<F> Eq for Blake2sDomain<F> {}

impl<F> PartialOrd for Blake2sDomain<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.state.partial_cmp(&other.state)
    }
}

impl<F> Ord for Blake2sDomain<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.state.cmp(&other.state)
    }
}

impl<F: PrimeField> Element for Blake2sDomain<F> {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), Self::byte_len(), "invalid number of bytes");
        let mut state = [0u8; 32];
        state.copy_from_slice(bytes);
        state.into()
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.state);
    }
}

impl<F> std::hash::Hash for Blake2sDomain<F> {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        std::hash::Hash::hash(&self.state, hasher);
    }
}

// Implement `serde` traits by hand because we have not bound `F` to have those traits.
impl<F> Serialize for Blake2sDomain<F> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.state.serialize(s)
    }
}
impl<'de, F> Deserialize<'de> for Blake2sDomain<F> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <[u8; 32]>::deserialize(d).map(Into::into)
    }
}

impl Domain for Blake2sDomain<Fr> {
    type Field = Fr;
}
impl Domain for Blake2sDomain<Fp> {
    type Field = Fp;
}
impl Domain for Blake2sDomain<Fq> {
    type Field = Fq;
}

impl<F> Blake2sDomain<F> {
    // Strip the last (most-significant) two bits to ensure that we state within the ~256-bit field
    // `F`; note the fields `Fr`, `Fp`, and `Fq` are each 255-bit fields which fully utilize 254
    // bits, i.e. `254 < log2(field_modulus) < 255`.
    pub fn trim_to_fr32(&mut self) {
        self.state[31] &= 0b0011_1111;
    }
}

#[derive(Clone, Debug)]
pub struct Blake2sFunction<F> {
    hasher: State,
    _f: PhantomData<F>,
}

impl<F> Default for Blake2sFunction<F> {
    fn default() -> Self {
        Blake2sFunction {
            hasher: Blake2sBuilder::new().hash_length(32).to_state(),
            _f: PhantomData,
        }
    }
}

impl<F> std::hash::Hasher for Blake2sFunction<F> {
    fn write(&mut self, msg: &[u8]) {
        self.hasher.update(msg);
    }

    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

impl<F> Hashable<Blake2sFunction<F>> for Blake2sDomain<F> {
    fn hash(&self, hasher: &mut Blake2sFunction<F>) {
        <Blake2sFunction<F> as std::hash::Hasher>::write(hasher, self.as_ref());
    }
}

impl<F> Algorithm<Blake2sDomain<F>> for Blake2sFunction<F>
where
    F: PrimeField,
    Blake2sDomain<F>: Domain<Field = F>,
{
    fn hash(&mut self) -> Blake2sDomain<F> {
        self.hasher.clone().finalize().into()
    }

    fn reset(&mut self) {
        self.hasher = Blake2sBuilder::new().hash_length(32).to_state();
    }

    fn leaf(&mut self, leaf: Blake2sDomain<F>) -> Blake2sDomain<F> {
        leaf
    }

    fn node(
        &mut self,
        left: Blake2sDomain<F>,
        right: Blake2sDomain<F>,
        _height: usize,
    ) -> Blake2sDomain<F> {
        left.hash(self);
        right.hash(self);
        self.hash()
    }

    fn multi_node(&mut self, parts: &[Blake2sDomain<F>], _height: usize) -> Blake2sDomain<F> {
        for part in parts {
            part.hash(self);
        }
        self.hash()
    }
}

impl<F> HashFunction<Blake2sDomain<F>> for Blake2sFunction<F>
where
    F: PrimeField,
    Blake2sDomain<F>: Domain<Field = F>,
{
    fn hash(data: &[u8]) -> Blake2sDomain<F> {
        Blake2sBuilder::new()
            .hash_length(32)
            .to_state()
            .update(data)
            .finalize()
            .into()
    }

    fn hash2(a: &Blake2sDomain<F>, b: &Blake2sDomain<F>) -> Blake2sDomain<F> {
        Blake2sBuilder::new()
            .hash_length(32)
            .to_state()
            .update(a.as_ref())
            .update(b.as_ref())
            .finalize()
            .into()
    }
}

#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Blake2sHasher<F> {
    _f: PhantomData<F>,
}

// TODO (jake): should hashers over different fields have different names?
const HASHER_NAME: &str = "Blake2sHasher";

impl Hasher for Blake2sHasher<Fr> {
    type Field = Fr;
    type Domain = Blake2sDomain<Self::Field>;
    type Function = Blake2sFunction<Self::Field>;

    fn name() -> String {
        HASHER_NAME.into()
    }
}
impl Hasher for Blake2sHasher<Fp> {
    type Field = Fp;
    type Domain = Blake2sDomain<Self::Field>;
    type Function = Blake2sFunction<Self::Field>;

    fn name() -> String {
        HASHER_NAME.into()
    }
}
impl Hasher for Blake2sHasher<Fq> {
    type Field = Fq;
    type Domain = Blake2sDomain<Self::Field>;
    type Function = Blake2sFunction<Self::Field>;

    fn name() -> String {
        HASHER_NAME.into()
    }
}

// Only implement `Groth16Hasher` for `Blake2sHasher<Fr>` because `Fr` is the only field which is
// compatible with Groth16.
impl Groth16Hasher for Blake2sHasher<Fr> {
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

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        mut cs: CS,
        a_num: &AllocatedNum<Fr>,
        b_num: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
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
