use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::hash::Hasher as StdHasher;
use std::marker::PhantomData;
use std::panic::panic_any;

use bellperson::{
    gadgets::{
        blake2s::blake2s as blake2s_circuit, boolean::Boolean, multipack, num::AllocatedNum,
    },
    ConstraintSystem, SynthesisError,
};
use blake2s_simd::{Hash as Blake2sHash, Params as Blake2s, State};
use blstrs::Scalar as Fr;
use ff::{PrimeField, PrimeFieldBits};
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
#[cfg(feature = "nova")]
use pasta_curves::{Fp, Fq};
use serde::{Deserialize, Serialize};

use crate::types::{impl_hasher_for_field, Domain, HashFunction, Hasher};

#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Blake2sHasher<F = Fr> {
    _f: PhantomData<F>,
}

#[derive(Clone)]
pub struct Blake2sFunction<F = Fr> {
    hasher: State,
    _f: PhantomData<F>,
}

impl<F> Default for Blake2sFunction<F> {
    fn default() -> Self {
        Blake2sFunction {
            hasher: Blake2s::new().hash_length(32).to_state(),
            _f: PhantomData,
        }
    }
}

impl<F> PartialEq for Blake2sFunction<F> {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self) == format!("{:?}", other)
    }
}

impl<F> Eq for Blake2sFunction<F> {}

impl<F> Debug for Blake2sFunction<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Blake2sFunction({:?})", self.hasher)
    }
}

impl<F> StdHasher for Blake2sFunction<F> {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.hasher.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Blake2sDomain<F = Fr> {
    pub state: [u8; 32],
    #[serde(skip)]
    _f: PhantomData<F>,
}

impl<F> Debug for Blake2sDomain<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Blake2sDomain<{}>({})",
            std::any::type_name::<F>(),
            hex::encode(&self.state),
        )
    }
}

impl<F> Default for Blake2sDomain<F> {
    fn default() -> Self {
        Blake2sDomain {
            state: <[u8; 32]>::default(),
            _f: PhantomData,
        }
    }
}

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

impl<F> std::hash::Hash for Blake2sDomain<F> {
    fn hash<H: StdHasher>(&self, hasher: &mut H) {
        std::hash::Hash::hash(&self.state, hasher);
    }
}

impl<F> AsRef<Blake2sDomain<F>> for Blake2sDomain<F> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<F> Blake2sDomain<F> {
    pub fn trim_to_fr32(&mut self) {
        // strip two most significant bits, to ensure result is a valid 255-bit field element.
        self.state[31] &= 0b0011_1111;
    }
}

impl<F> AsRef<[u8]> for Blake2sDomain<F> {
    fn as_ref(&self) -> &[u8] {
        &self.state
    }
}

impl<F> Hashable<Blake2sFunction<F>> for Blake2sDomain<F> {
    fn hash(&self, state: &mut Blake2sFunction<F>) {
        state.write(self.as_ref())
    }
}

impl<F> Element for Blake2sDomain<F>
where
    F: PrimeField,
    Self: Domain<Field = F>,
{
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
        bytes.copy_from_slice(&self.state);
    }
}

#[allow(clippy::from_over_into)]
impl<F> Into<Blake2sDomain<F>> for Blake2sHash {
    fn into(self) -> Blake2sDomain<F> {
        let mut res = Blake2sDomain::default();
        res.state[..].copy_from_slice(self.as_ref());
        res.trim_to_fr32();

        res
    }
}

impl<F> HashFunction<Blake2sDomain<F>> for Blake2sFunction<F>
where
    F: PrimeFieldBits,
    Blake2sDomain<F>: Domain<Field = F>,
{
    fn hash(data: &[u8]) -> Blake2sDomain<F> {
        Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(data)
            .finalize()
            .into()
    }

    fn hash2(a: &Blake2sDomain<F>, b: &Blake2sDomain<F>) -> Blake2sDomain<F> {
        Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(a.as_ref())
            .update(b.as_ref())
            .finalize()
            .into()
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<F>>(
        mut cs: CS,
        left: &AllocatedNum<F>,
        right: &AllocatedNum<F>,
        height: usize,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let left_bits = left.to_bits_le(cs.namespace(|| "left num into bits"))?;
        let right_bits = right.to_bits_le(cs.namespace(|| "right num into bits"))?;

        Self::hash_leaf_bits_circuit(cs, &left_bits, &right_bits, height)
    }

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<F>>(
        mut cs: CS,
        leaves: &[AllocatedNum<F>],
        _height: usize,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let mut bits = Vec::with_capacity(leaves.len() * F::CAPACITY as usize);
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

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<F>>(
        cs: CS,
        left: &[Boolean],
        right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
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

    fn hash_circuit<CS: ConstraintSystem<F>>(
        mut cs: CS,
        bits: &[Boolean],
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let personalization = vec![0u8; 8];
        let alloc_bits = blake2s_circuit(cs.namespace(|| "hash"), bits, &personalization)?;

        multipack::pack_bits(cs.namespace(|| "pack"), &alloc_bits)
    }

    fn hash2_circuit<CS: ConstraintSystem<F>>(
        mut cs: CS,
        a_num: &AllocatedNum<F>,
        b_num: &AllocatedNum<F>,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
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

impl<F> Algorithm<Blake2sDomain<F>> for Blake2sFunction<F>
where
    F: PrimeField,
    Blake2sDomain<F>: Domain<Field = F>,
{
    #[inline]
    fn hash(&mut self) -> Blake2sDomain<F> {
        self.hasher.clone().finalize().into()
    }

    #[inline]
    fn reset(&mut self) {
        self.hasher = Blake2s::new().hash_length(32).to_state();
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
            part.hash(self)
        }
        self.hash()
    }
}

impl<F> From<[u8; 32]> for Blake2sDomain<F> {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        Blake2sDomain {
            state: val,
            _f: PhantomData,
        }
    }
}

impl<F> From<Blake2sDomain<F>> for [u8; 32] {
    #[inline]
    fn from(val: Blake2sDomain<F>) -> Self {
        val.state
    }
}

impl_hasher_for_field!(Blake2sHasher, Blake2sDomain, Blake2sFunction, "Blake2sHasher", Fr);

#[cfg(feature = "nova")]
impl_hasher_for_field!(Blake2sHasher, Blake2sDomain, Blake2sFunction, "Blake2sHasher", Fp, Fq);
