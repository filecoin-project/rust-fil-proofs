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
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use pasta_curves::{Fp, Fq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Domain, HashFunction, Hasher};

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

// Implementing `Domain` for specific fields (rather than blanket implementing for all `F`) restricts
// users to using the fields which are compatible with `rust-fil-proofs`.
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

// Must add the trait bound `F: PrimeField` because `Algorithm` requires that `F` implements
// `Clone`.
impl<F: PrimeField> Algorithm<Blake2sDomain<F>> for Blake2sFunction<F> {
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

// Specialized implementation of `HashFunction` over the BLS12-381 scalar field `Fr` because that
// field is the only one which is compatible with `HashFunction`'s Groth16 circuit interfaces.
impl HashFunction<Blake2sDomain<Fr>> for Blake2sFunction<Fr> {
    fn hash(data: &[u8]) -> Blake2sDomain<Fr> {
        Blake2sBuilder::new()
            .hash_length(32)
            .to_state()
            .update(data)
            .finalize()
            .into()
    }

    fn hash2(a: &Blake2sDomain<Fr>, b: &Blake2sDomain<Fr>) -> Blake2sDomain<Fr> {
        Blake2sBuilder::new()
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

// Specialized implementation of `HashFunction` over the Pasta scalar fields `Fp` and `Fq` because
// those fields are incompatible with `HashFunction`'s circuit Groth16 interfaces.
impl HashFunction<Blake2sDomain<Fp>> for Blake2sFunction<Fp> {
    fn hash(data: &[u8]) -> Blake2sDomain<Fp> {
        Blake2sBuilder::new()
            .hash_length(32)
            .to_state()
            .update(data)
            .finalize()
            .into()
    }

    fn hash2(a: &Blake2sDomain<Fp>, b: &Blake2sDomain<Fp>) -> Blake2sDomain<Fp> {
        Blake2sBuilder::new()
            .hash_length(32)
            .to_state()
            .update(a.as_ref())
            .update(b.as_ref())
            .finalize()
            .into()
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _left: &AllocatedNum<Fr>,
        _right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fp> cannot be used within Groth16 circuits")
    }

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _a_num: &AllocatedNum<Fr>,
        _b_num: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fp> cannot be used within Groth16 circuits")
    }
}
impl HashFunction<Blake2sDomain<Fq>> for Blake2sFunction<Fq> {
    fn hash(data: &[u8]) -> Blake2sDomain<Fq> {
        Blake2sBuilder::new()
            .hash_length(32)
            .to_state()
            .update(data)
            .finalize()
            .into()
    }

    fn hash2(a: &Blake2sDomain<Fq>, b: &Blake2sDomain<Fq>) -> Blake2sDomain<Fq> {
        Blake2sBuilder::new()
            .hash_length(32)
            .to_state()
            .update(a.as_ref())
            .update(b.as_ref())
            .finalize()
            .into()
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _left: &AllocatedNum<Fr>,
        _right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fq> cannot be used within Groth16 circuits")
    }

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _a_num: &AllocatedNum<Fr>,
        _b_num: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Blake2sFunction<Fq> cannot be used within Groth16 circuits")
    }
}

#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Blake2sHasher<F> {
    _f: PhantomData<F>,
}

// Implementing `Hasher` for specific fields (rather than blanket implementing for all `F`) restricts
// users to using the fields which are compatible with `rust-fil-proofs`.
impl Hasher for Blake2sHasher<Fr> {
    type Domain = Blake2sDomain<Fr>;
    type Function = Blake2sFunction<Fr>;

    fn name() -> String {
        "Blake2sHasher".into()
    }
}
impl Hasher for Blake2sHasher<Fp> {
    type Domain = Blake2sDomain<Fp>;
    type Function = Blake2sFunction<Fp>;

    fn name() -> String {
        "Blake2sHasher_pallas".into()
    }
}
impl Hasher for Blake2sHasher<Fq> {
    type Domain = Blake2sDomain<Fq>;
    type Function = Blake2sFunction<Fq>;

    fn name() -> String {
        "Blake2sHasher_vesta".into()
    }
}
