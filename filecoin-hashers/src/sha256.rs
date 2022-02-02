use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use bellperson::{
    gadgets::{boolean::Boolean, multipack, num::AllocatedNum, sha256::sha256 as sha256_circuit},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use pasta_curves::{Fp, Fq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{Domain, HashFunction, Hasher};

#[derive(Copy, Clone, Default)]
pub struct Sha256Domain<F> {
    pub state: [u8; 32],
    _f: PhantomData<F>,
}

impl<F> Debug for Sha256Domain<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Domain({})", hex::encode(&self.state))
    }
}

// Can't blanket `impl<F> From<F> for Sha256Domain<F> where F: PrimeField` because it can conflict
// with `impl<F> From<[u8; 32]> for Sha256Domain<F>`, i.e. `[u8; 32]` is an external type which may
// already implement the external trait `PrimeField`, which causes a "conflicting implementation"
// compiler error.
impl From<Fr> for Sha256Domain<Fr> {
    fn from(f: Fr) -> Self {
        Sha256Domain {
            state: f.to_repr(),
            _f: PhantomData,
        }
    }
}
impl From<Fp> for Sha256Domain<Fp> {
    fn from(f: Fp) -> Self {
        Sha256Domain {
            state: f.to_repr(),
            _f: PhantomData,
        }
    }
}
impl From<Fq> for Sha256Domain<Fq> {
    fn from(f: Fq) -> Self {
        Sha256Domain {
            state: f.to_repr(),
            _f: PhantomData,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<Fr> for Sha256Domain<Fr> {
    fn into(self) -> Fr {
        Fr::from_repr_vartime(self.state).expect("from_repr failure")
    }
}
#[allow(clippy::from_over_into)]
impl Into<Fp> for Sha256Domain<Fp> {
    fn into(self) -> Fp {
        Fp::from_repr_vartime(self.state).expect("from_repr failure")
    }
}
#[allow(clippy::from_over_into)]
impl Into<Fq> for Sha256Domain<Fq> {
    fn into(self) -> Fq {
        Fq::from_repr_vartime(self.state).expect("from_repr failure")
    }
}

// Currently, these panics serve as a stopgap to prevent accidental conversions of a Pasta field
// domains to/from a BLS12-381 scalar field domain.
impl From<Fr> for Sha256Domain<Fp> {
    fn from(_f: Fr) -> Self {
        panic!("cannot convert BLS12-381 scalar into Sha256Domain<Fp>")
    }
}
#[allow(clippy::from_over_into)]
impl Into<Fr> for Sha256Domain<Fp> {
    fn into(self) -> Fr {
        panic!("cannot convert Sha256Domain<Fp> into BLS12-381 scalar");
    }
}
impl From<Fr> for Sha256Domain<Fq> {
    fn from(_f: Fr) -> Self {
        panic!("cannot convert BLS12-381 scalar into Sha256Domain<Fq>")
    }
}
#[allow(clippy::from_over_into)]
impl Into<Fr> for Sha256Domain<Fq> {
    fn into(self) -> Fr {
        panic!("cannot convert Sha256Domain<Fq> into BLS12-381 scalar");
    }
}

impl<F> From<[u8; 32]> for Sha256Domain<F> {
    fn from(bytes: [u8; 32]) -> Self {
        Sha256Domain {
            state: bytes,
            _f: PhantomData,
        }
    }
}

impl<F> AsRef<[u8]> for Sha256Domain<F> {
    fn as_ref(&self) -> &[u8] {
        &self.state
    }
}

impl<F> AsRef<Self> for Sha256Domain<F> {
    fn as_ref(&self) -> &Self {
        self
    }
}

// Implement comparison traits by hand because we have not bound `F` to have those traits.
impl<F> PartialEq for Sha256Domain<F> {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl<F> Eq for Sha256Domain<F> {}

impl<F> PartialOrd for Sha256Domain<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.state.partial_cmp(&other.state)
    }
}

impl<F> Ord for Sha256Domain<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.state.cmp(&other.state)
    }
}

// Must add the trait bound `F: PrimeField` because `Element` requires that `F` implements `Clone`,
// `Send`, and `Sync`.
impl<F: PrimeField> Element for Sha256Domain<F> {
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

impl<F> std::hash::Hash for Sha256Domain<F> {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        std::hash::Hash::hash(&self.state, hasher);
    }
}

// Implement `serde` traits by hand because we have not bound `F` to have those traits.
impl<F> Serialize for Sha256Domain<F> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.state.serialize(s)
    }
}
impl<'de, F> Deserialize<'de> for Sha256Domain<F> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <[u8; 32]>::deserialize(d).map(Into::into)
    }
}

// Implementing `Domain` for specific fields (rather than blanket implementing for all `F`) restricts
// users to using the fields which are compatible with `rust-fil-proofs`.
impl Domain for Sha256Domain<Fr> {
    type Field = Fr;
}
impl Domain for Sha256Domain<Fp> {
    type Field = Fp;
}
impl Domain for Sha256Domain<Fq> {
    type Field = Fq;
}

impl<F> Sha256Domain<F> {
    // Strip the last (most-significant) two bits to ensure that we state within the ~256-bit field
    // `F`; note the fields `Fr`, `Fp`, and `Fq` are each 255-bit fields which fully utilize 254
    // bits, i.e. `254 < log2(field_modulus) < 255`.
    fn trim_to_fr32(&mut self) {
        self.state[31] &= 0b0011_1111;
    }
}

#[derive(Clone, Debug, Default)]
pub struct Sha256Function<F> {
    hasher: Sha256,
    _f: PhantomData<F>,
}

impl<F> std::hash::Hasher for Sha256Function<F> {
    fn write(&mut self, msg: &[u8]) {
        self.hasher.update(msg);
    }

    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called");
    }
}

impl<F> Hashable<Sha256Function<F>> for Sha256Domain<F> {
    fn hash(&self, hasher: &mut Sha256Function<F>) {
        <Sha256Function<F> as std::hash::Hasher>::write(hasher, self.as_ref());
    }
}

// Must add the trait bound `F: PrimeField` because `Algorithm` requires that `F` implements `Clone`
// and `Default`.
impl<F: PrimeField> Algorithm<Sha256Domain<F>> for Sha256Function<F> {
    fn hash(&mut self) -> Sha256Domain<F> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(self.hasher.clone().finalize().as_ref());
        let mut trimmed = Sha256Domain {
            state: digest,
            _f: PhantomData,
        };
        trimmed.trim_to_fr32();
        trimmed
    }

    fn reset(&mut self) {
        self.hasher.reset();
    }

    fn leaf(&mut self, leaf: Sha256Domain<F>) -> Sha256Domain<F> {
        leaf
    }

    fn node(
        &mut self,
        left: Sha256Domain<F>,
        right: Sha256Domain<F>,
        _height: usize,
    ) -> Sha256Domain<F> {
        left.hash(self);
        right.hash(self);
        self.hash()
    }

    fn multi_node(&mut self, parts: &[Sha256Domain<F>], _height: usize) -> Sha256Domain<F> {
        for part in parts {
            part.hash(self);
        }
        self.hash()
    }
}

// Specialized implementation of `HashFunction` over the BLS12-381 scalar field `Fr` because `Fr`
// is the only field which is compatible with `HashFunction`'s Groth16 circuit interfaces.
impl HashFunction<Sha256Domain<Fr>> for Sha256Function<Fr> {
    fn hash(data: &[u8]) -> Sha256Domain<Fr> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(Sha256::digest(data).as_ref());
        let mut trimmed: Sha256Domain<Fr> = digest.into();
        trimmed.trim_to_fr32();
        trimmed
    }

    fn hash2(a: &Sha256Domain<Fr>, b: &Sha256Domain<Fr>) -> Sha256Domain<Fr> {
        let mut digest = [0u8; 32];
        let hasher = Sha256::new()
            .chain(AsRef::<[u8]>::as_ref(a))
            .chain(AsRef::<[u8]>::as_ref(b));
        digest.copy_from_slice(hasher.finalize().as_ref());
        let mut trimmed: Sha256Domain<Fr> = digest.into();
        trimmed.trim_to_fr32();
        trimmed
    }

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<Fr>>(
        mut cs: CS,
        leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let mut bits = Vec::with_capacity(leaves.len() * Fr::CAPACITY as usize);
        for (i, leaf) in leaves.iter().enumerate() {
            let mut padded = leaf.to_bits_le(cs.namespace(|| format!("{}_num_into_bits", i)))?;
            while padded.len() % 8 != 0 {
                padded.push(Boolean::Constant(false));
            }

            bits.extend(
                padded
                    .chunks_exact(8)
                    .flat_map(|chunk| chunk.iter().rev())
                    .cloned(),
            );
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

        let mut left_padded = left.to_vec();
        while left_padded.len() % 8 != 0 {
            left_padded.push(Boolean::Constant(false));
        }

        preimage.extend(
            left_padded
                .chunks_exact(8)
                .flat_map(|chunk| chunk.iter().rev())
                .cloned(),
        );

        let mut right_padded = right.to_vec();
        while right_padded.len() % 8 != 0 {
            right_padded.push(Boolean::Constant(false));
        }

        preimage.extend(
            right_padded
                .chunks_exact(8)
                .flat_map(|chunk| chunk.iter().rev())
                .cloned(),
        );

        Self::hash_circuit(cs, &preimage[..])
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        mut cs: CS,
        bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let be_bits = sha256_circuit(cs.namespace(|| "hash"), bits)?;
        let le_bits = be_bits
            .chunks(8)
            .flat_map(|chunk| chunk.iter().rev())
            .cloned()
            .take(Fr::CAPACITY as usize)
            .collect::<Vec<_>>();
        multipack::pack_bits(cs.namespace(|| "pack_le"), &le_bits)
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

        let mut a_padded = a.to_vec();
        while a_padded.len() % 8 != 0 {
            a_padded.push(Boolean::Constant(false));
        }

        preimage.extend(
            a_padded
                .chunks_exact(8)
                .flat_map(|chunk| chunk.iter().rev())
                .cloned(),
        );

        let mut b_padded = b.to_vec();
        while b_padded.len() % 8 != 0 {
            b_padded.push(Boolean::Constant(false));
        }

        preimage.extend(
            b_padded
                .chunks_exact(8)
                .flat_map(|chunk| chunk.iter().rev())
                .cloned(),
        );

        Self::hash_circuit(cs, &preimage[..])
    }
}

// Specialized implementation of `HashFunction` over the Pasta scalar fields `Fp` and `Fq` because
// those fields are incompatible with `HashFunction`'s Groth16 circuit interfaces.
impl HashFunction<Sha256Domain<Fp>> for Sha256Function<Fp> {
    fn hash(data: &[u8]) -> Sha256Domain<Fp> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(Sha256::digest(data).as_ref());
        let mut trimmed: Sha256Domain<Fp> = digest.into();
        trimmed.trim_to_fr32();
        trimmed
    }

    fn hash2(a: &Sha256Domain<Fp>, b: &Sha256Domain<Fp>) -> Sha256Domain<Fp> {
        let mut digest = [0u8; 32];
        let hasher = Sha256::new()
            .chain(AsRef::<[u8]>::as_ref(a))
            .chain(AsRef::<[u8]>::as_ref(b));
        digest.copy_from_slice(hasher.finalize().as_ref());
        let mut trimmed: Sha256Domain<Fp> = digest.into();
        trimmed.trim_to_fr32();
        trimmed
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _left: &AllocatedNum<Fr>,
        _right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fp> cannot be used within Groth16 circuits")
    }

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _a_num: &AllocatedNum<Fr>,
        _b_num: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fp> cannot be used within Groth16 circuits")
    }
}
impl HashFunction<Sha256Domain<Fq>> for Sha256Function<Fq> {
    fn hash(data: &[u8]) -> Sha256Domain<Fq> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(Sha256::digest(data).as_ref());
        let mut trimmed: Sha256Domain<Fq> = digest.into();
        trimmed.trim_to_fr32();
        trimmed
    }

    fn hash2(a: &Sha256Domain<Fq>, b: &Sha256Domain<Fq>) -> Sha256Domain<Fq> {
        let mut digest = [0u8; 32];
        let hasher = Sha256::new()
            .chain(AsRef::<[u8]>::as_ref(a))
            .chain(AsRef::<[u8]>::as_ref(b));
        digest.copy_from_slice(hasher.finalize().as_ref());
        let mut trimmed: Sha256Domain<Fq> = digest.into();
        trimmed.trim_to_fr32();
        trimmed
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _left: &AllocatedNum<Fr>,
        _right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fq> cannot be used within Groth16 circuits")
    }

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _a_num: &AllocatedNum<Fr>,
        _b_num: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("Sha256Function<Fq> cannot be used within Groth16 circuits")
    }
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sha256Hasher<F> {
    _f: PhantomData<F>,
}

// Implementing `Hasher` for specific fields (rather than blanket implementing for all `F`)
// restricts users to using the fields which are compatible with `rust-fil-proofs`.
impl Hasher for Sha256Hasher<Fr> {
    type Domain = Sha256Domain<Fr>;
    type Function = Sha256Function<Fr>;

    fn name() -> String {
        "sha256_hasher".into()
    }
}
impl Hasher for Sha256Hasher<Fp> {
    type Domain = Sha256Domain<Fp>;
    type Function = Sha256Function<Fp>;

    fn name() -> String {
        "sha256_hasher_pallas".into()
    }
}
impl Hasher for Sha256Hasher<Fq> {
    type Domain = Sha256Domain<Fq>;
    type Function = Sha256Function<Fq>;

    fn name() -> String {
        "sha256_hasher_vesta".into()
    }
}
