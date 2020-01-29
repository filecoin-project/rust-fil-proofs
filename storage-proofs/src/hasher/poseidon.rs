use std::hash::Hasher as StdHasher;

use crate::crypto::{create_label, sloth};
use crate::error::{Error, Result};
use crate::hasher::{Domain, HashFunction, Hasher};
use anyhow::ensure;
use bellperson::gadgets::{boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use fil_sapling_crypto::jubjub::JubjubEngine;
use merkletree::hash::{Algorithm as LightAlgorithm, Hashable};
use merkletree::merkle::Element;
use neptune::circuit::poseidon_hash_simple;
use neptune::poseidon::poseidon;
use paired::bls12_381::{Bls12, Fr, FrRepr};
use serde::{Deserialize, Serialize};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHasher {}

impl Hasher for PoseidonHasher {
    type Domain = PoseidonDomain;
    type Function = PoseidonFunction;

    fn name() -> String {
        "PoseidonHasher".into()
    }

    fn create_label(data: &[u8], m: usize) -> Result<Self::Domain> {
        Ok(create_label::create_label(data, m)?.into())
    }

    #[inline]
    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain> {
        // Unrapping here is safe; `Fr` elements and hash domain elements are the same byte length.
        let key = Fr::from_repr(key.0)?;
        let ciphertext = Fr::from_repr(ciphertext.0)?;
        Ok(sloth::encode::<Bls12>(&key, &ciphertext).into())
    }

    #[inline]
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain> {
        // Unrapping here is safe; `Fr` elements and hash domain elements are the same byte length.
        let key = Fr::from_repr(key.0)?;
        let ciphertext = Fr::from_repr(ciphertext.0)?;

        Ok(sloth::decode::<Bls12>(&key, &ciphertext).into())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PoseidonFunction(Fr);

impl Default for PoseidonFunction {
    fn default() -> PoseidonFunction {
        PoseidonFunction(Fr::from_repr(FrRepr::default()).expect("failed default"))
    }
}

impl Hashable<PoseidonFunction> for Fr {
    fn hash(&self, state: &mut PoseidonFunction) {
        let mut bytes = Vec::with_capacity(32);
        self.into_repr().write_le(&mut bytes).unwrap();
        state.write(&bytes);
    }
}

impl Hashable<PoseidonFunction> for PoseidonDomain {
    fn hash(&self, state: &mut PoseidonFunction) {
        let mut bytes = Vec::with_capacity(32);
        self.0
            .write_le(&mut bytes)
            .expect("Failed to write `FrRepr`");
        state.write(&bytes);
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PoseidonDomain(pub FrRepr);

impl AsRef<PoseidonDomain> for PoseidonDomain {
    fn as_ref(&self) -> &PoseidonDomain {
        self
    }
}

impl std::hash::Hash for PoseidonDomain {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let raw: &[u64] = self.0.as_ref();
        std::hash::Hash::hash(raw, state);
    }
}

impl PartialEq for PoseidonDomain {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Eq for PoseidonDomain {}

impl Default for PoseidonDomain {
    fn default() -> PoseidonDomain {
        PoseidonDomain(FrRepr::default())
    }
}

impl Ord for PoseidonDomain {
    #[inline(always)]
    fn cmp(&self, other: &PoseidonDomain) -> ::std::cmp::Ordering {
        (self.0).cmp(&other.0)
    }
}

impl PartialOrd for PoseidonDomain {
    #[inline(always)]
    fn partial_cmp(&self, other: &PoseidonDomain) -> Option<::std::cmp::Ordering> {
        Some((self.0).cmp(&other.0))
    }
}

impl AsRef<[u8]> for PoseidonDomain {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        as_ref(&(self.0).0)
    }
}

// This is unsafe, and I wish it wasn't here, but I really need AsRef<[u8]> to work, without allocating.
// https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
// https://github.com/briansmith/ring/blob/abb3fdfc08562f3f02e95fb551604a871fd4195e/src/polyfill.rs#L93-L110
#[inline(always)]
#[allow(clippy::needless_lifetimes)]
fn as_ref<'a>(src: &'a [u64; 4]) -> &'a [u8] {
    unsafe {
        std::slice::from_raw_parts(
            src.as_ptr() as *const u8,
            src.len() * std::mem::size_of::<u64>(),
        )
    }
}

impl Domain for PoseidonDomain {
    // QUESTION: When, if ever, should serialize and into_bytes return different results?
    // The definitions here at least are equivalent.
    // I'm taking one step toward resolving this by formalizing that equivalence while copying this base implementation from perdersen.rs. -porcuquine.
    fn serialize(&self) -> Vec<u8> {
        self.into_bytes()
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PoseidonDomain::byte_len());
        self.0.write_le(&mut out).unwrap();

        out
    }

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        ensure!(raw.len() == PoseidonDomain::byte_len(), Error::BadFrBytes);
        let mut res: FrRepr = Default::default();
        res.read_le(raw)?;

        Ok(PoseidonDomain(res))
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        self.0.write_le(dest)?;
        Ok(())
    }

    fn random<R: rand::RngCore>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        Fr::random(rng).into()
    }
}

impl Element for PoseidonDomain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match PoseidonDomain::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic!(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.into_bytes());
    }
}

impl StdHasher for PoseidonFunction {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0 = Fr::from_repr(poseidon_hash(msg).0).unwrap();
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

fn poseidon_hash(data: &[u8]) -> PoseidonDomain {
    // FIXME: We shouldn't unwrap here, but doing otherwise will require an interface change.
    // We could truncate so `bytes_into_frs` cannot fail, then ensure `data` is always `fr_safe`.
    let preimage = data
        .chunks(32)
        .map(|ref chunk| {
            <Bls12 as ff::ScalarEngine>::Fr::from_repr(PoseidonDomain::from_slice(chunk).0).unwrap()
        })
        .collect::<Vec<_>>();

    let fr: <Bls12 as ScalarEngine>::Fr = poseidon::<Bls12>(&preimage);
    fr.into()
}

impl HashFunction<PoseidonDomain> for PoseidonFunction {
    //fn hash<E: JubjubEngine>(data: &[u8]) -> PoseidonDomain {
    fn hash(data: &[u8]) -> PoseidonDomain {
        poseidon_hash(data)
    }

    fn hash_leaf_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        cs: CS,
        left: &num::AllocatedNum<E>,
        right: &num::AllocatedNum<E>,
        _height: usize,
        _params: &E::Params,
    ) -> ::std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        let preimage = vec![left.clone(), right.clone()];

        poseidon_hash_simple::<CS, E>(cs, preimage)
    }

    fn hash_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        _cs: CS,
        _bits: &[boolean::Boolean],
        _params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        unimplemented!();
    }
}

impl LightAlgorithm<PoseidonDomain> for PoseidonFunction {
    #[inline]
    fn hash(&mut self) -> PoseidonDomain {
        self.0.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Fr::from_repr(FrRepr::from(0)).expect("failed 0");
    }

    fn leaf(&mut self, leaf: PoseidonDomain) -> PoseidonDomain {
        leaf
    }

    fn node(
        &mut self,
        left: PoseidonDomain,
        right: PoseidonDomain,
        _height: usize,
    ) -> PoseidonDomain {
        PoseidonDomain(
            poseidon::<Bls12>(&[
                <Bls12 as ff::ScalarEngine>::Fr::from_repr(left.0).unwrap(),
                <Bls12 as ff::ScalarEngine>::Fr::from_repr(right.0).unwrap(),
            ])
            .into(),
        )
    }
}

impl From<Fr> for PoseidonDomain {
    #[inline]
    fn from(val: Fr) -> Self {
        PoseidonDomain(val.into_repr())
    }
}

impl From<FrRepr> for PoseidonDomain {
    #[inline]
    fn from(val: FrRepr) -> Self {
        PoseidonDomain(val)
    }
}

impl From<PoseidonDomain> for Fr {
    #[inline]
    fn from(val: PoseidonDomain) -> Self {
        Fr::from_repr(val.0).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    use merkletree::hash::Hashable;

    use crate::merkle::MerkleTree;

    #[test]
    fn test_path() {
        let values = [
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
        ];

        let t =
            MerkleTree::<PoseidonDomain, PoseidonFunction>::new(values.iter().map(|x| *x)).unwrap();

        let p = t.gen_proof(0).unwrap(); // create a proof for the first value =k Fr::one()

        assert_eq!(*p.path(), vec![true, true]);
        assert_eq!(p.validate::<PoseidonFunction>(), true);
    }

    #[test]
    fn test_poseidon_hasher() {
        let leaves = [
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::zero().into_repr()),
            PoseidonDomain(Fr::zero().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
        ];

        let t =
            MerkleTree::<PoseidonDomain, PoseidonFunction>::new(leaves.iter().map(|x| *x)).unwrap();

        assert_eq!(t.leafs(), 4);

        let mut a = PoseidonFunction::default();

        assert_eq!(t.read_at(0).unwrap(), leaves[0]);
        assert_eq!(t.read_at(1).unwrap(), leaves[1]);
        assert_eq!(t.read_at(2).unwrap(), leaves[2]);
        assert_eq!(t.read_at(3).unwrap(), leaves[3]);

        let i1 = a.node(leaves[0], leaves[1], 0);
        a.reset();
        let i2 = a.node(leaves[2], leaves[3], 0);
        a.reset();

        assert_eq!(t.read_at(4).unwrap(), i1);
        assert_eq!(t.read_at(5).unwrap(), i2);

        let root = a.node(i1, i2, 1);
        a.reset();

        assert_eq!(
            t.read_at(4).unwrap().0,
            FrRepr([
                0x27667a53c9973ad5,
                0x7e0295caba457e67,
                0xa20c36b1b4f719a8,
                0x25b81b8c404581d5
            ])
        );

        let expected = FrRepr([
            0x15f039c35270cef7,
            0x66b6af463d76d9f6,
            0x10b959b9478c32c7,
            0x681da1446cf7b965,
        ]);
        let actual = t.read_at(6).unwrap().0;

        assert_eq!(actual, expected);
        assert_eq!(t.read_at(6).unwrap(), root);
    }

    #[test]
    fn test_as_ref() {
        let cases: Vec<[u64; 4]> = vec![
            [0, 0, 0, 0],
            [
                14963070332212552755,
                2414807501862983188,
                16116531553419129213,
                6357427774790868134,
            ],
        ];

        for case in cases.into_iter() {
            let repr = FrRepr(case);
            let val = PoseidonDomain(repr);

            for _ in 0..100 {
                assert_eq!(val.into_bytes(), val.into_bytes());
            }

            let raw: &[u8] = val.as_ref();

            for i in 0..4 {
                assert_eq!(case[i], unsafe {
                    let mut val = [0u8; 8];
                    val.clone_from_slice(&raw[i * 8..(i + 1) * 8]);
                    mem::transmute::<[u8; 8], u64>(val)
                });
            }
        }
    }

    #[test]
    fn test_serialize() {
        let repr = FrRepr([1, 2, 3, 4]);
        let val = PoseidonDomain(repr);

        let ser = serde_json::to_string(&val)
            .expect("Failed to serialize `PoseidonDomain` element to JSON string");
        let val_back = serde_json::from_str(&ser)
            .expect("Failed to deserialize JSON string to `PoseidonnDomain`");

        assert_eq!(val, val_back);
    }
}
