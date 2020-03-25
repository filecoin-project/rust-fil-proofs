use std::hash::Hasher as StdHasher;

use crate::crypto::sloth;
use crate::error::{Error, Result};
use crate::hasher::types::{
    PoseidonArity, PoseidonEngine, PoseidonMDArity, POSEIDON_CONSTANTS_1, POSEIDON_CONSTANTS_16,
    POSEIDON_CONSTANTS_2, POSEIDON_CONSTANTS_4, POSEIDON_CONSTANTS_8, POSEIDON_MD_CONSTANTS,
};
use crate::hasher::{Domain, HashFunction, Hasher};
use anyhow::ensure;
use bellperson::gadgets::{boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;
use generic_array::typenum::marker_traits::Unsigned;
use merkletree::hash::{Algorithm as LightAlgorithm, Hashable};
use merkletree::merkle::Element;
use neptune::circuit::poseidon_hash;
use neptune::poseidon::Poseidon;
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
        self.0 = Fr::from_repr(shared_hash(msg).0).unwrap();
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

fn shared_hash(data: &[u8]) -> PoseidonDomain {
    // FIXME: We shouldn't unwrap here, but doing otherwise will require an interface change.
    // We could truncate so `bytes_into_frs` cannot fail, then ensure `data` is always `fr_safe`.
    let preimage = data
        .chunks(32)
        .map(|ref chunk| {
            <Bls12 as ff::ScalarEngine>::Fr::from_repr(PoseidonDomain::from_slice(chunk).0).unwrap()
        })
        .collect::<Vec<_>>();

    shared_hash_frs(&preimage).into()
}

fn shared_hash_frs(
    preimage: &[<Bls12 as ff::ScalarEngine>::Fr],
) -> <Bls12 as ff::ScalarEngine>::Fr {
    match preimage.len() {
        1 => {
            let mut p = Poseidon::new_with_preimage(&preimage, &*POSEIDON_CONSTANTS_1);
            p.hash()
        }
        2 => {
            let mut p = Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_2);
            p.hash()
        }
        4 => {
            let mut p = Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_4);
            p.hash()
        }
        8 => {
            let mut p = Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_8);
            p.hash()
        }
        16 => {
            let mut p = Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_16);
            p.hash()
        }

        _ => panic!("Unsupported arity for Poseidon hasher: {}", preimage.len()),
    }
}

impl HashFunction<PoseidonDomain> for PoseidonFunction {
    fn hash(data: &[u8]) -> PoseidonDomain {
        shared_hash(data)
    }

    fn hash2(a: &PoseidonDomain, b: &PoseidonDomain) -> PoseidonDomain {
        let mut p =
            Poseidon::new_with_preimage(&[(*a).into(), (*b).into()][..], &*POSEIDON_CONSTANTS_2);
        let fr: <Bls12 as ScalarEngine>::Fr = p.hash();
        fr.into()
    }

    fn hash_md(input: &[PoseidonDomain]) -> PoseidonDomain {
        assert!(input.len() > 1, "hash_md needs more than one element.");
        let arity = PoseidonMDArity::to_usize();

        let mut p = Poseidon::new(&*POSEIDON_MD_CONSTANTS);

        let fr_input = input
            .iter()
            .map(|x| <Bls12 as ScalarEngine>::Fr::from_repr(x.0).unwrap())
            .collect::<Vec<_>>();

        fr_input[1..]
            .chunks(arity - 1)
            .fold(fr_input[0], |acc, elts| {
                p.reset();
                p.input(acc).unwrap(); // These unwraps will panic iff arity is incorrect, but it was checked above.
                elts.iter().for_each(|elt| {
                    let _ = p.input(*elt).unwrap();
                });
                p.hash()
            })
            .into()
    }

    fn hash_leaf_circuit<E: JubjubEngine + PoseidonEngine<typenum::U2>, CS: ConstraintSystem<E>>(
        cs: CS,
        left: &num::AllocatedNum<E>,
        right: &num::AllocatedNum<E>,
        _height: usize,
        _params: &E::Params,
    ) -> ::std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        let preimage = vec![left.clone(), right.clone()];

        poseidon_hash::<CS, E, typenum::U2>(cs, preimage, E::PARAMETERS())
    }

    fn hash_multi_leaf_circuit<
        Arity: 'static,
        E: JubjubEngine + PoseidonEngine<Arity>,
        CS: ConstraintSystem<E>,
    >(
        cs: CS,
        leaves: &[num::AllocatedNum<E>],
        _height: usize,
        _params: &E::Params,
    ) -> ::std::result::Result<num::AllocatedNum<E>, SynthesisError>
    where
        Arity: PoseidonArity<E>,
        typenum::Add1<Arity>: generic_array::ArrayLength<E::Fr>,
    {
        let params = E::PARAMETERS();
        poseidon_hash::<CS, E, Arity>(cs, leaves.to_vec(), params)
    }

    fn hash_md_circuit<
        E: JubjubEngine + PoseidonEngine<PoseidonMDArity>,
        CS: ConstraintSystem<E>,
    >(
        cs: &mut CS,
        elements: &[num::AllocatedNum<E>],
    ) -> ::std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        let params = E::PARAMETERS();
        let arity = PoseidonMDArity::to_usize();

        let mut hash = elements[0].clone();
        let mut preimage = vec![hash.clone(); arity]; // Allocate. This will be overwritten.
        let mut hash_num = 0;
        for elts in elements[1..].chunks(arity - 1) {
            preimage[0] = hash;
            for (i, elt) in elts.iter().enumerate() {
                preimage[i + 1] = elt.clone();
            }
            // any terminal padding
            #[allow(clippy::needless_range_loop)]
            for i in (elts.len() + 1)..arity {
                preimage[i] =
                    num::AllocatedNum::alloc(cs.namespace(|| format!("padding {}", i)), || {
                        Ok(E::Fr::zero())
                    })
                    .unwrap();
            }
            let cs = cs.namespace(|| format!("hash md {}", hash_num));
            hash = poseidon_hash::<_, E, PoseidonMDArity>(cs, preimage.clone(), params)?.clone();
            hash_num += 1;
        }

        Ok(hash)
    }

    fn hash_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        _cs: CS,
        _bits: &[boolean::Boolean],
        _params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        unimplemented!();
    }

    fn hash2_circuit<E, CS>(
        cs: CS,
        a: &num::AllocatedNum<E>,
        b: &num::AllocatedNum<E>,
        _params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError>
    where
        E: JubjubEngine + PoseidonEngine<typenum::U2>,
        CS: ConstraintSystem<E>,
    {
        let preimage = vec![a.clone(), b.clone()];
        poseidon_hash::<CS, E, typenum::U2>(cs, preimage, E::PARAMETERS())
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
        shared_hash_frs(&[
            <Bls12 as ff::ScalarEngine>::Fr::from_repr(left.0).unwrap(),
            <Bls12 as ff::ScalarEngine>::Fr::from_repr(right.0).unwrap(),
        ])
        .into()
    }

    fn multi_node(&mut self, parts: &[PoseidonDomain], _height: usize) -> PoseidonDomain {
        match parts.len() {
            1 | 2 | 4 | 8 | 16 => shared_hash_frs(
                &parts
                    .iter()
                    .map(|x| <Bls12 as ff::ScalarEngine>::Fr::from_repr(x.0).unwrap())
                    .collect::<Vec<_>>(),
            )
            .into(),
            arity => panic!("unsupported arity {}", arity),
        }
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

    use crate::gadgets::{constraint, TestConstraintSystem};
    use crate::merkle::MerkleTree;
    use bellperson::gadgets::num;

    #[test]
    fn test_path() {
        let values = [
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
        ];

        let t = MerkleTree::<PoseidonDomain, PoseidonFunction, typenum::U2>::new(
            values.iter().map(|x| *x),
        )
        .unwrap();

        let p = t.gen_proof(0).unwrap(); // create a proof for the first value =k Fr::one()

        assert_eq!(*p.path(), vec![0, 0]);
        assert_eq!(
            p.validate::<PoseidonFunction>()
                .expect("failed to validate"),
            true
        );
    }

    // #[test]
    // fn test_poseidon_quad() {
    //     let leaves = [Fr::one(), Fr::zero(), Fr::zero(), Fr::one()];

    //     assert_eq!(Fr::zero().into_repr(), shared_hash_frs(&leaves[..]).0);
    // }

    #[test]
    fn test_poseidon_hasher() {
        let leaves = [
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::zero().into_repr()),
            PoseidonDomain(Fr::zero().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
        ];

        let t = MerkleTree::<PoseidonDomain, PoseidonFunction, typenum::U2>::new(
            leaves.iter().map(|x| *x),
        )
        .unwrap();

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
                0xf8a4092bef029be0,
                0x2deffc4feff5a3e0,
                0x60949ee3e7f39a7d,
                0x2df335798cd6ce2e
            ])
        );

        let expected = FrRepr([
            0x7f422271ae4eac64,
            0x767b7565e9472cdd,
            0x0354271e16d4c223,
            0x5acce8e6359804c0,
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

    #[test]
    fn test_hash_md() {
        // let arity = PoseidonMDArity::to_usize();
        let n = 71;
        let data = vec![PoseidonDomain(Fr::one().into_repr()); n];
        let hashed = PoseidonFunction::hash_md(&data);

        assert_eq!(
            hashed,
            PoseidonDomain(FrRepr([
                0x23ff11d2d2a54e3a,
                0x1393376e3c10d281,
                0xca9aed2681cc9081,
                0x04f01dc7b8b9b562
            ]))
        );
    }
    #[test]
    fn test_hash_md_circuit() {
        // let arity = PoseidonMDArity::to_usize();
        let n = 71;
        let data = vec![PoseidonDomain(Fr::one().into_repr()); n];

        let mut cs = TestConstraintSystem::<Bls12>::new();
        let circuit_data = (0..n)
            .map(|n| {
                num::AllocatedNum::alloc(cs.namespace(|| format!("input {}", n)), || Ok(Fr::one()))
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let hashed = PoseidonFunction::hash_md(&data);
        let hashed_fr = Fr::from_repr(hashed.0).unwrap();

        let circuit_hashed =
            PoseidonFunction::hash_md_circuit(&mut cs, circuit_data.as_slice()).unwrap();
        let hashed_alloc =
            &num::AllocatedNum::alloc(cs.namespace(|| "calculated"), || Ok(hashed_fr)).unwrap();
        constraint::equal(
            &mut cs.namespace(|| "enforce correct"),
            || "correct result",
            &hashed_alloc,
            &circuit_hashed,
        );

        assert!(cs.is_satisfied());
        let expected_constraints = 2_777;
        let actual_constraints = cs.num_constraints();

        assert_eq!(expected_constraints, actual_constraints);

        assert_eq!(hashed_fr, circuit_hashed.get_value().unwrap());
    }
}
