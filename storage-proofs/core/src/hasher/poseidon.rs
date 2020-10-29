use std::hash::Hasher as StdHasher;

use crate::crypto::sloth;
use crate::error::{Error, Result};
use crate::hasher::types::{
    PoseidonArity, PoseidonMDArity, POSEIDON_CONSTANTS_16, POSEIDON_CONSTANTS_2,
    POSEIDON_CONSTANTS_4, POSEIDON_CONSTANTS_8, POSEIDON_MD_CONSTANTS,
};
use crate::hasher::{Domain, HashFunction, Hasher};
use anyhow::ensure;
use bellperson::bls::{Bls12, Fr, FrRepr};
use bellperson::gadgets::{boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use generic_array::typenum;
use generic_array::typenum::marker_traits::Unsigned;
use merkletree::hash::{Algorithm as LightAlgorithm, Hashable};
use merkletree::merkle::Element;
use neptune::circuit::poseidon_hash;
use neptune::poseidon::Poseidon;
use serde::{Deserialize, Serialize};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHasher {}

impl Hasher for PoseidonHasher {
    type Domain = PoseidonDomain;
    type Function = PoseidonFunction;

    fn name() -> String {
        "poseidon_hasher".into()
    }

    #[inline]
    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain> {
        // Unrapping here is safe; `Fr` elements and hash domain elements are the same byte length.
        let key = Fr::from_repr(key.0)?;
        let ciphertext = Fr::from_repr(ciphertext.0)?;
        Ok(sloth::encode(&key, &ciphertext).into())
    }

    #[inline]
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain> {
        // Unrapping here is safe; `Fr` elements and hash domain elements are the same byte length.
        let key = Fr::from_repr(key.0)?;
        let ciphertext = Fr::from_repr(ciphertext.0)?;

        Ok(sloth::decode(&key, &ciphertext).into())
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
        self.into_repr()
            .write_le(&mut bytes)
            .expect("write_le failure");
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
    fn into_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PoseidonDomain::byte_len());
        self.0.write_le(&mut out).expect("write_le failure");

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
        self.0 = Fr::from_repr(shared_hash(msg).0).expect("from_repr failure");
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
            <Bls12 as ff::ScalarEngine>::Fr::from_repr(PoseidonDomain::from_slice(chunk).0)
                .expect("from_repr failure")
        })
        .collect::<Vec<_>>();

    shared_hash_frs(&preimage).into()
}

fn shared_hash_frs(
    preimage: &[<Bls12 as ff::ScalarEngine>::Fr],
) -> <Bls12 as ff::ScalarEngine>::Fr {
    match preimage.len() {
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
            .map(|x| <Bls12 as ScalarEngine>::Fr::from_repr(x.0).expect("from_repr failure"))
            .collect::<Vec<_>>();

        fr_input[1..]
            .chunks(arity - 1)
            .fold(fr_input[0], |acc, elts| {
                p.reset();
                p.input(acc).expect("input failure"); // These unwraps will panic iff arity is incorrect, but it was checked above.
                elts.iter().for_each(|elt| {
                    let _ = p.input(*elt).expect("input failure");
                });
                p.hash()
            })
            .into()
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Bls12>>(
        cs: CS,
        left: &num::AllocatedNum<Bls12>,
        right: &num::AllocatedNum<Bls12>,
        _height: usize,
    ) -> ::std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let preimage = vec![left.clone(), right.clone()];

        poseidon_hash::<CS, Bls12, typenum::U2>(cs, preimage, typenum::U2::PARAMETERS())
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity, CS: ConstraintSystem<Bls12>>(
        cs: CS,
        leaves: &[num::AllocatedNum<Bls12>],
        _height: usize,
    ) -> ::std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let params = Arity::PARAMETERS();
        poseidon_hash::<CS, Bls12, Arity>(cs, leaves.to_vec(), params)
    }

    fn hash_md_circuit<CS: ConstraintSystem<Bls12>>(
        cs: &mut CS,
        elements: &[num::AllocatedNum<Bls12>],
    ) -> ::std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let params = PoseidonMDArity::PARAMETERS();
        let arity = PoseidonMDArity::to_usize();

        let mut hash = elements[0].clone();
        let mut preimage = vec![hash.clone(); arity]; // Allocate. This will be overwritten.
        for (hash_num, elts) in elements[1..].chunks(arity - 1).enumerate() {
            preimage[0] = hash;
            for (i, elt) in elts.iter().enumerate() {
                preimage[i + 1] = elt.clone();
            }
            // any terminal padding
            #[allow(clippy::needless_range_loop)]
            for i in (elts.len() + 1)..arity {
                preimage[i] =
                    num::AllocatedNum::alloc(cs.namespace(|| format!("padding {}", i)), || {
                        Ok(Fr::zero())
                    })
                    .expect("alloc failure");
            }
            let cs = cs.namespace(|| format!("hash md {}", hash_num));
            hash =
                poseidon_hash::<_, Bls12, PoseidonMDArity>(cs, preimage.clone(), params)?.clone();
        }

        Ok(hash)
    }

    fn hash_circuit<CS: ConstraintSystem<Bls12>>(
        _cs: CS,
        _bits: &[boolean::Boolean],
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        unimplemented!();
    }

    fn hash2_circuit<CS>(
        cs: CS,
        a: &num::AllocatedNum<Bls12>,
        b: &num::AllocatedNum<Bls12>,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let preimage = vec![a.clone(), b.clone()];
        poseidon_hash::<CS, Bls12, typenum::U2>(cs, preimage, typenum::U2::PARAMETERS())
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
            <Bls12 as ff::ScalarEngine>::Fr::from_repr(left.0).expect("from_repr failure"),
            <Bls12 as ff::ScalarEngine>::Fr::from_repr(right.0).expect("from_repr failure"),
        ])
        .into()
    }

    fn multi_node(&mut self, parts: &[PoseidonDomain], _height: usize) -> PoseidonDomain {
        match parts.len() {
            1 | 2 | 4 | 8 | 16 => shared_hash_frs(
                &parts
                    .iter()
                    .map(|x| {
                        <Bls12 as ff::ScalarEngine>::Fr::from_repr(x.0).expect("from_repr failure")
                    })
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
        Fr::from_repr(val.0).expect("from_repr failure")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    use crate::gadgets::constraint;
    use crate::merkle::MerkleTree;
    use bellperson::gadgets::num;
    use bellperson::util_cs::test_cs::TestConstraintSystem;

    #[test]
    fn test_path() {
        let values = [
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
            PoseidonDomain(Fr::one().into_repr()),
        ];

        let t = MerkleTree::<PoseidonHasher, typenum::U2>::new(values.iter().copied())
            .expect("merkle tree new failure");

        let p = t.gen_proof(0).expect("gen_proof failure"); // create a proof for the first value =k Fr::one()

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

        let t = MerkleTree::<PoseidonHasher, typenum::U2>::new(leaves.iter().copied())
            .expect("merkle tree new failure");

        assert_eq!(t.leafs(), 4);

        let mut a = PoseidonFunction::default();

        assert_eq!(t.read_at(0).expect("read_at failure"), leaves[0]);
        assert_eq!(t.read_at(1).expect("read_at failure"), leaves[1]);
        assert_eq!(t.read_at(2).expect("read_at failure"), leaves[2]);
        assert_eq!(t.read_at(3).expect("read_at failure"), leaves[3]);

        let i1 = a.node(leaves[0], leaves[1], 0);
        a.reset();
        let i2 = a.node(leaves[2], leaves[3], 0);
        a.reset();

        assert_eq!(t.read_at(4).expect("read_at failure"), i1);
        assert_eq!(t.read_at(5).expect("read_at failure"), i2);

        let root = a.node(i1, i2, 1);
        a.reset();

        assert_eq!(
            t.read_at(4).expect("read_at failure").0,
            FrRepr([
                0xb339ff6079800b5e,
                0xec5907b3dc3094af,
                0x93c003cc74a24f26,
                0x042f94ffbe786bc3,
            ])
        );

        let expected = FrRepr([
            0xefbb8be3e291e671,
            0x77cc72b8cb2b5ad2,
            0x30eb6385ae6b74ae,
            0x1effebb7b26ad9eb,
        ]);
        let actual = t.read_at(6).expect("read_at failure").0;

        assert_eq!(actual, expected);
        assert_eq!(t.read_at(6).expect("read_at failure"), root);
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
                0x351c54133b332c90,
                0xc26f6d625f4e8195,
                0x5fd9623643ed9622,
                0x59f42220e09ff6f7,
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
                    .expect("alloc failure")
            })
            .collect::<Vec<_>>();

        let hashed = PoseidonFunction::hash_md(&data);
        let hashed_fr = Fr::from_repr(hashed.0).expect("from_repr failure");

        let circuit_hashed = PoseidonFunction::hash_md_circuit(&mut cs, circuit_data.as_slice())
            .expect("hash_md_circuit failure");
        let hashed_alloc =
            &num::AllocatedNum::alloc(cs.namespace(|| "calculated"), || Ok(hashed_fr))
                .expect("alloc failure");
        constraint::equal(
            &mut cs.namespace(|| "enforce correct"),
            || "correct result",
            &hashed_alloc,
            &circuit_hashed,
        );

        assert!(cs.is_satisfied());
        let expected_constraints = 2_771;
        let actual_constraints = cs.num_constraints();

        assert_eq!(expected_constraints, actual_constraints);

        assert_eq!(
            hashed_fr,
            circuit_hashed.get_value().expect("get_value failure")
        );
    }
}
