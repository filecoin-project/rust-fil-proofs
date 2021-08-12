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

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PoseidonDomain<F: PrimeField>(pub F::Repr);

impl AsRef<[u8]> for PoseidonDomain<Fr> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PoseidonDomain<Fp> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PoseidonDomain<Fq> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Fr> for PoseidonDomain<Fr> {
    fn from(val: Fr) -> Self {
        PoseidonDomain(val.to_repr())
    }
}

impl From<PoseidonDomain<Fr>> for Fr {
    fn from(val: PoseidonDomain<Fr>) -> Self {
        Fr::from_repr(val.0).expect("from_repr failure")
    }
}

impl From<Fp> for PoseidonDomain<Fp> {
    fn from(val: Fp) -> Self {
        PoseidonDomain(val.to_repr())
    }
}

impl From<PoseidonDomain<Fp>> for Fp {
    fn from(val: PoseidonDomain<Fp>) -> Self {
        Fp::from_repr(val.0).expect("from_repr failure")
    }
}

impl From<Fq> for PoseidonDomain<Fq> {
    fn from(val: Fq) -> Self {
        PoseidonDomain(val.to_repr())
    }
}

impl From<PoseidonDomain<Fq>> for Fq {
    fn from(val: PoseidonDomain<Fq>) -> Self {
        Fq::from_repr(val.0).expect("from_repr failure")
    }
}

impl From<[u8; 32]> for PoseidonDomain<Fr> {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        PoseidonDomain(val)
    }
}

impl From<[u8; 32]> for PoseidonDomain<Fp> {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        PoseidonDomain(val)
    }
}

impl From<[u8; 32]> for PoseidonDomain<Fq> {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        PoseidonDomain(val)
    }
}

impl StdHash for PoseidonDomain<Fr> {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        StdHash::hash(&self.0, state);
    }
}

impl StdHash for PoseidonDomain<Fp> {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        StdHash::hash(&self.0, state);
    }
}

impl StdHash for PoseidonDomain<Fq> {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        StdHash::hash(&self.0, state);
    }
}

impl Element for PoseidonDomain<Fr> {
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

impl Element for PoseidonDomain<Fp> {
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

impl Element for PoseidonDomain<Fq> {
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

impl Domain<Fr> for PoseidonDomain<Fr> {}
impl Domain<Fp> for PoseidonDomain<Fp> {}
impl Domain<Fq> for PoseidonDomain<Fq> {}

fn hash_bytes_bls12(preimage: &[u8]) -> PoseidonDomain<Fr> {
    // FIXME: We shouldn't unwrap here, but doing otherwise will require an interface change.
    // We could truncate so `bytes_into_frs` cannot fail, then ensure `data` is always `fr_safe`.
    let preimage = preimage
        .chunks(32)
        .map(|ref chunk| {
            let mut repr = <Fr as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(chunk);
            <Fr as PrimeField>::from_repr(repr).expect("from_repr failure")
        })
        .collect::<Vec<_>>();

    hash_field_elems_bls12(&preimage)
}

fn hash_bytes_pallas(preimage: &[u8]) -> PoseidonDomain<Fp> {
    // FIXME: We shouldn't unwrap here, but doing otherwise will require an interface change.
    // We could truncate so `bytes_into_frs` cannot fail, then ensure `data` is always `fr_safe`.
    let preimage = preimage
        .chunks(32)
        .map(|ref chunk| {
            let mut repr = <Fp as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(chunk);
            <Fp as PrimeField>::from_repr(repr).expect("from_repr failure")
        })
        .collect::<Vec<_>>();

    hash_field_elems_pallas(&preimage)
}

fn hash_bytes_vesta(preimage: &[u8]) -> PoseidonDomain<Fq> {
    // FIXME: We shouldn't unwrap here, but doing otherwise will require an interface change.
    // We could truncate so `bytes_into_frs` cannot fail, then ensure `data` is always `fr_safe`.
    let preimage = preimage
        .chunks(32)
        .map(|ref chunk| {
            let mut repr = <Fq as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(chunk);
            <Fq as PrimeField>::from_repr(repr).expect("from_repr failure")
        })
        .collect::<Vec<_>>();

    hash_field_elems_vesta(&preimage)
}

fn hash_field_elems_bls12(preimage: &[Fr]) -> PoseidonDomain<Fr> {
    let digest = match preimage.len() {
        2 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_2).hash(),
        4 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_4).hash(),
        8 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_8).hash(),
        16 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_16).hash(),
        _ => panic_any(format!(
            "Unsupported arity for Poseidon hasher: {}",
            preimage.len()
        )),
    };
    digest.into()
}

fn hash_field_elems_pallas(preimage: &[Fp]) -> PoseidonDomain<Fp> {
    let digest = match preimage.len() {
        2 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_2_PALLAS).hash(),
        4 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_4_PALLAS).hash(),
        8 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_8_PALLAS).hash(),
        16 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_16_PALLAS).hash(),
        _ => panic_any(format!(
            "Unsupported arity for Poseidon hasher: {}",
            preimage.len()
        )),
    };
    digest.into()
}

fn hash_field_elems_vesta(preimage: &[Fq]) -> PoseidonDomain<Fq> {
    let digest = match preimage.len() {
        2 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_2_VESTA).hash(),
        4 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_4_VESTA).hash(),
        8 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_8_VESTA).hash(),
        16 => Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_16_VESTA).hash(),
        _ => panic_any(format!(
            "Unsupported arity for Poseidon hasher: {}",
            preimage.len()
        )),
    };
    digest.into()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PoseidonFunction<F: PrimeField>(F);

impl<F: PrimeField> Default for PoseidonFunction<F> {
    fn default() -> PoseidonFunction<F> {
        PoseidonFunction(F::zero())
    }
}

impl StdHasher for PoseidonFunction<Fr> {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0 = Fr::from_repr(hash_bytes_bls12(msg).0).expect("from_repr failure");
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl StdHasher for PoseidonFunction<Fp> {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0 = Fp::from_repr(hash_bytes_pallas(msg).0).expect("from_repr failure");
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl StdHasher for PoseidonFunction<Fq> {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0 = Fq::from_repr(hash_bytes_vesta(msg).0).expect("from_repr failure");
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl Hashable<PoseidonFunction<Fr>> for Fr {
    fn hash(&self, state: &mut PoseidonFunction<Fr>) {
        state.write(&self.to_repr());
    }
}

impl Hashable<PoseidonFunction<Fp>> for Fp {
    fn hash(&self, state: &mut PoseidonFunction<Fp>) {
        state.write(&self.to_repr());
    }
}

impl Hashable<PoseidonFunction<Fq>> for Fq {
    fn hash(&self, state: &mut PoseidonFunction<Fq>) {
        state.write(&self.to_repr());
    }
}

impl Hashable<PoseidonFunction<Fr>> for PoseidonDomain<Fr> {
    fn hash(&self, state: &mut PoseidonFunction<Fr>) {
        state.write(&self.0);
    }
}

impl Hashable<PoseidonFunction<Fp>> for PoseidonDomain<Fp> {
    fn hash(&self, state: &mut PoseidonFunction<Fp>) {
        state.write(&self.0);
    }
}

impl Hashable<PoseidonFunction<Fq>> for PoseidonDomain<Fq> {
    fn hash(&self, state: &mut PoseidonFunction<Fq>) {
        state.write(&self.0);
    }
}

impl Algorithm<PoseidonDomain<Fr>> for PoseidonFunction<Fr> {
    #[inline]
    fn hash(&mut self) -> PoseidonDomain<Fr> {
        self.0.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Fr::zero();
    }

    fn leaf(&mut self, leaf: PoseidonDomain<Fr>) -> PoseidonDomain<Fr> {
        leaf
    }

    fn node(
        &mut self,
        left: PoseidonDomain<Fr>,
        right: PoseidonDomain<Fr>,
        _height: usize,
    ) -> PoseidonDomain<Fr> {
        hash_field_elems_bls12(&[
            Fr::from_repr(left.0).expect("from_repr failure"),
            Fr::from_repr(right.0).expect("from_repr failure"),
        ])
        .into()
    }

    fn multi_node(&mut self, parts: &[PoseidonDomain<Fr>], _height: usize) -> PoseidonDomain<Fr> {
        match parts.len() {
            1 | 2 | 4 | 8 | 16 => hash_field_elems_bls12(
                &parts
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        if let Some(fr) = Fr::from_repr(x.0) {
                            fr
                        } else {
                            panic_any(format!("from_repr failure at {}", i));
                        }
                    })
                    .collect::<Vec<_>>(),
            )
            .into(),
            arity => panic_any(format!("unsupported arity {}", arity)),
        }
    }
}

impl Algorithm<PoseidonDomain<Fp>> for PoseidonFunction<Fp> {
    #[inline]
    fn hash(&mut self) -> PoseidonDomain<Fp> {
        self.0.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Fp::zero();
    }

    fn leaf(&mut self, leaf: PoseidonDomain<Fp>) -> PoseidonDomain<Fp> {
        leaf
    }

    fn node(
        &mut self,
        left: PoseidonDomain<Fp>,
        right: PoseidonDomain<Fp>,
        _height: usize,
    ) -> PoseidonDomain<Fp> {
        hash_field_elems_pallas(&[
            Fp::from_repr(left.0).expect("from_repr failure"),
            Fp::from_repr(right.0).expect("from_repr failure"),
        ])
        .into()
    }

    fn multi_node(&mut self, parts: &[PoseidonDomain<Fp>], _height: usize) -> PoseidonDomain<Fp> {
        match parts.len() {
            1 | 2 | 4 | 8 | 16 => hash_field_elems_pallas(
                &parts
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        if let Some(fr) = Fp::from_repr(x.0) {
                            fr
                        } else {
                            panic_any(format!("from_repr failure at {}", i));
                        }
                    })
                    .collect::<Vec<_>>(),
            )
            .into(),
            arity => panic_any(format!("unsupported arity {}", arity)),
        }
    }
}

impl Algorithm<PoseidonDomain<Fq>> for PoseidonFunction<Fq> {
    #[inline]
    fn hash(&mut self) -> PoseidonDomain<Fq> {
        self.0.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Fq::zero();
    }

    fn leaf(&mut self, leaf: PoseidonDomain<Fq>) -> PoseidonDomain<Fq> {
        leaf
    }

    fn node(
        &mut self,
        left: PoseidonDomain<Fq>,
        right: PoseidonDomain<Fq>,
        _height: usize,
    ) -> PoseidonDomain<Fq> {
        hash_field_elems_vesta(&[
            Fq::from_repr(left.0).expect("from_repr failure"),
            Fq::from_repr(right.0).expect("from_repr failure"),
        ])
        .into()
    }

    fn multi_node(&mut self, parts: &[PoseidonDomain<Fq>], _height: usize) -> PoseidonDomain<Fq> {
        match parts.len() {
            1 | 2 | 4 | 8 | 16 => hash_field_elems_vesta(
                &parts
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        if let Some(fr) = Fq::from_repr(x.0) {
                            fr
                        } else {
                            panic_any(format!("from_repr failure at {}", i));
                        }
                    })
                    .collect::<Vec<_>>(),
            )
            .into(),
            arity => panic_any(format!("unsupported arity {}", arity)),
        }
    }
}

impl HashFunction<PoseidonDomain<Fr>, Fr> for PoseidonFunction<Fr> {
    fn hash(data: &[u8]) -> PoseidonDomain<Fr> {
        hash_bytes_bls12(data)
    }

    fn hash2(a: &PoseidonDomain<Fr>, b: &PoseidonDomain<Fr>) -> PoseidonDomain<Fr> {
        let mut p =
            Poseidon::new_with_preimage(&[(*a).into(), (*b).into()][..], &*POSEIDON_CONSTANTS_2);
        let fr: Fr = p.hash();
        fr.into()
    }

    fn hash_md(input: &[PoseidonDomain<Fr>]) -> PoseidonDomain<Fr> {
        assert!(input.len() > 1, "hash_md needs more than one element.");
        let arity = PoseidonMDArity::to_usize();

        let mut p = Poseidon::new(&*POSEIDON_MD_CONSTANTS);

        let fr_input = input
            .iter()
            .map(|x| Fr::from_repr(x.0).expect("from_repr failure"))
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
}

impl HashFunction<PoseidonDomain<Fp>, Fp> for PoseidonFunction<Fp> {
    fn hash(data: &[u8]) -> PoseidonDomain<Fp> {
        hash_bytes_pallas(data)
    }

    fn hash2(a: &PoseidonDomain<Fp>, b: &PoseidonDomain<Fp>) -> PoseidonDomain<Fp> {
        let mut p =
            Poseidon::new_with_preimage(&[(*a).into(), (*b).into()][..],
            &*POSEIDON_CONSTANTS_2_PALLAS);
        let fr: Fp = p.hash();
        fr.into()
    }

    fn hash_md(input: &[PoseidonDomain<Fp>]) -> PoseidonDomain<Fp> {
        assert!(input.len() > 1, "hash_md needs more than one element.");
        let arity = PoseidonMDArity::to_usize();

        let mut p = Poseidon::new(&*POSEIDON_MD_CONSTANTS_PALLAS);

        let fr_input = input
            .iter()
            .map(|x| Fp::from_repr(x.0).expect("from_repr failure"))
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
}

impl HashFunction<PoseidonDomain<Fq>, Fq> for PoseidonFunction<Fq> {
    fn hash(data: &[u8]) -> PoseidonDomain<Fq> {
        hash_bytes_vesta(data)
    }

    fn hash2(a: &PoseidonDomain<Fq>, b: &PoseidonDomain<Fq>) -> PoseidonDomain<Fq> {
        let mut p =
            Poseidon::new_with_preimage(&[(*a).into(), (*b).into()][..],
            &*POSEIDON_CONSTANTS_2_VESTA);
        let fr: Fq = p.hash();
        fr.into()
    }

    fn hash_md(input: &[PoseidonDomain<Fq>]) -> PoseidonDomain<Fq> {
        assert!(input.len() > 1, "hash_md needs more than one element.");
        let arity = PoseidonMDArity::to_usize();

        let mut p = Poseidon::new(&*POSEIDON_MD_CONSTANTS_VESTA);

        let fr_input = input
            .iter()
            .map(|x| Fq::from_repr(x.0).expect("from_repr failure"))
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
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHasher;

impl Hasher<Fr> for PoseidonHasher {
    type Domain = PoseidonDomain<Fr>;
    type Function = PoseidonFunction<Fr>;

    fn name() -> String {
        "poseidon_hasher_bls12".into()
    }
}

impl Hasher<Fp> for PoseidonHasher {
    type Domain = PoseidonDomain<Fp>;
    type Function = PoseidonFunction<Fp>;

    fn name() -> String {
        "poseidon_hasher_pallas".into()
    }
}

impl Hasher<Fq> for PoseidonHasher {
    type Domain = PoseidonDomain<Fq>;
    type Function = PoseidonFunction<Fq>;

    fn name() -> String {
        "poseidon_hasher_vesta".into()
    }
}

impl GrothHasher for PoseidonHasher {
    fn hash_leaf_circuit<CS: ConstraintSystem<Bls12>>(
        cs: CS,
        left: &AllocatedNum<Bls12>,
        right: &AllocatedNum<Bls12>,
        _height: usize,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError> {
        let preimage = vec![left.clone(), right.clone()];

        poseidon_circuit::<CS, Bls12, U2>(cs, preimage, U2::PARAMETERS())
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity, CS: ConstraintSystem<Bls12>>(
        cs: CS,
        leaves: &[AllocatedNum<Bls12>],
        _height: usize,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError> {
        let params = Arity::PARAMETERS();
        poseidon_circuit::<CS, Bls12, Arity>(cs, leaves.to_vec(), params)
    }

    fn hash_md_circuit<CS: ConstraintSystem<Bls12>>(
        cs: &mut CS,
        elements: &[AllocatedNum<Bls12>],
    ) -> Result<AllocatedNum<Bls12>, SynthesisError> {
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
                    AllocatedNum::alloc(cs.namespace(|| format!("padding {}", i)), || {
                        Ok(Fr::zero())
                    })
                    .expect("alloc failure");
            }
            let cs = cs.namespace(|| format!("hash md {}", hash_num));
            hash =
                poseidon_circuit::<_, Bls12, PoseidonMDArity>(cs, preimage.clone(), params)?.clone();
        }

        Ok(hash)
    }

    fn hash_circuit<CS: ConstraintSystem<Bls12>>(
        _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Bls12>, SynthesisError> {
        unimplemented!();
    }

    fn hash2_circuit<CS>(
        cs: CS,
        a: &AllocatedNum<Bls12>,
        b: &AllocatedNum<Bls12>,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let preimage = vec![a.clone(), b.clone()];
        poseidon_circuit::<CS, Bls12, U2>(cs, preimage, U2::PARAMETERS())
    }
}
