use std::cmp::Ordering;
use std::marker::PhantomData;

use bellperson::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::{Field, PrimeField};
use generic_array::typenum::{Unsigned, U2, U4, U8};
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use neptune::{circuit::poseidon_hash, Poseidon};
use pasta_curves::{Fp, Fq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    Domain, FieldArity, HashFunction, Hasher, PoseidonArity, PoseidonMDArity, POSEIDON_CONSTANTS,
    POSEIDON_CONSTANTS_2, POSEIDON_CONSTANTS_2_PALLAS, POSEIDON_CONSTANTS_2_VESTA,
    POSEIDON_MD_CONSTANTS, POSEIDON_MD_CONSTANTS_PALLAS, POSEIDON_MD_CONSTANTS_VESTA,
};

#[derive(Default, Copy, Clone, Debug)]
pub struct PoseidonDomain<F> {
    repr: [u8; 32],
    _f: PhantomData<F>,
}

// Can't blanket `impl<F> From<F> for PoseidonDomain<F> where F: PrimeField` because it can conflict
// with `impl<F> From<[u8; 32]> for PoseidonDomain<F>`, i.e. `[u8; 32]` is an external type which
// may already implement the external trait `PrimeField`, which causes a
// "conflicting implementation" compiler error.
impl From<Fr> for PoseidonDomain<Fr> {
    fn from(f: Fr) -> Self {
        PoseidonDomain {
            repr: f.to_repr(),
            _f: PhantomData,
        }
    }
}
impl From<Fp> for PoseidonDomain<Fp> {
    fn from(f: Fp) -> Self {
        PoseidonDomain {
            repr: f.to_repr(),
            _f: PhantomData,
        }
    }
}
impl From<Fq> for PoseidonDomain<Fq> {
    fn from(f: Fq) -> Self {
        PoseidonDomain {
            repr: f.to_repr(),
            _f: PhantomData,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<Fr> for PoseidonDomain<Fr> {
    fn into(self) -> Fr {
        Fr::from_repr_vartime(self.repr).expect("from_repr failure")
    }
}
#[allow(clippy::from_over_into)]
impl Into<Fp> for PoseidonDomain<Fp> {
    fn into(self) -> Fp {
        Fp::from_repr_vartime(self.repr).expect("from_repr failure")
    }
}
#[allow(clippy::from_over_into)]
impl Into<Fq> for PoseidonDomain<Fq> {
    fn into(self) -> Fq {
        Fq::from_repr_vartime(self.repr).expect("from_repr failure")
    }
}

// Currently, these panics serve as a stopgap to prevent accidental conversions of a Pasta field
// domains to/from a BLS12-381 scalar field domain.
impl From<Fr> for PoseidonDomain<Fp> {
    fn from(_f: Fr) -> Self {
        panic!("cannot convert BLS12-381 scalar into PoseidonDomain<Fp>")
    }
}
#[allow(clippy::from_over_into)]
impl Into<Fr> for PoseidonDomain<Fp> {
    fn into(self) -> Fr {
        panic!("cannot convert PoseidonDomain<Fp> into BLS12-381 scalar");
    }
}
impl From<Fr> for PoseidonDomain<Fq> {
    fn from(_f: Fr) -> Self {
        panic!("cannot convert BLS12-381 scalar into PoseidonDomain<Fq>")
    }
}
#[allow(clippy::from_over_into)]
impl Into<Fr> for PoseidonDomain<Fq> {
    fn into(self) -> Fr {
        panic!("cannot convert PoseidonDomain<Fq> into BLS12-381 scalar");
    }
}

impl<F> From<[u8; 32]> for PoseidonDomain<F> {
    fn from(bytes: [u8; 32]) -> Self {
        PoseidonDomain {
            repr: bytes,
            _f: PhantomData,
        }
    }
}

impl<F> AsRef<[u8]> for PoseidonDomain<F> {
    fn as_ref(&self) -> &[u8] {
        &self.repr
    }
}

impl<F> AsRef<Self> for PoseidonDomain<F> {
    fn as_ref(&self) -> &Self {
        self
    }
}

// Implement comparison traits by hand because we have not bound `F` to have those traits.
impl<F> PartialEq for PoseidonDomain<F> {
    fn eq(&self, other: &Self) -> bool {
        self.repr == other.repr
    }
}

impl<F> Eq for PoseidonDomain<F> {}

impl<F> PartialOrd for PoseidonDomain<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.repr.partial_cmp(&other.repr)
    }
}

impl<F> Ord for PoseidonDomain<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.repr.cmp(&other.repr)
    }
}

// Must add the trait bound `F: PrimeField` because `Element` requires that `F` implements `Clone`,
// `Send`, and `Sync`.
impl<F: PrimeField> Element for PoseidonDomain<F> {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), Self::byte_len(), "invalid number of bytes");
        let mut repr = [0u8; 32];
        repr.copy_from_slice(bytes);
        repr.into()
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.repr);
    }
}

impl<F> std::hash::Hash for PoseidonDomain<F> {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        std::hash::Hash::hash(&self.repr, hasher);
    }
}

// Implement `serde` traits by hand because we have not bound `F` to have those traits.
impl<F> Serialize for PoseidonDomain<F> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.repr.serialize(s)
    }
}
impl<'de, F> Deserialize<'de> for PoseidonDomain<F> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <[u8; 32]>::deserialize(d).map(Into::into)
    }
}

// Implementing `Domain` for specific fields (rather than blanket implementing for all `F`) restricts
// users to using the fields which are compatible with `rust-fil-proofs`.
impl Domain for PoseidonDomain<Fr> {
    type Field = Fr;
}
impl Domain for PoseidonDomain<Fp> {
    type Field = Fp;
}
impl Domain for PoseidonDomain<Fq> {
    type Field = Fq;
}

impl<F> PoseidonDomain<F> {
    pub fn repr(&self) -> [u8; 32] {
        self.repr
    }
}

fn shared_hash<F>(data: &[u8]) -> PoseidonDomain<F>
where
    F: PrimeField,
    PoseidonDomain<F>: Domain<Field = F>,
{
    let preimage: Vec<F> = data
        .chunks(32)
        .map(|chunk| {
            let mut repr = F::Repr::default();
            // FIXME: We shouldn't panic here, but doing otherwise will require an interface change.
            // We could truncate so `bytes_into_frs` cannot fail, then ensure `data` is always
            // `fr_safe`.
            repr.as_mut().copy_from_slice(chunk);
            F::from_repr_vartime(repr).expect("from_repr failure")
        })
        .collect();

    shared_hash_frs(&preimage).into()
}

// Must add trait bound `F: PrimeField` because `FieldArity<F, A>` requires `F: PrimeField`.
fn shared_hash_frs<F: PrimeField>(preimage: &[F]) -> F {
    match preimage.len() {
        2 => {
            let consts = &POSEIDON_CONSTANTS
                .get::<FieldArity<F, U2>>()
                .expect("arity-2 Poseidon constants not found for field");
            Poseidon::new_with_preimage(preimage, consts).hash()
        }
        4 => {
            let consts = &POSEIDON_CONSTANTS
                .get::<FieldArity<F, U4>>()
                .expect("arity-4 Poseidon constants not found for field");
            Poseidon::new_with_preimage(preimage, consts).hash()
        }
        8 => {
            let consts = &POSEIDON_CONSTANTS
                .get::<FieldArity<F, U8>>()
                .expect("arity-8 Poseidon constants not found for field");
            Poseidon::new_with_preimage(preimage, consts).hash()
        }
        n => panic!("unsupported arity for Poseidon hasher: {}", n),
    }
}

#[derive(Default, Clone, Debug)]
pub struct PoseidonFunction<F>(F);

impl<F> std::hash::Hasher for PoseidonFunction<F>
where
    F: PrimeField,
    PoseidonDomain<F>: Domain<Field = F>,
{
    fn write(&mut self, preimage: &[u8]) {
        self.0 = shared_hash(preimage).into();
    }

    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

impl<F> Hashable<PoseidonFunction<F>> for PoseidonDomain<F>
where
    F: PrimeField,
    PoseidonDomain<F>: Domain<Field = F>,
{
    fn hash(&self, hasher: &mut PoseidonFunction<F>) {
        <PoseidonFunction<F> as std::hash::Hasher>::write(hasher, self.as_ref())
    }
}

// We can't blanket `impl Hashable<PoseidonFunction<F>> for F where F: PrimeField` because we can't
// implement an external trait `Hashable` for an external type `F: PrimeField`.
impl Hashable<PoseidonFunction<Fr>> for Fr {
    fn hash(&self, hasher: &mut PoseidonFunction<Fr>) {
        <PoseidonFunction<Fr> as std::hash::Hasher>::write(hasher, &self.to_repr())
    }
}
impl Hashable<PoseidonFunction<Fp>> for Fp {
    fn hash(&self, hasher: &mut PoseidonFunction<Fp>) {
        <PoseidonFunction<Fp> as std::hash::Hasher>::write(hasher, &self.to_repr())
    }
}
impl Hashable<PoseidonFunction<Fq>> for Fq {
    fn hash(&self, hasher: &mut PoseidonFunction<Fq>) {
        <PoseidonFunction<Fq> as std::hash::Hasher>::write(hasher, &self.to_repr())
    }
}

impl<F> Algorithm<PoseidonDomain<F>> for PoseidonFunction<F>
where
    // Must add the trait bounds `F: PrimeField` and `PoseidonDomain<F>: Domain<Field = F>` because
    // they are required by `shared_hash_frs`.
    F: PrimeField,
    PoseidonDomain<F>: Domain<Field = F>,
{
    fn hash(&mut self) -> PoseidonDomain<F> {
        self.0.into()
    }

    fn reset(&mut self) {
        self.0 = F::zero();
    }

    fn leaf(&mut self, leaf: PoseidonDomain<F>) -> PoseidonDomain<F> {
        leaf
    }

    fn node(
        &mut self,
        left: PoseidonDomain<F>,
        right: PoseidonDomain<F>,
        _height: usize,
    ) -> PoseidonDomain<F> {
        shared_hash_frs::<F>(&[left.into(), right.into()]).into()
    }

    fn multi_node(&mut self, preimage: &[PoseidonDomain<F>], _height: usize) -> PoseidonDomain<F> {
        match preimage.len() {
            2 | 4 | 8 => {
                let preimage: Vec<F> = preimage.iter().map(|domain| (*domain).into()).collect();
                shared_hash_frs(&preimage).into()
            }
            arity => panic!("unsupported Halo Poseidon hasher arity: {}", arity),
        }
    }
}

// Specialized implementation of `HashFunction` over the BLS12-381 scalar field `Fr` because `Fr`
// is the only field which is compatible with `HashFunction`'s Groth16 circuit interfaces.
impl HashFunction<PoseidonDomain<Fr>> for PoseidonFunction<Fr> {
    fn hash(data: &[u8]) -> PoseidonDomain<Fr> {
        shared_hash(data)
    }

    fn hash2(a: &PoseidonDomain<Fr>, b: &PoseidonDomain<Fr>) -> PoseidonDomain<Fr> {
        let preimage = [(*a).into(), (*b).into()];
        Poseidon::new_with_preimage(&preimage, &*POSEIDON_CONSTANTS_2)
            .hash()
            .into()
    }

    fn hash_md(input: &[PoseidonDomain<Fr>]) -> PoseidonDomain<Fr> {
        assert!(
            input.len() > 1,
            "hash_md preimage must contain more than one element"
        );

        let arity = PoseidonMDArity::to_usize();
        let mut p = Poseidon::new(&*POSEIDON_MD_CONSTANTS);

        let fr_input: Vec<Fr> = input.iter().map(|domain| (*domain).into()).collect();

        fr_input[1..]
            .chunks(arity - 1)
            .fold(fr_input[0], |acc, frs| {
                p.reset();
                // Calling `.expect()` will panic iff we call `.input()` more that `arity` number
                // of times prior to resetting the hasher (i.e. if we exceed the arity of the
                // Poseidon constants) or if `preimge.len() == 1`; we prevent both scenarios.
                p.input(acc).expect("input failure");
                for fr in frs {
                    p.input(*fr).expect("input failure");
                }
                p.hash()
            })
            .into()
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        cs: CS,
        left: &AllocatedNum<Fr>,
        right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        Self::hash2_circuit(cs, left, right)
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity, CS: ConstraintSystem<Fr>>(
        cs: CS,
        leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let consts = &POSEIDON_CONSTANTS
            .get::<FieldArity<Fr, Arity>>()
            .unwrap_or_else(|| {
                panic!(
                    "arity-{} Poseidon constants not found for field",
                    Arity::to_usize(),
                )
            });
        poseidon_hash::<CS, Fr, Arity>(cs, leaves.to_vec(), consts)
    }

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        cs: &mut CS,
        elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
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
            hash = poseidon_hash::<_, Fr, PoseidonMDArity>(
                cs,
                preimage.clone(),
                &*POSEIDON_MD_CONSTANTS,
            )?
            .clone();
        }

        Ok(hash)
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!();
    }

    fn hash2_circuit<CS>(
        cs: CS,
        a: &AllocatedNum<Fr>,
        b: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError>
    where
        CS: ConstraintSystem<Fr>,
    {
        let preimage = vec![a.clone(), b.clone()];
        poseidon_hash::<CS, Fr, U2>(cs, preimage, &*POSEIDON_CONSTANTS_2)
    }
}

// Specialized implementation of `HashFunction` over the Pasta scalar fields `Fp` and `Fq` because
// those fields are incompatible with `HashFunction`'s Groth16 circuit interfaces.
impl HashFunction<PoseidonDomain<Fp>> for PoseidonFunction<Fp> {
    fn hash(data: &[u8]) -> PoseidonDomain<Fp> {
        shared_hash(data)
    }

    fn hash2(a: &PoseidonDomain<Fp>, b: &PoseidonDomain<Fp>) -> PoseidonDomain<Fp> {
        let preimage = [(*a).into(), (*b).into()];
        Poseidon::new_with_preimage(&preimage, &*POSEIDON_CONSTANTS_2_PALLAS)
            .hash()
            .into()
    }

    fn hash_md(input: &[PoseidonDomain<Fp>]) -> PoseidonDomain<Fp> {
        assert!(
            input.len() > 1,
            "hash_md preimage must contain more than one element"
        );

        let arity = PoseidonMDArity::to_usize();
        let mut p = Poseidon::new(&*POSEIDON_MD_CONSTANTS_PALLAS);

        let fr_input: Vec<Fp> = input.iter().map(|domain| (*domain).into()).collect();

        fr_input[1..]
            .chunks(arity - 1)
            .fold(fr_input[0], |acc, frs| {
                p.reset();
                // Calling `.expect()` will panic iff we call `.input()` more that `arity` number
                // of times prior to resetting the hasher (i.e. if we exceed the arity of the
                // Poseidon constants) or if `preimge.len() == 1`; we prevent both scenarios.
                p.input(acc).expect("input failure");
                for fr in frs {
                    p.input(*fr).expect("input failure");
                }
                p.hash()
            })
            .into()
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &AllocatedNum<Fr>,
        _right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity, CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fp> cannot be used within Groth16 circuits")
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fp> cannot be used within Groth16 circuits")
    }

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _a: &AllocatedNum<Fr>,
        _b: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fp> cannot be used within Groth16 circuits")
    }
}
impl HashFunction<PoseidonDomain<Fq>> for PoseidonFunction<Fq> {
    fn hash(data: &[u8]) -> PoseidonDomain<Fq> {
        shared_hash(data)
    }

    fn hash2(a: &PoseidonDomain<Fq>, b: &PoseidonDomain<Fq>) -> PoseidonDomain<Fq> {
        let preimage = [(*a).into(), (*b).into()];
        Poseidon::new_with_preimage(&preimage, &*POSEIDON_CONSTANTS_2_VESTA)
            .hash()
            .into()
    }

    fn hash_md(input: &[PoseidonDomain<Fq>]) -> PoseidonDomain<Fq> {
        assert!(
            input.len() > 1,
            "hash_md preimage must contain more than one element"
        );

        let arity = PoseidonMDArity::to_usize();
        let mut p = Poseidon::new(&*POSEIDON_MD_CONSTANTS_VESTA);

        let fr_input: Vec<Fq> = input.iter().map(|domain| (*domain).into()).collect();

        fr_input[1..]
            .chunks(arity - 1)
            .fold(fr_input[0], |acc, frs| {
                p.reset();
                // Calling `.expect()` will panic iff we call `.input()` more that `arity` number
                // of times prior to resetting the hasher (i.e. if we exceed the arity of the
                // Poseidon constants) or if `preimge.len() == 1`; we prevent both scenarios.
                p.input(acc).expect("input failure");
                for fr in frs {
                    p.input(*fr).expect("input failure");
                }
                p.hash()
            })
            .into()
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &AllocatedNum<Fr>,
        _right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity, CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fq> cannot be used within Groth16 circuits")
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fq> cannot be used within Groth16 circuits")
    }

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _a: &AllocatedNum<Fr>,
        _b: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("PoseidonFunction<Fq> cannot be used within Groth16 circuits")
    }
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct PoseidonHasher<F> {
    _f: PhantomData<F>,
}

// Implementing `Hasher` for specific fields (rather than blanket implementing for all `F`) restricts
// users to using the fields which are compatible with `rust-fil-proofs`.
impl Hasher for PoseidonHasher<Fr> {
    type Domain = PoseidonDomain<Fr>;
    type Function = PoseidonFunction<Fr>;

    fn name() -> String {
        "poseidon_hasher".into()
    }
}
impl Hasher for PoseidonHasher<Fp> {
    type Domain = PoseidonDomain<Fp>;
    type Function = PoseidonFunction<Fp>;

    fn name() -> String {
        "poseidon_hasher_pallas".into()
    }
}
impl Hasher for PoseidonHasher<Fq> {
    type Domain = PoseidonDomain<Fq>;
    type Function = PoseidonFunction<Fq>;

    fn name() -> String {
        "poseidon_hasher_vesta".into()
    }
}
