use std::cmp::Ordering;
use std::marker::PhantomData;

use bellperson::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::{Field, PrimeField};
use generic_array::typenum::{Unsigned, U2, U4, U8};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter},
    pasta::{Fp, Fq},
    plonk::{self, Advice, Column, Fixed},
};
use lazy_static::lazy_static;
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use neptune::{
    circuit::poseidon_hash,
    halo2_circuit::{PoseidonChipStd, PoseidonConfigStd},
    Poseidon,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use typemap::ShareMap;

use crate::{
    get_poseidon_constants, Domain, FieldArity, Groth16Hasher, Halo2Hasher, HashFunction,
    HashInstructions, Hasher, PoseidonArity, PoseidonMDArity, POSEIDON_CONSTANTS_2,
    POSEIDON_MD_CONSTANTS as POSEIDON_MD_CONSTANTS_BLS, POSEIDON_MD_CONSTANTS_PALLAS,
    POSEIDON_MD_CONSTANTS_VESTA,
};

lazy_static! {
    pub static ref POSEIDON_MD_CONSTANTS: ShareMap = {
        let mut tm = ShareMap::custom();
        tm.insert::<FieldArity<Fr, PoseidonMDArity>>(&*POSEIDON_MD_CONSTANTS_BLS);
        tm.insert::<FieldArity<Fp, PoseidonMDArity>>(&*POSEIDON_MD_CONSTANTS_PALLAS);
        tm.insert::<FieldArity<Fq, PoseidonMDArity>>(&*POSEIDON_MD_CONSTANTS_VESTA);
        tm
    };
}

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

impl<F> From<[u8; 32]> for PoseidonDomain<F> {
    fn from(bytes: [u8; 32]) -> Self {
        PoseidonDomain {
            repr: bytes,
            _f: PhantomData,
        }
    }
}

#[allow(clippy::from_over_into)]
impl<F> Into<[u8; 32]> for PoseidonDomain<F> {
    fn into(self) -> [u8; 32] {
        self.repr
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

// The trait bound `F: PrimeField` is necessary because `Element` requires that `F` implements
// `Clone + Send + Sync`.
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

fn shared_hash<F: PrimeField>(data: &[u8]) -> F {
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

    shared_hash_frs(&preimage)
}

// Must add trait bound `F: PrimeField` because `FieldArity<F, A>` requires `F: PrimeField`.
fn shared_hash_frs<F: PrimeField>(preimage: &[F]) -> F {
    match preimage.len() {
        2 => {
            let consts = get_poseidon_constants::<F, U2>();
            Poseidon::new_with_preimage(preimage, consts).hash()
        }
        4 => {
            let consts = get_poseidon_constants::<F, U4>();
            Poseidon::new_with_preimage(preimage, consts).hash()
        }
        8 => {
            let consts = get_poseidon_constants::<F, U8>();
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
        self.0 = shared_hash::<F>(preimage);
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

// We can't blanket `impl<F: PrimeField> Hashable<PoseidonFunction<F>> for F` because both
// `Hashable` and `PrimeField` are external traits (the compiler forbids implementing external
// traits on external types).
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
        let preimage: Vec<F> = preimage.iter().copied().map(Into::into).collect();
        shared_hash_frs(&preimage).into()
    }
}

impl<F> HashFunction<PoseidonDomain<F>> for PoseidonFunction<F>
where
    F: PrimeField,
    PoseidonDomain<F>: Domain<Field = F>,
{
    fn hash(data: &[u8]) -> PoseidonDomain<F> {
        shared_hash::<F>(data).into()
    }

    fn hash2(a: &PoseidonDomain<F>, b: &PoseidonDomain<F>) -> PoseidonDomain<F> {
        let preimage = [(*a).into(), (*b).into()];
        let consts = get_poseidon_constants::<F, U2>();
        Poseidon::new_with_preimage(&preimage, consts).hash().into()
    }

    fn hash_md(input: &[PoseidonDomain<F>]) -> PoseidonDomain<F> {
        assert!(
            input.len() > 1,
            "hash_md preimage must contain more than one element"
        );

        let arity = PoseidonMDArity::to_usize();
        let consts = POSEIDON_MD_CONSTANTS
            .get::<FieldArity<F, PoseidonMDArity>>()
            .unwrap_or_else(|| {
                panic!(
                    "arity-{} poseidon constants not found for field",
                    PoseidonMDArity::to_usize()
                )
            });
        let mut p = Poseidon::new(*consts);

        let fr_input: Vec<F> = input.iter().map(|domain| (*domain).into()).collect();

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
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct PoseidonHasher<F> {
    _f: PhantomData<F>,
}

// TODO (jake): should hashers over different fields have different names?
const HASHER_NAME: &str = "poseidon_hasher";

impl Hasher for PoseidonHasher<Fr> {
    type Field = Fr;
    type Domain = PoseidonDomain<Self::Field>;
    type Function = PoseidonFunction<Self::Field>;

    fn name() -> String {
        HASHER_NAME.into()
    }
}
impl Hasher for PoseidonHasher<Fp> {
    type Field = Fp;
    type Domain = PoseidonDomain<Self::Field>;
    type Function = PoseidonFunction<Self::Field>;

    fn name() -> String {
        HASHER_NAME.into()
    }
}
impl Hasher for PoseidonHasher<Fq> {
    type Field = Fq;
    type Domain = PoseidonDomain<Self::Field>;
    type Function = PoseidonFunction<Self::Field>;

    fn name() -> String {
        HASHER_NAME.into()
    }
}

// Only implement `Groth16Hasher` for `PoseidonHasher<Fr>` because `Fr` is the only field which is
// compatible with Groth16.
impl Groth16Hasher for PoseidonHasher<Fr> {
    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        cs: CS,
        left: &AllocatedNum<Fr>,
        right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        Self::hash2_circuit(cs, left, right)
    }

    fn hash_multi_leaf_circuit<A: PoseidonArity<Fr>, CS: ConstraintSystem<Fr>>(
        cs: CS,
        leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let consts = get_poseidon_constants::<Fr, A>();
        poseidon_hash(cs, leaves.to_vec(), consts)
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
            hash = poseidon_hash(cs, preimage.clone(), &*POSEIDON_MD_CONSTANTS_BLS)?.clone();
        }

        Ok(hash)
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!();
    }

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        cs: CS,
        a: &AllocatedNum<Fr>,
        b: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let preimage = vec![a.clone(), b.clone()];
        poseidon_hash(cs, preimage, &*POSEIDON_CONSTANTS_2)
    }
}

impl<F, A> HashInstructions<F> for PoseidonChipStd<F, A>
where
    F: FieldExt,
    A: PoseidonArity<F>,
{
    fn hash(
        &self,
        layouter: impl Layouter<F>,
        preimage: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, plonk::Error> {
        let consts = get_poseidon_constants::<F, A>();
        self.hash(layouter, preimage, consts)
    }
}

impl<F, A> Halo2Hasher<A> for PoseidonHasher<F>
where
    F: FieldExt,
    A: PoseidonArity<F>,
    Self: Hasher<Field = F>,
{
    type Chip = PoseidonChipStd<F, A>;
    type Config = PoseidonConfigStd<F, A>;

    fn construct(config: Self::Config) -> Self::Chip {
        Self::Chip::construct(config)
    }

    fn configure(
        meta: &mut plonk::ConstraintSystem<F>,
        advice_eq: &[Column<Advice>],
        advice_neq: &[Column<Advice>],
        fixed_eq: &[Column<Fixed>],
        fixed_neq: &[Column<Fixed>],
    ) -> Self::Config {
        let num_advice_eq = Self::Chip::num_advice_eq();
        let num_advice_total = Self::Chip::num_advice_total();
        let num_fixed_eq = Self::Chip::num_fixed_eq();
        let num_fixed_total = Self::Chip::num_fixed_total();

        // Check that the caller provided enough equality enabled and total columns. Note that
        // equality enabled columns can be used as non-equality-enabled columns, but not vice versa.
        let advice_eq_len = advice_eq.len();
        assert!(advice_eq_len >= num_advice_eq);
        assert!(advice_eq_len + advice_neq.len() >= num_advice_total);

        let fixed_eq_len = fixed_eq.len();
        assert!(fixed_eq_len >= num_fixed_eq);
        assert!(fixed_eq_len + fixed_neq.len() >= num_fixed_total);

        let advice: Vec<Column<Advice>> = advice_eq
            .iter()
            .chain(advice_neq.iter())
            .copied()
            .take(num_advice_total)
            .collect();

        let fixed: Vec<Column<Fixed>> = fixed_eq
            .iter()
            .chain(fixed_neq.iter())
            .copied()
            .take(num_fixed_total)
            .collect();

        Self::Chip::configure(meta, &advice, &fixed)
    }

    fn change_config_arity<A2>(config: Self::Config) -> <Self as Halo2Hasher<A2>>::Config
    where
        A2: PoseidonArity<Self::Field>,
    {
        config.change_arity()
    }
}
