use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use std::marker::PhantomData;
use std::panic::panic_any;

use bellperson::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use generic_array::typenum::{marker_traits::Unsigned, U2, U4, U8};
use merkletree::{
    hash::{Algorithm as LightAlgorithm, Hashable},
    merkle::Element,
};
use neptune::{circuit::poseidon_hash, poseidon::Poseidon};
#[cfg(feature = "nova")]
use pasta_curves::{Fp, Fq};
use serde::{Deserialize, Serialize};

use crate::types::{
    impl_hasher_for_field, get_poseidon_constants, get_poseidon_md_constants, Domain, HashFunction,
    Hasher, PoseidonArity, PoseidonMDArity,
};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHasher<F = Fr> {
    #[serde(skip)]
    _f: PhantomData<F>,
}

#[derive(Default, Clone, Debug)]
pub struct PoseidonFunction<F = Fr>(F);

impl<F> Hashable<PoseidonFunction<F>> for PoseidonDomain<F>
where
    F: PrimeField,
    Self: Domain<Field = F>,
{
    fn hash(&self, state: &mut PoseidonFunction<F>) {
        state.write(&self.repr)
    }
}

#[derive(Default, Copy, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PoseidonDomain<F = Fr> {
    repr: [u8; 32],
    #[serde(skip)]
    _f: PhantomData<F>,
}

impl<F> Debug for PoseidonDomain<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PoseidonDomain<{}>({})",
            std::any::type_name::<F>(),
            hex::encode(&self.repr),
        )
    }
}

impl<F> AsRef<PoseidonDomain<F>> for PoseidonDomain<F> {
    fn as_ref(&self) -> &PoseidonDomain<F> {
        self
    }
}

impl<F> StdHash for PoseidonDomain<F> {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        StdHash::hash(&self.repr, state);
    }
}

impl<F> PartialEq for PoseidonDomain<F> {
    fn eq(&self, other: &Self) -> bool {
        self.repr == other.repr
    }
}

impl<F> Eq for PoseidonDomain<F> {}

impl<F> Ord for PoseidonDomain<F> {
    #[inline(always)]
    fn cmp(&self, other: &PoseidonDomain<F>) -> Ordering {
        (self.repr).cmp(&other.repr)
    }
}

impl<F> PartialOrd for PoseidonDomain<F> {
    #[inline(always)]
    fn partial_cmp(&self, other: &PoseidonDomain<F>) -> Option<Ordering> {
        Some((self.repr).cmp(&other.repr))
    }
}

impl<F> AsRef<[u8]> for PoseidonDomain<F> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.repr
    }
}

impl<F> Element for PoseidonDomain<F>
where
    F: PrimeField,
    Self: Domain<Field = F>,
{
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match PoseidonDomain::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic_any(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.repr);
    }
}

impl<F> StdHasher for PoseidonFunction<F>
where
    F: PrimeField,
    PoseidonDomain<F>: Domain<Field = F>,
{
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0 = shared_hash::<F>(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

fn shared_hash<F: PrimeField>(data: &[u8]) -> F {
    // FIXME: We shouldn't unwrap here, but doing otherwise will require an interface change.
    // We could truncate so `bytes_into_frs` cannot fail, then ensure `data` is always `fr_safe`.
    let preimage = data
        .chunks(32)
        .map(|chunk| {
            let mut repr = F::Repr::default();
            repr.as_mut().copy_from_slice(chunk);
            F::from_repr_vartime(repr).expect("from_repr failure")
        })
        .collect::<Vec<_>>();

    shared_hash_frs(&preimage)
}

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
        _ => panic_any(format!(
            "Unsupported arity for Poseidon hasher: {}",
            preimage.len()
        )),
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
        let consts = get_poseidon_constants::<F, U2>();
        let mut p = Poseidon::new_with_preimage(&[(*a).into(), (*b).into()][..], consts);
        let fr: F = p.hash();
        fr.into()
    }

    fn hash_md(input: &[PoseidonDomain<F>]) -> PoseidonDomain<F> {
        assert!(input.len() > 1, "hash_md needs more than one element.");
        let arity = PoseidonMDArity::to_usize();

        let consts = get_poseidon_md_constants::<F>();
        let mut p = Poseidon::new(consts);

        let fr_input: Vec<F> = input.iter().map(|domain| (*domain).into()).collect();

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

    fn hash_leaf_circuit<CS: ConstraintSystem<F>>(
        cs: CS,
        left: &AllocatedNum<F>,
        right: &AllocatedNum<F>,
        _height: usize,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let preimage = vec![left.clone(), right.clone()];

        let consts = get_poseidon_constants::<F, U2>();
        poseidon_hash::<CS, F, U2>(cs, preimage, consts)
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity<F>, CS: ConstraintSystem<F>>(
        cs: CS,
        leaves: &[AllocatedNum<F>],
        _height: usize,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let params = get_poseidon_constants::<F, Arity>();
        poseidon_hash::<CS, F, Arity>(cs, leaves.to_vec(), params)
    }

    fn hash_md_circuit<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        elements: &[AllocatedNum<F>],
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let params = get_poseidon_md_constants::<F>();
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
                        Ok(F::zero())
                    })
                    .expect("alloc failure");
            }
            let cs = cs.namespace(|| format!("hash md {}", hash_num));
            hash = poseidon_hash::<_, F, PoseidonMDArity>(cs, preimage.clone(), params)?.clone();
        }

        Ok(hash)
    }

    fn hash_circuit<CS: ConstraintSystem<F>>(
        _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        unimplemented!();
    }

    fn hash2_circuit<CS>(
        cs: CS,
        a: &AllocatedNum<F>,
        b: &AllocatedNum<F>,
    ) -> Result<AllocatedNum<F>, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let preimage = vec![a.clone(), b.clone()];
        let consts = get_poseidon_constants::<F, U2>();
        poseidon_hash::<CS, F, U2>(cs, preimage, consts)
    }
}

impl<F> LightAlgorithm<PoseidonDomain<F>> for PoseidonFunction<F>
where
    F: PrimeField,
    PoseidonDomain<F>: Domain<Field = F>,
{
    #[inline]
    fn hash(&mut self) -> PoseidonDomain<F> {
        self.0.into()
    }

    #[inline]
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

    fn multi_node(&mut self, parts: &[PoseidonDomain<F>], _height: usize) -> PoseidonDomain<F> {
        match parts.len() {
            2 | 4 | 8 => shared_hash_frs(
                &parts
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect::<Vec<F>>(),
            )
            .into(),
            arity => panic_any(format!("unsupported arity {}", arity)),
        }
    }
}

impl<F> From<[u8; 32]> for PoseidonDomain<F> {
    #[inline]
    fn from(bytes: [u8; 32]) -> Self {
        PoseidonDomain {
            repr: bytes,
            _f: PhantomData,
        }
    }
}

impl<F> From<PoseidonDomain<F>> for [u8; 32] {
    #[inline]
    fn from(val: PoseidonDomain<F>) -> Self {
        val.repr
    }
}

impl_hasher_for_field!(PoseidonHasher, PoseidonDomain, PoseidonFunction, "poseidon_hasher", Fr);

#[cfg(feature = "nova")]
impl_hasher_for_field!(PoseidonHasher, PoseidonDomain, PoseidonFunction, "poseidon_hasher", Fp, Fq);

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use ff::Field;
    use merkletree::{merkle::MerkleTree, store::VecStore};

    fn u64s_to_u8s(u64s: [u64; 4]) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&u64s[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&u64s[1].to_le_bytes());
        bytes[16..24].copy_from_slice(&u64s[2].to_le_bytes());
        bytes[24..].copy_from_slice(&u64s[3].to_le_bytes());
        bytes
    }

    #[test]
    fn test_path() {
        let values = [
            PoseidonDomain::from(Fr::one()),
            PoseidonDomain::from(Fr::one()),
            PoseidonDomain::from(Fr::one()),
            PoseidonDomain::from(Fr::one()),
        ];

        let t = MerkleTree::<PoseidonDomain, PoseidonFunction, VecStore<_>, U2>::new(
            values.iter().copied(),
        )
        .expect("merkle tree new failure");

        let p = t.gen_proof(0).expect("gen_proof failure"); // create a proof for the first value =k Fr::one()

        assert_eq!(*p.path(), vec![0, 0]);
        assert!(p
            .validate::<PoseidonFunction>()
            .expect("failed to validate"));
    }

    // #[test]
    // fn test_poseidon_quad() {
    //     let leaves = [Fr::one(), Fr::zero(), Fr::zero(), Fr::one()];

    //     assert_eq!(Fr::zero().to_repr(), shared_hash_frs(&leaves[..]).to_repr());
    // }

    #[test]
    fn test_poseidon_hasher() {
        let leaves = [
            PoseidonDomain::from(Fr::one()),
            PoseidonDomain::from(Fr::zero()),
            PoseidonDomain::from(Fr::zero()),
            PoseidonDomain::from(Fr::one()),
        ];

        let t = MerkleTree::<PoseidonDomain, PoseidonFunction, VecStore<_>, U2>::new(
            leaves.iter().copied(),
        )
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
            t.read_at(4).expect("read_at failure").repr,
            u64s_to_u8s([
                0xb339ff6079800b5e,
                0xec5907b3dc3094af,
                0x93c003cc74a24f26,
                0x042f94ffbe786bc3,
            ]),
        );

        let expected = u64s_to_u8s([
            0xefbb8be3e291e671,
            0x77cc72b8cb2b5ad2,
            0x30eb6385ae6b74ae,
            0x1effebb7b26ad9eb,
        ]);
        let actual = t.read_at(6).expect("read_at failure").repr;

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
            let val = PoseidonDomain::<Fr>::from(u64s_to_u8s(case));

            for _ in 0..100 {
                assert_eq!(val.into_bytes(), val.into_bytes());
            }

            let raw: &[u8] = val.as_ref();

            for (limb, bytes) in case.iter().zip(raw.chunks(8)) {
                assert_eq!(&limb.to_le_bytes(), bytes);
            }
        }
    }

    #[test]
    fn test_serialize() {
        let val = PoseidonDomain::<Fr>::from(u64s_to_u8s([1, 2, 3, 4]));

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
        let data = vec![PoseidonDomain::from(Fr::one()); n];
        let hashed = PoseidonFunction::hash_md(&data);

        assert_eq!(
            hashed,
            PoseidonDomain::from(u64s_to_u8s([
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
        let data = vec![PoseidonDomain::from(Fr::one()); n];

        let mut cs = TestConstraintSystem::<Fr>::new();
        let circuit_data = (0..n)
            .map(|n| {
                AllocatedNum::alloc(cs.namespace(|| format!("input {}", n)), || Ok(Fr::one()))
                    .expect("alloc failure")
            })
            .collect::<Vec<_>>();

        let hashed = PoseidonFunction::<Fr>::hash_md(&data);
        let hashed_fr = Fr::from_repr_vartime(hashed.repr).expect("from_repr failure");

        let circuit_hashed = PoseidonFunction::<Fr>::hash_md_circuit(&mut cs, circuit_data.as_slice())
            .expect("hash_md_circuit failure");

        assert!(cs.is_satisfied());
        let expected_constraints = 2_770;
        let actual_constraints = cs.num_constraints();

        assert_eq!(expected_constraints, actual_constraints);

        assert_eq!(
            hashed_fr,
            circuit_hashed.get_value().expect("get_value failure")
        );
    }
}
