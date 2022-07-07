use std::cmp::Ordering;
use std::convert::TryInto;
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use bellperson::{
    gadgets::{boolean::Boolean, multipack, num::AllocatedNum, sha256::sha256 as sha256_circuit},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use fil_halo2_gadgets::{
    sha256::{Sha256FieldChip, Sha256FieldConfig},
    ColumnCount,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter},
    pasta::{Fp, Fq},
    plonk::{self, Advice, Column, Fixed},
};
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{
    Domain, Groth16Hasher, Halo2Hasher, HashFunction, HashInstructions, Hasher, PoseidonArity,
};

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

impl<F> From<[u8; 32]> for Sha256Domain<F> {
    fn from(bytes: [u8; 32]) -> Self {
        Sha256Domain {
            state: bytes,
            _f: PhantomData,
        }
    }
}

impl<F> Into<[u8; 32]> for Sha256Domain<F> {
    fn into(self) -> [u8; 32] {
        self.state
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

// The trait bound `F: PrimeField` is necessary because `Element` requires that `F` implements
// `Clone + Send + Sync`.
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
    pub fn trim_to_fr32(&mut self) {
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

impl<F> Algorithm<Sha256Domain<F>> for Sha256Function<F>
where
    F: PrimeField,
    Sha256Domain<F>: Domain<Field = F>,
{
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

impl<F> HashFunction<Sha256Domain<F>> for Sha256Function<F>
where
    F: PrimeField,
    Sha256Domain<F>: Domain<Field = F>,
{
    fn hash(data: &[u8]) -> Sha256Domain<F> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(Sha256::digest(data).as_ref());
        let mut trimmed: Sha256Domain<F> = digest.into();
        trimmed.trim_to_fr32();
        trimmed
    }

    fn hash2(a: &Sha256Domain<F>, b: &Sha256Domain<F>) -> Sha256Domain<F> {
        let mut digest = [0u8; 32];
        let hasher = Sha256::new()
            .chain(AsRef::<[u8]>::as_ref(a))
            .chain(AsRef::<[u8]>::as_ref(b));
        digest.copy_from_slice(hasher.finalize().as_ref());
        let mut trimmed: Sha256Domain<F> = digest.into();
        trimmed.trim_to_fr32();
        trimmed
    }
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sha256Hasher<F> {
    _f: PhantomData<F>,
}

// TODO (jake): should hashers over different fields have different names?
const HASHER_NAME: &str = "sha256_hasher";

impl Hasher for Sha256Hasher<Fr> {
    type Field = Fr;
    type Domain = Sha256Domain<Self::Field>;
    type Function = Sha256Function<Self::Field>;

    fn name() -> String {
        HASHER_NAME.into()
    }
}
impl Hasher for Sha256Hasher<Fp> {
    type Field = Fp;
    type Domain = Sha256Domain<Self::Field>;
    type Function = Sha256Function<Self::Field>;

    fn name() -> String {
        HASHER_NAME.into()
    }
}
impl Hasher for Sha256Hasher<Fq> {
    type Field = Fq;
    type Domain = Sha256Domain<Self::Field>;
    type Function = Sha256Function<Self::Field>;

    fn name() -> String {
        HASHER_NAME.into()
    }
}

// Only implement `Groth16Hasher` for `Sha256Hasher<Fr>` because `Fr` is the only field which is
// compatible with Groth16.
impl Groth16Hasher for Sha256Hasher<Fr> {
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

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        mut cs: CS,
        a_num: &AllocatedNum<Fr>,
        b_num: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
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

impl<F: FieldExt> HashInstructions<F> for Sha256FieldChip<F> {
    fn hash(
        &self,
        layouter: impl Layouter<F>,
        preimage: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, plonk::Error> {
        self.hash_field_elems(layouter, preimage)
    }
}

impl<F, A> Halo2Hasher<A> for Sha256Hasher<F>
where
    Self: Hasher<Field = F>,
    F: FieldExt,
    A: PoseidonArity<F>,
{
    type Chip = Sha256FieldChip<F>;
    type Config = Sha256FieldConfig<F>;

    fn load(layouter: &mut impl Layouter<F>, config: &Self::Config) -> Result<(), plonk::Error> {
        Sha256FieldChip::load(layouter, config)
    }

    fn construct(config: Self::Config) -> Self::Chip {
        Sha256FieldChip::construct(config)
    }

    #[allow(clippy::unwrap_used)]
    fn configure(
        meta: &mut plonk::ConstraintSystem<F>,
        advice_eq: &[Column<Advice>],
        _advice_neq: &[Column<Advice>],
        _fixed_eq: &[Column<Fixed>],
        _fixed_neq: &[Column<Fixed>],
    ) -> Self::Config {
        let num_cols = Self::Chip::num_cols();
        assert!(advice_eq.len() >= num_cols.advice_eq);
        let advice = advice_eq[..num_cols.advice_eq].try_into().unwrap();
        Sha256FieldChip::configure(meta, advice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::{
        gadgets::num::AllocatedNum, util_cs::test_cs::TestConstraintSystem, ConstraintSystem as _,
    };
    use blstrs::Scalar as Fr;
    use ff::{Field, PrimeField};
    use fil_halo2_gadgets::AdviceIter;
    use generic_array::typenum::U2;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
        dev::MockProver,
        pasta::{Fp, Fq},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };

    #[test]
    fn test_sha256_bls_pasta_compat() {
        // Test two one-block and two two-block preimages.
        let preimages = [vec![1u8], vec![0, 55, 0, 0], vec![1; 64], vec![1; 100]];
        for preimage in &preimages {
            let digest_fr: [u8; 32] =
                <Sha256Function<Fr> as HashFunction<_>>::hash(preimage).into();
            let digest_fp: [u8; 32] =
                <Sha256Function<Fp> as HashFunction<_>>::hash(preimage).into();
            let digest_fq: [u8; 32] =
                <Sha256Function<Fq> as HashFunction<_>>::hash(preimage).into();
            assert_eq!(digest_fr, digest_fp);
            assert_eq!(digest_fr, digest_fq);
        }
    }

    // Choose an arbitrary arity type because it is ignored by the sha256 circuit.
    type A = U2;

    struct Sha256Circuit<F>
    where
        F: FieldExt,
        Sha256Hasher<F>: Hasher<Field = F>,
    {
        preimage: Vec<Option<F>>,
        groth_digest: Fr,
    }

    impl<F> Circuit<F> for Sha256Circuit<F>
    where
        F: FieldExt,
        Sha256Hasher<F>: Hasher<Field = F>,
    {
        type Config = (
            <Sha256Hasher<F> as Halo2Hasher<A>>::Config,
            [Column<Advice>; 9],
        );
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Sha256Circuit {
                preimage: vec![None; self.preimage.len()],
                groth_digest: Fr::zero(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let advice = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];
            let sha256 =
                <Sha256Hasher<F> as Halo2Hasher<A>>::configure(meta, &advice, &[], &[], &[]);
            (sha256, advice)
        }

        #[allow(clippy::unwrap_used)]
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let (sha256_config, advice) = config;

            <Sha256Hasher<F> as Halo2Hasher<A>>::load(&mut layouter, &sha256_config)?;
            let sha256_chip = <Sha256Hasher<F> as Halo2Hasher<A>>::construct(sha256_config);

            let preimage = layouter.assign_region(
                || "assign preimage",
                |mut region| {
                    let mut advice_iter = AdviceIter::from(advice.to_vec());
                    self.preimage
                        .iter()
                        .enumerate()
                        .map(|(i, elem)| {
                            let (offset, col) = advice_iter.next();
                            region.assign_advice(
                                || format!("preimage elem {}", i),
                                col,
                                offset,
                                || elem.ok_or(Error::Synthesis),
                            )
                        })
                        .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()
                },
            )?;

            let digest = <<Sha256Hasher<F> as Halo2Hasher<A>>::Chip as HashInstructions<F>>::hash(
                &sha256_chip,
                layouter.namespace(|| "sha256"),
                &preimage,
            )?;

            assert_eq!(
                digest.value().unwrap().to_repr().as_ref(),
                self.groth_digest.to_repr().as_ref(),
            );

            Ok(())
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_sha256_groth16_halo2_compat() {
        // Test one-element preimage.
        {
            let groth_digest: Fr = {
                let mut cs = TestConstraintSystem::new();
                let preimage = [AllocatedNum::alloc(&mut cs, || Ok(Fr::one())).unwrap()];
                Sha256Hasher::hash_multi_leaf_circuit::<A, _>(&mut cs, &preimage, 0)
                    .unwrap()
                    .get_value()
                    .unwrap()
            };

            // Compute Halo2 digest using Pallas field.
            let circ = Sha256Circuit {
                preimage: vec![Some(Fp::one())],
                groth_digest,
            };
            let prover = MockProver::run(17, &circ, vec![]).unwrap();
            assert!(prover.verify().is_ok());

            // Compute Halo2 digest using Vesta field.
            let circ = Sha256Circuit {
                preimage: vec![Some(Fq::one())],
                groth_digest,
            };
            let prover = MockProver::run(17, &circ, vec![]).unwrap();
            assert!(prover.verify().is_ok());
        }

        // Test two-element preimage.
        {
            let groth_digest: Fr = {
                let mut cs = TestConstraintSystem::new();
                let preimage = [
                    AllocatedNum::alloc(cs.namespace(|| "preimage elem 1"), || Ok(Fr::one()))
                        .unwrap(),
                    AllocatedNum::alloc(cs.namespace(|| "preimage elem 2"), || Ok(Fr::from(55)))
                        .unwrap(),
                ];
                Sha256Hasher::hash_multi_leaf_circuit::<A, _>(&mut cs, &preimage, 0)
                    .unwrap()
                    .get_value()
                    .unwrap()
            };

            // Compute Halo2 digest using Pallas field.
            let circ = Sha256Circuit {
                preimage: vec![Some(Fp::one()), Some(Fp::from(55))],
                groth_digest,
            };
            let prover = MockProver::run(17, &circ, vec![]).unwrap();
            assert!(prover.verify().is_ok());

            // Compute Halo2 digest using Vesta field.
            let circ = Sha256Circuit {
                preimage: vec![Some(Fq::one()), Some(Fq::from(55))],
                groth_digest,
            };
            let prover = MockProver::run(17, &circ, vec![]).unwrap();
            assert!(prover.verify().is_ok());
        }
    }
}
