use fil_halo2_gadgets::{boolean::AssignedBit, WitnessOrCopy};
use filecoin_hashers::{Domain, HaloHasher, HashInstructions, PoseidonArity};
use generic_array::typenum::U0;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter},
    plonk::Error,
};

use crate::gadgets::halo2::insert::InsertChip;

pub struct MerkleChip<H, U, V = U0, W = U0>
where
    H: HaloHasher<U> + HaloHasher<V> + HaloHasher<W>,
    <H::Domain as Domain>::Field: FieldExt,
    U: PoseidonArity<<H::Domain as Domain>::Field>,
    V: PoseidonArity<<H::Domain as Domain>::Field>,
    W: PoseidonArity<<H::Domain as Domain>::Field>,
{
    base_hasher: <H as HaloHasher<U>>::Chip,
    base_insert: InsertChip<<H::Domain as Domain>::Field, U>,
    sub_hasher_insert: Option<(
        <H as HaloHasher<V>>::Chip,
        InsertChip<<H::Domain as Domain>::Field, V>,
    )>,
    top_hasher_insert: Option<(
        <H as HaloHasher<W>>::Chip,
        InsertChip<<H::Domain as Domain>::Field, W>,
    )>,
}

impl<H, U, V, W> MerkleChip<H, U, V, W>
where
    H: HaloHasher<U> + HaloHasher<V> + HaloHasher<W>,
    <H::Domain as Domain>::Field: FieldExt,
    U: PoseidonArity<<H::Domain as Domain>::Field>,
    V: PoseidonArity<<H::Domain as Domain>::Field>,
    W: PoseidonArity<<H::Domain as Domain>::Field>,
{
    pub fn with_subchips(
        base_hasher: <H as HaloHasher<U>>::Chip,
        base_insert: InsertChip<<H::Domain as Domain>::Field, U>,
        sub_hasher_insert: Option<(
            <H as HaloHasher<V>>::Chip,
            InsertChip<<H::Domain as Domain>::Field, V>,
        )>,
        top_hasher_insert: Option<(
            <H as HaloHasher<W>>::Chip,
            InsertChip<<H::Domain as Domain>::Field, W>,
        )>,
    ) -> Self {
        if V::to_usize() == 0 {
            assert!(sub_hasher_insert.is_none());
        } else {
            assert!(sub_hasher_insert.is_some());
        };
        if W::to_usize() == 0 {
            assert!(top_hasher_insert.is_none());
        } else {
            assert!(top_hasher_insert.is_some());
        };
        MerkleChip {
            base_hasher,
            base_insert,
            sub_hasher_insert,
            top_hasher_insert,
        }
    }

    pub fn compute_root(
        &self,
        layouter: impl Layouter<<H::Domain as Domain>::Field>,
        challenge_bits: &[AssignedBit<<H::Domain as Domain>::Field>],
        leaf: &Option<<H::Domain as Domain>::Field>,
        path: &[Vec<Option<<H::Domain as Domain>::Field>>],
    ) -> Result<AssignedCell<<H::Domain as Domain>::Field, <H::Domain as Domain>::Field>, Error> {
        self.compute_root_inner(
            layouter,
            challenge_bits,
            WitnessOrCopy::Witness(*leaf),
            path,
        )
    }

    pub fn copy_leaf_compute_root(
        &self,
        layouter: impl Layouter<<H::Domain as Domain>::Field>,
        challenge_bits: &[AssignedBit<<H::Domain as Domain>::Field>],
        leaf: &AssignedCell<<H::Domain as Domain>::Field, <H::Domain as Domain>::Field>,
        path: &[Vec<Option<<H::Domain as Domain>::Field>>],
    ) -> Result<AssignedCell<<H::Domain as Domain>::Field, <H::Domain as Domain>::Field>, Error> {
        self.compute_root_inner(
            layouter,
            challenge_bits,
            WitnessOrCopy::Copy(leaf.clone()),
            path,
        )
    }

    #[allow(unused_assignments)]
    #[allow(clippy::unwrap_used)]
    fn compute_root_inner(
        &self,
        mut layouter: impl Layouter<<H::Domain as Domain>::Field>,
        challenge_bits: &[AssignedBit<<H::Domain as Domain>::Field>],
        leaf: WitnessOrCopy<<H::Domain as Domain>::Field, <H::Domain as Domain>::Field>,
        path: &[Vec<Option<<H::Domain as Domain>::Field>>],
    ) -> Result<AssignedCell<<H::Domain as Domain>::Field, <H::Domain as Domain>::Field>, Error> {
        let base_arity = U::to_usize();
        let sub_arity = V::to_usize();
        let top_arity = W::to_usize();

        let base_arity_bit_len = base_arity.trailing_zeros();
        let sub_arity_bit_len = sub_arity.trailing_zeros();
        let top_arity_bit_len = top_arity.trailing_zeros();

        let base_path_len = if top_arity > 0 {
            path.len() - 2
        } else if sub_arity > 0 {
            path.len() - 1
        } else {
            path.len()
        };

        let mut cur = None;
        let mut height = 0;
        let mut path_values = path.iter();
        let mut challenge_bits = challenge_bits.iter();

        for _ in 0..base_path_len {
            let siblings = path_values.next().expect("no path elements remaining");

            assert_eq!(
                siblings.len(),
                base_arity - 1,
                "path element has incorrect number of siblings"
            );

            let index_bits: Vec<AssignedBit<<H::Domain as Domain>::Field>> = (0
                ..base_arity_bit_len)
                .map(|_| {
                    challenge_bits
                        .next()
                        .expect("no challenge bits remaining")
                        .clone()
                })
                .collect();

            let preimage = if height == 0 {
                match leaf {
                    WitnessOrCopy::Witness(ref leaf) => {
                        self.base_insert.witness_insert(
                            layouter.namespace(|| format!("base insert (height {})", height)),
                            siblings,
                            leaf,
                            &index_bits,
                        )?
                    }
                    WitnessOrCopy::Copy(ref leaf) => {
                        self.base_insert.copy_insert(
                            layouter.namespace(|| format!("base insert (height {})", height)),
                            siblings,
                            leaf,
                            &index_bits,
                        )?
                    }
                }
            } else {
                self.base_insert.copy_insert(
                    layouter.namespace(|| format!("base insert (height {})", height)),
                    siblings,
                    &cur.take().unwrap(),
                    &index_bits,
                )?
            };

            let digest = self.base_hasher.hash(
                layouter.namespace(|| format!("base hash siblings (height {})", height)),
                &preimage,
            )?;

            cur = Some(digest);
            height += 1;
        }

        if sub_arity > 0 {
            let siblings = path_values.next().expect("no path elements remaining");

            assert_eq!(
                siblings.len(),
                sub_arity - 1,
                "path element has incorrect number of siblings"
            );

            let index_bits: Vec<AssignedBit<<H::Domain as Domain>::Field>> = (0..sub_arity_bit_len)
                .map(|_| {
                    challenge_bits
                        .next()
                        .expect("no challenge bits remaining")
                        .clone()
                })
                .collect();

            let (sub_hasher, sub_insert) = self.sub_hasher_insert.as_ref().unwrap();

            let preimage = sub_insert.copy_insert(
                layouter.namespace(|| format!("insert (height {})", height)),
                siblings,
                &cur.take().unwrap(),
                &index_bits,
            )?;

            let digest = sub_hasher.hash(
                layouter.namespace(|| format!("merkle proof hash (height {})", height)),
                &preimage,
            )?;

            cur = Some(digest);
            height += 1;
        }

        if top_arity > 0 {
            let siblings = path_values.next().expect("no path elements remaining");

            assert_eq!(
                siblings.len(),
                top_arity - 1,
                "path element has incorrect number of siblings"
            );

            let index_bits: Vec<AssignedBit<<H::Domain as Domain>::Field>> = (0..top_arity_bit_len)
                .map(|_| {
                    challenge_bits
                        .next()
                        .expect("no challenge bits remaining")
                        .clone()
                })
                .collect();

            let (top_hasher, top_insert) = self.top_hasher_insert.as_ref().unwrap();

            let preimage = top_insert.copy_insert(
                layouter.namespace(|| format!("insert (height {})", height)),
                siblings,
                &cur.take().unwrap(),
                &index_bits,
            )?;

            let digest = top_hasher.hash(
                layouter.namespace(|| format!("merkle proof hash (height {})", height)),
                &preimage,
            )?;

            cur = Some(digest);
            height += 1;
        }

        Ok(cur.unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::any::TypeId;
    use std::convert::TryInto;
    use std::marker::PhantomData;

    use ff::PrimeField;
    use fil_halo2_gadgets::{
        uint32::{AssignedU32, UInt32Chip, UInt32Config},
        NumCols,
    };
    use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, HashFunction};
    use generic_array::typenum::{U0, U2, U4, U8};
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        pasta::Fp,
        plonk::{Circuit, ConstraintSystem},
    };
    use merkletree::store::VecStore;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::{
        gadgets::halo2::insert::InsertConfig,
        merkle::{
            generate_tree, MerkleProof, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper,
        },
        util::NODE_SIZE,
        TEST_SEED,
    };

    #[derive(Clone)]
    struct MyConfig<H, U, V, W>
    where
        H: HaloHasher<U> + HaloHasher<V> + HaloHasher<W>,
        <H::Domain as Domain>::Field: FieldExt,
        U: PoseidonArity<<H::Domain as Domain>::Field>,
        V: PoseidonArity<<H::Domain as Domain>::Field>,
        W: PoseidonArity<<H::Domain as Domain>::Field>,
    {
        uint32: UInt32Config<<H::Domain as Domain>::Field>,
        base_hasher: <H as HaloHasher<U>>::Config,
        base_insert: InsertConfig<<H::Domain as Domain>::Field, U>,
        sub: Option<(
            <H as HaloHasher<V>>::Config,
            InsertConfig<<H::Domain as Domain>::Field, V>,
        )>,
        top: Option<(
            <H as HaloHasher<W>>::Config,
            InsertConfig<<H::Domain as Domain>::Field, W>,
        )>,
    }

    struct MyCircuit<H, U, V, W>
    where
        H: HaloHasher<U> + HaloHasher<V> + HaloHasher<W>,
        <H::Domain as Domain>::Field: FieldExt,
        U: PoseidonArity<<H::Domain as Domain>::Field>,
        V: PoseidonArity<<H::Domain as Domain>::Field>,
        W: PoseidonArity<<H::Domain as Domain>::Field>,
    {
        challenge: Option<u32>,
        leaf: Option<<H::Domain as Domain>::Field>,
        path: Vec<Vec<Option<<H::Domain as Domain>::Field>>>,
        _u: PhantomData<U>,
        _v: PhantomData<V>,
        _w: PhantomData<W>,
    }

    impl<H, U, V, W> Circuit<<H::Domain as Domain>::Field> for MyCircuit<H, U, V, W>
    where
        H: 'static + HaloHasher<U> + HaloHasher<V> + HaloHasher<W>,
        <H::Domain as Domain>::Field: FieldExt,
        U: PoseidonArity<<H::Domain as Domain>::Field>,
        V: PoseidonArity<<H::Domain as Domain>::Field>,
        W: PoseidonArity<<H::Domain as Domain>::Field>,
    {
        type Config = MyConfig<H, U, V, W>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MyCircuit {
                challenge: None,
                leaf: None,
                path: self
                    .path
                    .iter()
                    .map(|sibs| vec![None; sibs.len()])
                    .collect(),
                _u: PhantomData,
                _v: PhantomData,
                _w: PhantomData,
            }
        }

        #[allow(clippy::unwrap_used)]
        fn configure(meta: &mut ConstraintSystem<<H::Domain as Domain>::Field>) -> Self::Config {
            let uint32_cols = UInt32Chip::<<H::Domain as Domain>::Field>::num_cols();
            let hasher_cols = <H as HaloHasher<U>>::num_cols();
            let insert_cols = InsertChip::<<H::Domain as Domain>::Field, U>::num_cols();

            let (advice_eq, advice_neq, fixed_eq, fixed_neq) =
                NumCols::for_circuit(&[uint32_cols, hasher_cols, insert_cols]).configure(meta);

            let uint32 =
                UInt32Chip::configure(meta, advice_eq[..uint32_cols.advice_eq].try_into().unwrap());

            let base_hasher = <H as HaloHasher<U>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );

            let base_insert = InsertChip::<<H::Domain as Domain>::Field, U>::configure(
                meta,
                &advice_eq,
                &advice_neq,
            );

            let sub = if V::to_usize() == 0 {
                None
            } else {
                let sub_hasher = <H as HaloHasher<V>>::configure(
                    meta,
                    &advice_eq,
                    &advice_neq,
                    &fixed_eq,
                    &fixed_neq,
                );
                let sub_insert = InsertChip::<<H::Domain as Domain>::Field, V>::configure(
                    meta,
                    &advice_eq,
                    &advice_neq,
                );
                Some((sub_hasher, sub_insert))
            };

            let top = if W::to_usize() == 0 {
                None
            } else {
                let top_hasher = <H as HaloHasher<W>>::configure(
                    meta,
                    &advice_eq,
                    &advice_neq,
                    &fixed_eq,
                    &fixed_neq,
                );
                let top_insert = InsertChip::<<H::Domain as Domain>::Field, W>::configure(
                    meta,
                    &advice_eq,
                    &advice_neq,
                );
                Some((top_hasher, top_insert))
            };

            MyConfig {
                uint32,
                base_hasher,
                base_insert,
                sub,
                top,
            }
        }

        #[allow(clippy::unwrap_used)]
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<<H::Domain as Domain>::Field>,
        ) -> Result<(), Error> {
            let MyConfig {
                uint32: uint32_config,
                base_hasher: base_hasher_config,
                base_insert: base_insert_config,
                sub: sub_config,
                top: top_config,
            } = config;

            let challenge_col = uint32_config.value_col();

            let uint32_chip = UInt32Chip::construct(uint32_config);

            <H as HaloHasher<U>>::load(&mut layouter, &base_hasher_config)?;
            let base_hasher_chip = <H as HaloHasher<U>>::construct(base_hasher_config);
            let base_insert_chip =
                InsertChip::<<H::Domain as Domain>::Field, U>::construct(base_insert_config);

            let sub_hasher_insert_chips = sub_config.map(|(hasher_config, insert_config)| {
                let hasher_chip = <H as HaloHasher<V>>::construct(hasher_config);
                let insert_chip =
                    InsertChip::<<H::Domain as Domain>::Field, V>::construct(insert_config);
                (hasher_chip, insert_chip)
            });

            let top_hasher_insert_chips = top_config.map(|(hasher_config, insert_config)| {
                let hasher_chip = <H as HaloHasher<W>>::construct(hasher_config);
                let insert_chip =
                    InsertChip::<<H::Domain as Domain>::Field, W>::construct(insert_config);
                (hasher_chip, insert_chip)
            });

            let merkle_chip = MerkleChip::<H, U, V, W>::with_subchips(
                base_hasher_chip,
                base_insert_chip,
                sub_hasher_insert_chips,
                top_hasher_insert_chips,
            );

            let challenge_bits = layouter.assign_region(
                || "challenge",
                |mut region| {
                    let offset = 0;
                    let challenge = AssignedU32::assign(
                        &mut region,
                        || "challenge",
                        challenge_col,
                        offset,
                        self.challenge,
                    )?;
                    uint32_chip.assign_bits(&mut region, offset, challenge)
                },
            )?;

            let root =
                merkle_chip.compute_root(layouter, &challenge_bits, &self.leaf, &self.path)?;
            assert_eq!(root.value().unwrap(), &self.expected_root());

            Ok(())
        }
    }

    impl<H, U, V, W> MyCircuit<H, U, V, W>
    where
        H: 'static + HaloHasher<U> + HaloHasher<V> + HaloHasher<W>,
        <H::Domain as Domain>::Field: FieldExt,
        U: PoseidonArity<<H::Domain as Domain>::Field>,
        V: PoseidonArity<<H::Domain as Domain>::Field>,
        W: PoseidonArity<<H::Domain as Domain>::Field>,
    {
        fn with_witness(challenge: u32, merkle_proof: &MerkleProof<H, U, V, W>) -> Self {
            let path = merkle_proof
                .path()
                .iter()
                .map(|(sibs, _)| sibs.iter().copied().map(|sib| Some(sib.into())).collect())
                .collect();
            MyCircuit {
                challenge: Some(challenge),
                leaf: Some(merkle_proof.leaf().into()),
                path,
                _u: PhantomData,
                _v: PhantomData,
                _w: PhantomData,
            }
        }

        fn k(num_leafs: usize) -> u32 {
            if TypeId::of::<H>() == TypeId::of::<Sha256Hasher<<H::Domain as Domain>::Field>>() {
                return 17;
            }

            let challenge_bit_len = num_leafs.trailing_zeros() as usize;

            let base_arity = U::to_usize();
            let sub_arity = V::to_usize();
            let top_arity = W::to_usize();

            let base_bit_len = base_arity.trailing_zeros() as usize;
            let sub_bit_len = sub_arity.trailing_zeros() as usize;
            let top_bit_len = top_arity.trailing_zeros() as usize;

            let base_path_len = if top_arity > 0 {
                (challenge_bit_len - (top_bit_len + sub_bit_len)) / base_bit_len
            } else if sub_arity > 0 {
                (challenge_bit_len - sub_bit_len) / base_bit_len
            } else {
                challenge_bit_len / base_bit_len
            };

            let base_hasher_rows = match base_arity {
                2 | 4 => 36,
                8 => 37,
                _ => unimplemented!(),
            };
            let sub_hasher_rows = match sub_arity {
                0 => 0,
                2 | 4 => 36,
                8 => 37,
                _ => unimplemented!(),
            };
            let top_hasher_rows = match top_arity {
                0 => 0,
                2 | 4 => 36,
                8 => 37,
                _ => unimplemented!(),
            };
            let insert_rows = 1;

            // Four rows for decomposing the challenge into 32 bits.
            let mut num_rows = 4;
            num_rows += base_path_len * (base_hasher_rows + insert_rows);
            if sub_arity > 0 {
                num_rows += sub_hasher_rows + insert_rows;
            }
            if top_arity > 0 {
                num_rows += top_hasher_rows + insert_rows;
            };

            (num_rows as f32).log2().ceil() as u32
        }

        #[allow(clippy::unwrap_used)]
        fn expected_root(&self) -> <H::Domain as Domain>::Field {
            let challenge = self.challenge.unwrap() as usize;
            let mut challenge_bits = (0..32).map(|i| challenge >> i & 1);

            let mut cur = self.leaf.unwrap();

            for siblings in self.path.iter() {
                let arity = siblings.len() + 1;
                let index_bit_len = arity.trailing_zeros() as usize;

                let mut index = 0;
                for i in 0..index_bit_len {
                    index += challenge_bits.next().unwrap() << i;
                }

                // Insert `cur` into `siblings` at position `index`.
                let mut preimage = Vec::<u8>::with_capacity(arity * NODE_SIZE);
                for sib in &siblings[..index] {
                    preimage.extend_from_slice(sib.as_ref().unwrap().to_repr().as_ref())
                }
                preimage.extend_from_slice(cur.to_repr().as_ref());
                for sib in &siblings[index..] {
                    preimage.extend_from_slice(sib.as_ref().unwrap().to_repr().as_ref())
                }

                cur = H::Function::hash(&preimage).into();
            }

            cur
        }
    }

    #[allow(clippy::unwrap_used)]
    fn test_merkle_chip_inner<H, U, V, W>()
    where
        H: 'static + HaloHasher<U> + HaloHasher<V> + HaloHasher<W>,
        <H::Domain as Domain>::Field: FieldExt,
        U: PoseidonArity<<H::Domain as Domain>::Field>,
        V: PoseidonArity<<H::Domain as Domain>::Field>,
        W: PoseidonArity<<H::Domain as Domain>::Field>,
    {
        const BASE_HEIGHT: u32 = 2;

        let base_arity = U::to_usize();
        let sub_arity = V::to_usize();
        let top_arity = W::to_usize();

        let mut num_leafs = base_arity.pow(BASE_HEIGHT);
        if sub_arity > 0 {
            num_leafs *= sub_arity;
        }
        if top_arity > 0 {
            num_leafs *= top_arity;
        }

        let mut rng = XorShiftRng::from_seed(TEST_SEED);
        let (_, tree) = generate_tree::<MerkleTreeWrapper<H, VecStore<H::Domain>, U, V, W>, _>(
            &mut rng, num_leafs, None,
        );

        for _ in 0..50 {
            let challenge = rng.gen::<usize>() % num_leafs;
            let merkle_proof = tree.gen_proof(challenge).unwrap();
            let circ = MyCircuit::<H, U, V, W>::with_witness(challenge as u32, &merkle_proof);
            let k = MyCircuit::<H, U, V, W>::k(num_leafs);
            let prover = MockProver::run(k, &circ, vec![]).unwrap();
            assert!(prover.verify().is_ok());
        }
    }

    #[test]
    fn test_merkle_chip_poseidon_2() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U2, U0, U0>();
    }

    #[test]
    fn test_merkle_chip_poseidon_4() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U4, U0, U0>();
    }

    #[test]
    fn test_merkle_chip_poseidon_8() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U0, U0>();
    }

    #[test]
    fn test_merkle_chip_poseidon_8_2() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U2, U0>();
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U8, U2>();
    }

    #[test]
    fn test_merkle_chip_poseidon_8_4() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U4, U0>();
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U8, U4>();
    }

    #[test]
    fn test_merkle_chip_poseidon_8_4_2() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U4, U2>();
    }

    // TODO: fix failing test.
    /*
    #[test]
    fn test_merkle_chip_sha256_2() {
        test_merkle_chip_inner::<Sha256Hasher<Fp>, U2, U0, U0>();
    }
    */
}
