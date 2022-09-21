use std::marker::PhantomData;

use fil_halo2_gadgets::{
    boolean::{AssignedBit, Bit},
    AdviceIter,
};
use filecoin_hashers::{Halo2Hasher, HashInstructions, Hasher};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};

use crate::{
    constants::{TreeDArity, TreeDHasher},
    halo2::partition_bit_len,
};

pub struct ApexTreeChip<F>
where
    F: FieldExt,
    TreeDHasher<F>: Hasher<Field = F>,
{
    hasher_chip: <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::Chip,
}

impl<F> ApexTreeChip<F>
where
    F: FieldExt,
    TreeDHasher<F>: Hasher<Field = F>,
{
    pub fn with_subchips(hasher_chip: <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::Chip) -> Self {
        ApexTreeChip { hasher_chip }
    }

    pub fn compute_root(
        &self,
        mut layouter: impl Layouter<F>,
        apex_leafs: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error> {
        let height = apex_leafs.len().trailing_zeros() as usize;
        let mut layer = Vec::<AssignedCell<F, F>>::new();

        for h in 0..height {
            let prev_layer = if h == 0 { apex_leafs } else { &layer };
            layer = prev_layer
                .chunks(2)
                .enumerate()
                .map(|(i, pair)| {
                    self.hasher_chip.hash(
                        layouter.namespace(|| format!("hash height {}, pair {}", h, i)),
                        pair,
                    )
                })
                .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()?;
        }

        assert_eq!(layer.len(), 1);
        Ok(layer[0].clone())
    }
}

#[derive(Clone)]
pub struct ChallengeBitsConfig<F: FieldExt, const SECTOR_NODES: usize> {
    advice: Vec<Column<Advice>>,
    s_challenge_bits: Selector,
    challenge_sans_partition_bit_len: usize,
    _f: PhantomData<F>,
}

pub struct ChallengeBitsChip<F: FieldExt, const SECTOR_NODES: usize> {
    config: ChallengeBitsConfig<F, SECTOR_NODES>,
}

impl<F: FieldExt, const SECTOR_NODES: usize> ChallengeBitsChip<F, SECTOR_NODES> {
    pub fn construct(config: ChallengeBitsConfig<F, SECTOR_NODES>) -> Self {
        ChallengeBitsChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: &[Column<Advice>],
    ) -> ChallengeBitsConfig<F, SECTOR_NODES> {
        for col in advice.iter() {
            meta.enable_equality(*col);
        }

        let challenge_sans_partition_bit_len = {
            let challenge_and_partition_bit_len = SECTOR_NODES.trailing_zeros() as usize;
            let partition_bit_len = partition_bit_len(SECTOR_NODES);
            challenge_and_partition_bit_len - partition_bit_len
        };

        let s_challenge_bits = meta.selector();
        meta.create_gate("challenge into bits", |meta| {
            let s_challenge_bits = meta.query_selector(s_challenge_bits);

            let mut advice_iter = AdviceIter::from(advice.to_vec());

            let challenge = {
                let (offset, col) = advice_iter.next();
                meta.query_advice(col, Rotation(offset as i32))
            };

            let mut expr = {
                let (offset, col) = advice_iter.next();
                meta.query_advice(col, Rotation(offset as i32))
            };
            let mut radix_pow = F::from(2);
            for _ in 0..challenge_sans_partition_bit_len - 1 {
                let (offset, col) = advice_iter.next();
                let bit = meta.query_advice(col, Rotation(offset as i32));
                expr = expr + Expression::Constant(radix_pow) * bit;
                radix_pow = radix_pow.double();
            }

            [s_challenge_bits * (expr - challenge)]
        });

        ChallengeBitsConfig {
            advice: advice.to_vec(),
            s_challenge_bits,
            challenge_sans_partition_bit_len,
            _f: PhantomData,
        }
    }

    pub fn decompose(
        &self,
        mut layouter: impl Layouter<F>,
        pi_col: Column<Instance>,
        pi_row: usize,
    ) -> Result<Vec<AssignedBit<F>>, Error> {
        layouter.assign_region(
            || "decompose challenge",
            |mut region| {
                let offset = 0;
                self.config.s_challenge_bits.enable(&mut region, offset)?;

                let mut advice_iter = AdviceIter::new(offset, self.config.advice.clone());

                // Copy challenge public input.
                let challenge = {
                    let (offset, col) = advice_iter.next();
                    region.assign_advice_from_instance(
                        || "copy challenge public input",
                        pi_col,
                        pi_row,
                        col,
                        offset,
                    )?
                };

                // Assign challenge bits.
                challenge
                    .value()
                    // Convert `Value<F>` into `Value<Vec<bool>>`.
                    .map(|field| {
                        field
                            .to_repr()
                            .as_ref()
                            .iter()
                            .flat_map(|byte| (0..8).map(move |i| byte >> i & 1 == 1))
                            .take(self.config.challenge_sans_partition_bit_len)
                            .collect::<Vec<bool>>()
                    })
                    // Convert `Value<Vec<bool>>` into `Vec<Value<bool>>`.
                    .transpose_vec(self.config.challenge_sans_partition_bit_len)
                    .iter()
                    .enumerate()
                    .map(|(i, bit)| {
                        let (offset, col) = advice_iter.next();
                        region.assign_advice(|| format!("bit_{}", i), col, offset, || bit.map(Bit))
                    })
                    .collect::<Result<Vec<AssignedBit<F>>, Error>>()
            },
        )
    }
}

#[derive(Clone)]
pub struct ChallengeLabelsConfig<F: FieldExt> {
    rho: Column<Advice>,
    label_r_old: Column<Advice>,
    label_d_new: Column<Advice>,
    label_r_new: Column<Advice>,
    s_label_r_new: Selector,
    _f: PhantomData<F>,
}

pub struct ChallengeLabelsChip<F: FieldExt> {
    config: ChallengeLabelsConfig<F>,
}

impl<F: FieldExt> ChallengeLabelsChip<F> {
    pub fn construct(config: ChallengeLabelsConfig<F>) -> Self {
        ChallengeLabelsChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 4],
    ) -> ChallengeLabelsConfig<F> {
        for col in advice.iter() {
            meta.enable_equality(*col);
        }

        let [rho, label_r_old, label_d_new, label_r_new] = advice;

        let s_label_r_new = meta.selector();
        meta.create_gate("label_r_new", |meta| {
            let s_label_r_new = meta.query_selector(s_label_r_new);
            let rho = meta.query_advice(rho, Rotation::cur());
            let label_r_old = meta.query_advice(label_r_old, Rotation::cur());
            let label_d_new = meta.query_advice(label_d_new, Rotation::cur());
            let label_r_new = meta.query_advice(label_r_new, Rotation::cur());
            // `label_r_new = label_r_old + label_d_new * rho`.
            [s_label_r_new * (label_r_old + label_d_new * rho - label_r_new)]
        });

        ChallengeLabelsConfig {
            rho,
            label_r_old,
            label_d_new,
            label_r_new,
            s_label_r_new,
            _f: PhantomData,
        }
    }

    pub fn assign_labels(
        &self,
        mut layouter: impl Layouter<F>,
        label_r_old: Value<F>,
        label_d_new: Value<F>,
        label_r_new: Value<F>,
        pi_col: Column<Instance>,
        pi_row: usize,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        layouter.assign_region(
            || "challenge labels",
            |mut region| {
                let offset = 0;
                self.config.s_label_r_new.enable(&mut region, offset)?;

                region.assign_advice_from_instance(
                    || "copy rho public input",
                    pi_col,
                    pi_row,
                    self.config.rho,
                    offset,
                )?;

                let label_r_old = region.assign_advice(
                    || "label_r_old",
                    self.config.label_r_old,
                    offset,
                    || label_r_old,
                )?;

                let label_d_new = region.assign_advice(
                    || "label_d_new",
                    self.config.label_d_new,
                    offset,
                    || label_d_new,
                )?;

                let label_r_new = region.assign_advice(
                    || "label_r_new",
                    self.config.label_r_new,
                    offset,
                    || label_r_new,
                )?;

                Ok((label_r_old, label_d_new, label_r_new))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryInto;

    use fil_halo2_gadgets::ColumnBuilder;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, pasta::Fp, plonk::Circuit};

    #[derive(Clone)]
    struct ApexTreeConfig<F>
    where
        F: FieldExt,
        TreeDHasher<F>: Hasher<Field = F>,
    {
        sha256_config: <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::Config,
        advice: Vec<Column<Advice>>,
    }

    struct ApexTreeCircuit<F: FieldExt, const N: usize> {
        apex_leafs: [Value<F>; N],
    }

    impl<F, const N: usize> Circuit<F> for ApexTreeCircuit<F, N>
    where
        F: FieldExt,
        TreeDHasher<F>: Hasher<Field = F>,
    {
        type Config = ApexTreeConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            ApexTreeCircuit {
                apex_leafs: [Value::unknown(); N],
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let (advice_eq, advice_neq, fixed_eq, fixed_neq) = ColumnBuilder::new()
                .with_chip::<<TreeDHasher<F> as Halo2Hasher<TreeDArity>>::Chip>()
                .create_columns(meta);

            let sha256_config = <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );

            ApexTreeConfig {
                sha256_config,
                advice: advice_eq,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let ApexTreeConfig {
                sha256_config,
                advice,
            } = config;

            <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::load(&mut layouter, &sha256_config)?;
            let sha256_chip = <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::construct(sha256_config);
            let apex_tree_chip = ApexTreeChip::with_subchips(sha256_chip);

            let apex_leafs = layouter.assign_region(
                || "assign apex_leafs",
                |mut region| {
                    let mut advice_iter = AdviceIter::from(advice.clone());
                    self.apex_leafs
                        .iter()
                        .enumerate()
                        .map(|(i, apex_leaf)| {
                            let (offset, col) = advice_iter.next();
                            region.assign_advice(
                                || format!("apex_leaf_{}", i),
                                col,
                                offset,
                                || *apex_leaf,
                            )
                        })
                        .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()
                },
            )?;

            let _apex_root = apex_tree_chip
                .compute_root(layouter.namespace(|| "compute apex root"), &apex_leafs)?;

            Ok(())
        }
    }

    #[test]
    fn test_apex_tree_8_chip() {
        let circ = ApexTreeCircuit::<Fp, 8> {
            apex_leafs: (0..8)
                .map(|i| Value::known(Fp::from(i)))
                .collect::<Vec<Value<Fp>>>()
                .try_into()
                .unwrap(),
        };
        let prover = MockProver::run(17, &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn test_apex_tree_128_chip() {
        let circ = ApexTreeCircuit::<Fp, 128> {
            apex_leafs: (0..128)
                .map(|i| Value::known(Fp::from(i)))
                .collect::<Vec<Value<Fp>>>()
                .try_into()
                .unwrap(),
        };
        let prover = MockProver::run(20, &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}
