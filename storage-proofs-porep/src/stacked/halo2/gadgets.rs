use std::convert::TryInto;
use std::iter;
use std::marker::PhantomData;

use fil_halo2_gadgets::{sha256, uint32::AssignedU32, AdviceIter, ColumnCount, NumCols};
use filecoin_hashers::{
    poseidon::PoseidonHasher, sha256::Sha256Hasher, Halo2Hasher, HashInstructions, Hasher,
};
use generic_array::typenum::{U11, U2};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};

use crate::stacked::halo2::constants::{
    num_layers, LABEL_PREIMAGE_WORD_LEN, REPEATED_PARENT_LABELS_WORD_LEN,
};

#[derive(Clone)]
pub enum ColumnHasherConfig<F, const SECTOR_NODES: usize>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    Arity2(<PoseidonHasher<F> as Halo2Hasher<U2>>::Config),
    Arity11(<PoseidonHasher<F> as Halo2Hasher<U11>>::Config),
}

pub enum ColumnHasherChip<F, const SECTOR_NODES: usize>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    Arity2(<PoseidonHasher<F> as Halo2Hasher<U2>>::Chip),
    Arity11(<PoseidonHasher<F> as Halo2Hasher<U11>>::Chip),
}

impl<F, const SECTOR_NODES: usize> ColumnCount for ColumnHasherChip<F, SECTOR_NODES>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn num_cols() -> NumCols {
        match num_layers::<SECTOR_NODES>() {
            2 => <PoseidonHasher<F> as Halo2Hasher<U2>>::Chip::num_cols(),
            11 => <PoseidonHasher<F> as Halo2Hasher<U11>>::Chip::num_cols(),
            _ => unreachable!(),
        }
    }
}

impl<F, const SECTOR_NODES: usize> HashInstructions<F> for ColumnHasherChip<F, SECTOR_NODES>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn hash(
        &self,
        layouter: impl Layouter<F>,
        preimage: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error> {
        let num_layers = num_layers::<SECTOR_NODES>();
        assert_eq!(preimage.len(), num_layers);
        match self {
            ColumnHasherChip::Arity2(chip) => {
                assert_eq!(num_layers, 2);
                <<PoseidonHasher<F> as Halo2Hasher<U2>>::Chip as HashInstructions<F>>::hash(
                    chip, layouter, preimage,
                )
            }
            ColumnHasherChip::Arity11(chip) => {
                assert_eq!(num_layers, 11);
                <<PoseidonHasher<F> as Halo2Hasher<U11>>::Chip as HashInstructions<F>>::hash(
                    chip, layouter, preimage,
                )
            }
        }
    }
}

impl<F, const SECTOR_NODES: usize> ColumnHasherChip<F, SECTOR_NODES>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub fn construct(config: ColumnHasherConfig<F, SECTOR_NODES>) -> Self {
        let num_layers = num_layers::<SECTOR_NODES>();
        match config {
            ColumnHasherConfig::Arity2(config) => {
                assert_eq!(num_layers, 2);
                let chip = <PoseidonHasher<F> as Halo2Hasher<U2>>::construct(config);
                ColumnHasherChip::Arity2(chip)
            }
            ColumnHasherConfig::Arity11(config) => {
                assert_eq!(num_layers, 11);
                let chip = <PoseidonHasher<F> as Halo2Hasher<U11>>::construct(config);
                ColumnHasherChip::Arity11(chip)
            }
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_eq: &[Column<Advice>],
        advice_neq: &[Column<Advice>],
        fixed_eq: &[Column<Fixed>],
        fixed_neq: &[Column<Fixed>],
    ) -> ColumnHasherConfig<F, SECTOR_NODES> {
        match num_layers::<SECTOR_NODES>() {
            2 => {
                let config = <PoseidonHasher<F> as Halo2Hasher<U2>>::configure(
                    meta, advice_eq, advice_neq, fixed_eq, fixed_neq,
                );
                ColumnHasherConfig::Arity2(config)
            }
            11 => {
                let config = <PoseidonHasher<F> as Halo2Hasher<U11>>::configure(
                    meta, advice_eq, advice_neq, fixed_eq, fixed_neq,
                );
                ColumnHasherConfig::Arity11(config)
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Clone)]
pub struct LabelingConfig<F, const SECTOR_NODES: usize>
where
    F: FieldExt,
    Sha256Hasher<F>: Hasher<Field = F>,
{
    // The sha256 chip is the same for all arities; use arity `U2` here because `SdrPorepCircuit`
    // will have already instantiated a sha256 chip for arity `U2` to verify TreeD Merkle proofs.
    sha256: <Sha256Hasher<F> as Halo2Hasher<U2>>::Config,
    // Equality enabled advice.
    advice: Vec<Column<Advice>>,
}

pub struct LabelingConstants<F, const SECTOR_NODES: usize>
where
    F: FieldExt,
    Sha256Hasher<F>: Hasher<Field = F>,
{
    zero: AssignedU32<F>,
    layers: Vec<AssignedU32<F>>,
    padding: [AssignedU32<F>; 8],
}

#[derive(Clone)]
pub struct LabelingChip<F, const SECTOR_NODES: usize>
where
    F: FieldExt,
    Sha256Hasher<F>: Hasher<Field = F>,
{
    config: LabelingConfig<F, SECTOR_NODES>,
}

// TODO (jake): do we need to call `constrain_constant` if the witnessed values are
// used exclusively in sha256 preimages?
//
// If we enable equality checks against constants in LabelingChip, we need to
// enable a fixed column to store constants: `meta.enable_constant(fixed_eq)` and to implement
// `ColumnCount` for `LabelingChip` where `self.num_cols().fixed_eq = 1`.

impl<F, const SECTOR_NODES: usize> LabelingChip<F, SECTOR_NODES>
where
    F: FieldExt,
    Sha256Hasher<F>: Hasher<Field = F>,
{
    pub fn construct(config: LabelingConfig<F, SECTOR_NODES>) -> Self {
        LabelingChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        sha256: <Sha256Hasher<F> as Halo2Hasher<U2>>::Config,
        advice: &[Column<Advice>],
        // TODO (jake): do we need to equality constraint against constants?
        // fixed: Column<Fixed>,
    ) -> LabelingConfig<F, SECTOR_NODES> {
        for col in advice.iter() {
            meta.enable_equality(*col);
        }
        // TODO (jake): do we need to equality constraint against constants?
        // meta.enable_constant(fixed);
        LabelingConfig {
            sha256,
            advice: advice.to_vec(),
        }
    }

    #[allow(clippy::unwrap_used)]
    pub fn assign_constants(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<LabelingConstants<F, SECTOR_NODES>, Error> {
        let num_layers = num_layers::<SECTOR_NODES>();
        layouter.assign_region(
            || "assign labeling constants",
            |mut region| {
                let mut advice_iter = AdviceIter::from(self.config.advice.clone());

                let zero = {
                    let (offset, col) = advice_iter.next();
                    AssignedU32::assign(&mut region, || "zero", col, offset, Some(0))?
                    // TODO (jake): do we need to call `.constrain_constant()`?
                    // region.constrain_constant(zero.cell(), F::zero())?;
                };

                let layers = (1..=num_layers)
                    .map(|layer| {
                        let (offset, col) = advice_iter.next();
                        let assigned_layer = AssignedU32::assign(
                            &mut region,
                            || format!("layer {}", layer),
                            col,
                            offset,
                            Some(layer as u32),
                        )?;
                        // region.constrain_constant(assigned_layer.cell(), F::from(layer as u64))?;
                        Ok(assigned_layer)
                    })
                    .collect::<Result<Vec<AssignedU32<F>>, Error>>()?;

                let padding = sha256::get_padding(LABEL_PREIMAGE_WORD_LEN)
                    .iter()
                    .enumerate()
                    .map(|(i, pad_word)| {
                        let (offset, col) = advice_iter.next();
                        let assigned_pad_word = AssignedU32::assign(
                            &mut region,
                            || format!("padding word {}", i),
                            col,
                            offset,
                            Some(*pad_word),
                        )?;
                        /*
                        region.constrain_constant(
                            assigned_pad_word.cell(),
                            F::from(*pad_word as u64),
                        )?;
                        */
                        Ok(assigned_pad_word)
                    })
                    .collect::<Result<Vec<AssignedU32<F>>, Error>>()?
                    .try_into()
                    .unwrap();

                Ok(LabelingConstants {
                    zero,
                    layers,
                    padding,
                })
            },
        )
    }

    pub fn label(
        &self,
        mut layouter: impl Layouter<F>,
        labeling_constants: &LabelingConstants<F, SECTOR_NODES>,
        layer_index: usize,
        replica_id: &[AssignedU32<F>; 8],
        challenge: &AssignedU32<F>,
        repeated_parent_labels: &[AssignedU32<F>],
    ) -> Result<AssignedCell<F, F>, Error> {
        assert_eq!(
            repeated_parent_labels.len(),
            REPEATED_PARENT_LABELS_WORD_LEN
        );

        let zero = &labeling_constants.zero;
        let layer = &labeling_constants.layers[layer_index];
        let padding = &labeling_constants.padding;

        let preimage: Vec<AssignedU32<F>> = replica_id
            .iter()
            .chain(iter::once(layer))
            .chain(iter::once(zero))
            .chain(iter::once(challenge))
            .chain(iter::repeat(zero).take(5))
            .chain(repeated_parent_labels.iter())
            .chain(padding.iter())
            .cloned()
            .collect();

        let sha256_chip =
            <Sha256Hasher<F> as Halo2Hasher<U2>>::construct(self.config.sha256.clone());

        let digest_words =
            sha256_chip.hash_words_nopad(layouter.namespace(|| "sha256"), &preimage)?;

        sha256_chip.pack_digest(layouter.namespace(|| "pack digest"), &digest_words)
    }
}

#[derive(Clone)]
pub struct EncodingConfig<F: FieldExt> {
    // Equality enabled advice.
    label_d: Column<Advice>,
    key: Column<Advice>,
    label_r: Column<Advice>,
    s_encode: Selector,
    _f: PhantomData<F>,
}

#[derive(Clone)]
pub struct EncodingChip<F: FieldExt> {
    config: EncodingConfig<F>,
}

impl<F: FieldExt> EncodingChip<F> {
    pub fn construct(config: EncodingConfig<F>) -> Self {
        EncodingChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
    ) -> EncodingConfig<F> {
        for col in advice.iter() {
            meta.enable_equality(*col);
        }

        let [label_d, key, label_r] = advice;

        let s_encode = meta.selector();
        meta.create_gate("encode", |meta| {
            let s = meta.query_selector(s_encode);
            let label_d = meta.query_advice(label_d, Rotation::cur());
            let key = meta.query_advice(key, Rotation::cur());
            let label_r = meta.query_advice(label_r, Rotation::cur());
            [s * (label_d + key - label_r)]
        });

        EncodingConfig {
            label_d,
            key,
            label_r,
            s_encode,
            _f: PhantomData,
        }
    }

    pub fn encode(
        &self,
        mut layouter: impl Layouter<F>,
        label_d: &AssignedCell<F, F>,
        key: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "encode",
            |mut region| {
                let offset = 0;
                self.config.s_encode.enable(&mut region, offset)?;

                let label_d = label_d.copy_advice(
                    || "copy label_d",
                    &mut region,
                    self.config.label_d,
                    offset,
                )?;

                let key = key.copy_advice(|| "copy key", &mut region, self.config.key, offset)?;

                let label_r = label_d
                    .value()
                    .zip(key.value())
                    .map(|(label_d, key)| *label_d + key);

                region.assign_advice(
                    || "label_r",
                    self.config.label_r,
                    offset,
                    || label_r.ok_or(Error::Synthesis),
                )
            },
        )
    }
}
