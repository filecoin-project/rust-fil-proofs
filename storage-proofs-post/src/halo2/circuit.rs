use std::any::TypeId;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::mem;

use fil_halo2_gadgets::{
    uint32::{UInt32Chip, UInt32Config},
    ColumnBuilder,
};
use filecoin_hashers::{poseidon::PoseidonHasher, Halo2Hasher, Hasher, PoseidonArity};
use generic_array::typenum::U2;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use storage_proofs_core::{
    halo2::{
        gadgets::{
            insert::{InsertChip, InsertConfig},
            por::{self, MerkleChip},
        },
        CircuitRows,
    },
    merkle::MerkleProofTrait,
};

use crate::{
    fallback as vanilla,
    halo2::{WindowPostCircuit, WinningPostCircuit},
};

// The subset of a PoSt circuit's private inputs corresponding to a single challenged sector.
#[derive(Clone)]
pub struct SectorProof<F, U, V, W, const SECTOR_NODES: usize, const SECTOR_CHALLENGES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub comm_c: Value<F>,
    pub root_r: Value<F>,
    pub leafs_r: [Value<F>; SECTOR_CHALLENGES],
    pub paths_r: [Vec<Vec<Value<F>>>; SECTOR_CHALLENGES],
    pub _tree_r: PhantomData<(U, V, W)>,
}

impl<F, P, const SECTOR_NODES: usize, const SECTOR_CHALLENGES: usize> From<&vanilla::SectorProof<P>>
    for SectorProof<F, P::Arity, P::SubTreeArity, P::TopTreeArity, SECTOR_NODES, SECTOR_CHALLENGES>
where
    F: FieldExt,
    P: MerkleProofTrait<Hasher = PoseidonHasher<F>>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    #[allow(clippy::unwrap_used)]
    fn from(vanilla_proof: &vanilla::SectorProof<P>) -> Self {
        assert_eq!(vanilla_proof.inclusion_proofs.len(), SECTOR_CHALLENGES);

        let mut leafs_r = Vec::with_capacity(SECTOR_CHALLENGES);
        let mut paths_r = Vec::with_capacity(SECTOR_CHALLENGES);

        for merkle_proof in vanilla_proof.inclusion_proofs.iter() {
            let leaf_r: Value<F> = Value::known(merkle_proof.leaf().into());
            let path_r: Vec<Vec<Value<F>>> = merkle_proof
                .path()
                .iter()
                .map(|(siblings, _)| siblings.iter().map(|&sib| Value::known(sib.into())).collect())
                .collect();
            leafs_r.push(leaf_r);
            paths_r.push(path_r);
        }

        SectorProof {
            comm_c: Value::known(vanilla_proof.comm_c.into()),
            root_r: Value::known(vanilla_proof.comm_r_last.into()),
            leafs_r: leafs_r.try_into().unwrap(),
            paths_r: paths_r.try_into().unwrap(),
            _tree_r: PhantomData,
        }
    }
}

impl<F, P, const SECTOR_NODES: usize, const SECTOR_CHALLENGES: usize> From<vanilla::SectorProof<P>>
    for SectorProof<F, P::Arity, P::SubTreeArity, P::TopTreeArity, SECTOR_NODES, SECTOR_CHALLENGES>
where
    F: FieldExt,
    P: MerkleProofTrait<Hasher = PoseidonHasher<F>>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn from(vanilla_proof: vanilla::SectorProof<P>) -> Self {
        Self::from(&vanilla_proof)
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize, const SECTOR_CHALLENGES: usize>
    SectorProof<F, U, V, W, SECTOR_NODES, SECTOR_CHALLENGES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    #[allow(clippy::unwrap_used)]
    pub fn empty() -> Self {
        SectorProof {
            comm_c: Value::unknown(),
            root_r: Value::unknown(),
            leafs_r: [Value::unknown(); SECTOR_CHALLENGES],
            paths_r: vec![por::empty_path::<F, U, V, W, SECTOR_NODES>(); SECTOR_CHALLENGES]
                .try_into()
                .unwrap(),
            _tree_r: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct PostConfig<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    // Decomposes each Merkle challenge public input into 32 bits.
    pub uint32: UInt32Config<F>,
    // Computes `comm_r`.
    pub poseidon_2: <PoseidonHasher<F> as Halo2Hasher<U2>>::Config,
    // Computes TreeR root from each challenge's Merkle proof.
    #[allow(clippy::type_complexity)]
    pub tree_r: (
        <PoseidonHasher<F> as Halo2Hasher<U>>::Config,
        InsertConfig<F, U>,
        Option<(
            <PoseidonHasher<F> as Halo2Hasher<V>>::Config,
            InsertConfig<F, V>,
        )>,
        Option<(
            <PoseidonHasher<F> as Halo2Hasher<W>>::Config,
            InsertConfig<F, W>,
        )>,
    ),
    // Equality enabled columns.
    pub advice: [Column<Advice>; 2],
    pub pi: Column<Instance>,
}

impl<F, U, V, W, const SECTOR_NODES: usize> PostConfig<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    #[allow(clippy::unwrap_used)]
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let (advice_eq, advice_neq, fixed_eq, fixed_neq) = ColumnBuilder::new()
            .with_chip::<UInt32Chip<F>>()
            .with_chip::<<PoseidonHasher<F> as Halo2Hasher<U2>>::Chip>()
            .with_chip::<<PoseidonHasher<F> as Halo2Hasher<U>>::Chip>()
            .with_chip::<InsertChip<F, U>>()
            .create_columns(meta);

        let uint32 = UInt32Chip::configure(meta, advice_eq[..9].try_into().unwrap());

        let poseidon_2 = <PoseidonHasher<F> as Halo2Hasher<U2>>::configure(
            meta,
            &advice_eq,
            &advice_neq,
            &fixed_eq,
            &fixed_neq,
        );

        let binary_arity_type = TypeId::of::<U2>();
        let base_arity_type = TypeId::of::<U>();
        let sub_arity_type = TypeId::of::<V>();
        let top_arity_type = TypeId::of::<W>();

        let sub_arity = V::to_usize();
        let top_arity = W::to_usize();

        let poseidon_base = if base_arity_type == binary_arity_type {
            unsafe { mem::transmute(poseidon_2.clone()) }
        } else {
            <PoseidonHasher<F> as Halo2Hasher<U>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            )
        };

        let insert_base = InsertChip::<F, U>::configure(meta, &advice_eq, &advice_neq);

        let poseidon_sub = if sub_arity == 0 {
            None
        } else if sub_arity_type == binary_arity_type {
            unsafe { Some(mem::transmute(poseidon_2.clone())) }
        } else if sub_arity_type == base_arity_type {
            unsafe { Some(mem::transmute(poseidon_base.clone())) }
        } else {
            Some(<PoseidonHasher<F> as Halo2Hasher<V>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            ))
        };

        let insert_sub = if sub_arity == 0 {
            None
        } else if sub_arity_type == base_arity_type {
            unsafe { Some(mem::transmute(insert_base.clone())) }
        } else {
            Some(InsertChip::<F, V>::configure(meta, &advice_eq, &advice_neq))
        };

        let poseidon_top = if top_arity == 0 {
            None
        } else if top_arity_type == binary_arity_type {
            unsafe { Some(mem::transmute(poseidon_2.clone())) }
        } else if top_arity_type == base_arity_type {
            unsafe { Some(mem::transmute(poseidon_base.clone())) }
        } else if top_arity_type == sub_arity_type {
            unsafe { Some(mem::transmute(poseidon_sub.clone())) }
        } else {
            Some(<PoseidonHasher<F> as Halo2Hasher<W>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            ))
        };

        let insert_top = if top_arity == 0 {
            None
        } else if top_arity_type == base_arity_type {
            unsafe { Some(mem::transmute(insert_base.clone())) }
        } else if top_arity_type == sub_arity_type {
            unsafe { Some(mem::transmute(insert_sub.clone())) }
        } else {
            Some(InsertChip::<F, W>::configure(meta, &advice_eq, &advice_neq))
        };

        let pi = meta.instance_column();
        meta.enable_equality(pi);

        PostConfig {
            uint32,
            poseidon_2,
            tree_r: (
                poseidon_base,
                insert_base,
                poseidon_sub.zip(insert_sub),
                poseidon_top.zip(insert_top),
            ),
            advice: [advice_eq[0], advice_eq[1]],
            pi,
        }
    }

    pub fn construct_chips(
        self,
    ) -> (
        UInt32Chip<F>,
        <PoseidonHasher<F> as Halo2Hasher<U2>>::Chip,
        MerkleChip<PoseidonHasher<F>, U, V, W>,
    ) {
        let PostConfig {
            uint32: uint32_config,
            poseidon_2: poseidon_2_config,
            tree_r: (poseidon_base_config, insert_base_config, sub_config, top_config),
            ..
        } = self;

        let uint32_chip = UInt32Chip::construct(uint32_config);

        let poseidon_2_chip = <PoseidonHasher<F> as Halo2Hasher<U2>>::construct(poseidon_2_config);

        let tree_r_merkle_chip = {
            let poseidon_base_chip =
                <PoseidonHasher<F> as Halo2Hasher<U>>::construct(poseidon_base_config);
            let insert_base_chip = InsertChip::construct(insert_base_config);
            let sub_chips = sub_config.map(|(poseidon_sub, insert_sub)| {
                (
                    <PoseidonHasher<F> as Halo2Hasher<V>>::construct(poseidon_sub),
                    InsertChip::construct(insert_sub),
                )
            });
            let top_chips = top_config.map(|(poseidon_top, insert_top)| {
                (
                    <PoseidonHasher<F> as Halo2Hasher<W>>::construct(poseidon_top),
                    InsertChip::construct(insert_top),
                )
            });
            MerkleChip::<PoseidonHasher<F>, U, V, W>::with_subchips(
                poseidon_base_chip,
                insert_base_chip,
                sub_chips,
                top_chips,
            )
        };

        (uint32_chip, poseidon_2_chip, tree_r_merkle_chip)
    }
}

#[derive(Clone)]
pub enum PostCircuit<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    Winning(WinningPostCircuit<F, U, V, W, SECTOR_NODES>),
    Window(WindowPostCircuit<F, U, V, W, SECTOR_NODES>),
}

impl<F, U, V, W, const SECTOR_NODES: usize> From<WinningPostCircuit<F, U, V, W, SECTOR_NODES>>
    for PostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn from(circ: WinningPostCircuit<F, U, V, W, SECTOR_NODES>) -> Self {
        PostCircuit::Winning(circ)
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> From<WindowPostCircuit<F, U, V, W, SECTOR_NODES>>
    for PostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn from(circ: WindowPostCircuit<F, U, V, W, SECTOR_NODES>) -> Self {
        PostCircuit::Window(circ)
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> Circuit<F> for PostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    type Config = PostConfig<F, U, V, W, SECTOR_NODES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        if self.is_winning() {
            WinningPostCircuit::blank_circuit().into()
        } else {
            WindowPostCircuit::blank_circuit().into()
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        PostConfig::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        match self {
            PostCircuit::Winning(circ) => circ.synthesize(config, layouter),
            PostCircuit::Window(circ) => circ.synthesize(config, layouter),
        }
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> CircuitRows for PostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn k(&self) -> u32 {
        match self {
            PostCircuit::Winning(circ) => circ.k(),
            PostCircuit::Window(circ) => circ.k(),
        }
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> PostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn is_winning(&self) -> bool {
        matches!(self, PostCircuit::Winning(_))
    }
}
