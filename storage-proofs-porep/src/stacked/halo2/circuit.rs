#![allow(clippy::type_complexity)]

use std::any::TypeId;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::mem;

use fil_halo2_gadgets::{
    sha256::{Sha256WordsChip, Sha256WordsConfig},
    uint32::{AssignedU32, UInt32Chip, UInt32Config},
    AdviceIter, ColumnBuilder,
};
use filecoin_hashers::{
    poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain, FieldArity, HaloHasher,
    HashInstructions, Hasher, PoseidonArity, POSEIDON_CONSTANTS,
};
use generic_array::typenum::U2;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use storage_proofs_core::{
    drgraph::Graph,
    gadgets::halo2::{
        insert::{InsertChip, InsertConfig},
        por::{self, MerkleChip},
    },
    halo2_proofs::CircuitRows,
    merkle::{MerkleProofTrait, MerkleTreeTrait},
};

use crate::stacked::{
    self as vanilla,
    halo2::{
        constants::{
            challenge_count, num_layers, partition_count, DRG_PARENTS, EXP_PARENTS, LABEL_WORD_LEN,
            REPEATED_PARENT_LABELS_WORD_LEN, SECTOR_NODES_16_KIB, SECTOR_NODES_2_KIB,
            SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_8_KIB,
        },
        gadgets::{
            ColumnHasherChip, ColumnHasherConfig, EncodingChip, EncodingConfig, LabelingChip,
            LabelingConfig,
        },
    },
    LayerChallenges, Proof as VanillaChallengeProof, SetupParams, StackedBucketGraph, Tau,
};

type VanillaPartitionProof<TreeR, G> = Vec<VanillaChallengeProof<TreeR, G>>;

trait CircuitParams<const SECTOR_NODES: usize> {
    const PARTITION_COUNT: usize = partition_count::<SECTOR_NODES>();
    const CHALLENGE_COUNT: usize = challenge_count::<SECTOR_NODES>();
    const NUM_LAYERS: usize = num_layers::<SECTOR_NODES>();
    // Absolute rows of public inputs.
    const REPLICA_ID_ROW: usize = 0;
    const COMM_D_ROW: usize = 1;
    const COMM_R_ROW: usize = 2;
    const FIRST_CHALLENGE_ROW: usize = 3;

    fn challenge_row(challenge_index: usize) -> usize {
        Self::FIRST_CHALLENGE_ROW + challenge_index * (1 + DRG_PARENTS + EXP_PARENTS)
    }

    fn drg_parent_row(challenge_index: usize, drg_parent_index: usize) -> usize {
        Self::challenge_row(challenge_index) + 1 + drg_parent_index
    }

    fn exp_parent_row(challenge_index: usize, exp_parent_index: usize) -> usize {
        Self::challenge_row(challenge_index) + 1 + DRG_PARENTS + exp_parent_index
    }
}

#[derive(Clone)]
pub struct PublicInputs<F, const SECTOR_NODES: usize>
where
    F: FieldExt,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    pub replica_id: Option<F>,
    pub comm_d: Option<F>,
    pub comm_r: Option<F>,
    pub challenges: Vec<Option<u32>>,
    pub parents: Vec<Vec<Option<u32>>>,
}

impl<F, const SECTOR_NODES: usize> PublicInputs<F, SECTOR_NODES>
where
    F: FieldExt,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    pub fn from(
        setup_params: SetupParams,
        vanilla_pub_inputs: vanilla::PublicInputs<
            <PoseidonHasher<F> as Hasher>::Domain,
            <Sha256Hasher<F> as Hasher>::Domain,
        >,
    ) -> Self {
        assert_eq!(
            setup_params.nodes, SECTOR_NODES,
            "setup params contain incorrect sector size"
        );
        assert_eq!(
            setup_params.degree, DRG_PARENTS,
            "setup params contain incorrect base degree"
        );
        assert_eq!(
            setup_params.expansion_degree, EXP_PARENTS,
            "setup params contain incorrect exp degree"
        );

        let SetupParams {
            porep_id,
            api_version,
            ..
        } = setup_params;

        let graph = StackedBucketGraph::<PoseidonHasher<F>>::new_stacked(
            SECTOR_NODES,
            DRG_PARENTS,
            EXP_PARENTS,
            porep_id,
            api_version,
        )
        .expect("graph construction should not fail");

        let vanilla::PublicInputs {
            replica_id,
            seed: challenge_seed,
            tau,
            k,
        } = vanilla_pub_inputs;
        let Tau { comm_d, comm_r } = tau.expect("public inputs missing `tau`");
        let k = k.unwrap_or(0);

        let layer_challenges = LayerChallenges::new(
            num_layers::<SECTOR_NODES>(),
            challenge_count::<SECTOR_NODES>(),
        );

        let (challenges, parents): (Vec<Option<u32>>, Vec<Vec<Option<u32>>>) = layer_challenges
            .derive(SECTOR_NODES, &replica_id, &challenge_seed, k as u8)
            .iter()
            .map(|c| {
                let mut parents = vec![0u32; DRG_PARENTS + EXP_PARENTS];
                graph
                    .parents(*c, &mut parents)
                    .expect("failed to generate parents");
                let challenge = Some(*c as u32);
                let parents = parents.iter().copied().map(Some).collect();
                (challenge, parents)
            })
            .unzip();

        PublicInputs {
            replica_id: Some(replica_id.into()),
            comm_d: Some(comm_d.into()),
            comm_r: Some(comm_r.into()),
            challenges,
            parents,
        }
    }

    #[allow(clippy::unwrap_used)]
    pub fn to_vec(&self) -> Vec<Vec<F>> {
        assert!(
            self.replica_id.is_some()
                && self.comm_d.is_some()
                && self.comm_r.is_some()
                && self.challenges.iter().all(Option::is_some)
                && self
                    .parents
                    .iter()
                    .all(|parents| parents.iter().all(Option::is_some)),
            "all public inputs must contain a value before converting into a vector",
        );

        let num_pub_inputs = 3 + self.challenges.len() * (1 + DRG_PARENTS + EXP_PARENTS);
        let mut pub_inputs = Vec::with_capacity(num_pub_inputs);
        pub_inputs.push(self.replica_id.unwrap());
        pub_inputs.push(self.comm_d.unwrap());
        pub_inputs.push(self.comm_r.unwrap());
        for (c, parents) in self.challenges.iter().zip(self.parents.iter()) {
            pub_inputs.push(F::from(c.unwrap() as u64));
            for parent in parents {
                pub_inputs.push(F::from(parent.unwrap() as u64));
            }
        }

        vec![pub_inputs]
    }
}

#[derive(Clone, Debug)]
pub struct ParentProof<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    column: Vec<Option<F>>,
    path_c: Vec<Vec<Option<F>>>,
    _tree_r: PhantomData<(U, V, W)>,
}

impl<F, U, V, W, const SECTOR_NODES: usize> ParentProof<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    pub fn empty() -> Self {
        ParentProof {
            column: vec![None; num_layers::<SECTOR_NODES>()],
            path_c: por::empty_path::<F, U, V, W, SECTOR_NODES>(),
            _tree_r: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct ChallengeProof<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    leaf_d: Option<F>,
    path_d: Vec<Vec<Option<F>>>,
    path_c: Vec<Vec<Option<F>>>,
    path_r: Vec<Vec<Option<F>>>,
    drg_parent_proofs: [ParentProof<F, U, V, W, SECTOR_NODES>; DRG_PARENTS],
    exp_parent_proofs: [ParentProof<F, U, V, W, SECTOR_NODES>; EXP_PARENTS],
}

impl<F, U, V, W, TreeR, const SECTOR_NODES: usize>
    From<&VanillaChallengeProof<TreeR, Sha256Hasher<F>>>
    for ChallengeProof<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
    TreeR:
        MerkleTreeTrait<Hasher = PoseidonHasher<F>, Arity = U, SubTreeArity = V, TopTreeArity = W>,
{
    #[allow(clippy::unwrap_used)]
    fn from(challenge_proof: &VanillaChallengeProof<TreeR, Sha256Hasher<F>>) -> Self {
        let leaf_d: Option<F> = Some(challenge_proof.comm_d_proofs.leaf().into());

        let path_d: Vec<Vec<Option<F>>> = challenge_proof
            .comm_d_proofs
            .path()
            .iter()
            .map(|(siblings, _)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        let path_c: Vec<Vec<Option<F>>> = challenge_proof
            .replica_column_proofs
            .c_x
            .inclusion_proof
            .path()
            .iter()
            .map(|(siblings, _)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        let path_r: Vec<Vec<Option<F>>> = challenge_proof
            .comm_r_last_proof
            .path()
            .iter()
            .map(|(siblings, _)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        let drg_parent_proofs = challenge_proof
            .replica_column_proofs
            .drg_parents
            .iter()
            .map(|parent_proof| {
                let column = parent_proof
                    .column
                    .rows
                    .iter()
                    .map(|&label| Some(label.into()))
                    .collect();

                let path_c = parent_proof
                    .inclusion_proof
                    .path()
                    .iter()
                    .map(|(siblings, _)| siblings.iter().map(|&s| Some(s.into())).collect())
                    .collect();

                ParentProof {
                    column,
                    path_c,
                    _tree_r: PhantomData,
                }
            })
            .collect::<Vec<ParentProof<F, U, V, W, SECTOR_NODES>>>()
            .try_into()
            .unwrap();

        let exp_parent_proofs = challenge_proof
            .replica_column_proofs
            .exp_parents
            .iter()
            .map(|parent_proof| {
                let column = parent_proof
                    .column
                    .rows
                    .iter()
                    .map(|&label| Some(label.into()))
                    .collect();

                let path_c = parent_proof
                    .inclusion_proof
                    .path()
                    .iter()
                    .map(|(siblings, _)| siblings.iter().map(|&s| Some(s.into())).collect())
                    .collect();

                ParentProof {
                    column,
                    path_c,
                    _tree_r: PhantomData,
                }
            })
            .collect::<Vec<ParentProof<F, U, V, W, SECTOR_NODES>>>()
            .try_into()
            .unwrap();

        ChallengeProof {
            leaf_d,
            path_d,
            path_c,
            path_r,
            drg_parent_proofs,
            exp_parent_proofs,
        }
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> ChallengeProof<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    pub fn empty() -> Self {
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;
        let path_d = vec![vec![None]; challenge_bit_len];
        let path_r = por::empty_path::<F, U, V, W, SECTOR_NODES>();

        ChallengeProof {
            leaf_d: None,
            path_d,
            path_c: path_r.clone(),
            path_r,
            drg_parent_proofs: [
                ParentProof::empty(),
                ParentProof::empty(),
                ParentProof::empty(),
                ParentProof::empty(),
                ParentProof::empty(),
                ParentProof::empty(),
            ],
            exp_parent_proofs: [
                ParentProof::empty(),
                ParentProof::empty(),
                ParentProof::empty(),
                ParentProof::empty(),
                ParentProof::empty(),
                ParentProof::empty(),
                ParentProof::empty(),
                ParentProof::empty(),
            ],
        }
    }
}

#[derive(Clone)]
pub struct PrivateInputs<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    pub comm_c: Option<F>,
    // `root_r` is `comm_r_last`.
    pub root_r: Option<F>,
    pub challenge_proofs: Vec<ChallengeProof<F, U, V, W, SECTOR_NODES>>,
}

impl<F, U, V, W, TreeR, const SECTOR_NODES: usize>
    From<&VanillaPartitionProof<TreeR, Sha256Hasher<F>>> for PrivateInputs<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
    TreeR:
        MerkleTreeTrait<Hasher = PoseidonHasher<F>, Arity = U, SubTreeArity = V, TopTreeArity = W>,
{
    fn from(partition_proof: &VanillaPartitionProof<TreeR, Sha256Hasher<F>>) -> Self {
        PrivateInputs {
            comm_c: Some(partition_proof[0].comm_c().into()),
            root_r: Some(partition_proof[0].comm_r_last().into()),
            challenge_proofs: partition_proof.iter().map(Into::into).collect(),
        }
    }
}

impl<F, U, V, W, TreeR, const SECTOR_NODES: usize>
    From<VanillaPartitionProof<TreeR, Sha256Hasher<F>>> for PrivateInputs<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
    TreeR:
        MerkleTreeTrait<Hasher = PoseidonHasher<F>, Arity = U, SubTreeArity = V, TopTreeArity = W>,
{
    fn from(partition_proof: VanillaPartitionProof<TreeR, Sha256Hasher<F>>) -> Self {
        Self::from(&partition_proof)
    }
}

#[derive(Clone)]
pub struct SdrPorepConfig<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    // Decomposes a challenge into 32 bits.
    uint32: UInt32Config<F>,
    // Converts a field element into eight `u32` words having sha256 bit order.
    sha256_words: Sha256WordsConfig<F>,
    // Computes CommR.
    poseidon_2: <PoseidonHasher<F> as HaloHasher<U2>>::Config,
    // Computes a column digest.
    column_hasher: ColumnHasherConfig<F, SECTOR_NODES>,
    // TreeD Merkle proof.
    tree_d: (
        <Sha256Hasher<F> as HaloHasher<U2>>::Config,
        InsertConfig<F, U2>,
    ),
    // TreeR Merkle proof.
    tree_r: (
        <PoseidonHasher<F> as HaloHasher<U>>::Config,
        InsertConfig<F, U>,
        Option<(
            <PoseidonHasher<F> as HaloHasher<V>>::Config,
            InsertConfig<F, V>,
        )>,
        Option<(
            <PoseidonHasher<F> as HaloHasher<W>>::Config,
            InsertConfig<F, W>,
        )>,
    ),
    // Computes a challenge's layer label.
    labeling: LabelingConfig<F, SECTOR_NODES>,
    // Computes a challenge's replica label.
    encoding: EncodingConfig<F>,
    // Equality enabled advice.
    advice: Vec<Column<Advice>>,
    pi: Column<Instance>,
}

#[derive(Clone)]
pub struct SdrPorepCircuit<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    pub pub_inputs: PublicInputs<F, SECTOR_NODES>,
    pub priv_inputs: PrivateInputs<F, U, V, W, SECTOR_NODES>,
}

impl<F, U, V, W, const SECTOR_NODES: usize> CircuitParams<SECTOR_NODES>
    for SdrPorepCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
}

impl<F, U, V, W, const SECTOR_NODES: usize> Circuit<F> for SdrPorepCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    type Config = SdrPorepConfig<F, U, V, W, SECTOR_NODES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        SdrPorepCircuit {
            pub_inputs: PublicInputs {
                replica_id: None,
                comm_d: None,
                comm_r: None,
                challenges: vec![None; self.pub_inputs.challenges.len()],
                parents: vec![vec![None; DRG_PARENTS + EXP_PARENTS]; self.pub_inputs.parents.len()],
            },
            priv_inputs: PrivateInputs {
                comm_c: None,
                root_r: None,
                challenge_proofs: vec![
                    ChallengeProof::empty();
                    self.priv_inputs.challenge_proofs.len()
                ],
            },
        }
    }

    #[allow(clippy::unwrap_used)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let (advice_eq, advice_neq, fixed_eq, fixed_neq) = ColumnBuilder::new()
            .with_chip::<UInt32Chip<F>>()
            .with_chip::<Sha256WordsChip<F>>()
            .with_chip::<ColumnHasherChip<F, SECTOR_NODES>>()
            .with_chip::<<Sha256Hasher<F> as HaloHasher<U2>>::Chip>()
            // Only use the base arity because it is the largest TreeR arity and requires the
            // greatest number of columns.
            .with_chip::<<PoseidonHasher<F> as HaloHasher<U>>::Chip>()
            .with_chip::<InsertChip<F, U>>()
            .create_columns(meta);

        let uint32 = UInt32Chip::configure(meta, advice_eq[..9].try_into().unwrap());
        let sha256_words = Sha256WordsChip::configure(meta, advice_eq[..9].try_into().unwrap());

        let poseidon_2 = <PoseidonHasher<F> as HaloHasher<U2>>::configure(
            meta,
            &advice_eq,
            &advice_neq,
            &fixed_eq,
            &fixed_neq,
        );

        let column_hasher = match Self::NUM_LAYERS {
            // Reuse arity-2 poseidon hasher if possible.
            2 => ColumnHasherConfig::Arity2(poseidon_2.clone()),
            11 => ColumnHasherChip::configure(meta, &advice_eq, &advice_neq, &fixed_eq, &fixed_neq),
            _ => unreachable!(),
        };

        let sha256 = <Sha256Hasher<F> as HaloHasher<U2>>::configure(
            meta,
            &advice_eq,
            &advice_neq,
            &fixed_eq,
            &fixed_neq,
        );

        let insert_2 = InsertChip::configure(meta, &advice_eq, &advice_neq);

        let tree_d_arity_type = TypeId::of::<U2>();
        let base_arity_type = TypeId::of::<U>();
        let sub_arity_type = TypeId::of::<V>();
        let top_arity_type = TypeId::of::<W>();

        let (poseidon_base, insert_base) = if base_arity_type == tree_d_arity_type {
            // Convert each chip's `U2` type parameter to `U`.
            let poseidon_base = unsafe { mem::transmute(poseidon_2.clone()) };
            let insert_base = unsafe { mem::transmute(insert_2.clone()) };
            (poseidon_base, insert_base)
        } else {
            let poseidon_base = <PoseidonHasher<F> as HaloHasher<U>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let insert_base = InsertChip::<F, U>::configure(meta, &advice_eq, &advice_neq);
            (poseidon_base, insert_base)
        };

        let sub = if V::to_usize() == 0 {
            None
        } else if sub_arity_type == tree_d_arity_type {
            // Convert each chip's `U2` type parameter to `V`.
            let poseidon_sub = unsafe { mem::transmute(poseidon_2.clone()) };
            let insert_sub = unsafe { mem::transmute(insert_2.clone()) };
            Some((poseidon_sub, insert_sub))
        } else if sub_arity_type == base_arity_type {
            // Convert each chip's `U` type parameter to `V`.
            let poseidon_sub = unsafe { mem::transmute(poseidon_base.clone()) };
            let insert_sub = unsafe { mem::transmute(insert_base.clone()) };
            Some((poseidon_sub, insert_sub))
        } else {
            let poseidon_sub = <PoseidonHasher<F> as HaloHasher<V>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let insert_sub = InsertChip::<F, V>::configure(meta, &advice_eq, &advice_neq);
            Some((poseidon_sub, insert_sub))
        };

        let top = if W::to_usize() == 0 {
            None
        } else if top_arity_type == tree_d_arity_type {
            // Convert each chip's `U2` type parameter to `W`.
            let poseidon_top = unsafe { mem::transmute(poseidon_2.clone()) };
            let insert_top = unsafe { mem::transmute(insert_2.clone()) };
            Some((poseidon_top, insert_top))
        } else if top_arity_type == base_arity_type {
            // Convert each chip's `U` type parameter to `W`.
            let poseidon_top = unsafe { mem::transmute(poseidon_base.clone()) };
            let insert_top = unsafe { mem::transmute(insert_base.clone()) };
            Some((poseidon_top, insert_top))
        } else if top_arity_type == sub_arity_type {
            // Convert each chip's `V` type parameter to `W`.
            let (poseidon_sub, insert_sub) = sub.as_ref().unwrap();
            let poseidon_top = unsafe { mem::transmute(poseidon_sub.clone()) };
            let insert_top = unsafe { mem::transmute(insert_sub.clone()) };
            Some((poseidon_top, insert_top))
        } else {
            let poseidon_top = <PoseidonHasher<F> as HaloHasher<W>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let insert_top = InsertChip::<F, W>::configure(meta, &advice_eq, &advice_neq);
            Some((poseidon_top, insert_top))
        };

        let labeling = LabelingChip::configure(meta, sha256.clone(), &advice_eq);
        let encoding = EncodingChip::configure(meta, advice_eq[..3].try_into().unwrap());

        let pi = meta.instance_column();
        meta.enable_equality(pi);

        SdrPorepConfig {
            uint32,
            sha256_words,
            poseidon_2,
            column_hasher,
            tree_d: (sha256, insert_2),
            tree_r: (poseidon_base, insert_base, sub, top),
            labeling,
            encoding,
            advice: advice_eq,
            pi,
        }
    }

    #[allow(clippy::unwrap_used)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let SdrPorepCircuit {
            pub_inputs,
            priv_inputs,
        } = self;

        assert_eq!(pub_inputs.challenges.len(), Self::CHALLENGE_COUNT);
        assert_eq!(pub_inputs.parents.len(), Self::CHALLENGE_COUNT);
        assert!(pub_inputs
            .parents
            .iter()
            .all(|parents| parents.len() == DRG_PARENTS + EXP_PARENTS),);
        assert_eq!(priv_inputs.challenge_proofs.len(), Self::CHALLENGE_COUNT);

        let SdrPorepConfig {
            uint32: uint32_config,
            sha256_words: sha256_words_config,
            poseidon_2: poseidon_2_config,
            column_hasher: column_hasher_config,
            tree_d: (sha256_config, insert_2_config),
            tree_r: (poseidon_base_config, insert_base_config, sub_config, top_config),
            labeling: labeling_config,
            encoding: encoding_config,
            advice,
            pi: pi_col,
        } = config;

        <Sha256Hasher<F> as HaloHasher<U2>>::load(&mut layouter, &sha256_config)?;

        let uint32_chip = UInt32Chip::construct(uint32_config);
        let sha256_words_chip = Sha256WordsChip::construct(sha256_words_config);
        let poseidon_2_chip = <PoseidonHasher<F> as HaloHasher<U2>>::construct(poseidon_2_config);
        let column_hasher_chip = ColumnHasherChip::construct(column_hasher_config);
        let labeling_chip = LabelingChip::construct(labeling_config);
        let encoding_chip = EncodingChip::construct(encoding_config);

        let tree_d_merkle_chip = {
            let sha256_chip = <Sha256Hasher<F> as HaloHasher<U2>>::construct(sha256_config);
            let insert_2_chip = InsertChip::construct(insert_2_config);
            MerkleChip::<Sha256Hasher<F>, U2>::with_subchips(sha256_chip, insert_2_chip, None, None)
        };

        let tree_r_merkle_chip = {
            let poseidon_base_chip =
                <PoseidonHasher<F> as HaloHasher<U>>::construct(poseidon_base_config);
            let insert_base_chip = InsertChip::construct(insert_base_config);
            let sub_chips = sub_config.map(|(poseidon_sub, insert_sub)| {
                (
                    <PoseidonHasher<F> as HaloHasher<V>>::construct(poseidon_sub),
                    InsertChip::construct(insert_sub),
                )
            });
            let top_chips = top_config.map(|(poseidon_top, insert_top)| {
                (
                    <PoseidonHasher<F> as HaloHasher<W>>::construct(poseidon_top),
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

        // Decompose replica-id public input into 32-bit words.
        let replica_id = sha256_words_chip.pi_into_words(
            layouter.namespace(|| "decompose replica-id into sha256 words"),
            pi_col,
            Self::REPLICA_ID_ROW,
        )?;

        // Witness `comm_c`, `root_r`, and each challenge's TreeD leaf.
        let (comm_c, root_r, leafs_d) = layouter.assign_region(
            || "witness comm_c, root_r, and leafs_d",
            |mut region| {
                let mut advice_iter = AdviceIter::from(advice.clone());

                let comm_c = {
                    let (offset, col) = advice_iter.next();
                    region.assign_advice(
                        || "comm_c",
                        col,
                        offset,
                        || priv_inputs.comm_c.ok_or(Error::Synthesis),
                    )?
                };

                let root_r = {
                    let (offset, col) = advice_iter.next();
                    region.assign_advice(
                        || "root_r",
                        col,
                        offset,
                        || priv_inputs.root_r.ok_or(Error::Synthesis),
                    )?
                };

                let leafs_d = priv_inputs
                    .challenge_proofs
                    .iter()
                    .enumerate()
                    .map(|(i, challenge_proof)| {
                        let (offset, col) = advice_iter.next();
                        region.assign_advice(
                            || format!("challenge {} leaf_d", i),
                            col,
                            offset,
                            || challenge_proof.leaf_d.ok_or(Error::Synthesis),
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()?;

                Ok((comm_c, root_r, leafs_d))
            },
        )?;

        // Compute `comm_r = H(comm_c, root_r)` and constrain with public input.
        let comm_r = poseidon_2_chip.hash(
            layouter.namespace(|| "calculate comm_r"),
            &[comm_c.clone(), root_r.clone()],
            POSEIDON_CONSTANTS.get::<FieldArity<F, U2>>().unwrap(),
        )?;
        layouter.constrain_instance(comm_r.cell(), pi_col, Self::COMM_R_ROW)?;

        // Assign constants that can be reused across challenge labelings.
        let labeling_constants = labeling_chip.assign_constants(&mut layouter)?;

        for (i, (challenge, (leaf_d, challenge_proof))) in pub_inputs
            .challenges
            .iter()
            .zip(leafs_d.iter().zip(priv_inputs.challenge_proofs.iter()))
            .enumerate()
        {
            let mut layouter = layouter.namespace(|| format!("challenge {}", i));

            // Assign the challenge as 32 bits and constrain with public input.
            let (challenge, challenge_bits) = uint32_chip.witness_assign_bits(
                layouter.namespace(|| "assign challenge as 32 bits"),
                *challenge,
            )?;
            layouter.constrain_instance(challenge.cell(), pi_col, Self::challenge_row(i))?;

            // Verify the challenge's TreeD merkle proof.
            let comm_d = tree_d_merkle_chip.copy_leaf_compute_root(
                layouter.namespace(|| "calculate comm_d from challenge's merkle proof"),
                &challenge_bits,
                leaf_d,
                &challenge_proof.path_d,
            )?;
            layouter.constrain_instance(comm_d.cell(), pi_col, Self::COMM_D_ROW)?;

            // Assign the challenge's parent columns.
            let (drg_parent_columns, exp_parent_columns) = layouter.assign_region(
                || "assign parent columns",
                |mut region| {
                    let mut advice_iter = AdviceIter::from(advice.to_vec());

                    let drg_parent_columns = challenge_proof
                        .drg_parent_proofs
                        .iter()
                        .enumerate()
                        .map(|(parent_index, parent_proof)| {
                            parent_proof
                                .column
                                .iter()
                                .enumerate()
                                .map(|(layer_index, label)| {
                                    let (offset, col) = advice_iter.next();
                                    region.assign_advice(
                                        || {
                                            format!(
                                                "drg parent {} layer {} label",
                                                parent_index, layer_index,
                                            )
                                        },
                                        col,
                                        offset,
                                        || label.ok_or(Error::Synthesis),
                                    )
                                })
                                .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()
                        })
                        .collect::<Result<Vec<Vec<AssignedCell<F, F>>>, Error>>()?;

                    let exp_parent_columns = challenge_proof
                        .exp_parent_proofs
                        .iter()
                        .enumerate()
                        .map(|(parent_index, parent_proof)| {
                            parent_proof
                                .column
                                .iter()
                                .enumerate()
                                .map(|(layer_index, label)| {
                                    let (offset, col) = advice_iter.next();
                                    region.assign_advice(
                                        || {
                                            format!(
                                                "exp parent {} layer {} label",
                                                parent_index, layer_index,
                                            )
                                        },
                                        col,
                                        offset,
                                        || label.ok_or(Error::Synthesis),
                                    )
                                })
                                .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()
                        })
                        .collect::<Result<Vec<Vec<AssignedCell<F, F>>>, Error>>()?;

                    Ok((drg_parent_columns, exp_parent_columns))
                },
            )?;

            // Verify each parent's TreeC Merkle proof.
            for (parent_index, (parent_column, parent_proof)) in drg_parent_columns
                .iter()
                .zip(challenge_proof.drg_parent_proofs.iter())
                .enumerate()
            {
                let parent_bits = uint32_chip.pi_assign_bits(
                    layouter.namespace(|| format!("assign drg parent {} as 32 bits", parent_index)),
                    pi_col,
                    Self::drg_parent_row(i, parent_index),
                )?;
                // Compute parent's column digest.
                let leaf_c = column_hasher_chip.hash(
                    layouter.namespace(|| format!("drg parent {} column digest", parent_index)),
                    parent_column,
                )?;
                let comm_c_calc = tree_r_merkle_chip.copy_leaf_compute_root(
                    layouter.namespace(|| {
                        format!(
                            "calculate comm_c from drg parent {} merkle proof",
                            parent_index,
                        )
                    }),
                    &parent_bits,
                    &leaf_c,
                    &parent_proof.path_c,
                )?;
                layouter.assign_region(
                    || format!("constrain drg parent {} comm_c", parent_index),
                    |mut region| region.constrain_equal(comm_c.cell(), comm_c_calc.cell()),
                )?;
            }

            for (parent_index, (parent_column, parent_proof)) in exp_parent_columns
                .iter()
                .zip(challenge_proof.exp_parent_proofs.iter())
                .enumerate()
            {
                let parent_bits = uint32_chip.pi_assign_bits(
                    layouter.namespace(|| format!("assign exp parent {} as 32 bits", parent_index)),
                    pi_col,
                    Self::exp_parent_row(i, parent_index),
                )?;
                let leaf_c = column_hasher_chip.hash(
                    layouter.namespace(|| format!("exp parent {} column digest", parent_index)),
                    parent_column,
                )?;
                let comm_c_calc = tree_r_merkle_chip.copy_leaf_compute_root(
                    layouter.namespace(|| {
                        format!(
                            "calculate comm_c from exp parent {} merkle proof",
                            parent_index,
                        )
                    }),
                    &parent_bits,
                    &leaf_c,
                    &parent_proof.path_c,
                )?;
                layouter.assign_region(
                    || format!("constrain exp parent {} comm_c", parent_index),
                    |mut region| region.constrain_equal(comm_c.cell(), comm_c_calc.cell()),
                )?;
            }

            let mut challenge_column = Vec::<AssignedCell<F, F>>::with_capacity(Self::NUM_LAYERS);

            // Compute the challenge's label in each layer.
            for layer_index in 0..Self::NUM_LAYERS {
                let mut parent_labels: Vec<AssignedU32<F>> = if layer_index == 0 {
                    Vec::with_capacity(DRG_PARENTS * LABEL_WORD_LEN)
                } else {
                    Vec::with_capacity((DRG_PARENTS + EXP_PARENTS) * LABEL_WORD_LEN)
                };

                for (parent_index, parent_label) in drg_parent_columns
                    .iter()
                    .map(|parent_column| parent_column[layer_index].clone())
                    .enumerate()
                {
                    let parent_label = sha256_words_chip.into_words(
                        layouter.namespace(|| {
                            format!(
                                "drg parent {} layer {} label into sha256 words",
                                parent_index, layer_index,
                            )
                        }),
                        parent_label,
                    )?;
                    parent_labels.extend(parent_label);
                }

                if layer_index > 0 {
                    for (parent_index, parent_label) in exp_parent_columns
                        .iter()
                        // Expander parents are in the preceding layer.
                        .map(|parent_column| parent_column[layer_index - 1].clone())
                        .enumerate()
                    {
                        let parent_label = sha256_words_chip.into_words(
                            layouter.namespace(|| {
                                format!(
                                    "exp parent {} layer {} label into sha256 words",
                                    parent_index, layer_index,
                                )
                            }),
                            parent_label,
                        )?;
                        parent_labels.extend(parent_label);
                    }
                }

                let repeated_parent_labels: Vec<AssignedU32<F>> = parent_labels
                    .iter()
                    .cloned()
                    .cycle()
                    .take(REPEATED_PARENT_LABELS_WORD_LEN)
                    .collect();

                // Compute challenge's layer label.
                let challenge_label = labeling_chip.label(
                    layouter.namespace(|| {
                        format!("calculate challenge's layer {} label", layer_index,)
                    }),
                    &labeling_constants,
                    layer_index,
                    &replica_id,
                    &challenge,
                    &repeated_parent_labels,
                )?;
                challenge_column.push(challenge_label);
            }

            // Compute the challenge's column digest.
            let leaf_c = column_hasher_chip.hash(
                layouter.namespace(|| "challenge's column digest"),
                &challenge_column,
            )?;

            // Verify the challenge's TreeC Merkle proof.
            let comm_c_calc = tree_r_merkle_chip.copy_leaf_compute_root(
                layouter.namespace(|| "calculate comm_c from challenge's merkle proof"),
                &challenge_bits,
                &leaf_c,
                &challenge_proof.path_c,
            )?;
            layouter.assign_region(
                || "constrain challenge's comm_c",
                |mut region| region.constrain_equal(comm_c.cell(), comm_c_calc.cell()),
            )?;

            // Compute the challenge's encoding `leaf_r = leaf_d + key`, where the encoding key is
            // the challenge's last layer label.
            let leaf_r = encoding_chip.encode(
                layouter.namespace(|| "encode challenge"),
                leaf_d,
                &challenge_column[Self::NUM_LAYERS - 1],
            )?;

            // Verify the challenge's TreeR Merkle proof.
            let root_r_calc = tree_r_merkle_chip.copy_leaf_compute_root(
                layouter.namespace(|| "calculate comm_r from challenge's merkle proof"),
                &challenge_bits,
                &leaf_r,
                &challenge_proof.path_r,
            )?;
            layouter.assign_region(
                || "constrain challenge's root_r",
                |mut region| region.constrain_equal(root_r_calc.cell(), root_r.cell()),
            )?;
        }

        Ok(())
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> CircuitRows
    for SdrPorepCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    fn k(&self) -> u32 {
        match SECTOR_NODES {
            SECTOR_NODES_2_KIB => 18,
            SECTOR_NODES_4_KIB => 18,
            SECTOR_NODES_8_KIB => 18,
            SECTOR_NODES_16_KIB => 18,
            SECTOR_NODES_32_KIB => 18,
            // TODO (jake): add more sector sizes
            _ => unimplemented!(),
        }
    }
}
