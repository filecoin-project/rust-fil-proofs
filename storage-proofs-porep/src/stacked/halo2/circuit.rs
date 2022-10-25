#![allow(clippy::type_complexity)]

use std::convert::TryInto;
use std::marker::PhantomData;
use std::ops::Range;

use fil_halo2_gadgets::{
    sha256::{Sha256WordsChip, Sha256WordsConfig},
    uint32::AssignedU32,
    AdviceIter, ColumnBuilder,
};
use filecoin_hashers::{
    get_poseidon_constants, poseidon::PoseidonHasher, sha256::Sha256Hasher, Halo2Hasher,
    HashInstructions, Hasher, PoseidonArity, HALO2_STRENGTH_IS_STD,
};
use generic_array::typenum::U2;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use storage_proofs_core::{
    drgraph::Graph,
    halo2::{
        gadgets::{
            insert::{InsertChip, InsertConfig},
            por::{self, MerkleChip},
        },
        CircuitRows,
    },
    merkle::{MerkleProofTrait, MerkleTreeTrait},
    util::NODE_SIZE,
    SECTOR_NODES_16_KIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB,
    SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB, SECTOR_NODES_64_GIB, SECTOR_NODES_8_KIB,
};

use crate::stacked::{
    self as vanilla,
    halo2::{
        constants::{
            challenge_count, num_layers, DRG_PARENTS, EXP_PARENTS, GROTH16_PARTITIONING,
            LABEL_WORD_LEN, REPEATED_PARENT_LABELS_WORD_LEN,
        },
        gadgets::{
            ColumnHasherChip, ColumnHasherConfig, EncodingChip, EncodingConfig, LabelingChip,
            LabelingConfig,
        },
    },
    LayerChallenges, Proof as VanillaChallengeProof, SetupParams, StackedBucketGraph, Tau,
};

type VanillaPartitionProof<TreeR, G> = Vec<VanillaChallengeProof<TreeR, G>>;

pub const SDR_POREP_CIRCUIT_ID: &str = "sdr";

// Public input rows.
const REPLICA_ID_ROW: usize = 0;
const COMM_D_ROW: usize = 1;
const COMM_R_ROW: usize = 2;
const FIRST_CHALLENGE_ROW: usize = 3;
const MERKLE_CHALLENGES_PER_POREP_CHALLENGE: usize = 1 + DRG_PARENTS + EXP_PARENTS;

#[inline]
const fn challenge_row(challenge_index: usize, challenge_bits: usize) -> usize {
    // Add one public input for the porep challenge as a `u32`.
    FIRST_CHALLENGE_ROW
        + challenge_index * (MERKLE_CHALLENGES_PER_POREP_CHALLENGE * challenge_bits + 1)
}

#[inline]
const fn challenge_bits_rows(challenge_index: usize, challenge_bits: usize) -> Range<usize> {
    let start = challenge_row(challenge_index, challenge_bits) + 1;
    start..start + challenge_bits
}

#[inline]
const fn drg_parent_bits_rows(
    challenge_index: usize,
    drg_parent_index: usize,
    challenge_bits: usize,
) -> Range<usize> {
    let first_drg_parent_row = challenge_bits_rows(challenge_index, challenge_bits).end;
    let start = first_drg_parent_row + drg_parent_index * challenge_bits;
    start..start + challenge_bits
}

#[inline]
const fn exp_parent_bits_rows(
    challenge_index: usize,
    exp_parent_index: usize,
    challenge_bits: usize,
) -> Range<usize> {
    let last_drg_parent_index = DRG_PARENTS - 1;
    let first_exp_parent_row =
        drg_parent_bits_rows(challenge_index, last_drg_parent_index, challenge_bits).end;
    let start = first_exp_parent_row + exp_parent_index * challenge_bits;
    start..start + challenge_bits
}

#[derive(Clone)]
pub struct PublicInputs<F, const SECTOR_NODES: usize>
where
    F: FieldExt,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub replica_id: Option<F>,
    pub comm_d: Option<F>,
    pub comm_r: Option<F>,
    pub challenges: Vec<Option<u32>>,
    pub challenges_bits: Vec<Vec<Option<bool>>>,
    pub parents_bits: Vec<Vec<Vec<Option<bool>>>>,
}

impl<F, const SECTOR_NODES: usize> PublicInputs<F, SECTOR_NODES>
where
    F: FieldExt,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
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

        let layer_challenges =
            LayerChallenges::new(num_layers(SECTOR_NODES), challenge_count(SECTOR_NODES));

        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;
        let challenges =
            layer_challenges.derive(SECTOR_NODES, &replica_id, &challenge_seed, k as u8);

        let challenges_bits = challenges
            .iter()
            .map(|c| {
                (0..challenge_bit_len)
                    .map(|i| Some(c >> i & 1 == 1))
                    .collect()
            })
            .collect();

        let parents_bits = challenges
            .iter()
            .map(|c| {
                let mut parents = vec![0u32; DRG_PARENTS + EXP_PARENTS];
                graph
                    .parents(*c, &mut parents)
                    .expect("failed to generate parents");
                parents
                    .iter()
                    .map(|p| {
                        (0..challenge_bit_len)
                            .map(|i| Some(p >> i & 1 == 1))
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let challenges = challenges.iter().map(|c| Some(*c as u32)).collect();

        PublicInputs {
            replica_id: Some(replica_id.into()),
            comm_d: Some(comm_d.into()),
            comm_r: Some(comm_r.into()),
            challenges,
            challenges_bits,
            parents_bits,
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
                    .challenges_bits
                    .iter()
                    .all(|bits| bits.iter().all(Option::is_some))
                && self.parents_bits.iter().all(|parents_bits| {
                    parents_bits
                        .iter()
                        .all(|bits| bits.iter().all(Option::is_some))
                }),
            "all public inputs must contain a value before converting into a vector",
        );

        let mut pub_inputs = vec![
            self.replica_id.unwrap(),
            self.comm_d.unwrap(),
            self.comm_r.unwrap(),
        ];

        for ((challenge, challenge_bits), parents_bits) in self
            .challenges
            .iter()
            .zip(self.challenges_bits.iter())
            .zip(self.parents_bits.iter())
        {
            pub_inputs.push(F::from(challenge.unwrap() as u64));
            for bit in challenge_bits {
                if bit.unwrap() {
                    pub_inputs.push(F::one());
                } else {
                    pub_inputs.push(F::zero());
                }
            }
            for parent_bits in parents_bits {
                for bit in parent_bits {
                    if bit.unwrap() {
                        pub_inputs.push(F::one());
                    } else {
                        pub_inputs.push(F::zero());
                    }
                }
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
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub column: Vec<Value<F>>,
    pub path_c: Vec<Vec<Value<F>>>,
    pub _tree_r: PhantomData<(U, V, W)>,
}

impl<F, U, V, W, const SECTOR_NODES: usize> ParentProof<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub fn empty() -> Self {
        ParentProof {
            column: vec![Value::unknown(); num_layers(SECTOR_NODES)],
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
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub leaf_d: Value<F>,
    pub path_d: Vec<Vec<Value<F>>>,
    pub path_c: Vec<Vec<Value<F>>>,
    pub path_r: Vec<Vec<Value<F>>>,
    pub drg_parent_proofs: [ParentProof<F, U, V, W, SECTOR_NODES>; DRG_PARENTS],
    pub exp_parent_proofs: [ParentProof<F, U, V, W, SECTOR_NODES>; EXP_PARENTS],
}

impl<F, TreeR, const SECTOR_NODES: usize> From<&VanillaChallengeProof<TreeR, Sha256Hasher<F>>>
    for ChallengeProof<F, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity, SECTOR_NODES>
where
    F: FieldExt,
    TreeR: MerkleTreeTrait<Field = F, Hasher = PoseidonHasher<F>>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    #[allow(clippy::unwrap_used)]
    fn from(challenge_proof: &VanillaChallengeProof<TreeR, Sha256Hasher<F>>) -> Self {
        let leaf_d = Value::known(challenge_proof.comm_d_proofs.leaf().into());

        let path_d: Vec<Vec<Value<F>>> = challenge_proof
            .comm_d_proofs
            .path()
            .iter()
            .map(|(siblings, _)| siblings.iter().map(|&s| Value::known(s.into())).collect())
            .collect();

        let path_c: Vec<Vec<Value<F>>> = challenge_proof
            .replica_column_proofs
            .c_x
            .inclusion_proof
            .path()
            .iter()
            .map(|(siblings, _)| siblings.iter().map(|&s| Value::known(s.into())).collect())
            .collect();

        let path_r: Vec<Vec<Value<F>>> = challenge_proof
            .comm_r_last_proof
            .path()
            .iter()
            .map(|(siblings, _)| siblings.iter().map(|&s| Value::known(s.into())).collect())
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
                    .map(|&label| Value::known(label.into()))
                    .collect();

                let path_c = parent_proof
                    .inclusion_proof
                    .path()
                    .iter()
                    .map(|(siblings, _)| siblings.iter().map(|&s| Value::known(s.into())).collect())
                    .collect();

                ParentProof {
                    column,
                    path_c,
                    _tree_r: PhantomData,
                }
            })
            .collect::<Vec<
                ParentProof<
                    F,
                    TreeR::Arity,
                    TreeR::SubTreeArity,
                    TreeR::TopTreeArity,
                    SECTOR_NODES,
                >,
            >>()
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
                    .map(|&label| Value::known(label.into()))
                    .collect();

                let path_c = parent_proof
                    .inclusion_proof
                    .path()
                    .iter()
                    .map(|(siblings, _)| siblings.iter().map(|&s| Value::known(s.into())).collect())
                    .collect();

                ParentProof {
                    column,
                    path_c,
                    _tree_r: PhantomData,
                }
            })
            .collect::<Vec<
                ParentProof<
                    F,
                    TreeR::Arity,
                    TreeR::SubTreeArity,
                    TreeR::TopTreeArity,
                    SECTOR_NODES,
                >,
            >>()
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
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub fn empty() -> Self {
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;
        let path_d = vec![vec![Value::unknown()]; challenge_bit_len];
        let path_r = por::empty_path::<F, U, V, W, SECTOR_NODES>();

        ChallengeProof {
            leaf_d: Value::unknown(),
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
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub comm_c: Value<F>,
    // `root_r` is `comm_r_last`.
    pub root_r: Value<F>,
    pub challenge_proofs: Vec<ChallengeProof<F, U, V, W, SECTOR_NODES>>,
}

impl<F, TreeR, const SECTOR_NODES: usize> From<&VanillaPartitionProof<TreeR, Sha256Hasher<F>>>
    for PrivateInputs<F, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity, SECTOR_NODES>
where
    F: FieldExt,
    TreeR: MerkleTreeTrait<Field = F, Hasher = PoseidonHasher<F>>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn from(partition_proof: &VanillaPartitionProof<TreeR, Sha256Hasher<F>>) -> Self {
        PrivateInputs {
            comm_c: Value::known(partition_proof[0].comm_c().into()),
            root_r: Value::known(partition_proof[0].comm_r_last().into()),
            challenge_proofs: partition_proof.iter().map(Into::into).collect(),
        }
    }
}

impl<F, TreeR, const SECTOR_NODES: usize> From<VanillaPartitionProof<TreeR, Sha256Hasher<F>>>
    for PrivateInputs<F, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity, SECTOR_NODES>
where
    F: FieldExt,
    TreeR: MerkleTreeTrait<Field = F, Hasher = PoseidonHasher<F>>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
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
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    // Converts a field element into eight `u32` words having sha256 bit order.
    sha256_words: Sha256WordsConfig<F>,
    // Computes CommR.
    poseidon_2: <PoseidonHasher<F> as Halo2Hasher<U2>>::Config,
    // Computes a column digest.
    column_hasher: ColumnHasherConfig<F, SECTOR_NODES>,
    // TreeD Merkle proof.
    tree_d: (
        <Sha256Hasher<F> as Halo2Hasher<U2>>::Config,
        InsertConfig<F, U2>,
    ),
    // TreeR Merkle proof.
    tree_r: (
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
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub id: String,
    pub pub_inputs: PublicInputs<F, SECTOR_NODES>,
    pub priv_inputs: PrivateInputs<F, U, V, W, SECTOR_NODES>,
}

impl<F, U, V, W, const SECTOR_NODES: usize> Circuit<F> for SdrPorepCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    type Config = SdrPorepConfig<F, U, V, W, SECTOR_NODES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let challenge_count = challenge_count(SECTOR_NODES);
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;

        assert_eq!(self.pub_inputs.challenges.len(), challenge_count);
        assert_eq!(self.pub_inputs.challenges_bits.len(), challenge_count);
        assert!(self
            .pub_inputs
            .challenges_bits
            .iter()
            .all(|bits| bits.len() == challenge_bit_len));
        assert_eq!(self.pub_inputs.parents_bits.len(), challenge_count);
        assert!(self
            .pub_inputs
            .parents_bits
            .iter()
            .all(|parents| parents.len() == DRG_PARENTS + EXP_PARENTS));
        assert!(self
            .pub_inputs
            .parents_bits
            .iter()
            .all(|parents| parents.iter().all(|bits| bits.len() == challenge_bit_len)));
        assert_eq!(self.priv_inputs.challenge_proofs.len(), challenge_count);

        Self::blank_circuit()
    }

    #[allow(clippy::unwrap_used)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let (advice_eq, advice_neq, fixed_eq, fixed_neq) = ColumnBuilder::new()
            .with_chip::<Sha256WordsChip<F>>()
            .with_chip::<<Sha256Hasher<F> as Halo2Hasher<U2>>::Chip>()
            .with_chip::<<PoseidonHasher<F> as Halo2Hasher<U2>>::Chip>()
            .with_chip::<<PoseidonHasher<F> as Halo2Hasher<U>>::Chip>()
            .with_chip::<<PoseidonHasher<F> as Halo2Hasher<V>>::Chip>()
            .with_chip::<<PoseidonHasher<F> as Halo2Hasher<W>>::Chip>()
            // Only need the base arity here because it is guaranteed to be the largest arity, thus
            // all other arity insert chips will use a subset of the base arity's columns.
            .with_chip::<InsertChip<F, U>>()
            .with_chip::<ColumnHasherChip<F, SECTOR_NODES>>()
            .create_columns(meta);

        let sha256_words = Sha256WordsChip::configure(meta, advice_eq[..9].try_into().unwrap());

        let poseidon_2 = <PoseidonHasher<F> as Halo2Hasher<U2>>::configure(
            meta,
            &advice_eq,
            &advice_neq,
            &fixed_eq,
            &fixed_neq,
        );

        let column_hasher = match num_layers(SECTOR_NODES) {
            // Reuse arity-2 poseidon hasher if possible.
            2 => ColumnHasherConfig::Arity2(poseidon_2.clone()),
            11 => ColumnHasherChip::configure(meta, &advice_eq, &advice_neq, &fixed_eq, &fixed_neq),
            _ => unreachable!(),
        };

        let sha256 = <Sha256Hasher<F> as Halo2Hasher<U2>>::configure(
            meta,
            &advice_eq,
            &advice_neq,
            &fixed_eq,
            &fixed_neq,
        );

        let insert_2 = InsertChip::configure(meta, &advice_eq, &advice_neq);

        let binary_arity = 2;
        let base_arity = U::to_usize();
        let sub_arity = V::to_usize();
        let top_arity = W::to_usize();

        let (poseidon_base, insert_base) = if base_arity == binary_arity {
            por::transmute_arity::<PoseidonHasher<F>, U2, U>(poseidon_2.clone(), insert_2.clone())
        } else {
            let poseidon_base = <PoseidonHasher<F> as Halo2Hasher<U>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let insert_base = InsertChip::configure(meta, &advice_eq, &advice_neq);
            (poseidon_base, insert_base)
        };

        let sub = if sub_arity == 0 {
            None
        } else if sub_arity == binary_arity {
            Some(por::transmute_arity::<PoseidonHasher<F>, U2, V>(
                poseidon_2.clone(),
                insert_2.clone(),
            ))
        } else if sub_arity == base_arity {
            Some(por::transmute_arity::<PoseidonHasher<F>, U, V>(
                poseidon_base.clone(),
                insert_base.clone(),
            ))
        } else {
            let poseidon_sub = <PoseidonHasher<F> as Halo2Hasher<V>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let insert_sub = InsertChip::configure(meta, &advice_eq, &advice_neq);
            Some((poseidon_sub, insert_sub))
        };

        let top = if top_arity == 0 {
            None
        } else if top_arity == binary_arity {
            Some(por::transmute_arity::<PoseidonHasher<F>, U2, W>(
                poseidon_2.clone(),
                insert_2.clone(),
            ))
        } else if top_arity == base_arity {
            Some(por::transmute_arity::<PoseidonHasher<F>, U, W>(
                poseidon_base.clone(),
                insert_base.clone(),
            ))
        } else if top_arity == sub_arity {
            let (poseidon_sub, insert_sub) = sub.clone().unwrap();
            Some(por::transmute_arity::<PoseidonHasher<F>, V, W>(
                poseidon_sub,
                insert_sub,
            ))
        } else {
            let poseidon_top = <PoseidonHasher<F> as Halo2Hasher<W>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let insert_top = InsertChip::configure(meta, &advice_eq, &advice_neq);
            Some((poseidon_top, insert_top))
        };

        let labeling = LabelingChip::configure(meta, sha256.clone(), &advice_eq);
        let encoding = EncodingChip::configure(meta, advice_eq[..3].try_into().unwrap());

        let pi = meta.instance_column();
        meta.enable_equality(pi);

        SdrPorepConfig {
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
            ..
        } = self;

        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;
        let challenge_count = challenge_count(SECTOR_NODES);
        let num_layers = num_layers(SECTOR_NODES);

        assert_eq!(pub_inputs.challenges.len(), challenge_count);
        assert_eq!(pub_inputs.challenges_bits.len(), challenge_count);
        assert!(pub_inputs
            .challenges_bits
            .iter()
            .all(|bits| bits.len() == challenge_bit_len));
        assert_eq!(pub_inputs.parents_bits.len(), challenge_count);
        assert!(pub_inputs
            .parents_bits
            .iter()
            .all(|parents| parents.len() == DRG_PARENTS + EXP_PARENTS));
        assert!(pub_inputs.parents_bits.iter().all(|parents| parents
            .iter()
            .all(|parent_bits| parent_bits.len() == challenge_bit_len)));
        assert_eq!(priv_inputs.challenge_proofs.len(), challenge_count);

        let SdrPorepConfig {
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

        <Sha256Hasher<F> as Halo2Hasher<U2>>::load(&mut layouter, &sha256_config)?;

        let sha256_words_chip = Sha256WordsChip::construct(sha256_words_config);
        let poseidon_2_chip = <PoseidonHasher<F> as Halo2Hasher<U2>>::construct(poseidon_2_config);
        let column_hasher_chip = ColumnHasherChip::construct(column_hasher_config);
        let labeling_chip = LabelingChip::construct(labeling_config);
        let encoding_chip = EncodingChip::construct(encoding_config);

        let tree_d_merkle_chip = {
            let sha256_chip = <Sha256Hasher<F> as Halo2Hasher<U2>>::construct(sha256_config);
            let insert_2_chip = InsertChip::construct(insert_2_config);
            MerkleChip::<Sha256Hasher<F>, U2>::with_subchips(sha256_chip, insert_2_chip, None, None)
        };

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

        // Decompose replica-id public input into 32-bit words.
        let replica_id = sha256_words_chip.pi_into_words(
            layouter.namespace(|| "decompose replica-id into sha256 words"),
            pi_col,
            REPLICA_ID_ROW,
        )?;

        // Witness `comm_c`, `root_r`, each challenge, and each challenge's TreeD leaf.
        let (comm_c, root_r, challenges, leafs_d) = layouter.assign_region(
            || "witness comm_c, root_r, challenges, and leafs_d",
            |mut region| {
                let mut advice_iter = AdviceIter::from(advice.clone());

                let comm_c = {
                    let (offset, col) = advice_iter.next();
                    region.assign_advice(|| "comm_c", col, offset, || priv_inputs.comm_c)?
                };

                let root_r = {
                    let (offset, col) = advice_iter.next();
                    region.assign_advice(|| "root_r", col, offset, || priv_inputs.root_r)?
                };

                let challenges = pub_inputs
                    .challenges
                    .iter()
                    .enumerate()
                    .map(|(i, challenge)| {
                        let (offset, col) = advice_iter.next();
                        let challenge = match challenge {
                            Some(challenge) => Value::known(*challenge),
                            None => Value::unknown(),
                        };
                        AssignedU32::assign(
                            &mut region,
                            || format!("challenge {}", i),
                            col,
                            offset,
                            challenge,
                        )
                    })
                    .collect::<Result<Vec<AssignedU32<F>>, Error>>()?;

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
                            || challenge_proof.leaf_d,
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()?;

                Ok((comm_c, root_r, challenges, leafs_d))
            },
        )?;

        // Compute `comm_r = H(comm_c, root_r)` and constrain with public input.
        let comm_r = poseidon_2_chip.hash(
            layouter.namespace(|| "calculate comm_r"),
            &[comm_c.clone(), root_r.clone()],
            get_poseidon_constants::<F, U2>(),
        )?;
        layouter.constrain_instance(comm_r.cell(), pi_col, COMM_R_ROW)?;

        // Assign constants that can be reused across challenge labelings.
        let labeling_constants = labeling_chip.assign_constants(&mut layouter)?;

        // TODO (jake): check if it reduces circuit size to assign challenge bits from instance
        // once at start of synthesis and copy bits into merkle chip rather than reassign challenge
        // bits from public inputs in merkle chips.

        for (i, ((challenge, leaf_d), challenge_proof)) in challenges
            .iter()
            .zip(leafs_d.iter())
            .zip(priv_inputs.challenge_proofs.iter())
            .enumerate()
        {
            let mut layouter = layouter.namespace(|| format!("challenge {}", i));

            let challenge_row = challenge_row(i, challenge_bit_len);
            let challenge_bits_rows = challenge_bits_rows(i, challenge_bit_len);

            // Constrain challenge against public input.
            layouter.constrain_instance(challenge.cell(), pi_col, challenge_row)?;

            // Verify the challenge's TreeD merkle proof.
            let comm_d = tree_d_merkle_chip.compute_root_assigned_leaf_pi_bits(
                layouter.namespace(|| "calculate comm_d from challenge's merkle proof"),
                leaf_d.clone(),
                &challenge_proof.path_d,
                pi_col,
                challenge_bits_rows.clone(),
            )?;
            layouter.constrain_instance(comm_d.cell(), pi_col, COMM_D_ROW)?;

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
                                        || *label,
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
                                        || *label,
                                    )
                                })
                                .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()
                        })
                        .collect::<Result<Vec<Vec<AssignedCell<F, F>>>, Error>>()?;

                    Ok((drg_parent_columns, exp_parent_columns))
                },
            )?;

            // Verify each DRG parent's TreeC Merkle proof.
            for (parent_index, (parent_column, parent_proof)) in drg_parent_columns
                .iter()
                .zip(challenge_proof.drg_parent_proofs.iter())
                .enumerate()
            {
                // Compute parent's column digest.
                let leaf_c = column_hasher_chip.hash(
                    layouter.namespace(|| format!("drg parent {} column digest", parent_index)),
                    parent_column,
                )?;
                let comm_c_calc = tree_r_merkle_chip.compute_root_assigned_leaf_pi_bits(
                    layouter.namespace(|| {
                        format!(
                            "calculate comm_c from drg parent {} merkle proof",
                            parent_index,
                        )
                    }),
                    leaf_c,
                    &parent_proof.path_c,
                    pi_col,
                    drg_parent_bits_rows(i, parent_index, challenge_bit_len),
                )?;
                layouter.assign_region(
                    || format!("constrain drg parent {} comm_c", parent_index),
                    |mut region| region.constrain_equal(comm_c_calc.cell(), comm_c.cell()),
                )?;
            }

            // Verify each expander parent's TreeC Merkle proof.
            for (parent_index, (parent_column, parent_proof)) in exp_parent_columns
                .iter()
                .zip(challenge_proof.exp_parent_proofs.iter())
                .enumerate()
            {
                // Compute parent's column digest.
                let leaf_c = column_hasher_chip.hash(
                    layouter.namespace(|| format!("exp parent {} column digest", parent_index)),
                    parent_column,
                )?;
                let comm_c_calc = tree_r_merkle_chip.compute_root_assigned_leaf_pi_bits(
                    layouter.namespace(|| {
                        format!(
                            "calculate comm_c from exp parent {} merkle proof",
                            parent_index,
                        )
                    }),
                    leaf_c,
                    &parent_proof.path_c,
                    pi_col,
                    exp_parent_bits_rows(i, parent_index, challenge_bit_len),
                )?;
                layouter.assign_region(
                    || format!("constrain exp parent {} comm_c", parent_index),
                    |mut region| region.constrain_equal(comm_c_calc.cell(), comm_c.cell()),
                )?;
            }

            let mut challenge_column = Vec::<AssignedCell<F, F>>::with_capacity(num_layers);

            // Compute the challenge's label in each layer.
            for layer_index in 0..num_layers {
                let is_first_layer = layer_index == 0;

                let num_parents = if is_first_layer {
                    DRG_PARENTS
                } else {
                    DRG_PARENTS + EXP_PARENTS
                };

                let mut parent_labels =
                    Vec::<AssignedU32<F>>::with_capacity(num_parents * LABEL_WORD_LEN);

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

                if !is_first_layer {
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
                    layouter
                        .namespace(|| format!("calculate challenge's layer {} label", layer_index)),
                    &labeling_constants,
                    layer_index,
                    &replica_id,
                    challenge,
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
            let comm_c_calc = tree_r_merkle_chip.compute_root_assigned_leaf_pi_bits(
                layouter.namespace(|| "calculate comm_c from challenge's merkle proof"),
                leaf_c,
                &challenge_proof.path_c,
                pi_col,
                challenge_bits_rows.clone(),
            )?;
            layouter.assign_region(
                || "constrain challenge's comm_c",
                |mut region| region.constrain_equal(comm_c_calc.cell(), comm_c.cell()),
            )?;

            // Compute the challenge's encoding `leaf_r = leaf_d + key`, where the encoding key is
            // the challenge's last layer label.
            let leaf_r = encoding_chip.encode(
                layouter.namespace(|| "encode challenge"),
                leaf_d,
                &challenge_column[num_layers - 1],
            )?;

            // Verify the challenge's TreeR Merkle proof.
            let root_r_calc = tree_r_merkle_chip.compute_root_assigned_leaf_pi_bits(
                layouter.namespace(|| "calculate comm_r from challenge's merkle proof"),
                leaf_r,
                &challenge_proof.path_r,
                pi_col,
                challenge_bits_rows,
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
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn id(&self) -> String {
        SDR_POREP_CIRCUIT_ID.to_string()
    }

    fn k(&self) -> u32 {
        // Values were computed using `get_k` test.
        match GROTH16_PARTITIONING {
            true => match SECTOR_NODES {
                SECTOR_NODES_2_KIB => 18,
                SECTOR_NODES_4_KIB => 18,
                SECTOR_NODES_8_KIB => 18,
                SECTOR_NODES_16_KIB => 18,
                SECTOR_NODES_32_KIB if HALO2_STRENGTH_IS_STD => 19,
                SECTOR_NODES_32_KIB => 18,
                SECTOR_NODES_512_MIB => 19,
                SECTOR_NODES_32_GIB if HALO2_STRENGTH_IS_STD => 27,
                SECTOR_NODES_32_GIB => unimplemented!("this `k` value needs to be computed"),
                SECTOR_NODES_64_GIB if HALO2_STRENGTH_IS_STD => 27,
                SECTOR_NODES_64_GIB => unimplemented!("this `k` value needs to be computed"),
                _ => unimplemented!(),
            },
            false => match SECTOR_NODES {
                SECTOR_NODES_2_KIB => 17,
                SECTOR_NODES_4_KIB => 17,
                SECTOR_NODES_8_KIB => 17,
                SECTOR_NODES_16_KIB => 17,
                SECTOR_NODES_32_KIB if HALO2_STRENGTH_IS_STD => 18,
                SECTOR_NODES_32_KIB => 17,
                SECTOR_NODES_512_MIB => 18,
                SECTOR_NODES_32_GIB => 20,
                SECTOR_NODES_64_GIB => 20,
                _ => unimplemented!(),
            },
        }
    }

    fn sector_size(&self) -> usize {
        (SECTOR_NODES * NODE_SIZE) / 1024
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> SdrPorepCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    // Same as `Circuit::without_witnesses` except this associated function does not take `&self`.
    pub fn blank_circuit() -> Self {
        let challenge_count = challenge_count(SECTOR_NODES);
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;

        SdrPorepCircuit {
            id: SDR_POREP_CIRCUIT_ID.to_string(),
            pub_inputs: PublicInputs {
                replica_id: None,
                comm_d: None,
                comm_r: None,
                challenges: vec![None; challenge_count],
                challenges_bits: vec![vec![None; challenge_bit_len]; challenge_count],
                parents_bits: vec![
                    vec![vec![None; challenge_bit_len]; DRG_PARENTS + EXP_PARENTS];
                    challenge_count
                ],
            },
            priv_inputs: PrivateInputs {
                comm_c: Value::unknown(),
                root_r: Value::unknown(),
                challenge_proofs: vec![ChallengeProof::empty(); challenge_count],
            },
        }
    }

    #[allow(clippy::unwrap_used)]
    pub fn compute_k(k_start: Option<u32>) -> u32 {
        use generic_array::typenum::U0;
        use halo2_proofs::dev::MockProver;

        let challenge_count = challenge_count(SECTOR_NODES);
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;

        let challenge_bits = vec![Some(false); challenge_bit_len];

        let pub_inputs = PublicInputs {
            replica_id: Some(F::zero()),
            comm_d: Some(F::zero()),
            comm_r: Some(F::zero()),
            challenges: vec![Some(0); challenge_count],
            challenges_bits: vec![challenge_bits.clone(); challenge_count],
            parents_bits: vec![vec![challenge_bits; DRG_PARENTS + EXP_PARENTS]; challenge_count],
        };
        let pub_inputs_vec = pub_inputs.to_vec();

        let priv_inputs = {
            let mut path_d = por::empty_path::<F, U2, U0, U0, SECTOR_NODES>();
            let mut path_r = por::empty_path::<F, U, V, W, SECTOR_NODES>();
            for sibs in path_d.iter_mut().chain(path_r.iter_mut()) {
                *sibs = vec![Value::known(F::zero()); sibs.len()];
            }
            let path_c = path_r.clone();

            let mut parent_proof = ParentProof::<F, U, V, W, SECTOR_NODES>::empty();
            parent_proof.column = vec![Value::known(F::zero()); parent_proof.column.len()];
            parent_proof.path_c = path_c.clone();

            let drg_parent_proofs = (0..DRG_PARENTS)
                .map(|_| parent_proof.clone())
                .collect::<Vec<ParentProof<F, U, V, W, SECTOR_NODES>>>()
                .try_into()
                .unwrap();

            let exp_parent_proofs = (0..EXP_PARENTS)
                .map(|_| parent_proof.clone())
                .collect::<Vec<ParentProof<F, U, V, W, SECTOR_NODES>>>()
                .try_into()
                .unwrap();

            let challenge_proof = ChallengeProof {
                leaf_d: Value::known(F::zero()),
                path_d,
                path_c,
                path_r,
                drg_parent_proofs,
                exp_parent_proofs,
            };

            PrivateInputs {
                comm_c: Value::known(F::zero()),
                root_r: Value::known(F::zero()),
                challenge_proofs: vec![challenge_proof; challenge_count],
            }
        };

        let circ = SdrPorepCircuit {
            id: SDR_POREP_CIRCUIT_ID.to_string(),
            pub_inputs,
            priv_inputs,
        };

        // If a minimum `k` value is not supplied, use sha256's.
        let mut k = k_start.unwrap_or(17);
        loop {
            // println!("Trying k = {}", k);
            match MockProver::run(k, &circ, pub_inputs_vec.clone()) {
                Ok(_) => return k,
                Err(Error::NotEnoughRowsAvailable { .. }) | Err(Error::InstanceTooLarge) => k += 1,
                err => panic!("Unexpected error: {:?}", err),
            };
        }
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> SdrPorepCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt + storage_proofs_core::halo2::Halo2Field,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub fn proof_size(&self, batch_size: Option<usize>) -> usize {
        let k = self.k() as usize;
        let cost = halo2_proofs::dev::CircuitCost::<F::Curve, Self>::measure(k, self);
        match batch_size {
            Some(batch_size) => cost.proof_size(batch_size).into(),
            None => cost.marginal_proof_size().into(),
        }
    }
}

#[test]
#[ignore]
fn get_k() {
    use generic_array::typenum::{U0, U4, U8};
    use halo2_proofs::pasta::Fp;

    let mut k = SdrPorepCircuit::<Fp, U8, U0, U0, SECTOR_NODES_2_KIB>::compute_k(None);
    println!("Found k = {} (sector-size = 2kib)", k);

    k = SdrPorepCircuit::<Fp, U8, U2, U0, SECTOR_NODES_4_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 4kib)", k);

    k = SdrPorepCircuit::<Fp, U8, U4, U0, SECTOR_NODES_8_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 8kib)", k);

    k = SdrPorepCircuit::<Fp, U8, U8, U0, SECTOR_NODES_16_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 16kib)", k);

    k = SdrPorepCircuit::<Fp, U8, U8, U2, SECTOR_NODES_32_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 32kib)", k);

    /*
    use crate::stacked::halo2::constants::SECTOR_NODES_8_MIB;
    k = SdrPorepCircuit::<Fp, U8, U0, U0, SECTOR_NODES_8_MIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 8mib)", k);

    use crate::stacked::halo2::constants::SECTOR_NODES_16_MIB;
    k = SdrPorepCircuit::<Fp, U8, U2, U0, SECTOR_NODES_16_MIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 16mib)", k);
    */

    k = SdrPorepCircuit::<Fp, U8, U0, U0, SECTOR_NODES_512_MIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 512mib)", k);

    k = SdrPorepCircuit::<Fp, U8, U8, U0, SECTOR_NODES_32_GIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 32gib)", k);

    k = SdrPorepCircuit::<Fp, U8, U8, U2, SECTOR_NODES_64_GIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 64gib)", k);
}

#[test]
#[ignore]
#[allow(dead_code)]
fn get_proof_size() {
    use generic_array::typenum::{U0, U4, U8};
    use halo2_proofs::pasta::Fp;

    type Circuit2Kib = SdrPorepCircuit<Fp, U8, U0, U0, SECTOR_NODES_2_KIB>;
    type Circuit4Kib = SdrPorepCircuit<Fp, U8, U2, U0, SECTOR_NODES_4_KIB>;
    type Circuit8Kib = SdrPorepCircuit<Fp, U8, U4, U0, SECTOR_NODES_8_KIB>;
    type Circuit16Kib = SdrPorepCircuit<Fp, U8, U8, U0, SECTOR_NODES_16_KIB>;
    type Circuit32Kib = SdrPorepCircuit<Fp, U8, U8, U2, SECTOR_NODES_32_KIB>;
    type Circuit512Mib = SdrPorepCircuit<Fp, U8, U0, U0, SECTOR_NODES_512_MIB>;
    type Circuit32Gib = SdrPorepCircuit<Fp, U8, U8, U0, SECTOR_NODES_32_GIB>;
    type Circuit64Gib = SdrPorepCircuit<Fp, U8, U8, U2, SECTOR_NODES_64_GIB>;

    let circ = Circuit2Kib::blank_circuit();
    dbg!(circ.proof_size(None));
    dbg!(circ.proof_size(Some(1)));
    dbg!(circ.proof_size(Some(2)));
}
