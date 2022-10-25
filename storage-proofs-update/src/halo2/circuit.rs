use std::convert::TryInto;
use std::marker::PhantomData;
use std::ops::Range;

use fil_halo2_gadgets::{
    boolean::{AssignedBit, Bit},
    select::{SelectChip, SelectConfig},
    AdviceIter, ColumnBuilder,
};
use filecoin_hashers::{get_poseidon_constants, Halo2Hasher, Hasher, PoseidonArity};
use generic_array::typenum::U2;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
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
    merkle::{MerkleProof, MerkleProofTrait},
    util::NODE_SIZE,
    SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_1_KIB, SECTOR_NODES_2_KIB,
    SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB,
    SECTOR_NODES_64_GIB, SECTOR_NODES_8_KIB, SECTOR_NODES_8_MIB,
};

use crate::{
    constants::{validate_tree_r_shape, TreeDArity, TreeDHasher, TreeRHasher},
    gen_partition_challenges, gen_partition_rhos,
    halo2::{
        apex_leaf_count, challenge_count,
        gadgets::{ApexTreeChip, ChallengeLabelsChip, ChallengeLabelsConfig},
        partition_bit_len, partition_count, GROTH16_PARTITIONING,
    },
    phi, vanilla,
};

pub const EMPTY_SECTOR_UPDATE_CIRCUIT_ID: &str = "update";

const COMM_R_OLD_ROW: usize = 0;
const COMM_D_NEW_ROW: usize = COMM_R_OLD_ROW + 1;
const COMM_R_NEW_ROW: usize = COMM_D_NEW_ROW + 1;

#[inline]
const fn partition_bits_rows(partition_bit_len: usize) -> Range<usize> {
    let start = COMM_R_NEW_ROW + 1;
    start..start + partition_bit_len
}

#[inline]
const fn challenge_bits_rows(
    challenge_index: usize,
    challenge_bit_len: usize,
    partition_bit_len: usize,
) -> Range<usize> {
    let first_challenge_bit_row = partition_bits_rows(partition_bit_len).end;
    let challenge_sans_partition_bit_len = challenge_bit_len - partition_bit_len;
    let start = first_challenge_bit_row + challenge_index * (challenge_sans_partition_bit_len + 1);
    start..start + challenge_sans_partition_bit_len
}

#[inline]
const fn rho_row(
    challenge_index: usize,
    challenge_bit_len: usize,
    partition_bit_len: usize,
) -> usize {
    challenge_bits_rows(challenge_index, challenge_bit_len, partition_bit_len).end
}

#[derive(Clone)]
pub struct PublicInputs<F: FieldExt, const SECTOR_NODES: usize> {
    comm_r_old: Option<F>,
    comm_d_new: Option<F>,
    comm_r_new: Option<F>,
    partition_bits: Vec<Option<bool>>,
    challenges: Vec<Vec<Option<bool>>>,
    rhos: Vec<Option<F>>,
}

impl<F, const SECTOR_NODES: usize> From<vanilla::PublicInputs<F>> for PublicInputs<F, SECTOR_NODES>
where
    F: FieldExt,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    fn from(vanilla_pub_inputs: vanilla::PublicInputs<F>) -> Self {
        let vanilla::PublicInputs {
            k,
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h,
        } = vanilla_pub_inputs;
        let challenges = gen_partition_challenges(SECTOR_NODES, comm_r_new, k);
        let phi = phi(&comm_d_new, &comm_r_old);
        let rhos = gen_partition_rhos(SECTOR_NODES, &challenges, &phi, h);
        Self::new(
            k,
            comm_r_old.into(),
            comm_d_new.into(),
            comm_r_new.into(),
            challenges,
            rhos,
        )
    }
}

impl<F: FieldExt, const SECTOR_NODES: usize> PublicInputs<F, SECTOR_NODES> {
    pub fn new(
        k: usize,
        comm_r_old: F,
        comm_d_new: F,
        comm_r_new: F,
        // Each challenge in `challenges` must contain the partition index bits, i.e. `challenges`
        // is the collected output of the `Challenges` iterator.
        challenges: Vec<u32>,
        rhos: Vec<F>,
    ) -> Self {
        let partition_count = partition_count(SECTOR_NODES);
        assert!(
            k < partition_count,
            "partition index `k` exceeds sector size's partition count"
        );

        let partition_bit_len = partition_bit_len(SECTOR_NODES);
        let partition_bits = (0..partition_bit_len)
            .map(|i| Some(k >> i & 1 == 1))
            .collect();

        let challenge_count = challenge_count(SECTOR_NODES);
        assert_eq!(challenges.len(), challenge_count);
        assert_eq!(rhos.len(), challenge_count);

        // Strip the partition index from each challenge.
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;
        let challenge_sans_partition_bit_len = challenge_bit_len - partition_bit_len;
        let challenges = challenges
            .iter()
            .map(|c| {
                (0..challenge_sans_partition_bit_len)
                    .map(|i| Some(c >> i & 1 == 1))
                    .collect()
            })
            .collect();

        PublicInputs {
            partition_bits,
            comm_r_old: Some(comm_r_old),
            comm_d_new: Some(comm_d_new),
            comm_r_new: Some(comm_r_new),
            challenges,
            rhos: rhos.into_iter().map(Some).collect(),
        }
    }

    // Public inputs:
    // [
    //     comm_r_old, comm_d_new, comm_r_new,
    //     first_partition_bit, ..., last_partition_bit,
    //     challenge_0_first_bit, ..., challenge_0_last_bit, rho_0,
    //     ...,
    //     challenge_n_first_bit, ..., challenge_n_last_bit, rho_n,
    // ]
    pub fn to_vec(&self) -> Vec<Vec<F>> {
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;
        let partition_bit_len = partition_bit_len(SECTOR_NODES);
        let challenge_sans_partition_bit_len = challenge_bit_len - partition_bit_len;
        let challenge_count = challenge_count(SECTOR_NODES);

        assert_eq!(self.partition_bits.len(), partition_bit_len);
        assert_eq!(self.challenges.len(), challenge_count);
        assert!(self
            .challenges
            .iter()
            .all(|bits| bits.len() == challenge_sans_partition_bit_len),);
        assert_eq!(self.rhos.len(), challenge_count);
        assert!(
            self.comm_r_old.is_some()
                && self.comm_d_new.is_some()
                && self.comm_r_new.is_some()
                && self.partition_bits.iter().all(Option::is_some)
                && self
                    .challenges
                    .iter()
                    .all(|bits| bits.iter().all(Option::is_some))
                && self.rhos.iter().all(Option::is_some),
            "all public inputs must be set",
        );

        let num_pub_inputs =
            3 + partition_bit_len + challenge_count * (challenge_sans_partition_bit_len + 1);

        let mut pub_inputs = Vec::<F>::with_capacity(num_pub_inputs);
        pub_inputs.push(self.comm_r_old.unwrap());
        pub_inputs.push(self.comm_d_new.unwrap());
        pub_inputs.push(self.comm_r_new.unwrap());

        for bit in self.partition_bits.iter() {
            if bit.unwrap() {
                pub_inputs.push(F::one())
            } else {
                pub_inputs.push(F::zero())
            }
        }

        for (challenge_bits, rho) in self.challenges.iter().zip(&self.rhos) {
            for bit in challenge_bits {
                if bit.unwrap() {
                    pub_inputs.push(F::one())
                } else {
                    pub_inputs.push(F::zero())
                }
            }
            pub_inputs.push(rho.unwrap());
        }

        vec![pub_inputs]
    }
}

#[derive(Clone)]
pub struct ChallengeProof<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    leaf_r_old: Value<F>,
    path_r_old: Vec<Vec<Value<F>>>,
    leaf_d_new: Value<F>,
    path_d_new: Vec<Vec<Value<F>>>,
    leaf_r_new: Value<F>,
    path_r_new: Vec<Vec<Value<F>>>,
    _tree_r: PhantomData<(U, V, W)>,
}

impl<F, U, V, W, const SECTOR_NODES: usize> From<vanilla::ChallengeProof<F, U, V, W>>
    for ChallengeProof<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    fn from(challenge_proof: vanilla::ChallengeProof<F, U, V, W>) -> Self {
        let vanilla::ChallengeProof {
            proof_r_old,
            proof_d_new,
            proof_r_new,
        } = challenge_proof;
        Self::from_merkle_proofs(proof_r_old, proof_d_new, proof_r_new)
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> ChallengeProof<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    pub fn from_merkle_proofs(
        proof_r_old: MerkleProof<TreeRHasher<F>, U, V, W>,
        proof_d_new: MerkleProof<TreeDHasher<F>, TreeDArity>,
        proof_r_new: MerkleProof<TreeRHasher<F>, U, V, W>,
    ) -> Self {
        let leaf_r_old = Value::known(proof_r_old.leaf().into());
        let path_r_old: Vec<Vec<Value<F>>> = proof_r_old
            .path()
            .iter()
            .map(|(siblings, _insert)| siblings.iter().map(|&s| Value::known(s.into())).collect())
            .collect();

        let leaf_d_new = Value::known(proof_d_new.leaf().into());
        let path_d_new: Vec<Vec<Value<F>>> = proof_d_new
            .path()
            .iter()
            .map(|(siblings, _insert)| siblings.iter().map(|&s| Value::known(s.into())).collect())
            .collect();

        let leaf_r_new = Value::known(proof_r_new.leaf().into());
        let path_r_new: Vec<Vec<Value<F>>> = proof_r_new
            .path()
            .iter()
            .map(|(siblings, _insert)| siblings.iter().map(|&s| Value::known(s.into())).collect())
            .collect();

        ChallengeProof {
            leaf_r_old,
            path_r_old,
            leaf_d_new,
            path_d_new,
            leaf_r_new,
            path_r_new,
            _tree_r: PhantomData,
        }
    }

    pub fn empty() -> Self {
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;

        // TreeD is a binary-tree.
        let path_d_new = vec![vec![Value::unknown()]; challenge_bit_len];

        // TreeROld and TreeRNew have the same shape, thus have the same Merkle path length.
        let path_r_old = por::empty_path::<F, U, V, W, SECTOR_NODES>();
        let path_r_new = path_r_old.clone();

        ChallengeProof {
            leaf_r_old: Value::unknown(),
            path_r_old,
            leaf_d_new: Value::unknown(),
            path_d_new,
            leaf_r_new: Value::unknown(),
            path_r_new,
            _tree_r: PhantomData,
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
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    pub comm_c: Value<F>,
    pub root_r_old: Value<F>,
    pub root_r_new: Value<F>,
    pub apex_leafs: Vec<Value<F>>,
    pub challenge_proofs: Vec<ChallengeProof<F, U, V, W, SECTOR_NODES>>,
}

impl<F, U, V, W, const SECTOR_NODES: usize> From<vanilla::PartitionProof<F, U, V, W>>
    for PrivateInputs<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    fn from(vanilla_partition_proof: vanilla::PartitionProof<F, U, V, W>) -> Self {
        let comm_c: F = vanilla_partition_proof.comm_c.into();
        let root_r_old: F = vanilla_partition_proof.challenge_proofs[0]
            .proof_r_old
            .root()
            .into();
        let root_r_new: F = vanilla_partition_proof.challenge_proofs[0]
            .proof_r_new
            .root()
            .into();

        let apex_leafs: Vec<Value<F>> = vanilla_partition_proof
            .apex_leafs
            .iter()
            .copied()
            .map(|leaf| Value::known(leaf.into()))
            .collect();

        let challenge_proofs: Vec<ChallengeProof<F, U, V, W, SECTOR_NODES>> =
            vanilla_partition_proof
                .challenge_proofs
                .iter()
                .cloned()
                .map(ChallengeProof::from)
                .collect();

        PrivateInputs {
            comm_c: Value::known(comm_c),
            root_r_old: Value::known(root_r_old),
            root_r_new: Value::known(root_r_new),
            apex_leafs,
            challenge_proofs,
        }
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> PrivateInputs<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    pub fn new(
        comm_c: F,
        apex_leafs: &[F],
        challenge_proofs: &[vanilla::ChallengeProof<F, U, V, W>],
    ) -> Self {
        let root_r_old: F = challenge_proofs[0].proof_r_old.root().into();
        let root_r_new: F = challenge_proofs[0].proof_r_new.root().into();

        let apex_leafs: Vec<Value<F>> = apex_leafs.iter().copied().map(Value::known).collect();

        let challenge_proofs: Vec<ChallengeProof<F, U, V, W, SECTOR_NODES>> = challenge_proofs
            .iter()
            .cloned()
            .map(ChallengeProof::from)
            .collect();

        PrivateInputs {
            comm_c: Value::known(comm_c),
            root_r_old: Value::known(root_r_old),
            root_r_new: Value::known(root_r_new),
            apex_leafs,
            challenge_proofs,
        }
    }
}

#[derive(Clone)]
pub struct EmptySectorUpdateConfig<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    sha256_2: <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::Config,
    insert_2: InsertConfig<F, TreeDArity>,
    poseidon_2: <TreeRHasher<F> as Halo2Hasher<U2>>::Config,
    poseidon_base: <TreeRHasher<F> as Halo2Hasher<U>>::Config,
    insert_base: InsertConfig<F, U>,
    sub: Option<(
        <TreeRHasher<F> as Halo2Hasher<V>>::Config,
        InsertConfig<F, V>,
    )>,
    top: Option<(
        <TreeRHasher<F> as Halo2Hasher<W>>::Config,
        InsertConfig<F, W>,
    )>,
    // `SelectChip` is only used when Groth16 partitioning is enabled (i.e. when using apex trees).
    select: Option<SelectConfig<F>>,
    challenge_labels: ChallengeLabelsConfig<F>,
    advice: Vec<Column<Advice>>,
    pi: Column<Instance>,
}

pub struct EmptySectorUpdateCircuit<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    pub pub_inputs: PublicInputs<F, SECTOR_NODES>,
    pub priv_inputs: PrivateInputs<F, U, V, W, SECTOR_NODES>,
}

impl<F, U, V, W, const SECTOR_NODES: usize> EmptySectorUpdateConfig<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    #[allow(clippy::type_complexity)]
    #[allow(clippy::unwrap_used)]
    fn create_chips(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<
        (
            MerkleChip<TreeDHasher<F>, TreeDArity>,
            MerkleChip<TreeRHasher<F>, U, V, W>,
            <TreeRHasher<F> as Halo2Hasher<U2>>::Chip,
            Option<ApexTreeChip<F>>,
            Option<SelectChip<F>>,
            ChallengeLabelsChip<F>,
        ),
        Error,
    > {
        assert_eq!(GROTH16_PARTITIONING, self.select.is_some());

        <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::load(layouter, &self.sha256_2)?;

        let tree_d_merkle_chip = {
            let sha256_2_chip =
                <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::construct(self.sha256_2.clone());
            let insert_2_chip = InsertChip::construct(self.insert_2.clone());
            MerkleChip::with_subchips(sha256_2_chip, insert_2_chip, None, None)
        };

        let tree_r_merkle_chip = {
            let poseidon_base_chip =
                <TreeRHasher<F> as Halo2Hasher<U>>::construct(self.poseidon_base.clone());

            let insert_base_chip = InsertChip::construct(self.insert_base.clone());

            let sub_chips = self.sub.as_ref().map(|(poseidon_config, insert_config)| {
                (
                    <TreeRHasher<F> as Halo2Hasher<V>>::construct(poseidon_config.clone()),
                    InsertChip::construct(insert_config.clone()),
                )
            });

            let top_chips = self.top.as_ref().map(|(poseidon_config, insert_config)| {
                (
                    <TreeRHasher<F> as Halo2Hasher<W>>::construct(poseidon_config.clone()),
                    InsertChip::construct(insert_config.clone()),
                )
            });

            MerkleChip::with_subchips(poseidon_base_chip, insert_base_chip, sub_chips, top_chips)
        };

        let poseidon_2_chip =
            <TreeRHasher<F> as Halo2Hasher<U2>>::construct(self.poseidon_2.clone());

        // Only use apex-tree and select chips when using multiple-challenge partitions (i.e.
        // groth16 partitioning is enabled).
        let (apex_tree_chip, select_chip) = if GROTH16_PARTITIONING {
            let sha256_2_chip =
                <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::construct(self.sha256_2.clone());
            let apex_tree_chip = ApexTreeChip::with_subchips(sha256_2_chip);
            let select_chip = SelectChip::construct(self.select.clone().unwrap());
            (Some(apex_tree_chip), Some(select_chip))
        } else {
            (None, None)
        };

        let challenge_labels_chip = ChallengeLabelsChip::construct(self.challenge_labels.clone());

        Ok((
            tree_d_merkle_chip,
            tree_r_merkle_chip,
            poseidon_2_chip,
            apex_tree_chip,
            select_chip,
            challenge_labels_chip,
        ))
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> Circuit<F>
    for EmptySectorUpdateCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    type Config = EmptySectorUpdateConfig<F, U, V, W, SECTOR_NODES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::blank_circuit()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let (advice_eq, advice_neq, fixed_eq, fixed_neq) = ColumnBuilder::new()
            .with_chip::<<TreeDHasher<F> as Halo2Hasher<TreeDArity>>::Chip>()
            .with_chip::<<TreeRHasher<F> as Halo2Hasher<U>>::Chip>()
            .with_chip::<<TreeRHasher<F> as Halo2Hasher<V>>::Chip>()
            .with_chip::<<TreeRHasher<F> as Halo2Hasher<W>>::Chip>()
            // Only need the base arity here because it is guaranteed to be the largest arity, thus
            // all other arity insert chips will use a subset of the base arity's columns.
            .with_chip::<InsertChip<F, U>>()
            .create_columns(meta);

        let sha256_2 = <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::configure(
            meta,
            &advice_eq,
            &advice_neq,
            &fixed_eq,
            &fixed_neq,
        );

        let insert_2 = InsertChip::<F, U2>::configure(meta, &advice_eq, &advice_neq);

        let poseidon_2 = <TreeRHasher<F> as Halo2Hasher<U2>>::configure(
            meta,
            &advice_eq,
            &advice_neq,
            &fixed_eq,
            &fixed_neq,
        );

        let binary_arity = 2;
        let base_arity = U::to_usize();
        let sub_arity = V::to_usize();
        let top_arity = W::to_usize();

        let (poseidon_base, insert_base) = if base_arity == binary_arity {
            por::transmute_arity::<TreeRHasher<F>, U2, U>(poseidon_2.clone(), insert_2.clone())
        } else {
            let poseidon_base = <TreeRHasher<F> as Halo2Hasher<U>>::configure(
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
            Some(por::transmute_arity::<TreeRHasher<F>, U2, V>(
                poseidon_2.clone(),
                insert_2.clone(),
            ))
        } else if sub_arity == base_arity {
            Some(por::transmute_arity::<TreeRHasher<F>, U, V>(
                poseidon_base.clone(),
                insert_base.clone(),
            ))
        } else {
            let poseidon_sub = <TreeRHasher<F> as Halo2Hasher<V>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let insert_sub = InsertChip::configure(meta, &advice_eq, &advice_neq);
            Some((poseidon_sub, insert_sub))
        };

        let top = if W::to_usize() == 0 {
            None
        } else if top_arity == binary_arity {
            Some(por::transmute_arity::<TreeRHasher<F>, U2, W>(
                poseidon_2.clone(),
                insert_2.clone(),
            ))
        } else if top_arity == base_arity {
            Some(por::transmute_arity::<TreeRHasher<F>, U, W>(
                poseidon_base.clone(),
                insert_base.clone(),
            ))
        } else if top_arity == sub_arity {
            let (poseidon_sub, insert_sub) = sub.clone().unwrap();
            Some(por::transmute_arity::<TreeRHasher<F>, V, W>(
                poseidon_sub,
                insert_sub,
            ))
        } else {
            let poseidon_top = <TreeRHasher<F> as Halo2Hasher<W>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let insert_top = InsertChip::configure(meta, &advice_eq, &advice_neq);
            Some((poseidon_top, insert_top))
        };

        let select = if GROTH16_PARTITIONING {
            Some(SelectChip::configure(
                meta,
                advice_eq[..4].try_into().unwrap(),
            ))
        } else {
            None
        };

        let challenge_labels =
            ChallengeLabelsChip::configure(meta, advice_eq[..4].try_into().unwrap());

        let pi = meta.instance_column();
        meta.enable_equality(pi);

        EmptySectorUpdateConfig {
            sha256_2,
            insert_2,
            poseidon_2,
            poseidon_base,
            insert_base,
            sub,
            top,
            select,
            challenge_labels,
            advice: advice_eq,
            pi,
        }
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        validate_tree_r_shape::<U, V, W>(SECTOR_NODES);
        if GROTH16_PARTITIONING {
            self.synthesize_groth16_partitioning(config, layouter)
        } else {
            self.synthesize_halo2_partitioning(config, layouter)
        }
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> CircuitRows
    for EmptySectorUpdateCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    fn id(&self) -> String {
        EMPTY_SECTOR_UPDATE_CIRCUIT_ID.to_string()
    }

    fn k(&self) -> u32 {
        // Computed using `Self::compute_k`.
        match GROTH16_PARTITIONING {
            true => match SECTOR_NODES {
                SECTOR_NODES_1_KIB => 17,
                SECTOR_NODES_2_KIB => 18,
                SECTOR_NODES_4_KIB => 18,
                SECTOR_NODES_8_KIB => 18,
                SECTOR_NODES_16_KIB => 20,
                SECTOR_NODES_32_KIB => 20,
                SECTOR_NODES_8_MIB => 20,
                SECTOR_NODES_16_MIB => 20,
                SECTOR_NODES_512_MIB => 23,
                SECTOR_NODES_32_GIB => 23,
                SECTOR_NODES_64_GIB => 23,
                _ => unreachable!(),
            },
            false => match SECTOR_NODES {
                SECTOR_NODES_1_KIB => 17,
                SECTOR_NODES_2_KIB => 17,
                SECTOR_NODES_4_KIB => 17,
                SECTOR_NODES_8_KIB => 17,
                SECTOR_NODES_16_KIB => 17,
                SECTOR_NODES_32_KIB => 17,
                SECTOR_NODES_8_MIB => 17,
                SECTOR_NODES_16_MIB => 17,
                SECTOR_NODES_512_MIB => 17,
                SECTOR_NODES_32_GIB => 17,
                SECTOR_NODES_64_GIB => 18,
                _ => unreachable!(),
            },
        }
    }

    fn sector_size(&self) -> usize {
        (SECTOR_NODES * NODE_SIZE) / 1024
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> EmptySectorUpdateCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    #[allow(clippy::unwrap_used)]
    fn synthesize_groth16_partitioning(
        &self,
        config: <Self as Circuit<F>>::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let EmptySectorUpdateCircuit {
            pub_inputs,
            priv_inputs,
        } = self;

        let partition_count = partition_count(SECTOR_NODES);
        let partition_bit_len = partition_count.trailing_zeros() as usize;

        let challenge_count = challenge_count(SECTOR_NODES);
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;
        let challenge_sans_partition_bit_len = challenge_bit_len - partition_bit_len;

        let apex_leaf_count = apex_leaf_count(SECTOR_NODES);
        let apex_leaf_bit_len = apex_leaf_count.trailing_zeros() as usize;
        let challenge_to_apex_leaf_bit_len = challenge_sans_partition_bit_len - apex_leaf_bit_len;

        // Check that the partition index is valid for the sector-size.
        let k = pub_inputs
            .partition_bits
            .iter()
            .copied()
            .rev()
            .fold(Some(0), |acc, bit| {
                acc.zip(bit).map(|(acc, bit)| (acc << 1) + bit as usize)
            });
        if let Some(k) = k {
            assert!(k < partition_count);
        }

        assert_eq!(priv_inputs.apex_leafs.len(), apex_leaf_count);
        assert_eq!(priv_inputs.challenge_proofs.len(), challenge_count);

        let partition_path =
            priv_inputs.challenge_proofs[0].path_d_new[challenge_sans_partition_bit_len..].to_vec();

        assert_eq!(partition_path.len(), partition_bit_len);
        assert!(partition_path.iter().all(|siblings| siblings.len() == 1));

        // Check that all partition challenge's have the same same partition path.
        for challenge_proof in &priv_inputs.challenge_proofs[1..] {
            let challenge_partition_path =
                &challenge_proof.path_d_new[challenge_sans_partition_bit_len..];

            assert_eq!(challenge_partition_path.len(), partition_path.len());

            for (siblings, expected_siblings) in
                challenge_partition_path.iter().zip(partition_path.iter())
            {
                assert_eq!(siblings.len(), 1);
                siblings[0]
                    .zip(expected_siblings[0])
                    .assert_if_known(|(sib, expected_sib)| sib == expected_sib);
            }
        }

        let (
            tree_d_merkle_chip,
            tree_r_merkle_chip,
            poseidon_2_chip,
            apex_tree_chip,
            select_chip,
            challenge_labels_chip,
        ) = config.create_chips(&mut layouter)?;

        assert!(apex_tree_chip.is_some() && select_chip.is_some());
        let apex_tree_chip = apex_tree_chip.unwrap();
        let select_chip = select_chip.unwrap();

        let advice = config.advice;
        let pi_col = config.pi;

        // Assign initial values.
        let (comm_c, root_r_old, root_r_new, partition_bits, challenges, apex_leafs) = layouter
            .assign_region(
                || "assign comm_c, root_r_old, root_r_new, partition_bits, challenges, apex_leafs",
                |mut region| {
                    let mut advice_iter = AdviceIter::from(advice.clone());

                    let comm_c = {
                        let (offset, col) = advice_iter.next();
                        region.assign_advice(|| "comm_c", col, offset, || priv_inputs.comm_c)?
                    };

                    let root_r_old = {
                        let (offset, col) = advice_iter.next();
                        region.assign_advice(
                            || "root_r_old",
                            col,
                            offset,
                            || priv_inputs.root_r_old,
                        )?
                    };

                    let root_r_new = {
                        let (offset, col) = advice_iter.next();
                        region.assign_advice(
                            || "root_r_new",
                            col,
                            offset,
                            || priv_inputs.root_r_new,
                        )?
                    };

                    let partition_bits = pub_inputs
                        .partition_bits
                        .iter()
                        .enumerate()
                        .map(|(i, bit_opt)| {
                            let (offset, col) = advice_iter.next();
                            let bit = match bit_opt {
                                Some(bit) => Value::known(*bit),
                                None => Value::unknown(),
                            };
                            region.assign_advice(
                                || format!("partition_bits[{}]", i),
                                col,
                                offset,
                                || bit.map(Bit),
                            )
                        })
                        .collect::<Result<Vec<AssignedBit<F>>, Error>>()?;

                    let challenges = pub_inputs
                        .challenges
                        .iter()
                        .enumerate()
                        .map(|(i, challenge_bits)| {
                            challenge_bits
                                .iter()
                                .enumerate()
                                .map(|(bit_index, bit)| {
                                    let (offset, col) = advice_iter.next();
                                    let bit = match bit {
                                        Some(bit) => Value::known(Bit(*bit)),
                                        None => Value::unknown(),
                                    };
                                    region.assign_advice(
                                        || format!("challenge_{}_bits[{}]", i, bit_index),
                                        col,
                                        offset,
                                        || bit,
                                    )
                                })
                                .collect::<Result<Vec<AssignedBit<F>>, Error>>()
                        })
                        .collect::<Result<Vec<Vec<AssignedBit<F>>>, Error>>()?;

                    let apex_leafs = priv_inputs
                        .apex_leafs
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
                        .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()?;

                    Ok((
                        comm_c,
                        root_r_old,
                        root_r_new,
                        partition_bits,
                        challenges,
                        apex_leafs,
                    ))
                },
            )?;

        // Constrain partition bits and challenge bits against public inputs.
        for (bit, pi_row) in partition_bits
            .iter()
            .zip(partition_bits_rows(partition_bit_len))
        {
            layouter.constrain_instance(bit.cell(), pi_col, pi_row)?;
        }
        for (i, challenge_bits) in challenges.iter().enumerate() {
            for (bit, pi_row) in challenge_bits.iter().zip(challenge_bits_rows(
                i,
                challenge_bit_len,
                partition_bit_len,
            )) {
                layouter.constrain_instance(bit.cell(), pi_col, pi_row)?;
            }
        }

        let poseidon_2_consts = get_poseidon_constants::<F, U2>();

        // Compute `comm_r_old = H(comm_c, root_r_old)`.
        let comm_r_old = poseidon_2_chip.hash(
            layouter.namespace(|| "calculate comm_r_old"),
            &[comm_c.clone(), root_r_old.clone()],
            poseidon_2_consts,
        )?;

        // Compute `comm_r_new = H(comm_c, root_r_new)`.
        let comm_r_new = poseidon_2_chip.hash(
            layouter.namespace(|| "calculate comm_r_new"),
            &[comm_c, root_r_new.clone()],
            poseidon_2_consts,
        )?;

        // Compute apex root from apex leafs.
        let apex_root = apex_tree_chip
            .compute_root(layouter.namespace(|| "calculate apex root"), &apex_leafs)?;

        // Compute `comm_d_new` from apex root and partition proof.
        let comm_d_new = if partition_count == 1 {
            apex_root
        } else {
            tree_d_merkle_chip.compute_root_assigned_leaf(
                layouter.namespace(|| "calculate comm_d_new"),
                &partition_bits,
                apex_root,
                &partition_path,
            )?
        };

        // Constrain witnessed commitments with public inputs.
        layouter.constrain_instance(comm_r_old.cell(), pi_col, COMM_R_OLD_ROW)?;
        layouter.constrain_instance(comm_d_new.cell(), pi_col, COMM_D_NEW_ROW)?;
        layouter.constrain_instance(comm_r_new.cell(), pi_col, COMM_R_NEW_ROW)?;

        for (i, (challenge_bits, challenge_proof)) in challenges
            .iter()
            .zip(priv_inputs.challenge_proofs.iter())
            .enumerate()
        {
            let mut layouter = layouter.namespace(|| format!("challenge {}", i));

            let (label_r_old, label_d_new, label_r_new) = challenge_labels_chip.assign_labels(
                layouter.namespace(|| "assign labels"),
                challenge_proof.leaf_r_old,
                challenge_proof.leaf_d_new,
                challenge_proof.leaf_r_new,
                pi_col,
                rho_row(i, challenge_bit_len, partition_bit_len),
            )?;

            let challenge_and_partition_bits: Vec<AssignedBit<F>> = challenge_bits
                .iter()
                .chain(partition_bits.iter())
                .cloned()
                .collect();

            let root_r_old_calc = tree_r_merkle_chip.compute_root_assigned_leaf(
                layouter.namespace(|| "compute root_r_old from merkle proof"),
                &challenge_and_partition_bits,
                label_r_old,
                &challenge_proof.path_r_old,
            )?;
            layouter.assign_region(
                || "check root_r_old_calc",
                |mut region| region.constrain_equal(root_r_old_calc.cell(), root_r_old.cell()),
            )?;

            let root_r_new_calc = tree_r_merkle_chip.compute_root_assigned_leaf(
                layouter.namespace(|| "compute root_r_new from merkle proof"),
                &challenge_and_partition_bits,
                label_r_new,
                &challenge_proof.path_r_new,
            )?;
            layouter.assign_region(
                || "check root_r_new_calc",
                |mut region| region.constrain_equal(root_r_new_calc.cell(), root_r_new.cell()),
            )?;

            let (challenge_bits_to_apex_leaf, apex_leaf_bits) =
                challenge_bits.split_at(challenge_to_apex_leaf_bit_len);

            let apex_leaf = select_chip.select(
                layouter.namespace(|| "select apex leaf"),
                &apex_leafs,
                apex_leaf_bits,
            )?;

            let path_to_apex_leaf = &challenge_proof.path_d_new[..challenge_to_apex_leaf_bit_len];

            let apex_leaf_calc = tree_d_merkle_chip.compute_root_assigned_leaf(
                layouter.namespace(|| "compute apex leaf from merkle proof"),
                challenge_bits_to_apex_leaf,
                label_d_new.clone(),
                path_to_apex_leaf,
            )?;
            layouter.assign_region(
                || "check apex_leaf_calc",
                |mut region| region.constrain_equal(apex_leaf_calc.cell(), apex_leaf.cell()),
            )?;
        }

        Ok(())
    }

    fn synthesize_halo2_partitioning(
        &self,
        config: <Self as Circuit<F>>::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let EmptySectorUpdateCircuit {
            pub_inputs,
            priv_inputs,
        } = self;

        let challenge_count = challenge_count(SECTOR_NODES);
        assert_eq!(challenge_count, 1);

        let partition_bit_len = partition_bit_len(SECTOR_NODES);
        assert_eq!(partition_bit_len, 0);

        assert_eq!(pub_inputs.partition_bits.len(), partition_bit_len);
        assert_eq!(pub_inputs.challenges.len(), challenge_count);
        assert_eq!(pub_inputs.rhos.len(), challenge_count);

        assert!(priv_inputs.apex_leafs.is_empty());
        assert_eq!(priv_inputs.challenge_proofs.len(), challenge_count);

        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;

        let (
            tree_d_merkle_chip,
            tree_r_merkle_chip,
            poseidon_2_chip,
            apex_tree_chip,
            select_chip,
            challenge_labels_chip,
        ) = config.create_chips(&mut layouter)?;

        assert!(apex_tree_chip.is_none() && select_chip.is_none());

        let advice = config.advice;
        let pi_col = config.pi;

        // Assign initial values.
        let (comm_c, root_r_old, root_r_new) = layouter.assign_region(
            || "assign comm_c, root_r_old, and root_r_new",
            |mut region| {
                let mut advice_iter = AdviceIter::from(advice.clone());

                let comm_c = {
                    let (offset, col) = advice_iter.next();
                    region.assign_advice(|| "comm_c", col, offset, || priv_inputs.comm_c)?
                };

                let root_r_old = {
                    let (offset, col) = advice_iter.next();
                    region.assign_advice(|| "root_r_old", col, offset, || priv_inputs.root_r_old)?
                };

                let root_r_new = {
                    let (offset, col) = advice_iter.next();
                    region.assign_advice(|| "root_r_new", col, offset, || priv_inputs.root_r_new)?
                };

                Ok((comm_c, root_r_old, root_r_new))
            },
        )?;

        let poseidon_2_consts = get_poseidon_constants::<F, U2>();

        // Compute `comm_r_old = H(comm_c, root_r_old)`.
        let comm_r_old = poseidon_2_chip.hash(
            layouter.namespace(|| "calculate comm_r_old"),
            &[comm_c.clone(), root_r_old.clone()],
            poseidon_2_consts,
        )?;

        // Compute `comm_r_new = H(comm_c, root_r_new)`.
        let comm_r_new = poseidon_2_chip.hash(
            layouter.namespace(|| "calculate comm_r_new"),
            &[comm_c, root_r_new.clone()],
            poseidon_2_consts,
        )?;

        // Constrain witnessed commitments with public inputs.
        layouter.constrain_instance(comm_r_old.cell(), pi_col, COMM_R_OLD_ROW)?;
        layouter.constrain_instance(comm_r_new.cell(), pi_col, COMM_R_NEW_ROW)?;

        let challenge_proof = &priv_inputs.challenge_proofs[0];

        // Compute challenge's label using public rho.
        let (label_r_old, label_d_new, label_r_new) = challenge_labels_chip.assign_labels(
            layouter.namespace(|| "challenge labels"),
            challenge_proof.leaf_r_old,
            challenge_proof.leaf_d_new,
            challenge_proof.leaf_r_new,
            pi_col,
            rho_row(0, challenge_bit_len, partition_bit_len),
        )?;

        // Check challenge's TreeROld merkle proof.
        let root_r_old_calc = tree_r_merkle_chip.compute_root_assigned_leaf_pi_bits(
            layouter.namespace(|| "compute root_r_old from merkle proof"),
            label_r_old,
            &challenge_proof.path_r_old,
            pi_col,
            challenge_bits_rows(0, challenge_bit_len, partition_bit_len),
        )?;
        layouter.assign_region(
            || "check root_r_old_calc",
            |mut region| region.constrain_equal(root_r_old_calc.cell(), root_r_old.cell()),
        )?;

        // Check challenge's TreeDNew merkle proof.
        let comm_d_new_calc = tree_d_merkle_chip.compute_root_assigned_leaf_pi_bits(
            layouter.namespace(|| "compute comm_d_new from merkle proof"),
            label_d_new,
            &challenge_proof.path_d_new,
            pi_col,
            challenge_bits_rows(0, challenge_bit_len, partition_bit_len),
        )?;
        layouter.constrain_instance(comm_d_new_calc.cell(), pi_col, COMM_D_NEW_ROW)?;

        // Check challenge's TreeRNew merkle proof.
        let root_r_new_calc = tree_r_merkle_chip.compute_root_assigned_leaf_pi_bits(
            layouter.namespace(|| "compute root_r_new from merkle proof"),
            label_r_new,
            &challenge_proof.path_r_new,
            pi_col,
            challenge_bits_rows(0, challenge_bit_len, partition_bit_len),
        )?;
        layouter.assign_region(
            || "check root_r_new_calc",
            |mut region| region.constrain_equal(root_r_new_calc.cell(), root_r_new.cell()),
        )?;

        Ok(())
    }

    // Same as `Circuit::without_witnesses` except this associated function does not take `&self`.
    pub fn blank_circuit() -> Self {
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;
        let partition_bit_len = partition_bit_len(SECTOR_NODES);
        let challenge_sans_partition_bit_len = challenge_bit_len - partition_bit_len;
        let challenge_count = challenge_count(SECTOR_NODES);
        let apex_leaf_count = apex_leaf_count(SECTOR_NODES);

        EmptySectorUpdateCircuit {
            pub_inputs: PublicInputs {
                comm_r_old: None,
                comm_d_new: None,
                comm_r_new: None,
                partition_bits: vec![None; partition_bit_len],
                challenges: vec![vec![None; challenge_sans_partition_bit_len]; challenge_count],
                rhos: vec![None; challenge_count],
            },
            priv_inputs: PrivateInputs {
                comm_c: Value::unknown(),
                root_r_old: Value::unknown(),
                root_r_new: Value::unknown(),
                apex_leafs: vec![Value::unknown(); apex_leaf_count],
                challenge_proofs: vec![ChallengeProof::empty(); challenge_count],
            },
        }
    }

    pub fn compute_k(k_start: Option<u32>) -> u32 {
        use generic_array::typenum::U0;
        use halo2_proofs::dev::MockProver;

        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;
        let partition_bit_len = partition_bit_len(SECTOR_NODES);
        let challenge_sans_partition_bit_len = challenge_bit_len - partition_bit_len;
        let challenge_count = challenge_count(SECTOR_NODES);
        let apex_leaf_count = apex_leaf_count(SECTOR_NODES);

        let pub_inputs = PublicInputs {
            comm_r_old: Some(F::zero()),
            comm_d_new: Some(F::zero()),
            comm_r_new: Some(F::zero()),
            partition_bits: vec![Some(false); partition_bit_len],
            challenges: vec![vec![Some(false); challenge_sans_partition_bit_len]; challenge_count],
            rhos: vec![Some(F::zero()); challenge_count],
        };
        let pub_inputs_vec = pub_inputs.to_vec();

        let priv_inputs = {
            let mut path_d = por::empty_path::<F, U2, U0, U0, SECTOR_NODES>();
            let mut path_r = por::empty_path::<F, U, V, W, SECTOR_NODES>();
            for sibs in path_d.iter_mut().chain(path_r.iter_mut()) {
                *sibs = vec![Value::known(F::zero()); sibs.len()];
            }

            let challenge_proof = ChallengeProof {
                leaf_r_old: Value::known(F::zero()),
                path_r_old: path_r.clone(),
                leaf_d_new: Value::known(F::zero()),
                path_d_new: path_d,
                leaf_r_new: Value::known(F::zero()),
                path_r_new: path_r,
                _tree_r: PhantomData,
            };

            PrivateInputs {
                comm_c: Value::known(F::zero()),
                root_r_old: Value::known(F::zero()),
                root_r_new: Value::known(F::zero()),
                apex_leafs: vec![Value::known(F::zero()); apex_leaf_count],
                challenge_proofs: vec![challenge_proof; challenge_count],
            }
        };

        let circ = EmptySectorUpdateCircuit::<F, U, V, W, SECTOR_NODES> {
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

#[test]
#[ignore]
fn get_k() {
    use generic_array::typenum::{U0, U4, U8};
    use halo2_proofs::pasta::Fp;

    let mut k = EmptySectorUpdateCircuit::<Fp, U8, U4, U0, SECTOR_NODES_1_KIB>::compute_k(None);
    println!("Found k = {} (sector-size = 1kib)", k);

    k = EmptySectorUpdateCircuit::<Fp, U8, U0, U0, SECTOR_NODES_2_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 2kib)", k);

    k = EmptySectorUpdateCircuit::<Fp, U8, U2, U0, SECTOR_NODES_4_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 4kib)", k);

    k = EmptySectorUpdateCircuit::<Fp, U8, U4, U0, SECTOR_NODES_8_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 8kib)", k);

    k = EmptySectorUpdateCircuit::<Fp, U8, U8, U0, SECTOR_NODES_16_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 16kib)", k);

    k = EmptySectorUpdateCircuit::<Fp, U8, U8, U2, SECTOR_NODES_32_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 32kib)", k);

    k = EmptySectorUpdateCircuit::<Fp, U8, U0, U0, SECTOR_NODES_8_MIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 8mib)", k);

    k = EmptySectorUpdateCircuit::<Fp, U8, U2, U0, SECTOR_NODES_16_MIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 16mib)", k);

    k = EmptySectorUpdateCircuit::<Fp, U8, U0, U0, SECTOR_NODES_512_MIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 512mib)", k);

    k = EmptySectorUpdateCircuit::<Fp, U8, U8, U0, SECTOR_NODES_32_GIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 32gib)", k);

    k = EmptySectorUpdateCircuit::<Fp, U8, U8, U2, SECTOR_NODES_64_GIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 64gib)", k);
}
