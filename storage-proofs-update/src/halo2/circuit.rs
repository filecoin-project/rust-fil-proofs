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
};

use crate::{
    constants::{
        apex_leaf_count, challenge_count, partition_count, validate_tree_r_shape, TreeDArity,
        TreeDHasher, TreeRHasher, SECTOR_SIZE_16_KIB, SECTOR_SIZE_16_MIB, SECTOR_SIZE_1_KIB,
        SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_GIB, SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB,
        SECTOR_SIZE_512_MIB, SECTOR_SIZE_64_GIB, SECTOR_SIZE_8_KIB, SECTOR_SIZE_8_MIB,
    },
    gen_partition_challenges, gen_partition_rhos,
    halo2::gadgets::{
        ApexTreeChip, ChallengeBitsChip, ChallengeBitsConfig, ChallengeLabelsChip,
        ChallengeLabelsConfig,
    },
    phi, vanilla,
};

pub const EMPTY_SECTOR_UPDATE_CIRCUIT_ID: &str = "empty-sector-update-circuit";

trait CircuitParams<const SECTOR_NODES: usize> {
    const PARTITION_COUNT: usize = partition_count(SECTOR_NODES);
    const PARTITION_BIT_LEN: usize = Self::PARTITION_COUNT.trailing_zeros() as usize;
    const APEX_LEAF_COUNT: usize = apex_leaf_count(SECTOR_NODES);
    const APEX_LEAF_BIT_LEN: usize = Self::APEX_LEAF_COUNT.trailing_zeros() as usize;
    const CHALLENGE_COUNT: usize = challenge_count(SECTOR_NODES);
    const CHALLENGE_BIT_LEN: usize = SECTOR_NODES.trailing_zeros() as usize;
    const CHALLENGE_SANS_PARTITION_BIT_LEN: usize =
        Self::CHALLENGE_BIT_LEN - Self::PARTITION_BIT_LEN;
    const CHALLENGE_TO_APEX_LEAF_BIT_LEN: usize =
        Self::CHALLENGE_SANS_PARTITION_BIT_LEN - Self::APEX_LEAF_BIT_LEN;
    const PARTITION_BITS_ROWS: Range<usize> = 0..Self::PARTITION_BIT_LEN;
    const COMM_R_OLD_ROW: usize = Self::PARTITION_BIT_LEN;
    const COMM_D_NEW_ROW: usize = Self::COMM_R_OLD_ROW + 1;
    const COMM_R_NEW_ROW: usize = Self::COMM_D_NEW_ROW + 1;
    const FIRST_CHALLENGE_ROW: usize = Self::COMM_R_NEW_ROW + 1;
    const FIRST_RHO_ROW: usize = Self::FIRST_CHALLENGE_ROW + Self::CHALLENGE_COUNT;

    #[inline]
    fn challenge_row(challenge_index: usize) -> usize {
        Self::FIRST_CHALLENGE_ROW + challenge_index
    }

    #[inline]
    fn challenge_rho_row(challenge_index: usize) -> usize {
        Self::FIRST_RHO_ROW + challenge_index
    }
}

#[derive(Clone)]
pub struct PublicInputs<F: FieldExt, const SECTOR_NODES: usize> {
    partition_bits: Vec<Option<bool>>,
    comm_r_old: Option<F>,
    comm_d_new: Option<F>,
    comm_r_new: Option<F>,
    challenges: Vec<Option<u32>>,
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
        let partition_bit_len = partition_count.trailing_zeros() as usize;
        let partition_bits = (0..partition_bit_len)
            .map(|i| Some(k >> i & 1 == 1))
            .collect();

        let challenge_count = challenge_count(SECTOR_NODES);
        assert_eq!(challenges.len(), challenge_count);
        assert_eq!(rhos.len(), challenge_count);

        // Strip the partition index from each challenge.
        let challenge_bit_len = SECTOR_NODES.trailing_zeros() as usize;
        let challenge_sans_partition_bit_len = challenge_bit_len - partition_bit_len;
        let strip_partition_mask = (1u32 << challenge_sans_partition_bit_len) - 1;
        let challenges = challenges
            .iter()
            .map(|c| Some(c & strip_partition_mask))
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

    pub fn to_vec(&self) -> Vec<Vec<F>> {
        assert!(
            self.partition_bits.iter().all(Option::is_some)
                && self.comm_r_old.is_some()
                && self.comm_d_new.is_some()
                && self.comm_r_new.is_some()
                && self.challenges.iter().all(Option::is_some)
                && self.rhos.iter().all(Option::is_some),
            "all public inputs must contain a value before converting into a vector",
        );

        let num_pub_inputs = self.partition_bits.len() + 2 * self.challenges.len() + 3;

        let mut pub_inputs = Vec::<F>::with_capacity(num_pub_inputs);

        for bit in self.partition_bits.iter() {
            if bit.unwrap() {
                pub_inputs.push(F::one())
            } else {
                pub_inputs.push(F::zero())
            }
        }

        pub_inputs.push(self.comm_r_old.unwrap());
        pub_inputs.push(self.comm_d_new.unwrap());
        pub_inputs.push(self.comm_r_new.unwrap());

        for challenge in self.challenges.iter() {
            pub_inputs.push(F::from(challenge.unwrap() as u64));
        }

        for rho in self.rhos.iter() {
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
        // TODO (jake):
        /*
        let path_r = {
            let base_arity = U::to_usize();
            let sub_arity = V::to_usize();
            let top_arity = W::to_usize();

            let mut bits_remaining = challenge_bit_len;
            let mut sub_and_top_path = vec![];

            if sub_arity > 0 {
                sub_and_top_path.push(vec![Value::unknown(); sub_arity - 1]);
                bits_remaining -= sub_arity.trailing_zeros() as usize;
            };

            if top_arity > 0 {
                sub_and_top_path.push(vec![Value::unknown(); top_arity - 1]);
                bits_remaining -= top_arity.trailing_zeros() as usize;
            };

            let base_path_len = bits_remaining / base_arity.trailing_zeros() as usize;
            let base_path = vec![vec![Value::unknown(); base_arity - 1]; base_path_len];

            [base_path, sub_and_top_path].concat()
        };
        */
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
    select: SelectConfig<F>,
    challenge_bits: ChallengeBitsConfig<F, SECTOR_NODES>,
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
    fn create_chips(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<
        (
            MerkleChip<TreeDHasher<F>, TreeDArity>,
            MerkleChip<TreeRHasher<F>, U, V, W>,
            <TreeRHasher<F> as Halo2Hasher<U2>>::Chip,
            ApexTreeChip<F>,
            SelectChip<F>,
            ChallengeBitsChip<F, SECTOR_NODES>,
            ChallengeLabelsChip<F>,
        ),
        Error,
    > {
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

        let apex_tree_chip = {
            let sha256_2_chip =
                <TreeDHasher<F> as Halo2Hasher<TreeDArity>>::construct(self.sha256_2.clone());
            ApexTreeChip::with_subchips(sha256_2_chip)
        };

        let select_chip = SelectChip::construct(self.select.clone());
        let challenge_bits_chip = ChallengeBitsChip::construct(self.challenge_bits.clone());
        let challenge_labels_chip = ChallengeLabelsChip::construct(self.challenge_labels.clone());

        Ok((
            tree_d_merkle_chip,
            tree_r_merkle_chip,
            poseidon_2_chip,
            apex_tree_chip,
            select_chip,
            challenge_bits_chip,
            challenge_labels_chip,
        ))
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> CircuitParams<SECTOR_NODES>
    for EmptySectorUpdateCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
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
            por::change_hasher_insert_arity::<TreeRHasher<F>, U2, U>(
                poseidon_2.clone(),
                insert_2.clone(),
            )
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
            Some(por::change_hasher_insert_arity::<TreeRHasher<F>, U2, V>(
                poseidon_2.clone(),
                insert_2.clone(),
            ))
        } else if sub_arity == base_arity {
            Some(por::change_hasher_insert_arity::<TreeRHasher<F>, U, V>(
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
            Some(por::change_hasher_insert_arity::<TreeRHasher<F>, U2, W>(
                poseidon_2.clone(),
                insert_2.clone(),
            ))
        } else if top_arity == base_arity {
            Some(por::change_hasher_insert_arity::<TreeRHasher<F>, U, W>(
                poseidon_base.clone(),
                insert_base.clone(),
            ))
        } else if top_arity == sub_arity {
            let (poseidon_sub, insert_sub) = sub.clone().unwrap();
            Some(por::change_hasher_insert_arity::<TreeRHasher<F>, V, W>(
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

        let select = SelectChip::configure(meta, advice_eq[..4].try_into().unwrap());

        let challenge_bits = ChallengeBitsChip::configure(meta, &advice_eq);

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
            challenge_bits,
            challenge_labels,
            advice: advice_eq,
            pi,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        validate_tree_r_shape::<U, V, W>(SECTOR_NODES);

        let EmptySectorUpdateCircuit {
            pub_inputs,
            priv_inputs,
        } = self;

        assert_eq!(pub_inputs.partition_bits.len(), Self::PARTITION_BIT_LEN);
        assert_eq!(pub_inputs.challenges.len(), Self::CHALLENGE_COUNT);
        assert_eq!(pub_inputs.rhos.len(), Self::CHALLENGE_COUNT);

        // Check that `k` is valid for the sector-size.
        if pub_inputs.partition_bits.iter().all(Option::is_some) {
            let k: usize = pub_inputs
                .partition_bits
                .iter()
                .enumerate()
                .map(|(i, bit)| usize::from(bit.unwrap()) << i)
                .sum();
            assert!(
                k < Self::PARTITION_COUNT,
                "partition-index exceeds partition count",
            );
        }

        assert_eq!(priv_inputs.apex_leafs.len(), Self::APEX_LEAF_COUNT);
        assert_eq!(priv_inputs.challenge_proofs.len(), Self::CHALLENGE_COUNT);

        let partition_path = priv_inputs.challenge_proofs[0].path_d_new
            [Self::CHALLENGE_SANS_PARTITION_BIT_LEN..]
            .to_vec();

        assert_eq!(partition_path.len(), Self::PARTITION_BIT_LEN);
        assert!(partition_path.iter().all(|siblings| siblings.len() == 1));

        // Check that all partition challenge's have the same same partition path.
        for challenge_proof in &priv_inputs.challenge_proofs[1..] {
            let challenge_partition_path =
                &challenge_proof.path_d_new[Self::CHALLENGE_SANS_PARTITION_BIT_LEN..];

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
            challenge_bits_chip,
            challenge_labels_chip,
        ) = config.create_chips(&mut layouter)?;

        let advice = config.advice;
        let pi_col = config.pi;

        // Assign initial values.
        let (partition_bits, comm_c, root_r_old, root_r_new, apex_leafs) = layouter.assign_region(
            || "witness partition_bits, comm_c, root_r_old, root_r_new, apex_leafs",
            |mut region| {
                let mut advice_iter = AdviceIter::from(advice.clone());

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
                            || format!("partition_bit_{}", i),
                            col,
                            offset,
                            || bit.map(Bit),
                        )
                    })
                    .collect::<Result<Vec<AssignedBit<F>>, Error>>()?;

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

                Ok((partition_bits, comm_c, root_r_old, root_r_new, apex_leafs))
            },
        )?;

        // Constrain partition bits with public inputs.
        for (bit, pi_row) in partition_bits.iter().zip(Self::PARTITION_BITS_ROWS) {
            layouter.constrain_instance(bit.cell(), pi_col, pi_row)?;
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
        let comm_d_new = if Self::PARTITION_COUNT == 1 {
            apex_root
        } else {
            tree_d_merkle_chip.copy_leaf_compute_root(
                layouter.namespace(|| "calculate comm_d_new"),
                &partition_bits,
                &apex_root,
                &partition_path,
            )?
        };

        // Constrain witnessed commitments with public inputs.
        layouter.constrain_instance(comm_r_old.cell(), pi_col, Self::COMM_R_OLD_ROW)?;
        layouter.constrain_instance(comm_d_new.cell(), pi_col, Self::COMM_D_NEW_ROW)?;
        layouter.constrain_instance(comm_r_new.cell(), pi_col, Self::COMM_R_NEW_ROW)?;

        // Decompose public challenges into bits.
        let challenges_bits = (0..Self::CHALLENGE_COUNT)
            .map(|i| {
                challenge_bits_chip.decompose(
                    layouter.namespace(|| format!("decompose challenge {}", i)),
                    pi_col,
                    Self::challenge_row(i),
                )
            })
            .collect::<Result<Vec<Vec<AssignedBit<F>>>, Error>>()?;

        for (i, (challenge_bits, challenge_proof)) in challenges_bits
            .iter()
            .zip(priv_inputs.challenge_proofs.iter())
            .enumerate()
        {
            let (label_r_old, label_d_new, label_r_new) = challenge_labels_chip.assign_labels(
                layouter.namespace(|| format!("challenge {} labels", i)),
                challenge_proof.leaf_r_old,
                challenge_proof.leaf_d_new,
                challenge_proof.leaf_r_new,
                pi_col,
                Self::challenge_rho_row(i),
            )?;

            let challenge_and_partition_bits: Vec<AssignedBit<F>> = challenge_bits
                .iter()
                .chain(partition_bits.iter())
                .cloned()
                .collect();

            let root_r_old_calc = tree_r_merkle_chip.copy_leaf_compute_root(
                layouter
                    .namespace(|| format!("compute root_r_old from challenge {} merkle proof", i)),
                &challenge_and_partition_bits,
                &label_r_old,
                &challenge_proof.path_r_old,
            )?;
            layouter.assign_region(
                || format!("check challenge {} root_r_old_calc", i),
                |mut region| region.constrain_equal(root_r_old.cell(), root_r_old_calc.cell()),
            )?;

            let root_r_new_calc = tree_r_merkle_chip.copy_leaf_compute_root(
                layouter
                    .namespace(|| format!("compute root_r_new from challenge {} merkle proof", i)),
                &challenge_and_partition_bits,
                &label_r_new,
                &challenge_proof.path_r_new,
            )?;
            layouter.assign_region(
                || format!("check challenge {} root_r_new_calc", i),
                |mut region| region.constrain_equal(root_r_new.cell(), root_r_new_calc.cell()),
            )?;

            let (challenge_bits_to_apex_leaf, apex_leaf_bits) =
                challenge_bits.split_at(Self::CHALLENGE_TO_APEX_LEAF_BIT_LEN);

            let apex_leaf = select_chip.select(
                layouter.namespace(|| format!("select apex leaf for challenge {}", i)),
                &apex_leafs,
                apex_leaf_bits,
            )?;

            let path_to_apex_leaf =
                &challenge_proof.path_d_new[..Self::CHALLENGE_TO_APEX_LEAF_BIT_LEN];

            let apex_leaf_calc = tree_d_merkle_chip.copy_leaf_compute_root(
                layouter
                    .namespace(|| format!("compute apex leaf from challenge {} merkle proof", i)),
                challenge_bits_to_apex_leaf,
                &label_d_new,
                path_to_apex_leaf,
            )?;
            layouter.assign_region(
                || format!("check challenge {} apex_leaf_calc", i),
                |mut region| region.constrain_equal(apex_leaf.cell(), apex_leaf_calc.cell()),
            )?;
        }

        Ok(())
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
        match SECTOR_NODES {
            SECTOR_SIZE_1_KIB => 17,
            SECTOR_SIZE_2_KIB => 18,
            SECTOR_SIZE_4_KIB => 18,
            SECTOR_SIZE_8_KIB => 18,
            SECTOR_SIZE_16_KIB => 20,
            SECTOR_SIZE_32_KIB => 20,
            SECTOR_SIZE_8_MIB => 20,
            SECTOR_SIZE_16_MIB => 20,
            SECTOR_SIZE_512_MIB => 23,
            SECTOR_SIZE_32_GIB => 23,
            SECTOR_SIZE_64_GIB => 23,
            _ => unreachable!(),
        }
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
    // Same as `Circuit::without_witnesses` except this associated function does not take `&self`.
    pub fn blank_circuit() -> Self {
        let partition_count = partition_count(SECTOR_NODES);
        let partition_bit_len = partition_count.trailing_zeros() as usize;
        let challenge_count = challenge_count(SECTOR_NODES);
        let apex_leaf_count = apex_leaf_count(SECTOR_NODES);

        EmptySectorUpdateCircuit {
            pub_inputs: PublicInputs {
                partition_bits: vec![None; partition_bit_len],
                comm_r_old: None,
                comm_d_new: None,
                comm_r_new: None,
                challenges: vec![None; challenge_count],
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
}
