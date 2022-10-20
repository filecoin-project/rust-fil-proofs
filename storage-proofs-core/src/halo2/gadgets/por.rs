use std::ops::Range;

use fil_halo2_gadgets::{
    boolean::{AssignedBit, Bit},
    MaybeAssigned,
};
use filecoin_hashers::{Halo2Hasher, HashInstructions, PoseidonArity};
use generic_array::typenum::U0;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Column, Error, Instance},
};

use crate::halo2::gadgets::{
    insert::{InsertChip, InsertConfig},
    shift::ShiftChip,
};

pub struct MerkleChip<H, U, V = U0, W = U0>
where
    H: Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
    H::Field: FieldExt,
    U: PoseidonArity<H::Field>,
    V: PoseidonArity<H::Field>,
    W: PoseidonArity<H::Field>,
{
    base_hasher: <H as Halo2Hasher<U>>::Chip,
    base_insert: InsertChip<H::Field, U>,
    sub_hasher_insert: Option<(<H as Halo2Hasher<V>>::Chip, InsertChip<H::Field, V>)>,
    top_hasher_insert: Option<(<H as Halo2Hasher<W>>::Chip, InsertChip<H::Field, W>)>,
}

impl<H, U, V, W> MerkleChip<H, U, V, W>
where
    H: Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
    H::Field: FieldExt,
    U: PoseidonArity<H::Field>,
    V: PoseidonArity<H::Field>,
    W: PoseidonArity<H::Field>,
{
    pub fn with_subchips(
        base_hasher: <H as Halo2Hasher<U>>::Chip,
        base_insert: InsertChip<H::Field, U>,
        sub_hasher_insert: Option<(<H as Halo2Hasher<V>>::Chip, InsertChip<H::Field, V>)>,
        top_hasher_insert: Option<(<H as Halo2Hasher<W>>::Chip, InsertChip<H::Field, W>)>,
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

    pub fn compute_root_unassigned_leaf(
        &self,
        layouter: impl Layouter<H::Field>,
        challenge_bits: &[AssignedBit<H::Field>],
        leaf: Value<H::Field>,
        path: &[Vec<Value<H::Field>>],
    ) -> Result<AssignedCell<H::Field, H::Field>, Error> {
        let leaf = leaf.into();
        let bits: Vec<MaybeAssigned<Bit, H::Field>> =
            challenge_bits.iter().cloned().map(Into::into).collect();
        self.compute_root_inner(layouter, &bits, leaf, path)
    }

    pub fn compute_root_assigned_leaf(
        &self,
        layouter: impl Layouter<H::Field>,
        challenge_bits: &[AssignedBit<H::Field>],
        leaf: AssignedCell<H::Field, H::Field>,
        path: &[Vec<Value<H::Field>>],
    ) -> Result<AssignedCell<H::Field, H::Field>, Error> {
        let leaf = leaf.into();
        let bits: Vec<MaybeAssigned<Bit, H::Field>> =
            challenge_bits.iter().cloned().map(Into::into).collect();
        self.compute_root_inner(layouter, &bits, leaf, path)
    }

    pub fn compute_root_unassigned_leaf_pi_bits(
        &self,
        layouter: impl Layouter<H::Field>,
        leaf: Value<H::Field>,
        path: &[Vec<Value<H::Field>>],
        pi_col: Column<Instance>,
        pi_rows: Range<usize>,
    ) -> Result<AssignedCell<H::Field, H::Field>, Error> {
        let leaf = leaf.into();
        let bits: Vec<MaybeAssigned<Bit, H::Field>> = pi_rows
            .map(|pi_row| MaybeAssigned::Pi(pi_col, pi_row))
            .collect();
        self.compute_root_inner(layouter, &bits, leaf, path)
    }

    pub fn compute_root_assigned_leaf_pi_bits(
        &self,
        layouter: impl Layouter<H::Field>,
        leaf: AssignedCell<H::Field, H::Field>,
        path: &[Vec<Value<H::Field>>],
        pi_col: Column<Instance>,
        pi_rows: Range<usize>,
    ) -> Result<AssignedCell<H::Field, H::Field>, Error> {
        let leaf = leaf.into();
        let bits: Vec<MaybeAssigned<Bit, H::Field>> = pi_rows
            .map(|pi_row| MaybeAssigned::Pi(pi_col, pi_row))
            .collect();
        self.compute_root_inner(layouter, &bits, leaf, path)
    }

    fn compute_root_inner(
        &self,
        mut layouter: impl Layouter<H::Field>,
        challenge_bits: &[MaybeAssigned<Bit, H::Field>],
        leaf: MaybeAssigned<H::Field, H::Field>,
        path: &[Vec<Value<H::Field>>],
    ) -> Result<AssignedCell<H::Field, H::Field>, Error> {
        let base_arity = U::to_usize();
        let sub_arity = V::to_usize();
        let top_arity = W::to_usize();

        let base_arity_bit_len = base_arity.trailing_zeros();

        let base_path_len = if top_arity > 0 {
            path.len() - 2
        } else if sub_arity > 0 {
            path.len() - 1
        } else {
            path.len()
        };

        let mut cur = leaf;
        let mut height = 0;
        let mut path = path.iter();
        let mut challenge_bits = challenge_bits.iter();

        for _ in 0..base_path_len {
            let siblings = path.next().expect("no path elements remaining");

            assert_eq!(
                siblings.len(),
                base_arity - 1,
                "path element has incorrect number of siblings"
            );

            let index_bits: Vec<MaybeAssigned<Bit, H::Field>> = (0..base_arity_bit_len)
                .map(|_| challenge_bits.next().expect("no challenge bits remaining"))
                .cloned()
                .collect();

            let preimage = self.base_insert.insert_inner(
                layouter.namespace(|| format!("base insert (height {})", height)),
                siblings.as_slice(),
                cur.clone(),
                &index_bits,
            )?;

            cur = self
                .base_hasher
                .hash(
                    layouter.namespace(|| format!("base hash (height {})", height)),
                    &preimage,
                )?
                .into();

            height += 1;
        }

        if sub_arity != 0 {
            let siblings = path.next().expect("no path elements remaining");

            assert_eq!(
                siblings.len(),
                sub_arity - 1,
                "path element has incorrect number of siblings"
            );

            let sub_arity_bit_len = sub_arity.trailing_zeros();
            let index_bits: Vec<MaybeAssigned<Bit, H::Field>> = (0..sub_arity_bit_len)
                .map(|_| challenge_bits.next().expect("no challenge bits remaining"))
                .cloned()
                .collect();

            let (sub_hasher, sub_insert) =
                self.sub_hasher_insert.as_ref().expect("sub chips not set");

            let preimage = sub_insert.insert_inner(
                layouter.namespace(|| format!("sub insert (height {})", height)),
                siblings.as_slice(),
                cur.clone(),
                &index_bits,
            )?;

            cur = sub_hasher
                .hash(
                    layouter.namespace(|| format!("sub hash (height {})", height)),
                    &preimage,
                )?
                .into();

            height += 1;
        }

        if top_arity != 0 {
            let siblings = path.next().expect("no path elements remaining");

            assert_eq!(
                siblings.len(),
                top_arity - 1,
                "path element has incorrect number of siblings"
            );

            let top_arity_bit_len = top_arity.trailing_zeros();
            let index_bits: Vec<MaybeAssigned<Bit, H::Field>> = (0..top_arity_bit_len)
                .map(|_| challenge_bits.next().expect("no challenge bits remaining"))
                .cloned()
                .collect();

            let (top_hasher, top_insert) =
                self.top_hasher_insert.as_ref().expect("top chips not set");

            let preimage = top_insert.insert_inner(
                layouter.namespace(|| format!("top insert (height {})", height)),
                siblings.as_slice(),
                cur.clone(),
                &index_bits,
            )?;

            cur = top_hasher
                .hash(
                    layouter.namespace(|| format!("top hash (height {})", height)),
                    &preimage,
                )?
                .into();
        }

        // Check that any remaining challenge bits are zero.
        assert!(challenge_bits.all(|bit| {
            let mut bit_is_zero = true;
            match bit {
                MaybeAssigned::Unassigned(ref bit) => {
                    bit.map(|bit| bit_is_zero = !bool::from(bit));
                }
                MaybeAssigned::Assigned(ref bit) => {
                    bit.value().map(|bit| bit_is_zero = !bool::from(bit));
                }
                // If challenge bits are public inputs, there should be no bits remaining.
                MaybeAssigned::Pi(..) => {
                    bit_is_zero = false;
                }
            };
            bit_is_zero
        }));
        assert!(path.next().is_none());

        Ok(cur.into())
    }
}

pub fn empty_path<F, U, V, W, const NUM_LEAFS: usize>() -> Vec<Vec<Value<F>>>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
{
    let base_arity = U::to_usize();
    let sub_arity = V::to_usize();
    let top_arity = W::to_usize();

    let challenge_bit_len = NUM_LEAFS.trailing_zeros() as usize;

    let base_height = {
        let mut base_challenge_bit_len = challenge_bit_len;
        if sub_arity != 0 {
            base_challenge_bit_len -= sub_arity.trailing_zeros() as usize;
        }
        if top_arity != 0 {
            base_challenge_bit_len -= top_arity.trailing_zeros() as usize;
        }
        base_challenge_bit_len / (base_arity.trailing_zeros() as usize)
    };

    let mut path = vec![vec![Value::unknown(); base_arity - 1]; base_height];
    if sub_arity != 0 {
        path.push(vec![Value::unknown(); sub_arity - 1]);
    }
    if top_arity != 0 {
        path.push(vec![Value::unknown(); top_arity - 1]);
    }

    path
}

// Changes the chip configs' arities from `A` to `B`. This is safe only when arities `A` and `B`
// are known to have the same constraint system configuration.
#[inline]
pub fn transmute_arity<H, A, B>(
    hasher_config: <H as Halo2Hasher<A>>::Config,
    insert_config: InsertConfig<H::Field, A>,
) -> (<H as Halo2Hasher<B>>::Config, InsertConfig<H::Field, B>)
where
    H::Field: FieldExt,
    H: Halo2Hasher<A> + Halo2Hasher<B>,
    A: PoseidonArity<H::Field>,
    B: PoseidonArity<H::Field>,
{
    (
        <H as Halo2Hasher<A>>::transmute_arity::<B>(hasher_config),
        insert_config.transmute_arity::<B>(),
    )
}

// Returns `(base_path_len, has_sub_path, has_top_path)`.
pub fn path_lens(
    num_leafs: usize,
    base_arity: usize,
    sub_arity: usize,
    top_arity: usize,
) -> (usize, bool, bool) {
    let has_sub_path = sub_arity != 0;
    let has_top_path = top_arity != 0;

    let mut base_bits = num_leafs.trailing_zeros() as usize;
    if has_sub_path {
        base_bits -= sub_arity.trailing_zeros() as usize;
    }
    if has_top_path {
        base_bits -= top_arity.trailing_zeros() as usize;
    }
    let base_arity_bit_len = base_arity.trailing_zeros() as usize;
    assert_eq!(base_bits % base_arity_bit_len, 0);
    let base_path_len = base_bits / base_arity_bit_len;

    (base_path_len, has_sub_path, has_top_path)
}

#[allow(clippy::unwrap_used)]
pub fn challenge_to_shift_bits(
    challenge: usize,
    num_leafs: usize,
    base_arity: usize,
    sub_arity: usize,
    top_arity: usize,
) -> Vec<bool> {
    use std::iter;

    let challenge_bit_len = num_leafs.trailing_zeros() as usize;
    let mut challenge_bits = (0..challenge_bit_len).map(|i| challenge >> i & 1 == 1);

    let (base_path_len, has_sub_path, has_top_path) =
        path_lens(num_leafs, base_arity, sub_arity, top_arity);

    let base_arity_bit_len = base_arity.trailing_zeros() as usize;
    let base_shift_bit_len = base_arity - 1;

    let mut shift_bits = vec![];

    for _ in 0..base_path_len {
        let insert_index = (0..base_arity_bit_len).fold(0, |acc, i| {
            let bit = challenge_bits.next().unwrap() as usize;
            acc + (bit << i)
        });
        iter::repeat(true)
            .take(insert_index)
            .chain(iter::repeat(false))
            .take(base_shift_bit_len)
            .for_each(|bit| shift_bits.push(bit));
    }

    if has_sub_path {
        let sub_arity_bit_len = sub_arity.trailing_zeros() as usize;
        let sub_shift_bit_len = sub_arity - 1;
        let insert_index = (0..sub_arity_bit_len).fold(0, |acc, i| {
            let bit = challenge_bits.next().unwrap() as usize;
            acc + (bit << i)
        });
        iter::repeat(true)
            .take(insert_index)
            .chain(iter::repeat(false))
            .take(sub_shift_bit_len)
            .for_each(|bit| shift_bits.push(bit));
    }

    if has_top_path {
        let top_arity_bit_len = top_arity.trailing_zeros() as usize;
        let top_shift_bit_len = top_arity - 1;
        let insert_index = (0..top_arity_bit_len).fold(0, |acc, i| {
            let bit = challenge_bits.next().unwrap() as usize;
            acc + (bit << i)
        });
        iter::repeat(true)
            .take(insert_index)
            .chain(iter::repeat(false))
            .take(top_shift_bit_len)
            .for_each(|bit| shift_bits.push(bit));
    }

    assert!(challenge_bits.next().is_none());
    shift_bits
}

#[allow(clippy::unwrap_used)]
pub fn shift_bits_to_challenge(
    challenge_shift_bits: &[bool],
    num_leafs: usize,
    base_arity: usize,
    sub_arity: usize,
    top_arity: usize,
) -> usize {
    let (base_path_len, has_sub_path, has_top_path) =
        path_lens(num_leafs, base_arity, sub_arity, top_arity);

    let base_arity_bit_len = base_arity.trailing_zeros() as usize;
    let base_shift_bit_len = base_arity - 1;

    let mut challenge_shift_bits = challenge_shift_bits.iter();
    let mut challenge = 0;
    let mut shl = 0;

    for _ in 0..base_path_len {
        let insert_index = (0..base_shift_bit_len)
            .map(|_| challenge_shift_bits.next().unwrap())
            .filter(|bit| **bit)
            .count();
        challenge |= insert_index << shl;
        shl += base_arity_bit_len;
    }

    if has_sub_path {
        let sub_arity_bit_len = sub_arity.trailing_zeros() as usize;
        let sub_shift_bit_len = sub_arity - 1;
        let insert_index = (0..sub_shift_bit_len)
            .map(|_| challenge_shift_bits.next().unwrap())
            .filter(|bit| **bit)
            .count();
        challenge |= insert_index << shl;
        shl += sub_arity_bit_len;
    }

    if has_top_path {
        let top_shift_bit_len = top_arity - 1;
        let insert_index = (0..top_shift_bit_len)
            .map(|_| challenge_shift_bits.next().unwrap())
            .filter(|bit| **bit)
            .count();
        challenge |= insert_index << shl;
    }

    assert!(challenge_shift_bits.next().is_none());
    challenge
}

pub struct MerkleShiftChip<H, U, V = U0, W = U0>
where
    H: Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
    H::Field: FieldExt,
    U: PoseidonArity<H::Field>,
    V: PoseidonArity<H::Field>,
    W: PoseidonArity<H::Field>,
{
    base_hasher: <H as Halo2Hasher<U>>::Chip,
    sub_hasher: Option<<H as Halo2Hasher<V>>::Chip>,
    top_hasher: Option<<H as Halo2Hasher<W>>::Chip>,
    insert: ShiftChip<H::Field>,
}

impl<H, U, V, W> MerkleShiftChip<H, U, V, W>
where
    H: Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
    H::Field: FieldExt,
    U: PoseidonArity<H::Field>,
    V: PoseidonArity<H::Field>,
    W: PoseidonArity<H::Field>,
{
    pub fn with_subchips(
        base_hasher: <H as Halo2Hasher<U>>::Chip,
        sub_hasher: Option<<H as Halo2Hasher<V>>::Chip>,
        top_hasher: Option<<H as Halo2Hasher<W>>::Chip>,
        insert: ShiftChip<H::Field>,
    ) -> Self {
        assert_eq!(V::to_usize() == 0, sub_hasher.is_none());
        assert_eq!(W::to_usize() == 0, top_hasher.is_none());
        MerkleShiftChip {
            base_hasher,
            sub_hasher,
            top_hasher,
            insert,
        }
    }

    pub fn compute_root_unassigned_leaf(
        &self,
        layouter: impl Layouter<H::Field>,
        challenge_bits: &[AssignedBit<H::Field>],
        leaf: Value<H::Field>,
        path: &[Vec<Value<H::Field>>],
    ) -> Result<AssignedCell<H::Field, H::Field>, Error> {
        let leaf = leaf.into();
        let bits: Vec<MaybeAssigned<Bit, H::Field>> =
            challenge_bits.iter().cloned().map(Into::into).collect();
        self.compute_root_inner(layouter, &bits, leaf, path)
    }

    pub fn compute_root_assigned_leaf(
        &self,
        layouter: impl Layouter<H::Field>,
        challenge_bits: &[AssignedBit<H::Field>],
        leaf: AssignedCell<H::Field, H::Field>,
        path: &[Vec<Value<H::Field>>],
    ) -> Result<AssignedCell<H::Field, H::Field>, Error> {
        let leaf = leaf.into();
        let bits: Vec<MaybeAssigned<Bit, H::Field>> =
            challenge_bits.iter().cloned().map(Into::into).collect();
        self.compute_root_inner(layouter, &bits, leaf, path)
    }

    pub fn compute_root_unassigned_leaf_pi_bits(
        &self,
        layouter: impl Layouter<H::Field>,
        leaf: Value<H::Field>,
        path: &[Vec<Value<H::Field>>],
        pi_col: Column<Instance>,
        pi_rows: Range<usize>,
    ) -> Result<AssignedCell<H::Field, H::Field>, Error> {
        let leaf = leaf.into();
        let bits: Vec<MaybeAssigned<Bit, H::Field>> = pi_rows
            .map(|pi_row| MaybeAssigned::Pi(pi_col, pi_row))
            .collect();
        self.compute_root_inner(layouter, &bits, leaf, path)
    }

    pub fn compute_root_assigned_leaf_pi_bits(
        &self,
        layouter: impl Layouter<H::Field>,
        leaf: AssignedCell<H::Field, H::Field>,
        path: &[Vec<Value<H::Field>>],
        pi_col: Column<Instance>,
        pi_rows: Range<usize>,
    ) -> Result<AssignedCell<H::Field, H::Field>, Error> {
        let leaf = leaf.into();
        let bits: Vec<MaybeAssigned<Bit, H::Field>> = pi_rows
            .map(|pi_row| MaybeAssigned::Pi(pi_col, pi_row))
            .collect();
        self.compute_root_inner(layouter, &bits, leaf, path)
    }

    fn compute_root_inner(
        &self,
        mut layouter: impl Layouter<H::Field>,
        challenge_bits: &[MaybeAssigned<Bit, H::Field>],
        leaf: MaybeAssigned<H::Field, H::Field>,
        path: &[Vec<Value<H::Field>>],
    ) -> Result<AssignedCell<H::Field, H::Field>, Error> {
        let base_arity = U::to_usize();
        let sub_arity = V::to_usize();
        let top_arity = W::to_usize();

        let base_siblings = base_arity - 1;

        let base_path_len = if top_arity > 0 {
            path.len() - 2
        } else if sub_arity > 0 {
            path.len() - 1
        } else {
            path.len()
        };

        let mut cur = leaf;
        let mut height = 0;
        let mut path = path.iter().cloned();
        let mut challenge_bits = challenge_bits.iter();

        for _ in 0..base_path_len {
            let siblings: Vec<MaybeAssigned<H::Field, H::Field>> = path
                .next()
                .expect("no path elements remaining")
                .into_iter()
                .map(Into::into)
                .collect();

            assert_eq!(
                siblings.len(),
                base_siblings,
                "path element has incorrect number of siblings"
            );

            let shift_bits: Vec<MaybeAssigned<Bit, H::Field>> = (0..base_siblings)
                .map(|_| challenge_bits.next().expect("no challenge bits remaining"))
                .cloned()
                .collect();

            let preimage = self.insert.insert_inner(
                layouter.namespace(|| format!("base insert (height {})", height)),
                &cur,
                siblings.as_slice(),
                &shift_bits,
            )?;

            cur = self
                .base_hasher
                .hash(
                    layouter.namespace(|| format!("base hash (height {})", height)),
                    &preimage,
                )?
                .into();

            height += 1;
        }

        if sub_arity != 0 {
            let siblings: Vec<MaybeAssigned<H::Field, H::Field>> = path
                .next()
                .expect("no path elements remaining")
                .into_iter()
                .map(Into::into)
                .collect();

            let sub_siblings = sub_arity - 1;
            assert_eq!(
                siblings.len(),
                sub_siblings,
                "path element has incorrect number of siblings"
            );

            let shift_bits: Vec<MaybeAssigned<Bit, H::Field>> = (0..sub_siblings)
                .map(|_| challenge_bits.next().expect("no challenge bits remaining"))
                .cloned()
                .collect();

            let preimage = self.insert.insert_inner(
                layouter.namespace(|| format!("sub insert (height {})", height)),
                &cur,
                siblings.as_slice(),
                &shift_bits,
            )?;

            cur = self
                .sub_hasher
                .as_ref()
                .expect("sub hasher not set")
                .hash(
                    layouter.namespace(|| format!("sub hash (height {})", height)),
                    &preimage,
                )?
                .into();

            height += 1;
        }

        if top_arity != 0 {
            let siblings: Vec<MaybeAssigned<H::Field, H::Field>> = path
                .next()
                .expect("no path elements remaining")
                .into_iter()
                .map(Into::into)
                .collect();

            let top_siblings = top_arity - 1;
            assert_eq!(
                siblings.len(),
                top_siblings,
                "path element has incorrect number of siblings"
            );

            let shift_bits: Vec<MaybeAssigned<Bit, H::Field>> = (0..top_siblings)
                .map(|_| challenge_bits.next().expect("no challenge bits remaining"))
                .cloned()
                .collect();

            let preimage = self.insert.insert_inner(
                layouter.namespace(|| format!("top insert (height {})", height)),
                &cur,
                siblings.as_slice(),
                &shift_bits,
            )?;

            cur = self
                .top_hasher
                .as_ref()
                .expect("top hasher not set")
                .hash(
                    layouter.namespace(|| format!("top hash (height {})", height)),
                    &preimage,
                )?
                .into();
        }

        // Check that any remaining challenge bits are zero.
        assert!(challenge_bits.all(|bit| {
            let mut bit_is_zero = true;
            match bit {
                MaybeAssigned::Unassigned(ref bit) => {
                    bit.map(|bit| bit_is_zero = !bool::from(bit));
                }
                MaybeAssigned::Assigned(ref bit) => {
                    bit.value().map(|bit| bit_is_zero = !bool::from(bit));
                }
                // If challenge bits are public inputs, there should be no bits remaining.
                MaybeAssigned::Pi(..) => {
                    bit_is_zero = false;
                }
            };
            bit_is_zero
        }));
        assert!(path.next().is_none());

        Ok(cur.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::any::TypeId;
    use std::marker::PhantomData;

    use fil_halo2_gadgets::ColumnBuilder;
    use filecoin_hashers::{
        poseidon::{PoseidonDomain, PoseidonHasher},
        sha256::Sha256Hasher,
        Hasher,
    };
    use generic_array::typenum::{U2, U4, U8};
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
        halo2::gadgets::shift::ShiftConfig,
        merkle::{generate_tree, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper},
        TEST_SEED,
    };

    const BASE_HEIGHT: u32 = 5;

    fn test_merkle_chip_inner<H, U, V, W>()
    where
        H: 'static + Hasher<Field = Fp> + Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
        U: PoseidonArity<Fp>,
        V: PoseidonArity<Fp>,
        W: PoseidonArity<Fp>,
    {
        #[derive(Clone)]
        struct MyConfig<H, U, V, W>
        where
            H: Hasher<Field = Fp> + Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
            U: PoseidonArity<H::Field>,
            V: PoseidonArity<H::Field>,
            W: PoseidonArity<H::Field>,
        {
            base_hasher: <H as Halo2Hasher<U>>::Config,
            base_insert: InsertConfig<Fp, U>,
            sub: Option<(<H as Halo2Hasher<V>>::Config, InsertConfig<Fp, V>)>,
            top: Option<(<H as Halo2Hasher<W>>::Config, InsertConfig<Fp, W>)>,
            pi: Column<Instance>,
        }

        struct MyCircuit<H, U, V, W>
        where
            H: Hasher<Field = Fp> + Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
            U: PoseidonArity<Fp>,
            V: PoseidonArity<Fp>,
            W: PoseidonArity<Fp>,
        {
            challenge_bits: Vec<bool>,
            leaf: Value<Fp>,
            path: Vec<Vec<Value<Fp>>>,
            expected_root: Fp,
            _tree: PhantomData<(H, U, V, W)>,
        }

        impl<H, U, V, W> Circuit<Fp> for MyCircuit<H, U, V, W>
        where
            H: 'static + Hasher<Field = Fp> + Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
            U: PoseidonArity<Fp>,
            V: PoseidonArity<Fp>,
            W: PoseidonArity<Fp>,
        {
            type Config = MyConfig<H, U, V, W>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    challenge_bits: self.challenge_bits.clone(),
                    leaf: Value::unknown(),
                    path: self
                        .path
                        .iter()
                        .map(|sibs| vec![Value::unknown(); sibs.len()])
                        .collect(),
                    expected_root: self.expected_root,
                    _tree: PhantomData,
                }
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let base_arity = U::to_usize();
                let sub_arity = V::to_usize();
                let top_arity = W::to_usize();

                let (advice_eq, advice_neq, fixed_eq, fixed_neq) = ColumnBuilder::new()
                    .with_chip::<<H as Halo2Hasher<U>>::Chip>()
                    .with_chip::<<H as Halo2Hasher<V>>::Chip>()
                    .with_chip::<<H as Halo2Hasher<W>>::Chip>()
                    // Only need the base arity here because it is guaranteed to be the largest arity,
                    // thus all other arity insert chips will use a subset of the base arity's columns.
                    .with_chip::<InsertChip<Fp, U>>()
                    .create_columns(meta);

                let pi = meta.instance_column();
                meta.enable_equality(pi);

                let base_hasher = <H as Halo2Hasher<U>>::configure(
                    meta,
                    &advice_eq,
                    &advice_neq,
                    &fixed_eq,
                    &fixed_neq,
                );
                let base_insert = InsertChip::configure(meta, &advice_eq, &advice_neq);

                let sub = if sub_arity == 0 {
                    None
                } else if sub_arity == base_arity {
                    Some(transmute_arity::<H, U, V>(
                        base_hasher.clone(),
                        base_insert.clone(),
                    ))
                } else {
                    let sub_hasher = <H as Halo2Hasher<V>>::configure(
                        meta,
                        &advice_eq,
                        &advice_neq,
                        &fixed_eq,
                        &fixed_neq,
                    );
                    let sub_insert = InsertChip::configure(meta, &advice_eq, &advice_neq);
                    Some((sub_hasher, sub_insert))
                };

                let top = if top_arity == 0 {
                    None
                } else if top_arity == base_arity {
                    Some(transmute_arity::<H, U, W>(
                        base_hasher.clone(),
                        base_insert.clone(),
                    ))
                } else if top_arity == sub_arity {
                    let (sub_hasher, sub_insert) = sub.clone().expect("sub chips not set");
                    Some(transmute_arity::<H, V, W>(sub_hasher, sub_insert))
                } else {
                    let top_hasher = <H as Halo2Hasher<W>>::configure(
                        meta,
                        &advice_eq,
                        &advice_neq,
                        &fixed_eq,
                        &fixed_neq,
                    );
                    let top_insert = InsertChip::configure(meta, &advice_eq, &advice_neq);
                    Some((top_hasher, top_insert))
                };

                MyConfig {
                    base_hasher,
                    base_insert,
                    sub,
                    top,
                    pi,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let MyConfig {
                    base_hasher: base_hasher_config,
                    base_insert: base_insert_config,
                    sub: sub_config,
                    top: top_config,
                    pi: pi_col,
                } = config;

                <H as Halo2Hasher<U>>::load(&mut layouter, &base_hasher_config)?;
                let base_hasher_chip = <H as Halo2Hasher<U>>::construct(base_hasher_config);
                let base_insert_chip = InsertChip::construct(base_insert_config);

                let sub_hasher_insert_chips = sub_config.map(|(hasher_config, insert_config)| {
                    let hasher_chip = <H as Halo2Hasher<V>>::construct(hasher_config);
                    let insert_chip = InsertChip::construct(insert_config);
                    (hasher_chip, insert_chip)
                });

                let top_hasher_insert_chips = top_config.map(|(hasher_config, insert_config)| {
                    let hasher_chip = <H as Halo2Hasher<W>>::construct(hasher_config);
                    let insert_chip = InsertChip::construct(insert_config);
                    (hasher_chip, insert_chip)
                });

                let merkle_chip = MerkleChip::<H, U, V, W>::with_subchips(
                    base_hasher_chip,
                    base_insert_chip,
                    sub_hasher_insert_chips,
                    top_hasher_insert_chips,
                );

                merkle_chip
                    .compute_root_unassigned_leaf_pi_bits(
                        layouter,
                        self.leaf,
                        &self.path,
                        pi_col,
                        0..self.challenge_bits.len(),
                    )?
                    .value()
                    .assert_if_known(|root| **root == self.expected_root);

                Ok(())
            }
        }

        impl<H, U, V, W> MyCircuit<H, U, V, W>
        where
            H: 'static + Hasher<Field = Fp> + Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
            U: PoseidonArity<Fp>,
            V: PoseidonArity<Fp>,
            W: PoseidonArity<Fp>,
        {
            fn k(num_leafs: usize) -> u32 {
                let hasher_type = TypeId::of::<H>();
                if hasher_type == TypeId::of::<Sha256Hasher<Fp>>() {
                    return 17;
                }
                assert_eq!(hasher_type, TypeId::of::<PoseidonHasher<Fp>>());

                let base_arity = U::to_usize();
                let sub_arity = V::to_usize();
                let top_arity = W::to_usize();

                let (base_path_len, has_sub_path, has_top_path) =
                    path_lens(num_leafs, base_arity, sub_arity, top_arity);

                use filecoin_hashers::poseidon::PoseidonChip;
                let base_rows = PoseidonChip::<Fp, U>::num_rows() + InsertChip::<Fp, U>::num_rows();
                let mut num_rows = base_path_len * base_rows;
                if has_sub_path {
                    let sub_rows =
                        PoseidonChip::<Fp, V>::num_rows() + InsertChip::<Fp, V>::num_rows();
                    num_rows += sub_rows;
                }
                if has_top_path {
                    let top_rows =
                        PoseidonChip::<Fp, W>::num_rows() + InsertChip::<Fp, W>::num_rows();
                    num_rows += top_rows;
                };

                (num_rows as f32).log2().floor() as u32 + 1
            }
        }

        let base_arity = U::to_usize();
        let sub_arity = V::to_usize();
        let top_arity = W::to_usize();

        let mut num_leafs = base_arity.pow(BASE_HEIGHT);
        if sub_arity != 0 {
            num_leafs *= sub_arity;
        }
        if top_arity != 0 {
            num_leafs *= top_arity;
        }
        let challenge_bit_len = num_leafs.trailing_zeros() as usize;

        let mut rng = XorShiftRng::from_seed(TEST_SEED);
        let (_, tree) = generate_tree::<MerkleTreeWrapper<H, VecStore<H::Domain>, U, V, W>, _>(
            &mut rng, num_leafs, None,
        );
        let root: Fp = tree.root().into();

        let challenges: Vec<usize> = if num_leafs < 10 {
            (0..num_leafs).collect()
        } else {
            (0..10).map(|_| rng.gen::<usize>() % num_leafs).collect()
        };

        let mut k = MyCircuit::<H, U, V, W>::k(num_leafs);

        for challenge in challenges {
            let merkle_proof = tree
                .gen_proof(challenge)
                .expect("failed to generate merkle proof");

            let circ = MyCircuit::<H, U, V, W> {
                challenge_bits: (0..challenge_bit_len)
                    .map(|i| challenge >> i & 1 == 1)
                    .collect(),
                leaf: Value::known(merkle_proof.leaf().into()),
                path: merkle_proof.as_values(),
                expected_root: root,
                _tree: PhantomData,
            };

            let pub_inputs: Vec<Fp> = circ
                .challenge_bits
                .iter()
                .map(|bit| if *bit { Fp::one() } else { Fp::zero() })
                .collect();

            let prover = MockProver::run(k, &circ, vec![pub_inputs.clone()])
                .or_else(|err| {
                    if let Error::NotEnoughRowsAvailable { .. } = err {
                        k += 1;
                        MockProver::run(k, &circ, vec![])
                    } else {
                        Err(err)
                    }
                })
                .expect("MockProver failed");
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
    }

    #[test]
    fn test_merkle_chip_poseidon_8_4() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U4, U0>();
    }

    #[test]
    fn test_merkle_chip_poseidon_8_8() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U8, U0>();
    }

    #[test]
    fn test_merkle_chip_poseidon_8_4_2() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U4, U2>();
    }

    #[test]
    fn test_merkle_chip_poseidon_8_8_2() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U8, U2>();
    }

    #[test]
    fn test_merkle_chip_poseidon_8_8_4() {
        test_merkle_chip_inner::<PoseidonHasher<Fp>, U8, U8, U4>();
    }

    #[test]
    fn test_merkle_chip_sha256_2() {
        test_merkle_chip_inner::<Sha256Hasher<Fp>, U2, U0, U0>();
    }

    fn test_merkle_shift_chip_inner<U, V, W>()
    where
        U: PoseidonArity<Fp>,
        V: PoseidonArity<Fp>,
        W: PoseidonArity<Fp>,
    {
        #[derive(Clone)]
        struct MyConfig<U, V, W>
        where
            U: PoseidonArity<Fp>,
            V: PoseidonArity<Fp>,
            W: PoseidonArity<Fp>,
        {
            base_hasher: <PoseidonHasher<Fp> as Halo2Hasher<U>>::Config,
            sub_hasher: Option<<PoseidonHasher<Fp> as Halo2Hasher<V>>::Config>,
            top_hasher: Option<<PoseidonHasher<Fp> as Halo2Hasher<W>>::Config>,
            insert: ShiftConfig<Fp>,
            pi: Column<Instance>,
        }

        struct MyCircuit<U, V, W>
        where
            U: PoseidonArity<Fp>,
            V: PoseidonArity<Fp>,
            W: PoseidonArity<Fp>,
        {
            challenge_bits: Vec<bool>,
            leaf: Value<Fp>,
            path: Vec<Vec<Value<Fp>>>,
            expected_root: Fp,
            _arity: PhantomData<(U, V, W)>,
        }

        impl<U, V, W> Circuit<Fp> for MyCircuit<U, V, W>
        where
            U: PoseidonArity<Fp>,
            V: PoseidonArity<Fp>,
            W: PoseidonArity<Fp>,
        {
            type Config = MyConfig<U, V, W>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    challenge_bits: self.challenge_bits.clone(),
                    leaf: Value::unknown(),
                    path: self
                        .path
                        .iter()
                        .map(|sibs| vec![Value::unknown(); sibs.len()])
                        .collect(),
                    expected_root: self.expected_root,
                    _arity: PhantomData,
                }
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let base_arity = U::to_usize();
                let sub_arity = V::to_usize();
                let top_arity = W::to_usize();

                let (advice_eq, advice_neq, fixed_eq, fixed_neq) = ColumnBuilder::new()
                    .with_chip::<<PoseidonHasher<Fp> as Halo2Hasher<U>>::Chip>()
                    .with_chip::<<PoseidonHasher<Fp> as Halo2Hasher<V>>::Chip>()
                    .with_chip::<<PoseidonHasher<Fp> as Halo2Hasher<W>>::Chip>()
                    .with_chip::<ShiftChip<Fp>>()
                    .create_columns(meta);

                let pi = meta.instance_column();
                meta.enable_equality(pi);

                let base_hasher = <PoseidonHasher<Fp> as Halo2Hasher<U>>::configure(
                    meta,
                    &advice_eq,
                    &advice_neq,
                    &fixed_eq,
                    &fixed_neq,
                );

                let sub_hasher = if sub_arity == 0 {
                    None
                } else if sub_arity == base_arity {
                    Some(
                        <PoseidonHasher<Fp> as Halo2Hasher<U>>::transmute_arity::<V>(
                            base_hasher.clone(),
                        ),
                    )
                } else {
                    Some(<PoseidonHasher<Fp> as Halo2Hasher<V>>::configure(
                        meta,
                        &advice_eq,
                        &advice_neq,
                        &fixed_eq,
                        &fixed_neq,
                    ))
                };

                let top_hasher = if top_arity == 0 {
                    None
                } else if top_arity == base_arity {
                    Some(
                        <PoseidonHasher<Fp> as Halo2Hasher<U>>::transmute_arity::<W>(
                            base_hasher.clone(),
                        ),
                    )
                } else if top_arity == sub_arity {
                    Some(
                        <PoseidonHasher<Fp> as Halo2Hasher<V>>::transmute_arity::<W>(
                            sub_hasher.clone().expect("sub hasher not set"),
                        ),
                    )
                } else {
                    Some(<PoseidonHasher<Fp> as Halo2Hasher<W>>::configure(
                        meta,
                        &advice_eq,
                        &advice_neq,
                        &fixed_eq,
                        &fixed_neq,
                    ))
                };

                let insert = ShiftChip::configure(meta, &advice_eq);

                MyConfig {
                    base_hasher,
                    sub_hasher,
                    top_hasher,
                    insert,
                    pi,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let MyConfig {
                    base_hasher: base_hasher_config,
                    sub_hasher: sub_hasher_config,
                    top_hasher: top_hasher_config,
                    insert: insert_config,
                    pi: pi_col,
                } = config;

                let base_hasher_chip =
                    <PoseidonHasher<Fp> as Halo2Hasher<U>>::construct(base_hasher_config);

                let sub_hasher_chip = sub_hasher_config
                    .map(|config| <PoseidonHasher<Fp> as Halo2Hasher<V>>::construct(config));

                let top_hasher_chip = top_hasher_config
                    .map(|config| <PoseidonHasher<Fp> as Halo2Hasher<W>>::construct(config));

                let insert_chip = ShiftChip::construct(insert_config);

                let merkle_chip = MerkleShiftChip::<PoseidonHasher<Fp>, U, V, W>::with_subchips(
                    base_hasher_chip,
                    sub_hasher_chip,
                    top_hasher_chip,
                    insert_chip,
                );

                merkle_chip
                    .compute_root_unassigned_leaf_pi_bits(
                        layouter,
                        self.leaf,
                        &self.path,
                        pi_col,
                        0..self.challenge_bits.len(),
                    )?
                    .value()
                    .assert_if_known(|root| **root == self.expected_root);

                Ok(())
            }
        }

        impl<U, V, W> MyCircuit<U, V, W>
        where
            U: PoseidonArity<Fp>,
            V: PoseidonArity<Fp>,
            W: PoseidonArity<Fp>,
        {
            fn k(num_leafs: usize) -> u32 {
                use filecoin_hashers::poseidon::PoseidonChip;

                let base_arity = U::to_usize();
                let sub_arity = V::to_usize();
                let top_arity = W::to_usize();

                let (base_path_len, has_sub_path, has_top_path) =
                    path_lens(num_leafs, base_arity, sub_arity, top_arity);

                let base_rows =
                    PoseidonChip::<Fp, U>::num_rows() + ShiftChip::<Fp>::num_rows(base_arity);

                let mut num_rows = base_path_len * base_rows;
                if has_sub_path {
                    num_rows +=
                        PoseidonChip::<Fp, V>::num_rows() + ShiftChip::<Fp>::num_rows(sub_arity);
                }
                if has_top_path {
                    num_rows +=
                        PoseidonChip::<Fp, W>::num_rows() + ShiftChip::<Fp>::num_rows(top_arity);
                };

                (num_rows as f32).log2().floor() as u32 + 1
            }
        }

        let base_arity = U::to_usize();
        let sub_arity = V::to_usize();
        let top_arity = W::to_usize();

        let mut num_leafs = base_arity.pow(BASE_HEIGHT);
        if sub_arity != 0 {
            num_leafs *= sub_arity;
        }
        if top_arity != 0 {
            num_leafs *= top_arity;
        }

        let mut rng = XorShiftRng::from_seed(TEST_SEED);
        let (_, tree) = generate_tree::<
            MerkleTreeWrapper<PoseidonHasher<Fp>, VecStore<PoseidonDomain<Fp>>, U, V, W>,
            _,
        >(&mut rng, num_leafs, None);
        let root: Fp = tree.root().into();

        let challenges: Vec<usize> = if num_leafs < 10 {
            (0..num_leafs).collect()
        } else {
            (0..10).map(|_| rng.gen::<usize>() % num_leafs).collect()
        };

        let mut k = MyCircuit::<U, V, W>::k(num_leafs);

        for challenge in challenges {
            let merkle_proof = tree
                .gen_proof(challenge)
                .expect("failed to generate merkle proof");

            let circ = MyCircuit::<U, V, W> {
                challenge_bits: challenge_to_shift_bits(
                    challenge, num_leafs, base_arity, sub_arity, top_arity,
                ),
                leaf: Value::known(merkle_proof.leaf().into()),
                path: merkle_proof.as_values(),
                expected_root: root,
                _arity: PhantomData,
            };

            let pub_inputs: Vec<Fp> = circ
                .challenge_bits
                .iter()
                .map(|bit| if *bit { Fp::one() } else { Fp::zero() })
                .collect();

            let prover = MockProver::run(k, &circ, vec![pub_inputs.clone()])
                .or_else(|err| {
                    if let Error::NotEnoughRowsAvailable { .. } = err {
                        k += 1;
                        MockProver::run(k, &circ, vec![pub_inputs])
                    } else {
                        Err(err)
                    }
                })
                .expect("MockProver failed");
            assert!(prover.verify().is_ok());
        }
    }

    #[test]
    fn test_merkle_shift_chip_poseidon_2() {
        test_merkle_shift_chip_inner::<U2, U0, U0>();
    }

    #[test]
    fn test_merkle_shift_chip_poseidon_4() {
        test_merkle_shift_chip_inner::<U4, U0, U0>();
    }

    #[test]
    fn test_merkle_shift_chip_poseidon_8() {
        test_merkle_shift_chip_inner::<U4, U0, U0>();
    }

    #[test]
    fn test_merkle_shift_chip_poseidon_8_2() {
        test_merkle_shift_chip_inner::<U8, U2, U0>();
    }

    #[test]
    fn test_merkle_shift_chip_poseidon_8_4() {
        test_merkle_shift_chip_inner::<U8, U4, U0>();
    }

    #[test]
    fn test_merkle_shift_chip_poseidon_8_8() {
        test_merkle_shift_chip_inner::<U8, U8, U0>();
    }

    #[test]
    fn test_merkle_shift_chip_poseidon_8_4_2() {
        test_merkle_shift_chip_inner::<U8, U4, U2>();
    }

    #[test]
    fn test_merkle_shift_chip_poseidon_8_8_2() {
        test_merkle_shift_chip_inner::<U8, U8, U2>();
    }

    #[test]
    fn test_merkle_shift_chip_poseidon_8_8_4() {
        test_merkle_shift_chip_inner::<U8, U8, U4>();
    }
}
