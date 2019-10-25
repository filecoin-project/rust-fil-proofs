use std::fmt::{self, Debug, Formatter};
use std::hash::Hasher as StdHasher;

use bitvec::{BitVec, LittleEndian};
use bellperson::{ConstraintSystem, SynthesisError};
use ff::{PrimeField, PrimeFieldRepr};
use fil_sapling_crypto::circuit::{boolean, num, pedersen_hash as pedersen_hash_circuit};
use fil_sapling_crypto::jubjub::{
    edwards, read_exp_table_range, JubjubEngine, JubjubParams, PrimeOrder,
    MAX_EXP_TABLE_SEGMENTS_IN_MEMORY,
};
use fil_sapling_crypto::pedersen_hash::{pedersen_hash, pedersen_hash_with_exp_table, Personalization};
use merkletree::hash::{Algorithm as LightAlgorithm, Hashable};
use merkletree::merkle::Element;
use paired::bls12_381::{Bls12, Fr, FrRepr};
use rand::{Rand, Rng};

use crate::circuit::pedersen::pedersen_md_no_padding;
use crate::crypto::{kdf, pedersen, sloth};
use crate::crypto::pedersen::JJ_PARAMS;
use crate::error::{Error, Result};
use crate::hasher::{Domain, HashFunction, Hasher};

const N_BITS_PER_SEGMENT: usize = 189;

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct PedersenHasher {}

impl Hasher for PedersenHasher {
    type Domain = PedersenDomain;
    type Function = PedersenFunction;

    fn name() -> String {
        "PedersenHasher".into()
    }

    fn kdf(data: &[u8], m: usize) -> Self::Domain {
        kdf::kdf(data, m).into()
    }

    #[inline]
    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Self::Domain {
        // Unrapping here is safe; `Fr` elements and hash domain elements are the same byte length.
        let key = Fr::from_repr(key.0).unwrap();
        let ciphertext = Fr::from_repr(ciphertext.0).unwrap();
        sloth::encode::<Bls12>(&key, &ciphertext).into()
    }

    #[inline]
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Self::Domain {
        // Unrapping here is safe; `Fr` elements and hash domain elements are the same byte length.
        let key = Fr::from_repr(key.0).unwrap();
        let ciphertext = Fr::from_repr(ciphertext.0).unwrap();

        sloth::decode::<Bls12>(&key, &ciphertext).into()
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PedersenDomain(pub FrRepr);

impl AsRef<PedersenDomain> for PedersenDomain {
    fn as_ref(&self) -> &PedersenDomain {
        self
    }
}

impl std::hash::Hash for PedersenDomain {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let raw: &[u64] = self.0.as_ref();
        std::hash::Hash::hash(raw, state);
    }
}

impl PartialEq for PedersenDomain {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Eq for PedersenDomain {}

impl Default for PedersenDomain {
    fn default() -> PedersenDomain {
        PedersenDomain(FrRepr::default())
    }
}

impl Rand for PedersenDomain {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let fr: Fr = rng.gen();
        PedersenDomain(fr.into_repr())
    }
}

impl Ord for PedersenDomain {
    #[inline(always)]
    fn cmp(&self, other: &PedersenDomain) -> ::std::cmp::Ordering {
        (self.0).cmp(&other.0)
    }
}

impl PartialOrd for PedersenDomain {
    #[inline(always)]
    fn partial_cmp(&self, other: &PedersenDomain) -> Option<::std::cmp::Ordering> {
        Some((self.0).cmp(&other.0))
    }
}

impl AsRef<[u8]> for PedersenDomain {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        as_ref(&(self.0).0)
    }
}

// This is unsafe, and I wish it wasn't here, but I really need AsRef<[u8]> to work, without allocating.
// https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
// https://github.com/briansmith/ring/blob/abb3fdfc08562f3f02e95fb551604a871fd4195e/src/polyfill.rs#L93-L110
#[inline(always)]
#[allow(clippy::needless_lifetimes)]
fn as_ref<'a>(src: &'a [u64; 4]) -> &'a [u8] {
    unsafe {
        std::slice::from_raw_parts(
            src.as_ptr() as *const u8,
            src.len() * std::mem::size_of::<u64>(),
        )
    }
}

impl Domain for PedersenDomain {
    // QUESTION: When, if ever, should serialize and into_bytes return different results?
    // The definitions here at least are equivalent.
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PedersenDomain::byte_len());
        self.0.write_le(&mut bytes).unwrap();
        bytes
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PedersenDomain::byte_len());
        self.0.write_le(&mut out).unwrap();

        out
    }

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != PedersenDomain::byte_len() {
            return Err(Error::BadFrBytes);
        }
        let mut res: FrRepr = Default::default();
        res.read_le(raw).map_err(|_| Error::BadFrBytes)?;

        Ok(PedersenDomain(res))
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        self.0.write_le(dest)?;
        Ok(())
    }
}

impl Element for PedersenDomain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match PedersenDomain::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic!(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.into_bytes());
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PedersenHashState {
    curr_hash: edwards::CompressedPoint<Bls12, PrimeOrder>,
    unhashed_bits: BitVec<LittleEndian, u8>,
}

impl Debug for PedersenHashState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("PedersenHashState")
            .field("curr_hash", &self.curr_hash)
            .field("unhashed_bits", &self.unhashed_bits)
            .finish()
    }
}

impl Default for PedersenHashState {
    fn default() -> PedersenHashState {
        PedersenHashState {
            curr_hash: edwards::Point::<Bls12, PrimeOrder>::zero().compress(),
            unhashed_bits: BitVec::new(),
        }
    }
}

impl PedersenHashState {
    fn new() -> PedersenHashState {
        PedersenHashState::default()
    }

    fn update(
        &mut self,
        data: &[u8],
        exp_table: &[Vec<Vec<edwards::Point<Bls12, PrimeOrder>>>],
    ) {
        let input_bits = BitVec::<LittleEndian, u8>::from(data);

        let n_input_bits = input_bits.len();
        let n_stored_bits = self.unhashed_bits.len();
        let n_bits_total = n_input_bits + n_stored_bits;

        if n_bits_total < N_BITS_PER_SEGMENT {
            self.unhashed_bits.extend(input_bits);
            return;
        }

        let n_bits_to_store = n_bits_total % N_BITS_PER_SEGMENT;
        let n_bits_to_hash = n_bits_total - n_bits_to_store;

        let bits_to_hash = self
            .unhashed_bits
            .iter()
            .chain(input_bits.iter())
            .take(n_bits_to_hash);

        let digest = pedersen_hash_with_exp_table(
            Personalization::None,
            bits_to_hash,
            exp_table,
            &JJ_PARAMS,
        );

        self.curr_hash = self
            .curr_hash
            .decompress(&JJ_PARAMS)
            .add(&digest, &JJ_PARAMS)
            .compress();

        let n_input_bits_hashed = n_input_bits - n_bits_to_store;
        self.unhashed_bits = input_bits.iter().skip(n_input_bits_hashed).collect();
    }

    fn finalize(&mut self, exp_table: &[Vec<Vec<edwards::Point<Bls12, PrimeOrder>>>]) -> Fr {
        let n_unhashed_bits = self.unhashed_bits.len();

        if n_unhashed_bits == 0 {
            return self.curr_hash.decompress(&JJ_PARAMS).into_xy().0;
        }

        let bits_to_hash = self.unhashed_bits.iter().take(n_unhashed_bits);

        let segment_digest = pedersen_hash_with_exp_table(
            Personalization::None,
            bits_to_hash,
            exp_table,
            &JJ_PARAMS,
        );

        let curr_hash = self
            .curr_hash
            .decompress(&JJ_PARAMS)
            .add(&segment_digest, &JJ_PARAMS);

        let digest = curr_hash.into_xy().0;
        self.curr_hash = curr_hash.compress();
        digest
    }

    fn n_unhashed_bits(&self) -> usize {
        self.unhashed_bits.len()
    }

    fn curr_hash(&self) -> &edwards::CompressedPoint<Bls12, PrimeOrder> {
        &self.curr_hash
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PedersenFunction {
    states: Vec<PedersenHashState>,
    next_segment: usize,
    n_segments_remaining_in_exp_table: usize,
    exp_table: Vec<Vec<Vec<edwards::Point<Bls12, PrimeOrder>>>>,
    is_finalized: bool,
}

impl Default for PedersenFunction {
    /// Creates a new `PedersenFunction` to hash a single preimage.
    fn default() -> PedersenFunction {
        PedersenFunction::new_batched(1)
    }
}

impl Debug for PedersenFunction {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("PedersenFunction")
            .field("states", &self.states)
            .field("next_segment", &self.next_segment)
            .field("is_finalized", &self.is_finalized)
            .finish()
    }
}

impl StdHasher for PedersenFunction {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        assert_eq!(
            self.states.len(), 1,
            "cannot call `write` when `PedersenFunction` is hashing multiple preimages"
        );
        self.update_all(&[msg]);
        self.finalize_all();
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl HashFunction<PedersenDomain> for PedersenFunction {
    fn hash(data: &[u8]) -> PedersenDomain {
        pedersen::pedersen_md_no_padding(data).into()
    }

    fn hash_leaf_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        cs: CS,
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        _height: usize,
        params: &E::Params,
    ) -> ::std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        let mut preimage: Vec<boolean::Boolean> = vec![];
        preimage.extend_from_slice(left);
        preimage.extend_from_slice(right);

        Ok(
            pedersen_hash_circuit::pedersen_hash(cs, Personalization::None, &preimage, params)?
                .get_x()
                .clone(),
        )
    }

    fn hash_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        cs: CS,
        bits: &[boolean::Boolean],
        params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        pedersen_md_no_padding(cs, params, bits)
    }
}

impl LightAlgorithm<PedersenDomain> for PedersenFunction {
    #[inline]
    fn hash(&mut self) -> PedersenDomain {
        assert_eq!(
            self.states.len(), 1,
            "cannot call `hash` when `PedersenFunction` is hashing multiple preimages"
        );
        self.states[0].curr_hash().decompress(&JJ_PARAMS).into_xy().0.into()
    }

    #[inline]
    fn reset(&mut self) {
        assert_eq!(
            self.states.len(), 1,
            "cannot call `reset` when `PedersenFunction` is hashing multiple preimages"
        );
        *self = PedersenFunction::default();
    }

    fn leaf(&mut self, leaf: PedersenDomain) -> PedersenDomain {
        leaf
    }

    fn node(
        &mut self,
        left: PedersenDomain,
        right: PedersenDomain,
        _height: usize,
    ) -> PedersenDomain {
        let node_bits = NodeBits::new(&(left.0).0[..], &(right.0).0[..]);

        pedersen_hash::<Bls12, _>(Personalization::None, node_bits, &pedersen::JJ_PARAMS)
            .into_xy()
            .0
            .into()
    }
}

impl PedersenFunction {
    /// Creates a new `PedersenFunction` to hash `batch_size` number of preimages.
    pub fn new_batched(batch_size: usize) -> Self {
        PedersenFunction {
            states: (0..batch_size).map(|_| PedersenHashState::new()).collect(),
            next_segment: 0,
            n_segments_remaining_in_exp_table: 0,
            exp_table: vec![],
            is_finalized: false,
        }
    }

    pub fn update_all(&mut self, updates: &[&[u8]]) {
        assert!(
            !self.is_finalized,
            "cannot update a finalized Pedersen function"
        );

        if cfg!(test) {
            let all_updates_are_the_same_size = updates
                .iter()
                .all(|update| update.len() == updates[0].len());

            assert!(
                all_updates_are_the_same_size,
                "all preimage updates must contain the same number of bytes"
            );
        } else {
            use crate::util::NODE_SIZE;

            let all_updates_are_node_size = updates
                .iter()
                .all(|update| update.len() == NODE_SIZE);

            assert!(all_updates_are_node_size, "all preimage updates must be size `NODE_SIZE`");
        }

        let n_unhashed_bits = self.states[0].n_unhashed_bits();
        // let n_update_bits = NODE_SIZE * 8;
        let n_update_bits = updates[0].len() * 8;
        let n_bits_total = n_unhashed_bits + n_update_bits;
        let n_segments_to_hash = n_bits_total / N_BITS_PER_SEGMENT;

        // As an optimization, we always keep the first 5 segments of the exp-table in memory. If we
        // can use the portion of the exp-table that is already in memory, we should, becuase
        // reading the exp-table from disk is expensive.
        let use_in_memory_exp_table = self.next_segment + n_segments_to_hash <= 5;

        if use_in_memory_exp_table {
            let exp_table = &JJ_PARAMS.pedersen_hash_exp_table()[self.next_segment..];
            for (state, update) in self.states.iter_mut().zip(updates.iter()) {
                state.update(update, exp_table);
            }
            self.next_segment += n_segments_to_hash;
            return;
        }

        let must_read_exp_table = n_segments_to_hash > self.n_segments_remaining_in_exp_table;

        if must_read_exp_table {
            let exp_table_path = JJ_PARAMS.exp_table_path().as_ref().unwrap();
            self.exp_table = read_exp_table_range(
                self.next_segment,
                MAX_EXP_TABLE_SEGMENTS_IN_MEMORY,
                exp_table_path,
            );
            let n_segments_read = self.exp_table.len();
            assert!(n_segments_read != 0, "ran out of segments in exp-table");
            self.n_segments_remaining_in_exp_table = n_segments_read;
        }

        // Skip the previously used exp-table segments.
        let exp_table_offset = self.exp_table.len() - self.n_segments_remaining_in_exp_table;
        let exp_table = &self.exp_table[exp_table_offset..];

        for (state, update) in self.states.iter_mut().zip(updates.iter()) {
            state.update(update, exp_table);
        }

        self.next_segment += n_segments_to_hash;
        self.n_segments_remaining_in_exp_table -= n_segments_to_hash;
    }

    #[allow(clippy::range_plus_one)]
    pub fn finalize_all(&mut self) -> Vec<Fr> {
        // Assume all states have the same number of unhashed bits remaining. If we have previously
        // called `self.finalize_all()`, this value will be zero.
        let n_unhashed_bits = self.states[0].n_unhashed_bits();

        if n_unhashed_bits == 0 {
            self.is_finalized = true;
            return self
                .states
                .iter_mut()
                .map(|state| state.finalize(&[]))
                .collect();
        }

        let n_segments_to_hash =
            (n_unhashed_bits as f32 / N_BITS_PER_SEGMENT as f32).ceil() as usize;

        assert_eq!(
            n_segments_to_hash, 1,
            "called finalize_all with more than one segment's worth of outstanding data"
        );

        let must_read_exp_table = self.n_segments_remaining_in_exp_table == 0;

        if must_read_exp_table {
            let exp_table_path = JJ_PARAMS.exp_table_path().as_ref().unwrap();
            self.exp_table = read_exp_table_range(self.next_segment, 1, exp_table_path);
            let n_segments_read = self.exp_table.len();
            assert!(n_segments_read == 1, "ran out of segments in exp-table");
            self.n_segments_remaining_in_exp_table = 1;
        }

        let exp_table_offset = self.exp_table.len() - self.n_segments_remaining_in_exp_table;
        let exp_table = &self.exp_table[exp_table_offset..exp_table_offset + 1];

        let digests: Vec<Fr> = self
            .states
            .iter_mut()
            .map(|state| state.finalize(exp_table))
            .collect();

        self.is_finalized = true;
        digests
    }
}

impl Hashable<PedersenFunction> for Fr {
    fn hash(&self, state: &mut PedersenFunction) {
        let mut bytes = Vec::with_capacity(32);
        self.into_repr().write_le(&mut bytes).unwrap();
        state.write(&bytes);
    }
}

impl Hashable<PedersenFunction> for PedersenDomain {
    fn hash(&self, state: &mut PedersenFunction) {
        let mut bytes = Vec::with_capacity(32);
        self.0
            .write_le(&mut bytes)
            .expect("Failed to write `FrRepr`");
        state.write(&bytes);
    }
}

/// Helper to iterate over a pair of `Fr`.
struct NodeBits<'a> {
    // 256 bits
    lhs: &'a [u64],
    // 256 bits
    rhs: &'a [u64],
    index: usize,
}

impl<'a> NodeBits<'a> {
    pub fn new(lhs: &'a [u64], rhs: &'a [u64]) -> Self {
        NodeBits { lhs, rhs, index: 0 }
    }
}

impl<'a> Iterator for NodeBits<'a> {
    type Item = bool;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < 255 {
            // return lhs
            let a = self.index / 64;
            let b = self.index % 64;
            let res = (self.lhs[a] & (1 << b)) != 0;
            self.index += 1;
            return Some(res);
        }

        if self.index < 2 * 255 {
            // return rhs
            let a = (self.index - 255) / 64;
            let b = (self.index - 255) % 64;
            let res = (self.rhs[a] & (1 << b)) != 0;
            self.index += 1;
            return Some(res);
        }

        None
    }
}

impl From<Fr> for PedersenDomain {
    #[inline]
    fn from(val: Fr) -> Self {
        PedersenDomain(val.into_repr())
    }
}

impl From<FrRepr> for PedersenDomain {
    #[inline]
    fn from(val: FrRepr) -> Self {
        PedersenDomain(val)
    }
}

impl From<PedersenDomain> for Fr {
    #[inline]
    fn from(val: PedersenDomain) -> Self {
        Fr::from_repr(val.0).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    use fil_sapling_crypto::jubjub::JubjubBls12;
    use merkletree::hash::Hashable;
    use rand::{thread_rng, Rng};

    use crate::merkle::MerkleTree;

    #[test]
    fn test_path() {
        let values = ["hello", "world", "you", "two"];
        let t = MerkleTree::<PedersenDomain, PedersenFunction>::from_data(values.iter());

        let p = t.gen_proof(0); // create a proof for the first value = "hello"
        assert_eq!(*p.path(), vec![true, true]);
        assert_eq!(p.validate::<PedersenFunction>(), true);
    }

    #[test]
    fn test_pedersen_hasher() {
        let values = ["hello", "world", "you", "two"];

        let t = MerkleTree::<PedersenDomain, PedersenFunction>::from_data(values.iter());

        assert_eq!(t.leafs(), 4);

        let mut a = PedersenFunction::default();
        let leaves: Vec<PedersenDomain> = values
            .iter()
            .map(|v| {
                v.hash(&mut a);
                let h = a.hash();
                a.reset();
                h
            })
            .collect();

        assert_eq!(t.read_at(0), leaves[0]);
        assert_eq!(t.read_at(1), leaves[1]);
        assert_eq!(t.read_at(2), leaves[2]);
        assert_eq!(t.read_at(3), leaves[3]);

        let i1 = a.node(leaves[0], leaves[1], 0);
        a.reset();
        let i2 = a.node(leaves[2], leaves[3], 0);
        a.reset();

        assert_eq!(t.read_at(4), i1);
        assert_eq!(t.read_at(5), i2);

        let root = a.node(i1, i2, 1);
        a.reset();

        assert_eq!(
            t.read_at(0).0,
            FrRepr([
                8141980337328041169,
                4041086031096096197,
                4135265344031344584,
                7650472305044950055
            ])
        );

        let expected = FrRepr([
            11371136130239400769,
            4290566175630177573,
            11576422143286805197,
            2687080719931344767,
        ]);
        let actual = t.read_at(6).0;

        assert_eq!(actual, expected);
        assert_eq!(t.read_at(6), root);
    }

    #[test]
    fn test_as_ref() {
        let cases: Vec<[u64; 4]> = vec![
            [0, 0, 0, 0],
            [
                14963070332212552755,
                2414807501862983188,
                16116531553419129213,
                6357427774790868134,
            ],
        ];

        for case in cases.into_iter() {
            let repr = FrRepr(case);
            let val = PedersenDomain(repr);

            for _ in 0..100 {
                assert_eq!(val.into_bytes(), val.into_bytes());
            }

            let raw: &[u8] = val.as_ref();

            for i in 0..4 {
                assert_eq!(case[i], unsafe {
                    let mut val = [0u8; 8];
                    val.clone_from_slice(&raw[i * 8..(i + 1) * 8]);
                    mem::transmute::<[u8; 8], u64>(val)
                });
            }
        }
    }

    #[test]
    fn test_serialize() {
        let repr = FrRepr([1, 2, 3, 4]);
        let val = PedersenDomain(repr);

        let ser = serde_json::to_string(&val)
            .expect("Failed to serialize `PedersenDomain` element to JSON string");
        let val_back = serde_json::from_str(&ser)
            .expect("Failed to deserialize JSON string to `PedersenDomain`");

        assert_eq!(val, val_back);
    }

    // Asserts that using `PedersenFunction` in "updateable" mode (preimage data is fed in
    // incrementally), returns the same digest as sapling's Pedersen hash (preimage data is supplied
    // in full at the start of the hash function call).
    #[test]
    fn test_updateable_pedersen_hash() {
        let mut rng = thread_rng();

        // The max preimage size we test against is 118 bytes which is the largest preimage size
        // hashable with 5 segments' worth of Pedersen params (5 segments * 189 bits/segment /
        // 8 bits/byte = 118.125 max preimage bytes for 5 segments' worth of Pedersen params). 5
        // segments' worth of Pedersen Hash params are always gauranteed to be in memory,
        // therefore this test won't be slowed down by reading the exp-table file.
        let preimage_byte_lens = [2usize, 20, 50, 100, 118];

        for preimage_len in preimage_byte_lens.iter() {
            let preimage: Vec<u8> = (0..*preimage_len).map(|_| rng.gen()).collect();

            // Hash with the updateable Pedersen hash function.
            let mut hasher = PedersenFunction::new_batched(1);
            let preimage_len_half = preimage_len / 2;
            hasher.update_all(&[&preimage[..preimage_len_half]]);
            hasher.update_all(&[&preimage[preimage_len_half..]]);
            let digest = hasher.finalize_all()[0];

            // Hash with sapling's Pedersen hash function.
            let bits = BitVec::<bitvec::LittleEndian, u8>::from(preimage.as_slice());
            let expected_digest = pedersen_hash::<Bls12, _>(
                Personalization::None,
                bits.iter().take(8 * preimage_len),
                &JJ_PARAMS,
            )
            .into_xy()
            .0;

            assert_eq!(digest, expected_digest);
        }
    }

    // Asserts that hashing 3 preimages with a single `PedersenFunction` results in the same digest
    // for each preimage as is returned by sapling's Pedersen hash function.
    #[test]
    fn test_batched_pedersen_function() {
        let mut rng = thread_rng();
        let preimage_byte_lens = [2usize, 20, 50, 100, 118];

        for preimage_len in preimage_byte_lens.iter() {
            let preimage_1: Vec<u8> = (0..*preimage_len).map(|_| rng.gen()).collect();
            let preimage_2: Vec<u8> = (0..*preimage_len).map(|_| rng.gen()).collect();
            let preimage_3: Vec<u8> = (0..*preimage_len).map(|_| rng.gen()).collect();

            // Hash with the batched Pedersen hasher.
            let mut hasher = PedersenFunction::new_batched(3);
            hasher.update_all(&[&preimage_1, &preimage_2, &preimage_3]);
            let digests = hasher.finalize_all();

            // Hash each of the preimages separately using sapling's Pedersen hash.
            let preimage_1_bits = BitVec::<bitvec::LittleEndian, u8>::from(preimage_1.as_slice());
            let expected_digest_1 = pedersen_hash::<Bls12, _>(
                Personalization::None,
                preimage_1_bits.iter().take(8 * preimage_len),
                &JJ_PARAMS,
            )
            .into_xy()
            .0;
            assert_eq!(digests[0], expected_digest_1);

            let preimage_2_bits = BitVec::<bitvec::LittleEndian, u8>::from(preimage_2.as_slice());
            let expected_digest_2 = pedersen_hash::<Bls12, _>(
                Personalization::None,
                preimage_2_bits.iter().take(8 * preimage_len),
                &JJ_PARAMS,
            )
            .into_xy()
            .0;
            assert_eq!(digests[1], expected_digest_2);

            let preimage_3_bits = BitVec::<bitvec::LittleEndian, u8>::from(preimage_3.as_slice());
            let expected_digest_3 = pedersen_hash::<Bls12, _>(
                Personalization::None,
                preimage_3_bits.iter().take(8 * preimage_len),
                &JJ_PARAMS,
            )
            .into_xy()
            .0;
            assert_eq!(digests[2], expected_digest_3);
        }
    }

    // Asserts that Pedersen hashing using the batched updateable `PedersenFunction` yields the same
    // digests for long preimages (preimages containing more than 5 segments worth of data) as
    // sapling's Pedersen hash.
    #[test]
    fn test_batched_pedersen_function_with_long_preimage() {
        // The max preimage size we can hash with 10 segments's worth of Pedersen params (10
        // segments * 189 bits/segment / 8 bits/byte = 236.25 max preimage size in bytes for 10
        // segments' worth of Pedersen params).
        let preimage_byte_len = 236;

        let mut rng = thread_rng();
        let preimage_1: Vec<u8> = (0..preimage_byte_len).map(|_| rng.gen()).collect();
        let preimage_2: Vec<u8> = (0..preimage_byte_len).map(|_| rng.gen()).collect();

        // Hash with the batched updateable Pedersen hasher.
        let mut hasher = PedersenFunction::new_batched(2);
        hasher.update_all(&[&preimage_1[..100], &preimage_2[..100]]);
        hasher.update_all(&[&preimage_1[100..200], &preimage_2[100..200]]);
        hasher.update_all(&[&preimage_1[200..], &preimage_2[200..]]);
        let digests = hasher.finalize_all();

        // Hash the preimages individually with sapling's Pedersen hash.
        let params = JubjubBls12::new_with_n_segments_and_window_size(10, 1, None);

        let preimage_1_bits = BitVec::<bitvec::LittleEndian, u8>::from(preimage_1.as_slice());
        let expected_digest_1 = pedersen_hash::<Bls12, _>(
            Personalization::None,
            preimage_1_bits.iter().take(8 * preimage_byte_len),
            &params,
        )
        .into_xy()
        .0;
        assert_eq!(digests[0], expected_digest_1);

        let preimage_2_bits = BitVec::<bitvec::LittleEndian, u8>::from(preimage_2.as_slice());
        let expected_digest_2 = pedersen_hash::<Bls12, _>(
            Personalization::None,
            preimage_2_bits.iter().take(8 * preimage_byte_len),
            &params,
        )
        .into_xy()
        .0;
        assert_eq!(digests[1], expected_digest_2);
    }

    // Asserts that updating `PedersenFunction` with any number of bytes results in the correct
    // preimage.
    #[test]
    fn test_updateable_pedersen_hash_update_lengths() {
        // The preimage length that we will test against is 210 bytes. This length is chosen because
        // it is the summation of the integers 0..=20: 0 + 1 + 2 + ... + 20 = 210. Using a preimage
        // length of 210 bytes allows us to do 21 updates of the hasher, each containing a unique
        // number of bytes from the preimage (update lengths: 0, 1, 2, ..., 20 bytes); note that the
        // first hasher update of zero bytes does nothing.
        let n_updates = 20;
        let preimage_byte_len = 210;

        let mut rng = thread_rng();
        let preimage: Vec<u8> = (0..preimage_byte_len).map(|_| rng.gen()).collect();

        // Hash with `PedersenFunction`, updating it with 21 different sized subsets of the
        // preimage.
        let mut hasher = PedersenFunction::new_batched(1);
        let mut n_bytes_hashed = 0;
        for update_len in 0..=n_updates {
            let update_bytes = &preimage[n_bytes_hashed..n_bytes_hashed + update_len];
            hasher.update_all(&[update_bytes]);
            n_bytes_hashed += update_len;
        }
        let digest = hasher.finalize_all()[0];

        // Hash with sapling's Pedersen hash function.
        let params = JubjubBls12::new_with_n_segments_and_window_size(9, 1, None);
        let bits = BitVec::<bitvec::LittleEndian, u8>::from(preimage.as_slice());
        let expected_digest = pedersen_hash::<Bls12, _>(
            Personalization::None,
            bits.iter().take(8 * preimage_byte_len),
            &params,
        )
        .into_xy()
        .0;

        assert_eq!(digest, expected_digest);
    }
}
