use std::cmp::Ordering;
use std::hash::Hasher as StdHasher;
use std::marker::PhantomData;

use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::{boolean, num};
use fil_sapling_crypto::jubjub::JubjubEngine;
use merkletree::hash::{Algorithm, Hashable};
use merkletree::merkle::Element;
use paired::bls12_381::{Bls12, Fr, FrRepr};
use rand::{Rand, Rng};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::crypto::sloth;
use crate::error::Result;
use crate::hasher::*;

// TODO: make compile time parameter
const BETA_HEIGHT: usize = 1;

#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct HybridHasher<AH: Hasher, BH: Hasher> {
    _a: PhantomData<AH>,
    _b: PhantomData<BH>,
}

impl<AH: Hasher, BH: Hasher> Hasher for HybridHasher<AH, BH> {
    type Domain = HybridDomain<AH::Domain, BH::Domain>;
    type Function = HybridFunction<AH::Domain, BH::Domain, AH::Function, BH::Function>;

    fn name() -> String {
        format!("HybridHasher<{}, {}>", AH::name(), BH::name())
    }

    fn kdf(data: &[u8], m: usize) -> Self::Domain {
        assert_eq!(
            data.len(),
            32 * (1 + m),
            "invalid input length: data.len(): {} m: {}",
            data.len(),
            m
        );

        <Self::Function as HashFunction<Self::Domain>>::hash(data)
    }

    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Self::Domain {
        // TODO: validate this is how sloth should work in this case
        let k = (*key).into();
        let c = (*ciphertext).into();

        sloth::encode::<Bls12>(&k, &c).into()
    }

    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Self::Domain {
        // TODO: validate this is how sloth should work in this case
        sloth::decode::<Bls12>(&(*key).into(), &(*ciphertext).into()).into()
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct HybridFunction<AD: Domain, BD: Domain, AF: HashFunction<AD>, BF: HashFunction<BD>> {
    a: AF,
    b: BF,
    _a: PhantomData<AD>,
    _b: PhantomData<BD>,
}

impl<AD: Domain, BD: Domain, AF: HashFunction<AD>, BF: HashFunction<BD>> StdHasher
    for HybridFunction<AD, BD, AF, BF>
{
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        unreachable!("DO NOT USE ME");
    }

    #[inline]
    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

impl<AD: Domain, BD: Domain, AF: HashFunction<AD>, BF: HashFunction<BD>>
    HashFunction<HybridDomain<AD, BD>> for HybridFunction<AD, BD, AF, BF>
{
    fn hash(data: &[u8]) -> HybridDomain<AD, BD> {
        // This construction assumes the leafs are hashed using `A`, can make a switch to change this.
        HybridDomain::Alpha(<AF as HashFunction<AD>>::hash(data))
    }

    fn hash_leaf_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        cs: CS,
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        height: usize,
        params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        // This construction assumes the leafs are hashed using `A`, can make a switch to change this.
        if height < BETA_HEIGHT {
            AF::hash_leaf_circuit::<E, CS>(cs, left, right, height, params)
        } else {
            BF::hash_leaf_circuit::<E, CS>(cs, left, right, height, params)
        }
    }

    fn hash_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        mut cs: CS,
        bits: &[boolean::Boolean],
        params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        AF::hash_circuit(cs, bits, params)
    }
}

impl<AD: Domain, BD: Domain, AF: HashFunction<AD>, BF: HashFunction<BD>>
    Algorithm<HybridDomain<AD, BD>> for HybridFunction<AD, BD, AF, BF>
{
    #[inline]
    fn hash(&mut self) -> HybridDomain<AD, BD> {
        // This construction assumes the leafs are hashed using `A`, can make a switch to change this.
        HybridDomain::Alpha(self.a.hash())
    }

    #[inline]
    fn reset(&mut self) {
        // This construction assumes the leafs are hashed using `A`, can make a switch to change this.
        self.a.reset()
    }

    fn leaf(&mut self, leaf: HybridDomain<AD, BD>) -> HybridDomain<AD, BD> {
        // This construction assumes the leafs are hashed using `A`, can make a switch to change this.
        HybridDomain::Alpha(self.a.leaf(leaf.into_alpha()))
    }

    fn node(
        &mut self,
        left: HybridDomain<AD, BD>,
        right: HybridDomain<AD, BD>,
        height: usize,
    ) -> HybridDomain<AD, BD> {
        if height < BETA_HEIGHT {
            HybridDomain::Alpha(self.a.node(left.into_alpha(), right.into_alpha(), height))
        } else {
            HybridDomain::Beta(self.b.node(left.into_beta(), right.into_beta(), height))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub enum HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    #[serde(bound(serialize = "AD: Serialize", deserialize = "AD: DeserializeOwned"))]
    Alpha(AD),

    #[serde(bound(serialize = "BD: Serialize", deserialize = "BD: DeserializeOwned"))]
    Beta(BD),
}

impl<AD: Domain, BD: Domain, AF: HashFunction<AD>, BF: HashFunction<BD>>
    Hashable<HybridFunction<AD, BD, AF, BF>> for HybridDomain<AD, BD>
{
    fn hash(&self, state: &mut HybridFunction<AD, BD, AF, BF>) {
        state.write(self.as_ref())
    }
}

impl<AD, BD> Default for HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    fn default() -> Self {
        HybridDomain::Alpha(AD::default())
    }
}

impl<AD, BD> PartialEq for HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (HybridDomain::Alpha(a), HybridDomain::Alpha(b)) => a == b,
            (HybridDomain::Beta(a), HybridDomain::Beta(b)) => a == b,
            _ => panic!("can't compare different variants of `HybridDomain`"),
        }
    }
}

impl<AD, BD> PartialOrd for HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (HybridDomain::Alpha(a), HybridDomain::Alpha(b)) => Some(a.cmp(b)),
            (HybridDomain::Beta(a), HybridDomain::Beta(b)) => Some(a.cmp(b)),
            _ => None,
        }
    }
}

impl<AD, BD> Ord for HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    fn cmp(&self, other: &Self) -> Ordering {
        match self.partial_cmp(other) {
            Some(ordering) => ordering,
            None => panic!("can't compare different variants of `HybridDomain`"),
        }
    }
}

impl<AD, BD> AsRef<[u8]> for HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    fn as_ref(&self) -> &[u8] {
        match self {
            HybridDomain::Alpha(alpha) => alpha.as_ref(),
            HybridDomain::Beta(beta) => beta.as_ref(),
        }
    }
}

impl<AD, BD> Element for HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    fn byte_len() -> usize {
        32
    }

    // We offload the responsibility of converting this `Alpha` to a `Beta` to the caller. The
    // caller should always be `HybridMerkleTree`, which is aware of the when to convert between the
    // variants via its `beta_height`.
    fn from_slice(bytes: &[u8]) -> Self {
        HybridDomain::Alpha(AD::from_slice(bytes))
    }

    fn copy_to_slice(&self, dest: &mut [u8]) {
        dest.copy_from_slice(self.as_ref());
    }
}

impl<AD, BD> Rand for HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    // We offload the responsibility of converting this `Alpha` to a `Beta` to the caller.
    fn rand<R>(rng: &mut R) -> Self
    where
        R: Rng,
    {
        let fr: Fr = rng.gen();
        fr.into()
    }
}

impl<AD, BD> From<Fr> for HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    // We offload the responsibility of converting this `Alpha` to a `Beta` to the caller.
    fn from(fr: Fr) -> Self {
        HybridDomain::Alpha(AD::from(fr))
    }
}

impl<AD, BD> From<FrRepr> for HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    // We offload the responsibility of converting this `Alpha` to a `Beta` to the caller.
    #[inline]
    fn from(fr_repr: FrRepr) -> Self {
        HybridDomain::Alpha(AD::from(fr_repr))
    }
}

impl<AD, BD> From<HybridDomain<AD, BD>> for Fr
where
    AD: Domain,
    BD: Domain,
{
    fn from(hybrid_domain: HybridDomain<AD, BD>) -> Self {
        match hybrid_domain {
            HybridDomain::Alpha(alpha) => alpha.into(),
            HybridDomain::Beta(beta) => beta.into(),
        }
    }
}

impl<AD, BD> Domain for HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    fn serialize(&self) -> Vec<u8> {
        match self {
            HybridDomain::Alpha(alpha) => Domain::serialize(alpha),
            HybridDomain::Beta(beta) => Domain::serialize(beta),
        }
    }

    fn into_bytes(&self) -> Vec<u8> {
        match self {
            HybridDomain::Alpha(alpha) => alpha.into_bytes(),
            HybridDomain::Beta(beta) => beta.into_bytes(),
        }
    }

    // We offload the responsibility of converting this `Alpha` to a `Beta` to the caller.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        AD::try_from_bytes(bytes).map(HybridDomain::Alpha)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        match self {
            HybridDomain::Alpha(alpha) => alpha.write_bytes(dest),
            HybridDomain::Beta(beta) => beta.write_bytes(dest),
        }
    }
}

impl<AD, BD> HybridDomain<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    pub fn alpha_value(&self) -> &AD {
        match self {
            HybridDomain::Alpha(alpha_value) => alpha_value,
            _ => panic!("`HybridDomain::Beta` does not have an alpha value"),
        }
    }

    pub fn beta_value(&self) -> &BD {
        match self {
            HybridDomain::Beta(beta_value) => beta_value,
            _ => panic!("`HybridDomain::Alpha` does not have a beta value"),
        }
    }

    pub fn is_alpha(&self) -> bool {
        if let HybridDomain::Alpha { .. } = self {
            true
        } else {
            false
        }
    }

    pub fn is_beta(&self) -> bool {
        if let HybridDomain::Beta { .. } = self {
            true
        } else {
            false
        }
    }

    // Assumes that we can convert between `Alpha` and `Beta`.
    pub fn convert_into_alpha(self) -> Self {
        if self.is_alpha() {
            self
        } else {
            let alpha = AD::from_slice(self.as_ref());
            HybridDomain::Alpha(alpha)
        }
    }

    // Assumes that we can convert between `Alpha` and `Beta`.
    pub fn convert_into_beta(self) -> Self {
        if self.is_beta() {
            self
        } else {
            let beta = BD::from_slice(self.as_ref());
            HybridDomain::Beta(beta)
        }
    }

    // Assumes that we can convert between `Alpha` and `Beta`.
    pub fn toggle(self) -> Self {
        if self.is_alpha() {
            self.convert_into_beta()
        } else {
            self.convert_into_alpha()
        }
    }

    pub fn into_alpha(self) -> AD {
        match self {
            HybridDomain::Alpha(a) => a,
            HybridDomain::Beta(b) => AD::from_slice(self.as_ref()),
        }
    }

    // Assumes that we can convert between `Alpha` and `Beta`.
    pub fn into_beta(self) -> BD {
        match self {
            HybridDomain::Alpha(a) => BD::from_slice(self.as_ref()),
            HybridDomain::Beta(b) => b,
        }
    }
}
