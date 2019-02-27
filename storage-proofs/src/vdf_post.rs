use std::cmp;
use std::marker::PhantomData;

use bitvec::{self, BitVec};
use byteorder::{ByteOrder, LittleEndian};
use itertools::Itertools;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{Engine, Field, PrimeField};
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::error::{Error, Result};
use crate::fr32::fr_into_bytes;
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::merkle::MerkleTree;
use crate::parameter_cache::ParameterSetIdentifier;
use crate::porc::{self, PoRC};
use crate::proof::ProofScheme;
use crate::vdf::Vdf;

#[derive(Clone, Debug)]
pub struct SetupParams<T: Domain, V: Vdf<T>> {
    /// The number of challenges to be asked at each iteration.
    pub challenge_count: usize,
    /// Size of a sealed sector in bytes.
    pub sector_size: usize,
    /// Number of times we repeat an online Proof-of-Replication in one single PoSt.
    pub post_epochs: usize,
    pub setup_params_vdf: V::SetupParams,
    /// The number of sectors that are proven over.
    pub sectors_count: usize,
}

#[derive(Clone, Debug)]
pub struct PublicParams<T: Domain, V: Vdf<T>> {
    /// The number of challenges to be asked at each iteration.
    pub challenge_count: usize,
    /// Size of a sealed sector in bytes.
    pub sector_size: usize,
    /// Number of times we repeat an online Proof-of-Replication in one single PoSt.
    pub post_epochs: usize,
    pub pub_params_vdf: V::PublicParams,
    /// The number of leaves in one sector.
    pub leaves: usize,
    /// The number of sectors that are proven over.
    pub sectors_count: usize,
    /// The number of bits per challenge (the length of a merkle path)
    pub challenge_bits: usize,
    pub seed_bits: usize,
}

impl<T: Domain, V: Vdf<T>> ParameterSetIdentifier for PublicParams<T, V> {
    fn parameter_set_identifier(&self) -> String {
        format!(
            "vdf_post::PublicParams{{challenge_count: {}, sector_size: {}, post_epochs: {}, pub_params_vdf: FIXME, leaves: {}, sectors_count: {}}}",
            self.challenge_count, self.sector_size, self.post_epochs,
            //self.pub_params_vdf.parameter_set_identifier(), // FIXME: implement
            self.leaves, self.sectors_count
        )
    }
}

#[derive(Clone, Debug)]
pub struct PublicInputs<T: Domain> {
    /// The root hash of the merkle tree of each sealed sector.
    pub commitments: Vec<T>,
    /// The initial set of challenges. Must be of length `challenge_count`.
    pub challenge_seed: T,
    pub faults: Vec<u64>, // TODO: Actually use the faults once faults are designed.
}

#[derive(Clone, Debug)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    pub trees: &'a [&'a MerkleTree<H::Domain, H::Function>],
    _h: PhantomData<H>,
}

impl<'a, H: 'a + Hasher> PrivateInputs<'a, H> {
    pub fn new(trees: &'a [&'a MerkleTree<H::Domain, H::Function>]) -> Self {
        PrivateInputs {
            trees,
            _h: PhantomData,
        }
    }
}

pub fn compute_root_commitment<T: Domain>(commitments: &[T]) -> T {
    // NOTE: We're just returning the first commitment so we have a consistent, valid value.
    // In reality, we will need some kind of vector commitment, but we haven't committed to what yet.
    // This is here so we can get all the plumbing right without having to.
    commitments[0]
}

/// VDF-PoSt
/// This is one construction of a Proof-of-Spacetime.
/// It currently only supports proving over a single sector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<'a, H: Hasher + 'a, V: Vdf<H::Domain>> {
    /// `post_iteration` online Proof-of-Replication proofs.
    #[serde(bound(
        serialize = "V::Proof: Serialize",
        deserialize = "V::Proof: Deserialize<'de>"
    ))]
    pub porep_proofs: Vec<<PoRC<'a, H> as ProofScheme<'a>>::Proof>,
    /// `post_epochs - 1` VDF proofs
    #[serde(bound(
        serialize = "V::Proof: Serialize",
        deserialize = "V::Proof: Deserialize<'de>"
    ))]
    pub vdf_proofs: Vec<V::Proof>,
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    pub ys: Vec<H::Domain>,
    pub challenges: Vec<Vec<usize>>,
    pub challenged_sectors: Vec<Vec<usize>>,
    _v: PhantomData<V>,
}

#[derive(Clone, Debug)]
pub struct VDFPoSt<H: Hasher, V: Vdf<H::Domain>> {
    _t: PhantomData<H>,
    _v: PhantomData<V>,
}

impl<'a, H: Hasher + 'a, V: Vdf<H::Domain>> ProofScheme<'a> for VDFPoSt<H, V> {
    type PublicParams = PublicParams<H::Domain, V>;
    type SetupParams = SetupParams<H::Domain, V>;
    type PublicInputs = PublicInputs<H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<'a, H, V>;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        // Sector sizes which are powers of two have the form 100000 (i.e. leading one and all zeroes after).
        let sector_size = sp.sector_size;
        assert_eq!(
            sector_size.count_ones(),
            1,
            "sector size must be a power of 2"
        );
        // Assuming well-formed (power of two) sector size, log2(sector_size) is given by number of trailing zeroes.
        let log2 = sector_size.trailing_zeros();
        let leaves = sector_size / 32;
        let challenge_bits = (log2 - 5) as usize;
        assert_eq!(
            2u64.pow(challenge_bits as u32),
            leaves as u64,
            "sanity check"
        );

        Ok(PublicParams {
            challenge_count: sp.challenge_count,
            sector_size: sp.sector_size,
            post_epochs: sp.post_epochs,
            pub_params_vdf: V::setup(&sp.setup_params_vdf)?,
            leaves,
            sectors_count: sp.sectors_count,
            challenge_bits,
            seed_bits: 255,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        if priv_inputs.trees.len() != pub_params.sectors_count {
            return Err(Error::MalformedInput);
        }

        let challenge_count = pub_params.challenge_count;
        let post_epochs = pub_params.post_epochs;

        let pub_params_porep = porc::PublicParams {
            leaves: pub_params.leaves,
            sectors_count: pub_params.sectors_count,
            challenges_count: pub_params.challenge_count,
        };

        let mut porep_proofs = Vec::with_capacity(post_epochs);
        let mut vdf_proofs = Vec::with_capacity(post_epochs - 1);
        let mut ys = Vec::with_capacity(post_epochs - 1);
        let mut challenges_vec = Vec::with_capacity(post_epochs);
        let mut challenged_sectors_vec = Vec::with_capacity(post_epochs);

        let mut challenge_stream = ChallengeStream::<H, V>::new(pub_params);

        {
            let mut mix = pub_inputs.challenge_seed;
            let mut i = 0;

            while let Some((challenges, challenged_sectors)) = challenge_stream.next(mix) {
                assert!(
                    challenges.len() == challenge_count,
                    format!(
                        "expected {} challenges, but {} were mixed.",
                        challenge_count,
                        challenges.len()
                    )
                );
                challenges_vec.push(challenges.clone());
                challenged_sectors_vec.push(challenged_sectors.clone());

                let pub_inputs_porep = porc::PublicInputs {
                    challenges: &challenges,
                    challenged_sectors: &challenged_sectors,
                    commitments: &pub_inputs.commitments,
                };

                let priv_inputs_porep = porc::PrivateInputs {
                    trees: priv_inputs.trees,
                };

                let proof = PoRC::prove(&pub_params_porep, &pub_inputs_porep, &priv_inputs_porep)?;
                porep_proofs.push(proof.clone());

                // Skip last VDF evaluation.
                if i + 1 < post_epochs {
                    let x = extract_vdf_input::<H>(&proof);
                    let (y, vdf_proof) = V::eval(&pub_params.pub_params_vdf, &x)?;

                    ys.push(y);
                    vdf_proofs.push(vdf_proof);
                    mix = y;
                } else {
                    break;
                }
                i += 1;
            }
        }

        assert_eq!(porep_proofs.len(), pub_params.post_epochs);
        assert_eq!(ys.len(), pub_params.post_epochs - 1);
        assert_eq!(vdf_proofs.len(), pub_params.post_epochs - 1);
        assert_eq!(challenges_vec.len(), pub_params.post_epochs);
        assert_eq!(challenged_sectors_vec.len(), pub_params.post_epochs);

        Ok(Proof {
            porep_proofs,
            ys,
            vdf_proofs,
            challenges: challenges_vec,
            challenged_sectors: challenged_sectors_vec,
            _v: PhantomData,
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let post_epochs = pub_params.post_epochs;

        let mut mix = pub_inputs.challenge_seed;
        let mut challenge_stream = ChallengeStream::<H, V>::new(pub_params);

        let mut i = 0;
        while let Some((challenges, challenged_sectors)) = challenge_stream.next(mix) {
            if i + 1 >= post_epochs {
                break;
            }

            // VDF Output Verification
            {
                if !V::verify(
                    &pub_params.pub_params_vdf,
                    &extract_vdf_input::<H>(&proof.porep_proofs[i]),
                    &proof.vdf_proofs[i],
                )? {
                    return Ok(false);
                }
            }

            // Explicit challenge verification is not needed here, since we generate the challenges ourselves
            // and provide them as input to PoRC::verify below.

            // TODO: Root Commitment verification.
            // FIXME: Skip for now, but this is an absence that needs to be addressed once we have a vector commitment strategy.

            // Online PoRep Verification
            {
                let pub_params_porep = porc::PublicParams {
                    leaves: pub_params.leaves,
                    sectors_count: pub_params.sectors_count,
                    challenges_count: pub_params.challenge_count,
                };

                let pub_inputs_porep = porc::PublicInputs {
                    challenges: &challenges,
                    challenged_sectors: &challenged_sectors,
                    commitments: &pub_inputs.commitments,
                };

                if !PoRC::verify(&pub_params_porep, &pub_inputs_porep, &proof.porep_proofs[i])? {
                    return Ok(false);
                }
            }

            // update loop state
            mix = proof.ys[i];
            i += 1;
        }
        Ok(true)
    }
}

pub fn extract_vdf_input<H: Hasher>(proof: &porc::Proof<H>) -> H::Domain {
    let leafs: Vec<u8> = proof.leafs().iter().fold(Vec::new(), |mut acc, leaf| {
        acc.extend(leaf.as_ref());
        acc
    });

    H::Function::hash(&leafs)
}

/// `derive_partial_challenges` generates `count` hashed 'partial' challenges, using `seed` as a source of randomness.
fn derive_partial_challenges<H: Hasher>(count: usize, seed: &[u8]) -> Vec<H::Domain> {
    (0..count)
        .map(|j| {
            let mut j_bytes = [0u8; 32];
            LittleEndian::write_u32(&mut j_bytes[0..4], j as u32);

            H::Function::hash(&[seed, &j_bytes].concat())
        })
        .collect()
}

/// `ChallengeStream` manages incremental challenge derivation.
/// Consumers require groups of `challenge_count` challenges. Each round of challenge generation
/// requires a new random input (`mix`).
/// A `ChallengeStream` mediates between this usage requirement and the implementation details
/// of the actual challenge generation mechanism.
pub struct ChallengeStream<H: Hasher, V: Vdf<H::Domain>> {
    partial_challenges: Option<Vec<H::Domain>>,
    challenge_count: usize,
    challenge_rounds: usize,
    partial_challenge_count: usize,
    sectors_count: usize,
    challenge_bits: usize,
    _v: PhantomData<V>,
}

impl<H: Hasher, V: Vdf<H::Domain>> ChallengeStream<H, V> {
    /// A `ChallengeStream` must derive some shared parameters used in challenge derivation.
    /// `new` initializes a new, stateful, `ChallengeStream` with these parameters.
    pub fn new(pp: &PublicParams<H::Domain, V>) -> ChallengeStream<H, V> {
        let challenge_count = pp.challenge_count;
        let challenge_rounds = pp.post_epochs;
        let sectors_count = pp.sectors_count;
        let challenge_bits = pp.challenge_bits;
        let sub_challenges = pp.seed_bits / challenge_bits;
        let partial_challenge_count =
            ((pp.post_epochs * challenge_count) as f32 / sub_challenges as f32).ceil() as usize;

        ChallengeStream {
            partial_challenges: None,
            challenge_count,
            challenge_rounds,
            partial_challenge_count,
            sectors_count,
            challenge_bits,
            _v: PhantomData,
        }
    }

    /// A set of partial challenges must be generated as a one-time initialization.
    /// These partial challenges are 'mixed' with randomness during challenge finalization.
    /// Because partial challenge generation requires access to the first `mix` value as a random seed,
    /// it must be deferred until the first set of challenges is requested.
    fn ensure_partial_challenges(&mut self, mix: H::Domain) {
        if self.partial_challenges.is_none() {
            let partial_challenges = derive_partial_challenges::<H>(
                self.challenge_rounds * self.partial_challenge_count,
                &fr_into_bytes::<Bls12>(&mix.into()),
            );

            self.partial_challenges = Some(partial_challenges);
        }
    }

    /// `next` takes a random value, `mix`, and return an appropriate (conforming with `ChallengeStream`'s parameters)
    /// set of 'final challenges' (and challenged sectors) suitable as input to PoRC.
    /// This process consumes `partial_challenges`, mutating `ChallengeStream`'s state.
    ///
    // FIXME: It's currently possible that a partial_challenge is not completely consumed by production
    // of all needed final challenges. In this case, the remainder will be needed as a witness to prove
    // challenge-generation was performed correctly. However, `next` currently only returns the needed
    // final challenges. This will have to be addressed when we implement challenge verification in circuits.
    fn next(&mut self, mix: H::Domain) -> Option<(Vec<usize>, Vec<usize>)> {
        self.ensure_partial_challenges(mix);

        let mut partial_challenges = self.partial_challenges.clone().unwrap();

        if partial_challenges.is_empty() {
            None
        } else {
            let partial_challenge = partial_challenges.remove(0);
            self.partial_challenges = Some(partial_challenges);

            let mut all_challenges = Vec::with_capacity(self.challenge_count);
            let mut all_challenged_sectors = Vec::with_capacity(self.challenge_count);
            let mut remaining_challenges = self.challenge_count;

            while all_challenges.len() < self.challenge_count {
                let (challenges, challenged_sectors) = derive_final_challenges::<H, Bls12>(
                    partial_challenge,
                    mix,
                    self.sectors_count,
                    self.challenge_bits,
                );

                for i in 0..cmp::min(challenges.len(), remaining_challenges) {
                    all_challenges.push(challenges[i]);
                    all_challenged_sectors.push(challenged_sectors[i]);
                }
                remaining_challenges = self.challenge_count - all_challenges.len();
            }
            Some((all_challenges, all_challenged_sectors))
        }
    }
}

/// Returns (challenges, challenged_sectors)
/// Note that if challenge_bits does not evenly divide 256, then the last challenge will be
/// sampled from a space of only `remainder` bits.
fn derive_final_challenges<H: Hasher, E: Engine>(
    partial_challenge: H::Domain,
    mix: H::Domain,
    _sectors_count: usize,
    challenge_bits: usize,
) -> (Vec<usize>, Vec<usize>)
where
    <E as Engine>::Fr: std::convert::From<pairing::bls12_381::Fr>,
{
    type BV = BitVec<bitvec::LittleEndian, u8>;

    let mut mixed = partial_challenge.into();
    mixed.sub_assign(&mix.into());

    let mixed_bytes = fr_into_bytes::<E>(&mixed.into());
    let mut challenges = Vec::new();
    let mut challenged_sectors = Vec::new();

    for chunk in BV::from(mixed_bytes)
        .into_iter()
        .chunks(challenge_bits)
        .into_iter()
    {
        let mut challenge: usize = 0;
        let mut place = 1;

        for bit in chunk {
            if bit {
                challenge += place;
            }
            place <<= 1;
        }

        let challenged_sector = 0; // FIXME: Actually generate challenged_sector.

        challenges.push(challenge);
        challenged_sectors.push(challenged_sector);
    }

    challenges.reverse();
    challenged_sectors.reverse();

    (challenges, challenged_sectors)
}

/// verify_final_challenge_derivation is used only in a unit test, but it is an important check of
/// and documentation of both the challenge derivation and the method of verifying it.
#[allow(dead_code)]
fn verify_final_challenge_derivation<H: Hasher>(
    challenges: &[usize],
    partial_challenge: H::Domain,
    mix: H::Domain,
    challenge_bits: usize,
) -> bool {
    assert!(challenge_bits > 0 && challenge_bits < 64);
    // Computing shift_factor will overflow if challenge_bits >= 64. No need to work around: 63 bits is plenty.
    let shift_factor = Fr::from_repr(FrRepr::from(1u64 << challenge_bits)).unwrap();
    let packed = challenges.iter().fold(Fr::zero(), |mut acc, challenge| {
        let fr_challenge = Fr::from_repr(FrRepr::from(*challenge as u64)).unwrap();

        acc.mul_assign(&shift_factor);
        acc.add_assign(&fr_challenge);

        acc
    });

    let mut fr_mixed: Fr = mix.into();
    let fr_partial: Fr = partial_challenge.into();
    fr_mixed.add_assign(&packed);

    fr_partial == fr_mixed
}

#[cfg(test)]
mod tests {
    use super::*;

    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::pedersen::{PedersenDomain, PedersenHasher};
    use crate::vdf_sloth;

    #[test]
    fn test_derive_and_verify_final_challenges() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for challenge_bits in 1..64 {
            let sectors_count = 1;
            let partial_challenge: Fr = rng.gen();
            let mix: Fr = rng.gen();

            let (challenges, _challenged_sectors) = derive_final_challenges::<PedersenHasher, Bls12>(
                partial_challenge.into(),
                mix.into(),
                sectors_count,
                challenge_bits,
            );

            assert!(verify_final_challenge_derivation::<PedersenHasher>(
                &challenges,
                partial_challenge.into(),
                mix.into(),
                challenge_bits,
            ));
        }
    }

    #[test]
    fn test_vdf_post_basics() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let sp = SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            challenge_count: 30,
            sector_size: 1024 * 32,
            post_epochs: 3,
            setup_params_vdf: vdf_sloth::SetupParams {
                key: rng.gen(),
                rounds: 1,
            },
            sectors_count: 2,
        };

        let pub_params = VDFPoSt::<PedersenHasher, vdf_sloth::Sloth>::setup(&sp).unwrap();

        let data0: Vec<u8> = (0..1024)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let data1: Vec<u8> = (0..1024)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph0 = BucketGraph::<PedersenHasher>::new(1024, 5, 0, new_seed());
        let tree0 = graph0.merkle_tree(data0.as_slice()).unwrap();
        let graph1 = BucketGraph::<PedersenHasher>::new(1024, 5, 0, new_seed());
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();

        let pub_inputs = PublicInputs {
            challenge_seed: rng.gen(),
            commitments: vec![tree0.root(), tree1.root()],
            faults: Vec::new(),
        };

        let priv_inputs = PrivateInputs {
            trees: &[&tree0, &tree1],
            _h: PhantomData,
        };

        let proof = VDFPoSt::<PedersenHasher, vdf_sloth::Sloth>::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
        )
        .unwrap();

        assert!(VDFPoSt::<PedersenHasher, vdf_sloth::Sloth>::verify(
            &pub_params,
            &pub_inputs,
            &proof
        )
        .unwrap());
    }
}
