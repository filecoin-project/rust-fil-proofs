use std::marker::PhantomData;
use std::{thread, time};

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{Error, Result};
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::hvh_post;
use crate::merkle::MerkleTree;
use crate::proof::ProofScheme;
use crate::vdf::Vdf;

#[derive(Clone, Debug)]
pub struct SetupParams<T: Domain, V: Vdf<T>> {
    pub setup_params_hvh_post: hvh_post::SetupParams<T, V>,
    pub post_periods_count: usize,
}

#[derive(Clone, Debug)]
pub struct PublicParams<T: Domain, V: Vdf<T>> {
    pub pub_params_hvh_post: hvh_post::PublicParams<T, V>,
    pub post_periods_count: usize,
}

#[derive(Clone, Debug)]
pub struct PublicInputs<T: Domain> {
    /// The root hashes of the merkle trees of the sealed sectors.
    pub commitments: Vec<T>,
}

#[derive(Clone, Debug)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    pub replicas: &'a [&'a [u8]],
    pub trees: &'a [&'a MerkleTree<H::Domain, H::Function>],
    _h: PhantomData<H>,
}

impl<'a, H: 'a + Hasher> PrivateInputs<'a, H> {
    pub fn new(
        replicas: &'a [&'a [u8]],
        trees: &'a [&'a MerkleTree<H::Domain, H::Function>],
    ) -> Self {
        PrivateInputs {
            replicas,
            trees,
            _h: PhantomData,
        }
    }
}

/// Bacon-PoSt
/// This is one construction of a Proof-of-Spacetime.
/// It currently only supports proving over a single sector.
#[derive(Clone, Debug)]
pub struct Proof<'a, H: Hasher + 'a, V: Vdf<H::Domain>>(Vec<hvh_post::Proof<'a, H, V>>);

impl<'a, H: Hasher + 'a, V: Vdf<H::Domain>> Proof<'a, H, V> {
    pub fn proofs(&self) -> &[hvh_post::Proof<'a, H, V>] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct BaconPost<H: Hasher, V: Vdf<H::Domain>> {
    _t: PhantomData<H>,
    _v: PhantomData<V>,
    beacon: Beacon,
}

#[derive(Clone, Debug, Default)]
struct Beacon {
    count: usize,
}
impl<H: Hasher, V: Vdf<H::Domain>> Default for BaconPost<H, V> {
    fn default() -> Self {
        BaconPost {
            _t: PhantomData,
            _v: PhantomData,
            beacon: Default::default(),
        }
    }
}

impl Beacon {
    pub fn get<T: Domain>(&mut self, t: usize) -> T {
        // TODO: actual beacon

        if self.count < t {
            // sleep a bit, to simulate dely
            thread::sleep(time::Duration::from_millis(10));
            self.count += 1;
        }

        let mut bytes = [0u8; 32];
        LittleEndian::write_u32(&mut bytes, t as u32);
        T::try_from_bytes(&bytes).expect("invalid beacon element")
    }
}

impl<'a, H: Hasher + 'a, V: Vdf<H::Domain>> BaconPost<H, V> {
    pub fn setup(&self, sp: &SetupParams<H::Domain, V>) -> Result<PublicParams<H::Domain, V>> {
        Ok(PublicParams {
            pub_params_hvh_post: hvh_post::HvhPost::<H, V>::setup(&sp.setup_params_hvh_post)?,
            post_periods_count: sp.post_periods_count,
        })
    }

    pub fn prove<'b>(
        &mut self,
        pub_params: &'b PublicParams<H::Domain, V>,
        pub_inputs: &'b PublicInputs<H::Domain>,
        priv_inputs: &'b PrivateInputs<'a, H>,
    ) -> Result<Proof<'a, H, V>> {
        let sectors_count = pub_params.pub_params_hvh_post.sectors_count;
        let challenge_count = pub_params.pub_params_hvh_post.challenge_count;
        let post_periods_count = pub_params.post_periods_count;

        if priv_inputs.replicas.len() != sectors_count {
            return Err(Error::MalformedInput);
        }

        if priv_inputs.trees.len() != sectors_count {
            return Err(Error::MalformedInput);
        }

        let mut proofs_hvh_post = Vec::with_capacity(post_periods_count);

        // First (t = 0)
        {
            // Run Bacon
            let r = self.beacon.get::<H::Domain>(0);

            // Generate challenges
            let challenges = derive_challenges::<H>(challenge_count, 0, &[], r.as_ref());

            // TODO: avoid cloining
            let pub_inputs_hvh_post = hvh_post::PublicInputs {
                commitments: pub_inputs.commitments.clone(),
                challenges,
            };

            let priv_inputs_hvh_post =
                hvh_post::PrivateInputs::<'a, H>::new(priv_inputs.replicas, priv_inputs.trees);

            proofs_hvh_post.push(hvh_post::HvhPost::prove(
                &pub_params.pub_params_hvh_post,
                &pub_inputs_hvh_post,
                &priv_inputs_hvh_post,
            )?);
        }

        // The rest (t = 1..post_periods_count)
        for t in 1..post_periods_count {
            // Run Bacon
            let r = self.beacon.get::<H::Domain>(t);
            let x = extract_post_input::<H, V>(&proofs_hvh_post[t - 1]);

            // Generate challenges
            let challenges = derive_challenges::<H>(challenge_count, t, x.as_ref(), r.as_ref());

            // Generate proof
            // TODO: avoid cloining
            let pub_inputs_hvh_post = hvh_post::PublicInputs {
                challenges,
                commitments: pub_inputs.commitments.clone(),
            };

            let priv_inputs_hvh_post =
                hvh_post::PrivateInputs::new(priv_inputs.replicas, priv_inputs.trees);

            proofs_hvh_post.push(hvh_post::HvhPost::prove(
                &pub_params.pub_params_hvh_post,
                &pub_inputs_hvh_post,
                &priv_inputs_hvh_post,
            )?);
        }

        Ok(Proof(proofs_hvh_post))
    }

    pub fn verify(
        &mut self,
        pub_params: &PublicParams<H::Domain, V>,
        pub_inputs: &PublicInputs<H::Domain>,
        proof: &Proof<H, V>,
    ) -> Result<bool> {
        let challenge_count = pub_params.pub_params_hvh_post.challenge_count;
        let post_periods_count = pub_params.post_periods_count;

        // HVH Post Verification

        // First (t = 0)
        {
            let r = self.beacon.get::<H::Domain>(0);
            // Generate challenges
            let challenges = derive_challenges::<H>(challenge_count, 0, &[], r.as_ref());

            // TODO: avoid cloining
            let pub_inputs_hvh_post = hvh_post::PublicInputs {
                challenges,
                commitments: pub_inputs.commitments.clone(),
            };

            if !hvh_post::HvhPost::verify(
                &pub_params.pub_params_hvh_post,
                &pub_inputs_hvh_post,
                &proof.0[0],
            )? {
                return Ok(false);
            }
        }

        // The rest (t = 1..post_periods_count)
        for t in 1..post_periods_count {
            // Generate challenges
            let r = self.beacon.get::<H::Domain>(t);
            let x = extract_post_input::<H, V>(&proof.0[t - 1]);

            let challenges = derive_challenges::<H>(challenge_count, t, x.as_ref(), r.as_ref());

            // TODO: avoid cloining
            let pub_inputs_hvh_post = hvh_post::PublicInputs {
                challenges,
                commitments: pub_inputs.commitments.clone(),
            };

            if !hvh_post::HvhPost::verify(
                &pub_params.pub_params_hvh_post,
                &pub_inputs_hvh_post,
                &proof.0[t],
            )? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

fn extract_post_input<H: Hasher, V: Vdf<H::Domain>>(proof: &hvh_post::Proof<H, V>) -> H::Domain {
    let leafs: Vec<u8> = proof.proofs_porep.iter().fold(Vec::new(), |mut acc, p| {
        acc.extend(p.leafs().into_iter().fold(
            Vec::new(),
            |mut inner_acc: Vec<u8>, leaf: &H::Domain| {
                inner_acc.extend(leaf.as_ref());
                inner_acc
            },
        ));
        acc
    });

    H::Function::hash(&leafs)
}

fn derive_challenges<H: Hasher>(count: usize, t: usize, x: &[u8], r: &[u8]) -> Vec<H::Domain> {
    (0..count)
        .map(|i| {
            let mut i_bytes = [0u8; 32];
            LittleEndian::write_u32(&mut i_bytes[0..4], t as u32);
            LittleEndian::write_u32(&mut i_bytes[4..8], i as u32);

            H::Function::hash(&[x, r, &i_bytes].concat())
        })
        .collect()
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
    fn test_bacon_post_basics() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let sp = SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            setup_params_hvh_post: hvh_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
                challenge_count: 10,
                sector_size: 1024 * 32,
                post_epochs: 3,
                setup_params_vdf: vdf_sloth::SetupParams {
                    key: rng.gen(),
                    rounds: 1,
                },
                sectors_count: 2,
            },
            post_periods_count: 3,
        };

        let mut bacon_post = BaconPost::<PedersenHasher, vdf_sloth::Sloth>::default();

        let pub_params = bacon_post.setup(&sp).unwrap();

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
            commitments: vec![tree0.root(), tree1.root()],
        };

        let priv_inputs = PrivateInputs {
            trees: &[&tree0, &tree1],
            replicas: &[&data0, &data1],
            _h: PhantomData,
        };

        let proof = bacon_post
            .prove(&pub_params, &pub_inputs, &priv_inputs)
            .unwrap();

        assert!(bacon_post.verify(&pub_params, &pub_inputs, &proof).unwrap());
    }
}
