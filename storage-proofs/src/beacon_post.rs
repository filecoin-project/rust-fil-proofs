use std::marker::PhantomData;
use std::{thread, time};

use byteorder::{ByteOrder, LittleEndian};
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::error::{Error, Result};
use crate::hasher::{Domain, Hasher};
use crate::merkle::MerkleTree;
use crate::parameter_cache::ParameterSetIdentifier;
use crate::proof::ProofScheme;
use crate::vdf::Vdf;
use crate::vdf_post;

#[derive(Clone, Debug)]
pub struct SetupParams<T: Domain, V: Vdf<T>> {
    pub vdf_post_setup_params: vdf_post::SetupParams<T, V>,
    pub post_periods_count: usize,
}

#[derive(Clone, Debug)]
pub struct PublicParams<T: Domain, V: Vdf<T>> {
    pub vdf_post_pub_params: vdf_post::PublicParams<T, V>,
    pub post_periods_count: usize,
}

impl<T: Domain, V: Vdf<T>> ParameterSetIdentifier for PublicParams<T, V> {
    fn parameter_set_identifier(&self) -> String {
        format!(
            "beacon_post::PublicParams{{vdf_post_pub_params: {}, post_periods_count: {}",
            self.vdf_post_pub_params.parameter_set_identifier(),
            self.post_periods_count
        )
    }
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

/// Beacon-PoSt
/// This is one construction of a Proof-of-Spacetime.
/// It currently only supports proving over a single sector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<'a, H: Hasher + 'a, V: Vdf<H::Domain>>(
    #[serde(bound(
        serialize = "vdf_post::Proof<'a, H, V>: Serialize",
        deserialize = "vdf_post::Proof<'a, H, V>: Deserialize<'de>"
    ))]
    Vec<vdf_post::Proof<'a, H, V>>,
);

impl<'a, H: Hasher + 'a, V: Vdf<H::Domain>> Proof<'a, H, V> {
    pub fn proofs(&self) -> &[vdf_post::Proof<'a, H, V>] {
        &self.0
    }
}

#[derive(Clone, Debug, Default)]
pub struct BeaconPoSt<H: Hasher, V: Vdf<H::Domain>> {
    _t: PhantomData<H>,
    _v: PhantomData<V>,
}

#[derive(Clone, Debug, Default)]
pub struct Beacon {
    count: usize,
}

// TODO: We should make Beacon a trait and parameterize BeaconPoSt on that trait.
// This will allow for multiple Beacon implementations, particularly for tests.
// `Beacon::get(…)` should never block for values of `t` which are in the past.
impl Beacon {
    pub fn get<T: Domain>(&mut self, t: usize) -> T {
        // TODO: actual beacon

        if self.count < t {
            // sleep a bit, to simulate delay
            thread::sleep(time::Duration::from_millis(10));
            self.count += 1;
        }

        let mut bytes = [0u8; 32];
        LittleEndian::write_u32(&mut bytes, t as u32);
        T::try_from_bytes(&bytes).expect("invalid beacon element")
    }
}

impl<'a, H: Hasher, V: Vdf<H::Domain>> ProofScheme<'a> for BeaconPoSt<H, V>
where
    H: 'a,
{
    type PublicParams = PublicParams<H::Domain, V>;
    type SetupParams = SetupParams<H::Domain, V>;
    type PublicInputs = PublicInputs<H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<'a, H, V>;

    fn setup(sp: &SetupParams<H::Domain, V>) -> Result<PublicParams<H::Domain, V>> {
        Ok(PublicParams {
            vdf_post_pub_params: vdf_post::VDFPoSt::<H, V>::setup(&sp.vdf_post_setup_params)?,
            post_periods_count: sp.post_periods_count,
        })
    }

    fn prove<'b>(
        pub_params: &'b PublicParams<H::Domain, V>,
        pub_inputs: &'b PublicInputs<H::Domain>,
        priv_inputs: &'b PrivateInputs<'a, H>,
    ) -> Result<Proof<'a, H, V>> {
        let sectors_count = pub_params.vdf_post_pub_params.sectors_count;
        let post_periods_count = pub_params.post_periods_count;

        if priv_inputs.replicas.len() != sectors_count {
            return Err(Error::MalformedInput);
        }

        if priv_inputs.trees.len() != sectors_count {
            return Err(Error::MalformedInput);
        }

        let mut proofs_vdf_post = Vec::with_capacity(post_periods_count);

        let mut beacon = Beacon::default();

        for t in 0..post_periods_count {
            // Run Beacon
            let r = beacon.get::<H::Domain>(t);

            // Generate proof
            // TODO: avoid cloning
            let pub_inputs_vdf_post = vdf_post::PublicInputs {
                challenge_seed: r,
                commitments: pub_inputs.commitments.clone(),
                faults: Vec::new(),
            };

            let priv_inputs_vdf_post = vdf_post::PrivateInputs::new(priv_inputs.trees);

            proofs_vdf_post.push(vdf_post::VDFPoSt::prove(
                &pub_params.vdf_post_pub_params,
                &pub_inputs_vdf_post,
                &priv_inputs_vdf_post,
            )?);
        }

        Ok(Proof(proofs_vdf_post))
    }

    fn verify(
        pub_params: &PublicParams<H::Domain, V>,
        pub_inputs: &PublicInputs<H::Domain>,
        proof: &Proof<H, V>,
    ) -> Result<bool> {
        let post_periods_count = pub_params.post_periods_count;

        // VDF PoSt Verification

        let mut beacon = Beacon::default();

        for t in 0..post_periods_count {
            // Generate challenges
            let r = beacon.get::<H::Domain>(t);

            // TODO: avoid cloning
            let pub_inputs_vdf_post = vdf_post::PublicInputs {
                challenge_seed: r,
                commitments: pub_inputs.commitments.clone(),
                faults: Vec::new(),
            };

            if !vdf_post::VDFPoSt::verify(
                &pub_params.vdf_post_pub_params,
                &pub_inputs_vdf_post,
                &proof.0[t],
            )? {
                return Ok(false);
            }
        }

        Ok(true)
    }
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
    fn test_beacon_post_basics() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let sp = SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            vdf_post_setup_params: vdf_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
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

        let pub_params = BeaconPoSt::<PedersenHasher, vdf_sloth::Sloth>::setup(&sp).unwrap();

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

        let priv_inputs = PrivateInputs::<PedersenHasher> {
            trees: &[&tree0, &tree1],
            replicas: &[&data0, &data1],
            _h: PhantomData,
        };

        let proof = BeaconPoSt::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        assert!(BeaconPoSt::verify(&pub_params, &pub_inputs, &proof).unwrap());
    }
}
