use std::marker::PhantomData;

use byteorder::{ByteOrder, LittleEndian};

use error::{Error, Result};
use hasher::{Domain, HashFunction, Hasher};
use hvh_post;
use merkle::MerkleTree;
use proof::ProofScheme;
use vdf::Vdf;

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
    pub comm_rs: Vec<T>,
    /// The initial set of challengs. Must be of length `challenge_count`.
    pub challenges: Vec<T>,
}

#[derive(Clone, Debug)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    pub replicas: &'a [&'a [u8]],
    pub trees: &'a [&'a MerkleTree<H::Domain, H::Function>],
    _h: PhantomData<H>,
}

/// Bacon-PoSt
/// This is one construction of a Proof-of-Spacetime.
/// It currently only supports proving over a single sector.
#[derive(Clone, Debug)]
pub struct Proof<'a, H: Hasher + 'a, V: Vdf<H::Domain>>(Vec<hvh_post::Proof<'a, H, V>>);

#[derive(Clone, Debug)]
pub struct BaconPost<H: Hasher, V: Vdf<H::Domain>> {
    _t: PhantomData<H>,
    _v: PhantomData<V>,
}

impl<'a, H: Hasher + 'a, V: Vdf<H::Domain>> ProofScheme<'a> for BaconPost<H, V> {
    type PublicParams = PublicParams<H::Domain, V>;
    type SetupParams = SetupParams<H::Domain, V>;
    type PublicInputs = PublicInputs<H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<'a, H, V>;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            pub_params_hvh_post: hvh_post::HvhPost::<H, V>::setup(&sp.setup_params_hvh_post)?,
            post_periods_count: sp.post_periods_count,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
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
            // TODO: avoid cloining
            let pub_inputs_hvh_post = hvh_post::PublicInputs {
                comm_rs: pub_inputs.comm_rs.clone(),
                challenges: pub_inputs.challenges.clone(),
            };

            let priv_inputs_hvh_post =
                hvh_post::PrivateInputs::new(priv_inputs.replicas, priv_inputs.trees);

            proofs_hvh_post.push(hvh_post::HvhPost::prove(
                &pub_params.pub_params_hvh_post,
                &pub_inputs_hvh_post,
                &priv_inputs_hvh_post,
            )?);
        }

        // The rest (t = 1..post_periods_count)

        for t in 1..post_periods_count {
            // Run Bacon
            let r = random_beacon::<H::Domain>(t);
            let x = extract_post_input::<H, V>(&proofs_hvh_post[t - 1]);

            // Generate challenges
            let challenges: Vec<H::Domain> = (0..challenge_count)
                .map(|i| {
                    let mut i_bytes = [0u8; 32];
                    LittleEndian::write_u32(&mut i_bytes[0..4], i as u32);

                    H::Function::hash(&[x.as_ref(), r.as_ref(), &i_bytes].concat())
                })
                .collect();

            // Generate proof
            // TODO: avoid cloining
            let pub_inputs_hvh_post = hvh_post::PublicInputs {
                challenges: challenges,
                comm_rs: pub_inputs.comm_rs.clone(),
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

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let challenge_count = pub_params.pub_params_hvh_post.challenge_count;
        let post_periods_count = pub_params.post_periods_count;

        // HVH Post Verification

        // First (t = 0)
        {
            // TODO: avoid cloining
            let pub_inputs_hvh_post = hvh_post::PublicInputs {
                challenges: pub_inputs.challenges.clone(),
                comm_rs: pub_inputs.comm_rs.clone(),
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

            let r = random_beacon::<H::Domain>(t);
            let x = extract_post_input::<H, V>(&proof.0[t - 1]);

            let challenges: Vec<H::Domain> = (0..challenge_count)
                .map(|i| {
                    let mut i_bytes = [0u8; 32];
                    LittleEndian::write_u32(&mut i_bytes[0..4], i as u32);

                    H::Function::hash(&[x.as_ref(), r.as_ref(), &i_bytes].concat())
                })
                .collect();

            // TODO: avoid cloining
            let pub_inputs_hvh_post = hvh_post::PublicInputs {
                challenges: challenges,
                comm_rs: pub_inputs.comm_rs.clone(),
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

fn random_beacon<T: Domain>(t: usize) -> T {
    // TODO: actual beacon

    let mut bytes = [0u8; 32];
    LittleEndian::write_u32(&mut bytes, t as u32);
    T::try_from_bytes(&bytes).expect("invalid beacon element")
}

#[cfg(test)]
mod tests {
    use super::*;

    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use drgraph::{new_seed, BucketGraph, Graph};
    use fr32::fr_into_bytes;
    use hasher::pedersen::{PedersenDomain, PedersenHasher};
    use vdf_sloth;

    #[test]
    fn test_bacon_post_basics() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let sp = SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            setup_params_hvh_post: hvh_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
                challenge_count: 10,
                sector_size: 1024 * lambda,
                post_iterations: 3,
                setup_params_vdf: vdf_sloth::SetupParams {
                    key: rng.gen(),
                    rounds: 1,
                },
                lambda,
                sectors_count: 2,
            },
            post_periods_count: 3,
        };

        let pub_params = BaconPost::<PedersenHasher, vdf_sloth::Sloth>::setup(&sp).unwrap();

        let data0: Vec<u8> = (0..1024)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let data1: Vec<u8> = (0..1024)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph0 = BucketGraph::<PedersenHasher>::new(1024, 5, 0, new_seed());
        let tree0 = graph0.merkle_tree(data0.as_slice(), lambda).unwrap();
        let graph1 = BucketGraph::<PedersenHasher>::new(1024, 5, 0, new_seed());
        let tree1 = graph1.merkle_tree(data1.as_slice(), lambda).unwrap();

        let pub_inputs = PublicInputs {
            challenges: vec![rng.gen(), rng.gen()],
            comm_rs: vec![tree0.root(), tree1.root()],
        };

        let priv_inputs = PrivateInputs {
            trees: &[&tree0, &tree1],
            replicas: &[&data0, &data1],
            _h: PhantomData,
        };

        let proof = BaconPost::<PedersenHasher, vdf_sloth::Sloth>::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
        )
        .unwrap();

        assert!(
            BaconPost::<PedersenHasher, vdf_sloth::Sloth>::verify(&pub_params, &pub_inputs, &proof)
                .unwrap()
        );
    }
}
