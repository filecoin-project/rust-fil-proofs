use std::marker::PhantomData;

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{Error, Result};
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::merkle::MerkleTree;
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
    /// The size of a single leaf.
    pub leaves: usize,
    /// The number of sectors that are proven over.
    pub sectors_count: usize,
}

#[derive(Clone, Debug)]
pub struct PublicInputs<T: Domain> {
    /// The root hash of the merkle tree of the sealed sector.
    pub commitments: Vec<T>,
    /// The initial set of challengs. Must be of length `challenge_count`.
    pub challenges: Vec<T>,
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

/// HVH-PoSt
/// This is one construction of a Proof-of-Spacetime.
/// It currently only supports proving over a single sector.
#[derive(Clone, Debug)]
pub struct Proof<'a, H: Hasher + 'a, V: Vdf<H::Domain>> {
    /// `post_iteration` online Proof-of-Replication proofs.
    pub proofs_porep: Vec<<PoRC<H> as ProofScheme<'a>>::Proof>,
    /// `post_epochs - 1` VDF proofs
    pub proofs_vdf: Vec<V::Proof>,
    pub ys: Vec<H::Domain>,
}

#[derive(Clone, Debug)]
pub struct HvhPost<H: Hasher, V: Vdf<H::Domain>> {
    _t: PhantomData<H>,
    _v: PhantomData<V>,
}

impl<'a, H: Hasher + 'a, V: Vdf<H::Domain>> ProofScheme<'a> for HvhPost<H, V> {
    type PublicParams = PublicParams<H::Domain, V>;
    type SetupParams = SetupParams<H::Domain, V>;
    type PublicInputs = PublicInputs<H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<'a, H, V>;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            challenge_count: sp.challenge_count,
            sector_size: sp.sector_size,
            post_epochs: sp.post_epochs,
            pub_params_vdf: V::setup(&sp.setup_params_vdf)?,
            leaves: sp.sector_size / 32,
            sectors_count: sp.sectors_count,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        if priv_inputs.replicas.len() != pub_params.sectors_count {
            return Err(Error::MalformedInput);
        }

        if priv_inputs.trees.len() != pub_params.sectors_count {
            return Err(Error::MalformedInput);
        }

        let challenge_count = pub_params.challenge_count;
        let post_epochs = pub_params.post_epochs;

        let mut proofs_porep = Vec::with_capacity(post_epochs);

        let pub_params_porep = porc::PublicParams {
            leaves: pub_params.leaves,
            sectors_count: pub_params.sectors_count,
        };

        // Step 1: Generate first proof
        {
            let pub_inputs_porep = porc::PublicInputs {
                challenges: &pub_inputs.challenges,
                commitments: &pub_inputs.commitments,
            };

            let priv_inputs_porep = porc::PrivateInputs {
                replicas: priv_inputs.replicas,
                trees: priv_inputs.trees,
            };
            proofs_porep.push(PoRC::prove(
                &pub_params_porep,
                &pub_inputs_porep,
                &priv_inputs_porep,
            )?);
        }

        // Step 2: Generate `post_epochs - 1` remaining proofs

        let mut proofs_vdf = Vec::with_capacity(post_epochs - 1);
        let mut ys = Vec::with_capacity(post_epochs - 1);

        for k in 1..post_epochs {
            // Run VDF
            let x = extract_vdf_input::<H>(&proofs_porep[k - 1]);
            let (y, proof_vdf) = V::eval(&pub_params.pub_params_vdf, &x)?;

            proofs_vdf.push(proof_vdf);
            ys.push(y);

            let r = H::Function::hash_single_node(&y);

            // Generate challenges
            let challenges = derive_challenges::<H>(challenge_count, r.as_ref());

            // Generate proof
            let pub_inputs_porep = porc::PublicInputs {
                challenges: &challenges,
                commitments: &pub_inputs.commitments,
            };

            let priv_inputs_porep = porc::PrivateInputs {
                replicas: priv_inputs.replicas,
                trees: priv_inputs.trees,
            };
            proofs_porep.push(PoRC::prove(
                &pub_params_porep,
                &pub_inputs_porep,
                &priv_inputs_porep,
            )?);
        }

        Ok(Proof {
            proofs_porep,
            proofs_vdf,
            ys,
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let challenge_count = pub_params.challenge_count;
        let post_epochs = pub_params.post_epochs;

        // VDF Output Verification
        for i in 0..post_epochs - 1 {
            if !V::verify(
                &pub_params.pub_params_vdf,
                &extract_vdf_input::<H>(&proof.proofs_porep[i]),
                &proof.ys[i],
                &proof.proofs_vdf[i],
            )? {
                return Ok(false);
            }
        }

        // Online PoRep Verification

        let pub_params_porep = porc::PublicParams {
            leaves: pub_params.leaves,
            sectors_count: pub_params.sectors_count,
        };

        // First
        {
            let pub_inputs_porep = porc::PublicInputs {
                challenges: &pub_inputs.challenges,
                commitments: &pub_inputs.commitments,
            };

            if !PoRC::verify(&pub_params_porep, &pub_inputs_porep, &proof.proofs_porep[0])? {
                return Ok(false);
            }
        }

        // The rest
        for i in 1..post_epochs {
            // Generate challenges

            let r = H::Function::hash_single_node(&proof.ys[i - 1]);
            let challenges = derive_challenges::<H>(challenge_count, r.as_ref());

            let pub_inputs_porep = porc::PublicInputs {
                challenges: &challenges,
                commitments: &pub_inputs.commitments,
            };

            if !PoRC::verify(&pub_params_porep, &pub_inputs_porep, &proof.proofs_porep[i])? {
                return Ok(false);
            }
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

fn derive_challenges<H: Hasher>(count: usize, r: &[u8]) -> Vec<H::Domain> {
    (0..count)
        .map(|j| {
            let mut j_bytes = [0u8; 32];
            LittleEndian::write_u32(&mut j_bytes[0..4], j as u32);

            H::Function::hash(&[r, &j_bytes].concat())
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
    fn test_hvh_post_basics() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let sp = SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            challenge_count: 10,
            sector_size: 1024 * 32,
            post_epochs: 3,
            setup_params_vdf: vdf_sloth::SetupParams {
                key: rng.gen(),
                rounds: 1,
            },
            sectors_count: 2,
        };

        let pub_params = HvhPost::<PedersenHasher, vdf_sloth::Sloth>::setup(&sp).unwrap();

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
            challenges: vec![rng.gen(), rng.gen()],
            commitments: vec![tree0.root(), tree1.root()],
        };

        let priv_inputs = PrivateInputs {
            trees: &[&tree0, &tree1],
            replicas: &[&data0, &data1],
            _h: PhantomData,
        };

        let proof = HvhPost::<PedersenHasher, vdf_sloth::Sloth>::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
        )
        .unwrap();

        assert!(HvhPost::<PedersenHasher, vdf_sloth::Sloth>::verify(
            &pub_params,
            &pub_inputs,
            &proof
        )
        .unwrap());
    }
}
