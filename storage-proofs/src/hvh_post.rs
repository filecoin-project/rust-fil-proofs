use std::marker::PhantomData;

use byteorder::{ByteOrder, LittleEndian};

use error::Result;
use hasher::{Domain, HashFunction, Hasher};
use merkle::MerkleTree;
use online_porep::{self, OnlinePoRep};
use proof::ProofScheme;
use vdf::Vdf;

#[derive(Clone, Debug)]
pub struct SetupParams<T: Domain, V: Vdf<T>> {
    /// The number of challenges to be asked at each iteration.
    pub challenge_count: usize,
    /// Size of a sealed sector in bytes.
    pub sector_size: usize,
    /// Number of times we repeat an online Proof-of-Replication in one single PoSt.
    pub post_iterations: usize,
    pub setup_params_vdf: V::SetupParams,
    /// The size of a single leaf.
    pub lambda: usize,
}

#[derive(Clone, Debug)]
pub struct PublicParams<T: Domain, V: Vdf<T>> {
    /// The number of challenges to be asked at each iteration.
    pub challenge_count: usize,
    /// Size of a sealed sector in bytes.
    pub sector_size: usize,
    /// Number of times we repeat an online Proof-of-Replication in one single PoSt.
    pub post_iterations: usize,
    pub pub_params_vdf: V::PublicParams,
    /// The size of a single leaf.
    pub lambda: usize,
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
}

#[derive(Clone, Debug)]
pub struct PublicInputs<T: Domain> {
    /// The root hash of the merkle tree of the sealed sector.
    pub comm_r: T,
    /// The initial set of challengs. Must be of length `challenge_count`.
    pub challenges: Vec<T>,
}

#[derive(Clone, Debug)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    pub replica: &'a [u8],
    pub tree: &'a MerkleTree<H::Domain, H::Function>,
    _h: PhantomData<H>,
}

/// HVH-PoSt
/// This is one construction of a Proof-of-Spacetime.
/// It currently only supports proving over a single sector.
#[derive(Clone, Debug)]
pub struct Proof<'a, H: Hasher + 'a, V: Vdf<H::Domain>> {
    /// `post_iteration` online Proof-of-Replication proofs.
    pub proofs_porep: Vec<<OnlinePoRep<H> as ProofScheme<'a>>::Proof>,
    /// `post_iterations - 1` VDF proofs
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
            post_iterations: sp.post_iterations,
            pub_params_vdf: V::setup(&sp.setup_params_vdf)?,
            lambda: sp.lambda,
            leaves: sp.sector_size / sp.lambda,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let challenge_count = pub_params.challenge_count;
        let post_iterations = pub_params.post_iterations;

        let mut proofs_porep = Vec::with_capacity(post_iterations);

        let pub_params_porep = online_porep::PublicParams {
            lambda: pub_params.lambda,
            leaves: pub_params.leaves,
        };

        // Step 1: Generate first proof
        {
            let pub_inputs_porep = online_porep::PublicInputs {
                challenges: &pub_inputs.challenges,
                commitment: pub_inputs.comm_r,
            };

            let priv_inputs_porep = online_porep::PrivateInputs {
                replica: priv_inputs.replica,
                tree: priv_inputs.tree,
            };
            proofs_porep.push(OnlinePoRep::prove(
                &pub_params_porep,
                &pub_inputs_porep,
                &priv_inputs_porep,
            )?);
        }

        // Step 2: Generate `post_iterations - 1` remaining proofs

        let mut proofs_vdf = Vec::with_capacity(post_iterations - 1);
        let mut ys = Vec::with_capacity(post_iterations - 1);

        for k in 1..post_iterations {
            // Run VDF
            let x = extract_vdf_input::<H>(&proofs_porep[k - 1]);
            let (y, proof_vdf) = V::eval(&pub_params.pub_params_vdf, &x)?;

            proofs_vdf.push(proof_vdf);
            ys.push(y);

            let r = H::Function::hash_single_node(&y);

            // Generate challenges
            let challenges: Vec<H::Domain> = (0..challenge_count)
                .map(|i| {
                    let mut i_bytes = [0u8; 32];
                    LittleEndian::write_u32(&mut i_bytes[0..4], i as u32);

                    H::Function::hash(&[r.as_ref(), &i_bytes].concat())
                })
                .collect();

            // Generate proof
            let pub_inputs_porep = online_porep::PublicInputs {
                challenges: &challenges,
                commitment: pub_inputs.comm_r,
            };

            let priv_inputs_porep = online_porep::PrivateInputs {
                replica: priv_inputs.replica,
                tree: priv_inputs.tree,
            };
            proofs_porep.push(OnlinePoRep::prove(
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
        let post_iterations = pub_params.post_iterations;

        // VDF Output Verification
        for i in 0..post_iterations - 1 {
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

        // First
        let pub_params_porep = online_porep::PublicParams {
            lambda: pub_params.lambda,
            leaves: pub_params.leaves,
        };

        {
            let pub_inputs_porep = online_porep::PublicInputs {
                challenges: &pub_inputs.challenges,
                commitment: pub_inputs.comm_r,
            };

            if !OnlinePoRep::verify(&pub_params_porep, &pub_inputs_porep, &proof.proofs_porep[0])? {
                return Ok(false);
            }
        }

        // The rest
        for i in 1..post_iterations {
            // Generate challenges

            let r = H::Function::hash_single_node(&proof.ys[i - 1]);
            let challenges: Vec<H::Domain> = (0..challenge_count)
                .map(|j| {
                    let mut j_bytes = [0u8; 32];
                    LittleEndian::write_u32(&mut j_bytes[0..4], j as u32);

                    H::Function::hash(&[r.as_ref(), &j_bytes].concat())
                })
                .collect();

            let pub_inputs_porep = online_porep::PublicInputs {
                challenges: &challenges,
                commitment: pub_inputs.comm_r,
            };

            if !OnlinePoRep::verify(&pub_params_porep, &pub_inputs_porep, &proof.proofs_porep[i])? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

pub fn extract_vdf_input<H: Hasher>(proof: &online_porep::Proof<H>) -> H::Domain {
    let leafs: Vec<u8> = proof.leafs().iter().fold(Vec::new(), |mut acc, leaf| {
        acc.extend(leaf.as_ref());
        acc
    });

    H::Function::hash(&leafs)
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
    fn test_hvh_post_basics() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let sp = SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            challenge_count: 10,
            sector_size: 1024 * lambda,
            post_iterations: 3,
            setup_params_vdf: vdf_sloth::SetupParams {
                key: rng.gen(),
                rounds: 1,
            },
            lambda,
        };

        let pub_params = HvhPost::<PedersenHasher, vdf_sloth::Sloth>::setup(&sp).unwrap();

        let data: Vec<u8> = (0..1024)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<PedersenHasher>::new(1024, 5, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice(), lambda).unwrap();

        let pub_inputs = PublicInputs {
            challenges: vec![rng.gen(), rng.gen()],
            comm_r: tree.root(),
        };

        let priv_inputs = PrivateInputs {
            tree: &tree,
            replica: &data,
            _h: PhantomData,
        };

        let proof = HvhPost::<PedersenHasher, vdf_sloth::Sloth>::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
        )
        .unwrap();

        assert!(
            HvhPost::<PedersenHasher, vdf_sloth::Sloth>::verify(&pub_params, &pub_inputs, &proof)
                .unwrap()
        );
    }
}
