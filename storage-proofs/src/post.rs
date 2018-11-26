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
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
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
    pub xs: Vec<H::Domain>,
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
            leaves: sp.leaves,
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
        let mut xs = Vec::with_capacity(post_iterations - 1);
        let mut ys = Vec::with_capacity(post_iterations - 1);

        for k in 1..post_iterations {
            // Run VDF
            let x = extract_vdf_input::<H>(&proofs_porep[k - 1]);
            let (y, proof_vdf) = V::eval(&pub_params.pub_params_vdf, &x)?;

            proofs_vdf.push(proof_vdf);
            xs.push(x);
            ys.push(y);

            let r = H::Function::hash(y.as_ref());

            // Generate challenges
            let challenges: Vec<H::Domain> = (0..challenge_count)
                .map(|i| {
                    let mut i_bytes = [0u8; 4];
                    LittleEndian::write_u32(&mut i_bytes[..], i as u32);

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
            xs,
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
                &proof.xs[i],
                &proof.ys[i],
                &proof.proofs_vdf[i],
            )? {
                return Ok(false);
            }
        }

        // Sequentiality Verification

        for i in 0..post_iterations - 1 {
            if extract_vdf_input::<H>(&proof.proofs_porep[i]) != proof.xs[i] {
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
            }
        }

        // The rest
        for i in 1..post_iterations {
            // Generate challenges
            let r = H::Function::hash(proof.ys[i - 1].as_ref());
            let challenges: Vec<H::Domain> = (0..challenge_count)
                .map(|j| {
                    let mut j_bytes = [0u8; 4];
                    LittleEndian::write_u32(&mut j_bytes[..], j as u32);

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
