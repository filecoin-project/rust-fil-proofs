use std::marker::PhantomData;

use byteorder::{ByteOrder, LittleEndian};

use error::Result;
use hasher::{Domain, HashFunction, Hasher};
use proof::ProofScheme;

#[derive(Clone, Debug)]
pub struct HvhPostSetupParams<T: Domain, V: Vdf<T>> {
    /// The number of challenges to be asked at each iteration.
    pub challenge_count: usize,
    /// Size of a sealed sector in bytes.
    pub sector_size: usize,
    /// Number of times we repeat an online Proof-of-Replication in one single PoSt.
    pub post_iterations: usize,
    pub setup_params_vdf: V::SetupParams,
}

#[derive(Clone, Debug)]
pub struct HvhPostPublicParams<T: Domain, V: Vdf<T>> {
    /// The number of challenges to be asked at each iteration.
    pub challenge_count: usize,
    /// Size of a sealed sector in bytes.
    pub sector_size: usize,
    /// Number of times we repeat an online Proof-of-Replication in one single PoSt.
    pub post_iterations: usize,
    pub pub_params_vdf: V::PublicParams,
}

#[derive(Clone, Debug)]
pub struct HvhPostPublicInputs<T: Domain> {
    /// The root hash of the merkle tree of the sealed sector.
    pub comm_r: T,
    /// The initial set of challengs. Must be of length `challenge_count`.
    pub challenges: Vec<T>,
}

#[derive(Clone, Debug)]
pub struct HvhPostPrivateInputs<'a> {
    pub replica: &'a [u8],
}

/// HVH-PoSt
/// This is one construction of a Proof-of-Spacetime.
/// It currently only supports proving over a single sector.
#[derive(Clone, Debug)]
pub struct HvhPostProof<'a, T: Domain + 'a, V: Vdf<T>> {
    /// `post_iteration` online Proof-of-Replication proofs.
    pub proofs_porep: Vec<<OnlinePoRep<T> as ProofScheme<'a>>::Proof>,
    /// `post_iterations - 1` VDF proofs
    pub proofs_vdf: Vec<V::Proof>,
    pub xs: Vec<T>,
    pub ys: Vec<T>,
}

/// Generic trait to represent any Verfiable Delay Function (VDF).
pub trait Vdf<T: Domain>: Clone {
    type SetupParams: Clone;
    type PublicParams: Clone;
    type Proof: Clone;

    fn setup(&Self::SetupParams) -> Result<Self::PublicParams>;
    fn eval(&Self::PublicParams, x: &T) -> Result<(T, Self::Proof)>;
    fn verify(&Self::PublicParams, x: &T, y: &T, proof: &Self::Proof) -> Result<bool>;
}

#[derive(Clone, Debug)]
pub struct HvhPost<H: Hasher, V: Vdf<H::Domain>> {
    _t: PhantomData<H>,
    _v: PhantomData<V>,
}

impl<'a, H: Hasher + 'a, V: Vdf<H::Domain>> ProofScheme<'a> for HvhPost<H, V> {
    type PublicParams = HvhPostPublicParams<H::Domain, V>;
    type SetupParams = HvhPostSetupParams<H::Domain, V>;
    type PublicInputs = HvhPostPublicInputs<H::Domain>;
    type PrivateInputs = HvhPostPrivateInputs<'a>;
    type Proof = HvhPostProof<'a, H::Domain, V>;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(HvhPostPublicParams {
            challenge_count: sp.challenge_count,
            sector_size: sp.sector_size,
            post_iterations: sp.post_iterations,
            pub_params_vdf: V::setup(&sp.setup_params_vdf)?,
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

        let pub_params_porep = OnlinePoRepPublicParams {
            // TODO
        };

        // Step 1: Generate first proof
        {
            let pub_inputs_porep = OnlinePoRepPublicInputs {
                challenges: &pub_inputs.challenges,
                commitment: pub_inputs.comm_r,
            };

            let priv_inputs_porep = OnlinePoRepPrivateInputs {
                replica: priv_inputs.replica,
                // TODO: pass tree + leaf
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
            let pub_inputs_porep = OnlinePoRepPublicInputs {
                challenges: &pub_inputs.challenges,
                commitment: pub_inputs.comm_r,
            };

            let priv_inputs_porep = OnlinePoRepPrivateInputs {
                replica: priv_inputs.replica,
                // TODO: pass tree + leaf
            };
            proofs_porep.push(OnlinePoRep::prove(
                &pub_params_porep,
                &pub_inputs_porep,
                &priv_inputs_porep,
            )?);
        }

        Ok(HvhPostProof {
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
        let pub_params_porep = OnlinePoRepPublicParams {
            // TODO
        };

        {
            let pub_inputs_porep = OnlinePoRepPublicInputs {
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

            let pub_inputs_porep = OnlinePoRepPublicInputs {
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

pub fn extract_vdf_input<H: Hasher>(proof: &OnlinePoRepProof) -> H::Domain {
    let leafs: Vec<u8> = proof.leafs().concat();

    H::Function::hash(&leafs)
}

#[derive(Debug, Clone)]
pub struct OnlinePoRepSetupParams {}

#[derive(Debug, Clone)]
pub struct OnlinePoRepPublicParams {}

#[derive(Debug, Clone)]
pub struct OnlinePoRepPublicInputs<'a, T: Domain> {
    pub challenges: &'a [T],
    pub commitment: T,
}

#[derive(Debug, Clone)]
pub struct OnlinePoRepPrivateInputs<'a> {
    pub replica: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct OnlinePoRepProof {}

impl OnlinePoRepProof {
    pub fn leafs<'a>(&'a self) -> &'a [&'a [u8]] {
        unimplemented!();
    }
}

#[derive(Debug, Clone)]
pub struct OnlinePoRep<T: Domain> {
    _t: PhantomData<T>,
}

impl<'a, T: 'a + Domain> ProofScheme<'a> for OnlinePoRep<T> {
    type PublicParams = OnlinePoRepPublicParams;
    type SetupParams = OnlinePoRepSetupParams;
    type PublicInputs = OnlinePoRepPublicInputs<'a, T>;
    type PrivateInputs = OnlinePoRepPrivateInputs<'a>;
    type Proof = OnlinePoRepProof;

    fn setup(_sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        unimplemented!();
    }

    fn prove<'b>(
        _pub_params: &'b Self::PublicParams,
        _pub_inputs: &'b Self::PublicInputs,
        _priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        unimplemented!();
    }

    fn verify(
        _pub_params: &Self::PublicParams,
        _pub_inputs: &Self::PublicInputs,
        _proof: &Self::Proof,
    ) -> Result<bool> {
        unimplemented!();
    }
}
