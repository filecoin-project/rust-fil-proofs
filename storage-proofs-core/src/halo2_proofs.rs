use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::{CurveAffine, CurveExt, FieldExt},
    pasta::{Ep, Eq, Fp, Fq},
    plonk::{self, keygen_pk, keygen_vk, Circuit, Error, ProvingKey, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::RngCore;

use crate::proof::ProofScheme;

type Challenge<C> = Challenge255<C>;
type TranscriptReader<'proof, C> = Blake2bRead<&'proof [u8], C, Challenge<C>>;
type TranscriptWriter<C> = Blake2bWrite<Vec<u8>, C, Challenge<C>>;

pub struct Halo2Keypair<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar>,
{
    params: Params<C>,
    pk: ProvingKey<C>,
    _circ: PhantomData<Circ>,
}

impl<C, Circ> Halo2Keypair<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar>,
{
    pub fn create(k: u32, circ: &Circ) -> Result<Self, Error> {
        let params = Params::new(k);
        let vk = keygen_vk(&params, circ)?;
        let pk = keygen_pk(&params, vk, circ)?;
        Ok(Halo2Keypair {
            params,
            pk,
            _circ: PhantomData,
        })
    }

    pub fn params(&self) -> &Params<C> {
        &self.params
    }

    pub fn pk(&self) -> &ProvingKey<C> {
        &self.pk
    }

    pub fn vk(&self) -> &VerifyingKey<C> {
        self.pk.get_vk()
    }
}

pub struct Halo2Proof<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar>,
{
    proof_bytes: Vec<u8>,
    _c: PhantomData<C>,
    _circ: PhantomData<Circ>,
}

impl<C, Circ> From<Vec<u8>> for Halo2Proof<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar>,
{
    fn from(proof_bytes: Vec<u8>) -> Self {
        Halo2Proof {
            proof_bytes,
            _c: PhantomData,
            _circ: PhantomData,
        }
    }
}

impl<C, Circ> Halo2Proof<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar>,
{
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }
}

pub fn create_proof<C, Circ, R>(
    keypair: &Halo2Keypair<C, Circ>,
    circ: Circ,
    pub_inputs: &[Vec<C::Scalar>],
    rng: R,
) -> Result<Halo2Proof<C, Circ>, Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar>,
    R: RngCore,
{
    let pub_inputs: Vec<&[C::Scalar]> = pub_inputs.iter().map(Vec::as_slice).collect();
    let mut transcript = TranscriptWriter::<C>::init(vec![]);
    plonk::create_proof(
        keypair.params(),
        keypair.pk(),
        &[circ],
        &[&pub_inputs],
        rng,
        &mut transcript,
    )?;
    let proof_bytes: Vec<u8> = transcript.finalize();
    Ok(Halo2Proof::from(proof_bytes))
}

pub fn verify_proof<C, Circ>(
    keypair: &Halo2Keypair<C, Circ>,
    proof: &Halo2Proof<C, Circ>,
    pub_inputs: &[Vec<C::Scalar>],
) -> Result<(), Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar>,
{
    let pub_inputs: Vec<&[C::Scalar]> = pub_inputs.iter().map(Vec::as_slice).collect();
    let strategy = SingleVerifier::new(keypair.params());
    let mut transcript = TranscriptReader::<C>::init(proof.as_bytes());
    plonk::verify_proof(
        keypair.params(),
        keypair.vk(),
        strategy,
        &[&pub_inputs],
        &mut transcript,
    )
}

pub trait FieldProvingCurves: FieldExt {
    type Curve: CurveExt<ScalarExt = Self>;
    type Affine: CurveAffine<ScalarExt = Self>;
}

impl FieldProvingCurves for Fp {
    type Curve = Eq;
    type Affine = <Self::Curve as CurveExt>::AffineExt;
}

impl FieldProvingCurves for Fq {
    type Curve = Ep;
    type Affine = <Self::Curve as CurveExt>::AffineExt;
}

pub trait CircuitRows {
    fn k(&self) -> u32;
}

pub trait CompoundProof<'a, F, const SECTOR_NODES: usize>: ProofScheme<'a>
where
    F: FieldExt + FieldProvingCurves,
{
    type Circuit: Circuit<F> + CircuitRows;

    fn keypair(
        circ: &Self::Circuit,
    ) -> Result<Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>, Error> {
        Halo2Keypair::create(circ.k(), circ)
    }

    fn prove_with_vanilla_partition(
        setup_params: Self::SetupParams,
        vanilla_pub_inputs: Self::PublicInputs,
        vanilla_proof: Self::Proof,
        // TODO (jake): allow loading keypair from disk.
        // keypair: Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
    ) -> Result<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>, Error>;
}
