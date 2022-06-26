use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::{CurveAffine, CurveExt, FieldExt},
    pasta::{Ep, Eq, Fp, Fq},
    plonk::{
        self, keygen_pk, keygen_vk, BatchVerifier, Circuit, Error, ProvingKey, SingleVerifier,
        VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::RngCore;

use crate::proof::ProofScheme;

type Challenge<C> = Challenge255<C>;
type TranscriptReader<'proof, C> = Blake2bRead<&'proof [u8], C, Challenge<C>>;
type TranscriptWriter<C> = Blake2bWrite<Vec<u8>, C, Challenge<C>>;

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

pub struct Halo2Keypair<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    params: Params<C>,
    pk: ProvingKey<C>,
    _circ: PhantomData<Circ>,
}

impl<C, Circ> Halo2Keypair<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    pub fn create(empty_circuit: &Circ) -> Result<Self, Error> {
        let params = Params::new(empty_circuit.k());
        let vk = keygen_vk(&params, empty_circuit)?;
        let pk = keygen_pk(&params, vk, empty_circuit)?;
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
    circuit: Circ,
    pub_inputs: &[Vec<C::Scalar>],
    rng: R,
) -> Result<Halo2Proof<C, Circ>, Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
    R: RngCore,
{
    let pub_inputs: Vec<&[C::Scalar]> = pub_inputs.iter().map(Vec::as_slice).collect();
    let mut transcript = TranscriptWriter::init(vec![]);
    plonk::create_proof(
        keypair.params(),
        keypair.pk(),
        &[circuit],
        &[&pub_inputs],
        rng,
        &mut transcript,
    )?;
    let proof_bytes: Vec<u8> = transcript.finalize();
    Ok(Halo2Proof::from(proof_bytes))
}

pub fn create_batch_proof<C, Circ, R>(
    keypair: &Halo2Keypair<C, Circ>,
    circuits: &[Circ],
    pub_inputs: &[Vec<Vec<C::Scalar>>],
    rng: R,
) -> Result<Halo2Proof<C, Circ>, Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
    R: RngCore,
{
    assert_eq!(circuits.len(), pub_inputs.len());
    let pub_inputs: Vec<Vec<&[C::Scalar]>> = pub_inputs
        .iter()
        .map(|partition_pub_inputs| partition_pub_inputs.iter().map(Vec::as_slice).collect())
        .collect();
    let pub_inputs: Vec<&[&[C::Scalar]]> = pub_inputs.iter().map(Vec::as_slice).collect();
    let mut transcript = TranscriptWriter::init(vec![]);
    plonk::create_proof(
        keypair.params(),
        keypair.pk(),
        circuits,
        &pub_inputs,
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
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    let strategy = SingleVerifier::new(keypair.params());
    let pub_inputs: Vec<&[C::Scalar]> = pub_inputs.iter().map(Vec::as_slice).collect();
    let mut transcript = TranscriptReader::init(proof.as_bytes());
    plonk::verify_proof(
        keypair.params(),
        keypair.vk(),
        strategy,
        &[&pub_inputs],
        &mut transcript,
    )
}

pub fn verify_batch_proof<C, Circ, R>(
    keypair: &Halo2Keypair<C, Circ>,
    batch_proof: &Halo2Proof<C, Circ>,
    pub_inputs: &[Vec<Vec<C::Scalar>>],
    rng: R,
) -> Result<(), Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
    R: RngCore,
{
    let strategy = BatchVerifier::new(keypair.params(), rng);
    let pub_inputs: Vec<Vec<&[C::Scalar]>> = pub_inputs
        .iter()
        .map(|partition_pub_inputs| partition_pub_inputs.iter().map(Vec::as_slice).collect())
        .collect();
    let pub_inputs: Vec<&[&[C::Scalar]]> = pub_inputs.iter().map(Vec::as_slice).collect();
    let mut transcript = TranscriptReader::init(batch_proof.as_bytes());
    let _strategy = plonk::verify_proof(
        keypair.params(),
        keypair.vk(),
        strategy,
        &pub_inputs,
        &mut transcript,
    )?;
    Ok(())
}

pub trait CompoundProof<'a, F, const SECTOR_NODES: usize>: ProofScheme<'a>
where
    F: FieldExt + FieldProvingCurves,
{
    type Circuit: Circuit<F> + CircuitRows;

    #[inline]
    fn create_keypair(
        empty_circuit: &Self::Circuit,
    ) -> Result<Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>, Error> {
        Halo2Keypair::create(empty_circuit)
    }

    fn prove_partition_with_vanilla(
        setup_params: &Self::SetupParams,
        vanilla_pub_inputs: &Self::PublicInputs,
        vanilla_proof: &Self::Proof,
        keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
    ) -> Result<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>, Error>;

    fn prove_all_partitions_with_vanilla(
        setup_params: &Self::SetupParams,
        vanilla_pub_inputs: &Self::PublicInputs,
        vanilla_proofs: &[Self::Proof],
        keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
    ) -> Result<Vec<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>>, Error>;

    fn batch_prove_all_partitions_with_vanilla(
        setup_params: &Self::SetupParams,
        vanilla_pub_inputs: &Self::PublicInputs,
        vanilla_proofs: &[Self::Proof],
        keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
    ) -> Result<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>, Error>;

    fn verify_partition(
        setup_params: &Self::SetupParams,
        vanilla_pub_inputs: &Self::PublicInputs,
        circ_proof: &Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>,
        keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
    ) -> Result<(), Error>;

    fn verify_all_partitions(
        setup_params: &Self::SetupParams,
        vanilla_pub_inputs: &Self::PublicInputs,
        circ_proofs: &[Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>],
        keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
    ) -> Result<(), Error>;

    fn batch_verify_all_partitions(
        setup_params: &Self::SetupParams,
        vanilla_pub_inputs: &Self::PublicInputs,
        circ_proofs: &Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>,
        keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
    ) -> Result<(), Error>;
}
