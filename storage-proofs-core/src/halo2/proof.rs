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

pub trait Halo2Field: FieldExt {
    type Curve: CurveExt<ScalarExt = Self>;
    type Affine: CurveAffine<ScalarExt = Self>;
}

impl Halo2Field for Fp {
    type Curve = Eq;
    type Affine = <Self::Curve as CurveExt>::AffineExt;
}

impl Halo2Field for Fq {
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
    F: Halo2Field,
{
    type Circuit: Circuit<F> + CircuitRows;

    #[inline]
    fn create_keypair(
        empty_circuit: &Self::Circuit,
    ) -> Result<Halo2Keypair<F::Affine, Self::Circuit>, Error> {
        Halo2Keypair::create(empty_circuit)
    }

    fn prove_partition_with_vanilla(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        vanilla_proof: &Self::VanillaPartitionProof,
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<Halo2Proof<F::Affine, Self::Circuit>, Error>;

    fn prove_all_partitions_with_vanilla(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        vanilla_proofs: &[Self::VanillaPartitionProof],
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<Vec<Halo2Proof<F::Affine, Self::Circuit>>, Error>;

    fn batch_prove_all_partitions_with_vanilla(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        vanilla_proofs: &[Self::VanillaPartitionProof],
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<Halo2Proof<F::Affine, Self::Circuit>, Error>;

    fn verify_partition(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        circ_proof: &Halo2Proof<F::Affine, Self::Circuit>,
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<(), Error>;

    fn verify_all_partitions(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        circ_proofs: &[Halo2Proof<F::Affine, Self::Circuit>],
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<(), Error>;

    fn batch_verify_all_partitions(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        circ_proofs: &Halo2Proof<F::Affine, Self::Circuit>,
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Advice, Column, ConstraintSystem, Selector},
        poly::Rotation,
    };
    use rand::rngs::OsRng;

    #[derive(Clone)]
    struct MyConfig {
        advice: [Column<Advice>; 2],
        s_add: Selector,
    }

    #[derive(Clone)]
    struct MyCircuit {
        a: Option<Fp>,
        b: Option<Fp>,
        c: Option<Fp>,
    }

    impl Circuit<Fp> for MyCircuit {
        type Config = MyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MyCircuit {
                a: None,
                b: None,
                c: None,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let advice = [meta.advice_column(), meta.advice_column()];

            let s_add = meta.selector();
            meta.create_gate("add", |meta| {
                let s = meta.query_selector(s_add);
                let a = meta.query_advice(advice[0], Rotation::cur());
                let b = meta.query_advice(advice[1], Rotation::cur());
                let c = meta.query_advice(advice[0], Rotation::next());
                [s * (a + b - c)]
            });

            MyConfig {
                advice,
                s_add,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let MyConfig {
                advice,
                s_add,
            } = config;

            layouter.assign_region(
                || "assign witness",
                |mut region| {
                    let mut offset = 0;
                    s_add.enable(&mut region, offset)?;
                    region.assign_advice(
                        || "a",
                        advice[0],
                        offset,
                        || self.a.ok_or(Error::Synthesis),
                    )?;
                    region.assign_advice(
                        || "b",
                        advice[1],
                        offset,
                        || self.b.ok_or(Error::Synthesis),
                    )?;
                    offset += 1;
                    region.assign_advice(
                        || "c",
                        advice[0],
                        offset,
                        || self.c.ok_or(Error::Synthesis),
                    )?;
                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    impl CircuitRows for MyCircuit {
        fn k(&self) -> u32 {
            4
        }
    }

    impl MyCircuit {
        fn blank_circuit() -> Self {
            MyCircuit {
                a: None,
                b: None,
                c: None,
            }
        }
    }

    #[test]
    fn test_halo2_prove_verify() {
        let blank_circuit = MyCircuit::blank_circuit();
        let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&blank_circuit)
            .expect("failed to create halo2 keypair");

        // Generate and verify a single proof.
        let circ = MyCircuit {
            a: Some(Fp::one()),
            b: Some(Fp::from(2)),
            c: Some(Fp::from(3)),
        };
        let prover = MockProver::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
        let proof = create_proof(&keypair, circ.clone(), &[], &mut OsRng)
            .expect("failed to create halo2 proof");
        verify_proof(&keypair, &proof, &[]).expect("failed to verify halo2 proof");

        // Generate and verify a 2-proof batch proof.
        let circs = [
            circ,
            MyCircuit {
                a: Some(Fp::from(55)),
                b: Some(Fp::from(100)),
                c: Some(Fp::from(155)),
            },
        ];
        let batch_proof = create_batch_proof(&keypair, &circs, &[vec![], vec![]], &mut OsRng)
            .expect("failed to create halo2 batch proof");
        verify_batch_proof(&keypair, &batch_proof, &[vec![], vec![]], &mut OsRng)
            .expect("failed to verify halo2 batch proof");
    }
}
