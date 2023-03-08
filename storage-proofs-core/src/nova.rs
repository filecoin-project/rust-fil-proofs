use std::fs;

use bellperson::{
    gadgets::num::AllocatedNum, util_cs::test_cs::TestConstraintSystem, ConstraintSystem,
    SynthesisError,
};
use ff::PrimeField;
use pasta_curves::{Ep, Eq, Fp, Fq};
use nova_snark::{
    errors::NovaError,
    provider::{ipa_pc::EvaluationEngine, pedersen},
    spartan::RelaxedR1CSSNARK,
    traits::{
        circuit::{StepCircuit, TrivialTestCircuit},
        Group,
    },
    CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey,
};

use crate::parameter_cache::parameter_cache_dir;

pub type SecCircuit<F2> = TrivialTestCircuit<F2>;
pub type Params<G1, Circ> = PublicParams<G1, <G1 as Cycle>::G2, Circ, SecCircuit<<G1 as Cycle>::F2>>;
pub type CompressionPk<G1, Circ> = ProverKey<
    G1,
    <G1 as Cycle>::G2,
    Circ,
    SecCircuit<<G1 as Cycle>::F2>,
    RelaxedR1CSSNARK<G1, EvaluationEngine<G1>>,
    RelaxedR1CSSNARK<<G1 as Cycle>::G2, EvaluationEngine<<G1 as Cycle>::G2>>,
>;
pub type CompressionVk<G1, Circ> = VerifierKey<
    G1,
    <G1 as Cycle>::G2,
    Circ,
    SecCircuit<<G1 as Cycle>::F2>,
    RelaxedR1CSSNARK<G1, EvaluationEngine<G1>>,
    RelaxedR1CSSNARK<<G1 as Cycle>::G2, EvaluationEngine<<G1 as Cycle>::G2>>,
>;
pub type CompressionKeypair<G1, Circ> = (CompressionPk<G1, Circ>, CompressionVk<G1, Circ>);

pub trait Cycle: Group<Scalar = Self::F, Base = Self::F2, CE = pedersen::CommitmentEngine<Self>> {
    type F: PrimeField;
    type F2: PrimeField;
    type G2: Group<Base = Self::F, Scalar = Self::F2, CE = pedersen::CommitmentEngine<Self::G2>>;
}

impl Cycle for Ep {
    type F = Fq;
    type F2 = Fp;
    type G2 = Eq;
}

impl Cycle for Eq {
    type F = Fp;
    type F2 = Fq;
    type G2 = Ep;
}

pub trait CycleScalar: PrimeField {
    type G1: Cycle<F = Self>;
}

impl CycleScalar for Fp {
    type G1 = Eq;
}

impl CycleScalar for Fq {
    type G1 = Ep;
}

pub trait StepExt<F: PrimeField>: StepCircuit<F> {
    fn step_index(&self) -> usize {
        0
    }

    fn num_steps(&self) -> usize {
        1
    }

    #[inline]
    fn is_last_step(&self) -> bool {
        self.step_index() == self.num_steps() - 1
    }

    // Transforms the current step circuit into the next step's circuit.
    fn next_step(&mut self) {}

    #[inline]
    fn num_inputs(&self) -> usize {
        self.arity()
    }

    // Returns the current step circuit's inputs.
    fn inputs(&self) -> Vec<F>;

    // Returns the current step circuit's outputs.
    fn outputs(&self) -> Vec<F>;

    // Return an id associated with the circuit type (not circuit instance) that identifies the
    // circuit's nova parameters on disk.
    fn id(&self) -> Result<String, SynthesisError> {
        let mut cs = TestConstraintSystem::<F>::new();
        let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(F::zero()))
            .expect("failed to allocate input");
        let z0 = vec![zero; self.num_inputs()];
        self.synthesize(&mut cs, &z0)?;
        Ok(cs.hash())
    }
}

impl<F: PrimeField> StepExt<F> for SecCircuit<F> {
    #[inline]
    fn inputs(&self) -> Vec<F> {
        vec![F::zero(); self.arity()]
    }

    #[inline]
    fn outputs(&self) -> Vec<F> {
        self.inputs()
    }
}

fn create_secondary<F2: PrimeField>() -> (SecCircuit<F2>, Vec<F2>) {
    let circ_sec = SecCircuit::default();
    let z0_sec = circ_sec.inputs();
    (circ_sec, z0_sec)
}

#[inline]
pub fn gen_params<G1, Circ>(circ: Circ) -> Params<G1, Circ>
where
    G1: Cycle,
    Circ: StepCircuit<G1::F>,
{
    PublicParams::setup(circ, SecCircuit::default())
}

pub fn gen_recursive_proof<G1, Circ>(
    params: &Params<G1, Circ>,
    mut circ: Circ,
) -> Result<RecursiveProof<G1, Circ>, NovaError>
where
    G1: Cycle,
    Circ: StepExt<G1::F>,
{
    let num_steps = circ.num_steps();
    assert_ne!(num_steps, 0, "circuit cannot have zero steps");
    assert_eq!(circ.step_index(), 0, "circuit's step index must be zero");

    let z0 = circ.inputs();
    let (circ_sec, z0_sec) = create_secondary();

    let mut proof = RecursiveSNARK::prove_step(
        params,
        None,
        circ.clone(),
        circ_sec.clone(),
        z0.clone(),
        z0_sec.clone(),
    )
    .map(Some)?;

    let mut zs = Vec::with_capacity(num_steps + 1);
    zs.push(z0.clone());
    zs.push(circ.outputs());

    for _ in 0..num_steps - 1 {
        circ.next_step();
        assert_eq!(circ.inputs(), zs[circ.step_index()]);
        proof = RecursiveSNARK::prove_step(
            params,
            proof.take(),
            circ.clone(),
            circ_sec.clone(),
            z0.clone(),
            z0_sec.clone(),
        )
        .map(Some)?;
        zs.push(circ.outputs());
    }

    Ok(RecursiveProof {
        proof: proof.expect("proof should be set"),
        zs,
    })
}

pub fn verify_recursive_proof<G1, Circ>(
    params: &Params<G1, Circ>,
    proof: &RecursiveProof<G1, Circ>,
) -> Result<bool, NovaError>
where
    G1: Cycle,
    Circ: StepExt<G1::F>,
{
    let num_steps = proof.num_steps();
    let z0 = proof.z0().to_vec();
    let (_, z0_sec) = create_secondary();
    let expected_output = (proof.z_out().to_vec(), z0_sec.clone());
    let output = proof.proof.verify(params, num_steps, z0, z0_sec)?;
    Ok(output == expected_output)
}

#[inline]
pub fn gen_compression_keypair<G1, Circ>(params: &Params<G1, Circ>) -> CompressionKeypair<G1, Circ>
where
    G1: Cycle,
    Circ: StepCircuit<G1::F>,
{
    CompressedSNARK::setup(params)
}

#[inline]
pub fn gen_compressed_proof<G1, Circ>(
    params: &Params<G1, Circ>,
    pk: &CompressionPk<G1, Circ>,
    rec_proof: &RecursiveProof<G1, Circ>,
) -> Result<CompressedProof<G1, Circ>, NovaError>
where
    G1: Cycle,
    Circ: StepExt<G1::F>,
{
    CompressedSNARK::prove(params, pk, &rec_proof.proof).map(|cmpr_proof| {
        CompressedProof {
            proof: cmpr_proof,
            zs: rec_proof.zs.clone(),
        }
    })
}

pub fn verify_compressed_proof<G1, Circ>(
    vk: &CompressionVk<G1, Circ>,
    proof: &CompressedProof<G1, Circ>,
) -> Result<bool, NovaError>
where
    G1: Cycle,
    Circ: StepExt<G1::F>,
{
    let num_steps = proof.num_steps();
    let z0 = proof.z0().to_vec();
    let (_, z0_sec) = create_secondary();
    let expected_output = (proof.z_out().to_vec(), z0_sec.clone());
    let output = proof.proof.verify(vk, num_steps, z0, z0_sec)?;
    Ok(output == expected_output)
}

pub struct ParamStore;

impl ParamStore {
    pub fn params<G1, Circ>(circ: Circ) -> anyhow::Result<Params<G1, Circ>>
    where
        G1: Cycle,
        Circ: StepExt<G1::F>,
    {
        let circ_id = circ.id()?;
        let params_dir = parameter_cache_dir();
        fs::create_dir_all(&params_dir)?;
        let params_path = params_dir.join(format!("nova_params_{}", circ_id));
        let params = if params_path.exists() {
            let params_bytes = fs::read(&params_path)?;
            serde_json::from_slice(&params_bytes)?
        } else {
            let params = gen_params::<G1, Circ>(circ);
            let params_bytes = serde_json::to_vec(&params)?;
            fs::write(&params_path, &params_bytes)?;
            params
        };
        Ok(params)
    }

    pub fn compression_keypair<G1, Circ>(
        circ: &Circ,
        params: &Params<G1, Circ>,
    ) -> anyhow::Result<CompressionKeypair<G1, Circ>>
    where
        G1: Cycle,
        Circ: StepExt<G1::F>,
    {
        let circ_id = circ.id()?;
        let params_dir = parameter_cache_dir();
        fs::create_dir_all(&params_dir)?;
        let pk_path = params_dir.join(format!("nova_pk_{}", circ_id));
        let vk_path = params_dir.join(format!("nova_vk_{}", circ_id));
        if pk_path.exists() && vk_path.exists() {
            let pk_bytes = fs::read(&pk_path)?;
            let vk_bytes = fs::read(&vk_path)?;
            let pk = serde_json::from_slice(&pk_bytes)?;
            let vk = serde_json::from_slice(&vk_bytes)?;
            Ok((pk, vk))
        } else {
            let (pk, vk) = gen_compression_keypair(params);
            let pk_bytes = serde_json::to_vec(&pk)?;
            let vk_bytes = serde_json::to_vec(&vk)?;
            fs::write(&pk_path, &pk_bytes)?;
            fs::write(&vk_path, &vk_bytes)?;
            Ok((pk, vk))
        }
    }
}

pub struct RecursiveProof<G1, Circ>
where
    G1: Cycle,
    Circ: StepExt<G1::F>,
{
    pub proof: RecursiveSNARK<G1, G1::G2, Circ, SecCircuit<G1::F2>>,
    pub zs: Vec<Vec<G1::F>>,
}

impl<G1, Circ> RecursiveProof<G1, Circ>
where
    G1: Cycle,
    Circ: StepExt<G1::F>,
{
    #[inline]
    pub fn num_steps(&self) -> usize {
        self.zs.len() - 1
    }

    #[inline]
    pub fn z0(&self) -> &[G1::F] {
        &self.zs[0]
    }

    #[inline]
    pub fn z_out(&self) -> &[G1::F] {
        &self.zs[self.num_steps()]
    }

    #[inline]
    pub fn verify(&self, params: &Params<G1, Circ>) -> Result<bool, NovaError> {
        verify_recursive_proof(params, self)
    }

    #[inline]
    pub fn gen_compressed_proof(
        &self,
        params: &Params<G1, Circ>,
        pk: &CompressionPk<G1, Circ>,
    ) -> Result<CompressedProof<G1, Circ>, NovaError> {
        gen_compressed_proof(params, pk, self)
    }

    #[inline]
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(&self.proof).map_err(Into::into)
    }

    pub fn from_bytes(mut circ: Circ, proof_bytes: &[u8]) -> anyhow::Result<Self> {
        let num_steps = circ.num_steps();
        assert_ne!(num_steps, 0);
        assert_eq!(circ.step_index(), 0);
        let proof = serde_json::from_slice(&proof_bytes)?;
        let mut zs = Vec::<Vec<G1::F>>::with_capacity(num_steps + 1);
        zs.push(circ.inputs());
        for _ in 0..num_steps {
            zs.push(circ.outputs());
            circ.next_step();
        }
        Ok(RecursiveProof { proof, zs })
    }
}

pub struct CompressedProof<G1, Circ>
where
    G1: Cycle,
    Circ: StepExt<G1::F>,
{
    pub proof: CompressedSNARK<
        G1,
        G1::G2,
        Circ,
        SecCircuit<G1::F2>,
        RelaxedR1CSSNARK<G1, EvaluationEngine<G1>>,
        RelaxedR1CSSNARK<G1::G2, EvaluationEngine<G1::G2>>,
    >,
    pub zs: Vec<Vec<G1::F>>,
}

impl<G1, Circ> CompressedProof<G1, Circ>
where
    G1: Cycle,
    Circ: StepExt<G1::F>,
{
    #[inline]
    pub fn num_steps(&self) -> usize {
        self.zs.len() - 1
    }

    #[inline]
    pub fn z0(&self) -> &[G1::F] {
        &self.zs[0]
    }

    #[inline]
    pub fn z_out(&self) -> &[G1::F] {
        &self.zs[self.num_steps()]
    }

    #[inline]
    pub fn verify(&self, vk: &CompressionVk<G1, Circ>) -> Result<bool, NovaError> {
        verify_compressed_proof(vk, self)
    }

    #[inline]
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(&self.proof).map_err(Into::into)
    }

    pub fn from_bytes(mut circ: Circ, proof_bytes: &[u8]) -> anyhow::Result<Self> {
        let num_steps = circ.num_steps();
        assert_ne!(num_steps, 0);
        assert_eq!(circ.step_index(), 0);
        let proof = serde_json::from_slice(&proof_bytes)?;
        let mut zs = Vec::<Vec<G1::F>>::with_capacity(num_steps + 1);
        zs.push(circ.inputs());
        for _ in 0..num_steps {
            zs.push(circ.outputs());
            circ.next_step();
        }
        Ok(CompressedProof { proof, zs })
    }
}
