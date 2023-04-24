use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::time::Instant;

use bellperson::{
    gadgets::num::AllocatedNum, util_cs::test_cs::TestConstraintSystem, ConstraintSystem,
    SynthesisError,
};
use ff::{Field, PrimeField};
use log::info;
use pasta_curves::{Ep, Eq, Fp, Fq};
use nova_snark::{
    errors::NovaError,
    provider::{ipa_pc, pedersen},
    spartan::RelaxedR1CSSNARK,
    traits::{
        circuit::{StepCircuit, TrivialTestCircuit},
        Group,
    },
    ProverKey, PublicParams, VerifierKey,
};

use crate::parameter_cache::parameter_cache_dir;

// Buffered-io buffer size.
const BUF_SIZE: usize = 2 * 1024 * 1024 * 1024;

pub type Circ2<F2> = TrivialTestCircuit<F2>;
pub type Params<G, Circ> = PublicParams<G, <G as Cycle>::G2, Circ, Circ2<<G as Cycle>::F2>>;

type VecCommit<G> = pedersen::CommitmentEngine<G>;
type PolyEval<G> = ipa_pc::EvaluationEngine<G>;
type FoldingProof<G> = RelaxedR1CSSNARK<G, PolyEval<G>>;

type RecursiveSNARK<G, Circ> =
    nova_snark::RecursiveSNARK<G, <G as Cycle>::G2, Circ, Circ2<<G as Cycle>::F2>>;

type CompressedSNARK<G, Circ> = nova_snark::CompressedSNARK<
    G,
    <G as Cycle>::G2,
    Circ,
    Circ2<<G as Cycle>::F2>,
    FoldingProof<G>,
    FoldingProof<<G as Cycle>::G2>,
>;

pub type CompressionPk<G, Circ> = ProverKey<
    G,
    <G as Cycle>::G2,
    Circ,
    Circ2<<G as Cycle>::F2>,
    FoldingProof<G>,
    FoldingProof<<G as Cycle>::G2>,
>;
pub type CompressionVk<G, Circ> = VerifierKey<
    G,
    <G as Cycle>::G2,
    Circ,
    Circ2<<G as Cycle>::F2>,
    FoldingProof<G>,
    FoldingProof<<G as Cycle>::G2>,
>;
pub type CompressionKeypair<G, Circ> = (CompressionPk<G, Circ>, CompressionVk<G, Circ>);

pub trait Cycle: Group<Scalar = Self::F, Base = Self::F2, CE = VecCommit<Self>> {
    type F: PrimeField;
    type F2: PrimeField;
    type G2: Group<Base = Self::F, Scalar = Self::F2, CE = VecCommit<Self::G2>>;
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

// Denotes a prime field as being the primary scalar field for a curve group; used to retrieve the
// curve cycle corresponding the scalar field `Self`.
pub trait CycleScalar: PrimeField {
    type G: Cycle<F = Self>;
}

impl CycleScalar for <Ep as Cycle>::F {
    type G = Ep;
}

impl CycleScalar for <Eq as Cycle>::F {
    type G = Eq;
}

pub fn params_filename(circ_id: &str) -> String {
    format!("nova_{}.params", circ_id)
}

// Compression proving key file.
pub fn pk_filename(circ_id: &str) -> String {
    format!("nova_{}.pk", circ_id)
}

// Compression verifying key file.
pub fn vk_filename(circ_id: &str) -> String {
    format!("nova_{}.vk", circ_id)
}

/// ```no_run
/// let circ = MyCircuit { ... };
/// let params = circ.gen_params();
/// let (cpk, cvk) = circ.gen_compression_keypair(&params);
/// let r_proof = circ.gen_recursive_proof(params);
/// assert!(r_proof.verify(&params));
/// let c_proof = r_proof.compress(&params, &cpk);
/// assert!(c_proof.verify(&cvk));
/// ```
pub trait NovaCircuit<G: Cycle>: StepCircuit<G::F> {
    // Returns a unique id associated with the primary circuit type (not circuit instance) that
    // identifies the circuit's parameters/keys on disk.
    fn id(&self) -> Result<String, SynthesisError> {
        let mut cs = TestConstraintSystem::<G::F>::new();
        let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(G::F::zero()))
            .expect("failed to allocate input");
        let inputs = vec![zero; self.arity()];
        self.synthesize(&mut cs, &inputs)?;
        Ok(cs.hash())
    }

    // Pretty print the circuit type's name (not circuit instance's name).
    fn circ_name(&self) -> String;

    #[inline]
    fn step_index(&self) -> usize {
        0
    }

    #[inline]
    fn num_steps(&self) -> usize {
        1
    }

    // Converts the current circuit into the next step's circuit.
    fn next_step(&mut self);

    // Returns the current step circuit's inputs.
    fn step_inputs(&self) -> Vec<G::F>;

    // Returns the current step circuit's outputs (i.e. the next step circuit's inputs).
    fn step_outputs(&self) -> Vec<G::F>;

    fn create_secondary() -> (Circ2<G::F2>, Vec<G::F2>) {
        let circ_sec = Circ2::default();
        let inputs_sec = vec![G::F2::zero(); circ_sec.arity()];
        (circ_sec, inputs_sec)
    }

    fn gen_params(&self) -> Params<G, Self> {
        let circ_name = self.circ_name();
        info!("generating nova params: {}", circ_name);
        let start = Instant::now();
        let params = PublicParams::setup(self.clone(), Circ2::default());
        let dt = start.elapsed().as_secs_f32();
        info!("successfully generated nova params: {} ({}s)", circ_name, dt);
        params
    }

    fn load_params(&self) -> anyhow::Result<Params<G, Self>> {
        let circ_id = self.id()?;
        info!("loading nova params: {}, id={}", self.circ_name(), circ_id);

        let dir = parameter_cache_dir();
        fs::create_dir_all(&dir)?;
        let params_path = dir.join(params_filename(&circ_id));

        if params_path.exists() {
            info!("reading nova params from file: {}", params_path.display());
            let reader =
                File::open(&params_path).map(|file| BufReader::with_capacity(BUF_SIZE, file))?;
            let params = serde_json::from_reader(reader)?;
            info!("successfully read nova params from file: {}", params_path.display());
            Ok(params)
        } else {
            info!("nova params file not found: {}", params_path.display());
            let params = self.gen_params();
            info!("writing nova params to file: {}", params_path.display());
            let writer =
                File::create(&params_path).map(|file| BufWriter::with_capacity(BUF_SIZE, file))?;
            serde_json::to_writer(writer, &params)?;
            info!("successfully wrote nova params to file: {}", params_path.display());
            Ok(params)
        }
    }

    fn gen_compression_keypair(&self, params: &Params<G, Self>) -> CompressionKeypair<G, Self> {
        let circ_name = self.circ_name();
        info!("generating nova compression keys: {}", circ_name);
        let start = Instant::now();
        let keypair = CompressedSNARK::setup(params).expect("compression keygen should not fail");
        let dt = start.elapsed().as_secs_f32();
        info!("successfully generated nova compression keys: {} ({}s)", circ_name, dt);
        keypair
    }

    fn load_compression_keypair(
        &self,
        params: &Params<G, Self>,
    ) -> anyhow::Result<CompressionKeypair<G, Self>> {
        let circ_id = self.id()?;
        info!("loading nova compression keys: {}, id={}", self.circ_name(), circ_id);

        let dir = parameter_cache_dir();
        fs::create_dir_all(&dir)?;
        let pk_path = dir.join(pk_filename(&circ_id));
        let vk_path = dir.join(vk_filename(&circ_id));
        let (pk_exists, vk_exists) = (pk_path.exists(), vk_path.exists());

        if pk_exists && vk_exists {
            info!("reading nova compression pk from file: {}", pk_path.display());
            let pk_reader =
                File::open(&pk_path).map(|file| BufReader::with_capacity(BUF_SIZE, file))?;
            let pk = serde_json::from_reader(pk_reader)?;
            info!("successfully read nova compression pk from file: {}", pk_path.display());

            info!("reading nova compression vk from file: {}", vk_path.display());
            let vk_reader =
                File::open(&vk_path).map(|file| BufReader::with_capacity(BUF_SIZE, file))?;
            let vk = serde_json::from_reader(vk_reader)?;
            info!("successfully read nova compression vk from file: {}", vk_path.display());

            Ok((pk, vk))
        } else {
            if !pk_exists {
                info!("nova compression pk file not found: {}", pk_path.display());
            }
            if !vk_exists {
                info!("nova compression vk file not found: {}", vk_path.display());
            }

            let (pk, vk) = self.gen_compression_keypair(params);

            info!("writing nova compression pk to file: {}", pk_path.display());
            if pk_path.exists() {
                fs::remove_file(&pk_path)?;
            }
            let pk_writer =
                File::create(&pk_path).map(|file| BufWriter::with_capacity(BUF_SIZE, file))?;
            serde_json::to_writer(pk_writer, &pk)?;
            info!("successfully wrote nova compression pk to file: {}", pk_path.display());

            info!("writing nova compression vk to file: {}", vk_path.display());
            if vk_path.exists() {
                fs::remove_file(&vk_path)?;
            }
            let vk_writer =
                File::create(&vk_path).map(|file| BufWriter::with_capacity(BUF_SIZE, file))?;
            serde_json::to_writer(vk_writer, &vk)?;
            info!("successfully wrote nova compression vk to file: {}", vk_path.display());

            Ok((pk, vk))
        }
    }

    fn gen_recursive_proof(
        &mut self,
        params: &Params<G, Self>,
    ) -> Result<RecursiveProof<G, Self>, NovaError> {
        let circ_name = self.circ_name();
        let num_steps = self.num_steps();
        info!("generating recursive proof num_steps={}: {}", num_steps, circ_name);
        assert_ne!(num_steps, 0, "circuit cannot have zero steps");
        assert_eq!(self.step_index(), 0, "circuit's step index must be zero");

        let (circ_sec, inputs_sec) = Self::create_secondary();

        let mut inputs = Vec::<Vec<G::F>>::with_capacity(num_steps + 1);

        info!("generating recursive proof step={}: {}", self.step_index(), circ_name);
        inputs.push(self.step_inputs());
        let start = Instant::now();
        let mut proof = RecursiveSNARK::prove_step(
            params,
            None,
            self.clone(),
            circ_sec.clone(),
            inputs[0].clone(),
            inputs_sec.clone(),
        )
        .map(Some)?;

        for _ in 0..num_steps - 1 {
            self.next_step();
            info!("generating recursive proof step={}: {}", self.step_index(), circ_name);
            inputs.push(self.step_inputs());
            proof = RecursiveSNARK::prove_step(
                params,
                proof.take(),
                self.clone(),
                circ_sec.clone(),
                inputs[0].clone(),
                inputs_sec.clone(),
            )
            .map(Some)?;
        }
        let dt = start.elapsed().as_secs_f32();
        inputs.push(self.step_outputs());

        info!("successfully generated recursive proof: {} ({}s)", circ_name, dt);
        Ok(RecursiveProof {
            proof: proof.expect("unwrapping proof should not fail"),
            inputs,
            circ_name,
        })
    }
}

pub struct RecursiveProof<G, Circ>
where
    G: Cycle,
    Circ: NovaCircuit<G>,
{
    pub proof: RecursiveSNARK<G, Circ>,
    pub inputs: Vec<Vec<G::F>>,
    pub circ_name: String,
}

impl<G, Circ> RecursiveProof<G, Circ>
where
    G: Cycle,
    Circ: NovaCircuit<G>,
{
    #[inline]
    pub fn num_steps(&self) -> usize {
        self.inputs.len() - 1
    }

    pub fn verify(&self, params: &Params<G, Circ>) -> Result<bool, NovaError> {
        info!("verifying recursive proof num_steps={}: {}", self.num_steps(), self.circ_name);
        let num_steps = self.num_steps();
        let (z0, z_out) = (self.inputs[0].clone(), self.inputs[num_steps].clone());
        let (_, z0_sec) = Circ::create_secondary();
        let start = Instant::now();
        let output = self.proof.verify(params, num_steps, z0, z0_sec.clone())?;
        let dt = start.elapsed().as_secs_f32();
        let is_valid = output == (z_out, z0_sec);
        if is_valid {
            info!("successfully verified recursive proof: {} ({}s)", self.circ_name, dt);
        } else {
            info!("failed to verify recursive proof: {}", self.circ_name);
        }
        Ok(is_valid)
    }

    pub fn compress(
        &self,
        params: &Params<G, Circ>,
        pk: &CompressionPk<G, Circ>,
    ) -> Result<CompressedProof<G, Circ>, NovaError> {
        info!("compressing recursive proof: {}", self.circ_name);
        let start = Instant::now();
        let proof = CompressedSNARK::prove(params, pk, &self.proof)?;
        let dt = start.elapsed().as_secs_f32();
        info!("successfully compressed recursive proof: {} ({}s)", self.circ_name, dt);
        Ok(CompressedProof {
            proof,
            inputs: self.inputs.clone(),
            circ_name: self.circ_name.clone(),
        })
    }
}

pub struct CompressedProof<G, Circ>
where
    G: Cycle,
    Circ: NovaCircuit<G>,
{
    pub proof: CompressedSNARK<G, Circ>,
    pub inputs: Vec<Vec<G::F>>,
    pub circ_name: String,
}

impl<G, Circ> CompressedProof<G, Circ>
where
    G: Cycle,
    Circ: NovaCircuit<G>,
{
    #[inline]
    pub fn num_steps(&self) -> usize {
        self.inputs.len() - 1
    }

    pub fn verify(&self, vk: &CompressionVk<G, Circ>) -> Result<bool, NovaError> {
        info!("verifying compressed proof: {}", self.circ_name);
        let num_steps = self.num_steps();
        let (z0, z_out) = (self.inputs[0].clone(), self.inputs[num_steps].clone());
        let (_, z0_sec) = Circ::create_secondary();
        let start = Instant::now();
        let output = self.proof.verify(vk, num_steps, z0, z0_sec.clone())?;
        let dt = start.elapsed().as_secs_f32();
        let is_valid = output == (z_out, z0_sec);
        if is_valid {
            info!("successfully verified compressed proof: {} ({}s)", self.circ_name, dt);
        } else {
            info!("failed to verify compressed proof: {}", self.circ_name);
        }
        Ok(is_valid)
    }

    pub fn proof_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut zlib = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::default());
        bincode::serialize_into(&mut zlib, &self.proof)?;
        zlib.finish().map_err(Into::into)
    }
}
