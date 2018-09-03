use bellman::groth16;
use circuit::drgporep::DrgPoRepCompound;
use compound_proof::{self, CompoundProof};
use drgporep::{self, DrgParams, DrgPoRep, SetupParams};
use drgraph::{new_seed, BucketGraph};
use error::Result;
use fr32::{bytes_into_fr, fr_into_bytes, Fr32Ary};
use hasher::pedersen::PedersenHash;
use pairing::bls12_381::Bls12;
use pairing::Engine;
use parameter_cache::{parameter_cache_path, read_cached_params, write_params_to_cache};
use porep::{PoRep, Tau};
use proof::ProofScheme;
use sapling_crypto::jubjub::JubjubBls12;

use std::fs::File;
use std::io::Write;
use std::io::{BufWriter, Read};
use std::path::PathBuf;

type Commitment = [u8; 32];

/// How big, in bytes, is a SNARK proof?
pub const SNARK_BYTES: usize = 192;
type SnarkProof = [u8; SNARK_BYTES];

/// FrSafe is an array of the largest whole number of bytes guaranteed not to overflow the field.
type FrSafe = [u8; 31];

/// We need a distinguished place to cache 'the' parameters corresponding to the SetupParams
/// currently being used. These are only easily generated at replication time but need to be
/// accessed at verification time too.
const DUMMY_PARAMETER_CACHE_FILE: &str = "API-dummy-parameters";
/// If we try to read the cache while another process (like a test on CI…) is writing it,
/// things will go badly.

fn dummy_parameter_cache_path() -> PathBuf {
    parameter_cache_path(DUMMY_PARAMETER_CACHE_FILE)
}

pub const SECTOR_BYTES: usize = 64;
pub const LAMBDA: usize = 32;

lazy_static! {
    pub static ref SETUP_PARAMS: SetupParams = SetupParams {
        lambda: LAMBDA,
        drg: DrgParams {
            nodes: SECTOR_BYTES / LAMBDA,
            degree: 2,
            expansion_degree: 0,
            seed: new_seed(),
        },
        sloth_iter: 1
    };
    pub static ref PUBLIC_PARAMS: drgporep::PublicParams<BucketGraph> =
        <DrgPoRep<BucketGraph> as ProofScheme>::setup(&SETUP_PARAMS).unwrap();
    pub static ref ENGINE_PARAMS: JubjubBls12 = JubjubBls12::new();
}

fn commitment_from_fr<E: Engine>(fr: E::Fr) -> Commitment {
    let mut commitment = [0; 32];
    for (i, b) in fr_into_bytes::<E>(&fr).iter().enumerate() {
        commitment[i] = *b;
    }
    commitment
}

fn pad_safe_fr(unpadded: FrSafe) -> Fr32Ary {
    let mut res = [0; 32];
    res[0..31].copy_from_slice(&unpadded);
    res
}

pub fn seal(
    in_path: &PathBuf,
    out_path: &PathBuf,
    prover_id_in: FrSafe,
    challenge_seed: [u8; 32],
) -> Result<(Commitment, Commitment, SnarkProof)> {
    let f_in = File::open(in_path)?;

    let mut data = Vec::with_capacity(SECTOR_BYTES);
    f_in.take(SECTOR_BYTES as u64).read_to_end(&mut data)?;

    // Zero-pad the data
    for _ in data.len()..SECTOR_BYTES {
        data.push(0);
    }

    // Zero-pad the prover_id to 32 bytes (and therefore Fr32).
    let prover_id = pad_safe_fr(prover_id_in);

    let (tau, aux) = DrgPoRep::replicate(&PUBLIC_PARAMS, &prover_id, data.as_mut_slice())?;

    {
        let f_out = File::create(out_path)?;
        let mut buf_writer = BufWriter::new(f_out);
        buf_writer.write_all(&data)?;
    }

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &(*SETUP_PARAMS),
        engine_params: &(*ENGINE_PARAMS),
    };

    let compound_public_params = DrgPoRepCompound::<BucketGraph>::setup(&compound_setup_params)?;

    let prover_id_fr = bytes_into_fr::<Bls12>(&prover_id)?;

    let challenge = derive_challenge(
        fr_into_bytes::<Bls12>(&tau.comm_r.0).as_slice(),
        fr_into_bytes::<Bls12>(&tau.comm_d.0).as_slice(),
        challenge_seed,
    );
    let public_inputs = drgporep::PublicInputs {
        prover_id: prover_id_fr,
        challenges: vec![challenge],
        tau: Some(tau),
    };

    let private_inputs = drgporep::PrivateInputs {
        replica: data.as_slice(),
        aux: &aux,
    };

    let proof = DrgPoRepCompound::prove(&compound_public_params, &public_inputs, &private_inputs)?;

    let mut buf = Vec::with_capacity(SNARK_BYTES);

    proof.circuit_proof.write(&mut buf)?;

    let mut proof_bytes = [0; SNARK_BYTES];
    proof_bytes.copy_from_slice(&buf);

    write_params_to_cache(proof.groth_params.clone(), &dummy_parameter_cache_path())?;

    // We can eventually remove these assertions for performance, but we really
    // don't want to return an invalid proof, so for now let's make sure we can't.
    assert!(DrgPoRepCompound::verify(
        &(*PUBLIC_PARAMS),
        &public_inputs,
        proof,
    )?);

    assert!(verify_seal(
        commitment_from_fr::<Bls12>(tau.comm_r.0),
        commitment_from_fr::<Bls12>(tau.comm_d.0),
        prover_id_in,
        challenge_seed,
        &proof_bytes,
    )?);

    Ok((
        commitment_from_fr::<Bls12>(tau.comm_r.0),
        commitment_from_fr::<Bls12>(tau.comm_d.0),
        proof_bytes,
    ))
}

pub fn get_unsealed_range(
    sealed_path: &PathBuf,
    output_path: &PathBuf,
    prover_id_in: FrSafe,
    offset: u64,
    num_bytes: u64,
) -> Result<(u64)> {
    let prover_id = pad_safe_fr(prover_id_in);

    let f_in = File::open(sealed_path)?;

    let mut data = Vec::new();
    f_in.take(SECTOR_BYTES as u64).read_to_end(&mut data)?;

    let extracted = DrgPoRep::extract_all(&(*PUBLIC_PARAMS), &prover_id, &data)?;

    let f_out = File::create(output_path)?;
    let mut buf_writer = BufWriter::new(f_out);

    let written = buf_writer.write(&extracted[offset as usize..(offset + num_bytes) as usize])?;

    Ok(written as u64)
}

pub fn verify_seal(
    comm_r: Commitment,
    comm_d: Commitment,
    prover_id: FrSafe,
    challenge_seed: [u8; 32],
    proof_vec: &[u8],
) -> Result<bool> {
    let challenge = derive_challenge(&comm_r, &comm_d, challenge_seed);

    let prover_id = pad_safe_fr(prover_id);
    let prover_id_fr = bytes_into_fr::<Bls12>(&prover_id)?;

    let comm_r = PedersenHash(bytes_into_fr::<Bls12>(&comm_r)?);
    let comm_d = PedersenHash(bytes_into_fr::<Bls12>(&comm_d)?);

    let public_inputs = drgporep::PublicInputs {
        prover_id: prover_id_fr,
        challenges: vec![challenge],
        tau: Some(Tau { comm_r, comm_d }),
    };
    let proof = groth16::Proof::read(proof_vec)?;
    let groth_params = read_cached_params(&dummy_parameter_cache_path())?;

    let proof = compound_proof::Proof {
        circuit_proof: proof,
        groth_params,
    };

    DrgPoRepCompound::verify(&(*PUBLIC_PARAMS), &public_inputs, proof)
}

fn derive_challenge(_comm_r: &[u8], _comm_d: &[u8], _challenge_seed: [u8; 32]) -> usize {
    // TODO: actually derive challenge(s).
    1
}
