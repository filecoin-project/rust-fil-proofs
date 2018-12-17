use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;
use std::{thread, time};

use bellman::groth16;
use pairing::bls12_381::Bls12;
use pairing::Engine;
use sapling_crypto::jubjub::JubjubBls12;

use sector_base::api::disk_backed_storage::REAL_SECTOR_SIZE;
use sector_base::api::sector_store::SectorConfig;
use sector_base::api::sector_store::SectorStore;
use sector_base::io::fr32::write_unpadded;
use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgporep::{self, DrgParams};
use storage_proofs::drgraph::{new_seed, DefaultTreeHasher};
use storage_proofs::error::Result;
use storage_proofs::fr32::{bytes_into_fr, fr_into_bytes, Fr32Ary};
use storage_proofs::hasher::Hasher;
use storage_proofs::layered_drgporep;
use storage_proofs::merkle::MerkleTree;
use storage_proofs::parameter_cache::{
    parameter_cache_dir, parameter_cache_path, read_cached_params, write_params_to_cache,
};
use storage_proofs::porep::{replica_id, PoRep, Tau};
use storage_proofs::proof::ProofScheme;
use storage_proofs::zigzag_drgporep::ZigZagDrgPoRep;
use storage_proofs::zigzag_graph::ZigZagBucketGraph;

type Commitment = [u8; 32];

/// FrSafe is an array of the largest whole number of bytes guaranteed not to overflow the field.
type FrSafe = [u8; 31];

/// How big, in bytes, is the SNARK proof exposed by the API?
///
/// Note: These values need to be kept in sync with what's in api/mod.rs.
/// Due to limitations of cbindgen, we can't define a constant whose value is
/// a non-primitive (e.g. an expression like 192 * 2 or internal::STUFF) and
/// see the constant in the generated C-header file.
const SNARK_BYTES: usize = 192;
const POREP_PARTITIONS: usize = 2;
const POREP_PROOF_BYTES: usize = SNARK_BYTES * POREP_PARTITIONS;

type SnarkProof = [u8; POREP_PROOF_BYTES];

/// How big should a fake sector be when faking proofs?
const FAKE_SECTOR_BYTES: usize = 128;

fn dummy_parameter_cache_path(sector_config: &SectorConfig, sector_size: usize) -> PathBuf {
    parameter_cache_path(&format!(
        "{}[{}]",
        sector_config.dummy_parameter_cache_name(),
        sector_size
    ))
}

pub const OFFICIAL_ZIGZAG_PARAM_FILENAME: &str = "params.out";

lazy_static! {
    pub static ref ENGINE_PARAMS: JubjubBls12 = JubjubBls12::new();
}

lazy_static! {
    static ref ZIGZAG_PARAMS: Option<groth16::Parameters<Bls12>> =
        read_cached_params(&official_params_path()).ok();
}

fn official_params_path() -> PathBuf {
    parameter_cache_dir().join(OFFICIAL_ZIGZAG_PARAM_FILENAME)
}

fn get_zigzag_params() -> Option<groth16::Parameters<Bls12>> {
    (*ZIGZAG_PARAMS).clone()
}

const DEGREE: usize = 1; // TODO: 5; FIXME: increasing degree introduces a test failure. Figure out why.
const EXPANSION_DEGREE: usize = 6;
const SLOTH_ITER: usize = 0;
const LAYERS: usize = 2; // TODO: 10;
const CHALLENGE_COUNT: usize = 1;

fn setup_params(sector_bytes: usize) -> layered_drgporep::SetupParams {
    assert!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );
    let nodes = sector_bytes / 32;
    layered_drgporep::SetupParams {
        drg_porep_setup_params: drgporep::SetupParams {
            drg: DrgParams {
                nodes,
                degree: DEGREE,
                expansion_degree: EXPANSION_DEGREE,
                seed: new_seed(),
            },
            sloth_iter: SLOTH_ITER,
        },
        layers: LAYERS,
        challenge_count: CHALLENGE_COUNT,
    }
}

pub fn public_params(
    sector_bytes: usize,
) -> layered_drgporep::PublicParams<DefaultTreeHasher, ZigZagBucketGraph<DefaultTreeHasher>> {
    ZigZagDrgPoRep::<DefaultTreeHasher>::setup(&setup_params(sector_bytes)).unwrap()
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

/// Validate sector_config configuration and calculates derived configuration.
///
/// # Return Values
/// * - `fake` is true when faking.
/// * - `delay_seconds` is None if no delay.
/// * - `sector_bytes` is the size (in bytes) of sector which should be stored on disk.
/// * - `proof_sector_bytes` is the size of the sector which will be proved when faking.
pub fn get_config(sector_config: &SectorConfig) -> (bool, Option<u32>, usize, usize, bool) {
    let fake = sector_config.is_fake();
    let delay_seconds = sector_config.simulate_delay_seconds();
    let delayed = delay_seconds.is_some();
    let sector_bytes = sector_config.sector_bytes() as usize;
    let proof_sector_bytes = if fake {
        FAKE_SECTOR_BYTES
    } else {
        sector_bytes
    };

    // If configuration is 'completely real', then we can use the parameters pre-generated for the real circuit.
    let uses_official_circuit = !fake && (sector_bytes as u64 == REAL_SECTOR_SIZE);

    // It doesn't make sense to set a delay when not faking. The current implementations of SectorStore
    // never do, but if that were to change, it would be a mistake.
    let valid = if fake { true } else { !delayed };
    assert!(valid, "delay is only valid when faking");

    (
        fake,
        delay_seconds,
        sector_bytes,
        proof_sector_bytes,
        uses_official_circuit,
    )
}

pub fn seal(
    sector_store: &SectorStore,
    in_path: &PathBuf,
    out_path: &PathBuf,
    prover_id_in: FrSafe,
    sector_id_in: FrSafe,
) -> Result<(Commitment, Commitment, Commitment, SnarkProof)> {
    seal_2(
        sector_store.config(),
        in_path,
        out_path,
        prover_id_in,
        sector_id_in,
    )
}

pub fn seal_2(
    sector_config: &SectorConfig,
    in_path: &PathBuf,
    out_path: &PathBuf,
    prover_id_in: FrSafe,
    sector_id_in: FrSafe,
) -> Result<(Commitment, Commitment, Commitment, SnarkProof)> {
    let (fake, delay_seconds, sector_bytes, proof_sector_bytes, uses_official_circuit) =
        get_config(sector_config);

    let public_params = public_params(proof_sector_bytes);
    let challenge_count = public_params.challenge_count;
    if let Some(delay) = delay_seconds {
        delay_seal(delay);
    };

    let f_in = File::open(in_path)?;

    // Read all the provided data, even if we will prove less of it because we are faking.
    let mut data = Vec::with_capacity(sector_bytes);
    f_in.take(sector_bytes as u64).read_to_end(&mut data)?;

    // Zero-pad the data to the requested size.
    for _ in data.len()..sector_bytes {
        data.push(0);
    }

    // Copy all the data.
    let data_copy = data.clone();

    // Zero-pad the prover_id to 32 bytes (and therefore Fr32).
    let prover_id = pad_safe_fr(prover_id_in);
    // Zero-pad the sector_id to 32 bytes (and therefore Fr32).
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let compound_setup_params = compound_proof::SetupParams {
        // The proof might use a different number of bytes than we read and copied, if we are faking.
        vanilla_params: &setup_params(proof_sector_bytes),
        engine_params: &(*ENGINE_PARAMS),
        partitions: Some(POREP_PARTITIONS),
    };

    let compound_public_params = ZigZagCompound::setup(&compound_setup_params)?;

    let (tau, aux) = perform_replication(
        &out_path,
        &compound_public_params.vanilla_params,
        &replica_id,
        &mut data,
        fake,
        proof_sector_bytes,
    )?;

    let public_tau = tau.simplify();

    let public_inputs = layered_drgporep::PublicInputs {
        replica_id,
        challenge_count,
        tau: Some(public_tau),
        comm_r_star: tau.comm_r_star,
        k: None,
    };

    let private_inputs = layered_drgporep::PrivateInputs::<DefaultTreeHasher> {
        replica: &data_copy[0..proof_sector_bytes],
        aux,
        tau: tau.layer_taus,
    };

    let groth_params = if uses_official_circuit {
        get_zigzag_params()
    } else {
        None
    };

    let must_cache_params = if groth_params.is_some() {
        println!("Using official parameters.");
        false
    } else {
        true
    };

    let proof = ZigZagCompound::prove(
        &compound_public_params,
        &public_inputs,
        &private_inputs,
        groth_params,
    )?;

    let mut buf = Vec::with_capacity(POREP_PROOF_BYTES);

    proof.write(&mut buf)?;

    let mut proof_bytes = [0; POREP_PROOF_BYTES];
    proof_bytes.copy_from_slice(&buf);

    if must_cache_params {
        write_params_to_cache(
            proof.groth_params.clone(),
            &dummy_parameter_cache_path(sector_config, proof_sector_bytes),
        )?;
    }

    let comm_r = commitment_from_fr::<Bls12>(public_tau.comm_r.into());
    let comm_d = commitment_from_fr::<Bls12>(public_tau.comm_d.into());
    let comm_r_star = commitment_from_fr::<Bls12>(tau.comm_r_star.into());

    // Verification is cheap when parameters are cached,
    // and it is never correct to return a proof which does not verify.
    verify_seal(
        sector_config,
        comm_r,
        comm_d,
        comm_r_star,
        prover_id_in,
        sector_id_in,
        &proof_bytes,
    )
    .expect("post-seal verification sanity check failed");

    Ok((comm_r, comm_d, comm_r_star, proof_bytes))
}

fn delay_seal(seconds: u32) {
    let delay = time::Duration::from_secs(u64::from(seconds));
    thread::sleep(delay);
}

fn delay_get_unsealed_range(base_seconds: u32) {
    let delay = time::Duration::from_secs(u64::from(base_seconds / 2));
    thread::sleep(delay);
}

fn perform_replication(
    out_path: &PathBuf,
    public_params: &<ZigZagDrgPoRep<DefaultTreeHasher> as ProofScheme>::PublicParams,
    replica_id: &<DefaultTreeHasher as Hasher>::Domain,
    data: &mut [u8],
    fake: bool,
    proof_sector_bytes: usize,
) -> Result<(
    layered_drgporep::Tau<<DefaultTreeHasher as Hasher>::Domain>,
    Vec<MerkleTree<<DefaultTreeHasher as Hasher>::Domain, <DefaultTreeHasher as Hasher>::Function>>,
)> {
    if fake {
        // When faking replication, we write the original data to disk, before replication.
        write_data(out_path, data)?;

        assert!(
            data.len() >= FAKE_SECTOR_BYTES,
            "data length ({}) is less than FAKE_SECTOR_BYTES ({}) when faking replication",
            data.len(),
            FAKE_SECTOR_BYTES
        );
        let (tau, aux) = ZigZagDrgPoRep::replicate(
            public_params,
            &replica_id,
            &mut data[0..proof_sector_bytes],
            None,
        )?;
        Ok((tau, aux))
    } else {
        // When not faking replication, we write the replicated data to disk, after replication.
        let (tau, aux) = ZigZagDrgPoRep::replicate(public_params, &replica_id, data, None)?;

        write_data(out_path, data)?;
        Ok((tau, aux))
    }
}

fn write_data(out_path: &PathBuf, data: &[u8]) -> Result<()> {
    // Write replicated data to out_path.
    let f_out = File::create(out_path)?;
    let mut buf_writer = BufWriter::new(f_out);
    buf_writer.write_all(&data)?;
    Ok(())
}

pub fn get_unsealed_range(
    sector_store: &SectorStore,
    sealed_path: &PathBuf,
    output_path: &PathBuf,
    prover_id_in: FrSafe,
    sector_id_in: FrSafe,
    offset: u64,
    num_bytes: u64,
) -> Result<(u64)> {
    let (fake, delay_seconds, sector_bytes, proof_sector_bytes, _uses_official_circuit) =
        get_config(sector_store.config());
    if let Some(delay) = delay_seconds {
        delay_get_unsealed_range(delay);
    }

    let prover_id = pad_safe_fr(prover_id_in);
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let f_in = File::open(sealed_path)?;
    let mut data = Vec::new();
    f_in.take(sector_bytes as u64).read_to_end(&mut data)?;

    let f_out = File::create(output_path)?;
    let mut buf_writer = BufWriter::new(f_out);

    let unsealed = if fake {
        data
    } else {
        ZigZagDrgPoRep::extract_all(&public_params(proof_sector_bytes), &replica_id, &data)?
    };

    let written = write_unpadded(
        &unsealed,
        &mut buf_writer,
        offset as usize,
        num_bytes as usize,
    )?;

    Ok(written as u64)
}

pub fn verify_seal(
    sector_store: &SectorConfig,
    comm_r: Commitment,
    comm_d: Commitment,
    comm_r_star: Commitment,
    prover_id_in: FrSafe,
    sector_id_in: FrSafe,
    proof_vec: &[u8],
) -> Result<bool> {
    let (_fake, _delay_seconds, _sector_bytes, proof_sector_bytes, uses_official_circuit) =
        get_config(sector_store);

    let challenge_count = CHALLENGE_COUNT;
    let prover_id = pad_safe_fr(prover_id_in);
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let comm_r = bytes_into_fr::<Bls12>(&comm_r)?;
    let comm_d = bytes_into_fr::<Bls12>(&comm_d)?;
    let comm_r_star = bytes_into_fr::<Bls12>(&comm_r_star)?;

    let compound_setup_params = compound_proof::SetupParams {
        // The proof might use a different number of bytes than we read and copied, if we are faking.
        vanilla_params: &setup_params(proof_sector_bytes),
        engine_params: &(*ENGINE_PARAMS),
        partitions: Some(POREP_PARTITIONS),
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        Bls12,
        ZigZagDrgPoRep<'_, DefaultTreeHasher>,
    > = ZigZagCompound::setup(&compound_setup_params)?;

    let public_inputs = layered_drgporep::PublicInputs::<<DefaultTreeHasher as Hasher>::Domain> {
        replica_id,
        challenge_count,
        tau: Some(Tau {
            comm_r: comm_r.into(),
            comm_d: comm_d.into(),
        }),
        comm_r_star: comm_r_star.into(),
        k: None,
    };

    let groth_params = if uses_official_circuit {
        match get_zigzag_params() {
            Some(p) => p,
            None => read_cached_params(&dummy_parameter_cache_path(
                sector_store,
                proof_sector_bytes,
            ))?,
        }
    } else {
        read_cached_params(&dummy_parameter_cache_path(
            sector_store,
            proof_sector_bytes,
        ))?
    };

    let proof = MultiProof::new_from_reader(Some(POREP_PARTITIONS), proof_vec, groth_params)?;

    ZigZagCompound::verify(&compound_public_params, &public_inputs, &proof)
}
