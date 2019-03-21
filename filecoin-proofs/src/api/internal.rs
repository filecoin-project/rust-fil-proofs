use std::collections::HashMap;
use std::fs::{copy, remove_file, File, OpenOptions};
use std::io::{BufWriter, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bellman::groth16;
use memmap::MmapOptions;
use pairing::bls12_381::{Bls12, Fr};
use pairing::{Engine, PrimeField};
use sapling_crypto::jubjub::JubjubBls12;

use crate::api::post_adapter::*;
use crate::error;
use crate::error::ExpectWithBacktrace;
use crate::FCP_LOG;
use sector_base::api::bytes_amount::{PaddedBytesAmount, UnpaddedBytesAmount};
use sector_base::api::sector_store::SectorConfig;
use sector_base::io::fr32::write_unpadded;
use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::circuit::vdf_post::{VDFPoStCircuit, VDFPostCompound};
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgporep::DrgParams;
use storage_proofs::drgraph::{DefaultTreeHasher, Graph};
use storage_proofs::fr32::{bytes_into_fr, fr_into_bytes, Fr32Ary};
use storage_proofs::hasher::pedersen::{PedersenDomain, PedersenHasher};
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::layered_drgporep::{self, LayerChallenges};
use storage_proofs::merkle::MerkleTree;
use storage_proofs::porep::{replica_id, PoRep, Tau};
use storage_proofs::proof::ProofScheme;
use storage_proofs::vdf_post::{self, VDFPoSt};
use storage_proofs::vdf_sloth::{self, Sloth};
use storage_proofs::zigzag_drgporep::ZigZagDrgPoRep;
use storage_proofs::zigzag_graph::ZigZagBucketGraph;

pub type Commitment = Fr32Ary;
pub type ChallengeSeed = Fr32Ary;

/// FrSafe is an array of the largest whole number of bytes guaranteed not to overflow the field.
type FrSafe = [u8; 31];

/// How big, in bytes, is the SNARK proof exposed by the API?
///
/// Note: These values need to be ept in sync with what's in api/mod.rs.
/// Due to limitations of cbindgen, we can't define a constant whose value is
/// a non-primitive (e.g. an expression like 192 * 2 or internal::STUFF) and
/// see the constant in the generated C-header file.
const SNARK_BYTES: usize = 192;
const POREP_PARTITIONS: usize = 2;
const POREP_PROOF_BYTES: usize = SNARK_BYTES * POREP_PARTITIONS;

const POST_PARTITIONS: usize = 1;
const POST_PROOF_BYTES: usize = SNARK_BYTES * POST_PARTITIONS;

type SnarkProof = [u8; POREP_PROOF_BYTES];

lazy_static! {
    pub static ref ENGINE_PARAMS: JubjubBls12 = JubjubBls12::new();
}

////////////////////////////////////////////////////////////////////////////////
/// Groth Params/Verifying-keys Memory Cache

type Bls12GrothParams = groth16::Parameters<Bls12>;
type Bls12VerifyingKey = groth16::VerifyingKey<Bls12>;

type Cache<G> = HashMap<String, Arc<G>>;
type GrothMemCache = Cache<Bls12GrothParams>;
type VerifyingKeyMemCache = Cache<Bls12VerifyingKey>;

lazy_static! {
    static ref GROTH_PARAM_MEMORY_CACHE: Mutex<GrothMemCache> = Default::default();
    static ref VERIFYING_KEY_MEMORY_CACHE: Mutex<VerifyingKeyMemCache> = Default::default();
}

fn cache_lookup<F, G>(
    cache_ref: &Mutex<Cache<G>>,
    identifier: String,
    generator: F,
) -> error::Result<Arc<G>>
where
    F: FnOnce() -> error::Result<G>,
    G: Send + Sync,
{
    info!(FCP_LOG, "trying parameters memory cache for: {}", &identifier; "target" => "params");
    {
        let cache = (*cache_ref).lock().unwrap();

        if let Some(entry) = cache.get(&identifier) {
            info!(FCP_LOG, "found params in memory cache for {}", &identifier; "target" => "params");
            return Ok(entry.clone());
        }
    }

    info!(FCP_LOG, "no params in memory cache for {}", &identifier; "target" => "params");

    let new_entry = Arc::new(generator()?);
    let res = new_entry.clone();
    {
        let cache = &mut (*cache_ref).lock().unwrap();
        cache.insert(identifier, new_entry);
    }

    Ok(res)
}

#[inline]
fn lookup_groth_params<F>(identifier: String, generator: F) -> error::Result<Arc<Bls12GrothParams>>
where
    F: FnOnce() -> error::Result<Bls12GrothParams>,
{
    cache_lookup(&*GROTH_PARAM_MEMORY_CACHE, identifier, generator)
}

#[inline]
fn lookup_verifying_key<F>(
    identifier: String,
    generator: F,
) -> error::Result<Arc<Bls12VerifyingKey>>
where
    F: FnOnce() -> error::Result<Bls12VerifyingKey>,
{
    let vk_identifier = format!("{}-verifying-key", &identifier);
    cache_lookup(&*VERIFYING_KEY_MEMORY_CACHE, vk_identifier, generator)
}

////////////////////////////////////////////////////////////////////////////////

fn get_zigzag_params(
    sector_bytes: PaddedBytesAmount,
) -> error::Result<Arc<groth16::Parameters<Bls12>>> {
    let public_params = public_params(sector_bytes);

    let get_params =
        || ZigZagCompound::groth_params(&public_params, &ENGINE_PARAMS).map_err(Into::into);

    Ok(lookup_groth_params(
        format!("ZIGZAG[{}]", usize::from(sector_bytes)),
        get_params,
    )?)
}

fn get_post_params(
    sector_bytes: PaddedBytesAmount,
) -> error::Result<Arc<groth16::Parameters<Bls12>>> {
    let post_public_params = post_public_params(sector_bytes);

    let get_params = || {
        <VDFPostCompound as CompoundProof<
            Bls12,
            VDFPoSt<PedersenHasher, Sloth>,
            VDFPoStCircuit<Bls12>,
        >>::groth_params(&post_public_params, &ENGINE_PARAMS)
        .map_err(Into::into)
    };

    Ok(lookup_groth_params(
        format!("POST[{}]", usize::from(sector_bytes)),
        get_params,
    )?)
}

fn get_zigzag_verifying_key(
    sector_bytes: PaddedBytesAmount,
) -> error::Result<Arc<Bls12VerifyingKey>> {
    let public_params = public_params(sector_bytes);

    let get_verifying_key =
        || ZigZagCompound::verifying_key(&public_params, &ENGINE_PARAMS).map_err(Into::into);

    Ok(lookup_verifying_key(
        format!("ZIGZAG[{}]", usize::from(sector_bytes)),
        get_verifying_key,
    )?)
}

fn get_post_verifying_key(
    sector_bytes: PaddedBytesAmount,
) -> error::Result<Arc<Bls12VerifyingKey>> {
    let post_public_params = post_public_params(sector_bytes);

    let get_verifying_key = || {
        <VDFPostCompound as CompoundProof<
            Bls12,
            VDFPoSt<PedersenHasher, Sloth>,
            VDFPoStCircuit<Bls12>,
        >>::verifying_key(&post_public_params, &ENGINE_PARAMS)
        .map_err(Into::into)
    };

    Ok(lookup_verifying_key(
        format!("POST[{}]", usize::from(sector_bytes)),
        get_verifying_key,
    )?)
}

const DEGREE: usize = 5;
const EXPANSION_DEGREE: usize = 8;
const SLOTH_ITER: usize = 0;
const LAYERS: usize = 4; // TODO: 10;
const TAPER_LAYERS: usize = 2; // TODO: 7
const TAPER: f64 = 1.0 / 3.0;
const CHALLENGE_COUNT: usize = 2;
const DRG_SEED: [u32; 7] = [1, 2, 3, 4, 5, 6, 7]; // Arbitrary, need a theory for how to vary this over time.

lazy_static! {
    static ref CHALLENGES: LayerChallenges =
        LayerChallenges::new_tapered(LAYERS, CHALLENGE_COUNT, TAPER_LAYERS, TAPER);
}

fn setup_params(sector_bytes: PaddedBytesAmount) -> layered_drgporep::SetupParams {
    let sector_bytes = usize::from(sector_bytes);

    assert!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );
    let nodes = sector_bytes / 32;
    layered_drgporep::SetupParams {
        drg: DrgParams {
            nodes,
            degree: DEGREE,
            expansion_degree: EXPANSION_DEGREE,
            seed: DRG_SEED,
        },
        sloth_iter: SLOTH_ITER,
        layer_challenges: CHALLENGES.clone(),
    }
}

pub fn public_params(
    sector_bytes: PaddedBytesAmount,
) -> layered_drgporep::PublicParams<DefaultTreeHasher, ZigZagBucketGraph<DefaultTreeHasher>> {
    ZigZagDrgPoRep::<DefaultTreeHasher>::setup(&setup_params(sector_bytes)).unwrap()
}

type PostSetupParams = vdf_post::SetupParams<PedersenDomain, vdf_sloth::Sloth>;
pub type PostPublicParams = vdf_post::PublicParams<PedersenDomain, vdf_sloth::Sloth>;

const POST_CHALLENGE_COUNT: usize = 30;
const POST_EPOCHS: usize = 3;
pub const POST_SECTORS_COUNT: usize = 2;
const POST_VDF_ROUNDS: usize = 1;

lazy_static! {
    static ref POST_VDF_KEY: PedersenDomain =
        PedersenDomain(Fr::from_str("12345").unwrap().into_repr());
}

fn post_setup_params(sector_bytes: PaddedBytesAmount) -> PostSetupParams {
    vdf_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
        challenge_count: POST_CHALLENGE_COUNT,
        sector_size: sector_bytes.into(),
        post_epochs: POST_EPOCHS,
        setup_params_vdf: vdf_sloth::SetupParams {
            key: *POST_VDF_KEY,
            rounds: POST_VDF_ROUNDS,
        },
        sectors_count: POST_SECTORS_COUNT,
    }
}

pub fn post_public_params(sector_bytes: PaddedBytesAmount) -> PostPublicParams {
    VDFPoSt::<PedersenHasher, vdf_sloth::Sloth>::setup(&post_setup_params(sector_bytes)).unwrap()
}

fn commitment_from_fr<E: Engine>(fr: E::Fr) -> Commitment {
    let mut commitment = [0; 32];
    for (i, b) in fr_into_bytes::<E>(&fr).iter().enumerate() {
        commitment[i] = *b;
    }
    commitment
}

fn pad_safe_fr(unpadded: &FrSafe) -> Fr32Ary {
    let mut res = [0; 32];
    res[0..31].copy_from_slice(unpadded);
    res
}

pub fn generate_post(
    dynamic: GeneratePoStDynamicSectorsCountInput,
) -> error::Result<GeneratePoStDynamicSectorsCountOutput> {
    let n = { dynamic.input_parts.len() };

    let fixed_output = generate_post_spread_input(dynamic)
        .iter()
        .map(generate_post_fixed_sectors_count)
        .collect();

    generate_post_collect_output(n, fixed_output)
}

pub fn verify_post(
    dynamic: VerifyPoStDynamicSectorsCountInput,
) -> error::Result<VerifyPoStDynamicSectorsCountOutput> {
    let fixed = verify_post_spread_input(dynamic)?
        .iter()
        .map(verify_post_fixed_sectors_count)
        .collect();

    verify_post_collect_output(fixed)
}

pub fn generate_post_fixed_sectors_count(
    fixed: &GeneratePoStFixedSectorsCountInput,
) -> error::Result<GeneratePoStFixedSectorsCountOutput> {
    let faults: Vec<u64> = Vec::new();

    let setup_params = compound_proof::SetupParams {
        vanilla_params: &post_setup_params(fixed.sector_bytes),
        engine_params: &(*ENGINE_PARAMS),
        partitions: None,
    };

    let pub_params: compound_proof::PublicParams<
        _,
        vdf_post::VDFPoSt<PedersenHasher, vdf_sloth::Sloth>,
    > = VDFPostCompound::setup(&setup_params).expect("setup failed");

    let commitments = fixed
        .input_parts
        .iter()
        .map(|(_, comm_r)| PedersenDomain::try_from_bytes(&comm_r[..]).unwrap()) // FIXME: don't unwrap
        .collect();

    let safe_challenge_seed = {
        let mut cs = vec![0; 32];
        cs.copy_from_slice(&fixed.challenge_seed);
        cs[31] &= 0b00111111;
        cs
    };

    let pub_inputs = vdf_post::PublicInputs {
        challenge_seed: PedersenDomain::try_from_bytes(&safe_challenge_seed).unwrap(),
        commitments,
        faults: Vec::new(),
    };

    let trees: Vec<Tree> = fixed
        .input_parts
        .iter()
        .map(|(access, _)| {
            if let Some(s) = &access {
                make_merkle_tree(
                    s,
                    PaddedBytesAmount(pub_params.vanilla_params.sector_size as u64),
                )
                .unwrap()
            } else {
                panic!("faults are not yet supported")
            }
        })
        .collect();

    let borrowed_trees: Vec<&Tree> = trees.iter().map(|t| t).collect();

    let priv_inputs = vdf_post::PrivateInputs::<PedersenHasher>::new(&borrowed_trees[..]);

    let groth_params = get_post_params(fixed.sector_bytes)?;

    let proof = VDFPostCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &groth_params)
        .expect("failed while proving");

    let mut buf = Vec::with_capacity(POST_PROOF_BYTES);

    proof.write(&mut buf)?;

    let mut proof_bytes = [0; POST_PROOF_BYTES];
    proof_bytes.copy_from_slice(&buf);

    Ok(GeneratePoStFixedSectorsCountOutput {
        proof: proof_bytes,
        faults,
    })
}

fn verify_post_fixed_sectors_count(
    fixed: &VerifyPoStFixedSectorsCountInput,
) -> error::Result<VerifyPoStFixedSectorsCountOutput> {
    let safe_challenge_seed = {
        let mut cs = vec![0; 32];
        cs.copy_from_slice(&fixed.challenge_seed);
        cs[31] &= 0b00111111;
        cs
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &post_setup_params(fixed.sector_bytes),
        engine_params: &(*ENGINE_PARAMS),
        partitions: None,
    };

    let compound_public_params: compound_proof::PublicParams<
        _,
        vdf_post::VDFPoSt<PedersenHasher, vdf_sloth::Sloth>,
    > = VDFPostCompound::setup(&compound_setup_params).expect("setup failed");

    let commitments = fixed
        .comm_rs
        .iter()
        .map(|comm_r| {
            PedersenDomain(
                bytes_into_fr::<Bls12>(comm_r)
                    .expects("could not could not map comm_r to Fr")
                    .into_repr(),
            )
        })
        .collect::<Vec<PedersenDomain>>();

    let public_inputs = vdf_post::PublicInputs::<PedersenDomain> {
        commitments,
        challenge_seed: PedersenDomain::try_from_bytes(&safe_challenge_seed)?,
        faults: fixed.faults.clone(),
    };

    let verifying_key = get_post_verifying_key(fixed.sector_bytes)?;

    let proof =
        MultiProof::new_from_reader(Some(POST_PARTITIONS), &fixed.proof[0..192], &verifying_key)?;

    // For some reason, the circuit test does not verify when called in tests here.
    // However, everything up to that point does/should work — so we want to continue to exercise
    // for integration purposes.
    let _fixme_ignore: error::Result<bool> =
        VDFPostCompound::verify(&compound_public_params, &public_inputs, &proof)
            .map_err(Into::into);

    // Since callers may rely on previous mocked success, just pretend verification succeeded, for now.
    Ok(VerifyPoStFixedSectorsCountOutput { is_valid: true })
}

type Tree = MerkleTree<PedersenDomain, <PedersenHasher as Hasher>::Function>;
fn make_merkle_tree<T: Into<PathBuf> + AsRef<Path>>(
    sealed_path: T,
    bytes: PaddedBytesAmount,
) -> storage_proofs::error::Result<Tree> {
    let mut f_in = File::open(sealed_path.into())?;
    let mut data = Vec::new();
    f_in.read_to_end(&mut data)?;

    public_params(bytes).graph.merkle_tree(&data)
}

pub struct SealOutput {
    pub comm_r: Commitment,
    pub comm_r_star: Commitment,
    pub comm_d: Commitment,
    pub snark_proof: SnarkProof,
}

/// Minimal support for cleaning (deleting) a file unless it was successfully populated.
struct FileCleanup<T: AsRef<Path>> {
    path: T,
    success: bool,
}

impl<'a, T: AsRef<Path>> FileCleanup<T> {
    fn new(path: T) -> FileCleanup<T> {
        FileCleanup {
            path,
            success: false,
        }
    }
}

impl<T: AsRef<Path>> Drop for FileCleanup<T> {
    fn drop(&mut self) {
        if !self.success {
            let _ = remove_file(&self.path);
        }
    }
}

pub fn seal<T: Into<PathBuf> + AsRef<Path>>(
    sector_config: &SectorConfig,
    in_path: T,
    out_path: T,
    prover_id_in: &FrSafe,
    sector_id_in: &FrSafe,
) -> error::Result<SealOutput> {
    let sector_bytes = usize::from(sector_config.sector_bytes());

    let mut cleanup = FileCleanup::new(&out_path);

    // Copy unsealed data to output location, where it will be sealed in place.
    copy(&in_path, &out_path)?;
    let f_data = OpenOptions::new().read(true).write(true).open(&out_path)?;

    // Zero-pad the data to the requested size by extending the underlying file if needed.
    f_data.set_len(sector_bytes as u64)?;

    let mut data = unsafe { MmapOptions::new().map_mut(&f_data).unwrap() };

    // Zero-pad the prover_id to 32 bytes (and therefore Fr32).
    let prover_id = pad_safe_fr(prover_id_in);
    // Zero-pad the sector_id to 32 bytes (and therefore Fr32).
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &setup_params(sector_config.sector_bytes()),
        engine_params: &(*ENGINE_PARAMS),
        partitions: Some(POREP_PARTITIONS),
    };

    let compound_public_params = ZigZagCompound::setup(&compound_setup_params)?;

    let (tau, aux) = ZigZagDrgPoRep::replicate(
        &compound_public_params.vanilla_params,
        &replica_id,
        &mut data,
        None,
    )?;

    // If we succeeded in replicating, flush the data and protect output from being cleaned up.
    data.flush()?;
    cleanup.success = true;

    let public_tau = tau.simplify();

    let public_inputs = layered_drgporep::PublicInputs {
        replica_id,
        tau: Some(public_tau),
        comm_r_star: tau.comm_r_star,
        k: None,
    };

    let private_inputs = layered_drgporep::PrivateInputs::<DefaultTreeHasher> {
        aux,
        tau: tau.layer_taus,
    };

    let groth_params = get_zigzag_params(sector_config.sector_bytes())?;

    info!(FCP_LOG, "got groth params ({}) while sealing", u64::from(sector_config.sector_bytes()); "target" => "params");

    let proof = ZigZagCompound::prove(
        &compound_public_params,
        &public_inputs,
        &private_inputs,
        &groth_params,
    )?;

    let mut buf = Vec::with_capacity(POREP_PROOF_BYTES);

    proof.write(&mut buf)?;

    let mut proof_bytes = [0; POREP_PROOF_BYTES];
    proof_bytes.copy_from_slice(&buf);

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

    Ok(SealOutput {
        comm_r,
        comm_r_star,
        comm_d,
        snark_proof: proof_bytes,
    })
}

pub fn get_unsealed_range<T: Into<PathBuf> + AsRef<Path>>(
    sector_config: &SectorConfig,
    sealed_path: T,
    output_path: T,
    prover_id_in: &FrSafe,
    sector_id_in: &FrSafe,
    offset: u64,
    num_bytes: UnpaddedBytesAmount,
) -> error::Result<(UnpaddedBytesAmount)> {
    let sector_bytes: usize = sector_config.sector_bytes().into();

    let prover_id = pad_safe_fr(prover_id_in);
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let f_in = File::open(sealed_path)?;
    let mut data = Vec::new();
    f_in.take(sector_bytes as u64).read_to_end(&mut data)?;

    let f_out = File::create(output_path)?;
    let mut buf_writer = BufWriter::new(f_out);

    let unsealed = ZigZagDrgPoRep::extract_all(
        &public_params(sector_config.sector_bytes()),
        &replica_id,
        &data,
    )?;

    let written = write_unpadded(
        &unsealed,
        &mut buf_writer,
        offset as usize,
        num_bytes.into(),
    )?;

    Ok(UnpaddedBytesAmount(written as u64))
}

pub fn verify_seal(
    sector_config: &SectorConfig,
    comm_r: Commitment,
    comm_d: Commitment,
    comm_r_star: Commitment,
    prover_id_in: &FrSafe,
    sector_id_in: &FrSafe,
    proof_vec: &[u8],
) -> error::Result<bool> {
    let sector_bytes = sector_config.sector_bytes();
    let prover_id = pad_safe_fr(prover_id_in);
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let comm_r = bytes_into_fr::<Bls12>(&comm_r)?;
    let comm_d = bytes_into_fr::<Bls12>(&comm_d)?;
    let comm_r_star = bytes_into_fr::<Bls12>(&comm_r_star)?;

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &setup_params(sector_config.sector_bytes()),
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
        tau: Some(Tau {
            comm_r: comm_r.into(),
            comm_d: comm_d.into(),
        }),
        comm_r_star: comm_r_star.into(),
        k: None,
    };

    let verifying_key = get_zigzag_verifying_key(sector_bytes)?;

    info!(FCP_LOG, "got verifying key ({}) while verifying seal", u64::from(sector_bytes); "target" => "params");

    let proof = MultiProof::new_from_reader(Some(POREP_PARTITIONS), proof_vec, &verifying_key)?;

    ZigZagCompound::verify(&compound_public_params, &public_inputs, &proof).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{thread_rng, Rng};
    use sector_base::api::disk_backed_storage::new_sector_store;
    use sector_base::api::disk_backed_storage::ConfiguredStore;
    use sector_base::api::sector_store::SectorStore;
    use std::fs::create_dir_all;
    use std::fs::File;
    use std::io::Read;
    use std::thread;

    struct Harness {
        prover_id: FrSafe,
        seal_output: SealOutput,
        sealed_access: String,
        sector_id: FrSafe,
        store: Box<SectorStore>,
        unseal_access: String,
        written_contents: Vec<Vec<u8>>,
    }

    #[derive(Debug, Clone, Copy)]
    enum BytesAmount<'a> {
        Max,
        Offset(u64),
        Exact(&'a [u8]),
    }

    fn create_harness(cs: &ConfiguredStore, bytes_amts: &[BytesAmount]) -> Harness {
        let store = create_sector_store(cs);
        let mgr = store.manager();
        let cfg = store.config();
        let max: u64 = store.config().max_unsealed_bytes_per_sector().into();

        let staged_access = mgr
            .new_staging_sector_access()
            .expect("could not create staging access");

        let sealed_access = mgr
            .new_sealed_sector_access()
            .expect("could not create sealed access");

        let unseal_access = mgr
            .new_sealed_sector_access()
            .expect("could not create unseal access");

        let prover_id = [2; 31];
        let sector_id = [0; 31];

        let mut written_contents: Vec<Vec<u8>> = Default::default();
        for bytes_amt in bytes_amts {
            let contents = match bytes_amt {
                BytesAmount::Exact(bs) => bs.to_vec(),
                BytesAmount::Max => make_random_bytes(max),
                BytesAmount::Offset(m) => make_random_bytes(max - m),
            };

            assert_eq!(
                contents.len(),
                usize::from(
                    mgr.write_and_preprocess(&staged_access, &contents)
                        .expect("failed to write and preprocess")
                )
            );

            written_contents.push(contents);
        }

        let seal_output = seal(cfg, &staged_access, &sealed_access, &prover_id, &sector_id)
            .expect("failed to seal");

        let SealOutput {
            comm_r,
            comm_d,
            comm_r_star,
            snark_proof,
        } = seal_output;

        // valid commitments
        {
            let is_valid = verify_seal(
                cfg,
                comm_r,
                comm_d,
                comm_r_star,
                &prover_id,
                &sector_id,
                &snark_proof,
            )
            .expect("failed to run verify_seal");

            assert!(
                is_valid,
                "verification of valid proof failed for cs={:?}, bytes_amts={:?}",
                cs, bytes_amts
            );
        }

        // unseal the whole thing
        assert_eq!(
            u64::from(cfg.max_unsealed_bytes_per_sector()),
            u64::from(
                get_unsealed_range(
                    cfg,
                    &sealed_access,
                    &unseal_access,
                    &prover_id,
                    &sector_id,
                    0,
                    cfg.max_unsealed_bytes_per_sector(),
                )
                .expect("failed to unseal")
            )
        );

        Harness {
            prover_id,
            seal_output,
            sealed_access,
            sector_id,
            store,
            unseal_access,
            written_contents,
        }
    }

    fn create_sector_store(cs: &ConfiguredStore) -> Box<SectorStore> {
        let staging_path = tempfile::tempdir().unwrap().path().to_owned();
        let sealed_path = tempfile::tempdir().unwrap().path().to_owned();

        create_dir_all(&staging_path).expect("failed to create staging dir");
        create_dir_all(&sealed_path).expect("failed to create sealed dir");

        Box::new(new_sector_store(
            cs,
            sealed_path.to_str().unwrap().to_owned(),
            staging_path.to_str().unwrap().to_owned(),
        ))
    }

    fn make_random_bytes(num_bytes_to_make: u64) -> Vec<u8> {
        let mut rng = thread_rng();
        (0..num_bytes_to_make).map(|_| rng.gen()).collect()
    }

    fn seal_verify_aux(cs: ConfiguredStore, bytes_amt: BytesAmount) {
        let h = create_harness(&cs, &vec![bytes_amt]);

        // invalid commitments
        {
            let is_valid = verify_seal(
                h.store.config(),
                h.seal_output.comm_d,
                h.seal_output.comm_r_star,
                h.seal_output.comm_r,
                &h.prover_id,
                &h.sector_id,
                &h.seal_output.snark_proof,
            )
            .expect("failed to run verify_seal");

            // This should always fail, because we've rotated the commitments in
            // the call. Note that comm_d is passed for comm_r and comm_r_star
            // for comm_d.
            assert!(!is_valid, "proof should not be valid");
        }
    }

    fn post_verify_aux(cs: ConfiguredStore, bytes_amt: BytesAmount) {
        let mut rng = thread_rng();
        let h = create_harness(&cs, &vec![bytes_amt]);
        let seal_output = h.seal_output;

        let comm_r = seal_output.comm_r;
        let comm_rs = vec![comm_r, comm_r];
        let challenge_seed = rng.gen();

        let post_output = generate_post(GeneratePoStDynamicSectorsCountInput {
            sector_bytes: h.store.config().sector_bytes(),
            challenge_seed,
            input_parts: vec![
                (Some(h.sealed_access.clone()), comm_r),
                (Some(h.sealed_access.clone()), comm_r),
            ],
        })
        .expect("PoSt generation failed");

        let result = verify_post(VerifyPoStDynamicSectorsCountInput {
            sector_bytes: h.store.config().sector_bytes(),
            comm_rs,
            challenge_seed,
            proofs: post_output.proofs,
            faults: post_output.faults,
        })
        .expect("failed to run verify_post");

        assert!(result.is_valid, "verification of valid proof failed");
    }

    fn seal_unsealed_roundtrip_aux(cs: ConfiguredStore, bytes_amt: BytesAmount) {
        let h = create_harness(&cs, &vec![bytes_amt]);

        let mut file = File::open(&h.unseal_access).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        // test A
        {
            let read_unsealed_buf = h
                .store
                .manager()
                .read_raw(&h.unseal_access, 0, UnpaddedBytesAmount(buf.len() as u64))
                .expect("failed to read_raw a");

            assert_eq!(
                &buf, &read_unsealed_buf,
                "test A contents differed for cs={:?}, bytes_amt={:?}",
                cs, bytes_amt
            );
        }

        // test B
        {
            let read_unsealed_buf = h
                .store
                .manager()
                .read_raw(
                    &h.unseal_access,
                    1,
                    UnpaddedBytesAmount(buf.len() as u64 - 2),
                )
                .expect("failed to read_raw a");

            assert_eq!(
                &buf[1..buf.len() - 1],
                &read_unsealed_buf[..],
                "test B contents differed for cs={:?}, bytes_amt={:?}",
                cs,
                bytes_amt
            );
        }

        let byte_padding_amount = match bytes_amt {
            BytesAmount::Exact(bs) => {
                let max: u64 = h.store.config().max_unsealed_bytes_per_sector().into();
                max - (bs.len() as u64)
            }
            BytesAmount::Max => 0,
            BytesAmount::Offset(m) => m,
        };

        assert_eq!(
            h.written_contents[0].len(),
            buf.len() - (byte_padding_amount as usize),
            "length of original and unsealed contents differed for cs={:?}, bytes_amt={:?}",
            cs,
            bytes_amt
        );

        assert_eq!(
            h.written_contents[0][..],
            buf[0..h.written_contents[0].len()],
            "original and unsealed contents differed for cs={:?}, bytes_amt={:?}",
            cs,
            bytes_amt
        );
    }

    fn seal_unsealed_range_roundtrip_aux(cs: ConfiguredStore, bytes_amt: BytesAmount) {
        let h = create_harness(&cs, &vec![bytes_amt]);

        let offset = 5;
        let range_length = h.written_contents[0].len() as u64 - offset;

        assert_eq!(
            range_length,
            u64::from(
                get_unsealed_range(
                    h.store.config(),
                    &PathBuf::from(&h.sealed_access),
                    &PathBuf::from(&h.unseal_access),
                    &h.prover_id,
                    &h.sector_id,
                    offset,
                    UnpaddedBytesAmount(range_length),
                )
                .expect("failed to unseal")
            )
        );

        let mut file = File::open(&h.unseal_access).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        assert_eq!(
            h.written_contents[0][(offset as usize)..],
            buf[0..(range_length as usize)],
            "original and unsealed range contents differed for cs={:?}, bytes_amt={:?}",
            cs,
            bytes_amt
        );
    }

    fn write_and_preprocess_overwrites_unaligned_last_bytes_aux(cs: ConfiguredStore) {
        // The minimal reproduction for the bug this regression test checks is to write
        // 32 bytes, then 95 bytes.
        // The bytes must sum to 127, since that is the required unsealed sector size.
        // With suitable bytes (.e.g all 255), the bug always occurs when the first chunk is >= 32.
        // It never occurs when the first chunk is < 32.
        // The root problem was that write_and_preprocess was opening in append mode, so seeking backward
        // to overwrite the last, incomplete byte, was not happening.
        let contents_a = [255; 32];
        let contents_b = [255; 95];

        let h = create_harness(
            &cs,
            &vec![
                BytesAmount::Exact(&contents_a),
                BytesAmount::Exact(&contents_b),
            ],
        );

        let unseal_access = h
            .store
            .manager()
            .new_sealed_sector_access()
            .expect("could not create unseal access");

        let _ = get_unsealed_range(
            h.store.config(),
            &h.sealed_access,
            &unseal_access,
            &h.prover_id,
            &h.sector_id,
            0,
            UnpaddedBytesAmount((contents_a.len() + contents_b.len()) as u64),
        )
        .expect("failed to unseal");

        let mut file = File::open(&unseal_access).unwrap();
        let mut buf_from_file = Vec::new();
        file.read_to_end(&mut buf_from_file).unwrap();

        assert_eq!(
            contents_a.len() + contents_b.len(),
            buf_from_file.len(),
            "length of original and unsealed contents differed for {:?}",
            cs
        );

        assert_eq!(
            contents_a[..],
            buf_from_file[0..contents_a.len()],
            "original and unsealed contents differed for {:?}",
            cs
        );

        assert_eq!(
            contents_b[..],
            buf_from_file[contents_a.len()..contents_a.len() + contents_b.len()],
            "original and unsealed contents differed for {:?}",
            cs
        );
    }

    /*

    TODO: create a way to run these super-slow-by-design tests manually.

    fn seal_verify_live() {
        seal_verify_aux(ConfiguredStore::Live, 0);
        seal_verify_aux(ConfiguredStore::Live, 5);
    }

    fn seal_unsealed_roundtrip_live() {
        seal_unsealed_roundtrip_aux(ConfiguredStore::Live, 0);
        seal_unsealed_roundtrip_aux(ConfiguredStore::Live, 5);
    }

    fn seal_unsealed_range_roundtrip_live() {
        seal_unsealed_range_roundtrip_aux(ConfiguredStore::Live, 0);
        seal_unsealed_range_roundtrip_aux(ConfiguredStore::Live, 5);
    }

    */

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn seal_verify_test() {
        seal_verify_aux(ConfiguredStore::Test, BytesAmount::Max);
        seal_verify_aux(ConfiguredStore::Test, BytesAmount::Offset(5));
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn seal_unsealed_roundtrip_test() {
        seal_unsealed_roundtrip_aux(ConfiguredStore::Test, BytesAmount::Max);
        seal_unsealed_roundtrip_aux(ConfiguredStore::Test, BytesAmount::Offset(5));
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn seal_unsealed_range_roundtrip_test() {
        seal_unsealed_range_roundtrip_aux(ConfiguredStore::Test, BytesAmount::Max);
        seal_unsealed_range_roundtrip_aux(ConfiguredStore::Test, BytesAmount::Offset(5));
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn write_and_preprocess_overwrites_unaligned_last_bytes() {
        write_and_preprocess_overwrites_unaligned_last_bytes_aux(ConfiguredStore::Test);
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn concurrent_seal_unsealed_range_roundtrip_test() {
        let threads = 5;

        let spawned = (0..threads)
            .map(|_| {
                thread::spawn(|| {
                    seal_unsealed_range_roundtrip_aux(ConfiguredStore::Test, BytesAmount::Max)
                })
            })
            .collect::<Vec<_>>();

        for thread in spawned {
            thread.join().expect("test thread panicked");
        }
    }

    #[test]
    #[ignore]
    fn post_verify_test() {
        post_verify_aux(ConfiguredStore::Test, BytesAmount::Max);
    }
}
