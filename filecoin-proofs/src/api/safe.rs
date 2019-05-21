use slog::*;

use sector_base::api::bytes_amount::UnpaddedBytesAmount;
use sector_base::api::porep_config::PoRepConfig;
use sector_base::api::porep_proof_partitions;
use sector_base::api::post_config::PoStConfig;
use sector_base::api::post_proof_partitions::PoStProofPartitions;
use sector_base::api::sector_class::SectorClass;
use sector_base::api::sector_size::SectorSize;

use crate::api::internal;
use crate::api::post_adapter::*;
use crate::api::sector_builder::metadata::*;
use crate::api::sector_builder::SectorBuilder;
use crate::FCP_LOG;

pub type Result<T> = std::result::Result<T, failure::Error>;

/// Verifies the output of seal.
pub fn verify_seal(
    sector_size: u64,
    comm_r: [u8; 32],
    comm_d: [u8; 32],
    comm_r_star: [u8; 32],
    prover_id: &[u8; 31],
    sector_id: &[u8; 31],
    proof: Vec<u8>,
) -> Result<bool> {
    info!(FCP_LOG, "verify_seal: {}", "start"; "target" => "API");

    let ppp = porep_proof_partitions::try_from_bytes(&proof)?;
    let cfg = PoRepConfig(SectorSize(sector_size), ppp);

    let result = internal::verify_seal(
        cfg,
        comm_r,
        comm_d,
        comm_r_star,
        prover_id,
        sector_id,
        &proof,
    )?;

    info!(FCP_LOG, "verify_seal: {}", "finish"; "target" => "API");

    Ok(result)
}

/// Generates a proof-of-spacetime for the given replica commitments.
pub fn generate_post(
    sb: &SectorBuilder,
    comm_rs: Vec<[u8; 32]>,
    challenge_seed: &[u8; 32],
) -> Result<GeneratePoStDynamicSectorsCountOutput> {
    info!(FCP_LOG, "generate_post: {}", "start"; "target" => "API");

    let res = sb.generate_post(&comm_rs, challenge_seed)?;

    info!(FCP_LOG, "generate_post: {}", "finish"; "target" => "API");

    Ok(res)
}

/// Verifies that a proof-of-spacetime is valid.
pub fn verify_post(
    sector_size: u64,
    proof_partitions: u8,
    comm_rs: Vec<[u8; 32]>,
    challenge_seed: &[u8; 32],
    proofs: Vec<Vec<u8>>,
    faults: Vec<u64>,
) -> Result<bool> {
    info!(FCP_LOG, "verify_post: {}", "start"; "target" => "API");

    let cfg = PoStConfig(
        SectorSize(sector_size),
        PoStProofPartitions(proof_partitions),
    );

    let res = internal::verify_post(VerifyPoStDynamicSectorsCountInput {
        post_config: cfg,
        comm_rs,
        challenge_seed: into_safe_challenge_seed(challenge_seed),
        proofs,
        faults,
    })?;

    info!(FCP_LOG, "verify_post: {}", "finish"; "target" => "API");

    Ok(res.is_valid)
}

/// Initializes and returns a SectorBuilder.
pub fn init_sector_builder(
    sector_class: SectorClass,
    last_used_sector_id: u64,
    metadata_dir: &str,
    prover_id: [u8; 31],
    sealed_sector_dir: &str,
    staged_sector_dir: &str,
    max_num_staged_sectors: u8,
) -> Result<SectorBuilder> {
    let result = SectorBuilder::init_from_metadata(
        sector_class,
        last_used_sector_id,
        metadata_dir,
        prover_id,
        sealed_sector_dir,
        staged_sector_dir,
        max_num_staged_sectors,
    )?;

    Ok(result)
}

/// Returns the number of user bytes that will fit into a staged sector.
pub fn get_max_user_bytes_per_staged_sector(sector_size: u64) -> u64 {
    u64::from(UnpaddedBytesAmount::from(SectorSize(sector_size)))
}

/// Writes user piece-bytes to a staged sector and returns the id of the sector
/// to which the bytes were written.
pub fn add_piece(
    sb: &SectorBuilder,
    piece_key: &str,
    piece_bytes_amount: u64,
    piece_path: &str,
) -> Result<u64> {
    let sector_id = sb.add_piece(piece_key.into(), piece_bytes_amount, piece_path.into())?;

    Ok(sector_id)
}

/// Unseals and returns the bytes associated with the provided piece key.
pub fn read_piece_from_sealed_sector(sb: &SectorBuilder, piece_key: &str) -> Result<Vec<u8>> {
    let bytes = sb.read_piece_from_sealed_sector(piece_key.into())?;

    Ok(bytes)
}

/// For demo purposes. Seals all staged sectors.
pub fn seal_all_staged_sectors(sb: &SectorBuilder) -> Result<()> {
    sb.seal_all_staged_sectors()?;

    Ok(())
}

/// Returns sector sealing status for the provided sector id if it exists. If
/// we don't know about the provided sector id, produce an error.
pub fn get_seal_status(sb: &SectorBuilder, sector_id: u64) -> Result<SealStatus> {
    let seal_status = sb.get_seal_status(sector_id)?;

    Ok(seal_status)
}

pub fn get_sealed_sectors(sb: &SectorBuilder) -> Result<Vec<SealedSectorMetadata>> {
    let sealed_sectors = sb.get_sealed_sectors()?;

    Ok(sealed_sectors)
}

pub fn get_staged_sectors(sb: &SectorBuilder) -> Result<Vec<StagedSectorMetadata>> {
    let staged_sectors = sb.get_staged_sectors()?;

    Ok(staged_sectors)
}

fn into_safe_challenge_seed(challenge_seed: &[u8; 32]) -> [u8; 32] {
    let mut cs = [0; 32];
    cs.copy_from_slice(challenge_seed);
    cs[31] &= 0b00111111;
    cs
}
