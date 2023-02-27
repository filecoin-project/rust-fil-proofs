use storage_proofs_core::api_version::ApiVersion;

/// Selects the challenge index used to determine the leaf challenge for PoSt
pub fn get_challenge_index(
    api_version: ApiVersion,
    sector_index: usize,
    challenge_count_per_sector: usize,
    challenge_index: usize,
) -> u64 {
    (match api_version {
        ApiVersion::V1_2_0 => challenge_index,
        _ => sector_index * challenge_count_per_sector + challenge_index,
    } as u64)
}
