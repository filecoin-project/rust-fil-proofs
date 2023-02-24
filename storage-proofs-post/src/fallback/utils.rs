use storage_proofs_core::api_version::ApiVersion;

/// Selects the challenge index used to determine the leaf challenge for PoSt
pub fn get_challenge_index(
    api_version: ApiVersion,
    sector: usize,
    sector_chunk_index: usize,
    num_sectors_per_chunk: usize,
    challenge_count: usize,
    challenge_index: usize,
) -> u64 {
    (match api_version {
        ApiVersion::V1_2_0 => challenge_index,
        _ => {
            (sector * num_sectors_per_chunk + sector_chunk_index) * challenge_count
                + challenge_index
        }
    } as u64)
}
