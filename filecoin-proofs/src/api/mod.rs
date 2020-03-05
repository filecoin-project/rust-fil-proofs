use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bincode::deserialize;
use merkletree::merkle::get_merkle_tree_leafs;
use merkletree::store::{DiskStore, LevelCacheStore, StoreConfig};
use storage_proofs::cache_key::CacheKey;
use storage_proofs::hasher::Hasher;
use storage_proofs::measurements::{measure_op, Operation};
use storage_proofs::porep::stacked::{
    generate_replica_id, PersistentAux, StackedDrg, TemporaryAux, BINARY_ARITY, OCT_ARITY,
};
use storage_proofs::porep::PoRep;
use storage_proofs::sector::SectorId;

use crate::api::util::{as_safe_commitment, get_tree_size};
use crate::commitment_reader::CommitmentReader;
use crate::constants::{
    DefaultPieceHasher, DefaultTreeHasher,
    MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR as MINIMUM_PIECE_SIZE,
};
use crate::fr32::write_unpadded;
use crate::parameters::public_params;
use crate::types::{
    Commitment, PaddedBytesAmount, PieceInfo, PoRepConfig, PoRepProofPartitions, ProverId,
    SealPreCommitPhase1Output, Ticket, UnpaddedByteIndex, UnpaddedBytesAmount,
};

mod post;
mod seal;
pub(crate) mod util;

pub use self::post::*;
pub use self::seal::*;

use storage_proofs::pieces::generate_piece_commitment_bytes_from_source;

/// Unseals the sector at `sealed_path` and returns the bytes for a piece
/// whose first (unpadded) byte begins at `offset` and ends at `offset` plus
/// `num_bytes`, inclusive. Note that the entire sector is unsealed each time
/// this function is called.
///
/// # Arguments
///
/// * `porep_config` - porep configuration containing the sector size.
/// * `cache_path` - path to the directory in which the sector data's Merkle Tree is written.
/// * `sealed_path` - path to the sealed sector file that we will unseal and read a byte range.
/// * `output_path` - path to a file that we will write the requested byte range to.
/// * `prover_id` - the prover-id that sealed the sector.
/// * `sector_id` - the sector-id of the sealed sector.
/// * `comm_d` - the commitment to the sector's data.
/// * `ticket` - the ticket that was used to generate the sector's replica-id.
/// * `offset` - the byte index in the unsealed sector of the first byte that we want to read.
/// * `num_bytes` - the number of bytes that we want to read.
#[allow(clippy::too_many_arguments)]
pub fn get_unsealed_range<T: Into<PathBuf> + AsRef<Path>>(
    porep_config: PoRepConfig,
    cache_path: T,
    sealed_path: T,
    output_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    comm_d: Commitment,
    ticket: Ticket,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> Result<UnpaddedBytesAmount> {
    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");

    let comm_d =
        as_safe_commitment::<<DefaultPieceHasher as Hasher>::Domain, _>(&comm_d, "comm_d")?;

    let replica_id =
        generate_replica_id::<DefaultTreeHasher, _>(&prover_id, sector_id.into(), &ticket, comm_d);

    let f_in = File::open(&sealed_path)
        .with_context(|| format!("could not open sealed_path={:?}", sealed_path.as_ref()))?;
    let mut data = Vec::new();
    f_in.take(u64::from(PaddedBytesAmount::from(porep_config)))
        .read_to_end(&mut data)?;

    let f_out = File::create(&output_path)
        .with_context(|| format!("could not create output_path={:?}", output_path.as_ref()))?;
    let mut buf_writer = BufWriter::new(f_out);

    let tree_size = get_tree_size::<<DefaultPieceHasher as Hasher>::Domain>(
        porep_config.sector_size,
        BINARY_ARITY,
    );
    let tree_leafs = get_merkle_tree_leafs(tree_size, BINARY_ARITY);
    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let config = StoreConfig::new(
        cache_path.as_ref(),
        CacheKey::CommDTree.to_string(),
        StoreConfig::default_cached_above_base_layer(tree_leafs, BINARY_ARITY),
    );
    let pp = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
    )?;

    let offset_padded: PaddedBytesAmount = UnpaddedBytesAmount::from(offset).into();
    let num_bytes_padded: PaddedBytesAmount = num_bytes.into();

    let unsealed_all = StackedDrg::<DefaultTreeHasher, DefaultPieceHasher>::extract_all(
        &pp,
        &replica_id,
        &data,
        Some(config),
    )?;
    let start: usize = offset_padded.into();
    let end = start + usize::from(num_bytes_padded);
    let unsealed = &unsealed_all[start..end];

    // If the call to `extract_range` was successful, the `unsealed` vector must
    // have a length which equals `num_bytes_padded`. The byte at its 0-index
    // byte will be the the byte at index `offset_padded` in the sealed sector.
    let written = write_unpadded(unsealed, &mut buf_writer, 0, num_bytes.into())
        .with_context(|| format!("could not write to output_path={:?}", output_path.as_ref()))?;

    Ok(UnpaddedBytesAmount(written as u64))
}

/// Generates a piece commitment for the provided byte source. Returns an error
/// if the byte source produced more than `piece_size` bytes.
///
/// # Arguments
///
/// * `source` - a readable source of unprocessed piece bytes. The piece's commitment will be
/// generated for the bytes read from the source plus any added padding.
/// * `piece_size` - the number of unpadded user-bytes which can be read from source before EOF.
pub fn generate_piece_commitment<T: std::io::Read>(
    source: T,
    piece_size: UnpaddedBytesAmount,
) -> Result<PieceInfo> {
    measure_op(Operation::GeneratePieceCommitment, || {
        ensure_piece_size(piece_size)?;

        // send the source through the preprocessor
        let source = std::io::BufReader::new(source);
        let mut pad_reader = crate::pad_reader::PadReader::new(source);

        let commitment = generate_piece_commitment_bytes_from_source::<DefaultPieceHasher>(
            &mut pad_reader,
            PaddedBytesAmount::from(piece_size).into(),
        )?;

        PieceInfo::new(commitment, piece_size)
    })
}

/// Computes a NUL-byte prefix and/or suffix for `source` using the provided
/// `piece_lengths` and `piece_size` (such that the `source`, after
/// preprocessing, will occupy a subtree of a merkle tree built using the bytes
/// from `target`), runs the resultant byte stream through the preprocessor,
/// and writes the result to `target`. Returns a tuple containing the number of
/// bytes written to `target` (`source` plus alignment) and the commitment.
///
/// WARNING: Depending on the ordering and size of the pieces in
/// `piece_lengths`, this function could write a prefix of NUL bytes which
/// wastes ($SIZESECTORSIZE/2)-$MINIMUM_PIECE_SIZE space. This function will be
/// deprecated in favor of `write_and_preprocess`, and miners will be prevented
/// from sealing sectors containing more than $TOOMUCH alignment bytes.
///
/// # Arguments
///
/// * `source` - a readable source of unprocessed piece bytes.
/// * `target` - a writer where we will write the processed piece bytes.
/// * `piece_size` - the number of unpadded user-bytes which can be read from source before EOF.
/// * `piece_lengths` - the number of bytes for each previous piece in the sector.
pub fn add_piece<R, W>(
    source: R,
    target: W,
    piece_size: UnpaddedBytesAmount,
    piece_lengths: &[UnpaddedBytesAmount],
) -> Result<(PieceInfo, UnpaddedBytesAmount)>
where
    R: Read,
    W: Write,
{
    measure_op(Operation::AddPiece, || {
        ensure_piece_size(piece_size)?;

        let source = std::io::BufReader::new(source);
        let mut target = std::io::BufWriter::new(target);

        let written_bytes = crate::pieces::sum_piece_bytes_with_alignment(&piece_lengths);
        let piece_alignment = crate::pieces::get_piece_alignment(written_bytes, piece_size);
        let pad_reader = crate::pad_reader::PadReader::new(source);

        // write left alignment
        for _ in 0..usize::from(PaddedBytesAmount::from(piece_alignment.left_bytes)) {
            target.write_all(&[0u8][..])?;
        }

        let mut commitment_reader = CommitmentReader::new(pad_reader);
        let n = std::io::copy(&mut commitment_reader, &mut target)
            .context("failed to write and preprocess bytes")?;

        ensure!(n != 0, "add_piece: read 0 bytes before EOF from source");
        let n = PaddedBytesAmount(n as u64);
        let n: UnpaddedBytesAmount = n.into();

        ensure!(n == piece_size, "add_piece: invalid bytes amount written");

        // write right alignment
        for _ in 0..usize::from(PaddedBytesAmount::from(piece_alignment.right_bytes)) {
            target.write_all(&[0u8][..])?;
        }

        let commitment = commitment_reader.finish()?;
        let mut comm = [0u8; 32];
        comm.copy_from_slice(commitment.as_ref());

        let written = piece_alignment.left_bytes + piece_alignment.right_bytes + piece_size;

        Ok((PieceInfo::new(comm, n)?, written))
    })
}

fn ensure_piece_size(piece_size: UnpaddedBytesAmount) -> Result<()> {
    ensure!(
        piece_size >= UnpaddedBytesAmount(MINIMUM_PIECE_SIZE),
        "Piece must be at least {} bytes",
        MINIMUM_PIECE_SIZE
    );

    let padded_piece_size: PaddedBytesAmount = piece_size.into();
    ensure!(
        u64::from(padded_piece_size).is_power_of_two(),
        "Bit-padded piece size must be a power of 2 ({:?})",
        padded_piece_size,
    );

    Ok(())
}

/// Writes bytes from `source` to `target`, adding bit-padding ("preprocessing")
/// as needed. Returns a tuple containing the number of bytes written to
/// `target` and the commitment.
///
/// WARNING: This function neither prepends nor appends alignment bytes to the
/// `target`; it is the caller's responsibility to ensure properly sized
/// and ordered writes to `target` such that `source`-bytes occupy whole
/// subtrees of the final merkle tree built over `target`.
///
/// # Arguments
///
/// * `source` - a readable source of unprocessed piece bytes.
/// * `target` - a writer where we will write the processed piece bytes.
/// * `piece_size` - the number of unpadded user-bytes which can be read from source before EOF.
pub fn write_and_preprocess<R, W>(
    source: R,
    target: W,
    piece_size: UnpaddedBytesAmount,
) -> Result<(PieceInfo, UnpaddedBytesAmount)>
where
    R: Read,
    W: Write,
{
    add_piece(source, target, piece_size, Default::default())
}

// Verifies if a DiskStore specified by a config is consistent.
fn verify_store(config: &StoreConfig, arity: usize) -> Result<()> {
    let store_path = StoreConfig::data_path(&config.path, &config.id);
    ensure!(
        Path::new(&store_path).exists(),
        "Missing store file: {}",
        store_path.display()
    );

    ensure!(
        config.size.is_some(),
        "Missing store size: {}",
        store_path.display()
    );

    ensure!(
        DiskStore::<<DefaultPieceHasher as Hasher>::Domain>::is_consistent(
            config.size.unwrap(),
            arity,
            &config,
        )?,
        "Store is inconsistent: {:?}",
        store_path
    );

    Ok(())
}

// Checks for the existence of the tree d store, the replica, and all generated labels.
pub fn validate_cache_for_precommit_phase2<R, T>(
    cache_path: R,
    replica_path: T,
    seal_precommit_phase1_output: &SealPreCommitPhase1Output,
) -> Result<()>
where
    R: AsRef<Path>,
    T: AsRef<Path>,
{
    ensure!(
        replica_path.as_ref().exists(),
        "Missing replica: {}",
        replica_path.as_ref().to_path_buf().display()
    );

    // Verify all stores/labels within the Labels object.
    let cache = cache_path.as_ref().to_path_buf();
    seal_precommit_phase1_output
        .labels
        .verify_stores(verify_store, &cache)?;

    verify_store(&seal_precommit_phase1_output.config, BINARY_ARITY)
}

// Checks for the existence of the replica data and t_aux, which in
// turn allows us to verify the tree d, tree r, tree c, and the
// labels.
pub fn validate_cache_for_commit<R, T>(cache_path: R, replica_path: T) -> Result<()>
where
    R: AsRef<Path>,
    T: AsRef<Path>,
{
    // Verify that the replica exists and is not empty.
    ensure!(
        replica_path.as_ref().exists(),
        "Missing replica: {}",
        replica_path.as_ref().to_path_buf().display()
    );

    let metadata = File::open(&replica_path)?.metadata()?;
    ensure!(
        metadata.len() > 0,
        "Replica {} exists, but is empty!",
        replica_path.as_ref().to_path_buf().display()
    );

    let cache = &cache_path.as_ref();

    // Make sure p_aux exists and is valid.
    let mut p_aux_bytes = vec![];
    let p_aux_path = cache.join(CacheKey::PAux.to_string());
    let mut f_p_aux = File::open(&p_aux_path)
        .with_context(|| format!("could not open file p_aux={:?}", p_aux_path))?;
    f_p_aux.read_to_end(&mut p_aux_bytes)?;

    let _: PersistentAux<DefaultTreeHasher> = deserialize(&p_aux_bytes)?;
    drop(p_aux_bytes);

    // Make sure t_aux exists and is valid.
    let t_aux = {
        let mut t_aux_bytes = vec![];
        let t_aux_path = cache.join(CacheKey::TAux.to_string());
        let mut f_t_aux = File::open(&t_aux_path)
            .with_context(|| format!("could not open file t_aux={:?}", t_aux_path))?;
        f_t_aux.read_to_end(&mut t_aux_bytes)?;

        let mut res: TemporaryAux<DefaultTreeHasher, DefaultPieceHasher> =
            deserialize(&t_aux_bytes)?;

        // Switch t_aux to the passed in cache_path
        res.set_cache_path(&cache_path);
        res
    };

    // Verify all stores/labels within the Labels object.
    let cache = cache_path.as_ref().to_path_buf();
    t_aux.labels.verify_stores(verify_store, &cache)?;

    // Verify each tree disk store.
    verify_store(&t_aux.tree_d_config, BINARY_ARITY)?;
    verify_store(&t_aux.tree_c_config, OCT_ARITY)?;

    let store_path =
        StoreConfig::data_path(&t_aux.tree_r_last_config.path, &t_aux.tree_r_last_config.id);

    ensure!(
        Path::new(&store_path).exists(),
        "Missing store file: {:?}",
        store_path
    );

    ensure!(
        t_aux.tree_r_last_config.size.is_some(),
        "Missing store size: {:?}",
        store_path
    );

    ensure!(
        LevelCacheStore::<<DefaultPieceHasher as Hasher>::Domain, std::fs::File>::is_consistent(
            t_aux.tree_r_last_config.size.unwrap(),
            OCT_ARITY,
            &t_aux.tree_r_last_config,
        )?,
        "Store is inconsistent: {:?}",
        store_path
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::Once;

    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs::fr32::bytes_into_fr;
    use storage_proofs::post::election::Candidate;
    use tempfile::NamedTempFile;

    use crate::constants::{POREP_PARTITIONS, SECTOR_SIZE_2_KIB, SINGLE_PARTITION_PROOF_LEN};
    use crate::types::{PoStConfig, SectorSize};

    static INIT_LOGGER: Once = Once::new();
    fn init_logger() {
        INIT_LOGGER.call_once(|| {
            fil_logger::init();
        });
    }

    #[test]
    fn test_verify_seal_fr32_validation() {
        let convertible_to_fr_bytes = [0; 32];
        let out = bytes_into_fr::<Bls12>(&convertible_to_fr_bytes);
        assert!(out.is_ok(), "tripwire");

        let not_convertible_to_fr_bytes = [255; 32];
        let out = bytes_into_fr::<Bls12>(&not_convertible_to_fr_bytes);
        assert!(out.is_err(), "tripwire");

        {
            let result = verify_seal(
                PoRepConfig {
                    sector_size: SectorSize(SECTOR_SIZE_2_KIB),
                    partitions: PoRepProofPartitions(
                        *POREP_PARTITIONS
                            .read()
                            .unwrap()
                            .get(&SECTOR_SIZE_2_KIB)
                            .unwrap(),
                    ),
                },
                not_convertible_to_fr_bytes,
                convertible_to_fr_bytes,
                [0; 32],
                SectorId::from(0),
                [0; 32],
                [0; 32],
                &[],
            );

            if let Err(err) = result {
                let needle = "Invalid all zero commitment";
                let haystack = format!("{}", err);

                assert!(
                    haystack.contains(needle),
                    format!("\"{}\" did not contain \"{}\"", haystack, needle)
                );
            } else {
                panic!("should have failed comm_r to Fr32 conversion");
            }
        }

        {
            let result = verify_seal(
                PoRepConfig {
                    sector_size: SectorSize(SECTOR_SIZE_2_KIB),
                    partitions: PoRepProofPartitions(
                        *POREP_PARTITIONS
                            .read()
                            .unwrap()
                            .get(&SECTOR_SIZE_2_KIB)
                            .unwrap(),
                    ),
                },
                convertible_to_fr_bytes,
                not_convertible_to_fr_bytes,
                [0; 32],
                SectorId::from(0),
                [0; 32],
                [0; 32],
                &[],
            );

            if let Err(err) = result {
                let needle = "Invalid all zero commitment";
                let haystack = format!("{}", err);

                assert!(
                    haystack.contains(needle),
                    format!("\"{}\" did not contain \"{}\"", haystack, needle)
                );
            } else {
                panic!("should have failed comm_d to Fr32 conversion");
            }
        }
    }

    #[test]
    #[ignore]
    fn test_verify_post_fr32_validation() {
        init_logger();

        let not_convertible_to_fr_bytes = [255; 32];
        let out = bytes_into_fr::<Bls12>(&not_convertible_to_fr_bytes);
        assert!(out.is_err(), "tripwire");
        let mut replicas = BTreeMap::new();
        replicas.insert(
            1.into(),
            PublicReplicaInfo::new(not_convertible_to_fr_bytes).unwrap(),
        );
        let winner = Candidate {
            sector_id: 1.into(),
            partial_ticket: Fr::zero(),
            ticket: [0; 32],
            sector_challenge_index: 0,
        };

        let result = verify_post(
            PoStConfig {
                sector_size: SectorSize(SECTOR_SIZE_2_KIB),
                challenge_count: crate::constants::POST_CHALLENGE_COUNT,
                challenged_nodes: crate::constants::POST_CHALLENGED_NODES,
                priority: false,
            },
            &[0; 32],
            1,
            &[vec![0u8; SINGLE_PARTITION_PROOF_LEN]][..],
            &replicas,
            &[winner][..],
            [0; 32],
        );

        if let Err(err) = result {
            let needle = "Invalid commitment (comm_r)";
            let haystack = format!("{}", err);

            assert!(
                haystack.contains(needle),
                format!("\"{}\" did not contain \"{}\"", haystack, needle)
            );
        } else {
            panic!("should have failed comm_r to Fr32 conversion");
        }
    }

    #[test]
    fn test_verify_post_duplicate_checking() {
        init_logger();

        let mut fr_bytes = [1; 32];
        fr_bytes[31] = 0;

        let _out = bytes_into_fr::<Bls12>(&fr_bytes);
        let mut replicas = BTreeMap::new();
        replicas.insert(1.into(), PublicReplicaInfo::new(fr_bytes).unwrap());
        let winner = Candidate {
            sector_id: 1.into(),
            partial_ticket: Fr::zero(),
            ticket: [0; 32],
            sector_challenge_index: 0,
        };

        let result = verify_post(
            PoStConfig {
                sector_size: SectorSize(SECTOR_SIZE_2_KIB),
                challenge_count: crate::constants::POST_CHALLENGE_COUNT,
                challenged_nodes: crate::constants::POST_CHALLENGED_NODES,
                priority: false,
            },
            &[0; 32],
            1,
            &[
                vec![0u8; SINGLE_PARTITION_PROOF_LEN],
                vec![0u8; SINGLE_PARTITION_PROOF_LEN],
            ][..],
            &replicas,
            &[winner.clone(), winner][..],
            [0; 32],
        );

        assert!(
            result.is_err(),
            "expected error when passing duplicate winner"
        );

        if let Err(err) = result {
            let message = "duplicate sector_challenge_index";
            let error_string = format!("{}", err);

            assert!(
                error_string.contains(message),
                format!("\"{}\" did not contain \"{}\"", error_string, message)
            );
        } else {
            panic!("should have failed comm_r to Fr32 conversion");
        }
    }

    #[test]
    #[ignore]
    fn test_seal_lifecycle() -> Result<()> {
        init_logger();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let sector_size = SECTOR_SIZE_2_KIB;

        let number_of_bytes_in_piece =
            UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size.clone()));

        let piece_bytes: Vec<u8> = (0..number_of_bytes_in_piece.0)
            .map(|_| rand::random::<u8>())
            .collect();

        let mut piece_file = NamedTempFile::new()?;
        piece_file.write_all(&piece_bytes)?;
        piece_file.as_file_mut().sync_all()?;
        piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

        let piece_info =
            generate_piece_commitment(piece_file.as_file_mut(), number_of_bytes_in_piece)?;
        piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

        let mut staged_sector_file = NamedTempFile::new()?;
        add_piece(
            &mut piece_file,
            &mut staged_sector_file,
            number_of_bytes_in_piece,
            &[],
        )?;

        let piece_infos = vec![piece_info];

        let sealed_sector_file = NamedTempFile::new()?;
        let mut unseal_file = NamedTempFile::new()?;
        let config = PoRepConfig {
            sector_size: SectorSize(sector_size.clone()),
            partitions: PoRepProofPartitions(
                *POREP_PARTITIONS.read().unwrap().get(&sector_size).unwrap(),
            ),
        };

        let cache_dir = tempfile::tempdir().unwrap();
        let prover_id = rng.gen();
        let ticket = rng.gen();
        let seed = rng.gen();
        let sector_id = SectorId::from(12);

        let phase1_output = seal_pre_commit_phase1(
            config,
            cache_dir.path(),
            staged_sector_file.path(),
            sealed_sector_file.path(),
            prover_id,
            sector_id,
            ticket,
            &piece_infos,
        )?;

        validate_cache_for_precommit_phase2(
            cache_dir.path(),
            staged_sector_file.path(),
            &phase1_output,
        )?;

        let pre_commit_output = seal_pre_commit_phase2(
            config,
            phase1_output,
            cache_dir.path(),
            sealed_sector_file.path(),
        )?;

        let comm_d = pre_commit_output.comm_d.clone();
        let comm_r = pre_commit_output.comm_r.clone();

        validate_cache_for_commit(cache_dir.path(), sealed_sector_file.path())?;

        let phase1_output = seal_commit_phase1(
            config,
            cache_dir.path(),
            sealed_sector_file.path(),
            prover_id,
            sector_id,
            ticket,
            seed,
            pre_commit_output,
            &piece_infos,
        )?;

        clear_cache(cache_dir.path())?;

        let commit_output = seal_commit_phase2(config, phase1_output, prover_id, sector_id)?;

        let _ = get_unsealed_range(
            config,
            cache_dir.path(),
            &sealed_sector_file.path(),
            &unseal_file.path(),
            prover_id,
            sector_id,
            comm_d,
            ticket,
            UnpaddedByteIndex(508),
            UnpaddedBytesAmount(508),
        )?;

        let mut contents = vec![];
        assert!(
            unseal_file.read_to_end(&mut contents).is_ok(),
            "failed to populate buffer with unsealed bytes"
        );
        assert_eq!(contents.len(), 508);
        assert_eq!(&piece_bytes[508..508 + 508], &contents[..]);

        let computed_comm_d = compute_comm_d(config.sector_size, &piece_infos)?;

        assert_eq!(
            comm_d, computed_comm_d,
            "Computed and expected comm_d don't match."
        );

        let verified = verify_seal(
            config,
            comm_r,
            comm_d,
            prover_id,
            sector_id,
            ticket,
            seed,
            &commit_output.proof,
        )?;
        assert!(verified, "failed to verify valid seal");

        Ok(())
    }
}
