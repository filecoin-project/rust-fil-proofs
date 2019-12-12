use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, ensure, Context, Result};
use merkletree::store::{StoreConfig, DEFAULT_CACHED_ABOVE_BASE_LAYER};
use storage_proofs::drgraph::DefaultTreeHasher;
use storage_proofs::hasher::Hasher;
use storage_proofs::sector::SectorId;
use storage_proofs::stacked::{generate_replica_id, CacheKey, StackedDrg};
use tempfile::tempfile;

use crate::api::util::as_safe_commitment;
use crate::constants::{
    DefaultPieceHasher,
    MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR as MINIMUM_PIECE_SIZE,
};
use crate::fr32::{write_padded, write_unpadded};
use crate::parameters::public_params;
use crate::pieces::get_aligned_source;
use crate::types::{
    Commitment, PaddedBytesAmount, PieceInfo, PoRepConfig, PoRepProofPartitions, ProverId, Ticket,
    UnpaddedByteIndex, UnpaddedBytesAmount,
};

mod post;
mod seal;
pub(crate) mod util;

pub use self::post::*;
pub use self::seal::*;
use std::io;
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

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let config = StoreConfig::new(
        cache_path,
        CacheKey::CommDTree.to_string(),
        DEFAULT_CACHED_ABOVE_BASE_LAYER,
    );
    let pp = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
    )?;

    let offset_padded: PaddedBytesAmount = UnpaddedBytesAmount::from(offset).into();
    let num_bytes_padded: PaddedBytesAmount = num_bytes.into();

    let unsealed = StackedDrg::<DefaultTreeHasher, DefaultPieceHasher>::extract_range(
        &pp,
        &replica_id,
        &data,
        Some(config),
        offset_padded.into(),
        num_bytes_padded.into(),
    )?;

    // If the call to `extract_range` was successful, the `unsealed` vector must
    // have a length which equals `num_bytes_padded`. The byte at its 0-index
    // byte will be the the byte at index `offset_padded` in the sealed sector.
    let written = write_unpadded(&unsealed, &mut buf_writer, 0, num_bytes.into())
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
    ensure_piece_size(piece_size)?;

    let mut temp_piece_file = tempfile()?;

    // send the source through the preprocessor, writing output to temp file
    let n = UnpaddedBytesAmount(
        write_padded(source, &temp_piece_file).context("failed to write and preprocess bytes")?
            as u64,
    );

    if n == UnpaddedBytesAmount(0) {
        return Err(anyhow!(
            "generate_piece_commitment: read 0 bytes from source before EOF"
        ));
    }

    if n != piece_size {
        return Err(anyhow!(
            "wrote ({:?}) but expected to write ({:?}) when preprocessing",
            n,
            piece_size
        ));
    }

    temp_piece_file
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("could not seek in temp_piece_file={:?}", temp_piece_file))?;

    let commitment = generate_piece_commitment_bytes_from_source::<DefaultPieceHasher>(
        &mut temp_piece_file,
        PaddedBytesAmount::from(n).into(),
    )?;

    PieceInfo::new(commitment, piece_size)
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
) -> Result<(UnpaddedBytesAmount, Commitment)>
where
    R: Read,
    W: Read + Write + Seek,
{
    ensure_piece_size(piece_size)?;

    let (aligned_source_size, alignment, aligned_source) =
        get_aligned_source(source, &piece_lengths, piece_size);

    // allows us to tee the source byte stream
    let (mut pipe_r, pipe_w) = os_pipe::pipe().context("failed to create pipe")?;

    // all bytes read from the TeeReader are written to its writer, no bytes
    // will be read from the TeeReader before they are written to its writer
    let tee_r = tee::TeeReader::new(aligned_source, pipe_w);

    // reads from tee_r block until the tee's source bytes can be written to its
    // writer, so to prevent write_padded from blocking indefinitely, we need
    // to spin up a separate thread (to read from the pipe which receives writes
    // from the TeeReader)
    let t_handle = std::thread::spawn(move || {
        // discard n left-alignment bytes
        let n = alignment.left_bytes.into();
        io::copy(&mut pipe_r.by_ref().take(n), &mut io::sink())
            .context("failed to skip alignment bytes")?;

        // generate commitment for piece bytes
        let result =
            generate_piece_commitment(&mut pipe_r.by_ref().take(piece_size.into()), piece_size);

        // drain the remaining bytes (all alignment) from the reader
        std::io::copy(&mut pipe_r.by_ref(), &mut io::sink())
            .context("failed to drain reader")
            .and_then(|_| result)
    });

    // send the source through the preprocessor, writing output to target
    let write_rslt = write_padded(tee_r, target).context("failed to write and preprocess bytes");

    // block until piece commitment-generating thread returns
    let join_rslt = t_handle
        .join()
        .map_err(|err| anyhow!("join piece commitment-generating thread failed: {:?}", err));

    match (write_rslt, join_rslt) {
        (Ok(n), Ok(Ok(r))) => {
            ensure!(n != 0, "add_piece: read 0 bytes before EOF from source");

            let n = UnpaddedBytesAmount(n as u64);

            ensure!(
                aligned_source_size == n,
                "expected to write {:?} source bytes, but actually wrote {:?}",
                aligned_source_size,
                n
            );

            Ok((n, r.commitment))
        }
        (Ok(n), Ok(Err(err))) => {
            let e = anyhow!(
                "wrote {:?} to target but then failed to generate piece commitment: {:?}",
                n,
                err
            );
            Err(e)
        }
        (Ok(n), Err(err)) => {
            let e = anyhow!(
                "wrote {:?} to target but then failed to generate piece commitment: {:?}",
                n,
                err
            );
            Err(e)
        }
        (Err(err), _) => {
            let e = anyhow!("failed to write and preprocess: {:?}", err);
            Err(e)
        }
    }
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
) -> Result<(UnpaddedBytesAmount, Commitment)>
where
    R: Read,
    W: Read + Write + Seek,
{
    add_piece(source, target, piece_size, Default::default())
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
    use storage_proofs::election_post::Candidate;
    use storage_proofs::fr32::bytes_into_fr;
    use tempfile::NamedTempFile;

    use crate::constants::{
        DEFAULT_POREP_PROOF_PARTITIONS, SECTOR_SIZE_ONE_KIB, SINGLE_PARTITION_PROOF_LEN,
    };
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
                    sector_size: SectorSize(SECTOR_SIZE_ONE_KIB),
                    partitions: DEFAULT_POREP_PROOF_PARTITIONS,
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
                    sector_size: SectorSize(SECTOR_SIZE_ONE_KIB),
                    partitions: DEFAULT_POREP_PROOF_PARTITIONS,
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
                sector_size: SectorSize(SECTOR_SIZE_ONE_KIB),
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
    #[ignore]
    fn test_seal_lifecycle() -> Result<()> {
        init_logger();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let sector_size = SECTOR_SIZE_ONE_KIB;

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
            partitions: DEFAULT_POREP_PROOF_PARTITIONS,
        };

        let cache_dir = tempfile::tempdir().unwrap();
        let prover_id = rng.gen();
        let ticket = rng.gen();
        let seed = rng.gen();
        let sector_id = SectorId::from(12);

        let pre_commit_output = seal_pre_commit(
            config,
            cache_dir.path(),
            &staged_sector_file.path(),
            &sealed_sector_file.path(),
            prover_id,
            sector_id,
            ticket,
            &piece_infos,
        )?;

        let comm_d = pre_commit_output.comm_d.clone();
        let comm_r = pre_commit_output.comm_r.clone();

        let commit_output = seal_commit(
            config,
            cache_dir.path(),
            prover_id,
            sector_id,
            ticket,
            seed,
            pre_commit_output,
            &piece_infos,
        )?;

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
        assert_eq!(&piece_bytes[508..], &contents[..]);

        let computed_comm_d = compute_comm_d(config, &piece_infos)?;

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
