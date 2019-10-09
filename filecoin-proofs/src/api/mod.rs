use std::convert::TryInto;
use std::fs::{copy, File, OpenOptions};
use std::io::prelude::*;
use std::io::{BufWriter, Cursor, Read, SeekFrom};
use std::path::{Path, PathBuf};

use memmap::MmapOptions;
use paired::bls12_381::Bls12;
use paired::Engine;

use crate::caches::{get_stacked_params, get_stacked_verifying_key};
use crate::constants::{
    MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR as MINIMUM_PIECE_SIZE,
    MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR as MIN_NUM_LEAVES, POREP_MINIMUM_CHALLENGES,
    SINGLE_PARTITION_PROOF_LEN,
};
use crate::error;
use crate::file_cleanup::FileCleanup;
use crate::fr32::{write_padded, write_unpadded};
use crate::parameters::{public_params, setup_params};
use crate::pieces::{get_aligned_source, get_piece_alignment, PieceAlignment};
use crate::singletons::ENGINE_PARAMS;
use crate::types::{
    PaddedBytesAmount, PoRepConfig, PoRepProofPartitions, SectorSize, UnpaddedByteIndex,
    UnpaddedBytesAmount,
};

use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::circuit::stacked::StackedCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgraph::{DefaultTreeHasher, Graph};
use storage_proofs::fr32::{bytes_into_fr, fr_into_bytes, Fr32Ary};
use storage_proofs::hasher::pedersen::{PedersenDomain, PedersenHasher};
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::merkle::MerkleTree;
use storage_proofs::piece_inclusion_proof::{
    generate_piece_commitment_bytes_from_source, piece_inclusion_proofs, PieceInclusionProof,
    PieceSpec,
};
use storage_proofs::porep::PoRep;
use storage_proofs::sector::SectorId;
use storage_proofs::stacked::{self, generate_replica_id, ChallengeRequirements, StackedDrg, Tau};
use tempfile::tempfile;

mod post;
pub use crate::api::post::*;

/// FrSafe is an array of the largest whole number of bytes guaranteed not to overflow the field.
pub type FrSafe = [u8; 31];

pub type Commitment = Fr32Ary;
pub type ChallengeSeed = [u8; 32];
type Tree = MerkleTree<PedersenDomain, <PedersenHasher as Hasher>::Function>;

pub type PersistentAux = stacked::PersistentAux<PedersenDomain>;

pub type Ticket = [u8; 32];

#[derive(Clone, Debug)]
pub struct SealOutput {
    pub comm_r: Commitment,
    pub comm_d: Commitment,
    pub p_aux: PersistentAux,
    pub proof: Vec<u8>,
    pub comm_ps: Vec<Commitment>,
    pub piece_inclusion_proofs: Vec<PieceInclusionProof<PedersenHasher>>,
}

fn as_safe_commitment(
    comm: &Commitment,
    commitment_name: impl AsRef<str>,
) -> Result<PedersenDomain, failure::Error> {
    bytes_into_fr::<Bls12>(comm).map(Into::into).map_err(|err| {
        format_err!(
            "Invalid commitment ({}): {:?}",
            commitment_name.as_ref(),
            err
        )
    })
}

struct PseudoPieceSpec {
    position: usize,
    number_of_leaves: usize,
    left_bytes: PaddedBytesAmount,
    rest_bytes: PaddedBytesAmount,
}

fn generate_pseudo_piece_specs(piece_lengths: &[UnpaddedBytesAmount]) -> Vec<PseudoPieceSpec> {
    let mut byte_index = UnpaddedBytesAmount(0);

    piece_lengths
        .iter()
        .map(|&unpadded_piece_length| {
            let PieceAlignment {
                left_bytes,
                right_bytes,
            } = get_piece_alignment(byte_index, unpadded_piece_length);

            let padded_piece_length = PaddedBytesAmount::from(unpadded_piece_length);
            let padded_left_bytes = PaddedBytesAmount::from(left_bytes);
            let padded_right_bytes =
                PaddedBytesAmount::from(unpadded_piece_length + right_bytes) - padded_piece_length;

            let leaf_position =
                (usize::from(byte_index) / MINIMUM_PIECE_SIZE as usize) * MIN_NUM_LEAVES;

            byte_index = byte_index + left_bytes + unpadded_piece_length + right_bytes;

            let number_of_leaves = (usize::from(byte_index) / MINIMUM_PIECE_SIZE as usize)
                * MIN_NUM_LEAVES
                - leaf_position;

            PseudoPieceSpec {
                position: leaf_position,
                number_of_leaves,
                left_bytes: padded_left_bytes,
                rest_bytes: padded_piece_length + padded_right_bytes,
            }
        })
        .collect()
}

fn generate_piece_specs_from_source(
    source: &mut (impl Read + Seek),
    piece_lengths: &[UnpaddedBytesAmount],
) -> error::Result<Vec<PieceSpec>> {
    let pseudo_piece_specs = generate_pseudo_piece_specs(piece_lengths);

    let mut piece_specs: Vec<PieceSpec> = vec![];

    for pseudo_piece_spec in pseudo_piece_specs {
        source.seek(SeekFrom::Current(
            usize::from(pseudo_piece_spec.left_bytes) as i64
        ))?;

        let mut buf = vec![0; usize::from(pseudo_piece_spec.rest_bytes)];
        source.read_exact(&mut buf)?;

        let mut source = Cursor::new(&buf);
        let comm_p = generate_piece_commitment_bytes_from_source::<PedersenHasher>(&mut source)?;

        piece_specs.push(PieceSpec {
            comm_p,
            position: pseudo_piece_spec.position,
            number_of_leaves: pseudo_piece_spec.number_of_leaves,
        });
    }

    Ok(piece_specs)
}

/// Seals the staged sector at `in_path` in place, saving the resulting replica
/// to `out_path`.
///
pub fn seal<T: AsRef<Path>>(
    porep_config: PoRepConfig,
    in_path: T,
    out_path: T,
    prover_id_in: &FrSafe,
    sector_id: SectorId,
    ticket: Ticket,
    piece_lengths: &[UnpaddedBytesAmount],
) -> error::Result<SealOutput> {
    let sector_bytes = usize::from(PaddedBytesAmount::from(porep_config));

    let mut cleanup = FileCleanup::new(&out_path);

    // Copy unsealed data to output location, where it will be sealed in place.
    copy(&in_path, &out_path)?;
    let f_data = OpenOptions::new().read(true).write(true).open(&out_path)?;

    // Zero-pad the data to the requested size by extending the underlying file if needed.
    f_data.set_len(sector_bytes as u64)?;

    let mut data = unsafe { MmapOptions::new().map_mut(&f_data).unwrap() };

    // TODO: do these need to be Fr safe?

    // Zero-pad the prover_id to 32 bytes (and therefore Fr32).
    let prover_id = pad_safe_fr(prover_id_in);
    // Zero-pad the sector_id to 32 bytes (and therefore Fr32).
    let sector_id_as_safe_fr = pad_safe_fr(&sector_id.as_fr_safe());

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        ),
        engine_params: &(*ENGINE_PARAMS),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params = StackedCompound::setup(&compound_setup_params)?;

    let data_tree = compound_public_params
        .vanilla_params
        .graph
        .merkle_tree(&data)?;

    let replica_id = generate_replica_id::<DefaultTreeHasher>(
        &prover_id,
        &sector_id_as_safe_fr,
        &ticket,
        data_tree.root(),
    );

    let (tau, (p_aux, t_aux)) = StackedDrg::replicate(
        &compound_public_params.vanilla_params,
        &replica_id,
        &mut data,
        Some(data_tree),
    )?;

    let mut in_data = OpenOptions::new().read(true).open(&in_path)?;
    let piece_specs = generate_piece_specs_from_source(&mut in_data, &piece_lengths)?;
    let piece_inclusion_proofs =
        piece_inclusion_proofs::<PedersenHasher>(&piece_specs, &t_aux.tree_d)?;
    let comm_ps: Vec<Commitment> = piece_specs
        .iter()
        .map(|piece_spec| piece_spec.comm_p)
        .collect();

    // If we succeeded in replicating, flush the data and protect output from being cleaned up.
    data.flush()?;
    cleanup.success = true;

    let public_tau = tau;

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(public_tau.clone()),
        k: None,
        seed: None,
    };

    let private_inputs = stacked::PrivateInputs::<DefaultTreeHasher> {
        p_aux: p_aux.clone(),
        t_aux,
    };

    let groth_params = get_stacked_params(porep_config)?;

    info!(
        "got groth params ({}) while sealing",
        u64::from(PaddedBytesAmount::from(porep_config))
    );

    let proof = StackedCompound::prove(
        &compound_public_params,
        &public_inputs,
        &private_inputs,
        &groth_params,
    )?;

    let mut buf = Vec::with_capacity(
        SINGLE_PARTITION_PROOF_LEN * usize::from(PoRepProofPartitions::from(porep_config)),
    );

    proof.write(&mut buf)?;

    let comm_r = commitment_from_fr::<Bls12>(public_tau.comm_r.into());
    let comm_d = commitment_from_fr::<Bls12>(public_tau.comm_d.into());

    let valid_pieces = PieceInclusionProof::verify_all(
        &comm_d,
        &piece_inclusion_proofs,
        &comm_ps,
        &piece_specs
            .into_iter()
            .map(|p| p.number_of_leaves)
            .collect::<Vec<_>>(),
        sector_bytes >> 5,
    )?;

    if !valid_pieces {
        return Err(format_err!("pip verification sanity check failed"));
    }

    // Verification is cheap when parameters are cached,
    // and it is never correct to return a proof which does not verify.
    verify_seal(
        porep_config,
        comm_r,
        comm_d,
        prover_id_in,
        sector_id,
        ticket,
        &buf,
    )
    .expect("post-seal verification sanity check failed");

    Ok(SealOutput {
        comm_r,
        comm_d,
        p_aux,
        proof: buf,
        comm_ps,
        piece_inclusion_proofs,
    })
}

/// Verifies the output of some previously-run seal operation.
///
pub fn verify_seal(
    porep_config: PoRepConfig,
    comm_r: Commitment,
    comm_d: Commitment,
    prover_id_in: &FrSafe,
    sector_id: SectorId,
    ticket: Ticket,
    proof_vec: &[u8],
) -> error::Result<bool> {
    let sector_bytes = PaddedBytesAmount::from(porep_config);
    let prover_id = pad_safe_fr(prover_id_in);
    let sector_id_as_safe_fr = pad_safe_fr(&sector_id.as_fr_safe());

    let comm_r = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d = as_safe_commitment(&comm_d, "comm_d")?;

    let replica_id = generate_replica_id::<DefaultTreeHasher>(
        &prover_id,
        &sector_id_as_safe_fr,
        &ticket,
        comm_d,
    );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        ),
        engine_params: &(*ENGINE_PARAMS),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        Bls12,
        StackedDrg<'_, DefaultTreeHasher>,
    > = StackedCompound::setup(&compound_setup_params)?;

    let public_inputs = stacked::PublicInputs::<<DefaultTreeHasher as Hasher>::Domain> {
        replica_id,
        tau: Some(Tau { comm_r, comm_d }),
        seed: None,
        k: None,
    };

    let verifying_key = get_stacked_verifying_key(porep_config)?;

    info!(
        "got verifying key ({}) while verifying seal",
        u64::from(sector_bytes)
    );

    let proof = MultiProof::new_from_reader(
        Some(usize::from(PoRepProofPartitions::from(porep_config))),
        proof_vec,
        &verifying_key,
    )?;

    StackedCompound::verify(
        &compound_public_params,
        &public_inputs,
        &proof,
        &ChallengeRequirements {
            minimum_challenges: POREP_MINIMUM_CHALLENGES,
        },
    )
    .map_err(Into::into)
}

/// Verify that the provided PIP proves the piece is included in the sector.
///
pub fn verify_piece_inclusion_proof(
    piece_inclusion_proof: &[u8],
    comm_d: &Commitment,
    comm_p: &Commitment,
    piece_size: UnpaddedBytesAmount,
    sector_size: SectorSize,
) -> error::Result<bool> {
    let piece_inclusion_proof: PieceInclusionProof<PedersenHasher> =
        piece_inclusion_proof.try_into()?;
    let comm_d = storage_proofs::hasher::pedersen::PedersenDomain::try_from_bytes(comm_d)?;
    let comm_p = storage_proofs::hasher::pedersen::PedersenDomain::try_from_bytes(comm_p)?;
    let piece_alignment = get_piece_alignment(UnpaddedBytesAmount(0), piece_size);
    let piece_size_with_alignment =
        PaddedBytesAmount::from(piece_size + piece_alignment.right_bytes);

    let piece_leaves = u64::from(piece_size_with_alignment) / 32;
    let sector_leaves = u64::from(PaddedBytesAmount::from(sector_size)) / 32;

    Ok(piece_inclusion_proof.verify(
        &comm_d,
        &comm_p,
        piece_leaves as usize,
        sector_leaves as usize,
    ))
}

/// Takes a piece file at `unpadded_piece_path` and the size of the piece and returns the comm_p.
///
pub fn generate_piece_commitment<T: std::io::Read>(
    unpadded_piece_file: T,
    unpadded_piece_size: UnpaddedBytesAmount,
) -> error::Result<Commitment> {
    let mut padded_piece_file = tempfile()?;

    let (_, mut source) = get_aligned_source(unpadded_piece_file, &[], unpadded_piece_size);
    write_padded(&mut source, &mut padded_piece_file)?;

    let _ = padded_piece_file.seek(SeekFrom::Start(0))?;

    let comm_p =
        generate_piece_commitment_bytes_from_source::<PedersenHasher>(&mut padded_piece_file)?;
    Ok(comm_p)
}

/// Unseals the sector at `sealed_path` and returns the bytes for a piece
/// whose first (unpadded) byte begins at `offset` and ends at `offset` plus
/// `num_bytes`, inclusive. Note that the entire sector is unsealed each time
/// this function is called.
#[allow(clippy::too_many_arguments)]
pub fn get_unsealed_range<T: Into<PathBuf> + AsRef<Path>>(
    porep_config: PoRepConfig,
    sealed_path: T,
    output_path: T,
    prover_id_in: &FrSafe,
    sector_id: SectorId,
    comm_d: Commitment,
    ticket: Ticket,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> error::Result<(UnpaddedBytesAmount)> {
    let sector_id_as_safe_fr = pad_safe_fr(&sector_id.as_fr_safe());
    let prover_id = pad_safe_fr(prover_id_in);
    let comm_d = storage_proofs::hasher::pedersen::PedersenDomain::try_from_bytes(&comm_d)?;

    let replica_id = generate_replica_id::<DefaultTreeHasher>(
        &prover_id,
        &sector_id_as_safe_fr,
        &ticket,
        comm_d,
    );

    let f_in = File::open(sealed_path)?;
    let mut data = Vec::new();
    f_in.take(u64::from(PaddedBytesAmount::from(porep_config)))
        .read_to_end(&mut data)?;

    let f_out = File::create(output_path)?;
    let mut buf_writer = BufWriter::new(f_out);

    let unsealed = StackedDrg::extract_all(
        &public_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        ),
        &replica_id,
        &data,
    )?;

    let written = write_unpadded(&unsealed, &mut buf_writer, offset.into(), num_bytes.into())?;

    Ok(UnpaddedBytesAmount(written as u64))
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Seek, SeekFrom};

    use crate::constants::SECTOR_SIZE_ONE_KIB;
    use crate::error::ExpectWithBacktrace;
    use crate::types::{PoStConfig, SectorSize};

    use rand::Rng;
    use tempfile::NamedTempFile;

    use storage_proofs::util::NODE_SIZE;

    use super::*;

    fn generate_comm_p(data: &[u8]) -> Result<Commitment, failure::Error> {
        let mut file = NamedTempFile::new().expects("could not create named temp file");
        file.write_all(data)?;
        file.seek(SeekFrom::Start(0))?;

        let comm_p =
            generate_piece_commitment(file.as_file_mut(), UnpaddedBytesAmount(data.len() as u64))?;
        Ok(comm_p)
    }

    fn add_piece<R, W>(
        mut source: &mut R,
        target: &mut W,
        piece_size: UnpaddedBytesAmount,
        piece_lengths: &[UnpaddedBytesAmount],
    ) -> std::io::Result<usize>
    where
        R: Read + ?Sized,
        W: Read + Write + Seek + ?Sized,
    {
        let (_, mut aligned_source) = get_aligned_source(&mut source, &piece_lengths, piece_size);
        write_padded(&mut aligned_source, target)
    }

    #[test]
    fn test_generate_piece_commitment_up_to_minimum() -> Result<(), failure::Error> {
        // test comm_p generation for all byte lengths up to the minimum piece alignment when
        // writing a piece to a sector
        let max = MINIMUM_PIECE_SIZE as usize;

        for n in 0..=max {
            let bytes: Vec<u8> = (0..n).map(|_| rand::random::<u8>()).collect();
            let mut data_a = vec![0; n];
            let mut data_b = vec![0; max];

            for i in 0..n {
                data_a[i] = bytes[i];
                data_b[i] = bytes[i];
            }

            let comm_p_a = generate_comm_p(&data_a)?;
            let comm_p_b = generate_comm_p(&data_b)?;

            assert_eq!(comm_p_a, comm_p_b);
        }

        Ok(())
    }

    #[test]
    fn test_generate_piece_commitment_over_minimum() -> Result<(), failure::Error> {
        // sanity check that larger byte lengths are still zero padded
        let bytes: Vec<u8> = (0..400).map(|_| rand::random::<u8>()).collect();
        let mut data_a = vec![0; 400];
        let mut data_b = vec![0; 508];

        for i in 0..400 {
            data_a[i] = bytes[i];
            data_b[i] = bytes[i];
        }

        let comm_p_a = generate_comm_p(&data_a)?;
        let comm_p_b = generate_comm_p(&data_b)?;

        assert_eq!(comm_p_a, comm_p_b);

        Ok(())
    }

    #[test]
    fn test_generate_pseudo_piece_specs() -> Result<(), failure::Error> {
        let mut rng = rand::thread_rng();

        for _ in 0..20 {
            let number_of_pieces = rng.gen_range(1, 20);
            let mut piece_lengths: Vec<UnpaddedBytesAmount> = vec![];

            for _ in 0..number_of_pieces {
                piece_lengths.push(UnpaddedBytesAmount(rng.gen_range(1, 1666)));
            }

            let pseudo_piece_specs = generate_pseudo_piece_specs(&piece_lengths);

            assert_eq!(pseudo_piece_specs.len(), number_of_pieces);

            let sum_piece_lengths: usize = piece_lengths
                .iter()
                .fold(UnpaddedBytesAmount(0), |a, &b| a + b)
                .into();
            let sum_piece_leaves = pseudo_piece_specs
                .iter()
                .fold(0, |acc, s| acc + s.number_of_leaves);

            assert!(sum_piece_lengths < sum_piece_leaves * NODE_SIZE);

            for (&piece_length, piece_spec) in piece_lengths.iter().zip(pseudo_piece_specs.iter()) {
                let usize_piece_length = u64::from(piece_length) as usize;
                let expected_piece_leaves = if usize_piece_length <= 127 {
                    4
                } else {
                    let padded_piece_length: PaddedBytesAmount = piece_length.into();
                    (u64::from(padded_piece_length).next_power_of_two() as usize) / NODE_SIZE
                };
                assert!(piece_spec.number_of_leaves >= expected_piece_leaves);
                assert!(piece_spec.number_of_leaves < expected_piece_leaves * 2);
            }
        }

        Ok(())
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
                PoRepConfig(SectorSize(SECTOR_SIZE_ONE_KIB), PoRepProofPartitions(2)),
                not_convertible_to_fr_bytes,
                convertible_to_fr_bytes,
                &[0; 31],
                SectorId::from(0),
                [0; 32],
                &[],
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

        {
            let result = verify_seal(
                PoRepConfig(SectorSize(SECTOR_SIZE_ONE_KIB), PoRepProofPartitions(2)),
                convertible_to_fr_bytes,
                not_convertible_to_fr_bytes,
                &[0; 31],
                SectorId::from(0),
                [0; 32],
                &[],
            );

            if let Err(err) = result {
                let needle = "Invalid commitment (comm_d)";
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
    fn test_verify_post_fr32_validation() {
        let not_convertible_to_fr_bytes = [255; 32];
        let out = bytes_into_fr::<Bls12>(&not_convertible_to_fr_bytes);
        assert!(out.is_err(), "tripwire");
        let mut replicas = BTreeMap::new();
        replicas.insert(
            1.into(),
            PublicReplicaInfo::new(not_convertible_to_fr_bytes),
        );

        let result = verify_post(
            PoStConfig(SectorSize(SECTOR_SIZE_ONE_KIB)),
            &[0; 32],
            &vec![0; SINGLE_PARTITION_PROOF_LEN],
            &replicas,
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
    fn test_pip_lifecycle() -> Result<(), failure::Error> {
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

        let comm_p = generate_piece_commitment(piece_file.as_file_mut(), number_of_bytes_in_piece)?;
        piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

        let mut staged_sector_file = NamedTempFile::new()?;
        add_piece(
            &mut piece_file,
            &mut staged_sector_file,
            number_of_bytes_in_piece,
            &[],
        )?;

        let sealed_sector_file = NamedTempFile::new()?;
        let config = PoRepConfig(SectorSize(sector_size.clone()), PoRepProofPartitions(2));

        let output = seal(
            config,
            &staged_sector_file.path(),
            &sealed_sector_file.path(),
            &[0; 31],
            SectorId::from(0),
            [0; 32],
            &[number_of_bytes_in_piece],
        )?;

        let piece_inclusion_proof_bytes: Vec<u8> = output.piece_inclusion_proofs[0].clone().into();

        let verified = verify_piece_inclusion_proof(
            &piece_inclusion_proof_bytes,
            &output.comm_d,
            &output.comm_ps[0],
            number_of_bytes_in_piece,
            SectorSize(sector_size),
        )?;

        assert!(verified);

        assert_eq!(output.comm_ps.len(), 1);
        assert_eq!(output.comm_ps[0], comm_p);

        Ok(())
    }
}
