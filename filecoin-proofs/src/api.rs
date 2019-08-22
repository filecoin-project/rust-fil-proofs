use std::convert::TryInto;
use std::fs::{copy, File, OpenOptions};
use std::io::prelude::*;
use std::io::{BufWriter, Cursor, Read, SeekFrom};
use std::path::{Path, PathBuf};

use ff::PrimeField;
use memmap::MmapOptions;
use paired::bls12_381::Bls12;
use paired::Engine;

use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::circuit::vdf_post::VDFPostCompound;
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgraph::{DefaultTreeHasher, Graph};
use storage_proofs::error::Error;
use storage_proofs::fr32::{bytes_into_fr, fr_into_bytes, Fr32Ary};
use storage_proofs::hasher::pedersen::{PedersenDomain, PedersenHasher};
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::layered_drgporep::{self, ChallengeRequirements};
use storage_proofs::merkle::MerkleTree;
use storage_proofs::piece_inclusion_proof::{
    generate_piece_commitment_bytes_from_source, piece_inclusion_proofs, PieceInclusionProof,
    PieceSpec,
};
use storage_proofs::porep::{replica_id, PoRep, Tau};
use storage_proofs::proof::NoRequirements;
use storage_proofs::zigzag_drgporep::ZigZagDrgPoRep;
use storage_proofs::{vdf_post, vdf_sloth};
use tempfile::tempfile;

use crate::caches::{
    get_post_params, get_post_verifying_key, get_zigzag_params, get_zigzag_verifying_key,
};
use crate::constants::{
    MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR as MINIMUM_PIECE_SIZE,
    MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR as MIN_NUM_LEAVES, POREP_MINIMUM_CHALLENGES,
    SINGLE_PARTITION_PROOF_LEN,
};
use crate::error;
use crate::file_cleanup::FileCleanup;
use crate::fr32::{write_padded, write_unpadded};
use crate::parameters::{post_setup_params, public_params, setup_params};
use crate::pieces::{get_aligned_source, get_piece_alignment, PieceAlignment};
use crate::post_adapter::*;
use crate::singletons::ENGINE_PARAMS;
use crate::types::{
    PaddedBytesAmount, PoRepConfig, PoRepProofPartitions, PoStConfig, PoStProofPartitions,
    SectorSize, UnpaddedByteIndex, UnpaddedBytesAmount,
};

/// FrSafe is an array of the largest whole number of bytes guaranteed not to overflow the field.
pub type FrSafe = [u8; 31];

pub type Commitment = Fr32Ary;
pub type ChallengeSeed = Fr32Ary;
type Tree = MerkleTree<PedersenDomain, <PedersenHasher as Hasher>::Function>;

#[derive(Clone, Debug)]
pub struct SealOutput {
    pub comm_r: Commitment,
    pub comm_r_star: Commitment,
    pub comm_d: Commitment,
    pub proof: Vec<u8>,
    pub comm_ps: Vec<Commitment>,
    pub piece_inclusion_proofs: Vec<PieceInclusionProof<PedersenHasher>>,
}

/// Generates a proof-of-spacetime, returning and detected storage faults.
/// Accepts as input a challenge seed, configuration struct, and a vector of
/// sealed sector file-path plus CommR tuples.
///
pub fn generate_post(
    post_config: PoStConfig,
    challenge_seed: ChallengeSeed,
    input_parts: Vec<(Option<String>, Commitment)>,
) -> error::Result<GeneratePoStDynamicSectorsCountOutput> {
    generate_post_dynamic(GeneratePoStDynamicSectorsCountInput {
        post_config,
        challenge_seed,
        input_parts,
    })
}

/// Verifies a proof-of-spacetime.
///
pub fn verify_post(
    post_config: PoStConfig,
    comm_rs: Vec<Commitment>,
    challenge_seed: ChallengeSeed,
    proofs: Vec<Vec<u8>>,
    faults: Vec<u64>,
) -> error::Result<VerifyPoStDynamicSectorsCountOutput> {
    verify_post_dynamic(VerifyPoStDynamicSectorsCountInput {
        post_config,
        comm_rs,
        challenge_seed,
        proofs,
        faults,
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
    sector_id_in: &FrSafe,
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

    // Zero-pad the prover_id to 32 bytes (and therefore Fr32).
    let prover_id = pad_safe_fr(prover_id_in);
    // Zero-pad the sector_id to 32 bytes (and therefore Fr32).
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        ),
        engine_params: &(*ENGINE_PARAMS),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params = ZigZagCompound::setup(&compound_setup_params)?;

    let (tau, aux) = ZigZagDrgPoRep::replicate(
        &compound_public_params.vanilla_params,
        &replica_id,
        &mut data,
        None,
    )?;

    let mut in_data = OpenOptions::new().read(true).open(&in_path)?;
    let piece_specs = generate_piece_specs_from_source(&mut in_data, &piece_lengths)?;
    let piece_inclusion_proofs = piece_inclusion_proofs::<PedersenHasher>(&piece_specs, &aux[0])?;
    let comm_ps: Vec<Commitment> = piece_specs
        .iter()
        .map(|piece_spec| piece_spec.comm_p)
        .collect();

    // If we succeeded in replicating, flush the data and protect output from being cleaned up.
    data.flush()?;
    cleanup.success = true;

    let public_tau = tau.simplify();

    let public_inputs = layered_drgporep::PublicInputs {
        replica_id,
        tau: Some(public_tau),
        comm_r_star: tau.comm_r_star,
        k: None,
        seed: None,
    };

    let private_inputs = layered_drgporep::PrivateInputs::<DefaultTreeHasher> {
        aux,
        tau: tau.layer_taus,
    };

    let groth_params = get_zigzag_params(porep_config)?;

    info!(
        "got groth params ({}) while sealing",
        u64::from(PaddedBytesAmount::from(porep_config))
    );

    let proof = ZigZagCompound::prove(
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
    let comm_r_star = commitment_from_fr::<Bls12>(tau.comm_r_star.into());

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
        comm_r_star,
        prover_id_in,
        sector_id_in,
        &buf,
    )
    .expect("post-seal verification sanity check failed");

    Ok(SealOutput {
        comm_r,
        comm_r_star,
        comm_d,
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
    comm_r_star: Commitment,
    prover_id_in: &FrSafe,
    sector_id_in: &FrSafe,
    proof_vec: &[u8],
) -> error::Result<bool> {
    let sector_bytes = PaddedBytesAmount::from(porep_config);
    let prover_id = pad_safe_fr(prover_id_in);
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let comm_r = bytes_into_fr::<Bls12>(&comm_r).map_err(|err| match err {
        Error::BadFrBytes => format_err!("could not transform comm_r into Fr32: {:?}", err),
        _ => err.into(),
    })?;

    let comm_d = bytes_into_fr::<Bls12>(&comm_d).map_err(|err| match err {
        Error::BadFrBytes => format_err!("could not transform comm_d into Fr32: {:?}", err),
        _ => err.into(),
    })?;

    let comm_r_star = bytes_into_fr::<Bls12>(&comm_r_star).map_err(|err| match err {
        Error::BadFrBytes => format_err!("could not transform comm_r_star into Fr32: {:?}", err),
        _ => err.into(),
    })?;

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
        ZigZagDrgPoRep<'_, DefaultTreeHasher>,
    > = ZigZagCompound::setup(&compound_setup_params)?;

    let public_inputs = layered_drgporep::PublicInputs::<<DefaultTreeHasher as Hasher>::Domain> {
        replica_id,
        tau: Some(Tau {
            comm_r: comm_r.into(),
            comm_d: comm_d.into(),
        }),
        seed: None,
        comm_r_star: comm_r_star.into(),
        k: None,
    };

    let verifying_key = get_zigzag_verifying_key(porep_config)?;

    info!(
        "got verifying key ({}) while verifying seal",
        u64::from(sector_bytes)
    );

    let proof = MultiProof::new_from_reader(
        Some(usize::from(PoRepProofPartitions::from(porep_config))),
        proof_vec,
        &verifying_key,
    )?;

    ZigZagCompound::verify(
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
pub fn generate_piece_commitment<T: Into<PathBuf> + AsRef<Path>>(
    unpadded_piece_path: T,
    unpadded_piece_size: UnpaddedBytesAmount,
) -> error::Result<Commitment> {
    let mut unpadded_piece_file = File::open(unpadded_piece_path)?;
    let mut padded_piece_file = tempfile()?;

    let (_, mut source) = get_aligned_source(&mut unpadded_piece_file, &[], unpadded_piece_size);
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
///
pub fn get_unsealed_range<T: Into<PathBuf> + AsRef<Path>>(
    porep_config: PoRepConfig,
    sealed_path: T,
    output_path: T,
    prover_id_in: &FrSafe,
    sector_id_in: &FrSafe,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> error::Result<(UnpaddedBytesAmount)> {
    let prover_id = pad_safe_fr(prover_id_in);
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let f_in = File::open(sealed_path)?;
    let mut data = Vec::new();
    f_in.take(u64::from(PaddedBytesAmount::from(porep_config)))
        .read_to_end(&mut data)?;

    let f_out = File::create(output_path)?;
    let mut buf_writer = BufWriter::new(f_out);

    let unsealed = ZigZagDrgPoRep::extract_all(
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

fn verify_post_dynamic(
    dynamic: VerifyPoStDynamicSectorsCountInput,
) -> error::Result<VerifyPoStDynamicSectorsCountOutput> {
    let fixed = verify_post_spread_input(dynamic)?
        .iter()
        .map(verify_post_fixed_sectors_count)
        .collect();

    verify_post_collect_output(fixed)
}

fn generate_post_dynamic(
    dynamic: GeneratePoStDynamicSectorsCountInput,
) -> error::Result<GeneratePoStDynamicSectorsCountOutput> {
    let n = { dynamic.input_parts.len() };

    let fixed_output = generate_post_spread_input(dynamic)
        .iter()
        .map(generate_post_fixed_sectors_count)
        .collect();

    generate_post_collect_output(n, fixed_output)
}

fn generate_post_fixed_sectors_count(
    fixed: &GeneratePoStFixedSectorsCountInput,
) -> error::Result<GeneratePoStFixedSectorsCountOutput> {
    let faults: Vec<u64> = Vec::new();

    let setup_params = compound_proof::SetupParams {
        vanilla_params: &post_setup_params(fixed.post_config),
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
        cs[31] &= 0b0011_1111;
        cs
    };

    let pub_inputs = vdf_post::PublicInputs {
        challenge_seed: PedersenDomain::try_from_bytes(&safe_challenge_seed).unwrap(),
        commitments,
        faults: Vec::new(),
    };

    // Because of padding the last real tree is duplicated many times, so instead of recreating it
    // we stop when they are the same and only use references.
    let mut trees: Vec<Tree> = Vec::new();
    let mut last_comm = None;

    for (access, comm) in fixed.input_parts.iter() {
        if let Some(last_comm) = last_comm {
            if comm == last_comm {
                // we are done generating unique trees
                break;
            }
        }

        if let Some(s) = &access {
            trees.push(
                make_merkle_tree(
                    s,
                    PaddedBytesAmount(pub_params.vanilla_params.sector_size as u64),
                )
                .unwrap(),
            );
            last_comm = Some(comm);
        } else {
            panic!("faults are not yet supported");
        }
    }

    let fixed_len = fixed.input_parts.len();
    let mut borrowed_trees: Vec<&Tree> = Vec::with_capacity(fixed_len);
    for tree in &trees {
        borrowed_trees.push(tree);
    }
    // "Pad" with the last tree
    let last_tree = &trees[trees.len() - 1];
    while borrowed_trees.len() < fixed_len {
        borrowed_trees.push(last_tree);
    }

    let priv_inputs = vdf_post::PrivateInputs::<PedersenHasher>::new(&borrowed_trees[..]);

    let groth_params = get_post_params(fixed.post_config)?;

    let proof = VDFPostCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &groth_params)
        .expect("failed while proving");

    let mut buf = Vec::with_capacity(
        SINGLE_PARTITION_PROOF_LEN * usize::from(PoStProofPartitions::from(fixed.post_config)),
    );

    proof.write(&mut buf)?;

    Ok(GeneratePoStFixedSectorsCountOutput { proof: buf, faults })
}

fn verify_post_fixed_sectors_count(
    fixed: &VerifyPoStFixedSectorsCountInput,
) -> error::Result<VerifyPoStFixedSectorsCountOutput> {
    let safe_challenge_seed = {
        let mut cs = vec![0; 32];
        cs.copy_from_slice(&fixed.challenge_seed);
        cs[31] &= 0b0011_1111;
        cs
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &post_setup_params(fixed.post_config),
        engine_params: &(*ENGINE_PARAMS),
        partitions: None,
    };

    let compound_public_params: compound_proof::PublicParams<
        _,
        vdf_post::VDFPoSt<PedersenHasher, vdf_sloth::Sloth>,
    > = VDFPostCompound::setup(&compound_setup_params).expect("setup failed");

    let mut commitments: Vec<PedersenDomain> = vec![];

    for comm_r in fixed.comm_rs.iter() {
        let commitment = bytes_into_fr::<Bls12>(comm_r).map_err(|err| match err {
            Error::BadFrBytes => format_err!("could not transform comm_r into Fr32: {:?}", err),
            _ => err.into(),
        })?;

        commitments.push(PedersenDomain(commitment.into_repr()));
    }

    let public_inputs = vdf_post::PublicInputs::<PedersenDomain> {
        commitments,
        challenge_seed: PedersenDomain::try_from_bytes(&safe_challenge_seed)?,
        faults: fixed.faults.clone(),
    };

    let verifying_key = get_post_verifying_key(fixed.post_config)?;

    let num_post_proof_bytes =
        SINGLE_PARTITION_PROOF_LEN * usize::from(PoStProofPartitions::from(fixed.post_config));

    let proof = MultiProof::new_from_reader(
        Some(usize::from(PoStProofPartitions::from(fixed.post_config))),
        &fixed.proof[0..num_post_proof_bytes],
        &verifying_key,
    )?;

    let is_valid = VDFPostCompound::verify(
        &compound_public_params,
        &public_inputs,
        &proof,
        &NoRequirements,
    )?;

    // Since callers may rely on previous mocked success, just pretend verification succeeded, for now.
    Ok(VerifyPoStFixedSectorsCountOutput { is_valid })
}

fn make_merkle_tree<T: Into<PathBuf> + AsRef<Path>>(
    sealed_path: T,
    bytes: PaddedBytesAmount,
) -> storage_proofs::error::Result<Tree> {
    let mut f_in = File::open(sealed_path.into())?;
    let mut data = Vec::new();
    f_in.read_to_end(&mut data)?;

    public_params(bytes, 1).graph.merkle_tree(&data)
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
    use rand::Rng;
    use tempfile::NamedTempFile;

    use storage_proofs::util::NODE_SIZE;

    use crate::constants::{POST_SECTORS_COUNT, TEST_SECTOR_SIZE};
    use crate::error::ExpectWithBacktrace;
    use crate::types::SectorSize;

    use super::*;

    fn generate_comm_p(data: &[u8]) -> Result<Commitment, failure::Error> {
        let mut file = NamedTempFile::new().expects("could not create named temp file");
        file.write_all(data)?;
        let comm_p =
            generate_piece_commitment(file.path(), UnpaddedBytesAmount(data.len() as u64))?;
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
                PoRepConfig(SectorSize(TEST_SECTOR_SIZE), PoRepProofPartitions(2)),
                not_convertible_to_fr_bytes,
                convertible_to_fr_bytes,
                convertible_to_fr_bytes,
                &[0; 31],
                &[0; 31],
                &[],
            );

            if let Err(err) = result {
                let needle = "could not transform comm_r into Fr32";
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
                PoRepConfig(SectorSize(TEST_SECTOR_SIZE), PoRepProofPartitions(2)),
                convertible_to_fr_bytes,
                not_convertible_to_fr_bytes,
                convertible_to_fr_bytes,
                &[0; 31],
                &[0; 31],
                &[],
            );

            if let Err(err) = result {
                let needle = "could not transform comm_d into Fr32";
                let haystack = format!("{}", err);

                assert!(
                    haystack.contains(needle),
                    format!("\"{}\" did not contain \"{}\"", haystack, needle)
                );
            } else {
                panic!("should have failed comm_d to Fr32 conversion");
            }
        }

        {
            let result = verify_seal(
                PoRepConfig(SectorSize(TEST_SECTOR_SIZE), PoRepProofPartitions(2)),
                convertible_to_fr_bytes,
                convertible_to_fr_bytes,
                not_convertible_to_fr_bytes,
                &[0; 31],
                &[0; 31],
                &[],
            );

            if let Err(err) = result {
                let needle = "could not transform comm_r_star into Fr32";
                let haystack = format!("{}", err);

                assert!(
                    haystack.contains(needle),
                    format!("\"{}\" did not contain \"{}\"", haystack, needle)
                );
            } else {
                panic!("should have failed comm_r_star to Fr32 conversion");
            }
        }
    }

    #[test]
    fn test_verify_post_fr32_validation() {
        let not_convertible_to_fr_bytes = [255; 32];
        let out = bytes_into_fr::<Bls12>(&not_convertible_to_fr_bytes);
        assert!(out.is_err(), "tripwire");

        let result = verify_post(
            PoStConfig(SectorSize(TEST_SECTOR_SIZE), PoStProofPartitions(2)),
            vec![not_convertible_to_fr_bytes],
            [0; 32],
            vec![[0; POST_SECTORS_COUNT * SINGLE_PARTITION_PROOF_LEN].to_vec()],
            vec![],
        );

        if let Err(err) = result {
            let needle = "could not transform comm_r into Fr32";
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
        let sector_size = TEST_SECTOR_SIZE;

        let number_of_bytes_in_piece =
            UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size.clone()));

        let piece_bytes: Vec<u8> = (0..number_of_bytes_in_piece.0)
            .map(|_| rand::random::<u8>())
            .collect();

        let mut piece_file = NamedTempFile::new()?;
        piece_file.write_all(&piece_bytes)?;
        piece_file.seek(SeekFrom::Start(0))?;

        let comm_p = generate_piece_commitment(&piece_file.path(), number_of_bytes_in_piece)?;

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
            &[0; 31],
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
