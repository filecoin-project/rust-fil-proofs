use std::iter::repeat;
use std::iter::repeat_with;

use crate::api::{ChallengeSeed, Commitment};
use crate::constants::POST_SECTORS_COUNT;
use crate::error;
use crate::types::PoStConfig;

pub struct GeneratePoStDynamicSectorsCountInput {
    pub post_config: PoStConfig,
    pub challenge_seed: ChallengeSeed,
    pub input_parts: Vec<(Option<String>, Commitment)>,
}

pub struct GeneratePoStFixedSectorsCountInput {
    pub post_config: PoStConfig,
    pub challenge_seed: ChallengeSeed,
    pub input_parts: [(Option<String>, Commitment); POST_SECTORS_COUNT],
}

pub struct VerifyPoStDynamicSectorsCountInput {
    pub post_config: PoStConfig,
    pub comm_rs: Vec<Commitment>,
    pub challenge_seed: ChallengeSeed,
    pub proofs: Vec<Vec<u8>>,
    pub faults: Vec<u64>,
}

pub struct VerifyPoStFixedSectorsCountInput {
    pub post_config: PoStConfig,
    pub comm_rs: [Commitment; POST_SECTORS_COUNT],
    pub challenge_seed: ChallengeSeed,
    pub proof: Vec<u8>,
    pub faults: Vec<u64>,
}

pub struct GeneratePoStDynamicSectorsCountOutput {
    pub proofs: Vec<Vec<u8>>,
    pub faults: Vec<u64>,
}

pub struct GeneratePoStFixedSectorsCountOutput {
    pub proof: Vec<u8>,
    pub faults: Vec<u64>,
}

pub struct VerifyPoStDynamicSectorsCountOutput {
    pub is_valid: bool,
}

pub struct VerifyPoStFixedSectorsCountOutput {
    pub is_valid: bool,
}

/// Maps inputs for a single dynamic sectors-count PoSt generation operation to
/// a vector of PoSt generation inputs for fixed sectors-count.
///
pub fn generate_post_spread_input(
    dynamic: GeneratePoStDynamicSectorsCountInput,
) -> Vec<GeneratePoStFixedSectorsCountInput> {
    let mut fixed: Vec<GeneratePoStFixedSectorsCountInput> = vec![];

    let chunks = dynamic.input_parts.chunks_exact(POST_SECTORS_COUNT);

    let remainder = chunks.remainder();

    for chunk in chunks {
        let mut input_parts: [(Option<String>, Commitment); POST_SECTORS_COUNT] =
            array![(None, [0u8;32]); POST_SECTORS_COUNT];

        for (i, input_part) in chunk.iter().cloned().enumerate() {
            input_parts[i] = input_part
        }

        fixed.push(GeneratePoStFixedSectorsCountInput {
            post_config: dynamic.post_config,
            challenge_seed: dynamic.challenge_seed,
            input_parts,
        });
    }

    if !remainder.is_empty() {
        let mut input_parts: [(Option<String>, Commitment); POST_SECTORS_COUNT] =
            array![(None, [0u8;32]); POST_SECTORS_COUNT];

        // This commitment duplicating logic might need to be revisited. For
        // now, we duplicate the last commitment until LEN(COMM_R) divides
        // evenly by POST_SECTORS_COUNT.
        let iter_with_idx = remainder
            .iter()
            .cloned()
            .chain(repeat_with(|| remainder[remainder.len() - 1].clone()))
            .take(POST_SECTORS_COUNT)
            .enumerate();

        for (i, input_part) in iter_with_idx {
            input_parts[i] = input_part;
        }

        fixed.push(GeneratePoStFixedSectorsCountInput {
            post_config: dynamic.post_config,
            challenge_seed: dynamic.challenge_seed,
            input_parts,
        });
    }

    fixed
}

/// Collapses return values from multiple fixed sectors-count PoSt generation
/// operations into a single return value for dynamic sector count. This
/// function discards any faults reported for duplicated CommRs.
///
pub fn generate_post_collect_output(
    orig_comm_rs_len: usize,
    xs: Vec<error::Result<GeneratePoStFixedSectorsCountOutput>>,
) -> error::Result<GeneratePoStDynamicSectorsCountOutput> {
    let z = if xs.is_empty() {
        Err(format_err!("input vector must not be empty"))
    } else {
        Ok(GeneratePoStDynamicSectorsCountOutput {
            proofs: Vec::new(),
            faults: Vec::new(),
        })
    };

    xs.into_iter()
        .enumerate()
        .fold(z, |acc, (i, item)| {
            acc.and_then(|d1| {
                item.map(|d2| GeneratePoStDynamicSectorsCountOutput {
                    proofs: [d1.proofs, vec![d2.proof]].concat(),
                    faults: [
                        d1.faults,
                        d2.faults
                            .iter()
                            .map(|fault| ((i as u64) * POST_SECTORS_COUNT as u64) + fault)
                            .collect(),
                    ]
                    .concat(),
                })
            })
        })
        .map(|dynamic| GeneratePoStDynamicSectorsCountOutput {
            proofs: dynamic.proofs,
            faults: dynamic.faults.into_iter().take(orig_comm_rs_len).collect(),
        })
}

/// Maps inputs for a single dynamic sectors-count PoSt verify operation to a
/// vector of PoSt verify inputs for fixed sectors-count.
///
pub fn verify_post_spread_input(
    dynamic: VerifyPoStDynamicSectorsCountInput,
) -> error::Result<Vec<VerifyPoStFixedSectorsCountInput>> {
    let faults_len = dynamic.faults.len();
    let commrs_len = dynamic.comm_rs.len();
    let proofs_len = { dynamic.proofs.len() };
    let replicas_c = (commrs_len as f64 / POST_SECTORS_COUNT as f64).ceil() as usize;
    let faults_max = dynamic.faults.iter().max();

    if faults_len > commrs_len {
        return Err(format_err!(
            "LEN(faults) must <= LEN(comm_rs): {:?}, {:?}",
            faults_len,
            commrs_len
        ));
    }

    if proofs_len != replicas_c {
        return Err(format_err!(
            "LEN(proofs) must == CEIL(LEN(comm_rs)/POST_SECTORS_COUNT): {:?}, {:?}",
            proofs_len,
            replicas_c
        ));
    }

    if faults_max
        .map(|m| *m > commrs_len as u64 - 1)
        .unwrap_or(false)
    {
        return Err(format_err!(
            "MAX(faults) must <= LEN(comm_rs)-1: {:?}, {:?}",
            faults_max,
            commrs_len - 1
        ));
    }

    let mut fixed: Vec<VerifyPoStFixedSectorsCountInput> = vec![];

    let chunks = dynamic.comm_rs.chunks_exact(POST_SECTORS_COUNT);

    let remainder = chunks.remainder();

    // each POST_SECTORS_COUNT grouping of commitments maps to a single fixed
    // sectors-count PoSt verification call
    for (i, chunk) in chunks.enumerate() {
        let mut comm_rs: [Commitment; POST_SECTORS_COUNT] = [[0; 32]; POST_SECTORS_COUNT];
        for (i, comm_r) in chunk.iter().enumerate() {
            comm_rs[i] = *comm_r;
        }

        fixed.push(VerifyPoStFixedSectorsCountInput {
            post_config: dynamic.post_config,
            comm_rs,
            challenge_seed: dynamic.challenge_seed,
            proof: dynamic.proofs[i].clone(),
            faults: Vec::new(),
        })
    }

    // If we receive a number of comm_rs which does not divide evenly by
    // POST_SECTORS_COUNT, form a grouping of comm_rs which does divide
    // evenly by POST_SECTORS_COUNT by duplicating the last comm_r in the
    // group until LEN(comm_rs) == POST_SECTORS_COUNT.
    if !remainder.is_empty() {
        let mut comm_rs: [Commitment; POST_SECTORS_COUNT] = array![[0u8;32]; POST_SECTORS_COUNT];

        let iter_with_idx = remainder
            .iter()
            .cloned()
            .chain(repeat(remainder[remainder.len() - 1]))
            .take(POST_SECTORS_COUNT)
            .enumerate();

        for (i, comm_r) in iter_with_idx {
            comm_rs[i] = comm_r;
        }

        fixed.push(VerifyPoStFixedSectorsCountInput {
            post_config: dynamic.post_config,
            comm_rs,
            challenge_seed: dynamic.challenge_seed,
            proof: dynamic.proofs[proofs_len - 1].to_vec(),
            faults: Vec::new(),
        })
    }

    // Map the dynamic sectors count indices to the fixed sectors count indices.
    //
    // For example:
    //
    // POST_SECTORS_COUNT = 2
    //
    // dynamic = {
    //   comm_rs=[a, b, c, d, e, f, g, h]
    //   faults=[0, 1, 5, 6]
    // }
    //
    // fixed = [
    //   {comm_rs=[a, b] faults=[0, 1]}
    //   {comm_rs=[c, d] faults=[]}
    //   {comm_rs=[e, f] faults=[1]}
    //   {comm_rs=[g, h] faults=[0]}
    // ]
    for fault in dynamic.faults {
        let i = (fault as f64 / POST_SECTORS_COUNT as f64).floor();
        fixed[i as usize]
            .faults
            .push(fault % POST_SECTORS_COUNT as u64);
    }

    // If we had to duplicate commitments to make LEN(COMMITMENTS) ==
    // POST_SECTORS_COUNT and the thing we duplicated was faulty, ensure that
    // the duplicates are marked as faulty, too.
    //
    // For example:
    //
    // POST_SECTORS_COUNT = 2
    //
    // dynamic = {
    //   comm_rs=[a, b, c]
    //   faults=[2]
    // }
    //
    // fixed = [
    //   {comm_rs=[a, b] faults=[]}
    //   {comm_rs=[c, c] faults=[0, 1]}
    // ]
    if !remainder.is_empty() {
        let fixed_len = { fixed.len() };
        let remdr_len = { remainder.len() };

        let last_remainder_fault: Option<u64> =
            { fixed[fixed_len - 1].faults.get(remdr_len - 1).cloned() };

        if let Some(fault) = last_remainder_fault {
            for n in 0..(POST_SECTORS_COUNT - remdr_len) {
                fixed[fixed_len - 1].faults.push(1 + fault + n as u64);
            }
        }
    }

    Ok(fixed)
}

/// Collapses return values from multiple fixed sectors-count PoSt verify
/// operations into a single return value for dynamic sector count.
///
pub fn verify_post_collect_output(
    xs: Vec<error::Result<VerifyPoStFixedSectorsCountOutput>>,
) -> error::Result<VerifyPoStDynamicSectorsCountOutput> {
    let z = if xs.is_empty() {
        Err(format_err!("input vector must not be empty"))
    } else {
        Ok(VerifyPoStDynamicSectorsCountOutput { is_valid: true })
    };

    xs.into_iter().fold(z, |acc, item| {
        acc.and_then(|d1| {
            item.map(|d2| VerifyPoStDynamicSectorsCountOutput {
                is_valid: d1.is_valid && d2.is_valid,
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use crate::constants::TEST_SECTOR_SIZE;
    use crate::types::*;

    use super::*;

    const TEST_CONFIG: PoStConfig =
        PoStConfig(SectorSize(TEST_SECTOR_SIZE), PoStProofPartitions(1));

    fn fault_vecs(fixed: &[VerifyPoStFixedSectorsCountInput]) -> Vec<Option<Vec<u64>>> {
        let mut out: Vec<Option<Vec<u64>>> = Default::default();

        for input in fixed.iter() {
            if input.faults.is_empty() {
                out.push(None);
            } else {
                out.push(Some(input.faults.clone()));
            }
        }

        out
    }

    #[test]
    fn test_verify_post_fixed_to_dynamic_output() {
        let ok = |x| Ok(VerifyPoStFixedSectorsCountOutput { is_valid: x });

        // returns first error encountered (from head of vector)
        let result_a = verify_post_collect_output(vec![
            ok(false),
            Err(format_err!("alpha")),
            Err(format_err!("beta")),
        ]);

        let error_a = result_a.err().unwrap();
        assert_eq!(true, format!("{:?}", error_a).contains("alpha"));
        assert_eq!(false, format!("{:?}", error_a).contains("beta"));

        // verify all proofs as one (invalid)
        let result_b = verify_post_collect_output(vec![ok(false), ok(true)]).unwrap();
        assert_eq!(false, result_b.is_valid);

        // verify all proofs as one (valid)
        let result_c = verify_post_collect_output(vec![ok(true), ok(true)]).unwrap();
        assert_eq!(true, result_c.is_valid);
    }
}
