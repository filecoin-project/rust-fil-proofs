use crate::api::internal::ChallengeSeed;
use crate::api::internal::Commitment;
use crate::api::internal::POST_SECTORS_COUNT;
use crate::error;
use sector_base::api::bytes_amount::PaddedBytesAmount;
use std::iter::repeat;
use std::iter::repeat_with;

pub struct GeneratePoStDynamicSectorsCountInput {
    pub sector_bytes: PaddedBytesAmount,
    pub challenge_seed: ChallengeSeed,
    pub input_parts: Vec<(Option<String>, Commitment)>,
}

pub struct GeneratePoStFixedSectorsCountInput {
    pub sector_bytes: PaddedBytesAmount,
    pub challenge_seed: ChallengeSeed,
    pub input_parts: [(Option<String>, Commitment); POST_SECTORS_COUNT],
}

pub struct VerifyPoStDynamicSectorsCountInput {
    pub sector_bytes: PaddedBytesAmount,
    pub comm_rs: Vec<Commitment>,
    pub challenge_seed: ChallengeSeed,
    pub proofs: Vec<[u8; 192]>,
    pub faults: Vec<u64>,
}

pub struct VerifyPoStFixedSectorsCountInput {
    pub sector_bytes: PaddedBytesAmount,
    pub comm_rs: [Commitment; POST_SECTORS_COUNT],
    pub challenge_seed: ChallengeSeed,
    pub proof: [u8; 192],
    pub faults: Vec<u64>,
}

pub struct GeneratePoStDynamicSectorsCountOutput {
    pub proofs: Vec<[u8; 192]>,
    pub faults: Vec<u64>,
}

pub struct GeneratePoStFixedSectorsCountOutput {
    pub proof: [u8; 192],
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
            Default::default();

        for (i, input_part) in chunk.iter().cloned().enumerate() {
            input_parts[i] = input_part
        }

        fixed.push(GeneratePoStFixedSectorsCountInput {
            sector_bytes: dynamic.sector_bytes,
            challenge_seed: dynamic.challenge_seed,
            input_parts,
        });
    }

    if !remainder.is_empty() {
        let mut input_parts: [(Option<String>, Commitment); POST_SECTORS_COUNT] =
            Default::default();

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
            sector_bytes: dynamic.sector_bytes,
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
    let proofs_len = dynamic.proofs.len();
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
            sector_bytes: dynamic.sector_bytes,
            comm_rs,
            challenge_seed: dynamic.challenge_seed,
            proof: dynamic.proofs[i],
            faults: Vec::new(),
        })
    }

    // If we receive a number of comm_rs which does not divide evenly by
    // POST_SECTORS_COUNT, form a grouping of comm_rs which does divide
    // evenly by POST_SECTORS_COUNT by duplicating the last comm_r in the
    // group until LEN(comm_rs) == POST_SECTORS_COUNT.
    if !remainder.is_empty() {
        let mut comm_rs: [Commitment; POST_SECTORS_COUNT] = Default::default();

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
            sector_bytes: dynamic.sector_bytes,
            comm_rs,
            challenge_seed: dynamic.challenge_seed,
            proof: dynamic.proofs[proofs_len - 1],
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
    use super::*;

    fn sector_access_flattened(fixed: &[GeneratePoStFixedSectorsCountInput]) -> Vec<&String> {
        fixed
            .iter()
            .flat_map(|x| x.input_parts.iter().flat_map(|(x, _)| x.iter()))
            .collect()
    }

    fn comm_rs_flattened(fixed: &[VerifyPoStFixedSectorsCountInput]) -> Vec<&[u8; 32]> {
        fixed.iter().flat_map(|x| x.comm_rs.iter()).collect()
    }

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
    fn test_generate_post_dynamic_to_fixed_input() {
        let dynamic_a = GeneratePoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            challenge_seed: [0; 32],
            input_parts: vec![],
        };

        let dynamic_b = GeneratePoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            challenge_seed: [0; 32],
            input_parts: vec![(Some("a".to_string()), [0; 32])],
        };

        let dynamic_c = GeneratePoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            challenge_seed: [0; 32],
            input_parts: vec![
                (Some("a".to_string()), [0; 32]),
                (Some("b".to_string()), [0; 32]),
            ],
        };

        let dynamic_d = GeneratePoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            challenge_seed: [0; 32],
            input_parts: vec![
                (Some("a".to_string()), [0; 32]),
                (Some("b".to_string()), [0; 32]),
                (Some("c".to_string()), [0; 32]),
            ],
        };

        let fixed_a = generate_post_spread_input(dynamic_a);
        let fixed_b = generate_post_spread_input(dynamic_b);
        let fixed_c = generate_post_spread_input(dynamic_c);
        let fixed_d = generate_post_spread_input(dynamic_d);

        // sanity check
        assert_eq!(POST_SECTORS_COUNT, 2);

        // produces a number of fixed-count inputs equal to:
        //
        // CEIL(LEN(input_parts)/POST_SECTORS_COUNT)
        //
        assert_eq!(fixed_a.len(), 0);
        assert_eq!(fixed_b.len(), 1);
        assert_eq!(fixed_c.len(), 1);
        assert_eq!(fixed_d.len(), 2);

        // duplicates the final input if odd number of input_parts provided
        assert_eq!(0, sector_access_flattened(&fixed_a).len());
        assert_eq!(vec!["a", "a"], sector_access_flattened(&fixed_b));
        assert_eq!(vec!["a", "b"], sector_access_flattened(&fixed_c));
        assert_eq!(vec!["a", "b", "c", "c"], sector_access_flattened(&fixed_d));
    }

    #[test]
    fn test_verify_post_dynamic_to_fixed_input() {
        let proof_a = [0; 192];
        let proof_b = [1; 192];

        let comm_r_a = [0; 32];
        let comm_r_b = [1; 32];
        let comm_r_c = [2; 32];
        let comm_r_d = [3; 32];

        let dynamic_a = VerifyPoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            comm_rs: Vec::new(),
            challenge_seed: [0; 32],
            proofs: Vec::new(),
            faults: Vec::new(),
        };

        let dynamic_b = VerifyPoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            comm_rs: vec![comm_r_a.clone()],
            challenge_seed: [0; 32],
            proofs: vec![proof_a.clone()],
            faults: Vec::new(),
        };

        let dynamic_c = VerifyPoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            comm_rs: vec![comm_r_a.clone(), comm_r_b.clone()],
            challenge_seed: [0; 32],
            proofs: vec![proof_a.clone()],
            faults: Vec::new(),
        };

        let dynamic_d = VerifyPoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            comm_rs: vec![comm_r_a.clone(), comm_r_b.clone(), comm_r_c.clone()],
            challenge_seed: [0; 32],
            proofs: vec![proof_a.clone(), proof_b.clone()],
            faults: Vec::new(),
        };

        let fixed_a = verify_post_spread_input(dynamic_a).unwrap();
        let fixed_b = verify_post_spread_input(dynamic_b).unwrap();
        let fixed_c = verify_post_spread_input(dynamic_c).unwrap();
        let fixed_d = verify_post_spread_input(dynamic_d).unwrap();

        // sanity check
        assert_eq!(POST_SECTORS_COUNT, 2);

        // produces a number of fixed-count inputs equal to:
        //
        // CEIL(LEN(comm_rs)/POST_SECTORS_COUNT)
        //
        assert_eq!(fixed_a.len(), 0);
        assert_eq!(fixed_b.len(), 1);
        assert_eq!(fixed_c.len(), 1);
        assert_eq!(fixed_d.len(), 2);

        // duplicates the final input if odd number of comm_rs provided
        assert_eq!(0, comm_rs_flattened(&fixed_a).len());
        assert_eq!(vec![&comm_r_a, &comm_r_a], comm_rs_flattened(&fixed_b));
        assert_eq!(vec![&comm_r_a, &comm_r_b], comm_rs_flattened(&fixed_c));
        assert_eq!(
            vec![&comm_r_a, &comm_r_b, &comm_r_c, &comm_r_c],
            comm_rs_flattened(&fixed_d)
        );

        // LEN(proofs) must equal CEIL(LEN(comm_rs)/2))
        assert_eq!(
            true,
            verify_post_spread_input(VerifyPoStDynamicSectorsCountInput {
                sector_bytes: PaddedBytesAmount(1),
                comm_rs: vec![comm_r_a.clone()],
                challenge_seed: [0; 32],
                proofs: vec![proof_a.clone(), proof_b.clone()],
                faults: Vec::new()
            })
            .is_err()
        );

        // LEN(proofs) must equal CEIL(LEN(comm_rs)/2))
        assert_eq!(
            true,
            verify_post_spread_input(VerifyPoStDynamicSectorsCountInput {
                sector_bytes: PaddedBytesAmount(1),
                comm_rs: vec![comm_r_a.clone()],
                challenge_seed: [0; 32],
                proofs: vec![],
                faults: Vec::new()
            })
            .is_err()
        );

        // 0 <= MAX(faults) <= (LEN(comm_rs)-1)
        assert_eq!(
            true,
            verify_post_spread_input(VerifyPoStDynamicSectorsCountInput {
                sector_bytes: PaddedBytesAmount(1),
                comm_rs: vec![comm_r_a.clone()],
                challenge_seed: [0; 32],
                proofs: vec![proof_a.clone()],
                faults: vec![1]
            })
            .is_err()
        );

        // LEN(FAULTS) <= LEN(COMM_RS)
        assert_eq!(
            true,
            verify_post_spread_input(VerifyPoStDynamicSectorsCountInput {
                sector_bytes: PaddedBytesAmount(1),
                comm_rs: vec![comm_r_a.clone()],
                challenge_seed: [0; 32],
                proofs: vec![proof_a.clone()],
                faults: vec![0, 1]
            })
            .is_err()
        );

        // map dynamic sectors count indices to fixed count fault indices
        let fixed_e = verify_post_spread_input(VerifyPoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            comm_rs: vec![
                comm_r_a.clone(),
                comm_r_b.clone(),
                comm_r_c.clone(),
                comm_r_d.clone(),
            ],
            challenge_seed: [0; 32],
            proofs: vec![proof_a.clone(), proof_b.clone()],
            faults: vec![3],
        })
        .unwrap();

        assert_eq!(vec![None, Some(vec![1 as u64])], fault_vecs(&fixed_e));

        // ensure fault-values map to appropriate, duplicated comm_r
        let fixed_f = verify_post_spread_input(VerifyPoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            comm_rs: vec![comm_r_a.clone()],
            challenge_seed: [0; 32],
            proofs: vec![proof_a.clone()],
            faults: vec![0],
        })
        .unwrap();

        assert_eq!(vec![Some(vec![0 as u64, 1 as u64])], fault_vecs(&fixed_f));

        // ensure fault-values map to appropriate, duplicated comm_r
        //
        // explanation: faults=[3] corresponds to faults=[1] in the second fixed
        // count pair and faults=[] in the first
        let fixed_g = verify_post_spread_input(VerifyPoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            comm_rs: vec![
                comm_r_a.clone(),
                comm_r_b.clone(),
                comm_r_c.clone(),
                comm_r_d.clone(),
            ],
            challenge_seed: [0; 32],
            proofs: vec![proof_a.clone(), proof_b.clone()],
            faults: vec![3],
        })
        .unwrap();

        assert_eq!(vec![None, Some(vec![1 as u64])], fault_vecs(&fixed_g));

        // ensure fault-values map to appropriate, duplicated comm_r
        //
        // explanation: faults=[0,2] corresponds to faults[0] in the first pair
        // and faults[0, 1] in the second (because the third commitment was
        // duplicated
        let fixed_h = verify_post_spread_input(VerifyPoStDynamicSectorsCountInput {
            sector_bytes: PaddedBytesAmount(1),
            comm_rs: vec![comm_r_a.clone(), comm_r_b.clone(), comm_r_c.clone()],
            challenge_seed: [0; 32],
            proofs: vec![proof_a.clone(), proof_b.clone()],
            faults: vec![0, 2],
        })
        .unwrap();

        assert_eq!(
            vec![Some(vec![0 as u64]), Some(vec![0 as u64, 1 as u64])],
            fault_vecs(&fixed_h)
        );
    }

    #[test]
    fn test_generate_post_fixed_to_dynamic_output() {
        let fixed_a = GeneratePoStFixedSectorsCountOutput {
            proof: [0; 192],
            faults: vec![0, 1],
        };
        let fixed_b = GeneratePoStFixedSectorsCountOutput {
            proof: [0; 192],
            faults: vec![0, 1],
        };
        let fixed_c = GeneratePoStFixedSectorsCountOutput {
            proof: [1; 192],
            faults: vec![],
        };
        let fixed_d = GeneratePoStFixedSectorsCountOutput {
            proof: [2; 192],
            faults: vec![1],
        };
        let fixed_e = GeneratePoStFixedSectorsCountOutput {
            proof: [2; 192],
            faults: vec![0, 1],
        };

        // returns first error encountered (from head of vector)
        let result_a = generate_post_collect_output(
            6,
            vec![
                Ok(fixed_a),
                Err(format_err!("alpha")),
                Err(format_err!("beta")),
            ],
        );
        let error_a = result_a.err().unwrap();
        assert_eq!(true, format!("{:?}", error_a).contains("alpha"));
        assert_eq!(false, format!("{:?}", error_a).contains("beta"));

        // combines proofs into single vector
        let result_b =
            generate_post_collect_output(6, vec![Ok(fixed_b), Ok(fixed_c), Ok(fixed_d)]).unwrap();
        assert_eq!(0, result_b.proofs[0][0]);
        assert_eq!(1, result_b.proofs[1][0]);
        assert_eq!(2, result_b.proofs[2][0]);

        // transforms static sectors count faults-offsets to dynamic sectors
        // count equivalents
        assert_eq!(vec![0, 1, 5], result_b.faults);

        // drops any faults reported on duplicated replicas
        let result_b = generate_post_collect_output(1, vec![Ok(fixed_e)]).unwrap();

        assert_eq!(vec![0], result_b.faults);
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
