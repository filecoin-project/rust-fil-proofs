use std::marker::PhantomData;
use std::ops::AddAssign;

use bellperson::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack::pack_bits,
        num::AllocatedNum,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use blstrs::{Bls12, Scalar as Fr};
use ff::{Field, PrimeField};
use filecoin_hashers::{sha256::Sha256Hasher, HashFunction, Hasher};
use generic_array::typenum::Unsigned;
use storage_proofs_core::merkle::{
    BinaryMerkleTree, MerkleProof, MerkleProofTrait, MerkleTreeTrait,
};

use crate::{
    gadgets::{allocated_num_to_allocated_bits, por_no_challenge_input},
    utils::validate_tree_shape,
};

// Allowed sector-sizes, measured in number of nodes.
pub const ALLOWED_SECTOR_SIZES: [u64; 5] = [1 << 5, 1 << 18, 1 << 24, 1 << 30, 1 << 31];

pub type TreeD = BinaryMerkleTree<Sha256Hasher>;

// Returns the six `h` values allowed for the given sector-size. Each `h` value is a possible number
// of high bits taken from each generated challenge `c`. The circuit takes `h_select = 2^i` as a
// public input which is used to choose a value for the constant `h` via `h = hs[i]`.
pub fn hs(sector_nodes: usize) -> [usize; 6] {
    if sector_nodes == 1 << 5 {
        [1; 6]
    } else {
        [7, 8, 9, 10, 11, 12]
    }
}

pub struct PublicParams {
    // The number of challenges per partition proof.
    challenges: usize,
    // The number of bits per challenge, i.e. `challenge_bits = log2(sector_nodes)`.
    challenge_bits: usize,
    // The number of challenges derived from a single digest.
    challenges_per_digest: usize,
    // The number of digests required to generate `challenges` number of challenges.
    digests: usize,
}

impl PublicParams {
    pub fn from_sector_size(sector_bytes: u64) -> Self {
        assert!(ALLOWED_SECTOR_SIZES
            .iter()
            .any(|allowed_nodes| allowed_nodes << 5 == sector_bytes));
        // The sector-size measured in 32-byte nodes.
        let sector_nodes = sector_bytes as usize >> 5;
        let challenges = if sector_nodes == 1 << 5 { 10 } else { 2200 };
        // `sector_nodes` is guaranteed to be a power of two.
        let challenge_bits = sector_nodes.trailing_zeros() as usize;
        let challenges_per_digest = Fr::CAPACITY as usize / challenge_bits;
        let digests = (challenges as f32 / challenges_per_digest as f32).ceil() as usize;
        PublicParams {
            challenges,
            challenge_bits,
            challenges_per_digest,
            digests,
        }
    }
}

pub struct PublicInputs<TreeR: MerkleTreeTrait> {
    pub comm_r_old: <TreeR::Hasher as Hasher>::Domain,
    pub comm_d_new: <<TreeD as MerkleTreeTrait>::Hasher as Hasher>::Domain,
    pub comm_r_new: <TreeR::Hasher as Hasher>::Domain,
    pub h_select: u64,
    pub _tree_r: PhantomData<TreeR>,
}

impl<TreeR: MerkleTreeTrait> PublicInputs<TreeR> {
    pub fn to_vec(self) -> Vec<Fr> {
        vec![
            self.comm_r_old.into(),
            self.comm_d_new.into(),
            self.comm_r_new.into(),
            Fr::from(self.h_select),
        ]
    }
}

// Three Merkle proofs (in TreeROld, TreeDNew, and TreeRNew) are generated for each challenge.
pub struct ChallengeProof<TreeR: MerkleTreeTrait> {
    r_old: MerkleProof<TreeR::Hasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
    // TreeD is assumed to be a binary tree (non-compound tree).
    d_new: MerkleProof<<TreeD as MerkleTreeTrait>::Hasher, <TreeD as MerkleTreeTrait>::Arity>,
    r_new: MerkleProof<TreeR::Hasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
}

// The `ChallengeProof` values to allocate in the constraint-system. The verifier sets these
// values to `None` because they are part of the prover's witness; the prover must provide values
// for each field.
pub struct ChallengeProofOptions<TreeR: MerkleTreeTrait> {
    // TreeROld
    leaf_r_old: Option<Fr>,
    path_r_old: Vec<Vec<Option<Fr>>>,
    // TreeDNew
    leaf_d_new: Option<Fr>,
    path_d_new: Vec<Vec<Option<Fr>>>,
    // TreeRNew
    leaf_r_new: Option<Fr>,
    path_r_new: Vec<Vec<Option<Fr>>>,
    _tree_r: PhantomData<TreeR>,
}

impl<TreeR: MerkleTreeTrait> ChallengeProofOptions<TreeR> {
    pub fn from_challenge_proof(challenge_proof: &ChallengeProof<TreeR>) -> Self {
        let leaf_r_old = Some(challenge_proof.r_old.leaf().into());
        let path_r_old: Vec<Vec<Option<Fr>>> = challenge_proof
            .r_old
            .path()
            .iter()
            .map(|(siblings, _insert_index)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        let leaf_d_new = Some(challenge_proof.d_new.leaf().into());
        let path_d_new: Vec<Vec<Option<Fr>>> = challenge_proof
            .d_new
            .path()
            .iter()
            .map(|(siblings, _insert_index)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        let leaf_r_new = Some(challenge_proof.r_new.leaf().into());
        let path_r_new: Vec<Vec<Option<Fr>>> = challenge_proof
            .r_new
            .path()
            .iter()
            .map(|(siblings, _insert_index)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        ChallengeProofOptions {
            leaf_r_old,
            path_r_old,
            leaf_d_new,
            path_d_new,
            leaf_r_new,
            path_r_new,
            _tree_r: PhantomData,
        }
    }

    pub fn blank(path_len_d: usize, base_path_len_r: usize) -> Self {
        // TreeD is assumed to be a binary tree (non-compound tree).
        let blank_path_d = vec![vec![None]; path_len_d];

        let mut blank_path_r = vec![vec![None; TreeR::Arity::to_usize() - 1]; base_path_len_r];
        let tree_r_sub_arity = TreeR::SubTreeArity::to_usize();
        if tree_r_sub_arity > 0 {
            blank_path_r.push(vec![None; tree_r_sub_arity - 1]);
        }
        let tree_r_top_arity = TreeR::TopTreeArity::to_usize();
        if tree_r_top_arity > 0 {
            blank_path_r.push(vec![None; tree_r_top_arity - 1]);
        }

        ChallengeProofOptions {
            leaf_d_new: None,
            path_d_new: blank_path_d,
            leaf_r_old: None,
            path_r_old: blank_path_r.clone(),
            leaf_r_new: None,
            path_r_new: blank_path_r,
            _tree_r: PhantomData,
        }
    }
}

pub struct EmptySectorUpdateCircuit<TreeR: MerkleTreeTrait> {
    pub_params: PublicParams,

    // Public-inputs
    comm_r_old: Option<Fr>,
    comm_d_new: Option<Fr>,
    comm_r_new: Option<Fr>,
    h_select: Option<Fr>,

    // Private-inputs
    comm_c: Option<Fr>,
    comm_r_last_old: Option<Fr>,
    comm_r_last_new: Option<Fr>,
    challenge_proofs: Option<Vec<ChallengeProof<TreeR>>>,
}

impl<TreeR: MerkleTreeTrait> Circuit<Bls12> for EmptySectorUpdateCircuit<TreeR> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let EmptySectorUpdateCircuit {
            pub_params,
            comm_d_new,
            comm_r_old,
            comm_r_new,
            h_select,
            comm_c,
            comm_r_last_old,
            comm_r_last_new,
            challenge_proofs,
            ..
        } = self;

        let PublicParams {
            challenges,
            challenge_bits,
            challenges_per_digest,
            digests,
            ..
        } = pub_params;

        let sector_nodes = 1 << challenge_bits;
        let hs = hs(sector_nodes);
        let path_len_d = (sector_nodes as f32).log2() as usize;
        // We do not validate `TreeD`'s shape because every sector-size in `ALLOWED_SECTOR_SIZES`
        // is valid for `TreeD`.
        validate_tree_shape::<TreeR>(sector_nodes);
        let base_path_len_r = {
            let base_arity = TreeR::Arity::to_usize();
            let sub_arity = TreeR::SubTreeArity::to_usize();
            let top_arity = TreeR::TopTreeArity::to_usize();
            let mut leafs_per_base_tree = sector_nodes;
            // We know that these integer divisions will not produce rounding errors because we have
            // validated the `TreeR`'s shape.
            if top_arity > 0 {
                leafs_per_base_tree /= top_arity;
            }
            if sub_arity > 0 {
                leafs_per_base_tree /= sub_arity;
            }
            (leafs_per_base_tree as f32).log(base_arity as f32) as usize
        };

        // Assert that `h_select` is valid. HSelect should be a uint whose binary representation has
        // exactly 1 of its first 6 bits set.
        if let Some(h_select) = h_select {
            assert!((0..6).any(|i| Fr::from(1u64 << i) == h_select));
        }

        if let Some(challenge_proofs) = challenge_proofs.as_ref() {
            assert_eq!(challenge_proofs.len(), challenges);
        }

        // Allocate public-inputs

        let comm_r_old = AllocatedNum::alloc(cs.namespace(|| "comm_r_old"), || {
            comm_r_old.ok_or(SynthesisError::AssignmentMissing)
        })?;
        comm_r_old.inputize(cs.namespace(|| "comm_r_old_input"))?;

        let comm_d_new = AllocatedNum::alloc(cs.namespace(|| "comm_d_new"), || {
            comm_d_new.ok_or(SynthesisError::AssignmentMissing)
        })?;
        comm_d_new.inputize(cs.namespace(|| "comm_d_new_input"))?;

        let comm_r_new = AllocatedNum::alloc(cs.namespace(|| "comm_r_new"), || {
            comm_r_new.ok_or(SynthesisError::AssignmentMissing)
        })?;
        comm_r_new.inputize(cs.namespace(|| "comm_r_new_input"))?;

        let h_select = AllocatedNum::alloc(cs.namespace(|| "h_select"), || {
            h_select.ok_or(SynthesisError::AssignmentMissing)
        })?;
        h_select.inputize(cs.namespace(|| "h_select_input"))?;

        // The 6 least-significant bits of `h_select`'s binary representation.
        let h_select_bits: Vec<AllocatedBit> =
            allocated_num_to_allocated_bits(cs.namespace(|| "h_select_bits"), &h_select)?
                .into_iter()
                .take(6)
                .collect();

        // phi = H(comm_d_new || comm_r_old)
        let phi = <TreeR::Hasher as Hasher>::Function::hash2_circuit(
            cs.namespace(|| "phi"),
            &comm_d_new,
            &comm_r_old,
        )?;

        // Allocate private-inputs

        let comm_c = AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
            comm_c.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let comm_r_last_old = AllocatedNum::alloc(cs.namespace(|| "comm_r_last_old"), || {
            comm_r_last_old.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let comm_r_last_new = AllocatedNum::alloc(cs.namespace(|| "comm_r_last_new"), || {
            comm_r_last_new.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // TODO: do I need to calculate `comm_r_old_calc` using `comm_c` and `comm_r_last_old`?

        // Assert that `comm_r_last_old` is valid: comm_r_old == H(comm_c || comm_r_last_old).
        let comm_r_old_calc = <TreeR::Hasher as Hasher>::Function::hash2_circuit(
            cs.namespace(|| "comm_r_old_calc"),
            &comm_c,
            &comm_r_last_old,
        )?;
        cs.enforce(
            || "enforce comm_r_old_calc == comm_r_old",
            |lc| lc + comm_r_old_calc.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + comm_r_old.get_variable(),
        );

        // Assert that `comm_r_last_new` is valid: comm_r_new == H(comm_c || comm_r_last_new).
        let comm_r_new_calc = <TreeR::Hasher as Hasher>::Function::hash2_circuit(
            cs.namespace(|| "comm_r_new_calc"),
            &comm_c,
            &comm_r_last_new,
        )?;
        cs.enforce(
            || "enforce comm_r_new_calc == comm_r_new",
            |lc| lc + comm_r_new_calc.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + comm_r_new.get_variable(),
        );

        // The number of challenges generated; used to annotate the constraint-system.
        let mut c_index = 0;

        for j in 0..digests {
            let digest_bits = challenges_digest::<TreeR::Hasher, _>(
                cs.namespace(|| format!("generate digest_{}", j)),
                &comm_r_new,
                j,
            )?;

            // Split `digest_bits` into each challenge's binary representation `c_bits`.
            for i in 0..challenges_per_digest {
                let c_bits = &digest_bits[i * challenge_bits..(i + 1) * challenge_bits];

                // `pack_bits` gadget takes `Boolean`'s, not `AllocatedBit`'s.
                let c_bits_boolean: Vec<Boolean> = c_bits.iter().cloned().map(Into::into).collect();

                // For each `h in hs`, right-shift `c_bits` by `h`, then scale each shifted value by
                // the corresponding bit in `h_select_bits`, finally summate the scaled shifted
                // values resulting in `c` shifted by the selected `h`.
                let mut c_shifted_and_zeros = Vec::<AllocatedNum<Bls12>>::with_capacity(6);

                for (k, (h, h_select_bit)) in hs.iter().zip(h_select_bits.iter()).enumerate() {
                    // Get the `h` most-significant bits from `c_bits` and allocate them as a single
                    // field element.
                    let c_shifted = pack_bits(
                        // We need to include `k` in the namespace name because some sector-sizes
                        // have duplicate values of `h` in `hs`, thus if we only included `h`
                        // (without `k`) in the namespace name we would get a namespace collision.
                        cs.namespace(|| format!("c_{} pack high bits (h={}, k={})", c_index, h, k)),
                        &c_bits_boolean[challenge_bits - h..],
                    )?;

                    // Multiply `c_shifted * h_select_bit`
                    let c_shifted_or_zero = AllocatedNum::alloc(
                        // We need to include `k` in the namespace name (see above comment).
                        cs.namespace(|| {
                            format!("c_{} packed high bits or zero (h={}, k={})", c_index, h, k,)
                        }),
                        || {
                            let h_select_bit = h_select_bit
                                .get_value()
                                .ok_or(SynthesisError::AssignmentMissing)?;

                            let c_shifted = c_shifted
                                .get_value()
                                .ok_or(SynthesisError::AssignmentMissing)?;

                            if h_select_bit {
                                Ok(c_shifted)
                            } else {
                                Ok(Fr::zero())
                            }
                        },
                    )?;
                    cs.enforce(
                        || {
                            format!(
                                "c_{} packed high bits * h_select_bit (h={}, k={})",
                                c_index, h, k
                            )
                        },
                        |lc| lc + c_shifted.get_variable(),
                        |lc| lc + h_select_bit.get_variable(),
                        |lc| lc + c_shifted_or_zero.get_variable(),
                    );

                    c_shifted_and_zeros.push(c_shifted_or_zero);
                }

                // Summate the 6 scaled shifted values; because 5 of the 6 `h_select_bits` are zero
                // (and 1 of the 6 is one) this sum equals the `c_shifted` value chosen via
                // `h_select`.
                let c_shifted = AllocatedNum::alloc(
                    cs.namespace(|| format!("c_{} selected high bits", c_index)),
                    || {
                        let mut sum = c_shifted_and_zeros[0]
                            .get_value()
                            .ok_or(SynthesisError::AssignmentMissing)?;
                        for c_shifted_or_zero in &c_shifted_and_zeros[1..] {
                            sum.add_assign(
                                &c_shifted_or_zero
                                    .get_value()
                                    .ok_or(SynthesisError::AssignmentMissing)?,
                            );
                        }
                        Ok(sum)
                    },
                )?;
                cs.enforce(
                    || {
                        format!(
                            "c_{} selected high bits == dot(c_shifteds, h_select_bits)",
                            c_index,
                        )
                    },
                    |lc| {
                        lc + c_shifted_and_zeros[0].get_variable()
                            + c_shifted_and_zeros[1].get_variable()
                            + c_shifted_and_zeros[2].get_variable()
                            + c_shifted_and_zeros[3].get_variable()
                            + c_shifted_and_zeros[4].get_variable()
                            + c_shifted_and_zeros[5].get_variable()
                    },
                    |lc| lc + CS::one(),
                    |lc| lc + c_shifted.get_variable(),
                );

                let rho = <TreeR::Hasher as Hasher>::Function::hash2_circuit(
                    cs.namespace(|| format!("rho_{}", c_index)),
                    &phi,
                    &c_shifted,
                )?;

                // Validate this challenge's Merkle proofs.

                let challenge_proof_opts = if let Some(challenge_proofs) = challenge_proofs.as_ref()
                {
                    let challenge_proof = &challenge_proofs[c_index];
                    ChallengeProofOptions::<TreeR>::from_challenge_proof(challenge_proof)
                } else {
                    ChallengeProofOptions::<TreeR>::blank(path_len_d, base_path_len_r)
                };

                let leaf_d_new = AllocatedNum::alloc(
                    cs.namespace(|| format!("c_{} leaf_d_new", c_index)),
                    || {
                        challenge_proof_opts
                            .leaf_d_new
                            .ok_or(SynthesisError::AssignmentMissing)
                    },
                )?;

                let mut path_d_new: Vec<Vec<AllocatedNum<Bls12>>> = vec![];
                for (tree_row, siblings) in challenge_proof_opts.path_d_new.iter().enumerate() {
                    let siblings = siblings
                        .iter()
                        .enumerate()
                        .map(|(sibling_index, sibling)| {
                            AllocatedNum::alloc(
                                cs.namespace(|| {
                                    format!(
                                        "c_{} proof_d_new sibling (tree_row={}, sib_{})",
                                        c_index, tree_row, sibling_index,
                                    )
                                }),
                                || sibling.ok_or(SynthesisError::AssignmentMissing),
                            )
                        })
                        .collect::<Result<Vec<AllocatedNum<Bls12>>, SynthesisError>>()?;
                    path_d_new.push(siblings);
                }

                por_no_challenge_input::<TreeD, _>(
                    cs.namespace(|| format!("c_{} tree_d_new por", c_index)),
                    c_bits.to_vec(),
                    leaf_d_new.clone(),
                    path_d_new,
                    comm_d_new.clone(),
                )?;

                let leaf_r_old = AllocatedNum::alloc(
                    cs.namespace(|| format!("c_{} leaf_r_old", c_index)),
                    || {
                        challenge_proof_opts
                            .leaf_r_old
                            .ok_or(SynthesisError::AssignmentMissing)
                    },
                )?;

                let mut path_r_old: Vec<Vec<AllocatedNum<Bls12>>> = vec![];
                for (tree_row, siblings) in challenge_proof_opts.path_r_old.iter().enumerate() {
                    let siblings = siblings
                        .iter()
                        .enumerate()
                        .map(|(sibling_index, sibling)| {
                            AllocatedNum::alloc(
                                cs.namespace(|| {
                                    format!(
                                        "c_{} proof_r_old sibling (tree_row={}, sib_{})",
                                        c_index, tree_row, sibling_index,
                                    )
                                }),
                                || sibling.ok_or(SynthesisError::AssignmentMissing),
                            )
                        })
                        .collect::<Result<Vec<AllocatedNum<Bls12>>, SynthesisError>>()?;
                    path_r_old.push(siblings);
                }

                por_no_challenge_input::<TreeR, _>(
                    cs.namespace(|| format!("c_{} tree_r_old por", c_index)),
                    c_bits.to_vec(),
                    leaf_r_old.clone(),
                    path_r_old,
                    comm_r_last_old.clone(),
                )?;

                // Assert that `label_r_new` is the correct labeling of the challenge:
                // label_r_new = label_r_old + label_d_new * rho

                let leaf_d_new_rho = leaf_d_new.mul(
                    cs.namespace(|| format!("c_{} label_d_new * rho", c_index)),
                    &rho,
                )?;

                let leaf_r_new = AllocatedNum::alloc(
                    cs.namespace(|| format!("c_{} leaf_r_new", c_index)),
                    || {
                        let mut sum = leaf_d_new_rho
                            .get_value()
                            .ok_or(SynthesisError::AssignmentMissing)?;
                        sum.add_assign(
                            &leaf_r_old
                                .get_value()
                                .ok_or(SynthesisError::AssignmentMissing)?,
                        );
                        Ok(sum)
                    },
                )?;

                cs.enforce(
                    || {
                        format!(
                            "c_{} label_r_new == label_d_new * rho + label_r_old",
                            c_index,
                        )
                    },
                    |lc| lc + leaf_d_new_rho.get_variable() + leaf_r_old.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + leaf_r_new.get_variable(),
                );

                // Sanity check that the challenge's provided TreeRNew label is equal to its
                // calculated label.
                if let Some(leaf_r_new) = leaf_r_new.get_value() {
                    assert_eq!(leaf_r_new, challenge_proof_opts.leaf_r_new.unwrap());
                }

                let mut path_r_new: Vec<Vec<AllocatedNum<Bls12>>> = vec![];
                for (tree_row, siblings) in challenge_proof_opts.path_r_new.iter().enumerate() {
                    let siblings = siblings
                        .iter()
                        .enumerate()
                        .map(|(sibling_index, sibling)| {
                            AllocatedNum::alloc(
                                cs.namespace(|| {
                                    format!(
                                        "c_{} proof_r_new sibling (tree_row={}, sib_{})",
                                        c_index, tree_row, sibling_index,
                                    )
                                }),
                                || sibling.ok_or(SynthesisError::AssignmentMissing),
                            )
                        })
                        .collect::<Result<Vec<AllocatedNum<Bls12>>, SynthesisError>>()?;
                    path_r_new.push(siblings);
                }

                por_no_challenge_input::<TreeR, _>(
                    cs.namespace(|| format!("c_{} tree_r_new por", c_index)),
                    c_bits.to_vec(),
                    leaf_r_new,
                    path_r_new,
                    comm_r_last_new.clone(),
                )?;

                c_index += 1;
                if c_index == challenges {
                    break;
                }
            }
        }

        Ok(())
    }
}

// Computes `digest_j = H(comm_r_new || j)` returns `digest` as bits.
pub fn challenges_digest<H, CS>(
    mut cs: CS,
    comm_r_new: &AllocatedNum<Bls12>,
    j: usize,
) -> Result<Vec<AllocatedBit>, SynthesisError>
where
    H: Hasher,
    CS: ConstraintSystem<Bls12>,
{
    let j_str = j.to_string();

    // Allocate digest index
    let j = AllocatedNum::alloc(cs.namespace(|| format!("j_{}", j_str)), || {
        Ok(Fr::from(j as u64))
    })?;

    // digest = H(comm_r_new || j)
    let digest = H::Function::hash2_circuit(
        cs.namespace(|| format!("digest_{}", j_str)),
        &comm_r_new,
        &j,
    )?;

    // Allocate `digest` as `Fr::NUM_BITS` number of `AllocatedBits`'s.
    allocated_num_to_allocated_bits(cs.namespace(|| format!("digest_{}_bits", j_str)), &digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use filecoin_hashers::{
        poseidon::{PoseidonDomain, PoseidonHasher},
        sha256::Sha256Domain,
        Domain,
    };
    use generic_array::typenum::{U0, U4, U8};
    use merkletree::store::{DiskStore, StoreConfig};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        merkle::MerkleTreeWrapper, util::default_rows_to_discard, TEST_SEED,
    };
    use tempfile::tempdir;

    use crate::{encode::encode_new_replica, Challenges};

    const SECTOR_NODES: usize = 1 << 5;
    const SECTOR_BYTES: usize = SECTOR_NODES << 5;

    // Selects a value for `h` via `h = hs[0] = hs[log2(h_select)]`.
    const H_SELECT: u64 = 0b000001;

    // The number of high bits to take from each challenge; `h = hs[log2(h_select)]`.
    const H: usize = 1;

    type TreeR = MerkleTreeWrapper<PoseidonHasher, DiskStore<PoseidonDomain>, U8, U4, U0>;

    fn create_tree<Tree: MerkleTreeTrait>(
        labels: &[<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain],
        tmp_path: &Path,
        tree_name: &str,
    ) -> MerkleTreeWrapper<
        Tree::Hasher,
        Tree::Store,
        Tree::Arity,
        Tree::SubTreeArity,
        Tree::TopTreeArity,
    > {
        let sector_nodes = labels.len();
        validate_tree_shape::<Tree>(sector_nodes);

        let base_arity = Tree::Arity::to_usize();
        let sub_arity = Tree::SubTreeArity::to_usize();
        let top_arity = Tree::TopTreeArity::to_usize();

        // Create a single base-tree, a single sub-tree (out of base-trees), or a single top-tree
        // (out of sub-trees, each made of base-trees).
        if sub_arity == 0 && top_arity == 0 {
            let config = StoreConfig::new(
                tmp_path,
                tree_name.to_string(),
                default_rows_to_discard(sector_nodes, base_arity),
            );
            let leafs = labels.iter().copied().map(Ok);
            MerkleTreeWrapper::try_from_iter_with_config(leafs, config)
                .expect(&format!("failed to create non-compound-tree {}", tree_name))
        } else if top_arity == 0 {
            let base_tree_count = sub_arity;
            let leafs_per_base_tree = sector_nodes / base_tree_count;
            let base_rows_to_discard = default_rows_to_discard(leafs_per_base_tree, base_arity);

            let base_trees: Vec<MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity>> = (0
                ..base_tree_count)
                .map(|i| {
                    let leafs = labels[i * leafs_per_base_tree..(i + 1) * leafs_per_base_tree]
                        .iter()
                        .copied()
                        .map(Ok);
                    let config = StoreConfig::new(
                        tmp_path,
                        format!("{}-base-{}", tree_name, i),
                        base_rows_to_discard,
                    );
                    MerkleTreeWrapper::try_from_iter_with_config(leafs, config)
                        .expect(&format!("failed to create {} base-tree {}", tree_name, i))
                })
                .collect();

            MerkleTreeWrapper::from_trees(base_trees)
                .expect(&format!("failed to create {} from base-trees", tree_name))
        } else {
            let base_tree_count = top_arity * sub_arity;
            let leafs_per_base_tree = sector_nodes / base_tree_count;
            let base_rows_to_discard = default_rows_to_discard(leafs_per_base_tree, base_arity);

            let sub_tree_count = top_arity;
            let base_trees_per_sub_tree = sub_arity;

            let sub_trees: Vec<
                MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity, Tree::SubTreeArity>,
            > = (0..sub_tree_count)
                .map(|sub_index| {
                    let first_sub_leaf = sub_index * base_trees_per_sub_tree * leafs_per_base_tree;
                    let base_trees: Vec<MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity>> =
                        (0..base_trees_per_sub_tree)
                            .map(|base_index| {
                                let first_base_leaf =
                                    first_sub_leaf + base_index * leafs_per_base_tree;
                                let leafs = labels
                                    [first_base_leaf..first_base_leaf + leafs_per_base_tree]
                                    .iter()
                                    .copied()
                                    .map(Ok);
                                let config = StoreConfig::new(
                                    tmp_path,
                                    format!("{}-sub-{}-base-{}", tree_name, sub_index, base_index),
                                    base_rows_to_discard,
                                );
                                MerkleTreeWrapper::try_from_iter_with_config(leafs, config).expect(
                                    &format!(
                                        "failed to create {} sub-tree {} base-tree {}",
                                        tree_name, sub_index, base_index,
                                    ),
                                )
                            })
                            .collect();
                    MerkleTreeWrapper::from_trees(base_trees).expect(&format!(
                        "failed to create {} sub-tree {} from base-trees",
                        tree_name, sub_index,
                    ))
                })
                .collect();

            MerkleTreeWrapper::from_sub_trees(sub_trees)
                .expect(&format!("failed to create {} from sub-trees", tree_name))
        }
    }

    #[test]
    fn test_empty_sector_update_circuit() {
        let mut rng = &mut XorShiftRng::from_seed(TEST_SEED);

        // Merkle tree storage directory.
        let tmp_dir = tempdir().unwrap();
        let tmp_path = tmp_dir.path();

        // Create a random TreeROld
        let labels_r_old: Vec<PoseidonDomain> = (0..SECTOR_NODES)
            .map(|_| PoseidonDomain::random(&mut rng))
            .collect();
        let tree_r_old = create_tree::<TreeR>(&labels_r_old, tmp_path, "tree-r-old");
        let comm_r_last_old = tree_r_old.root();
        let comm_c = <PoseidonHasher as Hasher>::Domain::random(&mut rng);
        let comm_r_old = <PoseidonHasher as Hasher>::Function::hash2(&comm_c, &comm_r_last_old);

        // Create a random TreeDNew
        let labels_d_new: Vec<Sha256Domain> = (0..SECTOR_NODES)
            .map(|_| Sha256Domain::random(&mut rng))
            .collect();
        let tree_d_new = create_tree::<TreeD>(&labels_d_new, tmp_path, "tree-d-new");
        let comm_d_new = tree_d_new.root();

        // phi = H(comm_d_new || comm_r_old)
        let phi =
            <PoseidonHasher as Hasher>::Function::hash2(&Fr::from(comm_d_new).into(), &comm_r_old);

        // Encode `labels_d_new` into `labels_r_new` and create TreeRNew
        let labels_r_new =
            encode_new_replica::<PoseidonHasher>(&labels_r_old, &labels_d_new, &phi, H);
        let tree_r_new = create_tree::<TreeR>(&labels_r_new, tmp_path, "tree-r-new");
        let comm_r_last_new = tree_r_new.root();
        let comm_r_new = <PoseidonHasher as Hasher>::Function::hash2(&comm_c, &comm_r_last_new);

        let pub_params = PublicParams::from_sector_size(SECTOR_BYTES as u64);

        // Prover generates 3 Merkle proofs for each challenge
        let challenge_proofs: Vec<ChallengeProof<TreeR>> =
            Challenges::<TreeR>::new(SECTOR_NODES, comm_r_new)
                .enumerate()
                .take(pub_params.challenges)
                .map(|(i, c)| ChallengeProof {
                    r_old: tree_r_old.gen_proof(c).expect(&format!(
                        "failed to generate tree_r_old proof for challenge c_{}={}",
                        i, c
                    )),
                    d_new: tree_d_new.gen_proof(c).expect(&format!(
                        "failed to generate tree_d_new proof for challenge c_{}={}",
                        i, c
                    )),
                    r_new: tree_r_new.gen_proof(c).expect(&format!(
                        "failed to generate tree_r_new proof for challenge c_{}={}",
                        i, c
                    )),
                })
                .collect();

        let pub_inputs = PublicInputs::<TreeR> {
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h_select: H_SELECT,
            _tree_r: PhantomData,
        };

        let circuit = EmptySectorUpdateCircuit::<TreeR> {
            pub_params,
            comm_r_old: Some(pub_inputs.comm_r_old.into()),
            comm_d_new: Some(pub_inputs.comm_d_new.into()),
            comm_r_new: Some(pub_inputs.comm_r_new.into()),
            h_select: Some(Fr::from(pub_inputs.h_select)),
            comm_c: Some(comm_c.into()),
            comm_r_last_old: Some(comm_r_last_old.into()),
            comm_r_last_new: Some(comm_r_last_new.into()),
            challenge_proofs: Some(challenge_proofs),
        };

        let mut cs = TestConstraintSystem::<Bls12>::new();
        circuit.synthesize(&mut cs).expect("failed to synthesize");
        assert!(cs.is_satisfied());
        assert!(cs.verify(&pub_inputs.to_vec()));
    }
}
