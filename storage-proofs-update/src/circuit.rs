use std::marker::PhantomData;

use bellperson::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        num::AllocatedNum,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use filecoin_hashers::{HashFunction, Hasher};
use generic_array::typenum::Unsigned;
use storage_proofs_core::{
    compound_proof::CircuitComponent,
    gadgets::insertion::select,
    merkle::{MerkleProof, MerkleProofTrait, MerkleTreeTrait},
};

use crate::{
    constants::{
        hs, validate_tree_r_shape, TreeD, TreeDArity, TreeDDomain, TreeDHasher, TreeRDomain,
        TreeRHasher,
    },
    gadgets::{
        allocated_num_to_allocated_bits, apex_por, gen_challenge_bits, get_challenge_high_bits,
        label_r_new, por_no_challenge_input,
    },
    PublicParams,
};

#[derive(Clone)]
pub struct PublicInputs {
    pub k: usize,
    pub comm_r_old: TreeRDomain,
    pub comm_d_new: TreeDDomain,
    pub comm_r_new: TreeRDomain,
    pub h_select: u64,
}

impl PublicInputs {
    // Returns public-inputs in the order expected by `ConstraintSystem::verify()`.
    pub fn to_vec(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.k as u64),
            self.comm_r_old.into(),
            self.comm_d_new.into(),
            self.comm_r_new.into(),
            Fr::from(self.h_select),
        ]
    }
}

pub struct ChallengeProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    pub leaf_r_old: Option<Fr>,
    pub path_r_old: Vec<Vec<Option<Fr>>>,
    pub leaf_d_new: Option<Fr>,
    pub path_d_new: Vec<Vec<Option<Fr>>>,
    pub leaf_r_new: Option<Fr>,
    pub path_r_new: Vec<Vec<Option<Fr>>>,
    pub _tree_r: PhantomData<TreeR>,
}

// Implement `Clone` by hand because `MerkleTreeTrait` does not implement `Clone`.
impl<TreeR> Clone for ChallengeProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    fn clone(&self) -> Self {
        ChallengeProof {
            leaf_r_old: self.leaf_r_old,
            path_r_old: self.path_r_old.clone(),
            leaf_d_new: self.leaf_d_new,
            path_d_new: self.path_d_new.clone(),
            leaf_r_new: self.leaf_r_new,
            path_r_new: self.path_r_new.clone(),
            _tree_r: PhantomData,
        }
    }
}

impl<TreeR> ChallengeProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    pub fn from_merkle_proofs(
        proof_r_old: MerkleProof<
            TreeRHasher,
            TreeR::Arity,
            TreeR::SubTreeArity,
            TreeR::TopTreeArity,
        >,
        proof_d_new: MerkleProof<TreeDHasher, TreeDArity>,
        proof_r_new: MerkleProof<
            TreeRHasher,
            TreeR::Arity,
            TreeR::SubTreeArity,
            TreeR::TopTreeArity,
        >,
    ) -> Self {
        let leaf_r_old = Some(proof_r_old.leaf().into());
        let path_r_old: Vec<Vec<Option<Fr>>> = proof_r_old
            .path()
            .iter()
            .map(|(siblings, _insert)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        let leaf_d_new = Some(proof_d_new.leaf().into());
        let path_d_new: Vec<Vec<Option<Fr>>> = proof_d_new
            .path()
            .iter()
            .map(|(siblings, _insert)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        let leaf_r_new = Some(proof_r_new.leaf().into());
        let path_r_new: Vec<Vec<Option<Fr>>> = proof_r_new
            .path()
            .iter()
            .map(|(siblings, _insert)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        ChallengeProof {
            leaf_r_old,
            path_r_old,
            leaf_d_new,
            path_d_new,
            leaf_r_new,
            path_r_new,
            _tree_r: PhantomData,
        }
    }

    pub fn blank(sector_nodes: usize) -> Self {
        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;

        // TreeD is a non-compound binary-tree.
        let blank_path_d = vec![vec![None]; challenge_bit_len];

        let blank_path_r = {
            let base_arity = TreeR::Arity::to_usize();
            let sub_arity = TreeR::SubTreeArity::to_usize();
            let top_arity = TreeR::TopTreeArity::to_usize();

            let mut bits_remaining = challenge_bit_len;
            let mut sub_and_top_path = vec![];
            if sub_arity > 0 {
                bits_remaining -= sub_arity.trailing_zeros() as usize;
                sub_and_top_path.push(vec![None; sub_arity - 1]);
            }
            if top_arity > 0 {
                bits_remaining -= top_arity.trailing_zeros() as usize;
                sub_and_top_path.push(vec![None; top_arity - 1]);
            }
            let base_path_len = bits_remaining / base_arity.trailing_zeros() as usize;
            let base_path = vec![vec![None; base_arity - 1]; base_path_len];

            let mut blank_path = base_path;
            blank_path.append(&mut sub_and_top_path);
            blank_path
        };

        ChallengeProof {
            leaf_r_old: None,
            path_r_old: blank_path_r.clone(),
            leaf_d_new: None,
            path_d_new: blank_path_d,
            leaf_r_new: None,
            path_r_new: blank_path_r,
            _tree_r: PhantomData,
        }
    }
}

pub struct EmptySectorUpdateCircuit<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    pub pub_params: PublicParams,

    // Public-inputs
    pub k: Option<Fr>,
    pub comm_r_old: Option<Fr>,
    pub comm_d_new: Option<Fr>,
    pub comm_r_new: Option<Fr>,
    pub h_select: Option<Fr>,

    // Private-inputs
    pub comm_c: Option<Fr>,
    pub comm_r_last_old: Option<Fr>,
    pub comm_r_last_new: Option<Fr>,
    pub apex_leafs: Vec<Option<Fr>>,
    pub challenge_proofs: Vec<ChallengeProof<TreeR>>,
}

impl<TreeR> CircuitComponent for EmptySectorUpdateCircuit<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    type ComponentPrivateInputs = ();
}

impl<TreeR> EmptySectorUpdateCircuit<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    pub fn blank(pub_params: PublicParams) -> Self {
        let apex_leafs = vec![None; pub_params.apex_leaf_count];
        let challenge_proofs =
            vec![ChallengeProof::blank(pub_params.sector_nodes); pub_params.challenge_count];
        EmptySectorUpdateCircuit {
            pub_params,
            k: None,
            comm_r_old: None,
            comm_d_new: None,
            comm_r_new: None,
            h_select: None,
            comm_c: None,
            comm_r_last_old: None,
            comm_r_last_new: None,
            apex_leafs,
            challenge_proofs,
        }
    }
}

impl<TreeR> Circuit<Fr> for EmptySectorUpdateCircuit<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let EmptySectorUpdateCircuit {
            pub_params,
            k,
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h_select,
            comm_c,
            comm_r_last_old,
            comm_r_last_new,
            apex_leafs,
            challenge_proofs,
        } = self;

        let PublicParams {
            sector_nodes,
            challenge_count,
            challenge_bit_len,
            partition_count,
            partition_bit_len,
            apex_leaf_count,
            apex_select_bit_len,
        } = pub_params;

        validate_tree_r_shape::<TreeR>(sector_nodes);
        let hs = hs(sector_nodes);
        let h_select_bit_len = hs.len();

        let partition_path =
            challenge_proofs[0].path_d_new[challenge_bit_len - partition_bit_len..].to_vec();

        if let Some(k) = k {
            let repr = k.to_bytes_le();
            assert!(
                (repr[0] as usize) < partition_count && repr[1..] == [0u8; 31],
                "partition-index exceeds partition count",
            );
        }
        // Assert that `h_select` is valid. HSelect should be a uint whose binary representation has
        // exactly 1 of its first `h_select_bit_len` (i.e. 6) bits set.
        if let Some(h_select) = h_select {
            let mut allowed_h_select_values = (0..h_select_bit_len).map(|i| Fr::from(1u64 << i));
            assert!(allowed_h_select_values.any(|allowed_h_select| allowed_h_select == h_select));
        }
        assert_eq!(apex_leafs.len(), apex_leaf_count);
        assert_eq!(partition_path.len(), partition_bit_len);
        assert!(partition_path.iter().all(|siblings| siblings.len() == 1));
        assert_eq!(challenge_proofs.len(), challenge_count);
        // Check that all partition challenge's have the same same partition path.
        for challenge_proof in &challenge_proofs[1..] {
            assert_eq!(
                &challenge_proof.path_d_new[challenge_bit_len - partition_bit_len..],
                partition_path,
            );
        }

        // Allocate public-inputs.

        let partition = AllocatedNum::alloc(cs.namespace(|| "partition_index"), || {
            k.ok_or(SynthesisError::AssignmentMissing)
        })?;
        partition.inputize(cs.namespace(|| "partition_index (public input)"))?;

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

        // Allocate values derived from public-inputs.

        // Allocate the partition-index as bits.
        let partition_bits: Vec<AllocatedBit> =
            allocated_num_to_allocated_bits(cs.namespace(|| "partition_bits"), &partition)?
                .into_iter()
                .take(partition_bit_len)
                .collect();

        // Allocate the six least-significant bits of `h_select`.
        let h_select_bits: Vec<AllocatedBit> =
            allocated_num_to_allocated_bits(cs.namespace(|| "h_select_bits"), &h_select)?
                .into_iter()
                .take(h_select_bit_len)
                .collect();

        // phi = H(comm_d_new || comm_r_old)
        let phi = <TreeR::Hasher as Hasher>::Function::hash2_circuit(
            cs.namespace(|| "phi"),
            &comm_d_new,
            &comm_r_old,
        )?;

        // Allocate private-inputs; excludes each challenge's Merkle proofs.

        let comm_c = AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
            comm_c.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let comm_r_last_old = AllocatedNum::alloc(cs.namespace(|| "comm_r_last_old"), || {
            comm_r_last_old.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let comm_r_last_new = AllocatedNum::alloc(cs.namespace(|| "comm_r_last_new"), || {
            comm_r_last_new.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let apex_leafs = apex_leafs
            .iter()
            .enumerate()
            .map(|(i, leaf)| {
                AllocatedNum::alloc(cs.namespace(|| format!("apex_leaf_{}", i)), || {
                    leaf.ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<AllocatedNum<Fr>>, SynthesisError>>()?;

        let partition_path = partition_path
            .iter()
            .enumerate()
            .map(|(i, siblings)| {
                AllocatedNum::alloc(
                    cs.namespace(|| format!("partition_path_sibling_{}", i)),
                    || siblings[0].ok_or(SynthesisError::AssignmentMissing),
                )
                .map(|sibling| vec![sibling])
            })
            .collect::<Result<Vec<Vec<AllocatedNum<Fr>>>, SynthesisError>>()?;

        // Assert that the witnessed `comm_r_last_old` and `comm_r_last_new` are consistent with the
        // public `comm_r_old` and `comm_r_new` via `comm_r = H(comm_c || comm_r_last)`.
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

        // Assert that this partition's `apex_leafs` are  consistent with the public `comm_d_new`.
        apex_por(
            cs.namespace(|| "apex_gadget"),
            apex_leafs.clone(),
            partition_bits.clone(),
            partition_path,
            comm_d_new,
        )?;

        // Generate `challenge_sans_partition_bit_len` number of random bits for each challenge.
        // For each challenge generate a random index in `0..number of leaf's per partition`; we
        // append the partition-index's bits onto the random bits generated for each challenge
        // producing a challenge in `0..sector_nodes` which is guaranteed to lie within this
        // partition's subset of leafs.
        let challenge_sans_partition_bit_len = challenge_bit_len - partition_bit_len;
        let generated_bits = gen_challenge_bits(
            cs.namespace(|| "gen_challenge_bits"),
            &comm_r_new,
            &partition,
            challenge_count,
            challenge_sans_partition_bit_len,
        )?;

        for (c_index, c_bits_without_partition) in generated_bits.into_iter().enumerate() {
            let c_bits: Vec<AllocatedBit> = c_bits_without_partition
                .iter()
                .chain(partition_bits.iter())
                .cloned()
                .collect();

            // Compute this challenge's `rho`.
            let c_high = get_challenge_high_bits(
                cs.namespace(|| format!("get_challenge_high_bits (c_index={})", c_index)),
                &c_bits_without_partition,
                &h_select_bits,
                &hs,
            )?;
            let rho = <TreeR::Hasher as Hasher>::Function::hash2_circuit(
                cs.namespace(|| format!("rho (c_index={})", c_index)),
                &phi,
                &c_high,
            )?;

            // Validate this challenge's Merkle proofs.
            let challenge_proof = &challenge_proofs[c_index];

            let leaf_r_old = AllocatedNum::alloc(
                cs.namespace(|| format!("leaf_r_old (c_index={})", c_index)),
                || {
                    challenge_proof
                        .leaf_r_old
                        .ok_or(SynthesisError::AssignmentMissing)
                },
            )?;

            let leaf_d_new = AllocatedNum::alloc(
                cs.namespace(|| format!("leaf_d_new (c_index={})", c_index)),
                || {
                    challenge_proof
                        .leaf_d_new
                        .ok_or(SynthesisError::AssignmentMissing)
                },
            )?;

            let leaf_r_new = label_r_new(
                cs.namespace(|| format!("leaf_r_new (c_index={})", c_index)),
                &leaf_r_old,
                &leaf_d_new,
                &rho,
            )?;

            // Check that the calculated value of `leaf_r_new` agrees with the provided value.
            if let Some(leaf_r_new) = leaf_r_new.get_value() {
                assert_eq!(leaf_r_new, challenge_proof.leaf_r_new.unwrap());
            }

            let path_r_old = challenge_proof.path_r_old
                .iter()
                .enumerate()
                .map(|(tree_row, siblings)| {
                    siblings
                        .iter()
                        .enumerate()
                        .map(|(sibling_index, sibling)| {
                            AllocatedNum::alloc(
                                cs.namespace(|| format!(
                                    "path_r_old sibling (c_index={}, tree_row={}, sibling_index={})",
                                    c_index,
                                    tree_row,
                                    sibling_index,
                                )),
                                || sibling.ok_or(SynthesisError::AssignmentMissing),
                            )
                        })
                        .collect::<Result<Vec<AllocatedNum<Fr>>, SynthesisError>>()
                })
                .collect::<Result<Vec<Vec<AllocatedNum<Fr>>>, SynthesisError>>()?;

            por_no_challenge_input::<TreeR, _>(
                cs.namespace(|| format!("por tree_r_old (c_index={})", c_index)),
                c_bits.clone(),
                leaf_r_old.clone(),
                path_r_old,
                comm_r_last_old.clone(),
            )?;

            let path_r_new = challenge_proof.path_r_new
                .iter()
                .enumerate()
                .map(|(tree_row, siblings)| {
                    siblings
                        .iter()
                        .enumerate()
                        .map(|(sibling_index, sibling)| {
                            AllocatedNum::alloc(
                                cs.namespace(|| format!(
                                    "path_r_new sibling (c_index={}, tree_row={}, sibling_index={})",
                                    c_index,
                                    tree_row,
                                    sibling_index,
                                )),
                                || sibling.ok_or(SynthesisError::AssignmentMissing),
                            )
                        })
                        .collect::<Result<Vec<AllocatedNum<Fr>>, SynthesisError>>()
                })
                .collect::<Result<Vec<Vec<AllocatedNum<Fr>>>, SynthesisError>>()?;

            por_no_challenge_input::<TreeR, _>(
                cs.namespace(|| format!("por tree_r_new (c_index={})", c_index)),
                c_bits.clone(),
                leaf_r_new.clone(),
                path_r_new,
                comm_r_last_new.clone(),
            )?;

            let apex_select_bits: Vec<Boolean> = {
                let start = challenge_bit_len - partition_bit_len - apex_select_bit_len;
                let stop = start + apex_select_bit_len;
                c_bits[start..stop]
                    .iter()
                    .cloned()
                    .map(Into::into)
                    .collect()
            };

            let apex_leaf = select(
                cs.namespace(|| format!("select_apex_leaf (c_index={})", c_index)),
                &apex_leafs,
                &apex_select_bits,
            )?;

            let path_len_to_apex_leaf = challenge_bit_len - partition_bit_len - apex_select_bit_len;

            let c_bits_to_apex_leaf: Vec<AllocatedBit> =
                c_bits.into_iter().take(path_len_to_apex_leaf).collect();

            let path_to_apex_leaf = challenge_proof
                .path_d_new
                .iter()
                .take(path_len_to_apex_leaf)
                .enumerate()
                .map(|(tree_row, siblings)| {
                    AllocatedNum::alloc(
                        cs.namespace(|| {
                            format!(
                                "path_to_apex_leaf sibling (c_index={}, tree_row={})",
                                c_index, tree_row,
                            )
                        }),
                        || siblings[0].ok_or(SynthesisError::AssignmentMissing),
                    )
                    .map(|sibling| vec![sibling])
                })
                .collect::<Result<Vec<Vec<AllocatedNum<Fr>>>, SynthesisError>>()?;

            por_no_challenge_input::<TreeD, _>(
                cs.namespace(|| format!("por to_apex_leaf (c_index={})", c_index)),
                c_bits_to_apex_leaf,
                leaf_d_new,
                path_to_apex_leaf,
                apex_leaf,
            )?;
        }

        Ok(())
    }
}
