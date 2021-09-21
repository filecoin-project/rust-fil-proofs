use std::marker::PhantomData;

use bellperson::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        num::AllocatedNum,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use blstrs::{Bls12, Scalar as Fr};
use filecoin_hashers::{HashFunction, Hasher};
use generic_array::typenum::Unsigned;
use storage_proofs_core::{
    gadgets::insertion::select,
    merkle::{MerkleProofTrait, MerkleTreeTrait},
};

use crate::{
    constants::{
        apex_leaf_count, challenge_count, hs, partition_count, tree_shape_is_valid, TreeD,
        ALLOWED_SECTOR_SIZES,
    },
    gadgets::{
        allocated_num_to_allocated_bits, apex_por, gen_challenge_bits, get_challenge_high_bits,
        label_r_new, por_no_challenge_input,
    },
};

type MerkleProof<Tree> = storage_proofs_core::merkle::MerkleProof<
    <Tree as MerkleTreeTrait>::Hasher,
    <Tree as MerkleTreeTrait>::Arity,
    <Tree as MerkleTreeTrait>::SubTreeArity,
    <Tree as MerkleTreeTrait>::TopTreeArity,
>;

#[derive(Clone)]
pub struct PublicParams {
    // The sector-size measured in nodes.
    pub sector_nodes: usize,
    // The number of challenges per partition proof.
    pub challenge_count: usize,
    // The number of bits per challenge, i.e. `challenge_bits = log2(sector_nodes)`.
    pub challenge_bit_len: usize,
    // The number of partition proofs for this sector-size.
    pub partition_count: usize,
    // The bit length of an integer in `0..partition_count`.
    pub partition_bit_len: usize,
    // The number of leafs in the apex-tree.
    pub apex_leaf_count: usize,
    // The bit length of an integer in `0..apex_leaf_count`.
    pub apex_select_bit_len: usize,
}

impl PublicParams {
    pub fn from_sector_size(sector_bytes: u64) -> Self {
        // The sector-size measured in 32-byte nodes.
        let sector_nodes = ALLOWED_SECTOR_SIZES
            .iter()
            .copied()
            .find(|allowed_nodes| (allowed_nodes << 5) as u64 == sector_bytes)
            .expect("provided sector-size is not allowed");

        // `sector_nodes` is guaranteed to be a power of two.
        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
        let challenge_count = challenge_count(sector_nodes);

        let partition_count = partition_count(sector_nodes);
        // `partition_count` is guaranteed to be a power of two.
        let partition_bit_len = partition_count.trailing_zeros() as usize;

        let apex_leaf_count = apex_leaf_count(sector_nodes);
        // `apex_leaf_count` is guaranteed to be a power of two.
        let apex_select_bit_len = apex_leaf_count.trailing_zeros() as usize;

        PublicParams {
            sector_nodes,
            challenge_count,
            challenge_bit_len,
            partition_count,
            partition_bit_len,
            apex_leaf_count,
            apex_select_bit_len,
        }
    }
}

#[derive(Clone)]
pub struct PublicInputs<TreeR: MerkleTreeTrait> {
    pub k: usize,
    pub comm_r_old: <TreeR::Hasher as Hasher>::Domain,
    pub comm_d_new: <<TreeD as MerkleTreeTrait>::Hasher as Hasher>::Domain,
    pub comm_r_new: <TreeR::Hasher as Hasher>::Domain,
    pub h_select: u64,
    pub _tree_r: PhantomData<TreeR>,
}

impl<TreeR: MerkleTreeTrait> PublicInputs<TreeR> {
    pub fn to_vec(self) -> Vec<Fr> {
        vec![
            Fr::from(self.k as u64),
            self.comm_r_old.into(),
            self.comm_d_new.into(),
            self.comm_r_new.into(),
            Fr::from(self.h_select),
        ]
    }
}

pub struct ChallengeProof<TreeR: MerkleTreeTrait> {
    pub leaf_r_old: Option<Fr>,
    pub path_r_old: Vec<Vec<Option<Fr>>>,
    pub leaf_d_new: Option<Fr>,
    pub path_d_new: Vec<Vec<Option<Fr>>>,
    pub leaf_r_new: Option<Fr>,
    pub path_r_new: Vec<Vec<Option<Fr>>>,
    pub _tree_r: PhantomData<TreeR>,
}

// Implement `Clone` by hand because `MerkleTreeTrait` does not implement `Clone`.
impl<TreeR: MerkleTreeTrait> std::clone::Clone for ChallengeProof<TreeR> {
    fn clone(&self) -> Self {
        ChallengeProof {
            leaf_r_old: self.leaf_r_old.clone(),
            path_r_old: self.path_r_old.clone(),
            leaf_d_new: self.leaf_d_new.clone(),
            path_d_new: self.path_d_new.clone(),
            leaf_r_new: self.leaf_r_new.clone(),
            path_r_new: self.path_r_new.clone(),
            _tree_r: PhantomData,
        }
    }
}

impl<TreeR: MerkleTreeTrait> ChallengeProof<TreeR> {
    pub fn from_merkle_proofs(
        proof_r_old: MerkleProof<TreeR>,
        proof_d_new: MerkleProof<TreeD>,
        proof_r_new: MerkleProof<TreeR>,
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

pub struct EmptySectorUpdateCircuit<TreeR: MerkleTreeTrait> {
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
    pub partition_path: Vec<Vec<Option<Fr>>>,
    pub challenge_proofs: Vec<ChallengeProof<TreeR>>,
}

impl<TreeR: MerkleTreeTrait> EmptySectorUpdateCircuit<TreeR> {
    pub fn blank(pub_params: PublicParams) -> Self {
        let apex_leafs = vec![None; pub_params.apex_leaf_count];
        let partition_path = vec![vec![None]; pub_params.partition_bit_len];
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
            partition_path,
            challenge_proofs,
        }
    }
}

impl<TreeR: MerkleTreeTrait> Circuit<Bls12> for EmptySectorUpdateCircuit<TreeR> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
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
            partition_path,
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

        let hs = hs(sector_nodes);
        let h_select_bit_len = hs.len();

        assert!(tree_shape_is_valid::<TreeR>(sector_nodes));
        if let Some(k) = k {
            let repr = k.to_bytes_le();
            assert!(
                (repr[0] as usize) < partition_count && repr[1..] == [0u8; 31],
                "partition-index exceeds partition count",
            );
        }
        // Assert that `h_select` is valid. HSelect should be a uint whose binary representation has
        // exactly 1 of its first 6 (i.e. `h_select_bit_len`) bits set.
        if let Some(h_select) = h_select {
            let mut allowed_h_select_values = (0..h_select_bit_len).map(|i| Fr::from(1u64 << i));
            assert!(allowed_h_select_values.any(|allowed_h_select| allowed_h_select == h_select));
        }
        assert_eq!(apex_leafs.len(), apex_leaf_count);
        assert_eq!(partition_path.len(), partition_bit_len);
        assert!(partition_path.iter().all(|siblings| siblings.len() == 1));
        assert_eq!(challenge_proofs.len(), challenge_count);

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
            .collect::<Result<Vec<AllocatedNum<Bls12>>, SynthesisError>>()?;

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
            .collect::<Result<Vec<Vec<AllocatedNum<Bls12>>>, SynthesisError>>()?;

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
            partition_path.clone(),
            comm_d_new.clone(),
        )?;

        // Generate `challenge_sans_partition_bit_len` number of random bits for each challenge.
        // For each challenge generate a random index in `0..number of leaf's per partition`; we
        // append the partition-index's bits onto the random bits generated for each challenge
        // producing a challenge in `0..sector_nodes` which is guaranteed to lie within this
        // partition's subset of leafs.
        let challenge_sans_partition_bit_len = challenge_bit_len - partition_bit_len;
        let generated_bits = gen_challenge_bits::<TreeR::Hasher, _>(
            cs.namespace(|| "gen_challenge_bits"),
            &comm_r_new,
            &partition,
            challenge_count,
            challenge_sans_partition_bit_len,
        )?;

        for (c_index, c_bits_without_partition) in generated_bits.into_iter().enumerate() {
            let c_bits: Vec<AllocatedBit> = c_bits_without_partition
                .into_iter()
                .chain(partition_bits.iter().cloned())
                .collect();

            // TODO: the high bits should not include the partition index.

            // Compute this challenge's `rho`.
            let c_high = get_challenge_high_bits(
                cs.namespace(|| format!("get_challenge_high_bits (c_index={})", c_index)),
                // TODO: remove comments
                // &c_bits_without_partition,
                // &partition_bits,
                &c_bits,
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
                        .collect::<Result<Vec<AllocatedNum<Bls12>>, SynthesisError>>()
                })
                .collect::<Result<Vec<Vec<AllocatedNum<Bls12>>>, SynthesisError>>()?;

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
                        .collect::<Result<Vec<AllocatedNum<Bls12>>, SynthesisError>>()
                })
                .collect::<Result<Vec<Vec<AllocatedNum<Bls12>>>, SynthesisError>>()?;

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
                .collect::<Result<Vec<Vec<AllocatedNum<Bls12>>>, SynthesisError>>()?;

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

/*
#[cfg(test)]
mod tests {
    use super::*;

    use filecoin_hashers::Domain;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        merkle::{create_base_merkle_tree, MerkleProof, MerkleProofTrait},
        TEST_SEED,
    };

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
        assert!(tree_shape_is_valid::<Tree>(sector_nodes));

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

            let base_trees: Vec<MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity>> =
                (0..base_tree_count)
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
                        MerkleTreeWrapper::try_from_iter_with_config(leafs, config).expect(
                            &format!("failed to create {} base-tree {}", tree_name, i),
                        )
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
                                let leafs =
                                    labels[first_base_leaf..first_base_leaf + leafs_per_base_tree]
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
                                        tree_name,
                                        sub_index,
                                        base_index,
                                    ),
                                )
                            })
                            .collect();
                    MerkleTreeWrapper::from_trees(base_trees).expect(&format!(
                        "failed to create {} sub-tree {} from base-trees",
                        tree_name,
                        sub_index,
                    ))
                })
                .collect();

            MerkleTreeWrapper::from_sub_trees(sub_trees)
                .expect(&format!("failed to create {} from sub-trees", tree_name))
        }
    }

    #[test]
    fn test_empty_sector_update_circuit() {

    }

    /*
    use crate::constants::TreeDArity;

    #[test]
    fn test_apex_tree() {
        let mut rng = &mut XorShiftRng::from_seed(TEST_SEED);

        let n_leafs = PARTITIONS * APEX_LEAFS;
        let leafs: Vec<TreeDDomain> = (0..n_leafs).map(|_| TreeDDomain::random(&mut rng)).collect();
        let data: Vec<u8> = leafs.iter().flat_map(|leaf| leaf.into_bytes()).collect();
        let tree = create_base_merkle_tree::<TreeD>(None, n_leafs, &data)
            .expect("create_base_merkle_tree failure");
        let comm_d = tree.root();

        let k = 0;

        let merkle_proofs: Vec<MerkleProof<TreeDHasher, TreeDArity>> = (0..APEX_LEAFS)
            .map(|node_index| {
                tree.gen_proof(node_index).expect(
                    &format!("failed to generate merkle proof for node {}", node_index),
                )
            })
            .collect();

        fn apex_root_sibling(merkle_proof: &MerkleProof<TreeDHasher, TreeDArity>) -> TreeDDomain {
            merkle_proof.path()[APEX_HEIGHT].0[0]
        }

        fn partition_index(merkle_proof: &MerkleProof<TreeDHasher, TreeDArity>) -> usize {
            let mut k = 0;
            for (i, el) in merkle_proof.path()[APEX_HEIGHT..].iter().enumerate() {
                let bit = el.1;
                assert!(bit <= 1);
                k += bit * (1 << i);
            }
            assert!(k < PARTITIONS);
            k
        }

        assert_eq!(tree.row_count(), APEX_ROWS + PARTITION_ROWS);
        let apex_root = apex_root_sibling(&merkle_proofs[0]);
        for merkle_proof in merkle_proofs.iter() {
            assert_eq!(merkle_proof.path().len(), APEX_ROWS + PARTITION_ROWS - 1);
            assert_eq!(apex_root_sibling(&merkle_proof), apex_root);
            assert_eq!(partition_index(&merkle_proof), k);
        }
    }
    */
}
*/
