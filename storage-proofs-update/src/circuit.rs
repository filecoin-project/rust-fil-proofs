use std::marker::PhantomData;

use bellperson::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack::pack_bits,
        num::AllocatedNum,
    },
    Circuit, ConstraintSystem, LinearCombination, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::{Field, PrimeFieldBits};
use filecoin_hashers::{HashFunction, Hasher, PoseidonArity};
use neptune::circuit::poseidon_hash;
use storage_proofs_core::{
    compound_proof::CircuitComponent,
    gadgets::{insertion::select, por::por_no_challenge_input},
    merkle::{MerkleProof, MerkleProofTrait},
};

use crate::{
    constants::{
        apex_leaf_count, challenge_count, hs, partition_count, validate_tree_r_shape, TreeD,
        TreeDArity, TreeDDomain, TreeDHasher, TreeR, TreeRDomain, TreeRHasher,
        POSEIDON_CONSTANTS_GEN_RANDOMNESS_BLS,
    },
    gadgets::{apex_por, gen_challenge_bits, get_challenge_high_bits, label_r_new},
    vanilla, PublicParams,
};

// The public inputs for `EmptySectorUpdateCircuit`.
#[derive(Clone)]
pub struct PublicInputs {
    // Pack `k` and `h_select` into a single public-input; `k` is at most 4 bits and `h_select` is 6
    // bits, thus we can pack `k` and `h_select` into a single field element.
    pub k_and_h_select: Option<Fr>,
    // The SDR-PoRep CommR corresponding to the replica prior to updating the sector data.
    pub comm_r_old: Option<Fr>,
    // The root of TreeDNew (a bin-tree built over the sector's updated data).
    pub comm_d_new: Option<Fr>,
    // A commitment to the `EmptySectorUpdate` encoding of the updated sector data.
    pub comm_r_new: Option<Fr>,
}

impl PublicInputs {
    pub fn new(
        sector_nodes: usize,
        k: usize,
        h: usize,
        comm_r_old: TreeRDomain<Fr>,
        comm_d_new: TreeDDomain<Fr>,
        comm_r_new: TreeRDomain<Fr>,
    ) -> Self {
        let partition_count = partition_count(sector_nodes);
        assert!(
            k < partition_count,
            "partition-index `k` exceeds partition-count for sector-size"
        );

        let hs_index = hs(sector_nodes)
            .iter()
            .position(|h_allowed| *h_allowed == h)
            .expect("invalid `h` for sector-size");

        let h_select = 1u64 << hs_index;

        let partition_bit_len = partition_count.trailing_zeros() as usize;
        let k_and_h_select = (k as u64) | (h_select << partition_bit_len);

        PublicInputs {
            k_and_h_select: Some(Fr::from(k_and_h_select)),
            comm_r_old: Some(comm_r_old.into()),
            comm_d_new: Some(comm_d_new.into()),
            comm_r_new: Some(comm_r_new.into()),
        }
    }

    // Public-inputs used during Groth16 parameter generation.
    pub fn empty() -> Self {
        PublicInputs {
            k_and_h_select: None,
            comm_r_old: None,
            comm_d_new: None,
            comm_r_new: None,
        }
    }

    // The ordered vector used to verify a Groth16 proof.
    pub fn to_vec(&self) -> Vec<Fr> {
        vec![
            self.k_and_h_select.unwrap(),
            self.comm_r_old.unwrap(),
            self.comm_d_new.unwrap(),
            self.comm_r_new.unwrap(),
        ]
    }
}

#[derive(Clone)]
pub struct ChallengeProof<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    pub leaf_r_old: Option<Fr>,
    pub path_r_old: Vec<Vec<Option<Fr>>>,
    pub leaf_d_new: Option<Fr>,
    pub path_d_new: Vec<Vec<Option<Fr>>>,
    pub leaf_r_new: Option<Fr>,
    pub path_r_new: Vec<Vec<Option<Fr>>>,
    pub _tree_r: PhantomData<(U, V, W)>,
}

impl<U, V, W> From<vanilla::ChallengeProof<Fr, U, V, W>> for ChallengeProof<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    fn from(challenge_proof: vanilla::ChallengeProof<Fr, U, V, W>) -> Self {
        let vanilla::ChallengeProof {
            proof_r_old,
            proof_d_new,
            proof_r_new,
        } = challenge_proof;
        ChallengeProof::from_merkle_proofs(proof_r_old, proof_d_new, proof_r_new)
    }
}

impl<U, V, W> ChallengeProof<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    pub fn from_merkle_proofs(
        proof_r_old: MerkleProof<TreeRHasher<Fr>, U, V, W>,
        proof_d_new: MerkleProof<TreeDHasher<Fr>, TreeDArity>,
        proof_r_new: MerkleProof<TreeRHasher<Fr>, U, V, W>,
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

    pub fn empty(sector_nodes: usize) -> Self {
        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;

        // TreeD is a binary-tree.
        let path_d = vec![vec![None]; challenge_bit_len];

        // TreeROld and TreeRNew have the same shape, thus have the same Merkle path length.
        let path_r = {
            let base_arity = U::to_usize();
            let sub_arity = V::to_usize();
            let top_arity = W::to_usize();

            let mut bits_remaining = challenge_bit_len;
            let mut sub_and_top_path = vec![];

            if sub_arity > 0 {
                sub_and_top_path.push(vec![None; sub_arity - 1]);
                bits_remaining -= sub_arity.trailing_zeros() as usize;
            };

            if top_arity > 0 {
                sub_and_top_path.push(vec![None; top_arity - 1]);
                bits_remaining -= top_arity.trailing_zeros() as usize;
            };

            let base_path_len = bits_remaining / base_arity.trailing_zeros() as usize;
            let base_path = vec![vec![None; base_arity - 1]; base_path_len];

            [base_path, sub_and_top_path].concat()
        };

        ChallengeProof {
            leaf_r_old: None,
            path_r_old: path_r.clone(),
            leaf_d_new: None,
            path_d_new: path_d,
            leaf_r_new: None,
            path_r_new: path_r,
            _tree_r: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct PrivateInputs<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    // CommC created by running SDR-PoRep on the old/un-updated data.
    pub comm_c: Option<Fr>,
    // Root of the replica tree (called TreeR or TreeRLast) output by SDR-PoRep on the
    // old/un-updated data (here called TreeROld).
    pub root_r_old: Option<Fr>,
    // Root of the replica tree build over the new/updated data's replica (TreeRNew).
    pub root_r_new: Option<Fr>,
    // The `k`-th chunk of nodes from the apex-leafs layer of TreeDNew (the tree built over the
    // new/updated data).
    pub apex_leafs: Vec<Option<Fr>>,
    // Generate three Merkle proofs (TreeROld, TreeDNew, TreeRNew) for each of this partition's
    // challenges.
    pub challenge_proofs: Vec<ChallengeProof<U, V, W>>,
}

impl<U, V, W> PrivateInputs<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    pub fn new(
        comm_c: TreeRDomain<Fr>,
        apex_leafs: &[TreeDDomain<Fr>],
        challenge_proofs: &[vanilla::ChallengeProof<Fr, U, V, W>],
    ) -> Self {
        let root_r_old: Fr = challenge_proofs[0].proof_r_old.root().into();
        let root_r_new: Fr = challenge_proofs[0].proof_r_new.root().into();

        let apex_leafs: Vec<Option<Fr>> = apex_leafs
            .iter()
            .copied()
            .map(|leaf| Some(leaf.into()))
            .collect();

        let challenge_proofs: Vec<ChallengeProof<U, V, W>> = challenge_proofs
            .iter()
            .cloned()
            .map(ChallengeProof::from)
            .collect();

        PrivateInputs {
            comm_c: Some(comm_c.into()),
            root_r_old: Some(root_r_old),
            root_r_new: Some(root_r_new),
            apex_leafs,
            challenge_proofs,
        }
    }

    pub fn empty(sector_nodes: usize) -> Self {
        let challenge_count = challenge_count(sector_nodes);
        let apex_leaf_count = apex_leaf_count(sector_nodes);
        PrivateInputs {
            comm_c: None,
            root_r_old: None,
            root_r_new: None,
            apex_leafs: vec![None; apex_leaf_count],
            challenge_proofs: vec![ChallengeProof::empty(sector_nodes); challenge_count],
        }
    }
}

pub struct EmptySectorUpdateCircuit<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    pub pub_params: PublicParams,
    pub pub_inputs: PublicInputs,
    pub priv_inputs: PrivateInputs<U, V, W>,
}

impl<U, V, W> CircuitComponent for EmptySectorUpdateCircuit<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    type ComponentPrivateInputs = ();
}

impl<U, V, W> EmptySectorUpdateCircuit<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    pub fn blank(pub_params: PublicParams) -> Self {
        let sector_bytes = (pub_params.sector_nodes as u64) << 5;
        assert_eq!(
            PublicParams::from_sector_size(sector_bytes),
            pub_params,
            "invalid public-params for sector-size",
        );
        let pub_inputs = PublicInputs::empty();
        let priv_inputs = PrivateInputs::<U, V, W>::empty(pub_params.sector_nodes);
        EmptySectorUpdateCircuit {
            pub_params,
            pub_inputs,
            priv_inputs,
        }
    }
}

impl<U, V, W> Circuit<Fr> for EmptySectorUpdateCircuit<U, V, W>
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let EmptySectorUpdateCircuit {
            pub_params:
                PublicParams {
                    sector_nodes,
                    challenge_count,
                    challenge_bit_len,
                    partition_count,
                    partition_bit_len,
                    apex_leaf_count,
                    apex_leaf_bit_len,
                },
            pub_inputs:
                PublicInputs {
                    k_and_h_select,
                    comm_r_old,
                    comm_d_new,
                    comm_r_new,
                },
            priv_inputs:
                PrivateInputs {
                    comm_c,
                    root_r_old,
                    root_r_new,
                    apex_leafs,
                    challenge_proofs,
                },
        } = self;

        validate_tree_r_shape::<U, V, W>(sector_nodes);
        let hs = hs(sector_nodes);
        let h_select_bit_len = hs.len();

        let partition_path =
            challenge_proofs[0].path_d_new[challenge_bit_len - partition_bit_len..].to_vec();

        if let Some(k_and_h_select) = k_and_h_select {
            let bits: Vec<bool> = k_and_h_select.to_le_bits().into_iter().collect();
            // Assert that `k` is valid for the sector-size.
            let k_bits = &bits[..partition_bit_len];
            let mut k = 0;
            for (i, bit) in k_bits.iter().enumerate() {
                if *bit {
                    k |= 1 << i;
                }
            }
            assert!(
                k < partition_count,
                "partition-index exceeds partition count"
            );
            // `h_select` should have exactly one bit set.
            let h_select_bits = &bits[partition_bit_len..partition_bit_len + h_select_bit_len];
            assert_eq!(
                h_select_bits.iter().filter(|bit| **bit).count(),
                1,
                "h_select does not have exactly one bit set"
            );
            // The remanining bits should be zero.
            assert!(bits[partition_bit_len + h_select_bit_len..]
                .iter()
                .all(|bit| !*bit));
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

        // Add a single public-input for `k` and `h_select` packed into one field element.
        let k_and_h_select = AllocatedNum::alloc(cs.namespace(|| "k_and_h_select"), || {
            k_and_h_select.ok_or(SynthesisError::AssignmentMissing)
        })?;
        k_and_h_select.inputize(cs.namespace(|| "k_and_h_select (public input)"))?;

        // Split `k_and_h_select` into partition and h-select bits.
        let k_and_h_select_bits = {
            let bit_len = partition_bit_len + h_select_bit_len;

            let bits: Vec<Option<bool>> = if let Some(k_and_h_select) = k_and_h_select.get_value() {
                k_and_h_select
                    .to_le_bits()
                    .into_iter()
                    .take(bit_len)
                    .map(Some)
                    .collect()
            } else {
                vec![None; bit_len]
            };

            let k_and_h_select_bits = bits
                .into_iter()
                .enumerate()
                .map(|(i, bit)| {
                    AllocatedBit::alloc(cs.namespace(|| format!("k_and_h_select_bit_{}", i)), bit)
                })
                .collect::<Result<Vec<AllocatedBit>, SynthesisError>>()?;

            let mut lc = LinearCombination::<Fr>::zero();
            let mut pow2 = Fr::one();
            for bit in k_and_h_select_bits.iter() {
                lc = lc + (pow2, bit.get_variable());
                pow2 = pow2.double();
            }
            cs.enforce(
                || "k_and_h_select binary decomp",
                |_| lc,
                |lc| lc + CS::one(),
                |lc| lc + k_and_h_select.get_variable(),
            );

            k_and_h_select_bits
        };

        let partition_bits = k_and_h_select_bits[..partition_bit_len].to_vec();
        let h_select_bits = k_and_h_select_bits[partition_bit_len..].to_vec();

        let partition = pack_bits(
            cs.namespace(|| "pack partition bits"),
            &partition_bits
                .iter()
                .cloned()
                .map(Into::into)
                .collect::<Vec<Boolean>>(),
        )?;

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

        // Compute `phi = H(comm_d_new || comm_r_old)` from public-inputs.
        let phi = poseidon_hash(
            cs.namespace(|| "phi"),
            vec![comm_d_new.clone(), comm_r_old.clone()],
            &*POSEIDON_CONSTANTS_GEN_RANDOMNESS_BLS,
        )?;

        // Allocate private-inputs; excludes each challenge's Merkle proofs.

        let comm_c = AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
            comm_c.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let root_r_old = AllocatedNum::alloc(cs.namespace(|| "root_r_old"), || {
            root_r_old.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let root_r_new = AllocatedNum::alloc(cs.namespace(|| "root_r_new"), || {
            root_r_new.ok_or(SynthesisError::AssignmentMissing)
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

        // Assert that the witnessed `root_r_old` and `root_r_new` are consistent with the
        // public `comm_r_old` and `comm_r_new` via `comm_r = H(comm_c || root_r)`.
        let comm_r_old_calc = <TreeRHasher<Fr> as Hasher>::Function::hash2_circuit(
            cs.namespace(|| "comm_r_old_calc"),
            &comm_c,
            &root_r_old,
        )?;
        cs.enforce(
            || "enforce comm_r_old_calc == comm_r_old",
            |lc| lc + comm_r_old_calc.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + comm_r_old.get_variable(),
        );
        let comm_r_new_calc = <TreeRHasher<Fr> as Hasher>::Function::hash2_circuit(
            cs.namespace(|| "comm_r_new_calc"),
            &comm_c,
            &root_r_new,
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
        // For each challenge generate a random index in `0..number of leafs per partition`; we
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
                &c_bits,
                &h_select_bits,
                &hs,
            )?;
            let rho = poseidon_hash(
                cs.namespace(|| format!("rho (c_index={})", c_index)),
                vec![phi.clone(), c_high.clone()],
                &*POSEIDON_CONSTANTS_GEN_RANDOMNESS_BLS,
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

            // Sanity check that the calculated `leaf_r_new` agrees with the provided value.
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

            por_no_challenge_input::<TreeR<Fr, U, V, W>, _>(
                cs.namespace(|| format!("por tree_r_old (c_index={})", c_index)),
                c_bits.clone(),
                leaf_r_old.clone(),
                path_r_old,
                root_r_old.clone(),
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

            por_no_challenge_input::<TreeR<Fr, U, V, W>, _>(
                cs.namespace(|| format!("por tree_r_new (c_index={})", c_index)),
                c_bits.clone(),
                leaf_r_new.clone(),
                path_r_new,
                root_r_new.clone(),
            )?;

            let apex_leaf_bits: Vec<Boolean> = {
                let start = challenge_bit_len - partition_bit_len - apex_leaf_bit_len;
                let stop = start + apex_leaf_bit_len;
                c_bits[start..stop]
                    .iter()
                    .cloned()
                    .map(Into::into)
                    .collect()
            };

            let apex_leaf = select(
                cs.namespace(|| format!("select_apex_leaf (c_index={})", c_index)),
                &apex_leafs,
                &apex_leaf_bits,
            )?;

            let path_len_to_apex_leaf = challenge_bit_len - partition_bit_len - apex_leaf_bit_len;

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

            por_no_challenge_input::<TreeD<Fr>, _>(
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
