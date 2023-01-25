//! This circuit is NOT AUDITED, USE AT YOUR OWN RISK.

use std::marker::PhantomData;

use bellperson::{
    gadgets::{boolean::AllocatedBit, num::AllocatedNum},
    Circuit, ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;
use filecoin_hashers::{PoseidonArity, PoseidonLookup, R1CSHasher};
use generic_array::typenum::U2;
use neptune::circuit::poseidon_hash;
use storage_proofs_core::{
    compound_proof::CircuitComponent,
    gadgets::por::por_no_challenge_input,
    merkle::{MerkleProof, MerkleProofTrait},
};

use crate::{
    constants::{
        challenge_count_poseidon, hs, validate_tree_r_shape, TreeR, TreeRDomain, TreeRHasher,
        POSEIDON_CONSTANTS_GEN_RANDOMNESS,
    },
    gadgets::{gen_challenge_bits, get_challenge_high_bits, label_r_new},
    poseidon::vanilla,
    PublicParams,
};

// The public inputs for `EmptySectorUpdateCircuit`.
#[derive(Clone)]
pub struct PublicInputs<F: PrimeField> {
    // `h_select` chooses the number of encoding hashes.`
    pub h_select: Option<F>,
    // The SDR-PoRep CommR corresponding to the replica prior to updating the sector data.
    pub comm_r_old: Option<F>,
    // The root of TreeDNew but with TreeR shape.
    pub comm_d_new: Option<F>,
    // A commitment to the `EmptySectorUpdate` encoding of the updated sector data.
    pub comm_r_new: Option<F>,
}

impl<F> PublicInputs<F>
where
    F: PrimeField,
    TreeRHasher<F>: R1CSHasher<Field = F>,
{
    pub fn new(
        sector_nodes: usize,
        h: usize,
        comm_r_old: TreeRDomain<F>,
        comm_d_new: TreeRDomain<F>,
        comm_r_new: TreeRDomain<F>,
    ) -> Self {
        let hs_index = hs(sector_nodes)
            .iter()
            .position(|h_allowed| *h_allowed == h)
            .expect("invalid `h` for sector-size");

        let h_select = 1u64 << hs_index;

        PublicInputs {
            h_select: Some(F::from(h_select)),
            comm_r_old: Some(comm_r_old.into()),
            comm_d_new: Some(comm_d_new.into()),
            comm_r_new: Some(comm_r_new.into()),
        }
    }

    // Public-inputs used during Groth16 parameter generation.
    pub fn empty() -> Self {
        PublicInputs {
            h_select: None,
            comm_r_old: None,
            comm_d_new: None,
            comm_r_new: None,
        }
    }

    // The ordered vector used to verify a Groth16 proof.
    pub fn to_vec(&self) -> Vec<F> {
        vec![
            self.h_select.unwrap(),
            self.comm_r_old.unwrap(),
            self.comm_d_new.unwrap(),
            self.comm_r_new.unwrap(),
        ]
    }
}

#[derive(Clone)]
pub struct ChallengeProof<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
{
    pub leaf_r_old: Option<F>,
    pub path_r_old: Vec<Vec<Option<F>>>,
    pub leaf_d_new: Option<F>,
    pub path_d_new: Vec<Vec<Option<F>>>,
    pub leaf_r_new: Option<F>,
    pub path_r_new: Vec<Vec<Option<F>>>,
    pub _tree_r: PhantomData<(U, V, W)>,
}

impl<F, U, V, W> From<vanilla::ChallengeProof<F, U, V, W>> for ChallengeProof<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeRHasher<F>: R1CSHasher<Field = F>,
{
    fn from(challenge_proof: vanilla::ChallengeProof<F, U, V, W>) -> Self {
        let vanilla::ChallengeProof {
            proof_r_old,
            proof_d_new,
            proof_r_new,
        } = challenge_proof;
        ChallengeProof::from_merkle_proofs(proof_r_old, proof_d_new, proof_r_new)
    }
}

impl<F, U, V, W> ChallengeProof<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeRHasher<F>: R1CSHasher<Field = F>,
{
    pub fn from_merkle_proofs(
        proof_r_old: MerkleProof<TreeRHasher<F>, U, V, W>,
        proof_d_new: MerkleProof<TreeRHasher<F>, U, V, W>,
        proof_r_new: MerkleProof<TreeRHasher<F>, U, V, W>,
    ) -> Self {
        let leaf_r_old = Some(proof_r_old.leaf().into());
        let path_r_old: Vec<Vec<Option<F>>> = proof_r_old
            .path()
            .iter()
            .map(|(siblings, _insert)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        let leaf_d_new = Some(proof_d_new.leaf().into());
        let path_d_new: Vec<Vec<Option<F>>> = proof_d_new
            .path()
            .iter()
            .map(|(siblings, _insert)| siblings.iter().map(|&s| Some(s.into())).collect())
            .collect();

        let leaf_r_new = Some(proof_r_new.leaf().into());
        let path_r_new: Vec<Vec<Option<F>>> = proof_r_new
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

        // TreeROld and TreeRNew and TreeD have the same shape, thus have the same Merkle path length.
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
            path_d_new: path_r.clone(),
            leaf_r_new: None,
            path_r_new: path_r,
            _tree_r: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct PrivateInputs<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
{
    // CommC created by running SDR-PoRep on the old/un-updated data.
    pub comm_c: Option<F>,
    // Root of the replica tree (called TreeR or TreeRLast) output by SDR-PoRep on the
    // old/un-updated data (here called TreeROld).
    pub root_r_old: Option<F>,
    // Root of the replica tree build over the new/updated data's replica (TreeRNew).
    pub root_r_new: Option<F>,
    // Generate three Merkle proofs (TreeROld, TreeDNew, TreeRNew) for each of this partition's
    // challenges.
    pub challenge_proofs: Vec<ChallengeProof<F, U, V, W>>,
}

impl<F, U, V, W> PrivateInputs<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeRHasher<F>: R1CSHasher<Field = F>,
{
    pub fn new(
        comm_c: TreeRDomain<F>,
        challenge_proofs: &[vanilla::ChallengeProof<F, U, V, W>],
    ) -> Self {
        let root_r_old: F = challenge_proofs[0].proof_r_old.root().into();
        let root_r_new: F = challenge_proofs[0].proof_r_new.root().into();

        let challenge_proofs: Vec<ChallengeProof<F, U, V, W>> = challenge_proofs
            .iter()
            .cloned()
            .map(ChallengeProof::from)
            .collect();

        PrivateInputs {
            comm_c: Some(comm_c.into()),
            root_r_old: Some(root_r_old),
            root_r_new: Some(root_r_new),
            challenge_proofs,
        }
    }

    pub fn empty(sector_nodes: usize) -> Self {
        PrivateInputs {
            comm_c: None,
            root_r_old: None,
            root_r_new: None,
            challenge_proofs: vec![
                ChallengeProof::empty(sector_nodes);
                challenge_count_poseidon(sector_nodes)
            ],
        }
    }
}

pub struct EmptySectorUpdateCircuit<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
{
    pub pub_params: PublicParams,
    pub pub_inputs: PublicInputs<F>,
    pub priv_inputs: PrivateInputs<F, U, V, W>,
}

impl<F, U, V, W> CircuitComponent for EmptySectorUpdateCircuit<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
{
    type ComponentPrivateInputs = ();
}

impl<F, U, V, W> EmptySectorUpdateCircuit<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeRHasher<F>: R1CSHasher<Field = F>,
{
    pub fn blank(pub_params: PublicParams) -> Self {
        let sector_bytes = (pub_params.sector_nodes as u64) << 5;
        assert_eq!(
            PublicParams::from_sector_size_poseidon(sector_bytes),
            pub_params,
            "invalid public-params for sector-size",
        );
        let pub_inputs = PublicInputs::empty();
        let priv_inputs = PrivateInputs::<F, U, V, W>::empty(pub_params.sector_nodes);
        EmptySectorUpdateCircuit {
            pub_params,
            pub_inputs,
            priv_inputs,
        }
    }
}

impl<F, U, V, W> Circuit<F> for EmptySectorUpdateCircuit<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeRHasher<F>: R1CSHasher<Field = F>,
{
    /// This circuit is NOT AUDITED, USE AT YOUR OWN RISK.
    fn synthesize<CS: ConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let EmptySectorUpdateCircuit {
            pub_params: PublicParams { sector_nodes, .. },
            pub_inputs:
                PublicInputs {
                    h_select,
                    comm_r_old,
                    comm_d_new,
                    comm_r_new,
                },
            priv_inputs:
                PrivateInputs {
                    comm_c,
                    root_r_old,
                    root_r_new,
                    challenge_proofs,
                },
        } = self;

        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
        let challenge_count = challenge_count_poseidon(sector_nodes);

        validate_tree_r_shape::<U, V, W>(sector_nodes);
        let hs = hs(sector_nodes);
        let h_select_bit_len = hs.len();

        if let Some(h_select) = h_select {
            let bits: Vec<bool> = h_select
                .to_repr()
                .as_ref()
                .iter()
                .flat_map(|byte| (0..8).map(|i| byte >> i & 1 == 1).collect::<Vec<bool>>())
                .collect();

            // `h_select` should have exactly one bit set.
            let h_select_bits = &bits[..h_select_bit_len];
            assert_eq!(
                h_select_bits.iter().filter(|bit| **bit).count(),
                1,
                "h_select does not have exactly one bit set"
            );
            // The remaining bits should be zero.
            assert!(bits[h_select_bit_len..].iter().all(|bit| !*bit));
        }

        assert_eq!(challenge_proofs.len(), challenge_count);

        // Allocate public-inputs.

        // Add a public-input `h_select`.
        let h_select = AllocatedNum::alloc(cs.namespace(|| "h_select"), || {
            h_select.ok_or(SynthesisError::AssignmentMissing)
        })?;
        h_select.inputize(cs.namespace(|| "h_select (public input)"))?;

        // `h_select` binary decomposition`
        let h_select_bits = {
            let bit_len = h_select_bit_len;

            let bits: Vec<Option<bool>> = if let Some(h_select) = h_select.get_value() {
                h_select
                    .to_repr()
                    .as_ref()
                    .iter()
                    .flat_map(|byte| (0..8).map(|i| byte >> i & 1 == 1).collect::<Vec<bool>>())
                    .take(bit_len)
                    .map(Some)
                    .collect()
            } else {
                vec![None; bit_len]
            };

            let h_select_bits = bits
                .into_iter()
                .enumerate()
                .map(|(i, bit)| {
                    AllocatedBit::alloc(cs.namespace(|| format!("h_select_bit_{}", i)), bit)
                })
                .collect::<Result<Vec<AllocatedBit>, SynthesisError>>()?;

            let mut lc = LinearCombination::<F>::zero();
            let mut pow2 = F::one();
            for bit in h_select_bits.iter() {
                lc = lc + (pow2, bit.get_variable());
                pow2 = pow2.double();
            }
            cs.enforce(
                || "h_select binary decomp",
                |_| lc,
                |lc| lc + CS::one(),
                |lc| lc + h_select.get_variable(),
            );

            h_select_bits
        };

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

        let rc = POSEIDON_CONSTANTS_GEN_RANDOMNESS
            .get::<PoseidonLookup<F, U2>>()
            .expect("arity-2 Poseidon constants not found for field");

        // Compute `phi = H(comm_d_new || comm_r_old)` from public-inputs.
        let phi = poseidon_hash(
            cs.namespace(|| "phi"),
            vec![comm_d_new.clone(), comm_r_old.clone()],
            *rc,
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

        // Assert that the witnessed `root_r_old` and `root_r_new` are consistent with the
        // public `comm_r_old` and `comm_r_new` via `comm_r = H(comm_c || root_r)`.
        let comm_r_old_calc = TreeRHasher::<F>::hash2_circuit(
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
        let comm_r_new_calc = TreeRHasher::<F>::hash2_circuit(
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

        let partition =
            AllocatedNum::alloc(cs.namespace(|| "gen_challenge_bits partition zero"), || {
                Ok(F::zero())
            })?;

        // Generate `challenge_bit_len` number of random bits for each challenge.
        // For each challenge generate a random index in `0..sector_nodes`
        let generated_bits = gen_challenge_bits(
            cs.namespace(|| "gen_challenge_bits"),
            &comm_r_new,
            &partition,
            challenge_count,
            challenge_bit_len,
        )?;

        for (c_index, c_bits) in generated_bits.into_iter().enumerate() {
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
                *rc,
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
                        .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()
                })
                .collect::<Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>>()?;

            por_no_challenge_input::<TreeR<F, U, V, W>, _>(
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
                        .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()
                })
                .collect::<Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>>()?;

            por_no_challenge_input::<TreeR<F, U, V, W>, _>(
                cs.namespace(|| format!("por tree_r_new (c_index={})", c_index)),
                c_bits.clone(),
                leaf_r_new.clone(),
                path_r_new,
                root_r_new.clone(),
            )?;

            let path_d_new = challenge_proof.path_d_new
                .iter()
                .enumerate()
                .map(|(tree_row, siblings)| {
                    siblings
                        .iter()
                        .enumerate()
                        .map(|(sibling_index, sibling)| {
                            AllocatedNum::alloc(
                                cs.namespace(|| format!(
                                    "path_d_new sibling (c_index={}, tree_row={}, sibling_index={})",
                                    c_index,
                                    tree_row,
                                    sibling_index,
                                )),
                                || sibling.ok_or(SynthesisError::AssignmentMissing),
                            )
                        })
                        .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()
                })
                .collect::<Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>>()?;

            por_no_challenge_input::<TreeR<F, U, V, W>, _>(
                cs.namespace(|| format!("por tree_d_new (c_index={})", c_index)),
                c_bits.clone(),
                leaf_d_new.clone(),
                path_d_new,
                comm_d_new.clone(),
            )?;
        }

        Ok(())
    }
}

impl<F, U, V, W> EmptySectorUpdateCircuit<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeRHasher<F>: R1CSHasher<Field = F>,
{
    pub fn generate_public_inputs(
        pub_params: &PublicParams,
        pub_inputs: &vanilla::PublicInputs<F>,
    ) -> storage_proofs_core::error::Result<Vec<F>> {
        let vanilla::PublicInputs {
            comm_r_old,
            comm_d_new,
            comm_r_new,
            h,
        } = *pub_inputs;

        let pub_inputs_circ = PublicInputs::new(
            pub_params.sector_nodes,
            h,
            comm_r_old,
            comm_d_new,
            comm_r_new,
        );

        Ok(pub_inputs_circ.to_vec())
    }
}
