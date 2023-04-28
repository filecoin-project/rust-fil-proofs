use std::iter;
use std::marker::PhantomData;

use bellperson::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        num::AllocatedNum,
        uint32::UInt32,
    },
    ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher, PoseidonArity};
use storage_proofs_core::{
    gadgets::{
        boolean::assign_bits,
        encode::encode,
        por::{assign_path, por_no_challenge_input},
        uint64::UInt64,
    },
    merkle::{BinaryMerkleTree, LCTree},
    util::reverse_bit_numbering,
};

use crate::stacked::{
    circuit::{create_label_circuit, hash_single_column},
    nova::{ChallengeProof, DRG_PARENTS, EXP_PARENTS, REPEATED_PARENTS, TOTAL_PARENTS},
};

#[inline]
fn assign_column<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    col: &[F],
) -> Result<Vec<AllocatedNum<F>>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    col
        .iter()
        .enumerate()
        .map(|(layer_index, label)| {
            AllocatedNum::alloc(
                cs.namespace(|| format!("{} column layer_{}", challenge_name, layer_index)),
                || Ok(*label),
            )
        })
        .collect()
}

pub struct ChallengeCircuit<'a, F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
{
    pub challenge_name: String,
    pub challenge: &'a AllocatedNum<F>,
    pub parents: &'a [AllocatedNum<F>],
    pub challenge_proof: &'a ChallengeProof<F>,
    pub _a: PhantomData<(U, V, W)>,
}

impl<'a, F, U, V, W> ChallengeCircuit<'a, F, U, V, W>
where
    F: PrimeFieldBits,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    #[inline]
    pub fn new(
        challenge_index: usize,
        challenge: &'a AllocatedNum<F>,
        parents: &'a [AllocatedNum<F>],
        challenge_proof: &'a ChallengeProof<F>,
    ) -> Self {
        ChallengeCircuit {
            challenge_name: format!("challenge_{}", challenge_index),
            challenge,
            parents,
            challenge_proof,
            _a: PhantomData,
        }
    }

    #[inline]
    pub fn assign_challenge_bits<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        challenge_bit_len: usize,
    ) -> Result<Vec<AllocatedBit>, SynthesisError> {
        assign_bits(cs, &self.challenge_name, self.challenge, challenge_bit_len)
    }

    #[inline]
    pub fn assign_parents_bits<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        challenge_bit_len: usize,
    ) -> Result<Vec<Vec<AllocatedBit>>, SynthesisError> {
        self.parents
            .iter()
            .enumerate()
            .map(|(parent_index, parent)| {
                let parent_name = format!("{} parent_{}", self.challenge_name, parent_index);
                assign_bits(cs, &parent_name, parent, challenge_bit_len)
            })
            .collect()
    }

    #[inline]
    pub fn assign_leaf_d<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        AllocatedNum::alloc(
            cs.namespace(|| format!("{} leaf_d", self.challenge_name)),
            || Ok(self.challenge_proof.leaf_d),
        )
    }

    #[inline]
    pub fn assign_path_d<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        self.challenge_proof
            .path_d
            .iter()
            .enumerate()
            .map(|(height, sib)| {
                AllocatedNum::alloc(
                    cs.namespace(|| {
                        format!("{} path_d height_{} sib", self.challenge_name, height)
                    }),
                    || Ok(*sib),
                )
            })
            .collect()
    }

    #[inline]
    pub fn assign_path_c<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError> {
        assign_path(
            cs,
            &format!("{} path_c", self.challenge_name),
            &self.challenge_proof.path_c,
        )
    }

    #[inline]
    pub fn assign_path_r<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError> {
        assign_path(
            cs,
            &format!("{} path_r", self.challenge_name),
            &self.challenge_proof.path_r,
        )
    }

    #[inline]
    pub fn verify_proof_d<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        challenge_bits: &[AllocatedBit],
        leaf_d: &AllocatedNum<F>,
        path_d: &[AllocatedNum<F>],
        comm_d: &AllocatedNum<F>,
    ) -> Result<(), SynthesisError> {
        por_no_challenge_input::<BinaryMerkleTree<Sha256Hasher<F>>, _>(
            cs.namespace(|| format!("{} proof_d", self.challenge_name)),
            challenge_bits.to_vec(),
            leaf_d.clone(),
            path_d.iter().cloned().map(|sib| vec![sib]).collect(),
            comm_d.clone(),
        )
    }

    #[inline]
    pub fn verify_proof_c<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        challenge_bits: &[AllocatedBit],
        leaf_c: &AllocatedNum<F>,
        path_c: &[Vec<AllocatedNum<F>>],
        comm_c: &AllocatedNum<F>,
    ) -> Result<(), SynthesisError> {
        por_no_challenge_input::<LCTree<PoseidonHasher<F>, U, V, W>, _>(
            cs.namespace(|| format!("{} proof_c", self.challenge_name)),
            challenge_bits.to_vec(),
            leaf_c.clone(),
            path_c.to_vec(),
            comm_c.clone(),
        )
    }

    #[inline]
    pub fn verify_proof_r<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        challenge_bits: &[AllocatedBit],
        leaf_r: &AllocatedNum<F>,
        path_r: &[Vec<AllocatedNum<F>>],
        root_r: &AllocatedNum<F>,
    ) -> Result<(), SynthesisError> {
        por_no_challenge_input::<LCTree<PoseidonHasher<F>, U, V, W>, _>(
            cs.namespace(|| format!("{} proof_r", self.challenge_name)),
            challenge_bits.to_vec(),
            leaf_r.clone(),
            path_r.to_vec(),
            root_r.clone(),
        )
    }

    pub fn assign_parent_paths_c<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> Result<(Vec<Vec<Vec<AllocatedNum<F>>>>, Vec<Vec<Vec<AllocatedNum<F>>>>), SynthesisError> {
        let drg_paths_c = self.challenge_proof.drg_parent_proofs
            .iter()
            .enumerate()
            .map(|(parent_index, parent_proof)| {
                assign_path(
                    cs,
                    &format!("{} drg_parent_{} path_c", self.challenge_name, parent_index),
                    &parent_proof.path_c,
                )
            })
            .collect::<Result<Vec<Vec<Vec<AllocatedNum<F>>>>, SynthesisError>>()?;

        let exp_paths_c = self.challenge_proof.exp_parent_proofs
            .iter()
            .enumerate()
            .map(|(parent_index, parent_proof)| {
                assign_path(
                    cs,
                    &format!("{} exp_parent_{} path_c", self.challenge_name, parent_index),
                    &parent_proof.path_c,
                )
            })
            .collect::<Result<Vec<Vec<Vec<AllocatedNum<F>>>>, SynthesisError>>()?;

        Ok((drg_paths_c, exp_paths_c))
    }

    pub fn verify_parent_proofs_c<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        parents_bits: &[Vec<AllocatedBit>],
        (drg_leafs_c, exp_leafs_c): &(Vec<AllocatedNum<F>>, Vec<AllocatedNum<F>>),
        (drg_paths_c, exp_paths_c): &(
            Vec<Vec<Vec<AllocatedNum<F>>>>,
            Vec<Vec<Vec<AllocatedNum<F>>>>,
        ),
        comm_c: &AllocatedNum<F>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(parents_bits.len(), TOTAL_PARENTS);
        assert!([drg_leafs_c.len(), drg_paths_c.len()].iter().all(|len| *len == DRG_PARENTS));
        assert!([exp_leafs_c.len(), exp_paths_c.len()].iter().all(|len| *len == EXP_PARENTS));

        for (parent_index, ((parent_bits, leaf_c), path_c)) in
            parents_bits.iter().zip(drg_leafs_c).zip(drg_paths_c).enumerate()
        {
            por_no_challenge_input::<LCTree<PoseidonHasher<F>, U, V, W>, _>(
                cs.namespace(|| {
                    format!("{} drg_parent_{} proof_c", self.challenge_name, parent_index)
                }),
                parent_bits.to_vec(),
                leaf_c.clone(),
                path_c.to_vec(),
                comm_c.clone(),
            )?;
        }

        for (parent_index, ((parent_bits, leaf_c), path_c)) in
            parents_bits.iter().skip(DRG_PARENTS).zip(exp_leafs_c).zip(exp_paths_c).enumerate()
        {
            por_no_challenge_input::<LCTree<PoseidonHasher<F>, U, V, W>, _>(
                cs.namespace(|| {
                    format!("{} exp_parent_{} proof_c", self.challenge_name, parent_index)
                }),
                parent_bits.to_vec(),
                leaf_c.clone(),
                path_c.to_vec(),
                comm_c.clone(),
            )?;
        }

        Ok(())
    }

    #[inline]
    pub fn hash_col<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        col: &[AllocatedNum<F>],
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        hash_single_column(cs.namespace(|| format!("{} column hash", self.challenge_name)), col)
    }

    pub fn assign_parent_cols<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> Result<(Vec<Vec<AllocatedNum<F>>>, Vec<Vec<AllocatedNum<F>>>), SynthesisError> {
        let drg_cols = self.challenge_proof.drg_parent_proofs
            .iter()
            .enumerate()
            .map(|(parent_index, parent_proof)| {
                assign_column(
                    cs,
                    &format!("{} drg_parent_{}", self.challenge_name, parent_index),
                    &parent_proof.column,
                )
            })
            .collect::<Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>>()?;

        let exp_cols = self.challenge_proof.exp_parent_proofs
            .iter()
            .enumerate()
            .map(|(parent_index, parent_proof)| {
                assign_column(
                    cs,
                    &format!("{} exp_parent_{}", self.challenge_name, parent_index),
                    &parent_proof.column,
                )
            })
            .collect::<Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>>()?;

        Ok((drg_cols, exp_cols))
    }

    pub fn hash_parent_cols<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        (drg_cols, exp_cols): &(Vec<Vec<AllocatedNum<F>>>, Vec<Vec<AllocatedNum<F>>>),
    ) -> Result<(Vec<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
        let drg_leafs_c = drg_cols
            .iter()
            .enumerate()
            .map(|(parent_index, col)| {
                hash_single_column(
                    cs.namespace(|| {
                        format!("{} drg_parent_{} column hash", self.challenge_name, parent_index)
                    }),
                    col,
                )
            })
            .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;

        let exp_leafs_c = exp_cols
            .iter()
            .enumerate()
            .map(|(parent_index, col)| {
                hash_single_column(
                    cs.namespace(|| {
                        format!("{} exp_parent_{} column hash", self.challenge_name, parent_index)
                    }),
                    col,
                )
            })
            .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;

        Ok((drg_leafs_c, exp_leafs_c))
    }

    pub fn create_labels<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        replica_id_bits: &[Boolean],
        challenge_bits: &[AllocatedBit],
        (drg_cols, exp_cols): &(Vec<Vec<AllocatedNum<F>>>, Vec<Vec<AllocatedNum<F>>>),
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert_eq!(replica_id_bits.len(), 256);
        assert!(challenge_bits.len() <= 32);
        assert_eq!(drg_cols.len(), DRG_PARENTS);
        assert_eq!(exp_cols.len(), EXP_PARENTS);
        let num_layers = drg_cols[0].len();
        assert!(drg_cols.iter().skip(1).chain(exp_cols).all(|col| col.len() == num_layers));

        (0..num_layers)
            .map(|layer_index| {
                let layer = UInt32::constant(layer_index as u32 + 1);

                let challenge_bits: Vec<Boolean> = challenge_bits
                    .iter()
                    .cloned()
                    .map(Boolean::from)
                    .chain(iter::repeat(Boolean::Constant(false)))
                    .take(64)
                    .collect();

                let challenge = UInt64::from_bits(&challenge_bits);

                let mut parent_labels = drg_cols
                    .iter()
                    .enumerate()
                    .map(|(parent_index, col)| {
                        col[layer_index].to_bits_le(cs.namespace(|| format!(
                            "{} drg_parent_{} layer_{} label bits",
                            self.challenge_name, parent_index, layer_index,
                        )))
                    })
                    .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?;

                if layer_index != 0 {
                    for (parent_index, col) in exp_cols.iter().enumerate() {
                        let prev_layer_index = layer_index - 1;
                        let label = col[prev_layer_index].to_bits_le(cs.namespace(|| format!(
                            "{} exp_parent_{} layer_{} label bits",
                            self.challenge_name, parent_index, prev_layer_index,
                        )))?;
                        parent_labels.push(label);
                    }
                }

                let repeated_parent_labels: Vec<Vec<Boolean>> = parent_labels
                    .iter()
                    .cloned()
                    .map(reverse_bit_numbering)
                    .cycle()
                    .take(REPEATED_PARENTS)
                    .collect();

                create_label_circuit(
                    cs.namespace(|| format!("{} layer_{} label", self.challenge_name, layer_index)),
                    replica_id_bits,
                    repeated_parent_labels,
                    layer,
                    challenge,
                )
            })
            .collect()
    }

    #[inline]
    pub fn encode<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        key: &AllocatedNum<F>,
        leaf_d: &AllocatedNum<F>,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        encode(cs.namespace(|| format!("{} leaf_r", self.challenge_name)), key, leaf_d)
    }
}
