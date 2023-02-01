use std::iter;

use bellperson::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        num::AllocatedNum,
        uint32::UInt32,
    },
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, R1CSHasher};
use storage_proofs_core::{
    gadgets::{por::por_no_challenge_input, uint64::UInt64},
    merkle::{Arity, BinaryMerkleTree, LCTree},
    util::{field_le_bits, reverse_bit_numbering},
};

use crate::stacked::{
    circuit::{create_label_circuit, hash_single_column},
    nova::{ParentProof, DRG_PARENTS, REPEATED_PARENTS, TOTAL_PARENTS},
};

pub fn assign_challenge_bits<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    challenge: &AllocatedNum<F>,
    challenge_bit_len: usize,
) -> Result<Vec<AllocatedBit>, SynthesisError>
where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
{
    let bit_values: Vec<Option<bool>> = match challenge.get_value() {
        Some(ref f) => field_le_bits(f)
            .into_iter()
            .map(Some)
            .take(challenge_bit_len)
            .collect(),
        None => vec![None; challenge_bit_len],
    };

    let bits = bit_values
        .into_iter()
        .enumerate()
        .map(|(bit_index, bit)| {
            AllocatedBit::alloc(
                cs.namespace(|| format!("{} bit_{}", challenge_name, bit_index)),
                bit,
            )
        })
        .collect::<Result<Vec<AllocatedBit>, SynthesisError>>()?;

    let mut lc = LinearCombination::zero();
    let mut coeff = F::one();
    for bit in &bits {
        lc = lc + (coeff, bit.get_variable());
        coeff = coeff.double();
    }
    cs.enforce(
        || format!("{} binary decomp", challenge_name),
        |_| lc,
        |lc| lc + CS::one(),
        |lc| lc + challenge.get_variable(),
    );

    Ok(bits)
}

fn assign_path_cr<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    tree_letter: char,
    path: &[Vec<Option<F>>],
) -> Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    path
        .iter()
        .enumerate()
        .map(|(height, sibs)| {
            sibs.iter()
                .enumerate()
                .map(|(sib_index, sib)| {
                    AllocatedNum::alloc(
                        cs.namespace(|| {
                            format!(
                                "{} path_{} height_{} sib_{}",
                                challenge_name, tree_letter, height, sib_index,
                            )
                        }),
                        || sib.ok_or(SynthesisError::AssignmentMissing),
                    )
                })
                .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()
        })
        .collect::<Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>>()
}

#[inline]
pub fn assign_path_c<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    path: &[Vec<Option<F>>],
) -> Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    assign_path_cr(cs, challenge_name, 'c', path)
}

#[inline]
pub fn assign_path_r<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    path: &[Vec<Option<F>>],
) -> Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    assign_path_cr(cs, challenge_name, 'r', path)
}

pub fn assign_proof_d<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    leaf_d: &Option<F>,
    path_d: &[Option<F>],
) -> Result<(AllocatedNum<F>, Vec<Vec<AllocatedNum<F>>>), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let leaf_d = AllocatedNum::alloc(
        cs.namespace(|| format!("{} leaf_d", challenge_name)),
        || leaf_d.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let path_d = path_d
        .iter()
        .enumerate()
        .map(|(height, sib)| {
            AllocatedNum::alloc(
                cs.namespace(|| format!("{} path_d height_{} sib", challenge_name, height)),
                || sib.ok_or(SynthesisError::AssignmentMissing),
            )
            .map(|sib| vec![sib])
        })
        .collect::<Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>>()?;

    Ok((leaf_d, path_d))
}

#[allow(dead_code)]
fn assign_proof_cr<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    tree_letter: char,
    leaf: &Option<F>,
    path: &[Vec<Option<F>>],
) -> Result<(AllocatedNum<F>, Vec<Vec<AllocatedNum<F>>>), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let leaf = AllocatedNum::alloc(
        cs.namespace(|| format!("{} leaf_{}", challenge_name, tree_letter)),
        || leaf.ok_or(SynthesisError::AssignmentMissing),
    )?;
    let path = assign_path_cr(cs, challenge_name, tree_letter, path)?;
    Ok((leaf, path))
}

#[allow(dead_code)]
#[inline]
fn assign_proof_c<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    leaf: &Option<F>,
    path: &[Vec<Option<F>>],
) -> Result<(AllocatedNum<F>, Vec<Vec<AllocatedNum<F>>>), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    assign_proof_cr(cs, challenge_name, 'c', leaf, path)
}

#[allow(dead_code)]
#[inline]
fn assign_proof_r<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    leaf: &Option<F>,
    path: &[Vec<Option<F>>],
) -> Result<(AllocatedNum<F>, Vec<Vec<AllocatedNum<F>>>), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    assign_proof_cr(cs, challenge_name, 'r', leaf, path)
}

#[inline]
pub fn verify_proof_d<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    challenge_bits: &[AllocatedBit],
    leaf_d: &AllocatedNum<F>,
    path_d: Vec<Vec<AllocatedNum<F>>>,
    comm_d: &AllocatedNum<F>,
) -> Result<(), SynthesisError>
where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
    Sha256Hasher<F>: R1CSHasher<Field = F>,
{
    por_no_challenge_input::<BinaryMerkleTree<Sha256Hasher<F>>, _>(
        cs.namespace(|| format!("{} proof_d", challenge_name)),
        challenge_bits.to_vec(),
        leaf_d.clone(),
        path_d,
        comm_d.clone(),
    )
}

#[inline]
pub fn verify_proof_c<F, A, CS>(
    cs: &mut CS,
    challenge_name: &str,
    challenge_bits: &[AllocatedBit],
    leaf_c: &AllocatedNum<F>,
    path_c: Vec<Vec<AllocatedNum<F>>>,
    comm_c: &AllocatedNum<F>,
) -> Result<(), SynthesisError>
where
    F: PrimeField + PrimeFieldBits,
    A: Arity<F>,
    CS: ConstraintSystem<F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>,
{
    por_no_challenge_input::<LCTree<PoseidonHasher<F>, A::U, A::V, A::W>, _>(
        cs.namespace(|| format!("{} proof_c", challenge_name)),
        challenge_bits.to_vec(),
        leaf_c.clone(),
        path_c,
        comm_c.clone(),
    )
}

#[inline]
pub fn verify_proof_r<F, A, CS>(
    cs: &mut CS,
    challenge_name: &str,
    challenge_bits: &[AllocatedBit],
    leaf_r: &AllocatedNum<F>,
    path_r: Vec<Vec<AllocatedNum<F>>>,
    root_r: &AllocatedNum<F>,
) -> Result<(), SynthesisError>
where
    F: PrimeField + PrimeFieldBits,
    A: Arity<F>,
    CS: ConstraintSystem<F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>,
{
    por_no_challenge_input::<LCTree<PoseidonHasher<F>, A::U, A::V, A::W>, _>(
        cs.namespace(|| format!("{} proof_r", challenge_name)),
        challenge_bits.to_vec(),
        leaf_r.clone(),
        path_r,
        root_r.clone(),
    )
}

#[inline]
fn assign_column<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    column: &[Option<F>],
) -> Result<Vec<AllocatedNum<F>>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    column
        .iter()
        .enumerate()
        .map(|(layer_index, label)| {
            AllocatedNum::alloc(
                cs.namespace(|| format!("{} column layer_{}", challenge_name, layer_index)),
                || label.ok_or(SynthesisError::AssignmentMissing),
            )
        })
        .collect()
}

pub fn assign_parent_proofs<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    drg_proofs: &[ParentProof<F>],
    exp_proofs: &[ParentProof<F>],
) -> Result<
    (
        Vec<Vec<AllocatedNum<F>>>,
        Vec<Vec<AllocatedNum<F>>>,
        Vec<Vec<Vec<AllocatedNum<F>>>>,
        Vec<Vec<Vec<AllocatedNum<F>>>>,
    ),
    SynthesisError,
>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let drg_columns = drg_proofs
        .iter()
        .enumerate()
        .map(|(drg_parent_index, parent_proof)| {
            let parent_name = format!("{} drg_parent_{}", challenge_name, drg_parent_index);
            assign_column(cs, &parent_name, &parent_proof.column)
        })
        .collect::<Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>>()?;

    let exp_columns = exp_proofs
        .iter()
        .enumerate()
        .map(|(exp_parent_index, parent_proof)| {
            let parent_name = format!("{} exp_parent_{}", challenge_name, exp_parent_index);
            assign_column(cs, &parent_name, &parent_proof.column)
        })
        .collect::<Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>>()?;

    let drg_paths_c = drg_proofs
        .iter()
        .enumerate()
        .map(|(drg_parent_index, parent_proof)| {
            let parent_name = format!("{} drg_parent_{}", challenge_name, drg_parent_index);
            assign_path_c(cs, &parent_name, &parent_proof.path_c)
        })
        .collect::<Result<Vec<Vec<Vec<AllocatedNum<F>>>>, SynthesisError>>()?;

    let exp_paths_c = exp_proofs
        .iter()
        .enumerate()
        .map(|(exp_parent_index, parent_proof)| {
            let parent_name = format!("{} exp_parent_{}", challenge_name, exp_parent_index);
            assign_path_c(cs, &parent_name, &parent_proof.path_c)
        })
        .collect::<Result<Vec<Vec<Vec<AllocatedNum<F>>>>, SynthesisError>>()?;

    Ok((drg_columns, exp_columns, drg_paths_c, exp_paths_c))
}

#[inline]
pub fn hash_column<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    column: &[AllocatedNum<F>],
) -> Result<AllocatedNum<F>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    hash_single_column(cs.namespace(|| format!("{} column hash", challenge_name)), column)
}

pub fn hash_parent_columns<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    drg_columns: &[Vec<AllocatedNum<F>>],
    exp_columns: &[Vec<AllocatedNum<F>>],
) -> Result<(Vec<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let drg_leafs_c = drg_columns
        .iter()
        .enumerate()
        .map(|(drg_parent_index, column)| {
            let parent_name = format!("{} drg_parent_{}", challenge_name, drg_parent_index);
            hash_column(cs, &parent_name, column)
        })
        .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;

    let exp_leafs_c = exp_columns
        .iter()
        .enumerate()
        .map(|(exp_parent_index, column)| {
            let parent_name = format!("{} exp_parent_{}", challenge_name, exp_parent_index);
            hash_column(cs, &parent_name, column)
        })
        .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;

    Ok((drg_leafs_c, exp_leafs_c))
}

pub fn create_label<F, CS>(
    cs: CS,
    replica_id: &[Boolean],
    parent_labels: &[Vec<Boolean>],
    layer_index: usize,
    // Least significant bit first.
    challenge_bits: &[AllocatedBit],
) -> Result<AllocatedNum<F>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    if layer_index == 0 {
        assert_eq!(parent_labels.len(), DRG_PARENTS);
    } else {
        assert_eq!(parent_labels.len(), TOTAL_PARENTS);
    }
    assert!(challenge_bits.len() <= 32);

    let replica_id = reverse_bit_numbering(replica_id.to_vec());
    assert_eq!(replica_id.len(), 256);

    let repeated_parent_labels: Vec<Vec<Boolean>> = parent_labels
        .iter()
        .cloned()
        .map(reverse_bit_numbering)
        .cycle()
        .take(REPEATED_PARENTS)
        .collect();
    assert!(repeated_parent_labels
        .iter()
        .all(|label_bits| label_bits.len() == 256));

    let layer_index = UInt32::constant(layer_index as u32 + 1);
    let challenge_bits: Vec<Boolean> = challenge_bits
        .iter()
        .cloned()
        .map(Boolean::from)
        .chain(iter::repeat(Boolean::Constant(false)))
        .take(64)
        .collect();
    let challenge_u64 = UInt64::from_bits(&challenge_bits);
    create_label_circuit(cs, &replica_id, repeated_parent_labels, layer_index, challenge_u64)
}
