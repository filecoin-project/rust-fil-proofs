use bellperson::{
    gadgets::{
        boolean::{field_into_allocated_bits_le, AllocatedBit, Boolean},
        num::AllocatedNum,
    },
    ConstraintSystem, LinearCombination, SynthesisError,
};
use blstrs::{Bls12, Scalar as Fr};
use ff::{Field, PrimeField};
use filecoin_hashers::{HashFunction, Hasher};
use generic_array::typenum::Unsigned;
use storage_proofs_core::{gadgets::insertion::insert, merkle::MerkleTreeTrait};

// Allocates `num` as `Fr::NUM_BITS` number of bits.
pub fn allocated_num_to_allocated_bits<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    num: &AllocatedNum<Bls12>,
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    let bits = field_into_allocated_bits_le(&mut cs, num.get_value())?;
    assert_eq!(bits.len(), Fr::NUM_BITS as usize);

    // Assert `(2^0 * bits[0] + ... + 2^(n - 1) * bits[n]) * 1 == num`.
    let mut lc = LinearCombination::<Bls12>::zero();
    let mut pow2 = Fr::one();
    for bit in bits.iter() {
        lc = lc + (pow2, bit.get_variable());
        pow2.double();
    }
    cs.enforce(
        || "binary decomp",
        |_| lc,
        |lc| lc + CS::one(),
        |lc| lc + num.get_variable(),
    );

    Ok(bits)
}

pub fn por_no_challenge_input<Tree, CS>(
    mut cs: CS,
    // little-endian
    c_bits: Vec<AllocatedBit>,
    leaf: AllocatedNum<Bls12>,
    path_values: Vec<Vec<AllocatedNum<Bls12>>>,
    root: AllocatedNum<Bls12>,
) -> Result<(), SynthesisError>
where
    Tree: MerkleTreeTrait,
    CS: ConstraintSystem<Bls12>,
{
    // This function assumes that `Tree`'s shape is valid, e.g. `base_arity > 0`, `if top_arity > 0
    // then sub_arity > 0`, all arities are a power of two, etc., and that `path_values` corresponds
    // to the tree arities.
    let base_arity = Tree::Arity::to_usize();
    let sub_arity = Tree::SubTreeArity::to_usize();
    let top_arity = Tree::TopTreeArity::to_usize();

    let base_arity_bit_len = base_arity.trailing_zeros();
    let sub_arity_bit_len = sub_arity.trailing_zeros();
    let top_arity_bit_len = top_arity.trailing_zeros();

    let base_path_len = path_values
        .iter()
        .take_while(|siblings| siblings.len() == base_arity - 1)
        .count();

    let mut cur = leaf;
    let mut height = 0;
    let mut path_values = path_values.into_iter();
    let mut c_bits = c_bits.into_iter().map(Boolean::from);

    // Hash base-tree Merkle proof elements.
    for _ in 0..base_path_len {
        let siblings = path_values.next().expect("no path elements remaining");
        assert_eq!(
            siblings.len(),
            base_arity - 1,
            "path element has incorrect number of siblings"
        );
        let insert_index: Vec<Boolean> = (0..base_arity_bit_len)
            .map(|_| c_bits.next().expect("no challenge bits remaining"))
            .collect();
        let preimg = insert(
            &mut cs.namespace(|| format!("merkle proof insert (height={})", height)),
            &cur,
            &insert_index,
            &siblings,
        )?;
        cur = <<Tree::Hasher as Hasher>::Function as HashFunction<
            <Tree::Hasher as Hasher>::Domain,
        >>::hash_multi_leaf_circuit::<Tree::Arity, _>(
            cs.namespace(|| format!("merkle proof hash (height={})", height)),
            &preimg,
            height,
        )?;
        height += 1;
    }

    // If one exists, hash the sub-tree Merkle proof element.
    if sub_arity > 0 {
        let siblings = path_values.next().expect("no path elements remaining");
        assert_eq!(
            siblings.len(),
            sub_arity - 1,
            "path element has incorrect number of siblings"
        );
        let insert_index: Vec<Boolean> = (0..sub_arity_bit_len)
            .map(|_| c_bits.next().expect("no challenge bits remaining"))
            .collect();
        let preimg = insert(
            &mut cs.namespace(|| format!("merkle proof insert (height={})", height)),
            &cur,
            &insert_index,
            &siblings,
        )?;
        cur = <<Tree::Hasher as Hasher>::Function as HashFunction<
            <Tree::Hasher as Hasher>::Domain,
        >>::hash_multi_leaf_circuit::<Tree::SubTreeArity, _>(
            cs.namespace(|| format!("merkle proof hash (height={})", height)),
            &preimg,
            height,
        )?;
        height += 1;
    }

    // If one exists, hash the top-tree Merkle proof element.
    if top_arity > 0 {
        let siblings = path_values.next().expect("no path elements remaining");
        assert_eq!(
            siblings.len(),
            top_arity - 1,
            "path element has incorrect number of siblings"
        );
        let insert_index: Vec<Boolean> = (0..top_arity_bit_len)
            .map(|_| c_bits.next().expect("no challenge bits remaining"))
            .collect();
        let preimg = insert(
            &mut cs.namespace(|| format!("merkle proof insert (height={})", height)),
            &cur,
            &insert_index,
            &siblings,
        )?;
        cur = <<Tree::Hasher as Hasher>::Function as HashFunction<
            <Tree::Hasher as Hasher>::Domain,
        >>::hash_multi_leaf_circuit::<Tree::TopTreeArity, _>(
            cs.namespace(|| format!("merkle proof hash (height={})", height)),
            &preimg,
            height,
        )?;
    }

    // Check that no additional challenge bits were provided.
    assert!(
        c_bits.next().is_none(),
        "challenge bit-length and tree arity do not agree"
    );

    // Assert equality between the computed root and the provided root.
    let computed_root = cur;

    cs.enforce(
        || "calculated root == provided root",
        |lc| lc + computed_root.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + root.get_variable(),
    );

    Ok(())
}
