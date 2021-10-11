use bellperson::{
    gadgets::{
        boolean::{field_into_allocated_bits_le, AllocatedBit, Boolean},
        multipack::pack_bits,
        num::AllocatedNum,
    },
    ConstraintSystem, LinearCombination, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::{Field, PrimeField};
use filecoin_hashers::{poseidon::PoseidonHasher, HashFunction, Hasher};
use generic_array::typenum::Unsigned;
use storage_proofs_core::{gadgets::insertion::insert, merkle::MerkleTreeTrait};

use crate::constants::{TreeD, TreeDHasher};

// Allocates `num` as `Fr::NUM_BITS` number of bits.
pub fn allocated_num_to_allocated_bits<CS: ConstraintSystem<Fr>>(
    mut cs: CS,
    num: &AllocatedNum<Fr>,
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    let bits = field_into_allocated_bits_le(&mut cs, num.get_value())?;
    assert_eq!(bits.len(), Fr::NUM_BITS as usize);

    // Assert `(2^0 * bits[0] + ... + 2^(n - 1) * bits[n]) * 1 == num`.
    let mut lc = LinearCombination::<Fr>::zero();
    let mut pow2 = Fr::one();
    for bit in bits.iter() {
        lc = lc + (pow2, bit.get_variable());
        pow2 = pow2.double();
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
    leaf: AllocatedNum<Fr>,
    path_values: Vec<Vec<AllocatedNum<Fr>>>,
    root: AllocatedNum<Fr>,
) -> Result<(), SynthesisError>
where
    Tree: MerkleTreeTrait,
    CS: ConstraintSystem<Fr>,
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

    let base_path_len = if top_arity > 0 {
        path_values.len() - 2
    } else if sub_arity > 0 {
        path_values.len() - 1
    } else {
        path_values.len()
    };

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

    // Sanity check that no additional challenge bits were provided.
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

pub fn apex_por<CS: ConstraintSystem<Fr>>(
    mut cs: CS,
    apex_leafs: Vec<AllocatedNum<Fr>>,
    partition_bits: Vec<AllocatedBit>,
    partition_path: Vec<Vec<AllocatedNum<Fr>>>,
    comm_d: AllocatedNum<Fr>,
) -> Result<(), SynthesisError> {
    // `apex_leafs.len()` is guaranteed to be a power of two.
    let apex_height = apex_leafs.len().trailing_zeros() as usize;
    let mut apex_tree = vec![apex_leafs];
    for row_index in 0..apex_height {
        let row = apex_tree
            .last()
            .unwrap()
            .chunks(2)
            .enumerate()
            .map(|(i, siblings)| {
                <TreeDHasher as Hasher>::Function::hash2_circuit(
                    cs.namespace(|| {
                        format!(
                            "apex_tree generation hash (tree_row={}, siblings={})",
                            row_index, i,
                        )
                    }),
                    &siblings[0],
                    &siblings[1],
                )
            })
            .collect::<Result<Vec<AllocatedNum<Fr>>, SynthesisError>>()?;
        apex_tree.push(row);
    }

    // This partition's apex-tree root.
    let partition_label = apex_tree.last().unwrap()[0].clone();

    por_no_challenge_input::<TreeD, _>(
        cs.namespace(|| "partition-tree por"),
        partition_bits,
        partition_label,
        partition_path,
        comm_d,
    )
}

// Generates the bits for this partition's challenges.
pub fn gen_challenge_bits<CS: ConstraintSystem<Fr>>(
    mut cs: CS,
    comm_r_new: &AllocatedNum<Fr>,
    partition: &AllocatedNum<Fr>,
    challenges: usize,
    bits_per_challenge: usize,
) -> Result<Vec<Vec<AllocatedBit>>, SynthesisError> {
    // The number of challenges derived per digest.
    let challenges_per_digest = Fr::CAPACITY as usize / bits_per_challenge;

    // The number of digests generated per partition.
    let digests_per_partition = (challenges as f32 / challenges_per_digest as f32).ceil() as u64;

    let mut generated_bits = Vec::with_capacity(challenges);

    for j in 0..digests_per_partition {
        // The index of the current digest across all partition proofs:
        // `digest_index = k * digests_per_partition + j`.
        let digest_index =
            AllocatedNum::alloc(cs.namespace(|| format!("digest_index_{}", j)), || {
                let k = partition
                    .get_value()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                let digest_index = k * Fr::from(digests_per_partition) + Fr::from(j);
                Ok(digest_index)
            })?;

        // `digests_per_partition` and `j` are (unallocated) constants.
        cs.enforce(
            || format!("digest_index_{} == k * digests_per_partition + {}", j, j),
            |lc| {
                lc + (Fr::from(digests_per_partition), partition.get_variable())
                    + (Fr::from(j), CS::one())
            },
            |lc| lc + CS::one(),
            |lc| lc + digest_index.get_variable(),
        );

        // `digest = H(comm_r_new || digest_index)`
        let digest = <PoseidonHasher as Hasher>::Function::hash2_circuit(
            cs.namespace(|| format!("digest_{}", j)),
            &comm_r_new,
            &digest_index,
        )?;

        // Allocate `digest` as `Fr::NUM_BITS` bits.
        let digest_bits = allocated_num_to_allocated_bits(
            cs.namespace(|| format!("digest_{}_bits", j)),
            &digest,
        )?;

        // We may not take all available challenge bits from the last digest.
        let challenges_to_take = if j == digests_per_partition - 1 {
            challenges - generated_bits.len()
        } else {
            challenges_per_digest
        };

        digest_bits
            .chunks(bits_per_challenge)
            .take(challenges_to_take)
            .for_each(|bits| {
                generated_bits.push(bits.to_vec());
            });
    }

    Ok(generated_bits)
}

pub fn get_challenge_high_bits<CS: ConstraintSystem<Fr>>(
    mut cs: CS,
    // little-endian
    c_bits: &[AllocatedBit],
    h_select_bits: &[AllocatedBit],
    hs: &[usize],
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    assert_eq!(h_select_bits.len(), hs.len());

    let bit_len = c_bits.len();

    let c_bits: Vec<Boolean> = c_bits.iter().cloned().map(Into::into).collect();

    // For each `h in hs`, get the `h` high bits of the challenge's bits. Scale each "high" value by
    // the corresponding bit of `h_select` producing a vector containing `hs.len() - 1` zeros and 1
    // "high" value selected via `h_select_bits`.
    let c_high_and_zeros = hs
        .iter()
        .zip(h_select_bits.iter())
        .enumerate()
        .map(|(k, (h, h_select_bit))| {
            // Pack the `h` high bits of `c` into a field element.
            let c_high = pack_bits(
                cs.namespace(|| format!("c_high (h={}, k={})", h, k)),
                &c_bits[bit_len - h..],
            )?;

            // `c_high * h_select_bit`
            let c_high_or_zero = AllocatedNum::alloc(
                cs.namespace(|| format!("c_high_or_zero (h={}, k={})", h, k)),
                || {
                    if h_select_bit
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?
                    {
                        c_high.get_value().ok_or(SynthesisError::AssignmentMissing)
                    } else {
                        Ok(Fr::zero())
                    }
                },
            )?;

            cs.enforce(
                || format!("c_high_or_zero == c_high * h_select_bit (h={}, k={})", h, k),
                |lc| lc + c_high.get_variable(),
                |lc| lc + h_select_bit.get_variable(),
                |lc| lc + c_high_or_zero.get_variable(),
            );

            Ok(c_high_or_zero)
        })
        .collect::<Result<Vec<AllocatedNum<Fr>>, SynthesisError>>()?;

    // Summate the scaled `c_high` values. One of the values is the selected `c_high` (chosen
    // via `h_select`) and all other values are zero. Thus, the sum is the selected `c_high`.
    let c_high_selected = AllocatedNum::alloc(cs.namespace(|| "c_high_selected"), || {
        let mut sum = c_high_and_zeros[0]
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        for c_high_or_zero in &c_high_and_zeros[1..] {
            sum += c_high_or_zero
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
        }
        Ok(sum)
    })?;

    cs.enforce(
        || "c_high_selected == dot(c_highs, h_select_bits)",
        |mut lc| {
            for c_high_or_zero in c_high_and_zeros.iter() {
                lc = lc + c_high_or_zero.get_variable();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + c_high_selected.get_variable(),
    );

    Ok(c_high_selected)
}

pub fn label_r_new<CS: ConstraintSystem<Fr>>(
    mut cs: CS,
    label_r_old: &AllocatedNum<Fr>,
    label_d_new: &AllocatedNum<Fr>,
    rho: &AllocatedNum<Fr>,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let label_d_new_rho = label_d_new.mul(cs.namespace(|| "label_d_new * rho"), rho)?;

    // `label_r_new = label_r_old + label_d_new * rho`
    let label_r_new = AllocatedNum::alloc(cs.namespace(|| "label_r_new"), || {
        let label_r_old = label_r_old
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        let label_d_new_rho = label_d_new_rho
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        Ok(label_r_old + label_d_new_rho)
    })?;

    cs.enforce(
        || "label_r_new == label_r_old + label_d_new * rho",
        |lc| lc + label_r_old.get_variable() + label_d_new_rho.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + label_r_new.get_variable(),
    );

    Ok(label_r_new)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use filecoin_hashers::Domain;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::TEST_SEED;

    use crate::{
        challenges::Challenges,
        constants::{
            apex_leaf_count, challenge_count, partition_count, TreeDDomain, TreeDHasher,
            TreeRDomain, ALLOWED_SECTOR_SIZES, SECTOR_SIZE_16_KIB, SECTOR_SIZE_1_KIB,
            SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB, SECTOR_SIZE_8_KIB,
        },
    };

    #[test]
    fn test_gen_challenge_bits_gadget() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        for sector_nodes in ALLOWED_SECTOR_SIZES.iter().copied() {
            let comm_r_new = TreeRDomain::random(&mut rng);

            let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
            let partition_count = partition_count(sector_nodes);
            let partition_bit_len = partition_count.trailing_zeros() as usize;
            let rand_challenge_bits = challenge_bit_len - partition_bit_len;
            let challenge_count = challenge_count(sector_nodes);

            for k in 0..partition_count {
                let challenges: Vec<usize> = Challenges::new(sector_nodes, comm_r_new, k).collect();

                let mut cs = TestConstraintSystem::<Fr>::new();
                let comm_r_new =
                    AllocatedNum::alloc(cs.namespace(|| "comm_r_new"), || Ok(comm_r_new.into()))
                        .unwrap();
                let partition =
                    AllocatedNum::alloc(cs.namespace(|| "k"), || Ok(Fr::from(k as u64))).unwrap();
                let partition_bits: Vec<AllocatedBit> =
                    allocated_num_to_allocated_bits(cs.namespace(|| "partition_bits"), &partition)
                        .unwrap()
                        .into_iter()
                        .take(partition_bit_len)
                        .collect();
                let generated_bits = gen_challenge_bits(
                    cs.namespace(|| "gen_challenge_bits"),
                    &comm_r_new,
                    &partition,
                    challenge_count,
                    rand_challenge_bits,
                )
                .unwrap();

                for (c, c_generated_bits) in challenges.into_iter().zip(generated_bits.into_iter())
                {
                    assert_eq!(c_generated_bits.len(), rand_challenge_bits);
                    let mut c_circ: usize = 0;
                    for (i, bit) in c_generated_bits
                        .iter()
                        .chain(partition_bits.iter())
                        .enumerate()
                    {
                        if bit.get_value().unwrap() {
                            c_circ |= 1 << i;
                        }
                    }
                    assert_eq!(c, c_circ);
                }
            }
        }
    }

    fn test_apex_por_gadget(
        sector_nodes: usize,
        partition_count: usize,
        apex_leafs_per_partition: usize,
    ) {
        let height = sector_nodes.trailing_zeros() as usize;
        let partition_bit_len = partition_count.trailing_zeros() as usize;
        let apex_tree_height = apex_leafs_per_partition.trailing_zeros() as usize;
        let apex_leafs_total = partition_count * apex_leafs_per_partition;

        let tree_d: Vec<Vec<TreeDDomain>> = {
            let mut rng = XorShiftRng::from_seed(TEST_SEED);
            let leafs: Vec<TreeDDomain> = (0..sector_nodes)
                .map(|_| TreeDDomain::random(&mut rng))
                .collect();
            let mut tree = vec![leafs];
            for _ in 0..height {
                let row: Vec<TreeDDomain> = tree
                    .last()
                    .unwrap()
                    .chunks(2)
                    .map(|siblings| {
                        <TreeDHasher as Hasher>::Function::hash2(&siblings[0], &siblings[1])
                    })
                    .collect();
                tree.push(row);
            }
            tree
        };

        assert_eq!(tree_d[height].len(), 1);
        let comm_d = tree_d[height][0].clone();

        let apex_roots_row = height - partition_bit_len;
        let apex_leafs_row = apex_roots_row - apex_tree_height;
        assert_eq!(tree_d[apex_roots_row].len(), partition_count);
        assert_eq!(tree_d[apex_leafs_row].len(), apex_leafs_total);

        for (k, apex_leafs) in tree_d[apex_leafs_row]
            .chunks(apex_leafs_per_partition)
            .enumerate()
        {
            let mut cs = TestConstraintSystem::<Fr>::new();
            let comm_d =
                AllocatedNum::alloc(cs.namespace(|| "comm_d"), || Ok(comm_d.into())).unwrap();

            let partition_bits: Vec<AllocatedBit> = (0..partition_bit_len)
                .map(|i| {
                    let bit = (k >> i) & 1 == 1;
                    AllocatedBit::alloc(cs.namespace(|| format!("partition_bit_{}", i)), Some(bit))
                        .unwrap()
                })
                .collect();

            let apex_leafs: Vec<AllocatedNum<Fr>> = apex_leafs
                .iter()
                .enumerate()
                .map(|(i, apex_leaf)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("apex_leaf_{}", i)), || {
                        Ok(apex_leaf.clone().into())
                    })
                    .unwrap()
                })
                .collect();

            let partition_path: Vec<Vec<AllocatedNum<Fr>>> = partition_bits
                .iter()
                .enumerate()
                .map(|(i, bit)| {
                    let row = apex_roots_row + i;
                    let cur = k >> i;
                    let sib = if bit.get_value().unwrap() {
                        cur - 1
                    } else {
                        cur + 1
                    };
                    let sibling = AllocatedNum::alloc(
                        cs.namespace(|| format!("partition_path_{}", i)),
                        || Ok(tree_d[row][sib].into()),
                    )
                    .unwrap();
                    vec![sibling]
                })
                .collect();

            apex_por(
                cs.namespace(|| "apex_por"),
                apex_leafs,
                partition_bits,
                partition_path,
                comm_d.clone(),
            )
            .unwrap();
        }
    }

    #[test]
    fn test_apex_por_gadget_16kib_4_8_partitions() {
        // Hardcode these values to test multiple partitions without using a large sector-size. Use
        // the row from TreeD which has 64 nodes as the apex-leafs row.
        let sector_nodes = SECTOR_SIZE_16_KIB;
        let partition_count = 4;
        let apex_leafs_per_partition = 16;
        test_apex_por_gadget(sector_nodes, partition_count, apex_leafs_per_partition);

        let partition_count = 8;
        let apex_leafs_per_partition = 8;
        test_apex_por_gadget(sector_nodes, partition_count, apex_leafs_per_partition);
    }

    #[test]
    fn test_apex_por_gadget_small_sector_sizes() {
        let small_sector_sizes = [
            SECTOR_SIZE_1_KIB,
            SECTOR_SIZE_2_KIB,
            SECTOR_SIZE_4_KIB,
            SECTOR_SIZE_8_KIB,
            SECTOR_SIZE_16_KIB,
            SECTOR_SIZE_32_KIB,
        ];
        for sector_nodes in small_sector_sizes.iter().copied() {
            let partition_count = partition_count(sector_nodes);
            let apex_leafs_per_partition = apex_leaf_count(sector_nodes);
            test_apex_por_gadget(sector_nodes, partition_count, apex_leafs_per_partition);
        }
    }
}
