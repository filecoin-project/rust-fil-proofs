use bellperson::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack::pack_bits,
        num::AllocatedNum,
    },
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;
use filecoin_hashers::{PoseidonLookup, R1CSHasher};
use generic_array::typenum::U2;
use neptune::circuit::poseidon_hash;
use storage_proofs_core::gadgets::por::por_no_challenge_input;

use crate::constants::{TreeD, TreeDHasher, POSEIDON_CONSTANTS_GEN_RANDOMNESS};

// Allocates `num` as `F::NUM_BITS` number of bits.
//
// This function is an alternative to `AllocatedNum::to_bits_le` that allows us to remove the bound
// `F: PrimeFieldBits`. We can remove the bound because all R1CS fields used in Filecoin, i.e.
// `Fr, Fp, Fq`, have a little-endian bytes repr.
pub fn le_bits<F, CS>(
    mut cs: CS,
    num: &AllocatedNum<F>,
) -> Result<Vec<AllocatedBit>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let le_bits_vals: Vec<Option<bool>> = match num.get_value() {
        Some(f) => {
            let repr = f.to_repr();
            let le_bytes = repr.as_ref();
            le_bytes
                .iter()
                .flat_map(|byte| {
                    (0..8)
                        .map(|i| Some(byte >> i & 1 == 1))
                        .collect::<Vec<Option<bool>>>()
                })
                .take(F::NUM_BITS as usize)
                .collect::<Vec<Option<bool>>>()
        }
        None => vec![None; F::NUM_BITS as usize],
    };

    let le_bits = le_bits_vals
        .into_iter()
        .enumerate()
        .map(|(i, bit)| AllocatedBit::alloc(cs.namespace(|| format!("bit {}", i)), bit))
        .collect::<Result<Vec<AllocatedBit>, SynthesisError>>()?;

    // Verify `num`'s binary decomposition.
    let mut lc = LinearCombination::<F>::zero();
    let mut pow2 = F::one();
    for bit in le_bits.iter() {
        lc = lc + (pow2, bit.get_variable());
        pow2 = pow2.double();
    }
    cs.enforce(
        || "binary decomp",
        |_| lc,
        |lc| lc + CS::one(),
        |lc| lc + num.get_variable(),
    );

    Ok(le_bits)
}

// Computes a partition's apex-tree from `apex_leafs` and asserts that `partition_path` is a valid
// Merkle path from the apex-tree's root to the TreeD root (`comm_d`). Each partition has a
// unique `apex_leafs` and `parition_path`. Every challenge for a partition has a TreeD Merkle
// path which ends with `partition_path`, thus we verify `partition_path` once per partition.
pub fn apex_por<F, CS>(
    mut cs: CS,
    apex_leafs: Vec<AllocatedNum<F>>,
    // little-endian
    partition_bits: Vec<AllocatedBit>,
    partition_path: Vec<Vec<AllocatedNum<F>>>,
    comm_d: AllocatedNum<F>,
) -> Result<(), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
    TreeDHasher<F>: R1CSHasher<Field = F>,
{
    // `apex_leafs.len()` is guaranteed to be a power of two.
    let apex_tree_height = apex_leafs.len().trailing_zeros() as usize;
    let mut apex_tree = vec![apex_leafs];
    for row_index in 0..apex_tree_height {
        let row = apex_tree
            .last()
            .unwrap()
            .chunks(2)
            .enumerate()
            .map(|(i, siblings)| {
                TreeDHasher::<F>::hash2_circuit(
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
            .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;
        apex_tree.push(row);
    }

    // This partition's apex-tree root.
    let apex_root = apex_tree.last().unwrap()[0].clone();

    por_no_challenge_input::<TreeD<F>, _>(
        cs.namespace(|| "partition-tree por"),
        partition_bits,
        apex_root,
        partition_path,
        comm_d,
    )
}

// Generates each challenge's random bits for a given partition.
pub fn gen_challenge_bits<F, CS>(
    mut cs: CS,
    comm_r_new: &AllocatedNum<F>,
    partition: &AllocatedNum<F>,
    challenges: usize,
    bits_per_challenge: usize,
) -> Result<Vec<Vec<AllocatedBit>>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    // The number of challenges derived per digest.
    let challenges_per_digest = F::CAPACITY as usize / bits_per_challenge;

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
                let digest_index = k * F::from(digests_per_partition) + F::from(j);
                Ok(digest_index)
            })?;

        // `digests_per_partition` and `j` are (unallocated) constants.
        cs.enforce(
            || format!("digest_index_{} == k * digests_per_partition + {}", j, j),
            |lc| {
                lc + (F::from(digests_per_partition), partition.get_variable())
                    + (F::from(j), CS::one())
            },
            |lc| lc + CS::one(),
            |lc| lc + digest_index.get_variable(),
        );

        let consts = POSEIDON_CONSTANTS_GEN_RANDOMNESS
            .get::<PoseidonLookup<F, U2>>()
            .expect("arity-2 Poseidon constants not found for field");

        // `digest = H(comm_r_new || digest_index)`
        let digest = poseidon_hash(
            cs.namespace(|| format!("digest_{}", j)),
            vec![comm_r_new.clone(), digest_index.clone()],
            *consts,
        )?;

        // Allocate `digest` as `F::NUM_BITS` bits.
        let digest_bits = le_bits(cs.namespace(|| format!("digest_{}_bits", j)), &digest)?;

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

// Returns the `h` high-bits of the given challenge's bits `c_bits`. `h` is chosen from `hs` using
// `h_select_bits` which has exactly one bit set; if that bit has index `i` then
// `h = hs[i] = dot(hs, h_select_bits)`.
pub fn get_challenge_high_bits<F, CS>(
    mut cs: CS,
    // little-endian
    c_bits: &[AllocatedBit],
    h_select_bits: &[AllocatedBit],
    hs: &[usize],
) -> Result<AllocatedNum<F>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
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
                        Ok(F::zero())
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
        .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()?;

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

// Computes the encoding of a sector node.
pub fn label_r_new<F, CS>(
    mut cs: CS,
    label_r_old: &AllocatedNum<F>,
    label_d_new: &AllocatedNum<F>,
    rho: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
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
    use blstrs::Scalar as Fr;
    use filecoin_hashers::{Domain, HashFunction, Hasher};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        SECTOR_NODES_16_KIB, SECTOR_NODES_1_KIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_KIB,
        SECTOR_NODES_4_KIB, SECTOR_NODES_8_KIB, TEST_SEED,
    };

    use crate::{
        challenges::Challenges,
        constants::{
            self, apex_leaf_count, challenge_count, partition_count, ALLOWED_SECTOR_SIZES,
        },
    };

    type TreeDDomain = constants::TreeDDomain<Fr>;
    type TreeDHasher = constants::TreeDHasher<Fr>;
    type TreeRDomain = constants::TreeRDomain<Fr>;

    #[test]
    fn test_gen_challenge_bits_gadget() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        let num_constraints_expected = [568, 568, 568, 568, 568, 568, 568, 568, 4544, 5680, 5680];

        for (sector_nodes, constraints_expected) in ALLOWED_SECTOR_SIZES
            .iter()
            .copied()
            .zip(num_constraints_expected.iter().copied())
        {
            let comm_r_new = TreeRDomain::random(&mut rng);

            let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
            let partition_count = partition_count(sector_nodes);
            let partition_bit_len = partition_count.trailing_zeros() as usize;
            let rand_challenge_bits = challenge_bit_len - partition_bit_len;
            let challenge_count = challenge_count(sector_nodes);

            for k in 0..partition_count {
                let challenges = Challenges::<Fr>::new(sector_nodes, comm_r_new, k);

                let mut cs = TestConstraintSystem::new();
                let comm_r_new =
                    AllocatedNum::alloc(cs.namespace(|| "comm_r_new"), || Ok(comm_r_new.into()))
                        .unwrap();
                let partition =
                    AllocatedNum::alloc(cs.namespace(|| "k"), || Ok(Fr::from(k as u64))).unwrap();
                let partition_bits: Vec<AllocatedBit> =
                    le_bits(cs.namespace(|| "partition_bits"), &partition)
                        .unwrap()
                        .into_iter()
                        .take(partition_bit_len)
                        .collect();
                let constraints_before = cs.num_constraints();
                let generated_bits = gen_challenge_bits(
                    cs.namespace(|| "gen_challenge_bits"),
                    &comm_r_new,
                    &partition,
                    challenge_count,
                    rand_challenge_bits,
                )
                .unwrap();
                let constraints_after = cs.num_constraints();
                let gadget_constraints = constraints_after - constraints_before;
                assert_eq!(gadget_constraints, constraints_expected);

                for (c, c_generated_bits) in challenges.zip(generated_bits.into_iter()) {
                    assert_eq!(c_generated_bits.len(), rand_challenge_bits);
                    let mut c_circ: u32 = 0;
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
        constraints_expected: usize,
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
        let comm_d = tree_d[height][0];

        let apex_roots_row = height - partition_bit_len;
        let apex_leafs_row = apex_roots_row - apex_tree_height;
        assert_eq!(tree_d[apex_roots_row].len(), partition_count);
        assert_eq!(tree_d[apex_leafs_row].len(), apex_leafs_total);

        for (k, apex_leafs) in tree_d[apex_leafs_row]
            .chunks(apex_leafs_per_partition)
            .enumerate()
        {
            let mut cs = TestConstraintSystem::new();
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
                        Ok((*apex_leaf).into())
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

            let constraints_before = cs.num_constraints();

            apex_por(
                cs.namespace(|| "apex_por"),
                apex_leafs,
                partition_bits,
                partition_path,
                comm_d.clone(),
            )
            .unwrap();

            let constraints_after = cs.num_constraints();
            let gadget_constraints = constraints_after - constraints_before;
            assert_eq!(gadget_constraints, constraints_expected);
        }
    }

    #[test]
    fn test_apex_por_gadget_16kib_4_8_partitions() {
        // Hardcode these values to test more than one partition without using a large sector-size.
        // Use the row from TreeD which has 64 nodes as the apex-leafs row.
        let sector_nodes = SECTOR_NODES_16_KIB;

        // Total apex leafs = 4 * 16 = 64
        let partition_count = 4;
        let apex_leafs_per_partition = 16;
        test_apex_por_gadget(
            sector_nodes,
            partition_count,
            apex_leafs_per_partition,
            771448,
        );

        // Total apex leafs = 8 * 8 = 64
        let partition_count = 8;
        let apex_leafs_per_partition = 8;
        test_apex_por_gadget(
            sector_nodes,
            partition_count,
            apex_leafs_per_partition,
            453797,
        );
    }

    #[test]
    fn test_apex_por_gadget_small_sector_sizes() {
        let small_sector_sizes = [
            SECTOR_NODES_1_KIB,
            SECTOR_NODES_2_KIB,
            SECTOR_NODES_4_KIB,
            SECTOR_NODES_8_KIB,
            SECTOR_NODES_16_KIB,
            SECTOR_NODES_32_KIB,
        ];
        let num_constraints_expected = [317654, 317654, 317654, 317654, 5808515, 5808515];
        for (sector_nodes, constraints_expected) in small_sector_sizes
            .iter()
            .copied()
            .zip(num_constraints_expected.iter().copied())
        {
            let partition_count = partition_count(sector_nodes);
            let apex_leafs_per_partition = apex_leaf_count(sector_nodes);
            test_apex_por_gadget(
                sector_nodes,
                partition_count,
                apex_leafs_per_partition,
                constraints_expected,
            );
        }
    }
}
