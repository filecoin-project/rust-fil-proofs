use bellperson::{
    bls::{Bls12, Fr},
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        num::AllocatedNum,
    },
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::{Field, PrimeField};
use filecoin_hashers::{Hasher, HashFunction};
use generic_array::typenum::Unsigned;
use storage_proofs_core::merkle::MerkleTreeTrait;

use crate::{
    gadgets::{allocated_num_to_allocated_bits, por_no_challenge_input},
    TreeD,
};

// The number of partitions.
const PARTITIONS: usize = 16;

const PARTITION_ROWS: usize = 4;
const PARTITION_HEIGHT: usize = PARTITION_ROWS - 1;
const PARTITION_PATH_LEN: usize = PARTITION_HEIGHT;

// The bit-length of a partition index: `log2(PARTITIONS)`.
const PARTITION_BIT_LEN: usize = PARTITION_ROWS;

// The number of challenges per partition: `ceil(1375 / PARTITIONS)`.
const CHALLENGES: usize = 86;

// The number of leafs in each partition's apex-tree.
const APEX_LEAFS: usize = 128;

// The number of rows in each partition's apex-tree: `log2(APEX_LEAFS) + 1`.
const APEX_ROWS: usize = 8;

// `log2(APEX_LEAFS)`
const APEX_HEIGHT: usize = 7;
const APEX_PATH_LEN: usize = APEX_HEIGHT;

type TreeDHasher = <TreeD as MerkleTreeTrait>::Hasher;
type TreeDDomain= <TreeDHasher as Hasher>::Domain;

pub struct PublicInputs {
    pub k: usize,
    pub comm_d_new: TreeDDomain,
}

pub struct ApexCircuit {
    // Public-inputs
    pub k: Option<Fr>,
    pub comm_d_new: Option<Fr>,

    // Private-inputs
    pub apex_leafs: Vec<Option<Fr>>,
    pub partition_path: Vec<Vec<Option<Fr>>>,
    // pub challenge_proofs: ChallengeProof<TreeR>
}

impl ApexCircuit {
    /*
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let ApexCircuit {
            k,
            comm_d_new,
            apex_leafs,
            partition_path,
        } = self;

        if let Some(k) = k {
            let k_repr = k.into_repr();
            let limbs: &[u64] = k_repr.as_ref();
            assert!(limbs[0] < PARTITIONS as u64);
            assert_eq!(limbs[1], 0);
            assert_eq!(limbs[2], 0);
            assert_eq!(limbs[3], 0);
        }
        assert_eq!(apex_leafs.len(), APEX_LEAFS);
        assert_eq!(partition_path.len(), PARTITION_PATH_LEN);
        assert!(partition_path.iter().all(|siblings| siblings.len() == 1));

        // Allocate public-inputs.

        let k = AllocatedNum::alloc(cs.namespace(|| "partition_index"), || {
            k.ok_or(SynthesisError::AssignmentMissing)
        })?;
        k.inputize(cs.namespace(|| "partition_index (public input)"))?;

        // Allocate the partition-index as bits.
        let k_bits: Vec<AllocatedBit> =
            allocated_num_to_allocated_bits(cs.namespace(|| "partition_index_bits"), &k)?
                .into_iter()
                .take(PARTITION_BIT_LEN)
                .collect();

        let comm_d_new = AllocatedNum::alloc(cs.namespace(|| "comm_d_new"), || {
            comm_d_new.ok_or(SynthesisError::AssignmentMissing)
        })?;
        comm_d_new.inputize(cs.namespace(|| "comm_d_new (public input)"))?;

        // Allocate private-inputs.

        // Allocate apex-tree
        let apex_leafs = apex_leafs
            .iter()
            .enumerate()
            .map(|(i, leaf)| {
                AllocatedNum::alloc(cs.namespace(|| format!("apex_leaf_{}", i)), || {
                    leaf.ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<AllocatedNum<Bls12>>, SynthesisError>>()?;
            
        let mut apex_tree: Vec<Vec<AllocatedNum<Bls12>>> = vec![apex_leafs];

        for row_index in 0..APEX_HEIGHT {
            let row = apex_tree
                .last()
                .unwrap()
                .chunks(2)
                .enumerate()
                .map(|(i, siblings)| {
                    <TreeDHasher as Hasher>::Function::hash2_circuit(
                        cs.namespace(|| format!(
                            "apex tree hash (tree_row={}, pair={})",
                            row_index,
                            i,
                        )),
                        &siblings[0],
                        &siblings[1],
                    )
                })
                .collect::<Result<Vec<AllocatedNum<Bls12>>, SynthesisError>>()?;
            apex_tree.push(row);
        }

        let apex_root = apex_tree.last().unwrap()[0].clone();

        // Allocate `partition_path`.
        let partition_path = partition_path
            .iter()
            .enumerate()
            .map(|(i, siblings)| {
                AllocatedNum::alloc(cs.namespace(|| format!("partition_path_sibling_{}", i)), || {
                    siblings[0].ok_or(SynthesisError::AssignmentMissing)
                })
                .map(|sibling| vec![sibling])
            })
            .collect::<Result<Vec<Vec<AllocatedNum<Bls12>>>, SynthesisError>>()?;

        // Assert that this partition's `apex_root`, and thus `apex_leafs`, is consistent with the
        // public `comm_d_new`.
        por_no_challenge_input::<TreeD, _>(
            cs.namespace(|| "partition-tree por"),
            k_bits,
            apex_root,
            partition_path,
            comm_d_new,
        )?;

        Ok(())
    }
    */

    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let ApexCircuit {
            k,
            comm_d_new,
            apex_leafs,
            partition_path,
        } = self;

        if let Some(k) = k {
            let k_repr = k.into_repr();
            let limbs: &[u64] = k_repr.as_ref();
            assert!(limbs[0] < PARTITIONS as u64);
            assert_eq!(limbs[1], 0);
            assert_eq!(limbs[2], 0);
            assert_eq!(limbs[3], 0);
        }
        assert_eq!(apex_leafs.len(), APEX_LEAFS);
        assert_eq!(partition_path.len(), PARTITION_PATH_LEN);
        assert!(partition_path.iter().all(|siblings| siblings.len() == 1));

        // Allocate public-inputs.

        let partition = AllocatedNum::alloc(cs.namespace(|| "partition_index"), || {
            k.ok_or(SynthesisError::AssignmentMissing)
        })?;
        partition.inputize(cs.namespace(|| "partition_index (public input)"))?;

        // Allocate the partition-index as bits.
        let partition_bits: Vec<AllocatedBit> =
            allocated_num_to_allocated_bits(cs.namespace(|| "partition_bits"), &partition)?
                .into_iter()
                .take(PARTITION_BIT_LEN)
                .collect();

        let comm_d_new = AllocatedNum::alloc(cs.namespace(|| "comm_d_new"), || {
            comm_d_new.ok_or(SynthesisError::AssignmentMissing)
        })?;
        comm_d_new.inputize(cs.namespace(|| "comm_d_new (public input)"))?;

        // Allocate private-inputs.

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
                AllocatedNum::alloc(cs.namespace(|| format!("partition_path_sibling_{}", i)), || {
                    siblings[0].ok_or(SynthesisError::AssignmentMissing)
                })
                .map(|sibling| vec![sibling])
            })
            .collect::<Result<Vec<Vec<AllocatedNum<Bls12>>>, SynthesisError>>()?;

        // Assert that this partition's `apex_leafs` are  consistent with the public `comm_d_new`.
        por_tree_d_apex(
            cs.namespace(|| "apex_gadget"),
            apex_leafs.clone(),
            partition_bits.clone(),
            partition_path.clone(),
            comm_d_new.clone(),
        )?;

        Ok(())
    }
}

fn por_tree_d_apex<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    apex_leafs: Vec<AllocatedNum<Bls12>>,
    partition_bits: Vec<AllocatedBit>,
    partition_path: Vec<Vec<AllocatedNum<Bls12>>>,
    comm_d: AllocatedNum<Bls12>,
) -> Result<(), SynthesisError> {
    let mut apex_tree = vec![apex_leafs];
    for row_index in 0..APEX_HEIGHT {
        let row = apex_tree
            .last()
            .unwrap()
            .chunks(2)
            .enumerate()
            .map(|(i, siblings)| {
                <TreeDHasher as Hasher>::Function::hash2_circuit(
                    cs.namespace(|| format!(
                        "apex_tree generation hash (tree_row={}, siblings={})",
                        row_index,
                        i,
                    )),
                    &siblings[0],
                    &siblings[1],
                )
            })
            .collect::<Result<Vec<AllocatedNum<Bls12>>, SynthesisError>>()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    use filecoin_hashers::Domain;
    use fr32::fr_into_bytes;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        merkle::{create_base_merkle_tree, MerkleProof, MerkleProofTrait},
        TEST_SEED,
    };

    type TreeDArity = <TreeD as MerkleTreeTrait>::Arity;

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
}
