use pairing::bls12_381::{Bls12, Fr};
use pairing::PrimeFieldRepr;
use pairing::{BitIterator, PrimeField};
use rand::Rng;
use sapling_crypto::pedersen_hash;

use crate::crypto;
use crate::error;
use crate::fr32::{bytes_into_fr, fr_into_bytes};
use crate::hasher::pedersen::{PedersenDomain, PedersenFunction, PedersenHasher};
use crate::merkle::{MerkleProof, MerkleTree};

#[macro_export]
macro_rules! table_tests {
    ($property_test_func:ident {
        $( $(#[$attr:meta])* $test_name:ident( $( $param:expr ),* ); )+
    }) => {
        $(
            $(#[$attr])*
                #[test]
            fn $test_name() {
                $property_test_func($( $param ),* )
            }
        )+
    }
}

pub struct FakeDrgParams {
    pub replica_id: Fr,
    pub replica_nodes: Vec<Fr>,
    pub replica_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
    pub replica_root: Fr,
    pub replica_parents: Vec<Vec<Fr>>,
    #[allow(clippy::type_complexity)]
    pub replica_parents_paths: Vec<Vec<Vec<Option<(Fr, bool)>>>>,
    pub data_nodes: Vec<Fr>,
    pub data_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
    pub data_root: Fr,
}

pub fn fake_drgpoprep_proof<R: Rng>(
    rng: &mut R,
    tree_depth: usize,
    m: usize,
    sloth_rounds: usize,
    challenge_count: usize,
) -> FakeDrgParams {
    let replica_id: Fr = rng.gen();
    let challenge = m + 1;
    // Part 1: original data inputs
    // generate a leaf
    let data_node: Fr = rng.gen();
    // generate a fake merkle tree for the leaf and get commD
    let (data_node_path, data_root) = random_merkle_path_with_value(rng, tree_depth, &data_node, 0);

    // Part 2: replica data inputs
    // generate parent nodes
    let replica_parents: Vec<Fr> = (0..m).map(|_| rng.gen()).collect();
    // run kdf for proverid, parent nodes
    let ciphertexts = replica_parents
        .iter()
        .fold(
            Ok(fr_into_bytes::<Bls12>(&replica_id)),
            |acc: error::Result<Vec<u8>>, parent: &Fr| {
                acc.and_then(|mut acc| {
                    parent.into_repr().write_le(&mut acc)?;
                    Ok(acc)
                })
            },
        )
        .unwrap();

    let key = crypto::kdf::kdf(ciphertexts.as_slice(), m);
    // run sloth(key, node)
    let replica_node: Fr = crypto::sloth::encode::<Bls12>(&key, &data_node, sloth_rounds);
    // run fake merkle with only the first 1+m real leaves

    let mut leaves = replica_parents.clone();
    leaves.push(data_node);
    // ensure we have an even number of leaves
    if m + 1 % 2 != 0 {
        leaves.push(rng.gen());
    }

    // get commR
    let subtree = MerkleTree::<PedersenDomain, PedersenFunction>::from_data(leaves);
    let subtree_root: Fr = subtree.root().into();
    let subtree_depth = subtree.height() - 1; // .height() inludes the leaf
    let remaining_depth = tree_depth - subtree_depth;
    let (remaining_path, replica_root) =
        random_merkle_path_with_value(rng, remaining_depth, &subtree_root, remaining_depth);

    // generate merkle path for challenged node and parents
    let replica_parents_paths: Vec<_> = (0..m)
        .map(|i| {
            let subtree_proof =
                MerkleProof::<PedersenHasher>::new_from_proof(&subtree.gen_proof(i));
            let mut subtree_path = subtree_proof.as_options();
            subtree_path.extend(remaining_path.clone());
            subtree_path
        })
        .collect();

    let replica_node_path = {
        let subtree_proof =
            MerkleProof::<PedersenHasher>::new_from_proof(&subtree.gen_proof(challenge));
        let mut subtree_path = subtree_proof.as_options();
        subtree_path.extend(&remaining_path);
        subtree_path
    };

    assert_eq!(data_node_path.len(), replica_node_path.len());

    FakeDrgParams {
        replica_id,
        replica_nodes: (0..challenge_count).map(|_| replica_node).collect(),
        replica_nodes_paths: (0..challenge_count)
            .map(|_| replica_node_path.clone())
            .collect(),
        replica_root,
        replica_parents: (0..challenge_count)
            .map(|_| replica_parents.clone())
            .collect(),
        replica_parents_paths: (0..challenge_count)
            .map(|_| replica_parents_paths.clone())
            .collect(),
        data_nodes: (0..challenge_count).map(|_| data_node).collect(),
        data_nodes_paths: (0..challenge_count)
            .map(|_| data_node_path.clone())
            .collect(),
        data_root,
    }
}

pub fn random_merkle_path_with_value<R: Rng>(
    rng: &mut R,
    tree_depth: usize,
    value: &Fr,
    offset: usize,
) -> (Vec<Option<(Fr, bool)>>, Fr) {
    let auth_path: Vec<Option<(Fr, bool)>> = vec![Some((rng.gen(), rng.gen())); tree_depth];

    let mut cur = if offset == 0 {
        let bytes = fr_into_bytes::<Bls12>(&value);
        bytes_into_fr::<Bls12>(&bytes).unwrap()
    } else {
        *value
    };

    for (i, p) in auth_path.clone().into_iter().enumerate() {
        let (uncle, is_right) = p.unwrap();
        let mut lhs = cur;
        let mut rhs = uncle;

        if is_right {
            ::std::mem::swap(&mut lhs, &mut rhs);
        }

        let mut lhs: Vec<bool> = BitIterator::new(lhs.into_repr()).collect();
        let mut rhs: Vec<bool> = BitIterator::new(rhs.into_repr()).collect();

        lhs.reverse();
        rhs.reverse();

        cur = pedersen_hash::pedersen_hash::<Bls12, _>(
            pedersen_hash::Personalization::MerkleTree(i + offset),
            lhs.into_iter()
                .take(Fr::NUM_BITS as usize)
                .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
            &crypto::pedersen::JJ_PARAMS,
        )
        .into_xy()
        .0;
    }

    (auth_path, cur)
}

pub fn random_merkle_path<R: Rng>(
    rng: &mut R,
    tree_depth: usize,
) -> (Vec<Option<(Fr, bool)>>, Fr, Fr) {
    let value: Fr = rng.gen();

    let (path, root) = random_merkle_path_with_value(rng, tree_depth, &value, 0);

    (path, value, root)
}
