use std::marker::PhantomData;

use bellperson::gadgets::{
    boolean::Boolean,
    sha256::sha256 as sha256_circuit,
    {multipack, num},
};
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use storage_proofs_core::{
    compound_proof::CircuitComponent, error::Result, gadgets::constraint, gadgets::encode,
    gadgets::por::PoRCircuit, gadgets::uint64, gadgets::variables::Root, hasher::Hasher,
    merkle::BinaryMerkleTree, util::fixup_bits,
};

/// DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
///
/// ----> Private `replica_node` - The replica node being proven.
///
/// * `replica_node` - The replica node being proven.
/// * `replica_node_path` - The path of the replica node being proven.
/// * `replica_root` - The merkle root of the replica.
///
/// * `replica_parents` - A list of all parents in the replica, with their value.
/// * `replica_parents_paths` - A list of all parents paths in the replica.
///
/// ----> Private `data_node` - The data node being proven.
///
/// * `data_node_path` - The path of the data node being proven.
/// * `data_root` - The merkle root of the data.
/// * `replica_id` - The id of the replica.
///

pub struct DrgPoRepCircuit<'a, H: Hasher> {
    pub replica_nodes: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    pub replica_nodes_paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
    pub replica_root: Root<Bls12>,
    pub replica_parents: Vec<Vec<Option<Fr>>>,
    #[allow(clippy::type_complexity)]
    pub replica_parents_paths: Vec<Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>>,
    pub data_nodes: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    pub data_nodes_paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
    pub data_root: Root<Bls12>,
    pub replica_id: Option<Fr>,
    pub private: bool,
    pub _h: PhantomData<&'a H>,
}

impl<'a, H: 'static + Hasher> DrgPoRepCircuit<'a, H> {
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn synthesize<CS>(
        mut cs: CS,
        replica_nodes: Vec<Option<Fr>>,
        replica_nodes_paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
        replica_root: Root<Bls12>,
        replica_parents: Vec<Vec<Option<Fr>>>,
        replica_parents_paths: Vec<Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>>,
        data_nodes: Vec<Option<Fr>>,
        data_nodes_paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
        data_root: Root<Bls12>,
        replica_id: Option<Fr>,
        private: bool,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        DrgPoRepCircuit::<H> {
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            replica_id,
            private,
            _h: Default::default(),
        }
        .synthesize(&mut cs)
    }
}

#[derive(Default, Clone)]
pub struct ComponentPrivateInputs {
    pub comm_r: Option<Root<Bls12>>,
    pub comm_d: Option<Root<Bls12>>,
}

impl<'a, H: Hasher> CircuitComponent for DrgPoRepCircuit<'a, H> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

///
/// # Public Inputs
///
/// * [0] replica_id/0
/// * [1] replica_id/1
/// * [2] replica auth_path_bits
/// * [3] replica commitment (root hash)
/// * for i in 0..replica_parents.len()
///   * [ ] replica parent auth_path_bits
///   * [ ] replica parent commitment (root hash) // Same for all.
/// * [r + 1] data auth_path_bits
/// * [r + 2] data commitment (root hash)
///
///  Total = 6 + (2 * replica_parents.len())
/// # Private Inputs
///
/// * [ ] replica value/0
/// * for i in 0..replica_parents.len()
///  * [ ] replica parent value/0
/// * [ ] data value/
///
/// Total = 2 + replica_parents.len()
///
impl<'a, H: 'static + Hasher> Circuit<Bls12> for DrgPoRepCircuit<'a, H> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let replica_id = self.replica_id;
        let replica_root = self.replica_root;
        let data_root = self.data_root;

        let nodes = self.data_nodes.len();

        assert_eq!(self.replica_nodes.len(), nodes);
        assert_eq!(self.replica_nodes_paths.len(), nodes);
        assert_eq!(self.replica_parents.len(), nodes);
        assert_eq!(self.replica_parents_paths.len(), nodes);
        assert_eq!(self.data_nodes_paths.len(), nodes);

        let replica_node_num = num::AllocatedNum::alloc(cs.namespace(|| "replica_id_num"), || {
            replica_id.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        replica_node_num.inputize(cs.namespace(|| "replica_id"))?;

        // get the replica_id in bits
        let replica_id_bits =
            fixup_bits(replica_node_num.to_bits_le(cs.namespace(|| "replica_id_bits"))?);

        let replica_root_var = Root::Var(replica_root.allocated(cs.namespace(|| "replica_root"))?);
        let data_root_var = Root::Var(data_root.allocated(cs.namespace(|| "data_root"))?);

        for i in 0..self.data_nodes.len() {
            let mut cs = cs.namespace(|| format!("challenge_{}", i));
            // ensure that all inputs are well formed
            let replica_node_path = &self.replica_nodes_paths[i];
            let replica_parents_paths = &self.replica_parents_paths[i];
            let data_node_path = &self.data_nodes_paths[i];

            let replica_node = &self.replica_nodes[i];
            let replica_parents = &self.replica_parents[i];
            let data_node = &self.data_nodes[i];

            assert_eq!(replica_parents.len(), replica_parents_paths.len());
            assert_eq!(data_node_path.len(), replica_node_path.len());
            assert_eq!(replica_node.is_some(), data_node.is_some());

            // Inclusion checks
            {
                let mut cs = cs.namespace(|| "inclusion_checks");
                PoRCircuit::<BinaryMerkleTree<H>>::synthesize(
                    cs.namespace(|| "replica_inclusion"),
                    Root::Val(*replica_node),
                    replica_node_path.clone().into(),
                    replica_root_var.clone(),
                    self.private,
                )?;

                // validate each replica_parents merkle proof
                for j in 0..replica_parents.len() {
                    PoRCircuit::<BinaryMerkleTree<H>>::synthesize(
                        cs.namespace(|| format!("parents_inclusion_{}", j)),
                        Root::Val(replica_parents[j]),
                        replica_parents_paths[j].clone().into(),
                        replica_root_var.clone(),
                        self.private,
                    )?;
                }

                // validate data node commitment
                PoRCircuit::<BinaryMerkleTree<H>>::synthesize(
                    cs.namespace(|| "data_inclusion"),
                    Root::Val(*data_node),
                    data_node_path.clone().into(),
                    data_root_var.clone(),
                    self.private,
                )?;
            }

            // Encoding checks
            {
                let mut cs = cs.namespace(|| "encoding_checks");
                // get the parents into bits
                let parents_bits: Vec<Vec<Boolean>> = replica_parents
                    .iter()
                    .enumerate()
                    .map(|(i, val)| {
                        let num = num::AllocatedNum::alloc(
                            cs.namespace(|| format!("parents_{}_num", i)),
                            || {
                                val.map(Into::into)
                                    .ok_or_else(|| SynthesisError::AssignmentMissing)
                            },
                        )?;
                        Ok(fixup_bits(num.to_bits_le(
                            cs.namespace(|| format!("parents_{}_bits", i)),
                        )?))
                    })
                    .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?;

                // generate the encryption key
                let key = kdf(
                    cs.namespace(|| "kdf"),
                    &replica_id_bits,
                    parents_bits,
                    None,
                    None,
                )?;

                let replica_node_num =
                    num::AllocatedNum::alloc(cs.namespace(|| "replica_node"), || {
                        (*replica_node).ok_or_else(|| SynthesisError::AssignmentMissing)
                    })?;

                let decoded = encode::decode(cs.namespace(|| "decode"), &key, &replica_node_num)?;

                // TODO this should not be here, instead, this should be the leaf Fr in the data_auth_path
                // TODO also note that we need to change/makesurethat the leaves are the data, instead of hashes of the data
                let expected = num::AllocatedNum::alloc(cs.namespace(|| "data node"), || {
                    data_node.ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

                // ensure the encrypted data and data_node match
                constraint::equal(&mut cs, || "equality", &expected, &decoded);
            }
        }
        // profit!
        Ok(())
    }
}

/// Key derivation function.
fn kdf<E, CS>(
    mut cs: CS,
    id: &[Boolean],
    parents: Vec<Vec<Boolean>>,
    window_index: Option<uint64::UInt64>,
    node: Option<uint64::UInt64>,
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    // ciphertexts will become a buffer of the layout
    // id | node | encodedParentNode1 | encodedParentNode1 | ...

    let mut ciphertexts = id.to_vec();

    if let Some(window_index) = window_index {
        ciphertexts.extend_from_slice(&window_index.to_bits_be());
    }

    if let Some(node) = node {
        ciphertexts.extend_from_slice(&node.to_bits_be());
    }

    for parent in parents.into_iter() {
        ciphertexts.extend_from_slice(&parent);
    }

    let alloc_bits = sha256_circuit(cs.namespace(|| "hash"), &ciphertexts[..])?;
    let fr = if alloc_bits[0].get_value().is_some() {
        let be_bits = alloc_bits
            .iter()
            .map(|v| v.get_value().ok_or(SynthesisError::AssignmentMissing))
            .collect::<Result<Vec<bool>, SynthesisError>>()?;

        let le_bits = be_bits
            .chunks(8)
            .flat_map(|chunk| chunk.iter().rev())
            .copied()
            .take(E::Fr::CAPACITY as usize)
            .collect::<Vec<bool>>();

        Ok(multipack::compute_multipacking::<E>(&le_bits)[0])
    } else {
        Err(SynthesisError::AssignmentMissing)
    };

    num::AllocatedNum::<E>::alloc(cs.namespace(|| "result_num"), || fr)
}

#[cfg(test)]
mod tests {

    use super::*;

    use ff::Field;
    use generic_array::typenum;
    use merkletree::store::StoreConfig;
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        cache_key::CacheKey,
        compound_proof,
        drgraph::{graph_height, new_seed, BucketGraph, BASE_DEGREE},
        fr32::{bytes_into_fr, fr_into_bytes},
        gadgets::TestConstraintSystem,
        hasher::PedersenHasher,
        merkle::MerkleProofTrait,
        proof::ProofScheme,
        test_helper::setup_replica,
        util::data_at_node,
    };

    use super::super::compound::DrgPoRepCompound;
    use crate::drg;
    use crate::stacked::BINARY_ARITY;
    use crate::PoRep;

    #[test]
    fn drgporep_input_circuit_with_bls12_381() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let nodes = 16;
        let degree = BASE_DEGREE;
        let challenge = 2;

        let replica_id: Fr = Fr::random(rng);

        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_rows_to_discard(nodes, BINARY_ARITY),
        );

        // Generate a replica path.
        let replica_path = cache_dir.path().join("replica-path");
        let mut mmapped_data = setup_replica(&data, &replica_path);

        let data_node: Option<Fr> = Some(
            bytes_into_fr(
                data_at_node(&mmapped_data, challenge).expect("failed to read original data"),
            )
            .unwrap(),
        );

        let sp = drg::SetupParams {
            drg: drg::DrgParams {
                nodes,
                degree,
                expansion_degree: 0,
                seed: new_seed(),
            },
            private: false,
            challenges_count: 1,
        };

        let pp = drg::DrgPoRep::<PedersenHasher, BucketGraph<_>>::setup(&sp)
            .expect("failed to create drgporep setup");
        let (tau, aux) = drg::DrgPoRep::<PedersenHasher, _>::replicate(
            &pp,
            &replica_id.into(),
            (mmapped_data.as_mut()).into(),
            None,
            config,
            replica_path.clone(),
        )
        .expect("failed to replicate");

        let pub_inputs = drg::PublicInputs {
            replica_id: Some(replica_id.into()),
            challenges: vec![challenge],
            tau: Some(tau.into()),
        };

        let priv_inputs = drg::PrivateInputs::<PedersenHasher> {
            tree_d: &aux.tree_d,
            tree_r: &aux.tree_r,
            tree_r_config_rows_to_discard: StoreConfig::default_rows_to_discard(
                nodes,
                BINARY_ARITY,
            ),
        };

        let proof_nc = drg::DrgPoRep::<PedersenHasher, _>::prove(&pp, &pub_inputs, &priv_inputs)
            .expect("failed to prove");

        assert!(
            drg::DrgPoRep::<PedersenHasher, _>::verify(&pp, &pub_inputs, &proof_nc)
                .expect("failed to verify"),
            "failed to verify (non circuit)"
        );

        let replica_node: Option<Fr> = Some(proof_nc.replica_nodes[0].data.into());

        let replica_node_path = proof_nc.replica_nodes[0].proof.as_options();
        let replica_root = Root::Val(Some(proof_nc.replica_root.into()));
        let replica_parents = proof_nc
            .replica_parents
            .iter()
            .map(|v| {
                v.iter()
                    .map(|(_, parent)| Some(parent.data.into()))
                    .collect()
            })
            .collect();
        let replica_parents_paths: Vec<_> = proof_nc
            .replica_parents
            .iter()
            .map(|v| {
                v.iter()
                    .map(|(_, parent)| parent.proof.as_options())
                    .collect()
            })
            .collect();

        let data_node_path = proof_nc.nodes[0].proof.as_options();
        let data_root = Root::Val(Some(proof_nc.data_root.into()));
        let replica_id = Some(replica_id);

        assert!(
            proof_nc.nodes[0].proof.validate(challenge),
            "failed to verify data commitment"
        );
        assert!(
            proof_nc.nodes[0]
                .proof
                .validate_data(data_node.unwrap().into()),
            "failed to verify data commitment with data"
        );

        let mut cs = TestConstraintSystem::<Bls12>::new();
        DrgPoRepCircuit::<PedersenHasher>::synthesize(
            cs.namespace(|| "drgporep"),
            vec![replica_node],
            vec![replica_node_path],
            replica_root,
            replica_parents,
            replica_parents_paths,
            vec![data_node],
            vec![data_node_path],
            data_root,
            replica_id,
            false,
        )
        .expect("failed to synthesize circuit");

        if !cs.is_satisfied() {
            println!(
                "failed to satisfy: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 149_580, "wrong number of constraints");

        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        assert_eq!(
            cs.get_input(1, "drgporep/replica_id/input variable"),
            replica_id.unwrap()
        );

        let generated_inputs =
                <DrgPoRepCompound<_, _> as compound_proof::CompoundProof<_, _>>::generate_public_inputs(
                    &pub_inputs,
                    &pp,
                    None,
                )
                .unwrap();
        let expected_inputs = cs.get_inputs();

        for ((input, label), generated_input) in
            expected_inputs.iter().skip(1).zip(generated_inputs.iter())
        {
            assert_eq!(input, generated_input, "{}", label);
        }

        assert_eq!(
            generated_inputs.len(),
            expected_inputs.len() - 1,
            "inputs are not the same length"
        );

        cache_dir.close().expect("Failed to remove cache dir");
    }

    #[test]
    fn drgporep_input_circuit_num_constraints() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        // 1 GB
        let n = (1 << 30) / 32;
        let m = BASE_DEGREE;
        let tree_depth = graph_height::<typenum::U2>(n);

        let mut cs = TestConstraintSystem::<Bls12>::new();
        DrgPoRepCircuit::<PedersenHasher>::synthesize(
            cs.namespace(|| "drgporep"),
            vec![Some(Fr::random(rng)); 1],
            vec![vec![(vec![Some(Fr::random(rng))], Some(0)); tree_depth]; 1],
            Root::Val(Some(Fr::random(rng))),
            vec![vec![Some(Fr::random(rng)); m]; 1],
            vec![vec![vec![(vec![Some(Fr::random(rng))], Some(0)); tree_depth]; m]; 1],
            vec![Some(Fr::random(rng)); 1],
            vec![vec![(vec![Some(Fr::random(rng))], Some(0)); tree_depth]; 1],
            Root::Val(Some(Fr::random(rng))),
            Some(Fr::random(rng)),
            false,
        )
        .expect("failed to synthesize circuit");

        assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 391_404, "wrong number of constraints");
    }
}
