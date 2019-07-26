use algebra::PairingEngine as Engine;
use algebra::fields::bls12_381::Fr;
use algebra::fields::FpParameters;
use algebra::curves::{bls12_381::Bls12_381 as Bls12};
use snark::{Circuit, ConstraintSystem, SynthesisError};
use snark_gadgets::boolean::{self, Boolean};
use snark_gadgets::{fields::fp::FpGadget, utils::{AllocGadget, ToBitsGadget}};

use crate::circuit::{constraint, multipack};
use crate::circuit::kdf::kdf;
use crate::circuit::sloth;
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgporep::DrgPoRep;
use crate::drgraph::Graph;
use crate::fr32::fr_into_bytes;
use crate::merklepor;
use crate::parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use crate::proof::ProofScheme;
use crate::singletons::PEDERSEN_PARAMS;
use crate::util::{bytes_into_bits, bytes_into_boolean_vec};
use std::marker::PhantomData;

/// DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
/// * `sloth_iter` - How many rounds sloth should run for.
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
/// * `degree` - The degree of the graph.
///
//implement_drgporep!(
//    DrgPoRepCircuit,
//    DrgPoRepCompound,
//    "drg-proof-of-replication",
//    false
//);
use crate::circuit::por::{PoRCircuit, PoRCompound};
use crate::hasher::{Domain, Hasher};
use algebra::fields::PrimeField;
use snark_gadgets::bits::boolean::AllocatedBit;

pub struct DrgPoRepCircuit<H: Hasher> {
    sloth_iter: usize,
    replica_nodes: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    replica_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
    replica_root: Root<Bls12>,
    replica_parents: Vec<Vec<Option<Fr>>>,
    #[allow(clippy::type_complexity)]
    replica_parents_paths: Vec<Vec<Vec<Option<(Fr, bool)>>>>,
    data_nodes: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    data_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
    data_root: Root<Bls12>,
    replica_id: Option<Fr>,
    degree: usize,
    private: bool,
    _h: PhantomData<H>,
}

impl<H: Hasher> DrgPoRepCircuit<H> {
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn synthesize<CS>(
        mut cs: CS,
        sloth_iter: usize,
        replica_nodes: Vec<Option<Fr>>,
        replica_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
        replica_root: Root<Bls12>,
        replica_parents: Vec<Vec<Option<Fr>>>,
        replica_parents_paths: Vec<Vec<Vec<Option<(Fr, bool)>>>>,
        data_nodes: Vec<Option<Fr>>,
        data_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
        data_root: Root<Bls12>,
        replica_id: Option<Fr>,
        degree: usize,
        private: bool,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        DrgPoRepCircuit::<H> {
            sloth_iter,
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            replica_id,
            degree,
            private,
            _h: Default::default(),
        }
        .synthesize(&mut cs)
    }
}

#[derive(Clone)]
pub struct ComponentPrivateInputs {
    pub comm_r: Option<Root<Bls12>>,
    pub comm_d: Option<Root<Bls12>>,
}

impl Default for ComponentPrivateInputs {
    fn default() -> ComponentPrivateInputs {
        ComponentPrivateInputs {
            comm_r: None,
            comm_d: None,
        }
    }
}

impl<H: Hasher> CircuitComponent for DrgPoRepCircuit<H> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

pub struct DrgPoRepCompound<H, G>
where
    H: Hasher,
    G: Graph<H>,
{
    // Sad phantom is sad
    _h: PhantomData<H>,
    _g: PhantomData<G>,
}

impl<E: Engine, C: Circuit<E>, H: Hasher, G: Graph<H>, P: ParameterSetIdentifier>
    CacheableParameters<E, C, P> for DrgPoRepCompound<H, G>
{
    fn cache_prefix() -> String {
        format!("drg-proof-of-replication-{}", H::name())
    }
}

impl<'a, H, G> CompoundProof<'a, Bls12, DrgPoRep<'a, H, G>, DrgPoRepCircuit<H>>
    for DrgPoRepCompound<H, G>
where
    H: 'a + Hasher,
    G: 'a + Graph<H> + ParameterSetIdentifier + Sync + Send,
{
    fn generate_public_inputs(
        pub_in: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
        // We can ignore k because challenges are generated by caller and included
        // in PublicInputs.
        _k: Option<usize>,
    ) -> Vec<Fr> {
        let replica_id = pub_in.replica_id.expect("missing replica id");
        let challenges = &pub_in.challenges;

        assert_eq!(pub_in.tau.is_none(), pub_params.private);

        let (comm_r, comm_d) = match pub_in.tau {
            None => (None, None),
            Some(tau) => (Some(tau.comm_r), Some(tau.comm_d)),
        };

        let leaves = pub_params.graph.size();

        let replica_id_bits = bytes_into_bits(&replica_id.into_bytes());

        let packed_replica_id =
            multipack::compute_multipacking::<Bls12>(&replica_id_bits[0..<Fr as PrimeField>::Params::CAPACITY as usize]);

        let por_pub_params = merklepor::PublicParams {
            leaves,
            private: pub_params.private,
        };

        let mut input = Vec::new();
        input.extend(packed_replica_id);

        let mut parents = vec![0; pub_params.graph.degree()];
        for challenge in challenges {
            let mut por_nodes = vec![*challenge];
            pub_params.graph.parents(*challenge, &mut parents);
            por_nodes.extend_from_slice(&parents);

            for node in por_nodes {
                let por_pub_inputs = merklepor::PublicInputs {
                    commitment: comm_r,
                    challenge: node,
                };
                let por_inputs = PoRCompound::<H>::generate_public_inputs(
                    &por_pub_inputs,
                    &por_pub_params,
                    None,
                );

                input.extend(por_inputs);
            }

            let por_pub_inputs = merklepor::PublicInputs {
                commitment: comm_d,
                challenge: *challenge,
            };

            let por_inputs =
                PoRCompound::<H>::generate_public_inputs(&por_pub_inputs, &por_pub_params, None);
            input.extend(por_inputs);
        }
        input
    }

    fn circuit<'b>(
        public_inputs: &'b <DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicInputs,
        component_private_inputs: <DrgPoRepCircuit<H> as CircuitComponent>::ComponentPrivateInputs,
        proof: &'b <DrgPoRep<'a, H, G> as ProofScheme<'a>>::Proof,
        public_params: &'b <DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
    ) -> DrgPoRepCircuit<H> {
        let challenges = public_params.challenges_count;
        let len = proof.nodes.len();

        assert!(len <= challenges, "too many challenges");
        assert_eq!(proof.replica_parents.len(), len);
        assert_eq!(proof.replica_nodes.len(), len);

        let replica_nodes: Vec<_> = proof
            .replica_nodes
            .iter()
            .map(|node| Some(node.data.into()))
            .collect();

        let replica_nodes_paths: Vec<_> = proof
            .replica_nodes
            .iter()
            .map(|node| node.proof.as_options())
            .collect();

        let is_private = public_params.private;

        let (data_root, replica_root) = if is_private {
            (
                component_private_inputs.comm_d.expect("is_private"),
                component_private_inputs.comm_r.expect("is_private"),
            )
        } else {
            (
                Root::Val(Some(proof.data_root.into())),
                Root::Val(Some(proof.replica_root.into())),
            )
        };

        let replica_id = public_inputs.replica_id;

        let replica_parents: Vec<_> = proof
            .replica_parents
            .iter()
            .map(|parents| {
                parents
                    .iter()
                    .map(|(_, parent)| Some(parent.data.into()))
                    .collect()
            })
            .collect();

        let replica_parents_paths: Vec<Vec<_>> = proof
            .replica_parents
            .iter()
            .map(|parents| {
                let p: Vec<_> = parents
                    .iter()
                    .map(|(_, parent)| parent.proof.as_options())
                    .collect();
                p
            })
            .collect();

        let data_nodes: Vec<_> = proof
            .nodes
            .iter()
            .map(|node| Some(node.data.into()))
            .collect();

        let data_nodes_paths: Vec<_> = proof
            .nodes
            .iter()
            .map(|node| node.proof.as_options())
            .collect();

        assert_eq!(
            public_inputs.tau.is_none(),
            public_params.private,
            "inconsistent private state"
        );

        DrgPoRepCircuit {
            sloth_iter: public_params.sloth_iter,
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            replica_id: replica_id.map(Into::into),
            degree: public_params.graph.degree(),
            private: public_params.private,
            _h: Default::default(),
        }
    }

    fn blank_circuit(
        public_params: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
    ) -> DrgPoRepCircuit<H> {
        let depth = public_params.graph.merkle_tree_depth() as usize;
        let degree = public_params.graph.degree();
        let challenges_count = public_params.challenges_count;

        let replica_nodes = vec![None; challenges_count];
        let replica_nodes_paths = vec![vec![None; depth]; challenges_count];

        let replica_root = Root::Val(None);
        let replica_parents = vec![vec![None; degree]; challenges_count];
        let replica_parents_paths = vec![vec![vec![None; depth]; degree]; challenges_count];
        let data_nodes = vec![None; challenges_count];
        let data_nodes_paths = vec![vec![None; depth]; challenges_count];
        let data_root = Root::Val(None);

        DrgPoRepCircuit {
            sloth_iter: public_params.sloth_iter,
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            replica_id: None,
            degree: public_params.graph.degree(),
            private: public_params.private,
            _h: Default::default(),
        }
    }
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
impl<H: Hasher> Circuit<Bls12> for DrgPoRepCircuit<H> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
//        let params = self.params;

        let replica_id = self.replica_id;
        let replica_root = self.replica_root;
        let data_root = self.data_root;

        let degree = self.degree;
        let nodes = self.data_nodes.len();

        assert_eq!(self.replica_nodes.len(), nodes);
        assert_eq!(self.replica_nodes_paths.len(), nodes);
        assert_eq!(self.replica_parents.len(), nodes);
        assert_eq!(self.replica_parents_paths.len(), nodes);

        assert_eq!(self.data_nodes_paths.len(), nodes);

        let raw_bytes; // Need let here so borrow in match lives long enough.
        let replica_id_bytes = match replica_id {
            Some(replica_id) => {
                raw_bytes = fr_into_bytes::<Bls12>(&replica_id);
                Some(raw_bytes.as_slice())
            }
            // Used in parameter generation or when circuit is created only for
            // structure and input count.
            None => None,
        };

        // get the replica_id in bits
        let replica_id_bits =
            bytes_into_boolean_vec(cs.ns(|| "replica_id_bits"), replica_id_bytes, 256)?;

        multipack::pack_into_inputs(
            cs.ns(|| "replica_id"),
            &replica_id_bits[0..<Fr as PrimeField>::Params::CAPACITY as usize],
        )?;

        let replica_root_var = Root::Var(replica_root.allocated(cs.ns(|| "replica_root"))?);
        let data_root_var = Root::Var(data_root.allocated(cs.ns(|| "data_root"))?);

        for i in 0..self.data_nodes.len() {
            let mut cs = cs.ns(|| format!("challenge_{}", i));
            // ensure that all inputs are well formed
            let replica_node_path = &self.replica_nodes_paths[i];
            let replica_parents_paths = &self.replica_parents_paths[i];
            let data_node_path = &self.data_nodes_paths[i];

            let replica_node = &self.replica_nodes[i];
            let replica_parents = &self.replica_parents[i];
            let data_node = &self.data_nodes[i];

            assert_eq!(data_node_path.len(), replica_node_path.len());
            assert_eq!(replica_node.is_some(), data_node.is_some());

            // Inclusion checks
            {
                let mut cs = cs.ns(|| "inclusion_checks");
                PoRCircuit::<H>::synthesize(
                    cs.ns(|| "replica_inclusion"),
                    *replica_node,
                    replica_node_path.clone(),
                    replica_root_var.clone(),
                    self.private,
                )?;

                // validate each replica_parents merkle proof
                for j in 0..replica_parents.len() {
                    PoRCircuit::<H>::synthesize(
                        cs.ns(|| format!("parents_inclusion_{}", j)),
                        replica_parents[j],
                        replica_parents_paths[j].clone(),
                        replica_root_var.clone(),
                        self.private,
                    )?;
                }

                // validate data node commitment
                PoRCircuit::<H>::synthesize(
                    cs.ns(|| "data_inclusion"),
                    *data_node,
                    data_node_path.clone(),
                    data_root_var.clone(),
                    self.private,
                )?;
            }

            // Encoding checks
            {
                let mut cs = cs.ns(|| "encoding_checks");
                // get the parents into bits
                let parents_bits: Vec<Vec<Boolean>> = {
                    replica_parents
                        .iter()
                        .enumerate()
                        .map(|(i, val)| -> Result<Vec<Boolean>, SynthesisError> {
//                            let mut v = boolean::field_into_boolean_vec_le(
//                                cs.ns(|| format!("parents_{}_bits", i)),
//                                *val,
//                            )?;
                            let mut v = match val {
                                Some(v) => {
                                    let mut bits =
                                        FpGadget::from(cs.ns(|| format!("allocation of element {}", i)), v)
                                            .to_bits(cs.ns(|| format!("conversion to bits {}", i)))?;
                                    bits.reverse();
                                    bits
                                }
                                None =>
                                    vec![Boolean::Constant(false); 256]
                            };
                            // sad padding is sad
                            while v.len() < 256 {
                                v.push(Boolean::Constant(false));
                            }

                            Ok(v)
                        })
                        .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?
                };

                // generate the encryption key
                let key = kdf(
                    cs.ns(|| "kdf"),
                    replica_id_bits.clone(),
                    parents_bits,
                    degree,
                )?;

                let decoded = sloth::decode(
                    cs.ns(|| "sloth_decode"),
                    &key,
                    *replica_node,
                    self.sloth_iter,
                )?;

                // TODO this should not be here, instead, this should be the leaf Fr in the data_auth_path
                // TODO also note that we need to change/makesurethat the leaves are the data, instead of hashes of the data
                let expected = FpGadget::alloc(cs.ns(|| "data node"), || {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::drgporep;
    use crate::drgraph::{graph_height, new_seed, BucketGraph};
    use crate::fr32::{bytes_into_fr, fr_into_bytes};
    use crate::hasher::{Hasher, PedersenHasher};
    use crate::porep::PoRep;
    use crate::proof::{NoRequirements, ProofScheme};
    use crate::util::data_at_node;

    use algebra::fields::Field;

    use rand::{Rand, Rng, SeedableRng, XorShiftRng};

    #[test]
    fn drgporep_input_circuit_with_bls12_381() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let nodes = 12;
        let degree = 6;
        let challenge = 2;
        let sloth_iter = 1;

        let replica_id: Fr = rng.gen();

        let mut data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::rand(rng)))
            .collect();

        // TODO: don't clone everything
        let original_data = data.clone();
        let data_node: Option<Fr> = Some(
            bytes_into_fr::<Bls12>(
                data_at_node(&original_data, challenge).expect("failed to read original data"),
            )
                .unwrap(),
        );

        let sp = drgporep::SetupParams {
            drg: drgporep::DrgParams {
                nodes,
                degree,
                expansion_degree: 0,
                seed: new_seed(),
            },
            sloth_iter,
            private: false,
            challenges_count: 1,
        };

        let pp = drgporep::DrgPoRep::<PedersenHasher, BucketGraph<_>>::setup(&sp)
            .expect("failed to create drgporep setup");
        let (tau, aux) = drgporep::DrgPoRep::<PedersenHasher, _>::replicate(
            &pp,
            &replica_id.into(),
            data.as_mut_slice(),
            None,
        )
            .expect("failed to replicate");

        let pub_inputs = drgporep::PublicInputs {
            replica_id: Some(replica_id.into()),
            challenges: vec![challenge],
            tau: Some(tau.into()),
        };
        let priv_inputs = drgporep::PrivateInputs::<PedersenHasher> {
            tree_d: &aux.tree_d,
            tree_r: &aux.tree_r,
        };

        let proof_nc =
            drgporep::DrgPoRep::<PedersenHasher, _>::prove(&pp, &pub_inputs, &priv_inputs)
                .expect("failed to prove");

        assert!(
            drgporep::DrgPoRep::<PedersenHasher, _>::verify(&pp, &pub_inputs, &proof_nc)
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
                .validate_data(&fr_into_bytes::<Bls12>(&data_node.unwrap())),
            "failed to verify data commitment with data"
        );

        let mut cs = TestConstraintSystem::<Bls12>::new();
        DrgPoRepCircuit::<PedersenHasher>::synthesize(
            cs.ns(|| "drgporep"),
            sloth_iter,
            vec![replica_node],
            vec![replica_node_path],
            replica_root,
            replica_parents,
            replica_parents_paths,
            vec![data_node],
            vec![data_node_path],
            data_root,
            replica_id,
            degree,
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
//        assert_eq!(cs.num_constraints(), 131216, "wrong number of constraints");
        assert_eq!(cs.num_constraints(), 362622, "wrong number of constraints");


        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        assert_eq!(
            cs.get_input(1, "drgporep/replica_id/input 0/alloc"),
            replica_id.unwrap()
        );
    }

    #[test]
    fn drgporep_input_circuit_num_constraints() {
//        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // 1 GB
        let n = (1 << 30) / 32;
        let m = 6;
        let tree_depth = graph_height(n);
        let sloth_iter = 1;

        let mut cs = TestConstraintSystem::<Bls12>::new();
        DrgPoRepCircuit::<PedersenHasher>::synthesize(
            cs.ns(|| "drgporep"),
            sloth_iter,
            vec![Some(Fr::rand(rng)); 1],
            vec![vec![Some((Fr::rand(rng), false)); tree_depth]; 1],
            Root::Val(Some(Fr::rand(rng))),
            vec![vec![Some(Fr::rand(rng)); m]; 1],
            vec![vec![vec![Some((Fr::rand(rng), false)); tree_depth]; m]; 1],
            vec![Some(Fr::rand(rng)); 1],
            vec![vec![Some((Fr::rand(rng), false)); tree_depth]; 1],
            Root::Val(Some(Fr::rand(rng))),
            Some(Fr::rand(rng)),
            m,
            false,
        )
            .expect("failed to synthesize circuit");

        assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
//        assert_eq!(cs.num_constraints(), 363392, "wrong number of constraints");
        assert_eq!(cs.num_constraints(), 1803894, "wrong number of constraints");
    }


    #[test]
//    #[ignore] // Slow test – run only when compiled for release.
    fn test_drgporep_compound_pedersen() {
        drgporep_test_compound::<PedersenHasher>();
    }
//
//    #[test]
//    #[ignore] // Slow test – run only when compiled for release.
//    fn test_drgporep_compound_blake2s() {
//        drgporep_test_compound::<Blake2sHasher>();
//    }
//
    fn drgporep_test_compound<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let nodes = 5;
        let degree = 2;
        let challenges = vec![1, 3];
        let sloth_iter = 1;

        let replica_id: Fr = rng.gen();
        let mut data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::rand(rng)))
            .collect();

        // Only generate seed once. It would be bad if we used different seeds in the same test.
        let seed = new_seed();

        let setup_params = compound_proof::SetupParams {
            vanilla_params: &drgporep::SetupParams {
                drg: drgporep::DrgParams {
                    nodes,
                    degree,
                    expansion_degree: 0,
                    seed,
                },
                sloth_iter,
                private: false,
                challenges_count: 2,
            },
            partitions: None,
        };

        let public_params =
            DrgPoRepCompound::<H, BucketGraph<_>>::setup(&setup_params).expect("setup failed");

        let (tau, aux) = drgporep::DrgPoRep::<H, _>::replicate(
            &public_params.vanilla_params,
            &replica_id.into(),
            data.as_mut_slice(),
            None,
        )
        .expect("failed to replicate");

        let public_inputs = drgporep::PublicInputs::<H::Domain> {
            replica_id: Some(replica_id.into()),
            challenges,
            tau: Some(tau),
        };

        let private_inputs = drgporep::PrivateInputs {
            tree_d: &aux.tree_d,
            tree_r: &aux.tree_r,
        };

        // This duplication is necessary so public_params don't outlive public_inputs and private_inputs.
        let setup_params = compound_proof::SetupParams {
            vanilla_params: &drgporep::SetupParams {
                drg: drgporep::DrgParams {
                    nodes,
                    degree,
                    expansion_degree: 0,
                    seed,
                },
                sloth_iter,
                private: false,
                challenges_count: 2,
            },
            partitions: None,
        };

        let public_params =
            DrgPoRepCompound::<H, BucketGraph<_>>::setup(&setup_params).expect("setup failed");

        {
            let (circuit, inputs) = DrgPoRepCompound::<H, _>::circuit_for_test(
                &public_params,
                &public_inputs,
                &private_inputs,
            );

            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");

            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));
        }

        {
            let gparams =
                DrgPoRepCompound::<H, _>::groth_params(&public_params.vanilla_params)
                    .expect("failed to get groth params");

            let proof = DrgPoRepCompound::<H, _>::prove(
                &public_params,
                &public_inputs,
                &private_inputs,
                &gparams,
            )
            .expect("failed while proving");

            let verified = DrgPoRepCompound::<H, _>::verify(
                &public_params,
                &public_inputs,
                &proof,
                &NoRequirements,
            )
            .expect("failed while verifying");

            assert!(verified);
        }
    }
}
