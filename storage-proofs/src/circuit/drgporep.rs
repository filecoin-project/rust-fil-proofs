use std::marker::PhantomData;

use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use fil_sapling_crypto::circuit::boolean::{field_into_boolean_vec_le, Boolean};
use fil_sapling_crypto::circuit::multipack;
use fil_sapling_crypto::circuit::num::AllocatedNum;
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::constraint;
use crate::circuit::kdf::kdf;
use crate::circuit::por::{PoRCircuit, PoRCompound};
use crate::circuit::sloth;
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgporep::DrgPoRep;
use crate::drgraph::Graph;
use crate::fr32::fr_into_bytes;
use crate::hasher::{Domain, Hasher};
use crate::hybrid_merklepor;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::proof::ProofScheme;
use crate::util::{bytes_into_bits, bytes_into_boolean_vec};

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
/// * `degree` - The degree of the graph.
///
//implement_drgporep!(
//    DrgPoRepCircuit,
//    DrgPoRepCompound,
//    "drg-proof-of-replication",
//    false
//);

pub struct DrgPoRepCircuit<'a, E, AH, BH>
where
    E: JubjubEngine,
    AH: Hasher,
    BH: Hasher,
{
    params: &'a E::Params,
    replica_nodes: Vec<Option<E::Fr>>,
    #[allow(clippy::type_complexity)]
    replica_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    replica_root: Root<E>,
    replica_parents: Vec<Vec<Option<E::Fr>>>,
    #[allow(clippy::type_complexity)]
    replica_parents_paths: Vec<Vec<Vec<Option<(E::Fr, bool)>>>>,
    data_nodes: Vec<Option<E::Fr>>,
    #[allow(clippy::type_complexity)]
    data_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    data_root: Root<E>,
    replica_id: Option<E::Fr>,
    degree: usize,
    beta_height: usize,
    prev_layer_beta_height: usize,
    private: bool,
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

impl<'a, E, AH, BH> DrgPoRepCircuit<'a, E, AH, BH>
where
    E: JubjubEngine,
    AH: Hasher,
    BH: Hasher,
{
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &E::Params,
        replica_nodes: Vec<Option<E::Fr>>,
        replica_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
        replica_root: Root<E>,
        replica_parents: Vec<Vec<Option<E::Fr>>>,
        replica_parents_paths: Vec<Vec<Vec<Option<(E::Fr, bool)>>>>,
        data_nodes: Vec<Option<E::Fr>>,
        data_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
        data_root: Root<E>,
        replica_id: Option<E::Fr>,
        degree: usize,
        beta_height: usize,
        prev_layer_beta_height: usize,
        private: bool,
    ) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        DrgPoRepCircuit::<_, AH, BH> {
            params,
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
            beta_height,
            prev_layer_beta_height,
            private,
            _ah: PhantomData,
            _bh: PhantomData,
        }
        .synthesize(&mut cs)
    }
}

#[derive(Clone)]
pub struct ComponentPrivateInputs<E: JubjubEngine> {
    pub comm_r: Option<Root<E>>,
    pub comm_d: Option<Root<E>>,
}

impl<E: JubjubEngine> Default for ComponentPrivateInputs<E> {
    fn default() -> ComponentPrivateInputs<E> {
        ComponentPrivateInputs {
            comm_r: None,
            comm_d: None,
        }
    }
}

impl<'a, E, AH, BH> CircuitComponent for DrgPoRepCircuit<'a, E, AH, BH>
where
    E: JubjubEngine,
    AH: Hasher,
    BH: Hasher,
{
    type ComponentPrivateInputs = ComponentPrivateInputs<E>;
}

pub struct DrgPoRepCompound<AH, BH, G>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH>,
{
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
    _g: PhantomData<G>,
}

impl<E, C, AH, BH, G, P> CacheableParameters<E, C, P> for DrgPoRepCompound<AH, BH, G>
where
    E: JubjubEngine,
    C: Circuit<E>,
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH>,
    P: ParameterSetMetadata,
{
    fn cache_prefix() -> String {
        format!("drg-proof-of-replication-{}-{}", AH::name(), BH::name())
    }
}

impl<'a, AH, BH, G>
    CompoundProof<'a, Bls12, DrgPoRep<'a, AH, BH, G>, DrgPoRepCircuit<'a, Bls12, AH, BH>>
    for DrgPoRepCompound<AH, BH, G>
where
    AH: 'static + Hasher,
    BH: 'static + Hasher,
    G: 'a + Graph<AH, BH> + ParameterSetMetadata + Sync + Send,
{
    fn generate_public_inputs(
        pub_in: &<DrgPoRep<'a, AH, BH, G> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<DrgPoRep<'a, AH, BH, G> as ProofScheme<'a>>::PublicParams,
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
            multipack::compute_multipacking::<Bls12>(&replica_id_bits[0..Fr::CAPACITY as usize]);

        let por_pub_params = hybrid_merklepor::PublicParams {
            leaves,
            beta_height: pub_params.beta_height,
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
                let por_pub_inputs = hybrid_merklepor::PublicInputs {
                    commitment: comm_r,
                    challenge: node,
                };
                let por_inputs = PoRCompound::<AH, BH>::generate_public_inputs(
                    &por_pub_inputs,
                    &por_pub_params,
                    None,
                );

                input.extend(por_inputs);
            }

            let por_pub_inputs = hybrid_merklepor::PublicInputs {
                commitment: comm_d,
                challenge: *challenge,
            };

            let por_inputs = PoRCompound::<AH, BH>::generate_public_inputs(
                &por_pub_inputs,
                &por_pub_params,
                None,
            );
            input.extend(por_inputs);
        }
        input
    }

    fn circuit<'b>(
        public_inputs: &'b <DrgPoRep<'a, AH, BH, G> as ProofScheme<'a>>::PublicInputs,
        component_private_inputs: <DrgPoRepCircuit<'a, Bls12, AH, BH> as CircuitComponent>::ComponentPrivateInputs,
        proof: &'b <DrgPoRep<'a, AH, BH, G> as ProofScheme<'a>>::Proof,
        public_params: &'b <DrgPoRep<'a, AH, BH, G> as ProofScheme<'a>>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> DrgPoRepCircuit<'a, Bls12, AH, BH> {
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
            params: engine_params,
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
            beta_height: public_params.beta_height,
            prev_layer_beta_height: public_params.prev_layer_beta_height,
            private: public_params.private,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    fn blank_circuit(
        public_params: &<DrgPoRep<'a, AH, BH, G> as ProofScheme<'a>>::PublicParams,
        params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> DrgPoRepCircuit<'a, Bls12, AH, BH> {
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
            params,
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
            beta_height: public_params.beta_height,
            prev_layer_beta_height: public_params.prev_layer_beta_height,
            private: public_params.private,
            _ah: PhantomData,
            _bh: PhantomData,
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
impl<'a, E, AH, BH> Circuit<E> for DrgPoRepCircuit<'a, E, AH, BH>
where
    E: JubjubEngine,
    AH: Hasher,
    BH: Hasher,
{
    fn synthesize<CS>(self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        let params = self.params;
        let replica_root = self.replica_root;
        let data_root = self.data_root;
        let degree = self.degree;
        let n_challenges = self.data_nodes.len();

        assert_eq!(self.replica_nodes.len(), n_challenges);
        assert_eq!(self.replica_nodes_paths.len(), n_challenges);
        assert_eq!(self.replica_parents.len(), n_challenges);
        assert_eq!(self.replica_parents_paths.len(), n_challenges);
        assert_eq!(self.data_nodes_paths.len(), n_challenges);

        // A replica-id of `None` is used in Groth parameter generation or when the
        // `DrgPoRepCircuit` is being created only for structure and input count.
        let replica_id_bytes = self
            .replica_id
            .as_ref()
            .map(|replica_id_fr| fr_into_bytes::<E>(replica_id_fr));

        let replica_id_bytes_slice = replica_id_bytes.as_ref().map(Vec::as_slice);

        let replica_id_bits = bytes_into_boolean_vec(
            cs.namespace(|| "replica_id_bits"),
            replica_id_bytes_slice,
            256,
        )?;

        // Compactly allocate `replica_id_bits` as a single public input (each bit is not allocated
        // individually, many bits are allocated using a single `Fr` allocation).
        multipack::pack_into_inputs(
            cs.namespace(|| "replica_id"),
            &replica_id_bits[..Fr::CAPACITY as usize],
        )?;

        // Allocate the replica tree's root if it has not already been allocated.
        let replica_root = replica_root
            .allocated(cs.namespace(|| "replica_root"))
            .map(Root::Var)?;

        // Allocate the data tree's root if it has not already been allocated.
        let data_root = data_root
            .allocated(cs.namespace(|| "data_root"))
            .map(Root::Var)?;

        for i in 0..n_challenges {
            // Create a namespace for the current challenge.
            let mut cs = cs.namespace(|| format!("challenge_{}", i));

            let data_node = &self.data_nodes[i];
            let data_node_path = &self.data_nodes_paths[i];
            let replica_node = &self.replica_nodes[i];
            let replica_node_path = &self.replica_nodes_paths[i];
            let replica_parents = &self.replica_parents[i];
            let replica_parents_paths = &self.replica_parents_paths[i];

            assert_eq!(data_node_path.len(), replica_node_path.len());

            // If `replica_node` and `data_node` are both `None` we are using this circuit for Groth
            // parameter generation, otherwise both should be `Some`. It is never the case that one
            // is `None` and the other is `Some`.
            assert_eq!(replica_node.is_some(), data_node.is_some());

            // Do inclusion checks. We isolate the below code into its own code block so that our
            // mutable borrow of the challenge namespace (`cs` above) using the inclusion check
            // namespace (`cs` below) is dropped when we are done using it.
            {
                let mut cs = cs.namespace(|| "inclusion_checks");

                // Validate the challenge's replica tree Merkle proof.
                PoRCircuit::<E, AH, BH>::synthesize(
                    cs.namespace(|| "replica_inclusion"),
                    &params,
                    *replica_node,
                    replica_node_path.clone(),
                    replica_root.clone(),
                    self.beta_height,
                    self.private,
                )?;

                // Validate the Merkle proof for each of the challenge's parents.
                for j in 0..replica_parents.len() {
                    PoRCircuit::<E, AH, BH>::synthesize(
                        cs.namespace(|| format!("parents_inclusion_{}", j)),
                        &params,
                        replica_parents[j],
                        replica_parents_paths[j].clone(),
                        replica_root.clone(),
                        self.beta_height,
                        self.private,
                    )?;
                }

                // Validate the challenge's data tree Merkle proof.
                PoRCircuit::<E, AH, BH>::synthesize(
                    cs.namespace(|| "data_inclusion"),
                    &params,
                    *data_node,
                    data_node_path.clone(),
                    data_root.clone(),
                    self.prev_layer_beta_height,
                    self.private,
                )?;
            }

            // Do encoding checks. We isolate the below code into its own code block so that our
            // mutable borrow of the challenge namespace (`cs` above) using the encoding check
            // namespace (`cs` below) is dropped when we are done using it.
            {
                let mut cs = cs.namespace(|| "encoding_checks");

                // Convert (and allocate) each parent's value into bits.
                let parents_bits = replica_parents
                    .iter()
                    .enumerate()
                    .map(|(i, val)| {
                        let mut bits = field_into_boolean_vec_le(
                            cs.namespace(|| format!("parents_{}_bits", i)),
                            *val,
                        )?;

                        // Add padding if necessary.
                        let len = bits.len();
                        let pad_len = 256 - len % 256;
                        let new_len = len + pad_len;
                        bits.resize(new_len, Boolean::Constant(false));

                        Ok(bits)
                    })
                    .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?;

                // Generate the encryption key.
                let key = kdf(
                    cs.namespace(|| "kdf"),
                    replica_id_bits.clone(),
                    parents_bits,
                    degree,
                )?;

                let decoded = sloth::decode(cs.namespace(|| "sloth_decode"), &key, *replica_node)?;

                // TODO this should not be here, instead, this should be the leaf Fr in the
                // data_auth_path.
                //
                // TODO also note that we need to change/make sure that the leaves are the data,
                // instead of hashes of the data.
                let expected = AllocatedNum::alloc(cs.namespace(|| "data node"), || {
                    data_node.ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

                // Ensure that the encrypted data and `data_node` match.
                constraint::equal(&mut cs, || "equality", &expected, &decoded);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::test::*;
    use crate::compound_proof::{self, CompoundProof};
    use crate::drgporep;
    use crate::drgraph::{graph_height, new_seed, BucketGraph};
    use crate::fr32::{bytes_into_fr, fr_into_bytes};
    use crate::hasher::blake2s::Blake2sDomain;
    use crate::hasher::hybrid::HybridDomain;
    use crate::hasher::pedersen::PedersenDomain;
    use crate::hasher::{Blake2sHasher, Hasher, PedersenHasher};
    use crate::porep::PoRep;
    use crate::proof::{NoRequirements, ProofScheme};
    use crate::settings;
    use crate::util::data_at_node;

    use ff::Field;
    use fil_sapling_crypto::jubjub::JubjubBls12;
    use rand::{Rand, Rng, SeedableRng, XorShiftRng};

    #[test]
    fn drgporep_input_circuit_with_bls12_381() {
        const N_NODES: usize = 16;
        const BETA_HEIGHT: usize = 1;
        const DEGREE: usize = 6;
        const CHALLENGE: usize = 2;

        type DrgPoRep<'a> = drgporep::DrgPoRep<
            'a,
            PedersenHasher,
            Blake2sHasher,
            BucketGraph<PedersenHasher, Blake2sHasher>,
        >;

        let window_size = settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size;
        let params = &JubjubBls12::new_with_window_size(window_size);

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let replica_id: Fr = rng.gen();

        let mut data: Vec<u8> = (0..N_NODES)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        // TODO: don't clone everything
        let original_data = data.clone();
        let data_node: Option<Fr> = Some(
            bytes_into_fr::<Bls12>(
                data_at_node(&original_data, CHALLENGE).expect("failed to read original data"),
            )
            .unwrap(),
        );

        let prev_layer_beta_height = (N_NODES as f32).log2().ceil() as usize + 1;

        let sp = drgporep::SetupParams {
            drg: drgporep::DrgParams {
                nodes: N_NODES,
                degree: DEGREE,
                expansion_degree: 0,
                seed: new_seed(),
            },
            private: false,
            challenges_count: 1,
            beta_height: BETA_HEIGHT,
            prev_layer_beta_height,
        };

        let pp = DrgPoRep::setup(&sp).expect("failed to create drgporep setup");

        // If `BETA_HEIGHT` is set to `1` then the replica-id will always be a beta domain.
        let replica_id_hybrid_domain: HybridDomain<PedersenDomain, Blake2sDomain> =
            HybridDomain::Beta(replica_id.clone().into());

        let (tau, aux) =
            DrgPoRep::replicate(&pp, &replica_id_hybrid_domain, data.as_mut_slice(), None)
                .expect("failed to replicate");

        let pub_inputs = drgporep::PublicInputs {
            replica_id: Some(replica_id_hybrid_domain),
            challenges: vec![CHALLENGE],
            tau: Some(tau),
        };

        let priv_inputs = drgporep::PrivateInputs::<PedersenHasher, Blake2sHasher> {
            tree_d: &aux.tree_d,
            tree_r: &aux.tree_r,
        };

        let proof_nc = DrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).expect("failed to prove");

        let is_valid = DrgPoRep::verify(&pp, &pub_inputs, &proof_nc).expect("failed to verify");
        assert!(is_valid, "failed to verify (non circuit)");

        let data_commitment_is_valid = proof_nc.nodes[0].proof.validate(CHALLENGE);
        assert!(data_commitment_is_valid, "failed to verify data commitment");

        // let challenge_value_matches_proof = proof_nc.nodes[0]
        //     .proof
        //     .challenge_value_matches_bytes(&fr_into_bytes::<Bls12>(&data_node.unwrap()));

        // assert!(
        //     challenge_value_matches_proof,
        //     "failed to verify data commitment with data"
        // );

        let replica_node: Option<Fr> = Some(proof_nc.replica_nodes[0].data.into());
        let replica_node_path = proof_nc.replica_nodes[0].proof.as_options();
        let replica_root = Root::Val(Some(proof_nc.replica_root.into()));

        let replica_parents: Vec<Vec<Option<Fr>>> = proof_nc
            .replica_parents
            .iter()
            .map(|v| {
                v.iter()
                    .map(|(_, parent)| Some(parent.data.into()))
                    .collect()
            })
            .collect();

        let replica_parents_paths: Vec<Vec<Vec<Option<(Fr, bool)>>>> = proof_nc
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

        let mut cs = TestConstraintSystem::<Bls12>::new();

        DrgPoRepCircuit::<Bls12, PedersenHasher, Blake2sHasher>::synthesize(
            cs.namespace(|| "drgporep"),
            params,
            vec![replica_node],
            vec![replica_node_path],
            replica_root,
            replica_parents,
            replica_parents_paths,
            vec![data_node],
            vec![data_node_path],
            data_root,
            Some(replica_id),
            DEGREE,
            BETA_HEIGHT,
            usize::max_value(),
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
        assert_eq!(cs.num_constraints(), 352574, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
        assert_eq!(cs.get_input(1, "drgporep/replica_id/input 0"), replica_id);
    }

    #[test]
    fn drgporep_input_circuit_num_constraints() {
        let window_size = settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size;
        let params = &JubjubBls12::new_with_window_size(window_size);

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // 1 GB
        let n = (1 << 30) / 32;
        let m = 6;
        let tree_depth = graph_height(n);

        let mut cs = TestConstraintSystem::<Bls12>::new();
        DrgPoRepCircuit::<Bls12, PedersenHasher, PedersenHasher>::synthesize(
            cs.namespace(|| "drgporep"),
            params,
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
            0,
            usize::max_value(),
            false,
        )
        .expect("failed to synthesize circuit");

        assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 361789, "wrong number of constraints");
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_drgporep_compound_pedersen() {
        drgporep_test_compound::<PedersenHasher, PedersenHasher>();
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_drgporep_compound_blake2s() {
        drgporep_test_compound::<Blake2sHasher, Blake2sHasher>();
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_drgporep_compound_pedersen_blake2s() {
        drgporep_test_compound::<PedersenHasher, Blake2sHasher>();
    }

    fn drgporep_test_compound<AH, BH>()
    where
        AH: 'static + Hasher,
        BH: 'static + Hasher,
    {
        const N_NODES: usize = 8;
        const BETA_HEIGHT: usize = 0;
        const PREV_LAYER_BETA_HEIGHT: usize = 4;
        const DEGREE: usize = 2;

        let window_size = settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size;
        let params = &JubjubBls12::new_with_window_size(window_size);

        let challenges = vec![1, 3];

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // The beta height for this layer is 0, so the replica-id will be from the alpha domain.
        let replica_id: HybridDomain<AH::Domain, BH::Domain> = HybridDomain::Alpha(rng.gen());

        let mut data: Vec<u8> = (0..N_NODES)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::rand(rng)))
            .collect();

        // Only generate seed once. It would be bad if we used different seeds in the same test.
        let seed = new_seed();

        let setup_params = compound_proof::SetupParams {
            vanilla_params: &drgporep::SetupParams {
                drg: drgporep::DrgParams {
                    nodes: N_NODES,
                    degree: DEGREE,
                    expansion_degree: 0,
                    seed,
                },
                private: false,
                challenges_count: 2,
                beta_height: BETA_HEIGHT,
                prev_layer_beta_height: PREV_LAYER_BETA_HEIGHT,
            },
            engine_params: params,
            partitions: None,
        };

        let public_params = DrgPoRepCompound::<AH, BH, BucketGraph<AH, BH>>::setup(&setup_params)
            .expect("setup failed");

        let (tau, aux) = drgporep::DrgPoRep::<AH, BH, BucketGraph<AH, BH>>::replicate(
            &public_params.vanilla_params,
            &replica_id,
            data.as_mut_slice(),
            None,
        )
        .expect("failed to replicate");

        let public_inputs = drgporep::PublicInputs::<AH::Domain, BH::Domain> {
            replica_id: Some(replica_id),
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
                    nodes: N_NODES,
                    degree: DEGREE,
                    expansion_degree: 0,
                    seed,
                },
                private: false,
                challenges_count: 2,
                beta_height: BETA_HEIGHT,
                prev_layer_beta_height: PREV_LAYER_BETA_HEIGHT,
            },
            engine_params: params,
            partitions: None,
        };

        let public_params = DrgPoRepCompound::<AH, BH, BucketGraph<AH, BH>>::setup(&setup_params)
            .expect("setup failed");

        {
            let (circuit, inputs) =
                DrgPoRepCompound::<AH, BH, BucketGraph<AH, BH>>::circuit_for_test(
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
            let gparams = DrgPoRepCompound::<AH, BH, BucketGraph<AH, BH>>::groth_params(
                &public_params.vanilla_params,
                &params,
            )
            .expect("failed to get groth params");

            let proof = DrgPoRepCompound::<AH, BH, BucketGraph<AH, BH>>::prove(
                &public_params,
                &public_inputs,
                &private_inputs,
                &gparams,
            )
            .expect("failed while proving");

            let verified = DrgPoRepCompound::<AH, BH, BucketGraph<AH, BH>>::verify(
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
