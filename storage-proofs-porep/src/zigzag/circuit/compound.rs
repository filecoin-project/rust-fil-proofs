use std::marker::PhantomData;

use bellperson::Circuit;
use blstrs::Scalar as Fr;
use filecoin_hashers::Hasher;
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    drgraph::Graph,
    error::Result,
    merkle::MerkleTreeTrait,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    proof::ProofScheme,
};

use crate::zigzag::{
    circuit::ZigZagCircuit,
    vanilla::{PublicInputs, PublicParams, ZigZagDrgPoRep},
};

/// Groth16 compound proof for ZigZag layered PoRep.
///
/// Uses a distinct `cache_prefix` (`"zigzag-proof-of-replication"`) and a distinct public-params
/// identifier so ZigZag gets its own Groth16 parameters, separate from Stacked DRG.
pub struct ZigZagCompound<Tree: MerkleTreeTrait, G: 'static + Hasher> {
    _tree: PhantomData<Tree>,
    _g: PhantomData<G>,
}

impl<C: Circuit<Fr>, P: ParameterSetMetadata, Tree: MerkleTreeTrait, G: 'static + Hasher>
    CacheableParameters<C, P> for ZigZagCompound<Tree, G>
{
    fn cache_prefix() -> String {
        format!(
            "zigzag-proof-of-replication-{}-{}",
            Tree::display(),
            G::name()
        )
    }
}

impl<'a, Tree, G> CompoundProof<'a, ZigZagDrgPoRep<Tree, G>, ZigZagCircuit<Tree, G>>
    for ZigZagCompound<Tree, G>
where
    Tree: 'static + MerkleTreeTrait,
    G: 'static + Hasher,
{
    fn generate_public_inputs(
        pub_in: &PublicInputs<<Tree::Hasher as Hasher>::Domain, G::Domain>,
        pub_params: &PublicParams<Tree>,
        k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let tau = pub_in.tau.as_ref().expect("missing tau");

        let mut inputs = Vec::new();

        // Must exactly match the inputize order in `ZigZagCircuit::synthesize`.
        inputs.push(pub_in.replica_id.into());
        inputs.push(tau.comm_d.into());
        inputs.push(tau.comm_r.into());

        let layers = pub_params.layer_challenges.layers();
        let leaves = pub_params.graph.size();
        let degree = pub_params.graph.degree();

        let mut layer_graph = pub_params.graph.clone();
        for layer in 0..layers {
            let challenges =
                pub_in.challenges(&pub_params.layer_challenges, leaves, layer as u8, k);

            let mut parents = vec![0u32; degree];
            for challenge in challenges {
                let challenge = challenge % leaves;

                inputs.push(Fr::from(challenge as u64));
                inputs.push(Fr::from(challenge as u64));

                layer_graph.parents(challenge, &mut parents)?;
                for parent in &parents {
                    inputs.push(Fr::from(*parent as u64));
                }
            }

            layer_graph = ZigZagDrgPoRep::<Tree, G>::transform(&layer_graph);
        }

        inputs.push(pub_in.comm_r_star.into());

        Ok(inputs)
    }

    fn circuit(
        public_inputs: &PublicInputs<<Tree::Hasher as Hasher>::Domain, G::Domain>,
        _component_private_inputs: <ZigZagCircuit<Tree, G> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<ZigZagDrgPoRep<Tree, G> as ProofScheme<'a>>::Proof,
        public_params: &PublicParams<Tree>,
        _partition_k: Option<usize>,
    ) -> Result<ZigZagCircuit<Tree, G>> {
        let tau = public_inputs.tau.as_ref();

        Ok(ZigZagCircuit {
            public_params: public_params.clone(),
            replica_id: Some(public_inputs.replica_id),
            comm_d: tau.map(|t| t.comm_d),
            comm_r: tau.map(|t| t.comm_r),
            comm_r_star: Some(public_inputs.comm_r_star),
            proof: Some(vanilla_proof.clone()),
            _g: PhantomData,
        })
    }

    fn blank_circuit(public_params: &PublicParams<Tree>) -> ZigZagCircuit<Tree, G> {
        ZigZagCircuit {
            public_params: public_params.clone(),
            replica_id: None,
            comm_d: None,
            comm_r: None,
            comm_r_star: None,
            proof: None,
            _g: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use filecoin_hashers::{
        poseidon::{PoseidonDomain, PoseidonHasher},
        sha256::Sha256Hasher,
    };
    use generic_array::typenum::{U0, U2};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        api_version::ApiVersion,
        compound_proof::{self, CompoundProof},
        drgraph::BASE_DEGREE,
        merkle::{DiskStore, MerkleTreeWrapper},
        util::NODE_SIZE,
        TEST_SEED,
    };

    use crate::zigzag::vanilla::{
        ChallengeRequirements, LayerChallenges, PrivateInputs, SetupParams, ZigZagDrgPoRep,
        EXP_DEGREE,
    };

    type ZZTree = MerkleTreeWrapper<PoseidonHasher, DiskStore<PoseidonDomain>, U2, U0, U0>;
    type Piece = Sha256Hasher;

    #[test]
    fn zigzag_compound_groth16_roundtrip() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        let nodes = 128;
        let layers = 2;
        let porep_id = [23u8; 32];

        let setup_params = compound_proof::SetupParams {
            vanilla_params: SetupParams {
                nodes,
                degree: BASE_DEGREE,
                expansion_degree: EXP_DEGREE,
                porep_id,
                api_version: ApiVersion::V1_2_0,
                layer_challenges: LayerChallenges::new_fixed(layers, 1),
            },
            partitions: Some(1),
            priority: false,
        };

        let public_params = ZigZagCompound::<ZZTree, Piece>::setup(&setup_params)
            .expect("compound setup failed");

        let replica_id = PoseidonDomain::from([1u8; 32]);
        let mut data = vec![0u8; nodes * NODE_SIZE];

        let (tau, tree_d, replica_trees) =
            ZigZagDrgPoRep::<ZZTree, Piece>::transform_and_replicate_layers(
                &public_params.vanilla_params.graph,
                &public_params.vanilla_params.layer_challenges,
                &replica_id,
                &mut data,
                None,
            )
            .expect("replication failed");

        let public_inputs = PublicInputs {
            replica_id,
            seed: None,
            tau: Some(tau.simplify()),
            comm_r_star: tau.comm_r_star,
            k: None,
        };
        let private_inputs = PrivateInputs::<ZZTree, Piece> {
            tree_d,
            aux: replica_trees,
            layer_comm_rs: tau.layer_comm_rs.clone(),
            comm_d: tau.comm_d,
        };

        {
            use bellperson::util_cs::test_cs::TestConstraintSystem;
            use bellperson::Circuit;

            let (circuit, inputs) = ZigZagCompound::<ZZTree, Piece>::circuit_for_test(
                &public_params,
                &public_inputs,
                &private_inputs,
            )
            .expect("circuit_for_test failed");

            let mut cs = TestConstraintSystem::<Fr>::new();
            circuit.synthesize(&mut cs).expect("synthesis failed");
            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert!(cs.verify(&inputs), "generated public inputs do not verify");
        }

        let groth_params = ZigZagCompound::<ZZTree, Piece>::groth_params(
            Some(&mut rng),
            &public_params.vanilla_params,
        )
        .expect("groth param generation failed");

        let proofs = ZigZagCompound::<ZZTree, Piece>::prove(
            &public_params,
            &public_inputs,
            &private_inputs,
            &groth_params,
        )
        .expect("groth prove failed");

        let verifying_key = ZigZagCompound::<ZZTree, Piece>::verifying_key::<XorShiftRng>(
            None,
            &public_params.vanilla_params,
        )
        .expect("failed to get verifying key");
        let prepared_verifying_key =
            bellperson::groth16::prepare_verifying_key(&verifying_key);
        let multi_proof =
            storage_proofs_core::multi_proof::MultiProof::new(proofs, &prepared_verifying_key);

        let verified = ZigZagCompound::<ZZTree, Piece>::verify(
            &public_params,
            &public_inputs,
            &multi_proof,
            &ChallengeRequirements {
                minimum_challenges: 1,
            },
        )
        .expect("groth verify errored");

        assert!(verified, "groth16 proof did not verify");
    }
}
