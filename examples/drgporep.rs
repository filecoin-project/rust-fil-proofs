extern crate bellman;
extern crate indicatif;
extern crate pairing;
extern crate proofs;
extern crate rand;
extern crate sapling_crypto;

use bellman::groth16::*;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use proofs::example_helper::Example;
use rand::Rng;
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

use proofs::fr32::{bytes_into_fr, fr_into_bytes};
use proofs::porep::PoRep;
use proofs::proof::ProofScheme;
use proofs::util::data_at_node;
use proofs::{circuit, drgporep};

struct DrgPoRepExample<'a, E: JubjubEngine> {
    params: &'a E::Params,
    lambda: usize,
    replica_node: Option<&'a E::Fr>,
    replica_node_path: &'a [Option<(E::Fr, bool)>],
    replica_root: Option<E::Fr>,
    replica_parents: Vec<Option<&'a E::Fr>>,
    replica_parents_paths: &'a [Vec<Option<(E::Fr, bool)>>],
    data_node: Option<&'a E::Fr>,
    data_node_path: Vec<Option<(E::Fr, bool)>>,
    data_root: Option<E::Fr>,
    prover_id: Option<&'a [u8]>,
    m: usize,
}

impl<'a, E: JubjubEngine> Circuit<E> for DrgPoRepExample<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        circuit::drgporep::drgporep(
            cs.namespace(|| "drgporep"),
            self.params,
            self.lambda,
            self.replica_node,
            self.replica_node_path,
            self.replica_root,
            self.replica_parents,
            self.replica_parents_paths,
            self.data_node,
            self.data_node_path,
            self.data_root,
            self.prover_id,
            self.m,
        )
    }
}

#[derive(Default)]
struct DrgPoRepApp {}

impl Example<Bls12> for DrgPoRepApp {
    fn name() -> String {
        "DrgPoRep".to_string()
    }

    fn generate_engine_params() -> JubjubBls12 {
        JubjubBls12::new()
    }

    fn generate_groth_params<R: Rng>(
        &mut self,
        rng: &mut R,
        jubjub_params: &JubjubBls12,
        tree_depth: usize,
        _challenge_count: usize,
        lambda: usize,
        m: usize,
    ) -> Parameters<Bls12> {
        generate_random_parameters::<Bls12, _, _>(
            DrgPoRepExample {
                params: jubjub_params,
                lambda: lambda * 8,
                replica_node: None,
                replica_node_path: &vec![None; tree_depth],
                replica_root: None,
                replica_parents: vec![None; m],
                replica_parents_paths: &vec![vec![None; tree_depth]; m],
                data_node: None,
                data_node_path: vec![None; tree_depth],
                data_root: None,
                prover_id: None,
                m,
            },
            rng,
        ).unwrap()
    }

    fn samples() -> usize {
        5
    }

    fn create_proof<R: Rng>(
        &mut self,
        rng: &mut R,
        engine_params: &JubjubBls12,
        groth_params: &Parameters<Bls12>,
        _tree_depth: usize,
        _challenge_count: usize,
        leaves: usize,
        lambda: usize,
        m: usize,
    ) -> Proof<Bls12> {
        let prover_id: Fr = rng.gen();
        let prover_id_bytes = fr_into_bytes::<Bls12>(&prover_id);
        let mut data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let original_data = data.clone();
        let challenge = 2;

        let sp = drgporep::SetupParams {
            lambda,
            drg: drgporep::DrgParams { n: leaves, m },
        };

        let pp = drgporep::DrgPoRep::setup(&sp).expect("failed to create drgporep setup");

        let (tau, aux) =
            drgporep::DrgPoRep::replicate(&pp, prover_id_bytes.as_slice(), data.as_mut_slice())
                .expect("failed to replicate");

        let pub_inputs = drgporep::PublicInputs {
            prover_id: &prover_id,
            challenge,
            tau: &tau,
        };
        let priv_inputs = drgporep::PrivateInputs {
            replica: data.as_slice(),
            aux: &aux,
        };

        let proof_nc =
            drgporep::DrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).expect("failed to prove");

        assert!(
            drgporep::DrgPoRep::verify(&pp, &pub_inputs, &proof_nc).expect("failed to verify"),
            "failed to verify (non circuit)"
        );

        let replica_node = Some(&proof_nc.replica_node.data);

        let replica_node_path = proof_nc.replica_node.proof.as_options();
        let replica_root = Some(proof_nc.replica_node.proof.root().into());
        let replica_parents: Vec<_> = proof_nc
            .replica_parents
            .iter()
            .map(|(_, parent)| Some(&parent.data))
            .collect();
        let replica_parents_paths: Vec<_> = proof_nc
            .replica_parents
            .iter()
            .map(|(_, parent)| parent.proof.as_options())
            .collect();
        let data_node = bytes_into_fr::<Bls12>(
            data_at_node(&original_data, challenge, lambda).expect("failed to read original data"),
        ).unwrap();

        let data_node_path = proof_nc.node.as_options();
        let data_root = Some(proof_nc.node.root().into());
        let prover_id = Some(prover_id_bytes.as_slice());

        assert!(
            proof_nc.node.validate(challenge),
            "failed to verify data commitment"
        );
        assert!(
            proof_nc.node.validate_data(&data_node),
            "failed to verify data commitment with data"
        );
        // create an instance of our circut (with the witness)
        let c = DrgPoRepExample {
            params: engine_params,
            lambda: lambda * 8,
            replica_node,
            replica_node_path: &replica_node_path,
            replica_root,
            replica_parents,
            replica_parents_paths: &replica_parents_paths,
            data_node: Some(&data_node),
            data_node_path,
            data_root,
            prover_id,
            m,
        };

        // create groth16 proof
        create_random_proof(c, groth_params, rng).expect("failed to create random proof")
    }

    fn verify_proof(
        &mut self,
        _proof: &Proof<Bls12>,
        _pvk: &PreparedVerifyingKey<Bls12>,
    ) -> Option<bool> {
        // not implemented yet
        None
    }
}

fn main() {
    DrgPoRepApp::main()
}
