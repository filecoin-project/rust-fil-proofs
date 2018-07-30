extern crate bellman;
extern crate pairing;
extern crate pbr;
extern crate proofs;
extern crate rand;
extern crate sapling_crypto;

use bellman::groth16::*;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::Bls12;
use proofs::example_helper::Example;
use rand::Rng;
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

use proofs::circuit;
use proofs::circuit::bench::BenchCS;
use proofs::fr32::fr_into_bytes;
use proofs::test_helper::fake_drgpoprep_proof;

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

const SLOTH_ROUNDS: usize = 1;

impl DrgPoRepApp {
    fn create_bench_circuit<R: Rng>(
        &mut self,
        rng: &mut R,
        engine_params: &JubjubBls12,
        tree_depth: usize,
        _challenge_count: usize,
        _leaves: usize,
        lambda: usize,
        m: usize,
    ) -> BenchCS<Bls12> {
        let f = fake_drgpoprep_proof(rng, tree_depth, m, SLOTH_ROUNDS);

        let prover_bytes = fr_into_bytes::<Bls12>(&f.prover_id);
        // create an instance of our circut (with the witness)
        let c = DrgPoRepExample {
            params: engine_params,
            lambda: lambda * 8,
            replica_node: Some(&f.replica_node),
            replica_node_path: &f.replica_node_path,
            replica_root: Some(f.replica_root),
            replica_parents: f
                .replica_parents
                .iter()
                .map(|parent| Some(parent))
                .collect(),
            replica_parents_paths: &f.replica_parents_paths,
            data_node: Some(&f.data_node),
            data_node_path: f.data_node_path.clone(),
            data_root: Some(f.data_root),
            prover_id: Some(prover_bytes.as_slice()),
            m,
        };

        let mut cs = BenchCS::<Bls12>::new();
        c.synthesize(&mut cs).expect("failed to synthesize circuit");
        cs
    }
}

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
        tree_depth: usize,
        _challenge_count: usize,
        _leaves: usize,
        lambda: usize,
        m: usize,
    ) -> Proof<Bls12> {
        let f = fake_drgpoprep_proof(rng, tree_depth, m, SLOTH_ROUNDS);

        let prover_bytes = fr_into_bytes::<Bls12>(&f.prover_id);

        // create an instance of our circut (with the witness)
        let c = DrgPoRepExample {
            params: engine_params,
            lambda: lambda * 8,
            replica_node: Some(&f.replica_node),
            replica_node_path: &f.replica_node_path,
            replica_root: Some(f.replica_root),
            replica_parents: f
                .replica_parents
                .iter()
                .map(|parent| Some(parent))
                .collect(),
            replica_parents_paths: &f.replica_parents_paths,
            data_node: Some(&f.data_node),
            data_node_path: f.data_node_path.clone(),
            data_root: Some(f.data_root),
            prover_id: Some(prover_bytes.as_slice()),
            m,
        };

        create_random_proof(c, groth_params, rng).expect("failed to create proof")
    }

    fn verify_proof(
        &mut self,
        _proof: &Proof<Bls12>,
        _pvk: &PreparedVerifyingKey<Bls12>,
    ) -> Option<bool> {
        // not implemented yet
        None
    }

    fn create_bench<R: Rng>(
        &mut self,
        rng: &mut R,
        engine_params: &JubjubBls12,
        tree_depth: usize,
        challenge_count: usize,
        leaves: usize,
        lambda: usize,
        m: usize,
    ) {
        self.create_bench_circuit(
            rng,
            engine_params,
            tree_depth,
            challenge_count,
            leaves,
            lambda,
            m,
        );
    }

    fn get_num_constraints<R: Rng>(
        &mut self,
        rng: &mut R,
        engine_params: &JubjubBls12,
        tree_depth: usize,
        challenge_count: usize,
        leaves: usize,
        lambda: usize,
        m: usize,
    ) -> usize {
        let cs = self.create_bench_circuit(
            rng,
            engine_params,
            tree_depth,
            challenge_count,
            leaves,
            lambda,
            m,
        );

        cs.num_constraints()
    }
}

fn main() {
    DrgPoRepApp::main()
}
