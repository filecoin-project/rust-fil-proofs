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
use proofs::test_helper::fake_drgpoprep_proof;

struct DrgPoRepExample<'a, E: JubjubEngine> {
    params: &'a E::Params,
    lambda: usize,
    sloth_iter: usize,
    replica_nodes: Vec<Option<E::Fr>>,
    replica_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    replica_root: Option<E::Fr>,
    replica_parents: Vec<Vec<Option<E::Fr>>>,
    replica_parents_paths: Vec<Vec<Vec<Option<(E::Fr, bool)>>>>,
    data_nodes: Vec<Option<E::Fr>>,
    data_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    data_root: Option<E::Fr>,
    prover_id: Option<E::Fr>,
    m: usize,
}

impl<'a, E: JubjubEngine> Circuit<E> for DrgPoRepExample<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        circuit::drgporep::synthesize_drgporep(
            cs.namespace(|| "drgporep"),
            self.params,
            self.lambda,
            self.sloth_iter,
            self.replica_nodes,
            self.replica_nodes_paths,
            self.replica_root,
            self.replica_parents,
            self.replica_parents_paths,
            self.data_nodes,
            self.data_nodes_paths,
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
        challenge_count: usize,
        _leaves: usize,
        lambda: usize,
        m: usize,
        sloth_iter: usize,
    ) -> BenchCS<Bls12> {
        let f = fake_drgpoprep_proof(rng, tree_depth, m, SLOTH_ROUNDS, challenge_count);

        // create an instance of our circut (with the witness)
        let c = DrgPoRepExample {
            params: engine_params,
            lambda: lambda * 8,
            sloth_iter,
            replica_nodes: f.replica_nodes.into_iter().map(|r| Some(r)).collect(),
            replica_nodes_paths: f.replica_nodes_paths,
            replica_root: Some(f.replica_root),
            replica_parents: f
                .replica_parents
                .iter()
                .map(|parents| parents.iter().map(|parent| Some(*parent)).collect())
                .collect(),
            replica_parents_paths: f.replica_parents_paths,
            data_nodes: f.data_nodes.into_iter().map(|d| Some(d)).collect(),
            data_nodes_paths: f.data_nodes_paths,
            data_root: Some(f.data_root),
            prover_id: Some(f.prover_id),
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
        challenge_count: usize,
        lambda: usize,
        m: usize,
        sloth_iter: usize,
    ) -> Parameters<Bls12> {
        generate_random_parameters::<Bls12, _, _>(
            DrgPoRepExample {
                params: jubjub_params,
                lambda: lambda * 8,
                sloth_iter,
                replica_nodes: vec![None; challenge_count],
                replica_nodes_paths: vec![vec![None; tree_depth]; challenge_count],
                replica_root: None,
                replica_parents: vec![vec![None; m]; challenge_count],
                replica_parents_paths: vec![vec![vec![None; tree_depth]; m]; challenge_count],
                data_nodes: vec![None; challenge_count],
                data_nodes_paths: vec![vec![None; tree_depth]; challenge_count],
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
        challenge_count: usize,
        _leaves: usize,
        lambda: usize,
        m: usize,
        sloth_iter: usize,
    ) -> Proof<Bls12> {
        let f = fake_drgpoprep_proof(rng, tree_depth, m, SLOTH_ROUNDS, challenge_count);

        // create an instance of our circut (with the witness)
        let c = DrgPoRepExample {
            params: engine_params,
            lambda: lambda * 8,
            sloth_iter,
            replica_nodes: f.replica_nodes.into_iter().map(|r| Some(r)).collect(),
            replica_nodes_paths: f.replica_nodes_paths,
            replica_root: Some(f.replica_root),
            replica_parents: f
                .replica_parents
                .iter()
                .map(|parents| parents.iter().map(|parent| Some(*parent)).collect())
                .collect(),
            replica_parents_paths: f.replica_parents_paths,
            data_nodes: f.data_nodes.into_iter().map(|d| Some(d)).collect(),
            data_nodes_paths: f.data_nodes_paths,
            data_root: Some(f.data_root),
            prover_id: Some(f.prover_id),
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
        sloth_iter: usize,
    ) {
        self.create_bench_circuit(
            rng,
            engine_params,
            tree_depth,
            challenge_count,
            leaves,
            lambda,
            m,
            sloth_iter,
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
        sloth_iter: usize,
    ) -> usize {
        let cs = self.create_bench_circuit(
            rng,
            engine_params,
            tree_depth,
            challenge_count,
            leaves,
            lambda,
            m,
            sloth_iter,
        );

        cs.num_constraints()
    }
}

fn main() {
    DrgPoRepApp::main()
}
