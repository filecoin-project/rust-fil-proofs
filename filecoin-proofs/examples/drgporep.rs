extern crate bellman;
extern crate pairing;
extern crate pbr;
extern crate rand;
extern crate sapling_crypto;

extern crate storage_proofs;

use bellman::groth16::*;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::Bls12;
use rand::Rng;
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

use storage_proofs::circuit;
use storage_proofs::circuit::variables::Root;
use storage_proofs::example_helper::Example;
use storage_proofs::hasher::PedersenHasher;
use storage_proofs::test_helper::fake_drgpoprep_proof;

struct DrgPoRepExample<'a, E: JubjubEngine> {
    params: &'a E::Params,
    sloth_iter: usize,
    replica_nodes: Vec<Option<E::Fr>>,
    replica_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    replica_root: Root<E>,
    replica_parents: Vec<Vec<Option<E::Fr>>>,
    replica_parents_paths: Vec<Vec<Vec<Option<(E::Fr, bool)>>>>,
    data_nodes: Vec<Option<E::Fr>>,
    data_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    data_root: Root<E>,
    replica_id: Option<E::Fr>,
    m: usize,
}

impl<'a> Circuit<Bls12> for DrgPoRepExample<'a, Bls12> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        circuit::drgporep::DrgPoRepCircuit::<_, PedersenHasher>::synthesize(
            cs.namespace(|| "drgporep"),
            self.params,
            self.sloth_iter,
            self.replica_nodes,
            self.replica_nodes_paths,
            self.replica_root,
            self.replica_parents,
            self.replica_parents_paths,
            self.data_nodes,
            self.data_nodes_paths,
            self.data_root,
            self.replica_id,
            self.m,
            false,
        )
    }
}

#[derive(Default)]
struct DrgPoRepApp {}

const SLOTH_ROUNDS: usize = 1;

impl<'a> Example<'a, DrgPoRepExample<'a, Bls12>> for DrgPoRepApp {
    fn name() -> String {
        "DrgPoRep".to_string()
    }

    fn generate_groth_params<R: Rng>(
        &mut self,
        rng: &mut R,
        jubjub_params: &'a JubjubBls12,
        tree_depth: usize,
        challenge_count: usize,
        m: usize,
        sloth_iter: usize,
    ) -> Parameters<Bls12> {
        generate_random_parameters::<Bls12, _, _>(
            DrgPoRepExample {
                params: jubjub_params,
                sloth_iter,
                replica_nodes: vec![None; challenge_count],
                replica_nodes_paths: vec![vec![None; tree_depth]; challenge_count],
                replica_root: Root::Val(None),
                replica_parents: vec![vec![None; m]; challenge_count],
                replica_parents_paths: vec![vec![vec![None; tree_depth]; m]; challenge_count],
                data_nodes: vec![None; challenge_count],
                data_nodes_paths: vec![vec![None; tree_depth]; challenge_count],
                data_root: Root::Val(None),
                replica_id: None,
                m,
            },
            rng,
        )
        .unwrap()
    }

    fn samples() -> usize {
        5
    }

    fn create_circuit<R: Rng>(
        &mut self,
        rng: &mut R,
        engine_params: &'a JubjubBls12,
        tree_depth: usize,
        challenge_count: usize,
        _leaves: usize,
        m: usize,
        sloth_iter: usize,
    ) -> DrgPoRepExample<'a, Bls12> {
        let f = fake_drgpoprep_proof(rng, tree_depth, m, SLOTH_ROUNDS, challenge_count);

        // create an instance of our circut (with the witness)
        DrgPoRepExample {
            params: engine_params,
            sloth_iter,
            replica_nodes: f.replica_nodes.into_iter().map(|r| Some(r)).collect(),
            replica_nodes_paths: f.replica_nodes_paths,
            replica_root: Root::Val(Some(f.replica_root)),
            replica_parents: f
                .replica_parents
                .iter()
                .map(|parents| parents.iter().map(|parent| Some(*parent)).collect())
                .collect(),
            replica_parents_paths: f.replica_parents_paths,
            data_nodes: f.data_nodes.into_iter().map(|d| Some(d)).collect(),
            data_nodes_paths: f.data_nodes_paths,
            data_root: Root::Val(Some(f.data_root)),
            replica_id: Some(f.replica_id),
            m,
        }
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
