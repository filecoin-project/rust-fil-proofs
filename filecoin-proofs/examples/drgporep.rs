use std::marker::PhantomData;

use algebra::curves::bls12_381::Bls12_381 as Bls12;
use algebra::fields::bls12_381::Fr;
use rand::Rng;
use snark::groth16::*;
use snark::{Circuit, ConstraintSystem, SynthesisError};
use storage_proofs::circuit;
use storage_proofs::circuit::variables::Root;
use storage_proofs::example_helper::Example;
use storage_proofs::hasher::PedersenHasher;
use storage_proofs::test_helper::fake_drgpoprep_proof;

struct DrgPoRepExample<'a> {
    replica_nodes: Vec<Option<Fr>>,
    replica_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
    replica_root: Root<Bls12>,
    replica_parents: Vec<Vec<Option<Fr>>>,
    replica_parents_paths: Vec<Vec<Vec<Option<(Fr, bool)>>>>,
    data_nodes: Vec<Option<Fr>>,
    data_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
    data_root: Root<Bls12>,
    replica_id: Option<Fr>,
    m: usize,
    _a: PhantomData<&'a usize>,
}

impl<'a> Circuit<Bls12> for DrgPoRepExample<'a> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        circuit::drgporep::DrgPoRepCircuit::<PedersenHasher>::synthesize(
            cs.ns(|| "drgporep"),
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

impl<'a> Example<'a, DrgPoRepExample<'a>> for DrgPoRepApp {
    fn name() -> String {
        "DrgPoRep".to_string()
    }

    fn generate_groth_params<R: Rng>(
        &mut self,
        rng: &mut R,
        tree_depth: usize,
        challenge_count: usize,
        m: usize,
    ) -> Parameters<Bls12> {
        generate_random_parameters::<Bls12, _, _>(
            DrgPoRepExample {
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
                _a: Default::default(),
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
        tree_depth: usize,
        challenge_count: usize,
        _leaves: usize,
        m: usize,
    ) -> DrgPoRepExample<'a> {
        let f = fake_drgpoprep_proof(rng, tree_depth, m, challenge_count);

        // create an instance of our circut (with the witness)
        DrgPoRepExample {
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
            _a: Default::default(),
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
