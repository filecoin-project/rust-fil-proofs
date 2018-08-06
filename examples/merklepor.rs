extern crate bellman;
extern crate pairing;
extern crate pbr;
extern crate proofs;
extern crate rand;
extern crate sapling_crypto;

use bellman::groth16::*;
use bellman::Circuit;
use pairing::bls12_381::{Bls12, Fr};
use pairing::Field;
use rand::Rng;
use sapling_crypto::circuit::multipack;
use sapling_crypto::jubjub::JubjubBls12;

use proofs::circuit;
use proofs::circuit::bench::BenchCS;
use proofs::example_helper::Example;
use proofs::test_helper::random_merkle_path;

struct MerklePorApp {
    auth_paths: Vec<Vec<Option<(Fr, bool)>>>,
    root: Fr,
    leaf: Fr,
}

impl Default for MerklePorApp {
    fn default() -> Self {
        MerklePorApp {
            auth_paths: Vec::default(),
            leaf: Fr::zero(),
            root: Fr::zero(),
        }
    }
}

impl MerklePorApp {
    fn create_bench_circuit<R: Rng>(
        &mut self,
        rng: &mut R,
        engine_params: &JubjubBls12,
        tree_depth: usize,
        challenge_count: usize,
        _leaves: usize,
        _lambda: usize,
        _m: usize,
    ) -> BenchCS<Bls12> {
        let (auth_path, leaf, root) = random_merkle_path(rng, tree_depth);
        self.root = root;
        self.leaf = leaf;
        self.auth_paths = (0..challenge_count).map(|_| auth_path.clone()).collect();
        let values = (0..challenge_count).map(|_| Some(self.leaf)).collect();

        // create an instance of our circut (with the witness)
        let c = circuit::ppor::ParallelProofOfRetrievability {
            params: engine_params,
            values,
            auth_paths: self.auth_paths.clone(),
            root: Some(self.root),
        };

        let mut cs = BenchCS::<Bls12>::new();
        c.synthesize(&mut cs).expect("failed to synthesize circuit");
        cs
    }
}

impl Example<Bls12> for MerklePorApp {
    fn name() -> String {
        "Multi-Challenge MerklePor".to_string()
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
        _lambda: usize,
        _m: usize,
    ) -> Parameters<Bls12> {
        generate_random_parameters::<Bls12, _, _>(
            circuit::ppor::ParallelProofOfRetrievability {
                params: jubjub_params,
                values: vec![None; challenge_count],
                auth_paths: vec![vec![None; tree_depth]; challenge_count],
                root: None,
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
        _lambda: usize,
        _m: usize,
    ) -> Proof<Bls12> {
        let (auth_path, leaf, root) = random_merkle_path(rng, tree_depth);
        self.root = root;
        self.leaf = leaf;
        self.auth_paths = (0..challenge_count).map(|_| auth_path.clone()).collect();
        let values = (0..challenge_count).map(|_| Some(self.leaf)).collect();

        // create an instance of our circut (with the witness)
        let proof = {
            let c = circuit::ppor::ParallelProofOfRetrievability {
                params: engine_params,
                values,
                auth_paths: self.auth_paths.clone(),
                root: Some(self.root),
            };

            // create groth16 proof
            create_random_proof(c, groth_params, rng).expect("failed to create proof")
        };

        proof
    }

    fn verify_proof(
        &mut self,
        proof: &Proof<Bls12>,
        pvk: &PreparedVerifyingKey<Bls12>,
    ) -> Option<bool> {
        // -- generate public inputs

        let auth_paths = self.auth_paths.clone();
        let len = auth_paths.len();

        // regen values, avoids storing
        let values: Vec<_> = (0..len).map(|_| Some(&self.leaf)).collect();

        let mut expected_inputs: Vec<Fr> = (0..len)
            .flat_map(|j| {
                let auth_path_bits: Vec<bool> =
                    auth_paths[j].iter().map(|p| p.unwrap().1).collect();
                let packed_auth_path: Vec<Fr> =
                    multipack::compute_multipacking::<Bls12>(&auth_path_bits);

                let mut input = vec![*values[j].unwrap()];
                input.extend(packed_auth_path);
                input
            }).collect();

        // add the root as the last one
        expected_inputs.push(self.root);

        // -- verify proof with public inputs
        Some(verify_proof(pvk, proof, &expected_inputs).expect("failed to verify proof"))
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
    MerklePorApp::main()
}
