extern crate bellman;
extern crate indicatif;
extern crate pairing;
extern crate proofs;
extern crate rand;
extern crate sapling_crypto;

use bellman::groth16::*;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use indicatif::{ProgressBar, ProgressStyle};
use pairing::bls12_381::{Bls12, Fr};
use proofs::example_helper::Example;
use rand::{Rng, SeedableRng, XorShiftRng};
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};
use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};

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

struct DrgPoRepApp {}

impl Example for DrgPoRepApp {
    fn do_the_work(data_size: usize, m: usize) {
        let jubjub_params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        println!(
            "data_size {}bytes, m = {}, tree_depth = {}",
            data_size, m, tree_depth
        );

        println!("Creating sample parameters...");

        let start = Instant::now();

        let path = format!("/tmp/filecoin-proofs-cache-{}-{}", data_size, m);
        let cache_path = Path::new(&path);

        println!("\tgroth params {:?}", start.elapsed());

        let groth_params: Parameters<_> = if cache_path.exists() {
            println!("\treading params from cache...");

            let mut f = File::open(&cache_path).unwrap();
            Parameters::read(&f, false).unwrap()
        } else {
            let p = generate_random_parameters::<Bls12, _, _>(
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
            ).unwrap();

            println!("\twriting params to cache...");
            let mut f = File::create(&cache_path).unwrap();
            p.write(&mut f).unwrap();

            p
        };

        // Prepare the verification key (for proof verification)
        // println!("\tverifying key {:?}", start.elapsed());
        // let pvk = prepare_verifying_key(&groth_params.vk);

        println!("\tgraph {:?}", start.elapsed());
        const SAMPLES: u32 = 5;

        let mut proof_vec = vec![];
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        let pb = ProgressBar::new((SAMPLES * 2) as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )
                .progress_chars("#>-"),
        );

        for _ in 0..SAMPLES {
            pb.inc(1);

            proof_vec.truncate(0);

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

            let mut proof_nc =
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
                data_at_node(&original_data, challenge, lambda)
                    .expect("failed to read original data"),
            ).unwrap();

            let data_node_path = proof_nc.node.as_options();
            let data_root = Some(proof_nc.node.root().into());
            let prover_id = Some(prover_id_bytes.as_slice());

            assert!(proof_nc.node.validate(), "failed to verify data commitment");
            assert!(
                proof_nc.node.validate_data(&data_node),
                "failed to verify data commitment with data"
            );

            let start = Instant::now();
            {
                // create an instance of our circut (with the witness)
                let c = DrgPoRepExample {
                    params: jubjub_params,
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
                let proof = create_random_proof(c, &groth_params, rng).unwrap();

                proof.write(&mut proof_vec).unwrap();
            }
            total_proving += start.elapsed();

            let start = Instant::now();
            let proof = Proof::<Bls12>::read(&proof_vec[..]).unwrap();
            proof.write(&mut proof_vec).unwrap();

            pb.inc(1);
            // TODO: generate expected inputs and verify proofs
            // assert!(verify_proof(&pvk, &proof, expected_inputs).unwrap());
            total_verifying += start.elapsed();
        }

        let proving_avg = total_proving / SAMPLES;
        let proving_avg =
            proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

        let verifying_avg = total_verifying / SAMPLES;
        let verifying_avg = verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64
            + (verifying_avg.as_secs() as f64);

        println!("Average proving time: {:?} seconds", proving_avg);
        println!("Average verifying time: {:?} seconds", verifying_avg);
    }
}

fn main() {
    DrgPoRepApp::main("Multi-Challenge MerklePor")
}
