extern crate bellman;
#[macro_use]
extern crate clap;
extern crate indicatif;
extern crate pairing;
extern crate proofs;
extern crate rand;
extern crate sapling_crypto;

use bellman::groth16::*;
use clap::{App, Arg};
use indicatif::{ProgressBar, ProgressStyle};
use pairing::bls12_381::{Bls12, Fr};
use rand::{SeedableRng, XorShiftRng};
use sapling_crypto::circuit::multipack;
use sapling_crypto::jubjub::JubjubBls12;
use std::time::{Duration, Instant};

use proofs::circuit;
use proofs::test_helper::random_merkle_path;

fn do_the_work(data_size: usize, challenge_count: usize) {
    let jubjub_params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let leaves = data_size / 32;
    let tree_depth = (leaves as f64).log2().ceil() as usize;

    println!(
        "data_size {}bytes, tree_depth = {}, challenge_count = {}",
        data_size, tree_depth, challenge_count
    );

    println!("Creating sample parameters...");
    let start = Instant::now();

    println!("\tgroth params {:?}", start.elapsed());
    let groth_params = generate_random_parameters::<Bls12, _, _>(
        circuit::ppor::ParallelProofOfRetrievability {
            params: jubjub_params,
            values: vec![None; challenge_count],
            auth_paths: &vec![vec![None; tree_depth]; challenge_count],
            root: None,
        },
        rng,
    ).unwrap();

    // Prepare the verification key (for proof verification)
    println!("\tverifying key {:?}", start.elapsed());
    let pvk = prepare_verifying_key(&groth_params.vk);

    println!("\tgraph {:?}", start.elapsed());
    const SAMPLES: usize = 5;

    let mut proof_vec = vec![];
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    let (auth_path, leaf, root) = random_merkle_path(rng, tree_depth);

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

        let start = Instant::now();
        proof_vec.truncate(0);
        let auth_paths: Vec<_> = (0..challenge_count).map(|_| auth_path.clone()).collect();
        let values: Vec<_> = (0..challenge_count).map(|_| Some(&leaf)).collect();

        {
            // create an instance of our circut (with the witness)
            let c = circuit::ppor::ParallelProofOfRetrievability {
                params: jubjub_params,
                values: values.clone(),
                auth_paths: &auth_paths,
                root: Some(root),
            };

            // create groth16 proof
            let proof = create_random_proof(c, &groth_params, rng).expect("failed to create proof");

            proof.write(&mut proof_vec).unwrap();
        }

        total_proving += start.elapsed();

        let start = Instant::now();
        let proof = Proof::<Bls12>::read(&proof_vec[..]).unwrap();

        // -- generate public inputs

        let mut expected_inputs: Vec<Fr> = (0..challenge_count)
            .flat_map(|j| {
                let auth_path_bits: Vec<bool> =
                    auth_paths[j].iter().map(|p| p.unwrap().1).collect();
                let packed_auth_path: Vec<Fr> =
                    multipack::compute_multipacking::<Bls12>(&auth_path_bits);

                let mut input = vec![*values[j].unwrap()];
                input.extend(packed_auth_path);
                input
            })
            .collect();

        // add the root as the last one
        expected_inputs.push(root);

        // -- verify proof with public inputs
        pb.inc(1);
        assert!(
            verify_proof(&pvk, &proof, &expected_inputs).expect("failed to verify proof"),
            "failed to verify circuit proof"
        );

        total_verifying += start.elapsed();
    }

    let proving_avg = total_proving / SAMPLES as u32;
    let proving_avg =
        proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / SAMPLES as u32;
    let verifying_avg =
        verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);

    pb.finish_and_clear();
    println!(
        "Average proving time: {:?} seconds\n\
         Average verifying time: {:?} seconds",
        proving_avg, verifying_avg,
    );
}

fn main() {
    let matches = App::new("Multi Challenge MerklePoR")
        .version("1.0")
        .arg(
            Arg::with_name("size")
                .required(true)
                .long("size")
                .help("The data size in MB")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("challenges")
                .long("challenges")
                .help("How many challenges to execute, defaults to 1")
                .takes_value(true),
        )
        .get_matches();

    let data_size = value_t!(matches, "size", usize).unwrap() * 1024 * 1024;
    let challenge_count = value_t!(matches, "challenges", usize).unwrap_or_else(|_| 1);

    do_the_work(data_size, challenge_count);
}
