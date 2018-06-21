extern crate bellman;
extern crate indicatif;
extern crate pairing;
extern crate proofs;
extern crate rand;
extern crate sapling_crypto;

use bellman::groth16::*;
use indicatif::{ProgressBar, ProgressStyle};
use pairing::bls12_381::Bls12;
use rand::{Rng, SeedableRng, XorShiftRng};
use sapling_crypto::circuit::multipack;
use sapling_crypto::jubjub::JubjubBls12;
use std::time::{Duration, Instant};

use proofs::proof::ProofScheme;
use proofs::util::data_at_node;
use proofs::{circuit, drgraph, fr32, merklepor};

fn main() {
    let jubjub_params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let lambda = 32;
    // TODO: need this many leaves to simulate roughly 1GB
    // (1024 * 1024 *1024) / 32 = 33 554 432;
    let leaves = (1024 * 1024) / 32;
    let m = 6;
    let tree_depth = (leaves as f64).log2().ceil() as usize;
    // TODO: go to 100
    let challenge_count = 1;

    let mut total_param = Duration::new(0, 0);

    println!(
        "leaves {}, m = {}, tree_depth = {}, challenge_count = {}",
        leaves, m, tree_depth, challenge_count
    );
    println!("Creating sample parameters...");

    let start = Instant::now();

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
    let pvk = prepare_verifying_key(&groth_params.vk);

    total_param += start.elapsed();

    const SAMPLES: usize = 5;

    let mut proof_vec = vec![];
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    let data: Vec<u8> = (0..leaves)
        .flat_map(|_| fr32::fr_into_bytes::<Bls12>(&rng.gen()))
        .collect();

    let graph = drgraph::Graph::new(leaves, Some(drgraph::Sampling::Bucket(m)));
    let tree = graph.merkle_tree(data.as_slice(), lambda).unwrap();

    // -- MerklePoR

    let pub_params = merklepor::PublicParams { lambda, leaves };

    println!("Sampling..");

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
        let pub_inputs: Vec<_> = (0..challenge_count)
            .map(|j| merklepor::PublicInputs {
                challenge: j + 1,
                commitment: tree.root(),
            })
            .collect();

        let priv_inputs: Vec<_> = (0..challenge_count)
            .map(|j| merklepor::PrivateInputs {
                tree: &tree,
                leaf: fr32::bytes_into_fr::<Bls12>(
                    data_at_node(
                        data.as_slice(),
                        pub_inputs[j].challenge + 1,
                        pub_params.lambda,
                    ).unwrap(),
                ).unwrap(),
            })
            .collect();

        // create a non circuit proof
        let proof_nonc: Vec<_> = (0..challenge_count)
            .map(|j| {
                merklepor::MerklePoR::prove(&pub_params, &pub_inputs[j], &priv_inputs[j]).unwrap()
            })
            .collect();

        // make sure it verifies
        for j in 0..challenge_count {
            assert!(
                merklepor::MerklePoR::verify(&pub_params, &pub_inputs[j], &proof_nonc[j]).unwrap(),
                "failed to verify merklepor proof"
            );
        }

        let start = Instant::now();
        proof_vec.truncate(0);

        {
            let auth_paths: Vec<_> = proof_nonc.iter().map(|p| p.proof.as_options()).collect();
            // create an instance of our circut (with the witness)
            let c = circuit::ppor::ParallelProofOfRetrievability {
                params: jubjub_params,
                values: proof_nonc.iter().map(|p| Some(&p.data)).collect(),
                auth_paths: &auth_paths,
                root: Some(pub_inputs[0].commitment.into()),
            };

            // create groth16 proof
            let proof = create_random_proof(c, &groth_params, rng).expect("failed to create proof");

            proof.write(&mut proof_vec).unwrap();
        }

        total_proving += start.elapsed();

        let start = Instant::now();
        let proof = Proof::<Bls12>::read(&proof_vec[..]).unwrap();

        // -- generate public inputs

        let expected_inputs: Vec<_> = (0..challenge_count)
            .flat_map(|j| {
                let auth_path_bits: Vec<bool> = proof_nonc[j]
                    .proof
                    .path()
                    .iter()
                    .map(|(_, is_right)| *is_right)
                    .collect();
                let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

                let mut input = vec![proof_nonc[j].data];
                input.extend(packed_auth_path);
                input.push(pub_inputs[j].commitment.into());
                input
            })
            .collect();

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
         Average verifying time: {:?} seconds\n\
         Param generation time: {:?} seconds",
        proving_avg,
        verifying_avg,
        total_param.as_secs()
    );
}
