mod mimc;

use std::fs::{remove_file, File};
use std::io::{BufReader, BufWriter};
use std::path::Path;

use bellperson::groth16::{create_random_proof, prepare_verifying_key, verify_proof};
use ff::Field;
use bellperson::bls::{Bls12, Fr};
use phase21::small::{read_small_params_from_large_file, verify_contribution_small, MPCSmall};
use phase21::{verify_contribution, MPCParameters};
use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaChaRng;

use mimc::{mimc as mimc_hash, MiMCDemo, MIMC_ROUNDS};

// This test is marked as ignore because we haven't checked-in the phase1 file required for this
// test to pass when run via CI. To run this test you must have the correct phase1 params file in
// the top level directory of this crate.
#[test]
#[ignore]
fn test_mimc_small_params() {
    assert!(
        Path::new("./phase1radix2m10").exists(),
        "the phase1 file `phase1radix2m10` must be in the crate's top level directory"
    );

    let constants = (0..MIMC_ROUNDS)
        .map(|_| Fr::random(&mut thread_rng()))
        .collect::<Vec<_>>();

    let circuit = MiMCDemo::<Bls12> {
        xl: None,
        xr: None,
        constants: &constants,
    };

    let mut rng_large = ChaChaRng::from_seed([0u8; 32]);
    let mut rng_small = ChaChaRng::from_seed([0u8; 32]);

    // Create the initial params.
    let initial_large = MPCParameters::new(circuit).unwrap();
    let initial_small = initial_large.copy_small();

    let mut large_added = initial_large.copy();

    // Make the first contributions.
    let (first_large, first_large_contrib) = {
        let mut params = initial_large.copy();
        let contrib = params.contribute(&mut rng_large);
        (params, contrib)
    };
    let (first_small, first_small_contrib) = {
        let mut params = initial_small.clone();
        let contrib = params.contribute(&mut rng_small);
        (params, contrib)
    };

    // Verify the first contributions.
    assert_eq!(
        &first_small_contrib[..],
        &first_large_contrib[..],
        "first small and large contributions are not equal"
    );

    let verified_large = verify_contribution(&initial_large, &first_large)
        .expect("first large verify_contribution() failed");
    assert_eq!(
        &first_large_contrib[..],
        &verified_large[..],
        "first large contribution does not match verified contribution"
    );

    let verified_small = verify_contribution_small(&initial_small, &first_small)
        .expect("first small verify_contribution_small() failed");
    assert_eq!(
        &first_small_contrib[..],
        &verified_small[..],
        "first small contribution does not match verified contribution"
    );

    // Verify that the first large and small params are consistent.
    assert!(first_large.has_last_contrib(&first_small));
    large_added.add_contrib(first_small.clone());
    assert_eq!(large_added, first_large);

    // Make the second contributions.
    let (second_large, second_large_contrib) = {
        let mut params = first_large.copy();
        let contrib = params.contribute(&mut rng_large);
        (params, contrib)
    };
    let (second_small, second_small_contrib) = {
        let mut params = first_small.clone();
        let contrib = params.contribute(&mut rng_small);
        (params, contrib)
    };

    // Verify the second contributions.
    assert_eq!(
        &second_small_contrib[..],
        &second_large_contrib[..],
        "second small and large contributions are not equal"
    );

    let verified_large = verify_contribution(&first_large, &second_large)
        .expect("second large verify_contribution() failed");
    assert_eq!(
        &second_large_contrib[..],
        &verified_large[..],
        "second large contribution does not match verified contribution"
    );

    let verified_small = verify_contribution_small(&first_small, &second_small)
        .expect("second small verify_contribution_small() failed");
    assert_eq!(
        &second_small_contrib[..],
        &verified_small[..],
        "second small contribution does not match verified contribution"
    );

    // Verify that the second large and small params are consistent.
    assert!(second_large.has_last_contrib(&second_small));
    large_added.add_contrib(second_small.clone());
    assert_eq!(large_added, second_large);

    // Verify large params against circuit.
    let all_contributions = large_added
        .verify(MiMCDemo::<Bls12> {
            xl: None,
            xr: None,
            constants: &constants,
        })
        .unwrap();
    assert_eq!(all_contributions.len(), 2);
    assert_eq!(&all_contributions[0][..], &first_large_contrib[..]);
    assert_eq!(&all_contributions[1][..], &second_large_contrib[..]);

    // Verify the generated params against the circuit.
    let groth_params = large_added.get_params();
    let pvk = prepare_verifying_key(&groth_params.vk);
    // Generate a random preimage and compute the image.
    let xl = Fr::random(&mut thread_rng());
    let xr = Fr::random(&mut thread_rng());
    let image = mimc_hash::<Bls12>(xl, xr, &constants);
    // Create an instance of the circuit (with the witness).
    let circuit = MiMCDemo {
        xl: Some(xl),
        xr: Some(xr),
        constants: &constants,
    };
    // Create a groth16 proof using the generated parameters.
    let proof = create_random_proof(circuit, groth_params, &mut thread_rng())
        .expect("failed to create Groth16 proof using MPC params");
    assert!(verify_proof(&pvk, &proof, &[image]).unwrap());
}

// This test is marked as ignore because we haven't checked-in the phase1 file required for this
// test to pass when run via CI. To run this test you must have the correct phase1 params file in
// the top level directory of this crate.
#[test]
#[ignore]
fn test_small_file_io() {
    const LARGE_PATH: &str = "./tests/large_params";
    const SMALL_PATH: &str = "./tests/small_params";

    struct TestCleanup;

    impl Drop for TestCleanup {
        fn drop(&mut self) {
            remove_file(LARGE_PATH).unwrap();
            remove_file(SMALL_PATH).unwrap();
        }
    }

    let _cleanup = TestCleanup;

    assert!(
        Path::new("./phase1radix2m10").exists(),
        "the phase1 file `phase1radix2m10` must be in the crate's top level directory"
    );

    let constants = (0..MIMC_ROUNDS)
        .map(|_| Fr::random(&mut thread_rng()))
        .collect::<Vec<_>>();

    let circuit = MiMCDemo::<Bls12> {
        xl: None,
        xr: None,
        constants: &constants,
    };

    let large_params = MPCParameters::new(circuit).unwrap();
    let small_params = large_params.copy_small();

    {
        let file = File::create(LARGE_PATH).unwrap();
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        large_params.write(&mut writer).unwrap();
    }
    {
        let file = File::create(SMALL_PATH).unwrap();
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        small_params.write(&mut writer).unwrap();
    }

    // Test small param deserialisation.
    {
        let file = File::open(SMALL_PATH).unwrap();
        let mut reader = BufReader::with_capacity(1024 * 1024, file);
        let small_read = MPCSmall::read(&mut reader, false, false).unwrap();
        assert_eq!(small_read, small_params);
        assert!(large_params.has_last_contrib(&small_read));
    };

    // Test `read_small_params_from_large_file()`.
    {
        let small_read = read_small_params_from_large_file(LARGE_PATH).unwrap();
        assert_eq!(small_read, small_params);
    }
}
