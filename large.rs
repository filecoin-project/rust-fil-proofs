mod mimc;

use std::path::Path;

use bellperson::groth16::{create_random_proof, prepare_verifying_key, verify_proof};
use ff::Field;
use bellperson::bls::{Bls12, Fr};
use phase21::{contains_contribution, MPCParameters, verify_contribution};
use rand::thread_rng;

use mimc::{mimc as mimc_hash, MiMCDemo, MIMC_ROUNDS};

// This test is marked as ignore because we haven't checked-in the phase1 file required for this
// test to pass when run via CI. To run this test you must have the correct phase1 params file in
// the top level directory of this crate.
#[test]
#[ignore]
fn test_large_params() {
    assert!(
        Path::new("./phase1radix2m10").exists(),
        "the phase1 file `phase1radix2m10` must be in the crate's top level directory"
    );

    let rng = &mut thread_rng();

    let constants = (0..MIMC_ROUNDS)
        .map(|_| Fr::random(rng))
        .collect::<Vec<_>>();

    let circuit = MiMCDemo::<Bls12> {
        xl: None,
        xr: None,
        constants: &constants,
    };

    let mut params = MPCParameters::new(circuit).unwrap();
    let old_params = params.copy();
    params.contribute(rng);

    let first_contrib = verify_contribution(&old_params, &params).expect("should verify");

    let old_params = params.copy();
    params.contribute(rng);

    let second_contrib = verify_contribution(&old_params, &params).expect("should verify");

    let all_contributions = params
        .verify(MiMCDemo::<Bls12> {
            xl: None,
            xr: None,
            constants: &constants,
        })
        .unwrap();

    assert!(contains_contribution(&all_contributions, &first_contrib));
    assert!(contains_contribution(&all_contributions, &second_contrib));


    // Create a Groth16 proof using the generated parameters and verfy that the proof is valid.
    let groth_params = params.get_params();

    // Generate a random preimage and compute the image.
    let xl = Fr::random(rng);
    let xr = Fr::random(rng);
    let image = mimc_hash::<Bls12>(xl, xr, &constants);

    let circuit = MiMCDemo {
        xl: Some(xl),
        xr: Some(xr),
        constants: &constants,
    };
    let proof = create_random_proof(circuit, groth_params, rng).unwrap();

    let pvk = prepare_verifying_key(&groth_params.vk);
    assert!(verify_proof(&pvk, &proof, &[image]).unwrap());
}
