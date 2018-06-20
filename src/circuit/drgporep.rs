use bellman::{ConstraintSystem, LinearCombination, SynthesisError};
use pairing::Field;
use sapling_crypto::circuit::boolean::Boolean;
use sapling_crypto::circuit::multipack;
use sapling_crypto::jubjub::JubjubEngine;

use circuit::kdf::kdf;
use circuit::por::proof_of_retrievability;
use circuit::xor::xor;
use util::bytes_into_boolean_vec;

/// DRG based Proof of Replication.
///
/// # Arguments
///
/// * `cs` - Constraint System
/// * `params` - parameters for the curve
/// * `lambda` - The size of the individual data leaves.
/// * `replica_node` - The replica node being proven.
/// * `replica_node_path` - The path of the replica node being proven.
/// * `replica_root` - The merkle root of the replica.
/// * `replica_parents` - A list of all parents in the replica, with their value.
/// * `replica_parents_paths` - A list of all parents paths in the replica.
/// * `data_node` - The data node being proven.
/// * `data_node_path` - The path of the data node being proven.
/// * `data_root` - The merkle root of the data.
/// * `prover_id` - The id of the prover
/// * `m` -
///
///
/// # Public Inputs
///
/// * [0] prover_id/0
/// * [1] prover_id/1
/// * [2] replica value/0 (might be more than a single element)
/// * [3] replica auth_path_bits
/// * [4] replica commitment (root hash)
/// * for i in 0..replica_parents.len()
///   * [ ] replica parent value/0 (might be more than a single element)
///   * [ ] replica parent auth_path_bits
///   * [ ] replica parent commitment (root hash)
/// * [r] data value/ (might be more than a single element)
/// * [r + 1] data auth_path_bits
/// * [r + 2] data commitment (root hash)
pub fn drgporep<E, CS>(
    mut cs: CS,
    params: &E::Params,
    lambda: usize,
    replica_node: Option<&[u8]>,
    replica_node_path: &[Option<(E::Fr, bool)>],
    replica_root: Option<E::Fr>,
    replica_parents: Vec<Option<&[u8]>>,
    replica_parents_paths: &[Vec<Option<(E::Fr, bool)>>],
    data_node: Option<&[u8]>,
    data_node_path: Vec<Option<(E::Fr, bool)>>,
    data_root: Option<E::Fr>,
    prover_id: Option<&[u8]>,
    m: usize,
) -> Result<(), SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    // ensure that all inputs are well formed

    assert_eq!(data_node_path.len(), replica_node_path.len());
    if let Some(prover_id) = prover_id {
        assert_eq!(prover_id.len(), 32);
    }

    // TODO: assert the parents are actually the parents of the replica_node

    // get the prover_id in bits
    let prover_id_bits =
        bytes_into_boolean_vec(cs.namespace(|| "prover_id bits"), prover_id, lambda)?;

    multipack::pack_into_inputs(cs.namespace(|| "prover_id"), &prover_id_bits)?;

    // validate the replica node merkle proof
    proof_of_retrievability(
        cs.namespace(|| "replica_node merkle proof"),
        params,
        replica_node,
        lambda,
        replica_node_path.to_owned(),
        replica_root,
    )?;

    // validate each replica_parents merkle proof
    {
        for i in 0..replica_parents.len() {
            proof_of_retrievability(
                cs.namespace(|| format!("replica parent: {}", i)),
                params,
                replica_parents[i],
                lambda,
                replica_parents_paths[i].clone(),
                replica_root,
            )?;
        }
    }
    // validate data node commitment
    proof_of_retrievability(
        cs.namespace(|| "data node commitment"),
        params,
        data_node,
        lambda,
        data_node_path,
        data_root,
    )?;

    // get the parents into bits
    let parents_bits: Vec<Vec<Boolean>> = {
        let mut cs = cs.namespace(|| "parents to bits");
        replica_parents
            .into_iter()
            .enumerate()
            .map(|(i, val)| -> Result<Vec<Boolean>, SynthesisError> {
                bytes_into_boolean_vec(cs.namespace(|| format!("parent {}", i)), val, lambda)
            })
            .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?
    };

    // generate the encryption key
    let key = kdf(
        cs.namespace(|| "kdf"),
        params,
        prover_id_bits,
        parents_bits,
        m,
    )?;

    // decrypt the data of the replica_node
    let encoded_bits = bytes_into_boolean_vec(
        cs.namespace(|| "replica node commitment bits"),
        replica_node,
        lambda,
    )?;

    let decoded_bits = {
        let mut cs = cs.namespace(|| "decode replica node commitment");
        xor(&mut cs, key.as_slice(), encoded_bits.as_slice())?
    };

    let expected_bits =
        bytes_into_boolean_vec(cs.namespace(|| "data node bits"), data_node, lambda)?;

    // build the linar combination for decoded
    let decoded_lc = {
        let mut lc = LinearCombination::zero();
        let mut coeff = E::Fr::one();

        for bit in decoded_bits {
            lc = lc + &bit.lc(CS::one(), coeff);
            coeff.double();
        }

        lc
    };

    // build the linar combination for expected
    let expected_lc = {
        let mut lc = LinearCombination::zero();
        let mut coeff = E::Fr::one();

        for bit in expected_bits {
            lc = lc + &bit.lc(CS::one(), coeff);
            coeff.double();
        }

        lc
    };

    // ensure the encrypted data and data_node match
    {
        // expected * 1 = decoded
        cs.enforce(
            || "encrypted matches data_node constraint",
            |_| expected_lc,
            |lc| lc + CS::one(),
            |_| decoded_lc,
        );
    }

    // profit!
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::*;
    use drgporep;
    use pairing::bls12_381::*;
    use pairing::Field;
    use porep::PoRep;
    use proof::ProofScheme;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;
    use util::{bytes_into_bits, data_at_node};

    #[test]
    fn drgporep_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let n = 12;
        let m = 6;
        let challenge = 2;

        let prover_id: Vec<u8> = (0..lambda).map(|_| rng.gen()).collect();
        let mut data: Vec<u8> = (0..lambda * n).map(|_| rng.gen()).collect();

        // TODO: don't clone evertything
        let original_data = data.clone();
        let data_node = Some(
            data_at_node(&original_data, challenge + 1, lambda)
                .expect("failed to read original data"),
        );

        let sp = drgporep::SetupParams {
            lambda,
            drg: drgporep::DrgParams { n, m },
        };

        let pp = drgporep::DrgPoRep::setup(&sp).expect("failed to create drgporep setup");

        let (tau, aux) =
            drgporep::DrgPoRep::replicate(&pp, prover_id.as_slice(), data.as_mut_slice())
                .expect("failed to replicate");

        let pub_inputs = drgporep::PublicInputs {
            prover_id: prover_id.as_slice(),
            challenge,
            tau: &tau,
        };
        let priv_inputs = drgporep::PrivateInputs {
            replica: data.as_slice(),
            aux: &aux,
        };

        let proof_nc =
            drgporep::DrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).expect("failed to prove");

        assert!(
            drgporep::DrgPoRep::verify(&pp, &pub_inputs, &proof_nc).expect("failed to verify"),
            "failed to verify (non circuit)"
        );

        let replica_node = Some(proof_nc.replica_node.data);

        let replica_node_path = proof_nc.replica_node.proof.as_options();
        let replica_root = Some(proof_nc.replica_node.proof.root().into());
        let replica_parents = proof_nc
            .replica_parents
            .clone()
            .into_iter()
            .map(|(_, parent)| Some(parent.data))
            .collect();
        let replica_parents_paths: Vec<_> = proof_nc
            .replica_parents
            .iter()
            .map(|(_, parent)| parent.proof.as_options())
            .collect();

        let data_node_path = proof_nc.node.as_options();
        let data_root = Some(proof_nc.node.root().into());
        let prover_id = Some(prover_id.as_slice());

        assert!(proof_nc.node.validate(), "failed to verify data commitment");
        assert!(
            proof_nc.node.validate_data(&data_node.unwrap()),
            "failed to verify data commitment with data"
        );

        let mut cs = TestConstraintSystem::<Bls12>::new();
        drgporep(
            cs.namespace(|| "drgporep"),
            params,
            lambda,
            replica_node,
            &replica_node_path,
            replica_root,
            replica_parents,
            &replica_parents_paths,
            data_node,
            data_node_path,
            data_root,
            prover_id,
            m,
        ).expect("failed to synthesize circuit");

        if !cs.is_satisfied() {
            println!(
                "failed to satisfy: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_inputs(), 35, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 59165, "wrong number of constraints");

        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        let prover_id_bits = bytes_into_bits(&prover_id.unwrap());
        let prover_id_packed = multipack::compute_multipacking::<Bls12>(&prover_id_bits);

        assert_eq!(prover_id_packed.len(), 2);
        assert_eq!(
            cs.get_input(1, "drgporep/prover_id/input 0"),
            prover_id_packed[0]
        );
        assert_eq!(
            cs.get_input(2, "drgporep/prover_id/input 1"),
            prover_id_packed[1]
        );
    }
}

// TODO: move somewhere else. `benches` or `examples` probably
#[cfg(test_expensive)]
mod tests {
    use super::*;
    use bellman::groth16::*;
    use drgporep;
    use pairing::bls12_381::{Bls12, Fr};
    use porep::PoRep;
    use proof::ProofScheme;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;
    use std::time::{Duration, Instant};

    // TODO: figure out the real value
    // TREE_DEPTH = log_2(1GB / 32B) where 1GB = sector size
    // const TREE_DEPTH = 25;
    const TREE_DEPTH: usize = 2;

    #[test]
    fn test_drgporep() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        println!("Creating jubjub parameters...");
        let jubjub_params = &JubjubBls12::new();

        println!("Creating sample parameters...");

        // Create parameters for our circuit

        // parents path is a vector of length TREE_DEPTH,
        // with the first element having a length of TREE_DEPTH - 1
        // and the last 1
        let parents_paths: Vec<Vec<Option<_>>> =
            (0..TREE_DEPTH).map(|i| vec![None; i + 1]).collect();

        let params = {
            let c = DrgPoRep::<Bls12> {
                params: jubjub_params,
                replica_node: None,
                replica_node_path: vec![None; TREE_DEPTH],
                replica_root: None,
                replica_parents: vec![None; TREE_DEPTH],
                replica_parents_paths: parents_paths,
                data_node: None,
                data_node_path: vec![None; TREE_DEPTH],
                data_root: None,
                prover_id: None,
            };

            generate_random_parameters(c, rng).unwrap()
        };

        println!("Preparinv verifying key... ");

        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&params.vk);

        println!("Creating proofs...");

        // Let's benchmark stuff!
        const SAMPLES: u32 = 20;
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        // Just a place to put the proof data, so we can
        // benchmark deserialization.
        // let mut proof_vec = vec![];

        let lambda = 32;
        let m = 100;
        let n = 2;

        let sp = drgporep::SetupParams {
            lambda: lambda,
            drg: drgporep::DrgParams { n: n, m: m },
        };

        for i in 0..SAMPLES {
            println!("sample: {}", i);

            let prover_id: Vec<u8> = vec![rng.gen(); lambda];
            let mut data: Vec<u8> = vec![rng.gen(); lambda * n];
            let challenge: usize = rng.gen();

            // let pp = drgporep::DrgPoRep::setup(&sp).unwrap();
            // let (tau, aux) =
            //     drgporep::DrgPoRep::replicate(&pp, prover_id.as_slice(), data.as_mut_slice());

            // let pub_inputs = drgporep::PublicInputs {
            //     prover_id: prover_id.as_slice(),
            //     challenge: challenge,
            //     tau: &tau,
            // };
            // let priv_inputs = drgporep::PrivateInputs {
            //     replica: data.as_slice(),
            //     aux: &aux,
            // };

            // let proof_nc = drgporep::DrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).unwrap();

            // proof_vec.truncate(0);

            // let start = Instant::now();

            // {
            //     // Create an instance of our circuit (with the
            //     // witness)
            //     let c = DrgPoRep::<Bls12> {
            //         params: jubjub_params,
            //         replica_node: Some(proof_nc.replica_node.data.into()),
            //         replica_node_path: proof_nc.replica_node.proof.into(),
            //         replica_root: None,
            //         replica_parents: vec![None; TREE_DEPTH],
            //         replica_parents_paths: parents_paths,
            //         data_node: None,
            //         data_node_path: vec![None; TREE_DEPTH],
            //         data_root: None,
            //         prover_id: None,
            //     };

            //     // Create a groth16 proof with our parameters.
            //     let proof = create_random_proof(c, &params, rng).unwrap();

            //     proof.write(&mut proof_vec).unwrap();
            // }

            // total_proving += start.elapsed();

            // let start = Instant::now();
            // let proof = Proof::read(&proof_vec[..]).unwrap();

            // // Check the proof
            // assert!(verify_proof(&pvk, &proof, &[image]).unwrap());
            // total_verifying += start.elapsed();
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
