use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError};
use bit_vec::BitVec;
use pairing::bls12_381::{Fr, FrRepr};
use pairing::{Field, PrimeField};
use sapling_crypto::circuit::boolean::{self, AllocatedBit, Boolean};
use sapling_crypto::jubjub::JubjubEngine;
use sapling_crypto::primitives::ValueCommitment;

use circuit::kdf::kdf;
use circuit::por::{expose_value_commitment, proof_of_retrievability};

/// How many bits are in a single prover_id
const PROVER_ID_BITS: usize = 256;

pub type MerklePath<E: JubjubEngine> = Vec<Option<(E::Fr, bool)>>;

/// This is an instance of the `DrgPoRep` circuit.
pub struct DrgPoRep<'a, E: JubjubEngine> {
    /// parameters for  the curve
    pub params: &'a E::Params,

    /// The replica node being proven.
    pub replica_node_commitment: Option<ValueCommitment<E>>,

    /// The path of the replica node being proven.
    pub replica_node_path: MerklePath<E>,

    /// The merkle root of the replica.
    pub replica_root: Option<E::Fr>,

    /// A list of all parents in the replica, with their value and their merkle path.
    pub replica_parents_commitments: Vec<Option<ValueCommitment<E>>>,

    pub replica_parents_paths: Vec<MerklePath<E>>,

    /// The data node being proven.
    pub data_node_commitment: Option<ValueCommitment<E>>,

    /// The path of the data node being proven.
    pub data_node_path: MerklePath<E>,

    /// The merkle root of the data.
    pub data_root: Option<E::Fr>,

    /// The id of the prover
    pub prover_id: Option<&'a [u8]>,
}

impl<'a, E: JubjubEngine> Circuit<E> for DrgPoRep<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // ensure that all inputs are well formed

        assert_eq!(self.data_node_path.len(), self.replica_node_path.len());
        if let Some(prover_id) = self.prover_id {
            assert_eq!(prover_id.len(), PROVER_ID_BITS / 8);
        }

        // TODO: assert the parents are actually the parents of the replica_node

        // validate the replica node merkle proof

        {
            let mut ns = cs.namespace(|| "replica_node merkle proof");
            proof_of_retrievability(
                &mut ns,
                self.params,
                self.replica_node_commitment.clone(),
                self.replica_node_path.clone(),
                self.replica_root,
            )?;
        }

        // validate each replica_parents merkle proof
        {
            for i in 0..self.replica_parents_commitments.len() {
                let mut ns = cs.namespace(|| format!("replica parent: {}", i));
                proof_of_retrievability(
                    &mut ns,
                    self.params,
                    self.replica_parents_commitments[i].clone(),
                    self.replica_parents_paths[i].clone(),
                    self.replica_root,
                )?;
            }
        }

        // get the prover_id in bits
        let prover_id_bits: Vec<Boolean> = {
            let mut ns = cs.namespace(|| "prover_id_bits");

            let values = match self.prover_id {
                Some(value) => BitVec::from_bytes(value)
                    .iter()
                    .map(Some)
                    .collect::<Vec<_>>(),
                None => vec![None; PROVER_ID_BITS],
            };

            values
                .into_iter()
                .enumerate()
                .map(|(i, b)| {
                    Ok(Boolean::from(AllocatedBit::alloc(
                        ns.namespace(|| format!("bit {}", i)),
                        b,
                    )?))
                })
                .collect::<Result<Vec<_>, SynthesisError>>()?
        };

        // get the parents int bits
        let parents_bits: Vec<Vec<Boolean>> = {
            let mut ns = cs.namespace(|| "parents to bits");
            self.replica_parents_commitments
                .into_iter()
                .enumerate()
                .map(|(i, val)| -> Result<Vec<Boolean>, SynthesisError> {
                    boolean::u64_into_boolean_vec_le(
                        ns.namespace(|| format!("bit [{}]", i)),
                        val.map(|v| v.value),
                    )
                })
                .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?
        };

        // generate the encryption key
        let key = {
            let mut ns = cs.namespace(|| "kdf");
            kdf(
                &mut ns,
                prover_id_bits,
                parents_bits,
                // TODO: what about the persona??
                b"12345678",
            )?
        };

        // decrypt the data of the replica_node
        // TODO: what encryption?
        let decoded_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "decoded data"),
            // TODO: actual value
            Some(0u64),
        )?;
        let expected_bits = expose_value_commitment(
            cs.namespace(|| "data node commitment"),
            self.data_node_commitment,
            self.params,
        )?;

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

        // TODO: what values need `inputize` called on?

        // profit!
        Ok(())
    }
}

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
                replica_node_commitment: None,
                replica_node_path: vec![None; TREE_DEPTH],
                replica_root: None,
                replica_parents_commitments: vec![None; TREE_DEPTH],
                replica_parents_paths: parents_paths,
                data_node_commitment: None,
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
            //         replica_node_commitment: Some(proof_nc.replica_node.data.into()),
            //         replica_node_path: proof_nc.replica_node.proof.into(),
            //         replica_root: None,
            //         replica_parents_commitments: vec![None; TREE_DEPTH],
            //         replica_parents_paths: parents_paths,
            //         data_node_commitment: None,
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
