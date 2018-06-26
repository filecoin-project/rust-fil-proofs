use bellman::{ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::boolean::{self, Boolean};
use sapling_crypto::circuit::{multipack, num};
use sapling_crypto::jubjub::JubjubEngine;

use circuit::kdf::kdf;
use circuit::por::proof_of_retrievability;
use circuit::sloth;
use util::bytes_into_boolean_vec;

/// DRG based Proof of Replication.
///
/// # Arguments
///
/// * `cs` - Constraint System
/// * `params` - parameters for the curve
/// * `lambda` - The size of the individual data leaves in bits.
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
    replica_node: Option<&E::Fr>,
    replica_node_path: &[Option<(E::Fr, bool)>],
    replica_root: Option<E::Fr>,
    replica_parents: Vec<Option<&E::Fr>>,
    replica_parents_paths: &[Vec<Option<(E::Fr, bool)>>],
    data_node: Option<&E::Fr>,
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
        &params,
        replica_node,
        replica_node_path.to_owned(),
        replica_root,
    )?;

    // validate each replica_parents merkle proof
    {
        for i in 0..replica_parents.len() {
            proof_of_retrievability(
                cs.namespace(|| format!("replica parent: {}", i)),
                &params,
                replica_parents[i],
                replica_parents_paths[i].clone(),
                replica_root,
            )?;
        }
    }
    // validate data node commitment
    proof_of_retrievability(
        cs.namespace(|| "data node commitment"),
        &params,
        data_node,
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
                let mut v = boolean::field_into_boolean_vec_le(
                    cs.namespace(|| format!("parent {}", i)),
                    val.cloned(),
                )?;
                // sad padding is sad
                while v.len() < 256 {
                    v.push(boolean::Boolean::Constant(false));
                }

                Ok(v)
            })
            .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?
    };

    // generate the encryption key
    let key = kdf(
        cs.namespace(|| "kdf"),
        &params,
        prover_id_bits,
        parents_bits,
        m,
    )?;

    let decoded = sloth::decode(
        cs.namespace(|| "decode replica node commitment"),
        &key,
        replica_node,
        sloth::DEFAULT_ROUNDS,
    )?;

    let expected = num::AllocatedNum::alloc(cs.namespace(|| "data node"), || {
        Ok(*data_node.ok_or_else(|| SynthesisError::AssignmentMissing)?)
    })?;

    // ensure the encrypted data and data_node match
    {
        // expected * 1 = decoded
        cs.enforce(
            || "encrypted matches data_node constraint",
            |lc| lc + expected.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + decoded.get_variable(),
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
    use fr32::{bytes_into_fr, fr_into_bytes};
    use pairing::bls12_381::*;
    use pairing::Field;
    use porep::PoRep;
    use proof::ProofScheme;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;
    use util::data_at_node;

    #[test]
    fn drgporep_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let n = 12;
        let m = 6;
        let challenge = 2;

        let prover_id: Vec<u8> = fr_into_bytes::<Bls12>(&rng.gen());
        let mut data: Vec<u8> = (0..n)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        // TODO: don't clone evertything
        let original_data = data.clone();
        let dn = bytes_into_fr::<Bls12>(
            data_at_node(&original_data, challenge + 1, lambda)
                .expect("failed to read original data"),
        ).unwrap();

        let data_node = Some(&dn);

        let sp = drgporep::SetupParams {
            lambda,
            drg: drgporep::DrgParams { n, m },
        };

        let pp = drgporep::DrgPoRep::setup(&sp).expect("failed to create drgporep setup");
        let (tau, aux) =
            drgporep::DrgPoRep::replicate(&pp, prover_id.as_slice(), data.as_mut_slice())
                .expect("failed to replicate");

        let prover_id_fr = bytes_into_fr::<Bls12>(prover_id.as_slice()).unwrap();
        let pub_inputs = drgporep::PublicInputs {
            prover_id: &prover_id_fr,
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

        let replica_node = Some(&proof_nc.replica_node.data);

        let replica_node_path = proof_nc.replica_node.proof.as_options();
        let replica_root = Some(proof_nc.replica_node.proof.root().into());
        let replica_parents = proof_nc
            .replica_parents
            .iter()
            .map(|(_, parent)| Some(&parent.data))
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
        assert_eq!(cs.num_inputs(), 27, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 58126, "wrong number of constraints");

        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        assert_eq!(cs.get_input(1, "drgporep/prover_id/input 0"), prover_id_fr,);
    }
}
