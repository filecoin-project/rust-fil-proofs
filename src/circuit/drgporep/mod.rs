use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError};
use bit_vec::BitVec;
use pairing::bls12_381::{Fr, FrRepr};
use pairing::{Field, PrimeField};
use sapling_crypto::circuit::boolean::{self, AllocatedBit, Boolean};
use sapling_crypto::jubjub::JubjubEngine;
use sapling_crypto::primitives::ValueCommitment;

use circuit::kdf::kdf;
use circuit::por::{expose_value_commitment, proof_of_retrievability};

pub type MerklePath<E: JubjubEngine> = Vec<Option<(E::Fr, bool)>>;

/// This is an instance of the `DrgPoRep` circuit.
pub struct DrgPoRep<'a, E: JubjubEngine> {
    /// parameters for  the curve
    pub params: &'a E::Params,

    /// The replica node being proven.
    pub replica_node_commitment: ValueCommitment<E>,

    /// The path of the replica node being proven.
    pub replica_node_path: MerklePath<E>,

    /// The merkle root of the replica.
    pub replica_root: E::Fr,

    /// A list of all parents in the replica, with their value and their merkle path.
    pub replica_parents: Vec<(ValueCommitment<E>, MerklePath<E>)>,

    /// The data node being proven.
    pub data_node_commitment: ValueCommitment<E>,

    /// The path of the data node being proven.
    pub data_node_path: MerklePath<E>,

    /// The merkle root of the data.
    pub data_root: E::Fr,

    /// The id of the prover
    pub prover_id: &'a [u8],
}

impl<'a, E: JubjubEngine> Circuit<E> for DrgPoRep<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // ensure that all inputs are well formed

        assert_eq!(self.data_node_path.len(), self.replica_node_path.len());
        assert_eq!(self.prover_id.len(), 32);

        // validate the replica node merkle proof

        {
            let mut ns = cs.namespace(|| "replica_node merkle proof");
            proof_of_retrievability(
                &mut ns,
                self.params,
                self.replica_node_commitment.clone(),
                self.replica_node_path.clone(),
                self.replica_root.clone(),
            )?;
        }

        // validate each replica_parents merkle proof
        {
            for (i, replica_parent) in self.replica_parents.iter().enumerate() {
                let mut ns = cs.namespace(|| format!("replica parent: {}", i));
                proof_of_retrievability(
                    &mut ns,
                    self.params,
                    replica_parent.0.clone(),
                    replica_parent.1.clone(),
                    self.replica_root.clone(),
                )?;
            }
        }

        // get the prover_id in bits
        let prover_id_bits: Vec<Boolean> = {
            let mut ns = cs.namespace(|| "prover_id_bits");
            BitVec::from_bytes(self.prover_id)
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    Ok(Boolean::from(AllocatedBit::alloc(
                        ns.namespace(|| format!("bit {}", i)),
                        Some(b),
                    )?))
                })
                .collect::<Result<Vec<_>, SynthesisError>>()?
        };

        // get the parents int bits
        let parents_bits: Vec<Vec<Boolean>> = {
            let mut ns = cs.namespace(|| "parents to bits");
            self.replica_parents
                .iter()
                .enumerate()
                .map(|(i, (val, _))| -> Result<Vec<Boolean>, SynthesisError> {
                    boolean::u64_into_boolean_vec_le(
                        ns.namespace(|| format!("bit [{}]", i)),
                        Some(val.value),
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
            Some(self.data_node_commitment),
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

#[cfg(test)]
mod test {
    use super::*;

    fn test_drgporep() {
        // TODO: write me
        assert!(true);
    }
}
