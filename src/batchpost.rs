use byteorder::{LittleEndian, WriteBytesExt};
use crypto::blake2s::blake2s;
use drgraph::{MerkleTree, TreeHash};
use error::Result;
use fr32::bytes_into_fr;
use merklepor;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use pairing::bls12_381::Bls12;
use proof::ProofScheme;
use util::data_at_node;

#[derive(Debug)]
pub struct PublicParams {
    /// The public params passed for the individual merklepors.
    pub params: merklepor::PublicParams,
    /// How many pors `prove` runs.
    pub batch_count: usize,
}

#[derive(Debug)]
pub struct SetupParams {}

#[derive(Debug)]
pub struct Proof {
    pub proofs: Vec<merklepor::Proof>,
    pub challenges: Vec<usize>,
}

#[derive(Debug)]
pub struct PublicInputs<'a> {
    /// The root hash of the underlying merkle tree.
    pub commitment: TreeHash,
    /// The inital challenge, which leaf to prove.
    pub challenge: usize,
    /// The prover id.
    pub prover_id: &'a [u8],
}

/// The inputs that are only available to the prover.
#[derive(Debug)]
pub struct PrivateInputs<'a> {
    /// The underlying data.
    pub data: &'a [u8],
    /// The underlying merkle tree.
    pub tree: &'a MerkleTree,
}

#[derive(Default, Debug)]
pub struct BatchPoST {}

impl<'a> ProofScheme<'a> for BatchPoST {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof;

    fn setup(_sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        // merklepor does not have a setup currently
        unimplemented!("not used")
    }

    fn prove(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        // initalize challenge
        let mut challenge = pub_inputs.challenge;
        let count = pub_params.batch_count;

        let mut proofs = Vec::with_capacity(count);
        let mut challenges = Vec::with_capacity(count);

        // push the first challenge
        challenges.push(challenge);

        for i in 0..count {
            // execute a single merklepor
            let proof = merklepor::MerklePoR::prove(
                &pub_params.params,
                &merklepor::PublicInputs {
                    commitment: pub_inputs.commitment,
                    challenge,
                },
                &merklepor::PrivateInputs {
                    leaf: bytes_into_fr::<Bls12>(data_at_node(
                        priv_inputs.data,
                        challenge + 1,
                        pub_params.params.lambda,
                    )?)?,
                    tree: priv_inputs.tree,
                },
            )?;

            challenge = derive_challenge(
                pub_inputs.prover_id,
                i,
                challenge,
                &proof,
                pub_params.params.leaves,
            )?;

            challenges.push(challenge);
            proofs.push(proof);
        }

        Ok(Proof { proofs, challenges })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let count = pub_params.batch_count;

        // ensure lengths match
        if proof.proofs.len() + 1 != proof.challenges.len() {
            println!(
                "invalid lengths {} != {}",
                proof.proofs.len() + 1,
                proof.challenges.len()
            );
            return Ok(false);
        }

        for i in 0..count {
            // verify the proof
            if !merklepor::MerklePoR::verify(
                &pub_params.params,
                &merklepor::PublicInputs {
                    challenge: proof.challenges[i],
                    commitment: pub_inputs.commitment,
                },
                &proof.proofs[i],
            )? {
                println!("proof does not verify");
                return Ok(false);
            }
            // verify the challenges are correct
            let challenge = derive_challenge(
                pub_inputs.prover_id,
                i,
                proof.challenges[i],
                &proof.proofs[i],
                pub_params.params.leaves,
            )?;

            if challenge != proof.challenges[i + 1] {
                println!("challenges dont match");
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(target_pointer_width = "64")]
fn write_usize(target: &mut Vec<u8>, value: usize) -> ::std::result::Result<(), ::std::io::Error> {
    target.write_u64::<LittleEndian>(value as u64)
}

#[cfg(target_pointer_width = "32")]
fn write_usize(target: &mut Vec<u8>, value: usize) -> ::std::result::Result<(), ::std::io::ERror> {
    target.write_u32::<LittleEndian>(value as u32)
}

/// Derives a new challenge, given the inputs, by concatenating the `prover_id`, the round `i`, the current `challenge` and the serialized `proof` and hashing them.
fn derive_challenge(
    prover_id: &[u8],
    i: usize,
    challenge: usize,
    proof: &merklepor::Proof,
    leaves: usize,
) -> Result<usize> {
    let mut bytes = prover_id.to_vec();

    write_usize(&mut bytes, i)?;
    write_usize(&mut bytes, challenge)?;
    bytes.extend(proof.serialize());

    let hash = blake2s(bytes.as_slice());

    // challenge is created by interpreting the hash as a biguint in little endian
    // and then running mod leaves on it.

    let big_challenge = BigUint::from_bytes_le(hash.as_slice());
    let big_mod_challenge = big_challenge % leaves;

    Ok(big_mod_challenge
        .to_usize()
        .expect("must fit into usize after mod operation"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use drgraph::{Graph, Sampling};
    use fr32::fr_into_bytes;
    use merklepor;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_batchpost() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let prover_id = fr_into_bytes::<Bls12>(&rng.gen());
        let pub_params = PublicParams {
            params: merklepor::PublicParams {
                lambda: 32,
                leaves: 32,
            },
            batch_count: 10,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let graph = Graph::new(32, Some(Sampling::Bucket(16)));
        let tree = graph.merkle_tree(data.as_slice(), 32).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: tree.root(),
            prover_id: prover_id.as_slice(),
        };

        let priv_inputs = PrivateInputs {
            tree: &tree,
            data: data.as_slice(),
        };

        let proof = BatchPoST::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        assert!(
            BatchPoST::verify(&pub_params, &pub_inputs, &proof).unwrap(),
            "failed to verify"
        );

        // mess with a single part of the proof
        {
            let mut proof = proof;
            proof.challenges[0] = proof.challenges[0] + 1;
            assert!(
                !BatchPoST::verify(&pub_params, &pub_inputs, &proof).unwrap(),
                "verified invalid proof"
            );
        }
    }
}
