use std::marker::PhantomData;

use byteorder::{LittleEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::crypto::blake2s::blake2s;
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::merkle::MerkleTree;
use crate::merklepor;
use crate::proof::ProofScheme;
use crate::util::data_at_node;

#[derive(Clone, Debug)]
pub struct PublicParams {
    /// The public params passed for the individual merklepors.
    pub params: merklepor::PublicParams,
    /// How many pors `prove` runs.
    pub batch_count: usize,
}

#[derive(Debug)]
pub struct SetupParams {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "merklepor::Proof<H>: Serialize",
        deserialize = "merklepor::Proof<H>: Deserialize<'de>"
    ))]
    pub proofs: Vec<merklepor::Proof<H>>,
    pub challenges: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct PublicInputs<'a, T: 'a + Domain> {
    /// The root hash of the underlying merkle tree.
    pub commitment: T,
    /// The inital challenge, which leaf to prove.
    pub challenge: usize,
    /// The prover id.
    pub replica_id: &'a T,
}

/// The inputs that are only available to the prover.
#[derive(Debug)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    /// The underlying data.
    pub data: &'a [u8],
    /// The underlying merkle tree.
    pub tree: &'a MerkleTree<H::Domain, H::Function>,
}

impl<'a, H: Hasher> PrivateInputs<'a, H> {
    pub fn new(data: &'a [u8], tree: &'a MerkleTree<H::Domain, H::Function>) -> Self {
        PrivateInputs { data, tree }
    }
}

#[derive(Default, Debug)]
pub struct BatchPoST<H: Hasher> {
    _h: PhantomData<H>,
}

impl<'a, H: 'a + Hasher> ProofScheme<'a> for BatchPoST<H> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a, H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<H>;

    fn setup(_sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        // merklepor does not have a setup currently
        unimplemented!("not used")
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
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
                    commitment: Some(pub_inputs.commitment),
                    challenge,
                },
                &merklepor::PrivateInputs::new(
                    H::Domain::try_from_bytes(data_at_node(priv_inputs.data, challenge)?)?,
                    priv_inputs.tree,
                ),
            )?;

            challenge = derive_challenge(
                pub_inputs.replica_id,
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
                    commitment: Some(pub_inputs.commitment),
                },
                &proof.proofs[i],
            )? {
                println!("proof does not verify");
                return Ok(false);
            }
            // verify the challenges are correct
            let challenge = derive_challenge(
                pub_inputs.replica_id,
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
fn write_usize(target: &mut Vec<u8>, value: usize) -> ::std::result::Result<(), ::std::io::Error> {
    target.write_u32::<LittleEndian>(value as u32)
}

/// Derives a new challenge, given the inputs, by concatenating the `replica_id`, the round `i`, the current `challenge` and the serialized `proof` and hashing them.
fn derive_challenge<H: Hasher>(
    replica_id: &H::Domain,
    i: usize,
    challenge: usize,
    proof: &merklepor::Proof<H>,
    leaves: usize,
) -> Result<usize> {
    let mut bytes = replica_id.into_bytes();

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

    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};
    use crate::merklepor;

    fn test_batchpost<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let replica_id: H::Domain = rng.gen();
        let pub_params = PublicParams {
            params: merklepor::PublicParams {
                leaves: 32,
                private: false,
            },
            batch_count: 10,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let graph = BucketGraph::<H>::new(32, 16, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();

        let pub_inputs = PublicInputs::<H::Domain> {
            challenge: 3,
            commitment: tree.root(),
            replica_id: &replica_id,
        };

        let priv_inputs = PrivateInputs::<H>::new(data.as_slice(), &tree);

        let proof = BatchPoST::<H>::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        assert!(
            BatchPoST::<H>::verify(&pub_params, &pub_inputs, &proof).unwrap(),
            "failed to verify"
        );

        // mess with a single part of the proof
        {
            let mut proof = proof;
            proof.challenges[0] = proof.challenges[0] + 1;
            assert!(
                !BatchPoST::<H>::verify(&pub_params, &pub_inputs, &proof).unwrap(),
                "verified invalid proof"
            );
        }
    }

    #[test]
    fn batchpost_pedersen() {
        test_batchpost::<PedersenHasher>();
    }

    #[test]
    fn batchpost_sha256() {
        test_batchpost::<Sha256Hasher>();
    }

    #[test]
    fn batchpost_blake2s() {
        test_batchpost::<Blake2sHasher>();
    }
}
