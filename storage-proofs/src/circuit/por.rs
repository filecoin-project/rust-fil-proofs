use bellman::{Circuit, ConstraintSystem, SynthesisError};
use compound_proof::CompoundProof;
use drgraph::graph_height;
use merklepor::MerklePoR;
use pairing::bls12_381::{Bls12, Fr};
use parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use proof::ProofScheme;
use sapling_crypto::circuit::{boolean, multipack, num, pedersen_hash};
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

/// Proof of retrievability.
///
/// # Fields
///
/// * `params` - The params for the bls curve.
/// * `value` - The value of the leaf.
/// * `auth_path` - The authentication path of the leaf in the tree.
/// * `root` - The merkle root of the tree.
///

pub struct PoRCircuit<'a, E: JubjubEngine> {
    params: &'a E::Params,
    value: Option<E::Fr>,
    auth_path: Vec<Option<(E::Fr, bool)>>,
    root: Option<E::Fr>,
}

pub struct PoRCompound {}

pub fn challenge_into_auth_path_bits(challenge: usize, leaves: usize) -> Vec<bool> {
    let height = graph_height(leaves);
    let mut bits = Vec::new();
    let mut n = challenge;
    for _ in 0..height {
        bits.push(n & 1 == 1);
        n >>= 1;
    }
    bits
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetIdentifier> CacheableParameters<E, C, P>
    for PoRCompound
{
    fn cache_prefix() -> String {
        String::from("proof-of-retrievability")
    }
}

// can only implment for Bls12 because merklepor is not generic over the engine.
impl<'a> CompoundProof<'a, Bls12, MerklePoR, PoRCircuit<'a, Bls12>> for PoRCompound {
    fn circuit<'b>(
        public_inputs: &<MerklePoR as ProofScheme>::PublicInputs,
        proof: &'b <MerklePoR as ProofScheme>::Proof,
        _public_params: &'b <MerklePoR as ProofScheme>::PublicParams,
        engine_params: &'a JubjubBls12,
    ) -> PoRCircuit<'a, Bls12> {
        PoRCircuit::<Bls12> {
            params: engine_params,
            value: Some(proof.data),
            auth_path: proof.proof.as_options(),
            root: Some(
                public_inputs
                    .commitment
                    .expect("required root commitment is missing")
                    .into(),
            ),
        }
    }

    fn generate_public_inputs(
        pub_inputs: &<MerklePoR as ProofScheme>::PublicInputs,
        pub_params: &<MerklePoR as ProofScheme>::PublicParams,
    ) -> Vec<Fr> {
        let auth_path_bits = challenge_into_auth_path_bits(pub_inputs.challenge, pub_params.leaves);
        let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

        let mut inputs = Vec::new();
        inputs.extend(packed_auth_path);
        inputs.push(pub_inputs.commitment.unwrap().into());

        inputs
    }
}

impl<'a, E: JubjubEngine> Circuit<E> for PoRCircuit<'a, E> {
    /// # Public Inputs
    ///
    /// This circuit expects the following public inputs.
    ///
    /// * [0] - packed version of the `is_right` components of the auth_path.
    /// * [1] - the merkle root of the tree.
    ///
    /// This circuit derives the following private inputs from its fields:
    /// * value_num - packed version of `value` as bits. (might be more than one Fr)
    ///
    /// Note: All public inputs must be provided as `E::Fr`.
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
    {
        // Allocate the "real" root that will be exposed.
        let rt = num::AllocatedNum::alloc(cs.namespace(|| "root_value"), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Expose the data_root
        rt.inputize(cs.namespace(|| "root"))?;

        make_circuit(cs, self.params, self.value, self.auth_path, &rt)?;

        Ok(())
    }
}

pub fn make_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    params: &E::Params,
    value: Option<E::Fr>,
    auth_path: Vec<Option<(E::Fr, bool)>>,
    root: &num::AllocatedNum<E>,
) -> Result<(), SynthesisError> {
    let value_num = num::AllocatedNum::alloc(cs.namespace(|| "value"), || {
        Ok(value.ok_or_else(|| SynthesisError::AssignmentMissing)?)
    })?;
    let mut value_bits = value_num.into_bits_le(cs.namespace(|| "value bits"))?;

    // sad face, need to pad to make all algorithms the same
    while value_bits.len() < 256 {
        value_bits.push(boolean::Boolean::Constant(false));
    }

    // Compute the hash of the value
    let cm = pedersen_hash::pedersen_hash(
        cs.namespace(|| "value hash"),
        pedersen_hash::Personalization::NoteCommitment,
        &value_bits,
        params,
    )?;

    // This is an injective encoding, as cur is a
    // point in the prime order subgroup.
    let mut cur = cm.get_x().clone();

    let mut auth_path_bits = Vec::with_capacity(auth_path.len());

    // Ascend the merkle tree authentication path
    for (i, e) in auth_path.into_iter().enumerate() {
        let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

        // Determines if the current subtree is the "right" leaf at this
        // depth of the tree.
        let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
            cs.namespace(|| "position bit"),
            e.map(|e| e.1),
        )?);

        // Witness the authentication path element adjacent
        // at this depth.
        let path_element = num::AllocatedNum::alloc(cs.namespace(|| "path element"), || {
            Ok(e.ok_or(SynthesisError::AssignmentMissing)?.0)
        })?;

        // Swap the two if the current subtree is on the right
        let (xl, xr) = num::AllocatedNum::conditionally_reverse(
            cs.namespace(|| "conditional reversal of preimage"),
            &cur,
            &path_element,
            &cur_is_right,
        )?;

        // We don't need to be strict, because the function is
        // collision-resistant. If the prover witnesses a congruency,
        // they will be unable to find an authentication path in the
        // tree with high probability.
        let mut preimage = vec![];
        preimage.extend(xl.into_bits_le(cs.namespace(|| "xl into bits"))?);
        preimage.extend(xr.into_bits_le(cs.namespace(|| "xr into bits"))?);

        // Compute the new subtree value
        cur = pedersen_hash::pedersen_hash(
            cs.namespace(|| "computation of pedersen hash"),
            pedersen_hash::Personalization::MerkleTree(i),
            &preimage,
            params,
        )?.get_x()
        .clone(); // Injective encoding

        auth_path_bits.push(cur_is_right);
    }

    // allocate input for is_right auth_path
    multipack::pack_into_inputs(cs.namespace(|| "packed auth_path"), &auth_path_bits)?;

    {
        // cur  * 1 = rt
        // enforce cur and rt are equal
        cs.enforce(
            || "enforce root is correct",
            |lc| lc + cur.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + root.get_variable(),
        );
    }

    Ok(())
}

impl<'a, E: JubjubEngine> PoRCircuit<'a, E> {
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &E::Params,
        value: Option<E::Fr>,
        auth_path: Vec<Option<(E::Fr, bool)>>,
        root: Option<E::Fr>,
    ) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        let por = PoRCircuit::<E> {
            params,
            value,
            auth_path,
            root,
        };

        por.synthesize(&mut cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::*;
    use compound_proof;
    use drgraph::{new_seed, BucketGraph, Graph};
    use fr32::{bytes_into_fr, fr_into_bytes};
    use merklepor;
    use pairing::Field;
    use proof::ProofScheme;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::multipack;
    use sapling_crypto::jubjub::JubjubBls12;
    use util::data_at_node;

    #[test]
    fn test_compound() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let leaves = 6;
        let lambda = 32;
        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let graph = BucketGraph::new(leaves, 16, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice(), lambda).unwrap();

        for i in 0..3 {
            let public_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: Some(tree.root()),
            };

            let setup_params = compound_proof::SetupParams {
                vanilla_params: &merklepor::SetupParams { lambda, leaves },
                engine_params: &JubjubBls12::new(),
            };
            let public_params = PoRCompound::setup(&setup_params).expect("setup failed");

            let private_inputs = merklepor::PrivateInputs {
                tree: &tree,
                leaf: bytes_into_fr::<Bls12>(
                    data_at_node(
                        data.as_slice(),
                        public_inputs.challenge,
                        public_params.vanilla_params.lambda,
                    ).unwrap(),
                ).expect("failed to create Fr from node data"),
            };

            let proof = PoRCompound::prove(&public_params, &public_inputs, &private_inputs)
                .expect("failed while proving");

            let verified =
                PoRCompound::verify(&public_params.vanilla_params, &public_inputs, proof)
                    .expect("failed while verifying");
            assert!(verified);

            let (circuit, inputs) =
                PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs);

            let mut cs = TestConstraintSystem::new();

            let _ = circuit.synthesize(&mut cs);
            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));
        }
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 6;
        let lambda = 32;

        for i in 0..6 {
            // -- Basic Setup

            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect();

            let graph = BucketGraph::new(leaves, 16, 0, new_seed());
            let tree = graph.merkle_tree(data.as_slice(), lambda).unwrap();

            // -- MerklePoR

            let pub_params = merklepor::PublicParams { lambda, leaves };
            let pub_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: Some(tree.root()),
            };

            let priv_inputs = merklepor::PrivateInputs {
                tree: &tree,
                leaf: bytes_into_fr::<Bls12>(
                    data_at_node(data.as_slice(), pub_inputs.challenge, pub_params.lambda).unwrap(),
                ).unwrap(),
            };

            // create a non circuit proof
            let proof =
                merklepor::MerklePoR::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

            // make sure it verifies
            assert!(
                merklepor::MerklePoR::verify(&pub_params, &pub_inputs, &proof).unwrap(),
                "failed to verify merklepor proof"
            );

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let por = PoRCircuit::<Bls12> {
                params,
                value: Some(proof.data),
                auth_path: proof.proof.as_options(),
                root: Some(pub_inputs.commitment.unwrap().into()),
            };

            por.synthesize(&mut cs).unwrap();

            assert_eq!(cs.num_inputs(), 3, "wrong number of inputs");
            assert_eq!(cs.num_constraints(), 4846, "wrong number of constraints");

            let auth_path_bits: Vec<bool> = proof
                .proof
                .path()
                .iter()
                .map(|(_, is_right)| *is_right)
                .collect();
            let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

            let mut expected_inputs = Vec::new();
            expected_inputs.extend(packed_auth_path);
            expected_inputs.push(pub_inputs.commitment.unwrap().into());

            assert_eq!(cs.get_input(0, "ONE"), Fr::one(), "wrong input 0");

            assert_eq!(
                cs.get_input(1, "packed auth_path/input 0"),
                expected_inputs[0],
                "wrong packed_auth_path"
            );

            assert_eq!(
                cs.get_input(2, "root/input variable"),
                expected_inputs[1],
                "wrong root input"
            );

            assert!(cs.is_satisfied(), "constraints are not all satisfied");
            assert!(cs.verify(&expected_inputs), "failed to verify inputs");
        }
    }
}
