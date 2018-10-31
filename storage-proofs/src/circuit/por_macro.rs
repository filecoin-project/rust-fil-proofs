#[macro_export]
macro_rules! implement_por {
    ($name:ident, $compound_name:ident, $string_name:expr, $private:expr) => {
        use hasher::Hasher;
        use std::marker::PhantomData;

        pub struct $name<'a, E: JubjubEngine> {
            params: &'a E::Params,
            value: Option<E::Fr>,
            auth_path: Vec<Option<(E::Fr, bool)>>,
            root: Option<E::Fr>,
        }

        pub struct $compound_name<H: Hasher> {
            _h: PhantomData<H>,
        }

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

        impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetIdentifier, H: Hasher>
            CacheableParameters<E, C, P> for $compound_name<H>
        {
            fn cache_prefix() -> String {
                String::from($string_name)
            }
        }

        // can only implment for Bls12 because merklepor is not generic over the engine.
        impl<'a, H> CompoundProof<'a, Bls12, MerklePoR<H>, $name<'a, Bls12>> for $compound_name<H>
        where
            H: 'a + Hasher,
        {
            fn circuit<'b>(
                public_inputs: &<MerklePoR<H> as ProofScheme<'a>>::PublicInputs,
                proof: &'b <MerklePoR<H> as ProofScheme<'a>>::Proof,
                _public_params: &'b <MerklePoR<H> as ProofScheme<'a>>::PublicParams,
                engine_params: &'a JubjubBls12,
            ) -> $name<'a, Bls12> {
                let root = if $private {
                    Some(proof.proof.root.clone().into())
                } else {
                    Some(
                        public_inputs
                            .commitment
                            .expect("required root commitment is missing")
                            .into(),
                    )
                };
                $name::<Bls12> {
                    params: engine_params,
                    value: Some(proof.data.clone().into()),
                    auth_path: proof.proof.as_options(),
                    root,
                }
            }

            fn generate_public_inputs(
                pub_inputs: &<MerklePoR<H> as ProofScheme<'a>>::PublicInputs,
                pub_params: &<MerklePoR<H> as ProofScheme<'a>>::PublicParams,
                _k: Option<usize>,
            ) -> Vec<Fr> {
                let auth_path_bits =
                    challenge_into_auth_path_bits(pub_inputs.challenge, pub_params.leaves);
                let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

                let mut inputs = Vec::new();
                inputs.extend(packed_auth_path);
                if !$private {
                    inputs.push(pub_inputs.commitment.unwrap().into());
                }

                inputs
            }
        }

        impl<'a, E: JubjubEngine> Circuit<E> for $name<'a, E> {
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
                let params = self.params;
                let value = self.value;
                let auth_path = self.auth_path;
                let root = self.root;

                {
                    let value_num = num::AllocatedNum::alloc(cs.namespace(|| "value"), || {
                        Ok(value.ok_or_else(|| SynthesisError::AssignmentMissing)?)
                    })?;

                    let mut cur = value_num;

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
                        let path_element =
                            num::AllocatedNum::alloc(cs.namespace(|| "path element"), || {
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
                        )?
                        .get_x()
                        .clone(); // Injective encoding

                        auth_path_bits.push(cur_is_right);
                    }

                    // allocate input for is_right auth_path
                    multipack::pack_into_inputs(cs.namespace(|| "path"), &auth_path_bits)?;

                    {
                        // Validate that the root of the merkle tree that we calculated is the same as the input.

                        let real_root_value = root;

                        // Allocate the "real" root that will be exposed.
                        let rt = num::AllocatedNum::alloc(cs.namespace(|| "root value"), || {
                            real_root_value.ok_or(SynthesisError::AssignmentMissing)
                        })?;

                        constraint::equal(cs, || "enforce root is correct", &cur, &rt);

                        if !$private {
                            // Expose the root
                            rt.inputize(cs.namespace(|| "root"))?;
                        }
                    }

                    Ok(())
                }
            }
        }

        impl<'a, E: JubjubEngine> $name<'a, E> {
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
                let por = $name::<E> {
                    params,
                    value,
                    auth_path,
                    root,
                };

                por.synthesize(&mut cs)
            }
        }
    };
}
