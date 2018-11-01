#[macro_export]
macro_rules! implement_drgporep {
    ($name:ident, $compound_name:ident, $string_name:expr, $private:expr) => {
        use circuit::por::{PoRCircuit, PoRCompound};
        use circuit::private_por::{PrivatePoRCircuit, PrivatePoRCompound};
        use hasher::{Domain, Hasher};

        pub struct $name<'a, E: JubjubEngine> {
            params: &'a E::Params,
            lambda: usize,
            sloth_iter: usize,
            replica_nodes: Vec<Option<E::Fr>>,
            replica_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
            replica_root: Option<E::Fr>,
            replica_parents: Vec<Vec<Option<E::Fr>>>,
            replica_parents_paths: Vec<Vec<Vec<Option<(E::Fr, bool)>>>>,
            data_nodes: Vec<Option<E::Fr>>,
            data_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
            data_root: Option<E::Fr>,
            replica_id: Option<E::Fr>,
            degree: usize,
        }
        impl<'a, E: JubjubEngine> $name<'a, E> {
            pub fn synthesize<CS>(
                mut cs: CS,
                params: &E::Params,
                lambda: usize,
                sloth_iter: usize,
                replica_nodes: Vec<Option<E::Fr>>,
                replica_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
                replica_root: Option<E::Fr>,
                replica_parents: Vec<Vec<Option<E::Fr>>>,
                replica_parents_paths: Vec<Vec<Vec<Option<(E::Fr, bool)>>>>,
                data_nodes: Vec<Option<E::Fr>>,
                data_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
                data_root: Option<E::Fr>,
                replica_id: Option<E::Fr>,
                degree: usize,
            ) -> Result<(), SynthesisError>
            where
                E: JubjubEngine,
                CS: ConstraintSystem<E>,
            {
                $name {
                    params,
                    lambda,
                    sloth_iter,
                    replica_nodes,
                    replica_nodes_paths,
                    replica_root,
                    replica_parents,
                    replica_parents_paths,
                    data_nodes,
                    data_nodes_paths,
                    data_root,
                    replica_id,
                    degree,
                }
                .synthesize(&mut cs)
            }
        }

        pub struct $compound_name<H, G>
        where
            H: Hasher,
            G: Graph<H>,
        {
            // Sad phantom is sad
            _h: PhantomData<H>,
            _g: PhantomData<G>,
        }

        impl<E: JubjubEngine, C: Circuit<E>, H: Hasher, G: Graph<H>, P: ParameterSetIdentifier>
            CacheableParameters<E, C, P> for $compound_name<H, G>
        {
            fn cache_prefix() -> String {
                String::from($string_name)
            }
        }

        impl<'a, H, G> CompoundProof<'a, Bls12, DrgPoRep<'a, H, G>, $name<'a, Bls12>>
            for $compound_name<H, G>
        where
            H: 'a + Hasher,
            G: 'a + Graph<H> + ParameterSetIdentifier,
        {
            fn generate_public_inputs(
                pub_in: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicInputs,
                pub_params: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
                // We can ignore k because challenges are genereated by caller and included
                // in PublicInputs.
                _k: Option<usize>,
            ) -> Vec<Fr> {
                let replica_id = pub_in.replica_id;
                let challenges = &pub_in.challenges;
                let (comm_r, comm_d) = if $private {
                    assert!(pub_in.tau.is_none());
                    (None, None)
                } else {
                    match pub_in.tau {
                        Some(tau) => (Some(tau.comm_r), Some(tau.comm_d)),
                        None => (None, None),
                    }
                };

                let lambda = pub_params.lambda;
                let leaves = pub_params.graph.size();

                let replica_id_bits = bytes_into_bits(&replica_id.into_bytes());

                let packed_replica_id = multipack::compute_multipacking::<Bls12>(
                    &replica_id_bits[0..Fr::CAPACITY as usize],
                );

                let por_pub_params = merklepor::PublicParams { lambda, leaves };

                let mut input = Vec::new();
                input.extend(packed_replica_id.clone());

                for challenge in challenges {
                    let mut por_nodes = vec![*challenge];
                    let parents = pub_params.graph.parents(*challenge);
                    por_nodes.extend(parents);

                    for node in por_nodes {
                        let por_pub_inputs = merklepor::PublicInputs {
                            commitment: comm_r,
                            challenge: node,
                        };
                        let por_inputs = if $private {
                            PrivatePoRCompound::<H>::generate_public_inputs(
                                &por_pub_inputs,
                                &por_pub_params,
                                None,
                            )
                        } else {
                            PoRCompound::<H>::generate_public_inputs(
                                &por_pub_inputs,
                                &por_pub_params,
                                None,
                            )
                        };
                        input.extend(por_inputs);
                    }

                    let por_pub_inputs = merklepor::PublicInputs {
                        commitment: comm_d,
                        challenge: *challenge,
                    };

                    let por_inputs = if $private {
                        PrivatePoRCompound::<H>::generate_public_inputs(
                            &por_pub_inputs,
                            &por_pub_params,
                            None,
                        )
                    } else {
                        PoRCompound::<H>::generate_public_inputs(
                            &por_pub_inputs,
                            &por_pub_params,
                            None,
                        )
                    };
                    input.extend(por_inputs);
                }
                input
            }

            fn circuit<'b>(
                public_inputs: &'b <DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicInputs,
                proof: &'b <DrgPoRep<'a, H, G> as ProofScheme<'a>>::Proof,
                public_params: &'b <DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
                engine_params: &'a <Bls12 as JubjubEngine>::Params,
            ) -> $name<'a, Bls12> {
                let lambda = public_params.lambda;

                let replica_nodes = proof
                    .replica_nodes
                    .iter()
                    .map(|node| Some(node.data.into()))
                    .collect();

                let replica_nodes_paths = proof
                    .replica_nodes
                    .iter()
                    .map(|node| node.proof.as_options())
                    .collect();

                let replica_root = Some((*proof.replica_nodes[0].proof.root()).into());

                let replica_parents = proof
                    .replica_parents
                    .iter()
                    .map(|parents| {
                        parents
                            .iter()
                            .map(|(_, parent)| Some(parent.data.into()))
                            .collect()
                    })
                    .collect();

                let replica_parents_paths: Vec<Vec<_>> = proof
                    .replica_parents
                    .iter()
                    .map(|parents| {
                        let p: Vec<_> = parents
                            .iter()
                            .map(|(_, parent)| parent.proof.as_options())
                            .collect();
                        p
                    })
                    .collect();

                let data_nodes = proof
                    .nodes
                    .iter()
                    .map(|node| Some(node.data.into()))
                    .collect();

                let data_nodes_paths = proof
                    .nodes
                    .iter()
                    .map(|node| node.proof.as_options())
                    .collect();

                let data_root = Some((*proof.nodes[0].proof.root()).into());
                let replica_id = Some(public_inputs.replica_id);

                $name {
                    params: engine_params,
                    lambda,
                    sloth_iter: public_params.sloth_iter,
                    replica_nodes,
                    replica_nodes_paths,
                    replica_root,
                    replica_parents,
                    replica_parents_paths,
                    data_nodes,
                    data_nodes_paths,
                    data_root,
                    replica_id: replica_id.map(|f| f.into()),
                    degree: public_params.graph.degree(),
                }
            }
        }

        ///
        /// # Public Inputs
        ///
        /// * [0] replica_id/0
        /// * [1] replica_id/1
        /// * [2] replica auth_path_bits
        /// * [3] replica commitment (root hash)
        /// * for i in 0..replica_parents.len()
        ///   * [ ] replica parent auth_path_bits
        ///   * [ ] replica parent commitment (root hash) // Same for all.
        /// * [r + 1] data auth_path_bits
        /// * [r + 2] data commitment (root hash)
        ///
        ///  Total = 6 + (2 * replica_parents.len())
        /// # Private Inputs
        ///
        /// * [ ] replica value/0
        /// * for i in 0..replica_parents.len()
        ///  * [ ] replica parent value/0
        /// * [ ] data value/
        ///
        /// Total = 2 + replica_parents.len()
        ///
        impl<'a, E: JubjubEngine> Circuit<E> for $name<'a, E> {
            fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
            where
                E: JubjubEngine,
            {
                let params = self.params;
                let lambda = self.lambda;

                let replica_id = self.replica_id;
                let replica_root = self.replica_root;
                let data_root = self.data_root;

                let degree = self.degree;

                let raw_bytes; // Need let here so borrow in match lives long enough.
                let replica_id_bytes = match replica_id {
                    Some(replica_id) => {
                        raw_bytes = fr_into_bytes::<E>(&replica_id);
                        Some(raw_bytes.as_slice())
                    }
                    // Used in parameter generation or when circuit is created only for
                    // structure and input count.
                    None => None,
                };

                // get the replica_id in bits
                let replica_id_bits = bytes_into_boolean_vec(
                    cs.namespace(|| "replica_id_bits"),
                    replica_id_bytes,
                    lambda,
                )?;

                multipack::pack_into_inputs(
                    cs.namespace(|| "replica_id"),
                    &replica_id_bits[0..Fr::CAPACITY as usize],
                )?;

                for i in 0..self.data_nodes.len() {
                    let mut cs = cs.namespace(|| format!("challenge_{}", i));
                    // ensure that all inputs are well formed
                    let replica_node_path = &self.replica_nodes_paths[i];
                    let replica_parents_paths = &self.replica_parents_paths[i];
                    let data_node_path = &self.data_nodes_paths[i];

                    let replica_node = &self.replica_nodes[i];
                    let replica_parents = &self.replica_parents[i];
                    let data_node = &self.data_nodes[i];

                    assert_eq!(data_node_path.len(), replica_node_path.len());

                    // Inclusion checks
                    {
                        let mut cs = cs.namespace(|| "inclusion_checks");

                        if $private {
                            PrivatePoRCircuit::synthesize(
                                cs.namespace(|| "replica_inclusion"),
                                &params,
                                *replica_node,
                                replica_node_path.clone(),
                                replica_root,
                            )?;
                        } else {
                            PoRCircuit::synthesize(
                                cs.namespace(|| "replica_inclusion"),
                                &params,
                                *replica_node,
                                replica_node_path.clone(),
                                replica_root,
                            )?;
                        }
                        // validate each replica_parents merkle proof
                        for i in 0..replica_parents.len() {
                            if $private {
                                PrivatePoRCircuit::synthesize(
                                    cs.namespace(|| format!("parent_inclusion_{}", i)),
                                    &params,
                                    replica_parents[i],
                                    replica_parents_paths[i].clone(),
                                    replica_root,
                                )?;
                            } else {
                                PoRCircuit::synthesize(
                                    cs.namespace(|| format!("parent_inclusion_{}", i)),
                                    &params,
                                    replica_parents[i],
                                    replica_parents_paths[i].clone(),
                                    replica_root,
                                )?;
                            }
                        }

                        // validate data node commitment
                        if $private {
                            PrivatePoRCircuit::synthesize(
                                cs.namespace(|| "data_inclusion"),
                                &params,
                                *data_node,
                                data_node_path.clone(),
                                data_root,
                            )?;
                        } else {
                            PoRCircuit::synthesize(
                                cs.namespace(|| "data_inclusion"),
                                &params,
                                *data_node,
                                data_node_path.clone(),
                                data_root,
                            )?;
                        }
                    }

                    // Encoding checks
                    {
                        let mut cs = cs.namespace(|| "encoding_checks");
                        // get the parents into bits
                        let parents_bits: Vec<Vec<Boolean>> = {
                            replica_parents
                                .into_iter()
                                .enumerate()
                                .map(|(i, val)| -> Result<Vec<Boolean>, SynthesisError> {
                                    let mut v = boolean::field_into_boolean_vec_le(
                                        cs.namespace(|| format!("parents_{}_bits", i)),
                                        *val,
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
                            replica_id_bits.clone(),
                            parents_bits,
                            degree,
                        )?;

                        let decoded = sloth::decode(
                            cs.namespace(|| "sloth_decode"),
                            &key,
                            *replica_node,
                            self.sloth_iter,
                        )?;

                        // TODO this should not be here, instead, this should be the leaf Fr in the data_auth_path
                        // TODO also note that we need to change/makesurethat the leaves are the data, instead of hashes of the data
                        let expected =
                            num::AllocatedNum::alloc(cs.namespace(|| "data node"), || {
                                data_node.ok_or_else(|| SynthesisError::AssignmentMissing)
                            })?;

                        // ensure the encrypted data and data_node match
                        constraint::equal(&mut cs, || "equality", &expected, &decoded);
                    }
                }
                // profit!
                Ok(())
            }
        }
    };
}
