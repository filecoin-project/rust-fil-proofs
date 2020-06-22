use anyhow::{ensure, Context};
use log::debug;
use paired::bls12_381::Fr;
use sha2raw::Sha256;
use storage_proofs_core::{
    error::Result,
    hasher::{Domain, Hasher},
    merkle::{MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper},
    proof::ProofScheme,
};

use super::{
    batch_hasher::{batch_hash_expanded, truncate_hash},
    hash_comm_r, hash_prefix, Challenge, ChallengeRequirements, Challenges, Config, LayerProof,
    NarrowStackedExpander, Parent, PrivateInputs, Proof, PublicInputs, PublicParams, SetupParams,
};
use crate::{encode, PoRep};

impl<'a, 'c, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> ProofScheme<'a>
    for NarrowStackedExpander<'c, Tree, G>
{
    type PublicParams = PublicParams<Tree>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<Tree, G>;
    type Proof = Vec<LayerProof<Tree, G>>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(sp.clone().into())
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let proofs = Self::prove_all_partitions(pub_params, pub_inputs, priv_inputs, 1)?;
        let k = pub_inputs.k.unwrap_or_default();

        // Because partition proofs require a common setup, the general ProofScheme implementation,
        // which makes use of `ProofScheme::prove` cannot be used here. Instead, we need to prove all
        // partitions in one pass, as implemented by `prove_all_partitions` below.
        assert!(
            k < 1,
            "It is a programmer error to call NarrowStackedExpander::prove with more than one partition."
        );

        Ok(proofs[k].to_owned())
    }

    fn prove_all_partitions<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
        partition_count: usize,
    ) -> Result<Vec<Self::Proof>> {
        ensure!(partition_count > 0, "partitions must not be 0");

        let config = &pub_params.config;
        let challenges = Challenges::new(
            config,
            pub_params.num_layer_challenges,
            &pub_inputs.replica_id,
            pub_inputs.seed,
        );

        let mut partition_proofs = Vec::with_capacity(partition_count);
        let rows_to_discard = priv_inputs.t_aux.tree_config_rows_to_discard;

        for partition in 0..partition_count {
            debug!("proving {} partition", partition);

            let mut proofs = Vec::with_capacity(challenges.len());

            let butterfly_parents = super::ButterflyGraph::from(config);
            let exp_parents = super::ExpanderGraph::from(config);

            let generate_node_proof =
                |challenge: &Challenge,
                 layer_tree: &MerkleTreeWrapper<_, _, _, _, _>,
                 pt: Option<(Vec<Parent>, &MerkleTreeWrapper<_, _, _, _, _>)>| {
                    // Data Inclusion Proof
                    let data_proof = priv_inputs
                        .t_aux
                        .tree_d
                        .gen_proof(challenge.absolute_index as usize)
                        .context("failed to create data proof")?;

                    // Layer Inclusion Proof
                    let layer_proof = layer_tree
                        .gen_cached_proof(challenge.absolute_index as usize, Some(rows_to_discard))
                        .context("failed to create layer proof")?;

                    // roots for the layers
                    let mut comm_layers = priv_inputs.p_aux.comm_layers.clone();
                    comm_layers.push(priv_inputs.p_aux.comm_replica);

                    let parents_proofs = if let Some((parents, parents_tree)) = pt {
                        parents
                            .iter()
                            .map(|relative_parent_index| {
                                // challenge is adjusted as the trees span all windows
                                let absolute_parent_index = challenge.window as usize
                                    * config.num_nodes_window
                                    + *relative_parent_index as usize;

                                parents_tree
                                    .gen_cached_proof(absolute_parent_index, Some(rows_to_discard))
                                    .context("failed to create parent proof")
                            })
                            .collect::<Result<_>>()?
                    } else {
                        Vec::new()
                    };

                    Ok(Proof::new(
                        data_proof,
                        layer_proof,
                        parents_proofs,
                        comm_layers,
                    ))
                };

            for (layer_challenge_index, layer_challenge) in challenges.clone().enumerate() {
                debug!("proving challenge: {}", layer_challenge_index);

                // -- First Layer Challenge
                debug!("proving first layer");
                let first_layer_proof = generate_node_proof(
                    &layer_challenge.first_layer_challenge,
                    &priv_inputs.t_aux.layers[0],
                    None,
                )?;

                // -- Expander Layer Challenges
                let expander_layer_proofs = layer_challenge
                    .expander_challenges
                    .iter()
                    .enumerate()
                    .map(|(i, challenge)| {
                        let layer = i + 2;
                        debug!("proving expander layer {}", layer);

                        let parents: Vec<Parent> = exp_parents
                            .expanded_parents(challenge.relative_index)
                            .collect();
                        let parents_tree = &priv_inputs.t_aux.layers[layer - 2];

                        generate_node_proof(
                            challenge,
                            &priv_inputs.t_aux.layers[layer - 1],
                            Some((parents, parents_tree)),
                        )
                    })
                    .collect::<Result<_>>()?;

                // -- Butterfly Layer Challenges
                let butterfly_layer_proofs = layer_challenge
                    .butterfly_challenges
                    .iter()
                    .enumerate()
                    .map(|(i, challenge)| {
                        let layer = i + config.num_expander_layers + 1;
                        debug!("proving butterfly layer {}", layer);

                        let parents: Vec<Parent> = butterfly_parents
                            .parents(challenge.relative_index, layer as u32)
                            .collect();

                        let parents_tree = &priv_inputs.t_aux.layers[layer - 2];

                        generate_node_proof(
                            challenge,
                            &priv_inputs.t_aux.layers[layer - 1],
                            Some((parents, parents_tree)),
                        )
                    })
                    .collect::<Result<_>>()?;

                // -- Last Layer Challenge
                debug!("proving last layer");
                let last_layer_proof = {
                    let layer = config.num_layers();

                    let challenge = layer_challenge.last_layer_challenge;
                    let parents: Vec<Parent> = butterfly_parents
                        .parents(challenge.relative_index, layer as u32)
                        .collect();

                    let parents_tree = &priv_inputs.t_aux.layers[layer - 2];
                    generate_node_proof(
                        &challenge,
                        &priv_inputs.t_aux.tree_replica,
                        Some((parents, parents_tree)),
                    )
                }?;

                proofs.push(LayerProof {
                    first_layer_proof,
                    expander_layer_proofs,
                    butterfly_layer_proofs,
                    last_layer_proof,
                });
            }

            partition_proofs.push(proofs);
        }

        Ok(partition_proofs)
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        let config = &pub_params.config;

        let is_valid = partition_proofs.iter().enumerate().all(|(k, proofs)| {
            let pub_inputs = Self::with_partition(pub_inputs.clone(), Some(k));
            let tau = pub_inputs.tau.as_ref().expect("missing tau");

            let challenges = Challenges::new(
                config,
                pub_params.num_layer_challenges,
                &pub_inputs.replica_id,
                pub_inputs.seed,
            );

            for (proof, challenge) in proofs.iter().zip(challenges) {
                debug!("verifying challenge {:?}", challenge);

                // -- First Layer

                check!(
                    Self::verify_first_layer(
                        tau,
                        pub_inputs.replica_id,
                        &proof.first_layer_proof,
                        &challenge.first_layer_challenge,
                    ),
                    "invalid first layer"
                );

                // -- Expander Layers

                check_eq!(
                    proof.expander_layer_proofs.len(),
                    config.num_expander_layers - 1,
                    "invalid number of expander proofs"
                );
                check_eq!(
                    challenge.expander_challenges.len(),
                    config.num_expander_layers - 1,
                    "invalid number of expander challenges"
                );
                for (i, (proof, challenge)) in proof
                    .expander_layer_proofs
                    .iter()
                    .zip(challenge.expander_challenges.iter())
                    .enumerate()
                {
                    let layer = i + 2;
                    check!(
                        Self::verify_expander_layer(
                            config,
                            tau,
                            pub_inputs.replica_id,
                            proof,
                            challenge,
                            layer,
                        ),
                        "invalid expander layer {}",
                        layer
                    );
                }

                // -- Butterfly Layers

                check_eq!(
                    proof.butterfly_layer_proofs.len(),
                    config.num_butterfly_layers - 1,
                    "invalid number of butterfly proofs"
                );
                check_eq!(
                    challenge.butterfly_challenges.len(),
                    config.num_butterfly_layers - 1,
                    "invalid number of butterfly challenges"
                );
                for (i, (proof, challenge)) in proof
                    .butterfly_layer_proofs
                    .iter()
                    .zip(challenge.butterfly_challenges.iter())
                    .enumerate()
                {
                    let layer = i + config.num_expander_layers + 1;
                    check!(
                        Self::verify_butterfly_layer(
                            config,
                            tau,
                            pub_inputs.replica_id,
                            proof,
                            challenge,
                            layer,
                        ),
                        "invalid butterfly layer {}",
                        layer
                    );
                }

                // -- Last Layer
                check!(
                    Self::verify_last_layer(
                        config,
                        tau,
                        pub_inputs.replica_id,
                        &proof.last_layer_proof,
                        &challenge.last_layer_challenge,
                        config.num_layers(),
                    ),
                    "invalid last layer"
                );
            }

            true
        });

        Ok(is_valid)
    }

    fn with_partition(mut pub_in: Self::PublicInputs, k: Option<usize>) -> Self::PublicInputs {
        pub_in.k = k;
        pub_in
    }

    fn satisfies_requirements(
        _public_params: &PublicParams<Tree>,
        _requirements: &ChallengeRequirements,
        _partitions: usize,
    ) -> bool {
        todo!()
    }
}

impl<'a, 'c, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher>
    NarrowStackedExpander<'c, Tree, G>
{
    fn verify_first_layer(
        tau: &<Self as PoRep<'c, Tree::Hasher, G>>::Tau,
        replica_id: <Tree::Hasher as Hasher>::Domain,
        proof: &Proof<Tree, G>,
        challenge: &Challenge,
    ) -> bool {
        let layer = 1;

        // verify comm_r
        let last = proof.comm_layers.len() - 1;
        let comm_r: <Tree::Hasher as Hasher>::Domain =
            hash_comm_r(&proof.comm_layers[..last], proof.comm_layers[last]).into();
        check_eq!(comm_r, tau.comm_r);

        // verify data inclusion
        check!(proof.data_proof.verify());
        check_eq!(proof.data_proof.root(), tau.comm_d);

        // verify layer inclusion
        check!(proof.layer_proof.verify());
        check_eq!(proof.layer_proof.root(), proof.comm_layers[layer - 1]);

        // no parents for the mask layer
        check_eq!(proof.parents_proofs.len(), 0, "mask parents length");

        let prefix = hash_prefix(
            layer as u32,
            challenge.relative_index,
            challenge.window as u32,
        );

        let mut hasher = Sha256::new();
        // Hash prefix + replica id, each 32 bytes.
        hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(&replica_id)]);

        // Mask layer hashing
        let mut label = hasher.finish();
        truncate_hash(&mut label);

        let expected_value = proof.layer_proof.leaf();
        check_eq!(
            &label,
            AsRef::<[u8]>::as_ref(&expected_value),
            "labeling check: {:?}",
            challenge,
        );
        true
    }

    fn verify_expander_layer(
        config: &Config,
        tau: &<Self as PoRep<'c, Tree::Hasher, G>>::Tau,
        replica_id: <Tree::Hasher as Hasher>::Domain,
        proof: &Proof<Tree, G>,
        challenge: &Challenge,
        layer: usize,
    ) -> bool {
        let exp_parents = super::ExpanderGraph::from(config);

        // verify comm_r
        let last = proof.comm_layers.len() - 1;
        let comm_r: <Tree::Hasher as Hasher>::Domain =
            hash_comm_r(&proof.comm_layers[..last], proof.comm_layers[last]).into();
        check_eq!(comm_r, tau.comm_r);

        // verify data inclusion
        check!(proof.data_proof.verify());
        check_eq!(proof.data_proof.root(), tau.comm_d);

        // verify layer inclusion
        check!(proof.layer_proof.verify());
        check_eq!(proof.layer_proof.root(), proof.comm_layers[layer - 1]);

        // Verify labeling
        for parent_proof in &proof.parents_proofs {
            check!(parent_proof.verify());
            check_eq!(parent_proof.root(), proof.comm_layers[layer - 2]);
        }
        let parent_indices = proof
            .parents_proofs
            .iter()
            .map(|p| p.path_index())
            .collect::<Vec<usize>>();

        check_eq!(
            proof.parents_proofs.len(),
            config.k as usize * config.degree_expander,
            "expander parents length"
        );
        check_eq!(
            &parent_indices,
            &exp_parents
                .expanded_parents(challenge.relative_index)
                .map(|p| challenge.window as usize * config.num_nodes_window + p as usize)
                .collect::<Vec<_>>(),
            "expander parent indices"
        );

        // actual labeling
        let data: Vec<_> = proof
            .parents_proofs
            .iter()
            .map(|parent_proof| parent_proof.leaf())
            .collect();
        let prefix = hash_prefix(
            layer as u32,
            challenge.relative_index as u32,
            challenge.window as u32,
        );

        let mut hasher = Sha256::new();
        // Hash prefix + replica id, each 32 bytes.
        hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(&replica_id)]);

        // Expander "batch" hashing
        let label = batch_hash_expanded(config.k as usize, config.degree_expander, hasher, &data);

        let expected_value = proof.layer_proof.leaf();
        check_eq!(
            &label,
            AsRef::<[u8]>::as_ref(&expected_value),
            "labeling check: {:?}",
            challenge,
        );
        true
    }

    fn verify_butterfly_layer(
        config: &Config,
        tau: &<Self as PoRep<'c, Tree::Hasher, G>>::Tau,
        replica_id: <Tree::Hasher as Hasher>::Domain,
        proof: &Proof<Tree, G>,
        challenge: &Challenge,
        layer: usize,
    ) -> bool {
        let butterfly_parents = super::ButterflyGraph::from(config);

        // verify comm_r
        let last = proof.comm_layers.len() - 1;
        let comm_r: <Tree::Hasher as Hasher>::Domain =
            hash_comm_r(&proof.comm_layers[..last], proof.comm_layers[last]).into();
        check_eq!(comm_r, tau.comm_r);

        // verify data inclusion
        check!(proof.data_proof.verify());
        check_eq!(proof.data_proof.root(), tau.comm_d);

        // verify layer inclusion
        check!(proof.layer_proof.verify());
        check_eq!(proof.layer_proof.root(), proof.comm_layers[layer - 1]);

        // Verify labeling
        for parent_proof in &proof.parents_proofs {
            check!(parent_proof.verify());
            check_eq!(parent_proof.root(), proof.comm_layers[layer - 2]);
        }
        let parent_indices = proof
            .parents_proofs
            .iter()
            .map(|p| p.path_index())
            .collect::<Vec<usize>>();

        check_eq!(
            proof.parents_proofs.len(),
            config.degree_butterfly,
            "butterfly parents length"
        );
        check_eq!(
            &parent_indices,
            &butterfly_parents
                .parents(challenge.relative_index, layer as u32)
                .map(|p| challenge.window as usize * config.num_nodes_window + p as usize)
                .collect::<Vec<_>>(),
            "butterfly parent indices"
        );

        // actual labeling
        let data: Vec<_> = proof
            .parents_proofs
            .iter()
            .map(|parent_proof| parent_proof.leaf())
            .collect();
        let prefix = hash_prefix(
            layer as u32,
            challenge.relative_index,
            challenge.window as u32,
        );

        let mut hasher = Sha256::new();
        // Hash prefix + replica id, each 32 bytes.
        hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(&replica_id)]);

        // Butterfly hashing
        for chunk in data.chunks(2) {
            hasher.input(&[
                AsRef::<[u8]>::as_ref(&chunk[0]),
                AsRef::<[u8]>::as_ref(&chunk[1]),
            ]);
        }
        let mut label = hasher.finish();
        truncate_hash(&mut label);

        let expected_value = proof.layer_proof.leaf();
        check_eq!(
            &label,
            AsRef::<[u8]>::as_ref(&expected_value),
            "labeling check: {:?}",
            challenge,
        );
        true
    }

    fn verify_last_layer(
        config: &Config,
        tau: &<Self as PoRep<'c, Tree::Hasher, G>>::Tau,
        replica_id: <Tree::Hasher as Hasher>::Domain,
        proof: &Proof<Tree, G>,
        challenge: &Challenge,
        layer: usize,
    ) -> bool {
        let butterfly_parents = super::ButterflyGraph::from(config);

        // verify comm_r
        let last = proof.comm_layers.len() - 1;
        let comm_r: <Tree::Hasher as Hasher>::Domain =
            hash_comm_r(&proof.comm_layers[..last], proof.comm_layers[last]).into();
        check_eq!(comm_r, tau.comm_r);

        // verify data inclusion
        check!(proof.data_proof.verify());
        check_eq!(proof.data_proof.root(), tau.comm_d);

        // verify layer inclusion
        check!(proof.layer_proof.verify());
        check_eq!(proof.layer_proof.root(), proof.comm_layers[layer - 1]);

        // Verify labeling
        for parent_proof in &proof.parents_proofs {
            check!(parent_proof.verify());
            check_eq!(parent_proof.root(), proof.comm_layers[layer - 2]);
        }
        let parent_indices = proof
            .parents_proofs
            .iter()
            .map(|p| p.path_index())
            .collect::<Vec<usize>>();

        check_eq!(
            proof.parents_proofs.len(),
            config.degree_butterfly,
            "butterfly parents length"
        );
        check_eq!(
            &parent_indices,
            &butterfly_parents
                .parents(challenge.relative_index, layer as u32)
                .map(|p| challenge.window as usize * config.num_nodes_window + p as usize)
                .collect::<Vec<_>>(),
            "butterfly parent indices"
        );

        // actual labeling
        let data: Vec<_> = proof
            .parents_proofs
            .iter()
            .map(|parent_proof| parent_proof.leaf())
            .collect();
        let prefix = hash_prefix(
            layer as u32,
            challenge.relative_index,
            challenge.window as u32,
        );

        let mut hasher = Sha256::new();
        // Hash prefix + replica id, each 32 bytes.
        hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(&replica_id)]);

        // Butterfly hashing
        for chunk in data.chunks(2) {
            hasher.input(&[
                AsRef::<[u8]>::as_ref(&chunk[0]),
                AsRef::<[u8]>::as_ref(&chunk[1]),
            ]);
        }
        let mut label = hasher.finish();
        truncate_hash(&mut label);

        let expected_value = proof.layer_proof.leaf();

        // encoding check
        let key = <Tree::Hasher as Hasher>::Domain::try_from_bytes(&label).unwrap();
        let data_node_fr: Fr = proof.data_proof.leaf().into();
        let data_node = data_node_fr.into();

        let encoded = encode::encode(key, data_node);
        check_eq!(
            AsRef::<[u8]>::as_ref(&encoded),
            AsRef::<[u8]>::as_ref(&expected_value),
            "encoding check: {:?}",
            challenge,
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use generic_array::typenum::{Unsigned, U0, U2, U8};
    use merkletree::store::StoreConfig;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::cache_key::CacheKey;
    use storage_proofs_core::{
        hasher::{Domain, PoseidonHasher, Sha256Hasher},
        merkle::LCTree,
        proof::ProofScheme,
    };

    use super::super::{Config, TemporaryAuxCache};
    use crate::PoRep;

    #[test]
    fn test_prove_verify() {
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Debug)
        //     .ok();

        type Tree = LCTree<PoseidonHasher, U8, U8, U0>;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let replica_id = <PoseidonHasher as Hasher>::Domain::random(rng);
        let config = Config {
            k: 4,
            num_nodes_window: 64,
            degree_expander: 12,
            degree_butterfly: 8,
            num_expander_layers: 4,
            num_butterfly_layers: 3,
            sector_size: 64 * 32 * 8,
        };

        let data: Vec<u8> = (0..config.num_nodes_sector())
            .flat_map(|_| {
                let v = <PoseidonHasher as Hasher>::Domain::random(rng);
                v.into_bytes()
            })
            .collect();

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            config: config.clone(),
            num_layer_challenges: 2,
        };

        let pp = NarrowStackedExpander::<Tree, Sha256Hasher>::setup(&sp).expect("setup failed");

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_rows_to_discard(config.num_nodes_sector(), U2::to_usize()),
        );

        // Generate a replica path.
        let temp_dir = tempdir::TempDir::new("test-extract-all").unwrap();
        let temp_path = temp_dir.path();
        let replica_path = temp_path.join("replica-path");

        let (tau, (p_aux, t_aux)) = NarrowStackedExpander::<Tree, Sha256Hasher>::replicate(
            &pp,
            &replica_id,
            (&mut data_copy[..]).into(),
            None,
            store_config.clone(),
            replica_path.clone(),
        )
        .expect("replication failed");
        assert_ne!(data, data_copy);

        std::fs::write(&replica_path, &data_copy).expect("failed to store replica");

        let seed = rng.gen();

        let pub_inputs = PublicInputs::<
            <<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain,
            <Sha256Hasher as Hasher>::Domain,
        > {
            replica_id,
            seed,
            tau: Some(tau),
            k: None,
        };

        // Store a copy of the t_aux for later resource deletion.
        let t_aux_orig = t_aux.clone();

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        let t_aux = TemporaryAuxCache::<Tree, Sha256Hasher>::new(&config, &t_aux, replica_path)
            .expect("failed to restore contents of t_aux");

        let priv_inputs = PrivateInputs { p_aux, t_aux };
        let partitions = 1;

        let all_partition_proofs =
            &NarrowStackedExpander::<Tree, Sha256Hasher>::prove_all_partitions(
                &pp,
                &pub_inputs,
                &priv_inputs,
                partitions,
            )
            .expect("failed to generate partition proofs");

        let proofs_are_valid = NarrowStackedExpander::<Tree, Sha256Hasher>::verify_all_partitions(
            &pp,
            &pub_inputs,
            all_partition_proofs,
        )
        .expect("failed to verify partition proofs");

        // Discard cached MTs that are no longer needed.
        t_aux_orig.clear_temp().expect("t_aux delete failed");

        assert!(proofs_are_valid);
    }
}
