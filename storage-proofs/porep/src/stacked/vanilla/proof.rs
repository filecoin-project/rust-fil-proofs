use std::marker::PhantomData;
use std::path::PathBuf;

use generic_array::typenum::{self, Unsigned};
use log::{info, trace};
use merkletree::merkle::{get_merkle_tree_len, is_merkle_tree_size_valid};
use merkletree::store::{DiskStore, StoreConfig};
use paired::bls12_381::Fr;
use rayon::prelude::*;
use storage_proofs_core::{
    cache_key::CacheKey,
    data::Data,
    drgraph::Graph,
    error::Result,
    hasher::{Domain, HashFunction, Hasher, PoseidonArity},
    measurements::{
        measure_op,
        Operation::{CommD, EncodeWindowTimeAll, GenerateTreeC, GenerateTreeRLast},
    },
    merkle::*,
    settings,
    util::NODE_SIZE,
};
use typenum::{U11, U2, U8};

use super::{
    challenges::LayerChallenges,
    column::Column,
    create_label, create_label_exp,
    graph::StackedBucketGraph,
    hash::hash_single_column,
    params::{
        get_node, Labels, LabelsCache, PersistentAux, Proof, PublicInputs, PublicParams,
        ReplicaColumnProof, Tau, TemporaryAux, TemporaryAuxCache, TransformedLayers, BINARY_ARITY,
    },
    EncodingProof, LabelingProof,
};

use ff::Field;
use generic_array::{sequence::GenericSequence, GenericArray};
use neptune::batch_hasher::BatcherType;
use neptune::column_tree_builder::{ColumnTreeBuilder, ColumnTreeBuilderTrait};
use storage_proofs_core::fr32::fr_into_bytes;

use crate::encode::{decode, encode};
use crate::PoRep;

pub const TOTAL_PARENTS: usize = 37;

#[derive(Debug)]
pub struct StackedDrg<'a, Tree: 'a + MerkleTreeTrait, G: 'a + Hasher> {
    _a: PhantomData<&'a Tree>,
    _b: PhantomData<&'a G>,
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> StackedDrg<'a, Tree, G> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_layers(
        graph: &StackedBucketGraph<Tree::Hasher>,
        pub_inputs: &PublicInputs<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>,
        p_aux: &PersistentAux<<Tree::Hasher as Hasher>::Domain>,
        t_aux: &TemporaryAuxCache<Tree, G>,
        layer_challenges: &LayerChallenges,
        layers: usize,
        _total_layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Vec<Proof<Tree, G>>>> {
        assert!(layers > 0);
        assert_eq!(t_aux.labels.len(), layers);

        let graph_size = graph.size();

        // Sanity checks on restored trees.
        assert!(pub_inputs.tau.is_some());
        assert_eq!(pub_inputs.tau.as_ref().unwrap().comm_d, t_aux.tree_d.root());

        let get_drg_parents_columns = |x: usize| -> Result<Vec<Column<Tree::Hasher>>> {
            let base_degree = graph.base_graph().degree();

            let mut columns = Vec::with_capacity(base_degree);

            let mut parents = vec![0; base_degree];
            graph.base_parents(x, &mut parents)?;

            for parent in &parents {
                columns.push(t_aux.column(*parent)?);
            }

            debug_assert!(columns.len() == base_degree);

            Ok(columns)
        };

        let get_exp_parents_columns = |x: usize| -> Result<Vec<Column<Tree::Hasher>>> {
            let mut parents = vec![0; graph.expansion_degree()];
            graph.expanded_parents(x, &mut parents);

            parents.iter().map(|parent| t_aux.column(*parent)).collect()
        };

        (0..partition_count)
            .map(|k| {
                trace!("proving partition {}/{}", k + 1, partition_count);

                // Derive the set of challenges we are proving over.
                let challenges = pub_inputs.challenges(layer_challenges, graph_size, Some(k));

                // Stacked commitment specifics
                challenges
                    .into_par_iter()
                    .enumerate()
                    .map(|(challenge_index, challenge)| {
                        trace!(" challenge {} ({})", challenge, challenge_index);
                        assert!(challenge < graph.size(), "Invalid challenge");
                        assert!(challenge > 0, "Invalid challenge");

                        // Initial data layer openings (c_X in Comm_D)
                        let comm_d_proof = t_aux.tree_d.gen_proof(challenge)?;
                        assert!(comm_d_proof.validate(challenge));

                        // Stacked replica column openings
                        let rcp = {
                            let (c_x, drg_parents, exp_parents) = {
                                assert_eq!(p_aux.comm_c, t_aux.tree_c.root());
                                let tree_c = &t_aux.tree_c;

                                // All labels in C_X
                                trace!("  c_x");
                                let c_x = t_aux.column(challenge as u32)?.into_proof(tree_c)?;

                                // All labels in the DRG parents.
                                trace!("  drg_parents");
                                let drg_parents = get_drg_parents_columns(challenge)?
                                    .into_iter()
                                    .map(|column| column.into_proof(tree_c))
                                    .collect::<Result<_>>()?;

                                // Labels for the expander parents
                                trace!("  exp_parents");
                                let exp_parents = get_exp_parents_columns(challenge)?
                                    .into_iter()
                                    .map(|column| column.into_proof(tree_c))
                                    .collect::<Result<_>>()?;

                                (c_x, drg_parents, exp_parents)
                            };

                            ReplicaColumnProof {
                                c_x,
                                drg_parents,
                                exp_parents,
                            }
                        };

                        // Final replica layer openings
                        trace!("final replica layer openings");
                        let comm_r_last_proof = t_aux.tree_r_last.gen_cached_proof(
                            challenge,
                            Some(t_aux.tree_r_last_config_rows_to_discard),
                        )?;

                        // For development and debugging.
                        assert!(comm_r_last_proof.validate(challenge));

                        // Labeling Proofs Layer 1..l
                        let mut labeling_proofs = Vec::with_capacity(layers);
                        let mut encoding_proof = None;

                        for layer in 1..=layers {
                            trace!("  encoding proof layer {}", layer,);
                            let parents_data: Vec<<Tree::Hasher as Hasher>::Domain> = if layer == 1
                            {
                                let mut parents = vec![0; graph.base_graph().degree()];
                                graph.base_parents(challenge, &mut parents)?;

                                parents
                                    .into_iter()
                                    .map(|parent| t_aux.domain_node_at_layer(layer, parent))
                                    .collect::<Result<_>>()?
                            } else {
                                let mut parents = vec![0; graph.degree()];
                                graph.parents(challenge, &mut parents)?;
                                let base_parents_count = graph.base_graph().degree();

                                parents
                                    .into_iter()
                                    .enumerate()
                                    .map(|(i, parent)| {
                                        if i < base_parents_count {
                                            // parents data for base parents is from the current layer
                                            t_aux.domain_node_at_layer(layer, parent)
                                        } else {
                                            // parents data for exp parents is from the previous layer
                                            t_aux.domain_node_at_layer(layer - 1, parent)
                                        }
                                    })
                                    .collect::<Result<_>>()?
                            };

                            // repeat parents
                            let mut parents_data_full = vec![Default::default(); TOTAL_PARENTS];
                            for chunk in parents_data_full.chunks_mut(parents_data.len()) {
                                chunk.copy_from_slice(&parents_data[..chunk.len()]);
                            }

                            let proof = LabelingProof::<Tree::Hasher>::new(
                                challenge as u64,
                                parents_data_full.clone(),
                            );

                            {
                                let labeled_node = rcp.c_x.get_node_at_layer(layer)?;
                                assert!(
                                    proof.verify(&pub_inputs.replica_id, &labeled_node),
                                    format!("Invalid encoding proof generated at layer {}", layer)
                                );
                                trace!("Valid encoding proof generated at layer {}", layer);
                            }

                            labeling_proofs.push(proof);

                            if layer == layers {
                                encoding_proof =
                                    Some(EncodingProof::new(challenge as u64, parents_data_full));
                            }
                        }

                        Ok(Proof {
                            comm_d_proofs: comm_d_proof,
                            replica_column_proofs: rcp,
                            comm_r_last_proof,
                            labeling_proofs,
                            encoding_proof: encoding_proof.expect("invalid tapering"),
                        })
                    })
                    .collect()
            })
            .collect()
    }

    pub(crate) fn extract_and_invert_transform_layers(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        data: &mut [u8],
        config: StoreConfig,
    ) -> Result<()> {
        trace!("extract_and_invert_transform_layers");

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        // generate labels
        let (labels, _) = Self::generate_labels(graph, layer_challenges, replica_id, config)?;

        let last_layer_labels = labels.labels_for_last_layer()?;
        let size = merkletree::store::Store::len(last_layer_labels);

        for (key, encoded_node_bytes) in last_layer_labels
            .read_range(0..size)?
            .into_iter()
            .zip(data.chunks_mut(NODE_SIZE))
        {
            let encoded_node =
                <Tree::Hasher as Hasher>::Domain::try_from_bytes(encoded_node_bytes)?;
            let data_node = decode::<<Tree::Hasher as Hasher>::Domain>(key, encoded_node);

            // store result in the data
            encoded_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&data_node));
        }

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn generate_labels(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        config: StoreConfig,
    ) -> Result<(LabelsCache<Tree>, Labels<Tree>)> {
        info!("generate labels");

        let layers = layer_challenges.layers();
        // For now, we require it due to changes in encodings structure.
        let mut labels: Vec<DiskStore<<Tree::Hasher as Hasher>::Domain>> =
            Vec::with_capacity(layers);
        let mut label_configs: Vec<StoreConfig> = Vec::with_capacity(layers);

        let layer_size = graph.size() * NODE_SIZE;
        // NOTE: this means we currently keep 2x sector size around, to improve speed.
        let mut labels_buffer = vec![0u8; 2 * layer_size];

        for layer in 1..=layers {
            info!("generating layer: {}", layer);

            if layer == 1 {
                let layer_labels = &mut labels_buffer[..layer_size];
                for node in 0..graph.size() {
                    create_label(graph, replica_id, layer_labels, node)?;
                }
            } else {
                let (layer_labels, exp_labels) = labels_buffer.split_at_mut(layer_size);
                for node in 0..graph.size() {
                    create_label_exp(graph, replica_id, exp_labels, layer_labels, node)?;
                }
            }

            info!("  setting exp parents");
            labels_buffer.copy_within(..layer_size, layer_size);

            // Write the result to disk to avoid keeping it in memory all the time.
            let layer_config =
                StoreConfig::from_config(&config, CacheKey::label_layer(layer), Some(graph.size()));

            info!("  storing labels on disk");
            // Construct and persist the layer data.
            let layer_store: DiskStore<<Tree::Hasher as Hasher>::Domain> =
                DiskStore::new_from_slice_with_config(
                    graph.size(),
                    Tree::Arity::to_usize(),
                    &labels_buffer[..layer_size],
                    layer_config.clone(),
                )?;
            info!(
                "  generated layer {} store with id {}",
                layer, layer_config.id
            );

            // Track the layer specific store and StoreConfig for later retrieval.
            labels.push(layer_store);
            label_configs.push(layer_config);
        }

        assert_eq!(
            labels.len(),
            layers,
            "Invalid amount of layers encoded expected"
        );

        Ok((
            LabelsCache::<Tree> { labels },
            Labels::<Tree> {
                labels: label_configs,
                _h: PhantomData,
            },
        ))
    }

    fn build_binary_tree<K: Hasher>(
        tree_data: &[u8],
        config: StoreConfig,
    ) -> Result<BinaryMerkleTree<K>> {
        trace!("building tree (size: {})", tree_data.len());

        let leafs = tree_data.len() / NODE_SIZE;
        assert_eq!(tree_data.len() % NODE_SIZE, 0);

        let tree = MerkleTree::from_par_iter_with_config(
            (0..leafs)
                .into_par_iter()
                // TODO: proper error handling instead of `unwrap()`
                .map(|i| get_node::<K>(tree_data, i).unwrap()),
            config,
        )?;
        Ok(tree)
    }

    fn generate_tree_c<ColumnArity, TreeArity>(
        layers: usize,
        nodes_count: usize,
        tree_count: usize,
        configs: Vec<StoreConfig>,
        labels: &LabelsCache<Tree>,
    ) -> Result<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        ColumnArity: PoseidonArity,
        TreeArity: PoseidonArity,
    {
        if settings::SETTINGS.lock().unwrap().use_gpu_column_builder {
            Self::generate_tree_c_gpu::<ColumnArity, TreeArity>(
                layers,
                nodes_count,
                tree_count,
                configs,
                labels,
            )
        } else {
            Self::generate_tree_c_cpu::<ColumnArity, TreeArity>(
                layers,
                nodes_count,
                tree_count,
                configs,
                labels,
            )
        }
    }

    fn generate_tree_c_gpu<ColumnArity, TreeArity>(
        layers: usize,
        nodes_count: usize,
        tree_count: usize,
        configs: Vec<StoreConfig>,
        labels: &LabelsCache<Tree>,
    ) -> Result<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        ColumnArity: PoseidonArity,
        TreeArity: PoseidonArity,
    {
        info!("generating tree c using the GPU");
        // Build the tree for CommC
        measure_op(GenerateTreeC, || {
            info!("Building column hashes");

            // NOTE: The max number of columns we recommend sending to
            // the GPU at once is 400000 for columns and 700000 for
            // trees (conservative soft-limits discussed).
            //
            // Override these values with care using environment
            // variables: FIL_PROOFS_MAX_COLUMN_BATCH_SIZE and
            // FIL_PROOFS_MAX_TREE_BATCH_SIZE, respectively.
            let max_gpu_column_batch_size =
                settings::SETTINGS.lock().unwrap().max_gpu_column_batch_size as usize;
            let max_gpu_tree_batch_size =
                settings::SETTINGS.lock().unwrap().max_gpu_tree_batch_size as usize;

            let mut column_tree_builder = ColumnTreeBuilder::<ColumnArity, TreeArity>::new(
                Some(BatcherType::GPU),
                nodes_count,
                max_gpu_column_batch_size,
                max_gpu_tree_batch_size,
            )?;

            for (i, config) in configs.iter().enumerate() {
                let mut node_index = 0;
                while node_index != nodes_count {
                    let chunked_nodes_count =
                        std::cmp::min(nodes_count - node_index, max_gpu_column_batch_size);
                    trace!(
                        "processing config {}/{} with column nodes {}",
                        i + 1,
                        tree_count,
                        chunked_nodes_count,
                    );
                    let mut columns: Vec<GenericArray<Fr, ColumnArity>> =
                        vec![
                            GenericArray::<Fr, ColumnArity>::generate(|_i: usize| Fr::zero());
                            chunked_nodes_count
                        ];

                    rayon::scope(|s| {
                        let n = num_cpus::get();

                        // only split if we have at least two elements per thread
                        let num_chunks = if n > chunked_nodes_count * 2 { 1 } else { n };

                        // chunk into n chunks
                        let chunk_size =
                            (chunked_nodes_count as f64 / num_chunks as f64).ceil() as usize;

                        // gather all n chunks in parallel
                        for (chunk, columns_chunk) in columns.chunks_mut(chunk_size).enumerate() {
                            let labels = &labels;

                            s.spawn(move |_| {
                                for (j, hash) in columns_chunk.iter_mut().enumerate() {
                                    for k in 1..=layers {
                                        let store = labels.labels_for_layer(k);
                                        let el: <Tree::Hasher as Hasher>::Domain = store
                                            .read_at(
                                                (i * nodes_count)
                                                    + node_index
                                                    + j
                                                    + chunk * chunk_size,
                                            )
                                            .unwrap();

                                        hash[k - 1] = el.into();
                                    }
                                }
                            });
                        }
                    });

                    node_index += chunked_nodes_count;
                    trace!(
                        "node index {}/{}/{}",
                        node_index,
                        chunked_nodes_count,
                        nodes_count,
                    );

                    if node_index != nodes_count {
                        column_tree_builder.add_columns(&columns)?;
                    } else {
                        assert_eq!(node_index, nodes_count);
                        let tree_data = column_tree_builder.add_final_columns(&columns)?;
                        let tree_data_len = tree_data.len();
                        info!(
                            "persisting base tree_c {}/{} of length {}",
                            i + 1,
                            tree_count,
                            tree_data_len
                        );
                        assert_eq!(tree_data_len, config.size.unwrap());

                        let flat_tree_data: Vec<_> = tree_data
                            .into_par_iter()
                            .flat_map(|el| fr_into_bytes(&el))
                            .collect();

                        // Persist the data to the store based on the current config.
                        DiskStore::<<Tree::Hasher as Hasher>::Domain>::new_from_slice_with_config(
                            tree_data_len,
                            Tree::Arity::to_usize(),
                            &flat_tree_data[..],
                            config.clone(),
                        )?;
                    }
                }
            }

            create_disk_tree::<
                DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >(configs[0].size.unwrap(), &configs)
        })
    }

    fn generate_tree_c_cpu<ColumnArity, TreeArity>(
        layers: usize,
        nodes_count: usize,
        tree_count: usize,
        configs: Vec<StoreConfig>,
        labels: &LabelsCache<Tree>,
    ) -> Result<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        ColumnArity: PoseidonArity,
        TreeArity: PoseidonArity,
    {
        info!("generating tree c using the CPU");
        measure_op(GenerateTreeC, || {
            info!("Building column hashes");

            let mut trees = Vec::with_capacity(tree_count);
            for (i, config) in configs.iter().enumerate() {
                let mut hashes: Vec<<Tree::Hasher as Hasher>::Domain> =
                    vec![<Tree::Hasher as Hasher>::Domain::default(); nodes_count];

                rayon::scope(|s| {
                    let n = num_cpus::get();

                    // only split if we have at least two elements per thread
                    let num_chunks = if n > nodes_count * 2 { 1 } else { n };

                    // chunk into n chunks
                    let chunk_size = (nodes_count as f64 / num_chunks as f64).ceil() as usize;

                    // calculate all n chunks in parallel
                    for (chunk, hashes_chunk) in hashes.chunks_mut(chunk_size).enumerate() {
                        let labels = &labels;

                        s.spawn(move |_| {
                            for (j, hash) in hashes_chunk.iter_mut().enumerate() {
                                let data: Vec<_> = (1..=layers)
                                    .map(|layer| {
                                        let store = labels.labels_for_layer(layer);
                                        let el: <Tree::Hasher as Hasher>::Domain = store
                                            .read_at((i * nodes_count) + j + chunk * chunk_size)
                                            .unwrap();
                                        el.into()
                                    })
                                    .collect();

                                *hash = hash_single_column(&data).into();
                            }
                        });
                    }
                });

                info!("building base tree_c {}/{}", i + 1, tree_count);
                trees.push(DiskTree::<
                    Tree::Hasher,
                    Tree::Arity,
                    typenum::U0,
                    typenum::U0,
                >::from_par_iter_with_config(
                    hashes.into_par_iter(), config.clone()
                ));
            }

            assert_eq!(tree_count, trees.len());
            create_disk_tree::<
                DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >(configs[0].size.unwrap(), &configs)
        })
    }

    pub(crate) fn transform_and_replicate_layers(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        data: Data,
        data_tree: Option<BinaryMerkleTree<G>>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<TransformedLayers<Tree, G>> {
        // Generate key layers.
        let (_, labels) = measure_op(EncodeWindowTimeAll, || {
            Self::generate_labels(graph, layer_challenges, replica_id, config.clone())
        })?;

        Self::transform_and_replicate_layers_inner(
            graph,
            layer_challenges,
            data,
            data_tree,
            config,
            replica_path,
            labels,
        )
    }

    pub(crate) fn transform_and_replicate_layers_inner(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        mut data: Data,
        data_tree: Option<BinaryMerkleTree<G>>,
        config: StoreConfig,
        replica_path: PathBuf,
        label_configs: Labels<Tree>,
    ) -> Result<TransformedLayers<Tree, G>> {
        trace!("transform_and_replicate_layers");
        let nodes_count = graph.size();

        assert_eq!(data.len(), nodes_count * NODE_SIZE);
        trace!("nodes count {}, data len {}", nodes_count, data.len());

        let tree_count = get_base_tree_count::<Tree>();
        let nodes_count = graph.size() / tree_count;

        // Ensure that the node count will work for binary and oct arities.
        let binary_arity_valid = is_merkle_tree_size_valid(nodes_count, BINARY_ARITY);
        let other_arity_valid = is_merkle_tree_size_valid(nodes_count, Tree::Arity::to_usize());
        trace!(
            "is_merkle_tree_size_valid({}, BINARY_ARITY) = {}",
            nodes_count,
            binary_arity_valid
        );
        trace!(
            "is_merkle_tree_size_valid({}, {}) = {}",
            nodes_count,
            Tree::Arity::to_usize(),
            other_arity_valid
        );
        assert!(binary_arity_valid);
        assert!(other_arity_valid);

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        // Generate all store configs that we need based on the
        // cache_path in the specified config.
        let mut tree_d_config = StoreConfig::from_config(
            &config,
            CacheKey::CommDTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, BINARY_ARITY)?),
        );
        tree_d_config.rows_to_discard =
            StoreConfig::default_rows_to_discard(nodes_count, BINARY_ARITY);

        let mut tree_r_last_config = StoreConfig::from_config(
            &config,
            CacheKey::CommRLastTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, Tree::Arity::to_usize())?),
        );

        // A default 'rows_to_discard' value will be chosen for
        // tree_r_last, unless the user overrides this value via the
        // environment setting (FIL_PROOFS_ROWS_TO_DISCARD).  If this
        // value is specified, no checking is done on it and it may
        // result in a broken configuration.  Use with caution.
        let env_rows_to_discard = settings::SETTINGS.lock().unwrap().rows_to_discard as usize;
        tree_r_last_config.rows_to_discard = if env_rows_to_discard != 0 {
            env_rows_to_discard
        } else {
            StoreConfig::default_rows_to_discard(nodes_count, Tree::Arity::to_usize())
        };

        let mut tree_c_config = StoreConfig::from_config(
            &config,
            CacheKey::CommCTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, Tree::Arity::to_usize())?),
        );
        tree_c_config.rows_to_discard =
            StoreConfig::default_rows_to_discard(nodes_count, Tree::Arity::to_usize());

        let labels = LabelsCache::<Tree>::new(&label_configs)?;
        let configs = split_config(tree_c_config.clone(), tree_count)?;

        let tree_c_root = match layers {
            2 => {
                let tree_c = Self::generate_tree_c::<U2, Tree::Arity>(
                    layers,
                    nodes_count,
                    tree_count,
                    configs,
                    &labels,
                )?;
                tree_c.root()
            }
            8 => {
                let tree_c = Self::generate_tree_c::<U8, Tree::Arity>(
                    layers,
                    nodes_count,
                    tree_count,
                    configs,
                    &labels,
                )?;
                tree_c.root()
            }
            11 => {
                let tree_c = Self::generate_tree_c::<U11, Tree::Arity>(
                    layers,
                    nodes_count,
                    tree_count,
                    configs,
                    &labels,
                )?;
                tree_c.root()
            }
            _ => panic!("Unsupported column arity"),
        };
        info!("tree_c done");

        // Build the MerkleTree over the original data (if needed).
        let tree_d = match data_tree {
            Some(t) => {
                trace!("using existing original data merkle tree");
                assert_eq!(t.len(), 2 * (data.len() / NODE_SIZE) - 1);

                t
            }
            None => {
                trace!("building merkle tree for the original data");
                data.ensure_data()?;
                measure_op(CommD, || {
                    Self::build_binary_tree::<G>(data.as_ref(), tree_d_config.clone())
                })?
            }
        };
        tree_d_config.size = Some(tree_d.len());
        assert_eq!(tree_d_config.size.unwrap(), tree_d.len());
        let tree_d_root = tree_d.root();
        drop(tree_d);

        // Encode original data into the last layer.
        info!("building tree_r_last");
        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            replica_path,
            nodes_count,
            tree_count,
        )?;

        let tree_r_last = measure_op(GenerateTreeRLast, || {
            data.ensure_data()?;

            let last_layer_labels = labels.labels_for_last_layer()?;
            let size = Store::len(last_layer_labels);

            let mut trees = Vec::with_capacity(tree_count);
            let mut start = 0;
            let mut end = size / tree_count;

            for (i, config) in configs.iter().enumerate() {
                let encoded_data = last_layer_labels
                    .read_range(start..end)?
                    .into_par_iter()
                    .zip(
                        data.as_mut()[(start * NODE_SIZE)..(end * NODE_SIZE)]
                            .par_chunks_mut(NODE_SIZE),
                    )
                    .map(|(key, data_node_bytes)| {
                        let data_node =
                            <Tree::Hasher as Hasher>::Domain::try_from_bytes(data_node_bytes)
                                .unwrap();
                        let encoded_node =
                            encode::<<Tree::Hasher as Hasher>::Domain>(key, data_node);
                        data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));

                        encoded_node
                    });

                info!("building base tree_r_last {}/{}", i + 1, tree_count);
                trees.push(LCTree::<Tree::Hasher, Tree::Arity, typenum::U0, typenum::U0>::from_par_iter_with_config(encoded_data, config.clone())?);

                start = end;
                end += size / tree_count;
            }

            assert_eq!(tree_count, trees.len());

            create_lc_tree::<
                LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >(tree_r_last_config.size.unwrap(), &configs, &replica_config)
        })?;
        info!("tree_r_last done");

        let tree_r_last_root = tree_r_last.root();
        drop(tree_r_last);

        data.drop_data();

        // comm_r = H(comm_c || comm_r_last)
        let comm_r: <Tree::Hasher as Hasher>::Domain =
            <Tree::Hasher as Hasher>::Function::hash2(&tree_c_root, &tree_r_last_root);

        Ok((
            Tau {
                comm_d: tree_d_root,
                comm_r,
            },
            PersistentAux {
                comm_c: tree_c_root,
                comm_r_last: tree_r_last_root,
            },
            TemporaryAux {
                labels: label_configs,
                tree_d_config,
                tree_r_last_config,
                tree_c_config,
                _g: PhantomData,
            },
        ))
    }

    /// Phase1 of replication.
    pub fn replicate_phase1(
        pp: &'a PublicParams<Tree>,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        config: StoreConfig,
    ) -> Result<Labels<Tree>> {
        info!("replicate_phase1");

        let (_, labels) = measure_op(EncodeWindowTimeAll, || {
            Self::generate_labels(&pp.graph, &pp.layer_challenges, replica_id, config)
        })?;

        Ok(labels)
    }

    #[allow(clippy::type_complexity)]
    /// Phase2 of replication.
    #[allow(clippy::type_complexity)]
    pub fn replicate_phase2(
        pp: &'a PublicParams<Tree>,
        labels: Labels<Tree>,
        data: Data<'a>,
        data_tree: BinaryMerkleTree<G>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<(
        <Self as PoRep<'a, Tree::Hasher, G>>::Tau,
        <Self as PoRep<'a, Tree::Hasher, G>>::ProverAux,
    )> {
        info!("replicate_phase2");

        let (tau, paux, taux) = Self::transform_and_replicate_layers_inner(
            &pp.graph,
            &pp.layer_challenges,
            data,
            Some(data_tree),
            config,
            replica_path,
            labels,
        )?;

        Ok((tau, (paux, taux)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use paired::bls12_381::Fr;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        drgraph::{new_seed, BASE_DEGREE},
        fr32::fr_into_bytes,
        hasher::{Blake2sHasher, PedersenHasher, PoseidonHasher, Sha256Hasher},
        merkle::MerkleTreeTrait,
        proof::ProofScheme,
        table_tests,
        test_helper::setup_replica,
    };

    use crate::stacked::{PrivateInputs, SetupParams, EXP_DEGREE};
    use crate::PoRep;

    const DEFAULT_STACKED_LAYERS: usize = 11;

    #[test]
    fn test_calculate_fixed_challenges() {
        let layer_challenges = LayerChallenges::new(10, 333);
        let expected = 333;

        let calculated_count = layer_challenges.challenges_count_all();
        assert_eq!(expected as usize, calculated_count);
    }

    #[test]
    fn extract_all_pedersen_8() {
        test_extract_all::<DiskTree<PedersenHasher, typenum::U8, typenum::U0, typenum::U0>>();
    }

    #[test]
    fn extract_all_pedersen_8_2() {
        test_extract_all::<DiskTree<PedersenHasher, typenum::U8, typenum::U2, typenum::U0>>();
    }

    #[test]
    fn extract_all_pedersen_8_8_2() {
        test_extract_all::<DiskTree<PedersenHasher, typenum::U8, typenum::U8, typenum::U2>>();
    }

    #[test]
    fn extract_all_sha256_8() {
        test_extract_all::<DiskTree<Sha256Hasher, typenum::U8, typenum::U0, typenum::U0>>();
    }

    #[test]
    fn extract_all_sha256_8_8() {
        test_extract_all::<DiskTree<Sha256Hasher, typenum::U8, typenum::U8, typenum::U0>>();
    }

    #[test]
    fn extract_all_sha256_8_8_2() {
        test_extract_all::<DiskTree<Sha256Hasher, typenum::U8, typenum::U8, typenum::U2>>();
    }

    #[test]
    fn extract_all_blake2s_8() {
        test_extract_all::<DiskTree<Blake2sHasher, typenum::U8, typenum::U0, typenum::U0>>();
    }

    #[test]
    fn extract_all_blake2s_8_8() {
        test_extract_all::<DiskTree<Blake2sHasher, typenum::U8, typenum::U8, typenum::U0>>();
    }

    #[test]
    fn extract_all_blake2s_8_8_2() {
        test_extract_all::<DiskTree<Blake2sHasher, typenum::U8, typenum::U8, typenum::U2>>();
    }

    #[test]
    fn extract_all_poseidon_8() {
        test_extract_all::<DiskTree<PoseidonHasher, typenum::U8, typenum::U0, typenum::U0>>();
    }

    #[test]
    fn extract_all_poseidon_8_2() {
        test_extract_all::<DiskTree<PoseidonHasher, typenum::U8, typenum::U2, typenum::U0>>();
    }

    #[test]
    fn extract_all_poseidon_8_8_2() {
        test_extract_all::<DiskTree<PoseidonHasher, typenum::U8, typenum::U8, typenum::U2>>();
    }

    fn test_extract_all<Tree: 'static + MerkleTreeTrait>() {
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let replica_id: <Tree::Hasher as Hasher>::Domain =
            <Tree::Hasher as Hasher>::Domain::random(rng);
        let nodes = 64 * get_base_tree_count::<Tree>();

        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| {
                let v: <Tree::Hasher as Hasher>::Domain =
                    <Tree::Hasher as Hasher>::Domain::random(rng);
                v.into_bytes()
            })
            .collect();

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_rows_to_discard(nodes, BINARY_ARITY),
        );

        // Generate a replica path.
        let replica_path = cache_dir.path().join("replica-path");
        let mut mmapped_data = setup_replica(&data, &replica_path);

        let challenges = LayerChallenges::new(DEFAULT_STACKED_LAYERS, 5);

        let sp = SetupParams {
            nodes,
            degree: BASE_DEGREE,
            expansion_degree: EXP_DEGREE,
            seed: new_seed(),
            layer_challenges: challenges.clone(),
        };

        let pp = StackedDrg::<Tree, Blake2sHasher>::setup(&sp).expect("setup failed");

        StackedDrg::<Tree, Blake2sHasher>::replicate(
            &pp,
            &replica_id,
            (mmapped_data.as_mut()).into(),
            None,
            config.clone(),
            replica_path.clone(),
        )
        .expect("replication failed");

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data);
        assert_ne!(data, copied, "replication did not change data");

        let decoded_data = StackedDrg::<Tree, Blake2sHasher>::extract_all(
            &pp,
            &replica_id,
            mmapped_data.as_mut(),
            Some(config.clone()),
        )
        .expect("failed to extract data");

        assert_eq!(data, decoded_data);

        cache_dir.close().expect("Failed to remove cache dir");
    }

    fn prove_verify_fixed(n: usize) {
        let challenges = LayerChallenges::new(DEFAULT_STACKED_LAYERS, 5);

        test_prove_verify::<DiskTree<PedersenHasher, typenum::U4, typenum::U0, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<PedersenHasher, typenum::U4, typenum::U2, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<PedersenHasher, typenum::U4, typenum::U8, typenum::U2>>(
            n,
            challenges.clone(),
        );

        test_prove_verify::<DiskTree<PedersenHasher, typenum::U8, typenum::U0, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<PedersenHasher, typenum::U8, typenum::U2, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<PedersenHasher, typenum::U8, typenum::U8, typenum::U2>>(
            n,
            challenges.clone(),
        );

        test_prove_verify::<DiskTree<Sha256Hasher, typenum::U8, typenum::U0, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<Sha256Hasher, typenum::U8, typenum::U2, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<Sha256Hasher, typenum::U8, typenum::U8, typenum::U2>>(
            n,
            challenges.clone(),
        );

        test_prove_verify::<DiskTree<Sha256Hasher, typenum::U4, typenum::U0, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<Sha256Hasher, typenum::U4, typenum::U2, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<Sha256Hasher, typenum::U4, typenum::U8, typenum::U2>>(
            n,
            challenges.clone(),
        );

        test_prove_verify::<DiskTree<Blake2sHasher, typenum::U4, typenum::U0, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<Blake2sHasher, typenum::U4, typenum::U2, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<Blake2sHasher, typenum::U4, typenum::U8, typenum::U2>>(
            n,
            challenges.clone(),
        );

        test_prove_verify::<DiskTree<Blake2sHasher, typenum::U8, typenum::U0, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<Blake2sHasher, typenum::U8, typenum::U2, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<Blake2sHasher, typenum::U8, typenum::U8, typenum::U2>>(
            n,
            challenges.clone(),
        );

        test_prove_verify::<DiskTree<PoseidonHasher, typenum::U4, typenum::U0, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<PoseidonHasher, typenum::U4, typenum::U2, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<PoseidonHasher, typenum::U4, typenum::U8, typenum::U2>>(
            n,
            challenges.clone(),
        );

        test_prove_verify::<DiskTree<PoseidonHasher, typenum::U8, typenum::U0, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<PoseidonHasher, typenum::U8, typenum::U2, typenum::U0>>(
            n,
            challenges.clone(),
        );
        test_prove_verify::<DiskTree<PoseidonHasher, typenum::U8, typenum::U8, typenum::U2>>(
            n,
            challenges.clone(),
        );
    }

    fn test_prove_verify<Tree: 'static + MerkleTreeTrait>(n: usize, challenges: LayerChallenges) {
        // This will be called multiple times, only the first one succeeds, and that is ok.
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let nodes = n * get_base_tree_count::<Tree>();
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let replica_id: <Tree::Hasher as Hasher>::Domain =
            <Tree::Hasher as Hasher>::Domain::random(rng);
        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_rows_to_discard(nodes, BINARY_ARITY),
        );

        // Generate a replica path.
        let replica_path = cache_dir.path().join("replica-path");
        let mut mmapped_data = setup_replica(&data, &replica_path);

        let partitions = 2;

        let sp = SetupParams {
            nodes,
            degree,
            expansion_degree,
            seed: new_seed(),
            layer_challenges: challenges.clone(),
        };

        let pp = StackedDrg::<Tree, Blake2sHasher>::setup(&sp).expect("setup failed");
        let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, Blake2sHasher>::replicate(
            &pp,
            &replica_id,
            (mmapped_data.as_mut()).into(),
            None,
            config,
            replica_path.clone(),
        )
        .expect("replication failed");

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data);
        assert_ne!(data, copied, "replication did not change data");

        let seed = rng.gen();

        let pub_inputs =
            PublicInputs::<<Tree::Hasher as Hasher>::Domain, <Blake2sHasher as Hasher>::Domain> {
                replica_id,
                seed,
                tau: Some(tau),
                k: None,
            };

        // Store a copy of the t_aux for later resource deletion.
        let t_aux_orig = t_aux.clone();

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        let t_aux = TemporaryAuxCache::<Tree, Blake2sHasher>::new(&t_aux, replica_path)
            .expect("failed to restore contents of t_aux");

        let priv_inputs = PrivateInputs { p_aux, t_aux };

        let all_partition_proofs = &StackedDrg::<Tree, Blake2sHasher>::prove_all_partitions(
            &pp,
            &pub_inputs,
            &priv_inputs,
            partitions,
        )
        .expect("failed to generate partition proofs");

        let proofs_are_valid = StackedDrg::<Tree, Blake2sHasher>::verify_all_partitions(
            &pp,
            &pub_inputs,
            all_partition_proofs,
        )
        .expect("failed to verify partition proofs");

        // Discard cached MTs that are no longer needed.
        TemporaryAux::<Tree, Blake2sHasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

        assert!(proofs_are_valid);

        cache_dir.close().expect("Failed to remove cache dir");
    }

    table_tests! {
        prove_verify_fixed {
           prove_verify_fixed_64_64(64);
        }
    }

    #[test]
    // We are seeing a bug, in which setup never terminates for some sector sizes.
    // This test is to debug that and should remain as a regression teset.
    fn setup_terminates() {
        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let nodes = 1024 * 1024 * 32 * 8; // This corresponds to 8GiB sectors (32-byte nodes)
        let layer_challenges = LayerChallenges::new(10, 333);
        let sp = SetupParams {
            nodes,
            degree,
            expansion_degree,
            seed: new_seed(),
            layer_challenges: layer_challenges.clone(),
        };

        // When this fails, the call to setup should panic, but seems to actually hang (i.e. neither return nor panic) for some reason.
        // When working as designed, the call to setup returns without error.
        let _pp = StackedDrg::<
            DiskTree<PedersenHasher, typenum::U8, typenum::U0, typenum::U0>,
            Blake2sHasher,
        >::setup(&sp)
        .expect("setup failed");
    }
}
