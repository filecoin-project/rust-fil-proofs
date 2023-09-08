use std::any::TypeId;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::marker::PhantomData;
use std::panic::panic_any;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{ensure, Context};
use bincode::deserialize;
use blstrs::Scalar as Fr;
use fdlimit::raise_fd_limit;
use ff::PrimeField;
use filecoin_hashers::{poseidon::PoseidonHasher, Domain, HashFunction, Hasher, PoseidonArity};
use generic_array::typenum::{Unsigned, U0, U11, U2, U8};
use lazy_static::lazy_static;
use log::{error, info, trace, warn};
use merkletree::{
    merkle::{get_merkle_tree_len, is_merkle_tree_size_valid},
    store::{DiskStore, Store, StoreConfig},
};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, ParallelIterator, ParallelSliceMut,
};
use storage_proofs_core::{
    cache_key::CacheKey,
    data::Data,
    drgraph::Graph,
    error::Result,
    measurements::{measure_op, Operation},
    merkle::{
        create_disk_tree, create_lc_tree, get_base_tree_count, split_config,
        split_config_and_replica, BinaryMerkleTree, DiskTree, LCTree, MerkleProofTrait,
        MerkleTreeTrait,
    },
    settings::SETTINGS,
    util::{default_rows_to_discard, NODE_SIZE},
};
use yastl::Pool;

use crate::{
    encode::{decode, encode, encode_fr},
    stacked::vanilla::{
        challenges::LayerChallenges,
        column::Column,
        create_label,
        graph::StackedBucketGraph,
        hash::hash_single_column,
        params::{
            get_node, Labels, LabelsCache, PersistentAux, Proof, PublicInputs, PublicParams,
            ReplicaColumnProof, SynthProofs, Tau, TemporaryAux, TemporaryAuxCache,
            TransformedLayers, BINARY_ARITY,
        },
        EncodingProof, LabelingProof,
    },
    PoRep,
};

pub const TOTAL_PARENTS: usize = 37;

lazy_static! {
    /// Ensure that only one `TreeBuilder` or `ColumnTreeBuilder` uses the GPU at a time.
    /// Curently, this is accomplished by only instantiating at most one at a time.
    /// It might be possible to relax this constraint, but in that case, only one builder
    /// should actually be active at any given time, so the mutex should still be used.
    static ref GPU_LOCK: Mutex<()> = Mutex::new(());

    static ref THREAD_POOL: Pool = Pool::new(num_cpus::get());
}

#[derive(Debug)]
pub struct StackedDrg<'a, Tree: MerkleTreeTrait, G: Hasher> {
    _a: PhantomData<&'a Tree>,
    _b: PhantomData<&'a G>,
}

#[derive(Debug)]
pub struct LayerState {
    pub config: StoreConfig,
    pub generated: bool,
}

pub enum TreeRElementData<Tree: MerkleTreeTrait> {
    FrList(Vec<Fr>),
    ElementList(Vec<<Tree::Hasher as Hasher>::Domain>),
}

#[allow(type_alias_bounds)]
pub type PrepareTreeRDataCallback<Tree: 'static + MerkleTreeTrait> =
    fn(
        source: &DiskStore<<Tree::Hasher as Hasher>::Domain>,
        data: Option<&mut Data<'_>>,
        start: usize,
        end: usize,
    ) -> Result<TreeRElementData<Tree>>;

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> StackedDrg<'a, Tree, G> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_layers(
        graph: &StackedBucketGraph<Tree::Hasher>,
        pub_inputs: &PublicInputs<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>,
        p_aux: &PersistentAux<<Tree::Hasher as Hasher>::Domain>,
        t_aux: &TemporaryAuxCache<Tree, G>,
        layer_challenges: &LayerChallenges,
        layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Vec<Proof<Tree, G>>>> {
        assert!(layers > 0);

        if !layer_challenges.use_synthetic {
            // This needs to be relaxed now since the layers may not exist in the synth porep case
            assert_eq!(t_aux.labels.len(), layers);
        }

        let graph_size = graph.size();

        // Sanity checks on restored trees.
        assert!(pub_inputs.tau.is_some());
        // Skip this check in the case of synthetic porep
        if t_aux.tree_d.is_some() {
            assert_eq!(
                pub_inputs.tau.as_ref().expect("as_ref failure").comm_d,
                t_aux.tree_d.as_ref().expect("failed to get tree_d").root()
            );
        }

        // If synthetic vanilla proofs are stored on disk, read and return the proofs corresponding
        // to the porep challlenge set.
        let read_synth_proofs = layer_challenges.use_synthetic && pub_inputs.seed.is_some();
        if read_synth_proofs {
            let read_res = Self::read_porep_proofs_from_synth(
                graph_size,
                pub_inputs,
                layer_challenges,
                t_aux,
                partition_count,
            );
            if read_res.is_ok() {
                return read_res;
            }
            info!(
                "failed to read porep proofs from synthetic proofs file: {:?}",
                t_aux.synth_proofs_path(),
            );

            // If the synthetic proofs file does not exist and we have the layers available,
            // we can generate non-synthetic proofs
            if t_aux.labels.len() == layers {
                info!("skipping synthetic proving; generating non-synthetic vanilla proofs");
            } else {
                error!("synthetic proving failure; synthetic proofs and layers are unavailable");

                return read_res;
            }
        }

        // If generating vanilla proofs for the synthetic challenge set, generate those proofs in a
        // single partition (otherwise we must ensure tha the synthetic challenge count is divisible
        // by the porep partition count).
        let gen_synth_proofs = layer_challenges.use_synthetic && pub_inputs.seed.is_none();
        if gen_synth_proofs {
            info!("generating synthetic vanilla proofs in a single partition");
        }

        info!(
            "read_synth_porep: {}, gen_synth_porep {}",
            read_synth_proofs, gen_synth_proofs
        );
        let get_drg_parents_columns = |x: usize| -> Result<Vec<Column<Tree::Hasher>>> {
            let base_degree = graph.base_graph().degree();

            let mut columns = Vec::with_capacity(base_degree);

            let mut parents = vec![0; base_degree];
            graph.base_parents(x, &mut parents)?;

            columns.extend(
                parents
                    .into_par_iter()
                    .map(|parent| t_aux.column(parent))
                    .collect::<Result<Vec<Column<Tree::Hasher>>>>()?,
            );

            debug_assert!(columns.len() == base_degree);

            Ok(columns)
        };

        let get_exp_parents_columns = |x: usize| -> Result<Vec<Column<Tree::Hasher>>> {
            let mut parents = vec![0; graph.expansion_degree()];
            graph.expanded_parents(x, &mut parents)?;

            parents
                .into_par_iter()
                .map(|parent| t_aux.column(parent))
                .collect()
        };

        let vanilla_proofs = (0..partition_count)
            .map(|k| {
                trace!("proving partition {}/{}", k + 1, partition_count);

                // Derive the set of challenges we are proving over.
                let challenges = pub_inputs.challenges(layer_challenges, graph_size, Some(k));

                THREAD_POOL.scoped(|scope| {
                    // Stacked commitment specifics
                    challenges
                        .into_par_iter()
                        .enumerate()
                        .map(|(challenge_index, challenge)| {
                            trace!(" challenge {} ({})", challenge, challenge_index);
                            assert!(challenge < graph.size(), "Invalid challenge");
                            assert!(challenge > 0, "Invalid challenge");

                            let comm_d_proof = t_aux
                                .tree_d
                                .as_ref()
                                .expect("failed to get tree_d")
                                .gen_proof(challenge)?;

                            let comm_d_proof_inner = comm_d_proof.clone();
                            let challenge_inner = challenge;
                            scope.execute(move || {
                                assert!(comm_d_proof_inner.validate(challenge_inner));
                            });

                            // Stacked replica column openings
                            let rcp = {
                                let (c_x, drg_parents, exp_parents) = {
                                    assert!(t_aux.tree_c.is_some());
                                    let tree_c =
                                        t_aux.tree_c.as_ref().expect("failed to get tree_c");
                                    assert_eq!(p_aux.comm_c, tree_c.root());

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

                            let comm_r_last_proof_inner = comm_r_last_proof.clone();
                            scope.execute(move || {
                                debug_assert!(comm_r_last_proof_inner.validate(challenge));
                            });

                            // Labeling Proofs Layer 1..l
                            let mut labeling_proofs = Vec::with_capacity(layers);
                            let mut encoding_proof = None;

                            for layer in 1..=layers {
                                trace!("  encoding proof layer {}", layer,);
                                let parents_data: Vec<<Tree::Hasher as Hasher>::Domain> =
                                    if layer == 1 {
                                        let mut parents = vec![0; graph.base_graph().degree()];
                                        graph.base_parents(challenge, &mut parents)?;

                                        parents
                                            .into_par_iter()
                                            .map(|parent| t_aux.domain_node_at_layer(layer, parent))
                                            .collect::<Result<_>>()?
                                    } else {
                                        let mut parents = vec![0; graph.degree()];
                                        graph.parents(challenge, &mut parents)?;
                                        let base_parents_count = graph.base_graph().degree();

                                        parents
                                            .into_par_iter()
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
                                    layer as u32,
                                    challenge as u64,
                                    parents_data_full.clone(),
                                );

                                {
                                    let labeled_node = *rcp.c_x.get_node_at_layer(layer)?;
                                    let replica_id = &pub_inputs.replica_id;
                                    let proof_inner = proof.clone();
                                    scope.execute(move || {
                                        assert!(
                                            proof_inner.verify(replica_id, &labeled_node),
                                            "Invalid encoding proof generated at layer {}",
                                            layer,
                                        );
                                        trace!("Valid encoding proof generated at layer {}", layer);
                                    });
                                }

                                labeling_proofs.push(proof);

                                if layer == layers {
                                    encoding_proof = Some(EncodingProof::new(
                                        layer as u32,
                                        challenge as u64,
                                        parents_data_full,
                                    ));
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
            })
            .collect::<Result<Vec<Vec<Proof<Tree, G>>>>>()?;

        // If synthetic vanilla proofs were generated, persist them here.
        if gen_synth_proofs {
            assert!(
                vanilla_proofs.iter().skip(1).all(Vec::is_empty),
                "synthetic proofs should be generated in a single partition",
            );
            let synth_proofs = &vanilla_proofs[0];
            Self::write_synth_proofs(synth_proofs, pub_inputs, graph, layer_challenges, t_aux)?;
            return Ok(vec![vec![]; partition_count]);
        }

        Ok(vanilla_proofs)
    }

    fn write_synth_proofs(
        synth_proofs: &[Proof<Tree, G>],
        pub_inputs: &PublicInputs<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>,
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        t_aux: &TemporaryAuxCache<Tree, G>,
    ) -> Result<()> {
        use crate::stacked::vanilla::SynthChallenges;

        ensure!(
            pub_inputs.tau.is_some(),
            "comm_r must be set prior to generating synthetic challenges",
        );

        THREAD_POOL.scoped(|scope| {
            // Verify synth proofs prior to writing because `ProofScheme`'s verification API is not
            // amenable to prover-only verification (i.e. the API uses public values, whereas synthetic
            // proofs are known only to the prover).
            let pub_params = PublicParams::<Tree>::new(graph.clone(), layer_challenges.clone());
            let replica_id: Fr = pub_inputs.replica_id.into();
            let comm_r: Fr = pub_inputs
                .tau
                .as_ref()
                .map(|tau| tau.comm_r.into())
                .expect("unwrapping should not fail");
            let synth_challenges = SynthChallenges::default(graph.size(), &replica_id, &comm_r);
            assert_eq!(synth_proofs.len(), synth_challenges.num_synth_challenges);
            for (challenge, proof) in synth_challenges.zip(synth_proofs) {
                let proof_inner = proof.clone();
                let challenge_inner = challenge;
                let pub_params_inner = pub_params.clone();
                let pub_inputs_inner = pub_inputs.clone();
                scope.execute(move || {
                    assert!(proof_inner.verify(
                        &pub_params_inner,
                        &pub_inputs_inner,
                        challenge_inner,
                        graph
                    ));
                });
            }
        });

        let path = t_aux.synth_proofs_path();
        info!("writing synth-porep vanilla proofs to file: {:?}", path);
        let file = File::create(&path).map(BufWriter::new).with_context(|| {
            format!(
                "failed to create synth-porep vanilla proofs file: {:?}",
                path,
            )
        })?;
        SynthProofs::write(file, synth_proofs).with_context(|| {
            format!(
                "failed to write synth-porep vanilla proofs to file: {:?}",
                path,
            )
        })?;
        info!(
            "successfully stored synth-porep vanilla proofs to file: {:?}",
            path,
        );
        Ok(())
    }

    fn read_porep_proofs_from_synth(
        sector_nodes: usize,
        pub_inputs: &PublicInputs<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>,
        layer_challenges: &LayerChallenges,
        t_aux: &TemporaryAuxCache<Tree, G>,
        partition_count: usize,
    ) -> Result<Vec<Vec<Proof<Tree, G>>>> {
        ensure!(
            pub_inputs.seed.is_some(),
            "porep challenge seed must be set prior to reading porep proofs from synthetic",
        );
        ensure!(
            pub_inputs.tau.is_some(),
            "comm_r must be set prior to generating synthetic porep challenges",
        );

        let seed = pub_inputs
            .seed
            .as_ref()
            .expect("unwrapping should not fail");
        let comm_r = pub_inputs
            .tau
            .as_ref()
            .map(|tau| &tau.comm_r)
            .expect("unwrapping should not fail");
        let path = t_aux.synth_proofs_path();
        info!("reading synthetic vanilla proofs from file: {:?}", path);

        let num_layers = layer_challenges.layers();

        let mut file = File::open(&path)
            .map(BufReader::new)
            .with_context(|| format!("failed to open synthetic vanilla proofs file: {:?}", path))?;

        let porep_proofs = (0..partition_count as u8)
            .map(|k| {
                let synth_indexes = layer_challenges.derive_synth_indexes(
                    sector_nodes,
                    &pub_inputs.replica_id,
                    comm_r,
                    seed,
                    k,
                );

                SynthProofs::read(
                    &mut file,
                    sector_nodes,
                    num_layers,
                    synth_indexes.into_iter(),
                )
                .with_context(|| {
                    format!(
                        "failed to read partition k={} synthetic proofs from file: {:?}",
                        k, path,
                    )
                })
            })
            .collect::<Result<Vec<Vec<Proof<Tree, G>>>>>()?;

        info!("successfully read porep vanilla proofs from synthetic file");
        Ok(porep_proofs)
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

        let labels =
            Self::generate_labels_for_decoding(graph, layer_challenges, replica_id, config)?;

        let last_layer_labels = labels.labels_for_last_layer()?;
        let size = Store::len(last_layer_labels);

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

    /// Generates the layers as needed for encoding.
    pub fn generate_labels_for_encoding<P>(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        cache_path: P,
    ) -> Result<(Labels<Tree>, Vec<LayerState>)>
    where
        P: AsRef<Path>,
    {
        let mut parent_cache = graph.parent_cache()?;

        #[cfg(feature = "multicore-sdr")]
        {
            if SETTINGS.use_multicore_sdr {
                info!("multi core replication");
                create_label::multi::create_labels_for_encoding(
                    graph,
                    &parent_cache,
                    layer_challenges.layers(),
                    replica_id,
                    &cache_path,
                )
            } else {
                info!("single core replication");
                create_label::single::create_labels_for_encoding(
                    graph,
                    &mut parent_cache,
                    layer_challenges.layers(),
                    replica_id,
                    &cache_path,
                )
            }
        }

        #[cfg(not(feature = "multicore-sdr"))]
        {
            info!("single core replication");
            create_label::single::create_labels_for_encoding(
                graph,
                &mut parent_cache,
                layer_challenges.layers(),
                replica_id,
                &cache_path,
            )
        }
    }

    /// Generates the layers, as needed for decoding.
    pub fn generate_labels_for_decoding(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        config: StoreConfig,
    ) -> Result<LabelsCache<Tree>> {
        let mut parent_cache = graph.parent_cache()?;

        #[cfg(feature = "multicore-sdr")]
        {
            if SETTINGS.use_multicore_sdr {
                info!("multi core replication");
                create_label::multi::create_labels_for_decoding(
                    graph,
                    &parent_cache,
                    layer_challenges.layers(),
                    replica_id,
                    config,
                )
            } else {
                info!("single core replication");
                create_label::single::create_labels_for_decoding(
                    graph,
                    &mut parent_cache,
                    layer_challenges.layers(),
                    replica_id,
                    config,
                )
            }
        }

        #[cfg(not(feature = "multicore-sdr"))]
        {
            info!("single core replication");
            create_label::single::create_labels_for_decoding(
                graph,
                &mut parent_cache,
                layer_challenges.layers(),
                replica_id,
                config,
            )
        }
    }

    // NOTE: Unlike
    // storage_proofs_core::merkle::create_base_merkle_tree, this
    // method requires the data on disk to be exactly the same size as
    // the tree length / NODE_SIZE.
    pub fn build_binary_tree<K: Hasher>(
        tree_data: &[u8],
        config: StoreConfig,
    ) -> Result<BinaryMerkleTree<K>> {
        trace!("building tree (size: {})", tree_data.len());

        let leafs = tree_data.len() / NODE_SIZE;
        assert_eq!(tree_data.len() % NODE_SIZE, 0);

        let tree = BinaryMerkleTree::from_par_iter_with_config(
            (0..leafs)
                .into_par_iter()
                // TODO: proper error handling instead of `unwrap()`
                .map(|i| get_node::<K>(tree_data, i).expect("get_node failure")),
            config,
        )?;
        Ok(tree)
    }

    // Even if the column builder is enabled, the GPU column builder
    // only supports Poseidon hashes.
    pub fn use_gpu_column_builder() -> bool {
        SETTINGS.use_gpu_column_builder
            && TypeId::of::<Tree::Hasher>() == TypeId::of::<PoseidonHasher>()
    }

    // Even if the tree builder is enabled, the GPU tree builder
    // only supports Poseidon hashes.
    pub fn use_gpu_tree_builder() -> bool {
        SETTINGS.use_gpu_tree_builder
            && TypeId::of::<Tree::Hasher>() == TypeId::of::<PoseidonHasher>()
    }

    #[cfg(any(feature = "cuda", feature = "opencl"))]
    pub fn generate_tree_c<ColumnArity, TreeArity>(
        nodes_count: usize,
        tree_count: usize,
        configs: Vec<StoreConfig>,
        labels: &LabelsCache<Tree>,
    ) -> Result<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        ColumnArity: 'static + PoseidonArity,
        TreeArity: PoseidonArity,
    {
        if Self::use_gpu_column_builder() {
            Self::generate_tree_c_gpu::<ColumnArity, TreeArity>(
                nodes_count,
                tree_count,
                configs,
                labels,
            )
        } else {
            Self::generate_tree_c_cpu::<ColumnArity, TreeArity>(
                nodes_count,
                tree_count,
                configs,
                labels,
            )
        }
    }

    #[cfg(not(any(feature = "cuda", feature = "opencl")))]
    pub fn generate_tree_c<ColumnArity, TreeArity>(
        nodes_count: usize,
        tree_count: usize,
        configs: Vec<StoreConfig>,
        labels: &LabelsCache<Tree>,
    ) -> Result<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        ColumnArity: 'static + PoseidonArity,
        TreeArity: PoseidonArity,
    {
        Self::generate_tree_c_cpu::<ColumnArity, TreeArity>(
            nodes_count,
            tree_count,
            configs,
            labels,
        )
    }

    #[allow(clippy::needless_range_loop)]
    #[cfg(any(feature = "cuda", feature = "opencl"))]
    fn generate_tree_c_gpu<ColumnArity, TreeArity>(
        nodes_count: usize,
        tree_count: usize,
        configs: Vec<StoreConfig>,
        labels: &LabelsCache<Tree>,
    ) -> Result<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        ColumnArity: 'static + PoseidonArity,
        TreeArity: PoseidonArity,
    {
        use std::cmp::min;
        use std::sync::mpsc::sync_channel as channel;

        use fr32::fr_into_bytes;
        use generic_array::GenericArray;
        use neptune::{
            batch_hasher::Batcher,
            column_tree_builder::{ColumnTreeBuilder, ColumnTreeBuilderTrait},
        };

        info!("generating tree c using the GPU");
        // Build the tree for CommC
        measure_op(Operation::GenerateTreeC, || {
            info!("Building column hashes");

            // NOTE: The max number of columns we recommend sending to the GPU at once is
            // 400000 for columns and 700000 for trees (conservative soft-limits discussed).
            //
            // 'column_write_batch_size' is how many nodes to chunk the base layer of data
            // into when persisting to disk.
            //
            // Override these values with care using environment variables:
            // FIL_PROOFS_MAX_GPU_COLUMN_BATCH_SIZE, FIL_PROOFS_MAX_GPU_TREE_BATCH_SIZE, and
            // FIL_PROOFS_COLUMN_WRITE_BATCH_SIZE respectively.
            let max_gpu_column_batch_size = SETTINGS.max_gpu_column_batch_size as usize;
            let max_gpu_tree_batch_size = SETTINGS.max_gpu_tree_batch_size as usize;
            let column_write_batch_size = SETTINGS.column_write_batch_size as usize;

            // This channel will receive batches of columns and add them to the ColumnTreeBuilder.
            let (builder_tx, builder_rx) = channel(0);

            let config_count = configs.len(); // Don't move config into closure below.
            THREAD_POOL.scoped(|s| {
                // This channel will receive the finished tree data to be written to disk.
                let (writer_tx, writer_rx) = channel::<(Vec<Fr>, Vec<Fr>)>(0);

                s.execute(move || {
                    for i in 0..config_count {
                        let mut node_index = 0;
                        let builder_tx = builder_tx.clone();
                        while node_index != nodes_count {
                            let chunked_nodes_count =
                                min(nodes_count - node_index, max_gpu_column_batch_size);
                            trace!(
                                "processing config {}/{} with column nodes {}",
                                i + 1,
                                tree_count,
                                chunked_nodes_count,
                            );

                            let columns: Vec<GenericArray<Fr, ColumnArity>> = {
                                use fr32::bytes_into_fr;

                                // Allocate layer data array and insert a placeholder for each layer.
                                let mut layer_data: Vec<Vec<u8>> =
                                    vec![
                                        vec![0u8; chunked_nodes_count * std::mem::size_of::<Fr>()];
                                        ColumnArity::to_usize()
                                    ];

                                // gather all layer data.
                                for (layer_index, layer_bytes) in
                                    layer_data.iter_mut().enumerate()
                                {
                                    let store = labels.labels_for_layer(layer_index + 1);
                                    let start = (i * nodes_count) + node_index;
                                    let end = start + chunked_nodes_count;

                                    store
                                        .read_range_into(start, end, layer_bytes)
                                        .expect("failed to read store range");
                                }

                                (0..chunked_nodes_count)
                                    .into_par_iter()
                                    .map(|index| {
                                        (0..ColumnArity::to_usize())
                                            .map(|layer_index| {
                                                bytes_into_fr(
                                                &layer_data[layer_index][std::mem::size_of::<Fr>()
                                                    * index
                                                    ..std::mem::size_of::<Fr>() * (index + 1)],
                                            )
                                            .expect("Could not create Fr from bytes.")
                                            })
                                            .collect::<GenericArray<Fr, ColumnArity>>()
                                    })
                                    .collect()
                            };

                            node_index += chunked_nodes_count;
                            trace!(
                                "node index {}/{}/{}",
                                node_index,
                                chunked_nodes_count,
                                nodes_count,
                            );

                            let is_final = node_index == nodes_count;
                            builder_tx
                                .send((columns, is_final))
                                .expect("failed to send columns");
                        }
                    }
                });
                s.execute(move || {
                    let _gpu_lock = GPU_LOCK.lock().expect("failed to get gpu lock");
                    let tree_batcher = match Batcher::pick_gpu(max_gpu_tree_batch_size) {
                        Ok(b) => Some(b),
                        Err(err) => {
                            warn!("no GPU found, falling back to CPU tree builder: {}", err);
                            None
                        }
                    };
                    let column_batcher = match Batcher::pick_gpu(max_gpu_column_batch_size) {
                        Ok(b) => Some(b),
                        Err(err) => {
                            warn!("no GPU found, falling back to CPU tree builder: {}", err);
                            None
                        }
                    };
                    let mut column_tree_builder = ColumnTreeBuilder::<Fr, ColumnArity, TreeArity>::new(
                        column_batcher,
                        tree_batcher,
                        nodes_count,
                    )
                    .expect("failed to create ColumnTreeBuilder");

                    // Loop until all trees for all configs have been built.
                    for i in 0..config_count {
                        loop {
                            let (columns, is_final): (Vec<GenericArray<Fr, ColumnArity>>, bool) =
                                builder_rx.recv().expect("failed to recv columns");

                            // Just add non-final column batches.
                            if !is_final {
                                column_tree_builder
                                    .add_columns(&columns)
                                    .expect("failed to add columns");
                                continue;
                            };

                            // If we get here, this is a final column: build a sub-tree.
                            let (base_data, tree_data) = column_tree_builder
                                .add_final_columns(&columns)
                                .expect("failed to add final columns");
                            trace!(
                                "base data len {}, tree data len {}",
                                base_data.len(),
                                tree_data.len()
                            );

                            let tree_len = base_data.len() + tree_data.len();
                            info!(
                                "persisting base tree_c {}/{} of length {}",
                                i + 1,
                                tree_count,
                                tree_len,
                            );

                            writer_tx
                                .send((base_data, tree_data))
                                .expect("failed to send base_data, tree_data");
                            break;
                        }
                    }
                });

                for config in &configs {
                    let (base_data, tree_data) = writer_rx
                        .recv()
                        .expect("failed to receive base_data, tree_data for tree_c");
                    let tree_len = base_data.len() + tree_data.len();

                    assert_eq!(base_data.len(), nodes_count);
                    assert_eq!(tree_len, config.size.expect("config size failure"));

                    // Persist the base and tree data to disk based using the current store config.
                    let tree_c_store_path = StoreConfig::data_path(&config.path, &config.id);
                    let tree_c_store_exists = Path::new(&tree_c_store_path).exists();
                    trace!(
                        "tree_c store path {:?} -- exists? {}",
                        tree_c_store_path,
                        tree_c_store_exists
                    );
                    if tree_c_store_exists {
                        std::fs::remove_file(&tree_c_store_path)
                            .expect("failed to remove tree_c_store_path");
                    }

                    let tree_c_store =
                        DiskStore::<<Tree::Hasher as Hasher>::Domain>::new_with_config(
                            tree_len,
                            Tree::Arity::to_usize(),
                            config.clone(),
                        )
                        .expect("failed to create DiskStore for base tree data");

                    let store = Arc::new(RwLock::new(tree_c_store));
                    let batch_size = min(base_data.len(), column_write_batch_size);
                    let flatten_and_write_store = |data: &Vec<Fr>, offset| {
                        data.into_par_iter()
                            .chunks(batch_size)
                            .enumerate()
                            .try_for_each(|(index, fr_elements)| {
                                let mut buf = Vec::with_capacity(batch_size * NODE_SIZE);

                                for fr in fr_elements {
                                    buf.extend(fr_into_bytes(fr));
                                }
                                store
                                    .write()
                                    .expect("failed to access store for write")
                                    .copy_from_slice(&buf[..], offset + (batch_size * index))
                            })
                    };

                    trace!(
                        "flattening tree_c base data of {} nodes using batch size {}",
                        base_data.len(),
                        batch_size
                    );
                    flatten_and_write_store(&base_data, 0)
                        .expect("failed to flatten and write store");
                    trace!("done flattening tree_c base data");

                    let base_offset = base_data.len();
                    trace!("flattening tree_c tree data of {} nodes using batch size {} and base offset {}", tree_data.len(), batch_size, base_offset);
                    flatten_and_write_store(&tree_data, base_offset)
                        .expect("failed to flatten and write store");
                    trace!("done flattening tree_c tree data");

                    trace!("writing tree_c store data");
                    store
                        .write()
                        .expect("failed to access store for sync")
                        .sync()
                        .expect("store sync failure");
                    trace!("done writing tree_c store data");
                }
            });

            create_disk_tree::<
                DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >(configs[0].size.expect("config size failure"), &configs)
        })
    }

    fn generate_tree_c_cpu<ColumnArity, TreeArity>(
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
        measure_op(Operation::GenerateTreeC, || {
            info!("Building column hashes");

            let mut trees = Vec::with_capacity(tree_count);
            for (i, config) in configs.iter().enumerate() {
                let mut hashes: Vec<<Tree::Hasher as Hasher>::Domain> =
                    vec![<Tree::Hasher as Hasher>::Domain::default(); nodes_count];

                THREAD_POOL.scoped(|s| {
                    let n = num_cpus::get();

                    // only split if we have at least two elements per thread
                    let num_chunks = if n > nodes_count * 2 { 1 } else { n };

                    // chunk into n chunks
                    let chunk_size = (nodes_count as f64 / num_chunks as f64).ceil() as usize;

                    // calculate all n chunks in parallel
                    for (chunk, hashes_chunk) in hashes.chunks_mut(chunk_size).enumerate() {
                        let labels = &labels;

                        s.execute(move || {
                            for (j, hash) in hashes_chunk.iter_mut().enumerate() {
                                let data: Vec<_> = (1..=ColumnArity::to_usize())
                                    .map(|layer| {
                                        let store = labels.labels_for_layer(layer);
                                        let el: <Tree::Hasher as Hasher>::Domain = store
                                            .read_at((i * nodes_count) + j + chunk * chunk_size)
                                            .expect("store read_at failure");
                                        el.into()
                                    })
                                    .collect();

                                *hash = hash_single_column(&data).into();
                            }
                        });
                    }
                });

                info!("building base tree_c {}/{}", i + 1, tree_count);
                trees.push(
                    DiskTree::<Tree::Hasher, Tree::Arity, U0, U0>::from_par_iter_with_config(
                        hashes.into_par_iter(),
                        config.clone(),
                    ),
                );
            }

            assert_eq!(tree_count, trees.len());

            create_disk_tree::<
                DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >(configs[0].size.expect("config size failure"), &configs)
        })
    }

    fn prepare_tree_r_data_cpu(
        source: &DiskStore<<Tree::Hasher as Hasher>::Domain>,
        data: Option<&mut Data<'_>>,
        start: usize,
        end: usize,
    ) -> Result<TreeRElementData<Tree>> {
        let encoded_data: Vec<<Tree::Hasher as Hasher>::Domain> = source
            .read_range(start..end)?
            .into_par_iter()
            .zip(
                data.expect("failed to unwrap data").as_mut()
                    [(start * NODE_SIZE)..(end * NODE_SIZE)]
                    .par_chunks_mut(NODE_SIZE),
            )
            .map(|(key, data_node_bytes)| {
                let data_node = <Tree::Hasher as Hasher>::Domain::try_from_bytes(data_node_bytes)
                    .expect("try from bytes failed");

                let key_elem = <Tree::Hasher as Hasher>::Domain::try_from_bytes(&key.into_bytes())
                    .expect("failed to convert key");
                let encoded_node = encode::<<Tree::Hasher as Hasher>::Domain>(key_elem, data_node);
                data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));

                encoded_node
            })
            .collect();

        Ok(TreeRElementData::ElementList(encoded_data))
    }

    #[cfg(any(feature = "cuda", feature = "opencl"))]
    fn prepare_tree_r_data(
        source: &DiskStore<<Tree::Hasher as Hasher>::Domain>,
        data: Option<&mut Data<'_>>,
        start: usize,
        end: usize,
    ) -> Result<TreeRElementData<Tree>> {
        if Self::use_gpu_tree_builder() {
            use fr32::bytes_into_fr;

            let mut layer_bytes = vec![0u8; (end - start) * std::mem::size_of::<Fr>()];
            source
                .read_range_into(start, end, &mut layer_bytes)
                .expect("failed to read layer bytes");

            let encoded_data: Vec<_> = layer_bytes
                .into_par_iter()
                .chunks(std::mem::size_of::<Fr>())
                .map(|chunk| bytes_into_fr(&chunk).expect("Could not create Fr from bytes."))
                .zip(
                    data.expect("failed to unwrap data").as_mut()
                        [(start * NODE_SIZE)..(end * NODE_SIZE)]
                        .par_chunks_mut(NODE_SIZE),
                )
                .map(|(key, data_node_bytes)| {
                    let data_node =
                        <Tree::Hasher as Hasher>::Domain::try_from_bytes(data_node_bytes)
                            .expect("try_from_bytes failed");

                    let mut encoded_fr: Fr = key;
                    let data_node_fr: Fr = data_node.into();
                    encode_fr(&mut encoded_fr, data_node_fr);
                    let encoded_fr_repr = encoded_fr.to_repr();
                    data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_fr_repr));

                    encoded_fr
                })
                .collect();

            Ok(TreeRElementData::FrList(encoded_data))
        } else {
            Self::prepare_tree_r_data_cpu(source, data, start, end)
        }
    }

    #[cfg(not(any(feature = "cuda", feature = "opencl")))]
    fn prepare_tree_r_data(
        source: &DiskStore<<Tree::Hasher as Hasher>::Domain>,
        data: Option<&mut Data<'_>>,
        start: usize,
        end: usize,
    ) -> Result<TreeRElementData<Tree>> {
        Self::prepare_tree_r_data_cpu(source, data, start, end)
    }

    /// Generate the TreeRLast.
    ///
    /// `nodes_count` is the number of nodes per sector, practically is the sector size in bytes
    /// divided by the 32 bytes node size.
    ///
    /// TreeRLast is split into several sub-trees. The exact number `tree_count` depends on the
    /// sector size.
    ///
    /// The `tree_r_last_config` specifies where those sub-trees are stored and what their
    /// filenames are.
    ///
    /// This tree is built during the PoRep during the PreCommit2 phase as well as during the empty
    /// sector update (aka SnapDeals). The input parameters are used differently in both cases,
    /// therefore the next section distinguishes between those for the other parameter
    /// descriptions.
    ///
    /// # PoRep TreeRLast
    ///
    /// When calling this function to produce the PoRep TreeRLast, several things beside the actual
    /// tree building are happening. When calling this function, `data` points to the unsealed
    /// data, which is then modified in-place during the execution. This means, that it's a copy
    /// of the unsealed data at the location where the final replica will be stored. That location
    /// is the same as the `replica_path`.
    ///
    /// That modification during the execution of the function is the replica encoding step. The
    /// data for the sector key is provided by the `source`, which is the last layer of the SDR
    /// process.
    ///
    /// The `callback` is `None`, this way the default callback is used, which does the encoding
    /// step described above. In case of the GPU code path, it also transforms the field elements
    /// into the representation needed for the GPU based tree building.
    ///
    /// # Empty sector update TreeRLast
    ///
    /// When calling this function to produce the empty sector update TreeRLast, no data is
    /// manipulated in place. This means that the `data` parameter isn't really used, hence it's
    /// initialized with [`Data::empty`]. The `replica_path` points to the already encoded replica
    /// file. The `source` points to the same replica file.
    ///
    /// A custom `callback` is passed in. In case of the GPU code path, that callback does only
    /// the on-the-fly transformation of the field elements for the GPU code path, it doesn't do
    /// any further transformations.
    #[cfg(any(feature = "cuda", feature = "opencl"))]
    pub fn generate_tree_r_last(
        data: &mut Data<'_>,
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
        source: &DiskStore<<Tree::Hasher as Hasher>::Domain>,
        callback: Option<PrepareTreeRDataCallback<Tree>>,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>> {
        let encode_data = match callback {
            Some(x) => x,
            None => Self::prepare_tree_r_data,
        };

        if Self::use_gpu_tree_builder() {
            Self::generate_tree_r_last_gpu(
                data,
                nodes_count,
                tree_count,
                tree_r_last_config,
                replica_path,
                source,
                encode_data,
            )
        } else {
            Self::generate_tree_r_last_cpu(
                data,
                nodes_count,
                tree_count,
                tree_r_last_config,
                replica_path,
                source,
                encode_data,
            )
        }
    }

    #[cfg(not(any(feature = "cuda", feature = "opencl")))]
    pub fn generate_tree_r_last(
        data: &mut Data<'_>,
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
        source: &DiskStore<<Tree::Hasher as Hasher>::Domain>,
        callback: Option<PrepareTreeRDataCallback<Tree>>,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>> {
        let encode_data = match callback {
            Some(x) => x,
            None => Self::prepare_tree_r_data,
        };

        Self::generate_tree_r_last_cpu(
            data,
            nodes_count,
            tree_count,
            tree_r_last_config,
            replica_path,
            source,
            encode_data,
        )
    }

    #[cfg(any(feature = "cuda", feature = "opencl"))]
    fn generate_tree_r_last_gpu(
        data: &mut Data<'_>,
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
        source: &DiskStore<<Tree::Hasher as Hasher>::Domain>,
        callback: PrepareTreeRDataCallback<Tree>,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>> {
        use std::cmp::min;
        use std::fs::OpenOptions;
        use std::sync::mpsc::sync_channel as channel;

        use fr32::fr_into_bytes;
        use merkletree::merkle::{get_merkle_tree_cache_size, get_merkle_tree_leafs};
        use neptune::{
            batch_hasher::Batcher,
            tree_builder::{TreeBuilder, TreeBuilderTrait},
        };

        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            replica_path,
            nodes_count,
            tree_count,
        )?;

        info!("generating tree r last using the GPU");
        let max_gpu_tree_batch_size = SETTINGS.max_gpu_tree_batch_size as usize;

        // This channel will receive batches of leaf nodes and add them to the TreeBuilder.
        let (builder_tx, builder_rx) = channel::<(Vec<Fr>, bool)>(0);
        let config_count = configs.len(); // Don't move config into closure below.
        let configs = &configs;
        let tree_r_last_config = &tree_r_last_config;

        THREAD_POOL.scoped(|s| {
            // This channel will receive the finished tree data to be written to disk.
            let (writer_tx, writer_rx) = channel::<Vec<Fr>>(0);

            s.execute(move || {
                for i in 0..config_count {
                    let mut node_index = 0;
                    while node_index != nodes_count {
                        let chunked_nodes_count =
                            min(nodes_count - node_index, max_gpu_tree_batch_size);
                        let start = (i * nodes_count) + node_index;
                        let end = start + chunked_nodes_count;
                        trace!(
                            "processing config {}/{} with leaf nodes {} [{}, {}, {}-{}]",
                            i + 1,
                            tree_count,
                            chunked_nodes_count,
                            node_index,
                            nodes_count,
                            start,
                            end,
                        );

                        let prepared_data = match callback(source, Some(data), start, end)
                            .expect("failed to prepare tree_r_last data")
                        {
                            TreeRElementData::FrList(x) => x,
                            _ => panic!("fr_list is required"),
                        };
                        node_index += chunked_nodes_count;

                        trace!(
                            "node index {}/{}/{}",
                            node_index,
                            chunked_nodes_count,
                            nodes_count,
                        );

                        let is_final = node_index == nodes_count;
                        builder_tx
                            .send((prepared_data, is_final))
                            .expect("failed to send prepared data");
                    }
                }
            });
            s.execute(move || {
                let _gpu_lock = GPU_LOCK.lock().expect("failed to get gpu lock");
                let batcher = match Batcher::pick_gpu(max_gpu_tree_batch_size) {
                    Ok(b) => Some(b),
                    Err(err) => {
                        warn!("no GPU found, falling back to CPU tree builder: {}", err);
                        None
                    }
                };
                let mut tree_builder = TreeBuilder::<Fr, Tree::Arity>::new(
                    batcher,
                    nodes_count,
                    tree_r_last_config.rows_to_discard,
                )
                .expect("failed to create TreeBuilder");

                // Loop until all trees for all configs have been built.
                for i in 0..config_count {
                    loop {
                        let (prepared_data, is_final) =
                            builder_rx.recv().expect("failed to recv prepared data");

                        // Just add non-final leaf batches.
                        if !is_final {
                            tree_builder
                                .add_leaves(&prepared_data)
                                .expect("failed to add leaves");
                            continue;
                        };

                        // If we get here, this is a final leaf batch: build a sub-tree.
                        info!(
                            "building base tree_r_last with GPU {}/{}",
                            i + 1,
                            tree_count
                        );
                        let (_, tree_data) = tree_builder
                            .add_final_leaves(&prepared_data)
                            .expect("failed to add final leaves");

                        writer_tx.send(tree_data).expect("failed to send tree_data");
                        break;
                    }
                }
            });

            for config in configs.iter() {
                let tree_data = writer_rx
                    .recv()
                    .expect("failed to receive tree_data for tree_r_last");

                let tree_data_len = tree_data.len();
                let cache_size = get_merkle_tree_cache_size(
                    get_merkle_tree_leafs(
                        config.size.expect("config size failure"),
                        Tree::Arity::to_usize(),
                    )
                    .expect("failed to get merkle tree leaves"),
                    Tree::Arity::to_usize(),
                    config.rows_to_discard,
                )
                .expect("failed to get merkle tree cache size");
                assert_eq!(tree_data_len, cache_size);

                let flat_tree_data: Vec<_> = tree_data
                    .into_par_iter()
                    .flat_map(|el| fr_into_bytes(&el))
                    .collect();

                // Persist the data to the store based on the current config.
                let tree_r_last_path = StoreConfig::data_path(&config.path, &config.id);
                trace!(
                    "persisting tree r of len {} with {} rows to discard at path {:?}",
                    tree_data_len,
                    config.rows_to_discard,
                    tree_r_last_path
                );
                let mut f = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&tree_r_last_path)
                    .expect("failed to open file for tree_r_last");
                f.write_all(&flat_tree_data)
                    .expect("failed to wrote tree_r_last data");
            }
        });

        create_lc_tree::<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>(
            tree_r_last_config.size.expect("config size failure"),
            configs,
            &replica_config,
        )
    }

    fn generate_tree_r_last_cpu(
        data: &mut Data<'_>,
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
        source: &DiskStore<<Tree::Hasher as Hasher>::Domain>,
        callback: PrepareTreeRDataCallback<Tree>,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>> {
        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            replica_path,
            nodes_count,
            tree_count,
        )?;

        info!("generating tree r last using the CPU");

        // Note that nodes_count is the count of nodes in each base tree
        let mut start = 0;
        let mut end = nodes_count;

        for (i, config) in configs.iter().enumerate() {
            let encoded_data: Vec<<Tree::Hasher as Hasher>::Domain> =
                match callback(source, Some(data), start, end)
                    .expect("failed to prepare tree_r_last data")
                {
                    TreeRElementData::ElementList(x) => x,
                    _ => panic!("element list required"),
                };

            info!(
                "building base tree_r_last with CPU {}/{}",
                i + 1,
                tree_count
            );

            // Remove the tree_r_last store if it exists already
            let tree_r_last_store_path = StoreConfig::data_path(&config.path, &config.id);
            let tree_r_last_store_exists = Path::new(&tree_r_last_store_path).exists();
            trace!(
                "tree_r_last store path {:?} -- exists? {}",
                tree_r_last_store_path,
                tree_r_last_store_exists
            );
            if tree_r_last_store_exists {
                std::fs::remove_file(&tree_r_last_store_path)
                    .expect("failed to remove tree_r_last_store_path");
            }

            LCTree::<Tree::Hasher, Tree::Arity, U0, U0>::from_par_iter_with_config(
                encoded_data,
                config.clone(),
            )
            .with_context(|| format!("failed tree_r_last CPU {}/{}", i + 1, tree_count))?;

            start += nodes_count;
            end += nodes_count;
        }

        create_lc_tree::<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>(
            tree_r_last_config.size.expect("config size failure"),
            &configs,
            &replica_config,
        )
    }

    pub(crate) fn transform_and_replicate_layers(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        data: Data<'_>,
        data_tree: Option<BinaryMerkleTree<G>>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<TransformedLayers<Tree, G>> {
        // Generate key layers.
        let labels = measure_op(Operation::EncodeWindowTimeAll, || {
            Self::generate_labels_for_encoding(graph, layer_challenges, replica_id, &config.path)
                .context("failed to generate labels")
        })?
        .0;

        Self::transform_and_replicate_layers_inner(
            graph,
            layer_challenges,
            data,
            data_tree,
            config.path,
            replica_path,
            labels,
        )
        .context("failed to transform")
    }

    pub(crate) fn transform_and_replicate_layers_inner(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        mut data: Data<'_>,
        data_tree: Option<BinaryMerkleTree<G>>,
        // The directory where the files we operate on are stored.
        cache_path: PathBuf,
        replica_path: PathBuf,
        label_configs: Labels<Tree>,
    ) -> Result<TransformedLayers<Tree, G>> {
        trace!("transform_and_replicate_layers");
        let total_nodes_count = graph.size();

        assert_eq!(data.len(), total_nodes_count * NODE_SIZE);
        trace!("nodes count {}, data len {}", total_nodes_count, data.len());

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
        let tree_d_config = StoreConfig {
            path: cache_path.clone(),
            id: CacheKey::CommDTree.to_string(),
            size: Some(get_merkle_tree_len(total_nodes_count, BINARY_ARITY)?),
            rows_to_discard: default_rows_to_discard(total_nodes_count, BINARY_ARITY),
        };

        let rows_to_discard = default_rows_to_discard(nodes_count, Tree::Arity::to_usize());
        let size = Some(get_merkle_tree_len(nodes_count, Tree::Arity::to_usize())?);

        let tree_r_last_config = StoreConfig {
            path: cache_path.clone(),
            id: CacheKey::CommRLastTree.to_string(),
            size,
            // A default 'rows_to_discard' value will be chosen for tree_r_last, unless the user
            // overrides this value via the environment setting (FIL_PROOFS_ROWS_TO_DISCARD). If
            // this value is specified, no checking is done on it and it may result in a broken
            // configuration. *Use with caution*. It must be noted that if/when this unchecked
            // value is passed through merkle_light, merkle_light now does a check that does not
            // allow us to discard more rows than is possible to discard.
            rows_to_discard,
        };
        trace!(
            "tree_r_last using rows_to_discard={}",
            tree_r_last_config.rows_to_discard
        );

        let tree_c_config = StoreConfig {
            path: cache_path,
            id: CacheKey::CommCTree.to_string(),
            size,
            rows_to_discard,
        };

        let labels =
            LabelsCache::<Tree>::new(&label_configs).context("failed to create labels cache")?;
        let configs = split_config(tree_c_config.clone(), tree_count)?;

        match raise_fd_limit() {
            Some(res) => {
                info!("Building trees [{} descriptors max available]", res);
            }
            None => error!("Failed to raise the fd limit"),
        };

        let tree_c_root = match layers {
            2 => {
                let tree_c = Self::generate_tree_c::<U2, Tree::Arity>(
                    nodes_count,
                    tree_count,
                    configs,
                    &labels,
                )?;
                tree_c.root()
            }
            8 => {
                let tree_c = Self::generate_tree_c::<U8, Tree::Arity>(
                    nodes_count,
                    tree_count,
                    configs,
                    &labels,
                )?;
                tree_c.root()
            }
            11 => {
                let tree_c = Self::generate_tree_c::<U11, Tree::Arity>(
                    nodes_count,
                    tree_count,
                    configs,
                    &labels,
                )?;
                tree_c.root()
            }
            _ => panic_any("Unsupported column arity"),
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
                measure_op(Operation::CommD, || {
                    Self::build_binary_tree::<G>(data.as_ref(), tree_d_config.clone())
                })?
            }
        };
        assert_eq!(
            tree_d_config.size.expect("config size failure"),
            tree_d.len()
        );
        let tree_d_root = tree_d.root();
        drop(tree_d);

        // Encode original data into the last layer.
        let last_layer_labels = labels.labels_for_last_layer()?;
        data.ensure_data()?;

        info!("building tree_r_last");
        let tree_r_last = measure_op(Operation::GenerateTreeRLast, || {
            Self::generate_tree_r_last(
                &mut data,
                nodes_count,
                tree_count,
                tree_r_last_config.clone(),
                replica_path.clone(),
                last_layer_labels,
                None,
            )
            .context("failed to generate tree_r_last")
        })?;
        info!("tree_r_last done");

        let tree_r_last_root = tree_r_last.root();
        drop(tree_r_last);

        data.drop_data()?;

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
    pub fn replicate_phase1<P>(
        pp: &'a PublicParams<Tree>,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        cache_path: P,
    ) -> Result<Labels<Tree>>
    where
        P: AsRef<Path>,
    {
        info!("replicate_phase1");

        let labels = measure_op(Operation::EncodeWindowTimeAll, || {
            Self::generate_labels_for_encoding(
                &pp.graph,
                &pp.layer_challenges,
                replica_id,
                cache_path,
            )
        })?
        .0;

        Ok(labels)
    }

    /// Phase2 of replication.
    #[allow(clippy::type_complexity)]
    pub fn replicate_phase2(
        pp: &'a PublicParams<Tree>,
        label_configs: Labels<Tree>,
        data: Data<'a>,
        data_tree: BinaryMerkleTree<G>,
        cache_path: PathBuf,
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
            cache_path,
            replica_path,
            label_configs,
        )?;

        Ok((tau, (paux, taux)))
    }

    // Assumes data is all zeros.
    // Replica path is used to create configs, but is not read.
    // Instead new zeros are provided (hence the need for replica to be all zeros).
    #[cfg(any(feature = "cuda", feature = "opencl"))]
    fn generate_fake_tree_r_last<TreeArity>(
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        TreeArity: PoseidonArity,
    {
        use std::fs::OpenOptions;

        use ff::Field;
        use fr32::fr_into_bytes;
        use merkletree::merkle::{get_merkle_tree_cache_size, get_merkle_tree_leafs};
        use neptune::{
            batch_hasher::Batcher,
            tree_builder::{TreeBuilder, TreeBuilderTrait},
        };

        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            replica_path,
            nodes_count,
            tree_count,
        )?;

        if Self::use_gpu_tree_builder() {
            info!("generating tree r last using the GPU");
            let max_gpu_tree_batch_size = SETTINGS.max_gpu_tree_batch_size as usize;

            let _gpu_lock = GPU_LOCK.lock().expect("failed to get gpu lock");
            let batcher = match Batcher::pick_gpu(max_gpu_tree_batch_size) {
                Ok(b) => Some(b),
                Err(err) => {
                    warn!("no GPU found, falling back to CPU tree builder: {}", err);
                    None
                }
            };
            let mut tree_builder = TreeBuilder::<Fr, Tree::Arity>::new(
                batcher,
                nodes_count,
                tree_r_last_config.rows_to_discard,
            )
            .expect("failed to create TreeBuilder");

            // Allocate zeros once and reuse.
            let zero_leaves: Vec<Fr> = vec![Fr::ZERO; max_gpu_tree_batch_size];
            for (i, config) in configs.iter().enumerate() {
                let mut consumed = 0;
                while consumed < nodes_count {
                    let batch_size = usize::min(max_gpu_tree_batch_size, nodes_count - consumed);

                    consumed += batch_size;

                    if consumed != nodes_count {
                        tree_builder
                            .add_leaves(&zero_leaves[0..batch_size])
                            .expect("failed to add leaves");
                        continue;
                    };

                    // If we get here, this is a final leaf batch: build a sub-tree.
                    info!(
                        "building base tree_r_last with GPU {}/{}",
                        i + 1,
                        tree_count
                    );

                    let (_, tree_data) = tree_builder
                        .add_final_leaves(&zero_leaves[0..batch_size])
                        .expect("failed to add final leaves");
                    let tree_data_len = tree_data.len();
                    let cache_size = get_merkle_tree_cache_size(
                        get_merkle_tree_leafs(
                            config.size.expect("config size failure"),
                            Tree::Arity::to_usize(),
                        )
                        .expect("failed to get merkle tree leaves"),
                        Tree::Arity::to_usize(),
                        config.rows_to_discard,
                    )
                    .expect("failed to get merkle tree cache size");
                    assert_eq!(tree_data_len, cache_size);

                    let flat_tree_data: Vec<_> = tree_data
                        .into_par_iter()
                        .flat_map(|el| fr_into_bytes(&el))
                        .collect();

                    // Persist the data to the store based on the current config.
                    let tree_r_last_path = StoreConfig::data_path(&config.path, &config.id);
                    trace!(
                        "persisting tree r of len {} with {} rows to discard at path {:?}",
                        tree_data_len,
                        config.rows_to_discard,
                        tree_r_last_path
                    );
                    let mut f = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .open(&tree_r_last_path)
                        .expect("failed to open file for tree_r_last");
                    f.write_all(&flat_tree_data)
                        .expect("failed to wrote tree_r_last data");
                }
            }
        } else {
            info!("generating tree r last using the CPU");
            for (i, config) in configs.iter().enumerate() {
                let encoded_data = vec![<Tree::Hasher as Hasher>::Domain::default(); nodes_count];

                info!(
                    "building base tree_r_last with CPU {}/{}",
                    i + 1,
                    tree_count
                );
                LCTree::<Tree::Hasher, Tree::Arity, U0, U0>::from_par_iter_with_config(
                    encoded_data,
                    config.clone(),
                )?;
            }
        };

        create_lc_tree::<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>(
            tree_r_last_config.size.expect("config size failure"),
            &configs,
            &replica_config,
        )
    }

    // Assumes data is all zeros.
    // Replica path is used to create configs, but is not read.
    // Instead new zeros are provided (hence the need for replica to be all zeros).
    #[cfg(not(any(feature = "cuda", feature = "opencl")))]
    fn generate_fake_tree_r_last<TreeArity>(
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        TreeArity: PoseidonArity,
    {
        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            replica_path,
            nodes_count,
            tree_count,
        )?;

        info!("generating tree r last using the CPU");
        for (i, config) in configs.iter().enumerate() {
            let encoded_data = vec![<Tree::Hasher as Hasher>::Domain::default(); nodes_count];

            info!(
                "building base tree_r_last with CPU {}/{}",
                i + 1,
                tree_count
            );
            LCTree::<Tree::Hasher, Tree::Arity, U0, U0>::from_par_iter_with_config(
                encoded_data,
                config.clone(),
            )?;
        }

        create_lc_tree::<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>(
            tree_r_last_config.size.expect("config size failure"),
            &configs,
            &replica_config,
        )
    }

    pub fn fake_replicate_phase2<R: AsRef<Path>, S: AsRef<Path>>(
        tree_c_root: <Tree::Hasher as Hasher>::Domain,
        replica_path: R,
        cache_path: S,
        sector_size: usize,
    ) -> Result<(
        <Tree::Hasher as Hasher>::Domain,
        PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    )> {
        let leaf_count = sector_size / NODE_SIZE;
        let replica_pathbuf = PathBuf::from(replica_path.as_ref());
        assert_eq!(0, sector_size % NODE_SIZE);
        let tree_count = get_base_tree_count::<Tree>();
        let nodes_count = leaf_count / tree_count;

        let tree_r_last_config = StoreConfig {
            path: cache_path.as_ref().into(),
            id: CacheKey::CommRLastTree.to_string(),
            size: Some(get_merkle_tree_len(nodes_count, Tree::Arity::to_usize())?),
            rows_to_discard: default_rows_to_discard(nodes_count, Tree::Arity::to_usize()),
        };

        // Encode original data into the last layer.
        info!("building tree_r_last");
        let tree_r_last = Self::generate_fake_tree_r_last::<Tree::Arity>(
            nodes_count,
            tree_count,
            tree_r_last_config,
            replica_pathbuf,
        )?;
        info!("tree_r_last done");

        let tree_r_last_root = tree_r_last.root();
        drop(tree_r_last);

        // comm_r = H(comm_c || comm_r_last)
        let comm_r: <Tree::Hasher as Hasher>::Domain =
            <Tree::Hasher as Hasher>::Function::hash2(&tree_c_root, &tree_r_last_root);

        let p_aux = PersistentAux {
            comm_c: tree_c_root,
            comm_r_last: tree_r_last_root,
        };

        Ok((comm_r, p_aux))
    }

    pub fn fake_comm_r<R: AsRef<Path>>(
        tree_c_root: <Tree::Hasher as Hasher>::Domain,
        existing_p_aux_path: R,
    ) -> Result<(
        <Tree::Hasher as Hasher>::Domain,
        PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    )> {
        let existing_p_aux: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
            let p_aux_bytes = fs::read(&existing_p_aux_path)?;

            deserialize(&p_aux_bytes)
        }?;

        let existing_comm_r_last = existing_p_aux.comm_r_last;

        // comm_r = H(comm_c || comm_r_last)
        let comm_r: <Tree::Hasher as Hasher>::Domain =
            <Tree::Hasher as Hasher>::Function::hash2(&tree_c_root, &existing_comm_r_last);

        let p_aux = PersistentAux {
            comm_c: tree_c_root,
            comm_r_last: existing_comm_r_last,
        };

        Ok((comm_r, p_aux))
    }
}
