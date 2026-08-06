use std::marker::PhantomData;
use std::path::Path;

use filecoin_hashers::Hasher;
use merkletree::store::StoreConfig;
use serde::{Deserialize, Serialize};
use storage_proofs_core::{
    drgraph::Graph,
    error::Result,
    merkle::{create_base_merkle_tree, BinaryMerkleTree, MerkleProofTrait, MerkleTreeTrait},
    por::DataProof,
    proof::ProofScheme,
    util::NODE_SIZE,
};

use crate::{
    encode,
    zigzag::vanilla::{
        challenges::LayerChallenges,
        graph::ZigZagBucketGraph,
        params::{
            comm_r_star, ChallengeRequirements, PrivateInputs, PublicInputs,
            PublicParams, SetupParams, Tau,
        },
        vde,
    },
};

/// ZigZag layered DRG PoRep.
///
/// `Tree` is the Poseidon replica-tree shape. `G` is the piece/data hasher (Sha256) used for the
/// layer-0 data tree so `comm_d` matches Filecoin's standard piece-aggregated CommD.
#[derive(Debug)]
pub struct ZigZagDrgPoRep<Tree, G>
where
    Tree: MerkleTreeTrait,
    G: Hasher,
{
    _tree: PhantomData<Tree>,
    _g: PhantomData<G>,
}

/// Per-layer proof: replica-node and parent inclusions in the Poseidon replica tree, plus (for
/// layers > 0) data-node inclusions in the previous layer's replica tree.
#[derive(Debug, Serialize, Deserialize)]
pub struct LayerProof<Tree: MerkleTreeTrait> {
    #[serde(bound = "")]
    pub replica_nodes: Vec<DataProof<Tree::Proof>>,
    #[serde(bound = "")]
    pub replica_parents: Vec<Vec<(u32, DataProof<Tree::Proof>)>>,
    /// Data-node proofs against the previous layer's Poseidon replica tree. Empty for layer 0
    /// (those live in [`Proof::layer0_data_nodes`] against the Sha256 `comm_d` tree).
    #[serde(bound = "")]
    pub nodes: Vec<DataProof<Tree::Proof>>,
}

impl<Tree: MerkleTreeTrait> Clone for LayerProof<Tree> {
    fn clone(&self) -> Self {
        LayerProof {
            replica_nodes: self.replica_nodes.clone(),
            replica_parents: self.replica_parents.clone(),
            nodes: self.nodes.clone(),
        }
    }
}

/// Full vanilla proof across all layers.
#[derive(Debug, Serialize, Deserialize)]
pub struct Proof<Tree: MerkleTreeTrait, G: 'static + Hasher> {
    #[serde(bound = "")]
    pub encoding_proofs: Vec<LayerProof<Tree>>,
    /// Layer-0 data-node inclusion proofs against the Sha256 `comm_d` tree.
    #[serde(bound = "")]
    pub layer0_data_nodes:
        Vec<DataProof<<BinaryMerkleTree<G> as MerkleTreeTrait>::Proof>>,
    #[serde(bound = "")]
    pub layer_comm_rs: Vec<<Tree::Hasher as Hasher>::Domain>,
    #[serde(bound = "")]
    pub comm_d: G::Domain,
}

impl<Tree: MerkleTreeTrait, G: 'static + Hasher> Clone for Proof<Tree, G> {
    fn clone(&self) -> Self {
        Proof {
            encoding_proofs: self.encoding_proofs.clone(),
            layer0_data_nodes: self.layer0_data_nodes.clone(),
            layer_comm_rs: self.layer_comm_rs.clone(),
            comm_d: self.comm_d,
        }
    }
}

impl<Tree, G> ZigZagDrgPoRep<Tree, G>
where
    Tree: 'static + MerkleTreeTrait,
    G: 'static + Hasher,
{
    pub fn transform(
        graph: &ZigZagBucketGraph<Tree::Hasher>,
    ) -> ZigZagBucketGraph<Tree::Hasher> {
        graph.zigzag()
    }

    pub fn invert_transform(
        graph: &ZigZagBucketGraph<Tree::Hasher>,
    ) -> ZigZagBucketGraph<Tree::Hasher> {
        // Zigzag is an involution.
        graph.zigzag()
    }

    /// Replicate `data` in place through `layers` ZigZag layers.
    ///
    /// Returns the commitments, the Sha256 data tree (`comm_d`), and one Poseidon replica tree per
    /// layer. When `cache_path` is `Some`, trees are persisted via `StoreConfig` (disk-backed
    /// stores) under that directory, so peak RAM is dominated by the sector buffer rather than
    /// fully-materialized in-memory trees.
    pub fn transform_and_replicate_layers(
        graph: &ZigZagBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        data: &mut [u8],
        cache_path: Option<&Path>,
    ) -> Result<(
        Tau<<Tree::Hasher as Hasher>::Domain, G::Domain>,
        BinaryMerkleTree<G>,
        Vec<Tree>,
    )> {
        let layers = layer_challenges.layers();
        assert!(layers > 0);
        assert_eq!(data.len() % NODE_SIZE, 0);

        let leaves = data.len() / NODE_SIZE;

        let tree_d_config = cache_path.map(|p| StoreConfig::new(p, "zigzag-tree-d", 0));
        // Layer 0: Sha256 Merkle tree over the original (fr32-padded) data — this is Filecoin CommD.
        let tree_d =
            create_base_merkle_tree::<BinaryMerkleTree<G>>(tree_d_config, leaves, data)?;
        let comm_d = tree_d.root();

        let mut replica_trees: Vec<Tree> = Vec::with_capacity(layers);
        let mut layer_comm_rs = Vec::with_capacity(layers);
        let mut current_graph = graph.clone();

        for layer in 0..layers {
            vde::encode(&current_graph, replica_id, data)?;
            let tree_r_config =
                cache_path.map(|p| StoreConfig::new(p, format!("zigzag-tree-r-{layer}"), 0));
            let tree_r = create_base_merkle_tree::<Tree>(tree_r_config, leaves, data)?;
            layer_comm_rs.push(tree_r.root());
            replica_trees.push(tree_r);
            current_graph = Self::transform(&current_graph);
        }

        let comm_r_star_val = comm_r_star::<Tree::Hasher>(replica_id, &layer_comm_rs)?;

        Ok((
            Tau {
                comm_d,
                layer_comm_rs,
                comm_r_star: comm_r_star_val,
            },
            tree_d,
            replica_trees,
        ))
    }

    /// Invert the replication, recovering the original data in place.
    pub fn extract_and_invert_transform_layers(
        graph: &ZigZagBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        data: &mut [u8],
    ) -> Result<()> {
        let layers = layer_challenges.layers();
        assert!(layers > 0);

        let mut layer_graph = graph.clone();
        for _ in 0..(layers - 1) {
            layer_graph = Self::transform(&layer_graph);
        }

        for _ in 0..layers {
            let decoded = vde::decode(&layer_graph, replica_id, data)?;
            data.copy_from_slice(&decoded);
            layer_graph = Self::invert_transform(&layer_graph);
        }

        Ok(())
    }
}

/// Build the ZigZag public parameters for the given setup parameters.
pub fn setup<Tree: MerkleTreeTrait>(sp: &SetupParams) -> Result<PublicParams<Tree>> {
    let graph = ZigZagBucketGraph::<Tree::Hasher>::new_zigzag(
        None,
        sp.nodes,
        sp.degree,
        sp.expansion_degree,
        sp.porep_id,
        sp.api_version,
    )?;

    Ok(PublicParams::new(graph, sp.layer_challenges.clone()))
}

impl<'a, Tree, G> ProofScheme<'a> for ZigZagDrgPoRep<Tree, G>
where
    Tree: 'static + MerkleTreeTrait,
    G: 'static + Hasher,
{
    type PublicParams = PublicParams<Tree>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<Tree::Hasher as Hasher>::Domain, G::Domain>;
    type PrivateInputs = PrivateInputs<Tree, G>;
    type Proof = Proof<Tree, G>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        setup::<Tree>(sp)
    }

    fn prove(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let proofs = Self::prove_all_partitions(pub_params, pub_inputs, priv_inputs, 1)?;
        Ok(proofs.into_iter().next().expect("missing partition proof"))
    }

    fn prove_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
        partition_count: usize,
    ) -> Result<Vec<Self::Proof>> {
        assert!(partition_count > 0);

        let layers = pub_params.layer_challenges.layers();
        assert_eq!(priv_inputs.aux.len(), layers);

        (0..partition_count)
            .map(|k| {
                let mut encoding_proofs = Vec::with_capacity(layers);
                let mut layer0_data_nodes = Vec::new();
                let mut layer_graph = pub_params.graph.clone();

                for layer in 0..layers {
                    let tree_r = &priv_inputs.aux[layer];
                    let graph_size = layer_graph.size();
                    let degree = layer_graph.degree();

                    let challenges = pub_inputs.challenges(
                        &pub_params.layer_challenges,
                        graph_size,
                        layer as u8,
                        Some(k),
                    );

                    let mut replica_nodes = Vec::with_capacity(challenges.len());
                    let mut replica_parents = Vec::with_capacity(challenges.len());
                    let mut nodes = Vec::with_capacity(challenges.len());

                    let mut parents = vec![0u32; degree];
                    for challenge in challenges {
                        let challenge = challenge % graph_size;
                        assert_ne!(challenge, 0, "cannot prove the first node");

                        let replica_proof = tree_r.gen_proof(challenge)?;
                        let replica_data = replica_proof.leaf();
                        replica_nodes.push(DataProof {
                            data: replica_data,
                            proof: replica_proof,
                        });

                        layer_graph.parents(challenge, &mut parents)?;
                        let mut parent_proofs = Vec::with_capacity(parents.len());
                        for parent in &parents {
                            let proof = tree_r.gen_proof(*parent as usize)?;
                            let data = proof.leaf();
                            parent_proofs.push((*parent, DataProof { data, proof }));
                        }
                        replica_parents.push(parent_proofs);

                        if layer == 0 {
                            let data_proof = priv_inputs.tree_d.gen_proof(challenge)?;
                            let data = data_proof.leaf();
                            layer0_data_nodes.push(DataProof {
                                data,
                                proof: data_proof,
                            });
                        } else {
                            // Data for layer i is the previous layer's replica.
                            let tree_d = &priv_inputs.aux[layer - 1];
                            let data_proof = tree_d.gen_proof(challenge)?;
                            let data = data_proof.leaf();
                            nodes.push(DataProof {
                                data,
                                proof: data_proof,
                            });
                        }
                    }

                    encoding_proofs.push(LayerProof {
                        replica_nodes,
                        replica_parents,
                        nodes,
                    });

                    layer_graph = Self::transform(&layer_graph);
                }

                Ok(Proof {
                    encoding_proofs,
                    layer0_data_nodes,
                    layer_comm_rs: priv_inputs.layer_comm_rs.clone(),
                    comm_d: priv_inputs.comm_d,
                })
            })
            .collect()
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let layers = pub_params.layer_challenges.layers();
        let k = pub_inputs.k.unwrap_or(0);

        if proof.encoding_proofs.len() != layers {
            return Ok(false);
        }
        if proof.layer_comm_rs.len() != layers {
            return Ok(false);
        }

        let tau = match &pub_inputs.tau {
            Some(t) => t,
            None => return Ok(false),
        };

        if proof.comm_d != tau.comm_d {
            return Ok(false);
        }
        if proof.layer_comm_rs[layers - 1] != tau.comm_r {
            return Ok(false);
        }

        let mut layer_graph = pub_params.graph.clone();

        for layer in 0..layers {
            let layer_proof = &proof.encoding_proofs[layer];
            let comm_r = proof.layer_comm_rs[layer];
            let graph_size = layer_graph.size();
            let degree = layer_graph.degree();

            let challenges = pub_inputs.challenges(
                &pub_params.layer_challenges,
                graph_size,
                layer as u8,
                Some(k),
            );

            if layer_proof.replica_nodes.len() != challenges.len()
                || layer_proof.replica_parents.len() != challenges.len()
            {
                return Ok(false);
            }

            if layer == 0 {
                if proof.layer0_data_nodes.len() != challenges.len() {
                    return Ok(false);
                }
            } else if layer_proof.nodes.len() != challenges.len() {
                return Ok(false);
            }

            let mut expected_parents = vec![0u32; degree];
            for (i, challenge) in challenges.into_iter().enumerate() {
                let challenge = challenge % graph_size;
                if challenge == 0 {
                    return Ok(false);
                }

                let replica_node = &layer_proof.replica_nodes[i];
                let parents = &layer_proof.replica_parents[i];

                if !replica_node.proof.validate(challenge) || replica_node.proof.root() != comm_r
                {
                    return Ok(false);
                }

                // Data-node inclusion: Sha256 comm_d for layer 0, previous replica root otherwise.
                let data_leaf = if layer == 0 {
                    let data_node = &proof.layer0_data_nodes[i];
                    if !data_node.proof.validate(challenge)
                        || data_node.proof.root() != proof.comm_d
                    {
                        return Ok(false);
                    }
                    // Domain types differ (G vs Tree::Hasher); compare via field elements.
                    let data_fr: blstrs::Scalar = data_node.data.into();
                    data_fr
                } else {
                    let data_node = &layer_proof.nodes[i];
                    let expected_comm_d = proof.layer_comm_rs[layer - 1];
                    if !data_node.proof.validate(challenge)
                        || data_node.proof.root() != expected_comm_d
                    {
                        return Ok(false);
                    }
                    data_node.data.into()
                };

                layer_graph.parents(challenge, &mut expected_parents)?;
                if parents.len() != expected_parents.len() {
                    return Ok(false);
                }
                for ((parent, parent_proof), expected) in parents.iter().zip(&expected_parents) {
                    if parent != expected {
                        return Ok(false);
                    }
                    if !parent_proof.proof.validate(*parent as usize)
                        || parent_proof.proof.root() != comm_r
                    {
                        return Ok(false);
                    }
                }

                let parent_data: Vec<_> = parents.iter().map(|(_, p)| p.data).collect();
                let key = vde::create_key_from_domains::<Tree::Hasher>(
                    &pub_inputs.replica_id,
                    &parent_data,
                )?;
                let unsealed = encode::decode(key, replica_node.data);
                let unsealed_fr: blstrs::Scalar = unsealed.into();
                if unsealed_fr != data_leaf {
                    return Ok(false);
                }
            }

            layer_graph = Self::transform(&layer_graph);
        }

        Ok(true)
    }

    fn with_partition(mut pub_in: Self::PublicInputs, k: Option<usize>) -> Self::PublicInputs {
        pub_in.k = k;
        pub_in
    }

    fn satisfies_requirements(
        pub_params: &Self::PublicParams,
        requirements: &Self::Requirements,
        partitions: usize,
    ) -> bool {
        let total = pub_params.layer_challenges.total_challenges() * partitions;
        total >= requirements.minimum_challenges
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use filecoin_hashers::{
        poseidon::{PoseidonDomain, PoseidonHasher},
        sha256::Sha256Hasher,
    };
    use generic_array::typenum::{U0, U2};
    use storage_proofs_core::{
        api_version::ApiVersion,
        drgraph::BASE_DEGREE,
        merkle::{DiskStore, MerkleTreeWrapper},
    };

    use crate::zigzag::vanilla::graph::EXP_DEGREE;

    type ZZTree = MerkleTreeWrapper<PoseidonHasher, DiskStore<PoseidonDomain>, U2, U0, U0>;
    type Piece = Sha256Hasher;

    fn replicate_extract_roundtrip(layers: usize) {
        let nodes = 128;
        let porep_id = [9u8; 32];

        let sp = SetupParams {
            nodes,
            degree: BASE_DEGREE,
            expansion_degree: EXP_DEGREE,
            porep_id,
            api_version: ApiVersion::V1_2_0,
            layer_challenges: LayerChallenges::new_fixed(layers, 1),
        };

        let pp = setup::<ZZTree>(&sp).expect("setup failed");

        let replica_id = PoseidonDomain::default();
        let original = vec![0u8; nodes * NODE_SIZE];
        let mut data = original.clone();

        let (tau, tree_d, replica_trees) =
            ZigZagDrgPoRep::<ZZTree, Piece>::transform_and_replicate_layers(
                &pp.graph,
                &pp.layer_challenges,
                &replica_id,
                &mut data,
                None,
            )
            .expect("replication failed");

        assert_ne!(data, original, "replication did not change data");
        assert_eq!(tau.layer_comm_rs.len(), layers);
        assert_eq!(replica_trees.len(), layers);

        let original_tree =
            create_base_merkle_tree::<BinaryMerkleTree<Piece>>(None, nodes, &original)
                .expect("failed to build original tree");
        assert_eq!(tau.comm_d, original_tree.root());
        assert_eq!(tau.comm_d, tree_d.root());
        assert_eq!(tau.simplify().comm_r, replica_trees[layers - 1].root());

        ZigZagDrgPoRep::<ZZTree, Piece>::extract_and_invert_transform_layers(
            &pp.graph,
            &pp.layer_challenges,
            &replica_id,
            &mut data,
        )
        .expect("extraction failed");

        assert_eq!(data, original, "extraction did not recover original data");
    }

    #[test]
    fn replicate_extract_single_layer() {
        replicate_extract_roundtrip(1);
    }

    #[test]
    fn replicate_extract_multi_layer() {
        replicate_extract_roundtrip(4);
    }

    fn prove_verify(layers: usize, challenge_count: usize) {
        let nodes = 128;
        let porep_id = [11u8; 32];

        let sp = SetupParams {
            nodes,
            degree: BASE_DEGREE,
            expansion_degree: EXP_DEGREE,
            porep_id,
            api_version: ApiVersion::V1_2_0,
            layer_challenges: LayerChallenges::new_fixed(layers, challenge_count),
        };

        let pp = ZigZagDrgPoRep::<ZZTree, Piece>::setup(&sp).expect("setup failed");

        let replica_id = PoseidonDomain::default();
        let mut data = vec![0u8; nodes * NODE_SIZE];

        let (tau, tree_d, replica_trees) =
            ZigZagDrgPoRep::<ZZTree, Piece>::transform_and_replicate_layers(
                &pp.graph,
                &pp.layer_challenges,
                &replica_id,
                &mut data,
                None,
            )
            .expect("replication failed");

        let pub_inputs = PublicInputs {
            replica_id,
            seed: None,
            tau: Some(tau.simplify()),
            comm_r_star: tau.comm_r_star,
            k: None,
        };

        let priv_inputs = PrivateInputs::<ZZTree, Piece> {
            tree_d,
            aux: replica_trees,
            layer_comm_rs: tau.layer_comm_rs.clone(),
            comm_d: tau.comm_d,
        };

        let proof = ZigZagDrgPoRep::<ZZTree, Piece>::prove(&pp, &pub_inputs, &priv_inputs)
            .expect("prove failed");

        assert!(
            ZigZagDrgPoRep::<ZZTree, Piece>::verify(&pp, &pub_inputs, &proof)
                .expect("verify errored"),
            "valid proof did not verify"
        );

        let mut bad_inputs = pub_inputs.clone();
        bad_inputs.replica_id = PoseidonDomain::from([3u8; 32]);
        bad_inputs.comm_r_star =
            comm_r_star::<PoseidonHasher>(&bad_inputs.replica_id, &tau.layer_comm_rs)
                .expect("comm_r_star failed");
        assert!(
            !ZigZagDrgPoRep::<ZZTree, Piece>::verify(&pp, &bad_inputs, &proof)
                .expect("verify errored"),
            "proof verified under the wrong replica id"
        );
    }

    #[test]
    fn prove_verify_single_layer() {
        prove_verify(1, 2);
    }

    #[test]
    fn prove_verify_multi_layer() {
        prove_verify(4, 2);
    }
}
