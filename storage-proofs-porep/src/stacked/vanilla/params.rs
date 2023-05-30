use std::io::{self, Read, Seek, SeekFrom, Write};
use std::iter;
use std::marker::PhantomData;
use std::mem;
use std::path::{Path, PathBuf};

use anyhow::Context;
use filecoin_hashers::{Domain, Hasher};
use fr32::bytes_into_fr_repr_safe;
use generic_array::typenum::{Unsigned, U2};
use log::trace;
use merkletree::{
    merkle::get_merkle_tree_leafs,
    store::{DiskStore, Store, StoreConfig},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    api_version::{ApiFeature, ApiVersion},
    drgraph::{Graph, BASE_DEGREE},
    error::Result,
    merkle::{
        create_disk_tree, create_lc_tree, get_base_tree_count, split_config,
        split_config_and_replica, BinaryMerkleTree, DiskTree, LCTree, MerkleProof,
        MerkleProofTrait, MerkleTreeTrait,
    },
    parameter_cache::ParameterSetMetadata,
    util::{data_at_node, NODE_SIZE},
};

use crate::stacked::vanilla::{
    Column, ColumnProof, EncodingProof, LabelingProof, LayerChallenges, StackedBucketGraph,
    EXP_DEGREE, SYNTHETIC_POREP_VANILLA_PROOFS_EXT, SYNTHETIC_POREP_VANILLA_PROOFS_KEY,
    TOTAL_PARENTS,
};

pub const BINARY_ARITY: usize = 2;
pub const QUAD_ARITY: usize = 4;
pub const OCT_ARITY: usize = 8;

#[derive(Debug, Clone)]
pub struct SetupParams {
    // Number of nodes
    pub nodes: usize,

    // Base degree of DRG
    pub degree: usize,

    pub expansion_degree: usize,

    pub porep_id: [u8; 32],
    pub challenges: LayerChallenges,
    pub num_layers: usize,
    pub api_version: ApiVersion,
    pub api_features: Vec<ApiFeature>,
}

#[derive(Debug)]
pub struct PublicParams<Tree>
where
    Tree: 'static + MerkleTreeTrait,
{
    pub graph: StackedBucketGraph<Tree::Hasher>,
    pub challenges: LayerChallenges,
    pub num_layers: usize,
    _t: PhantomData<Tree>,
}

impl<Tree> Clone for PublicParams<Tree>
where
    Tree: MerkleTreeTrait,
{
    fn clone(&self) -> Self {
        Self {
            graph: self.graph.clone(),
            challenges: self.challenges.clone(),
            num_layers: self.num_layers,
            _t: Default::default(),
        }
    }
}

impl<Tree> PublicParams<Tree>
where
    Tree: MerkleTreeTrait,
{
    pub fn new(
        graph: StackedBucketGraph<Tree::Hasher>,
        challenges: LayerChallenges,
        num_layers: usize,
    ) -> Self {
        PublicParams {
            graph,
            challenges,
            num_layers,
            _t: PhantomData,
        }
    }
}

impl<Tree> ParameterSetMetadata for PublicParams<Tree>
where
    Tree: MerkleTreeTrait,
{
    // This identifier is used for the hash value of the parameters file name, the output string
    // must stay the same at all times, else the filename parameters will be wrong.
    fn identifier(&self) -> String {
        format!(
            "layered_drgporep::PublicParams{{ graph: {}, challenges: LayerChallenges {{ layers: {}, max_count: {} }}, tree: {} }}",
            self.graph.identifier(),
            self.num_layers,
            self.challenges.challenges_count_all(),
            Tree::display()
        )
    }

    fn sector_size(&self) -> u64 {
        self.graph.sector_size()
    }
}

impl<'a, Tree> From<&'a PublicParams<Tree>> for PublicParams<Tree>
where
    Tree: MerkleTreeTrait,
{
    fn from(other: &PublicParams<Tree>) -> PublicParams<Tree> {
        PublicParams::new(
            other.graph.clone(),
            other.challenges.clone(),
            other.num_layers,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicInputs<T: Domain, S: Domain> {
    #[serde(bound = "")]
    pub replica_id: T,
    /// PoRep challenge generation randomness. `Some` indicates that proofs should be generated for
    /// porep challenges; `None` indicates that proofs should be generated for synthetic challenges.
    pub seed: Option<[u8; 32]>,
    #[serde(bound = "")]
    pub tau: Option<Tau<T, S>>,
    /// Partition index
    pub k: Option<usize>,
}

impl<T: Domain, S: Domain> PublicInputs<T, S> {
    /// If the porep challenge randomness `self.seed` is set, this method returns the porep
    /// challenges for partition `k` (for syth and non-syth poreps); otherwise if `self.seed` is
    /// `None`, returns the entire synthetic challenge set. Note synthetic challenges are generated
    /// in a single partition `k = 0`.
    pub fn challenges(
        &self,
        challenges: &LayerChallenges,
        sector_nodes: usize,
        k: Option<usize>,
    ) -> Vec<usize> {
        let k = k.unwrap_or(0);

        assert!(
            challenges.use_synthetic || self.seed.is_some(),
            "challenge seed must be set when synth porep is disabled",
        );
        assert!(
            !challenges.use_synthetic || self.tau.is_some(),
            "comm_r must be set prior to generating synth porep challenges",
        );
        let comm_r = self
            .tau
            .as_ref()
            .map(|tau| tau.comm_r)
            .unwrap_or(T::default());

        if let Some(seed) = self.seed.as_ref() {
            challenges.derive(sector_nodes, &self.replica_id, &comm_r, seed, k as u8)
        } else if k == 0 {
            challenges.derive_synthetic(sector_nodes, &self.replica_id, &comm_r)
        } else {
            vec![]
        }
    }
}

#[derive(Debug)]
pub struct PrivateInputs<Tree: MerkleTreeTrait, G: Hasher> {
    pub p_aux: PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    pub t_aux: TemporaryAuxCache<Tree, G>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof<Tree: MerkleTreeTrait, G: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<G, U2>: Serialize",
        deserialize = "MerkleProof<G, U2>: Deserialize<'de>"
    ))]
    pub comm_d_proofs: MerkleProof<G, U2>,
    #[serde(bound(
        serialize = "MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>: Deserialize<'de>"
    ))]
    pub comm_r_last_proof:
        MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    #[serde(bound(
        serialize = "ReplicaColumnProof<MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,>: Serialize",
        deserialize = "ReplicaColumnProof<MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>: Deserialize<'de>"
    ))]
    pub replica_column_proofs: ReplicaColumnProof<
        MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    >,
    #[serde(bound(
        serialize = "LabelingProof<Tree::Hasher>: Serialize",
        deserialize = "LabelingProof<Tree::Hasher>: Deserialize<'de>"
    ))]
    /// Indexed by layer in 1..layers.
    pub labeling_proofs: Vec<LabelingProof<Tree::Hasher>>,
    #[serde(bound(
        serialize = "EncodingProof<Tree::Hasher>: Serialize",
        deserialize = "EncodingProof<Tree::Hasher>: Deserialize<'de>"
    ))]
    pub encoding_proof: EncodingProof<Tree::Hasher>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for Proof<Tree, G> {
    fn clone(&self) -> Self {
        Self {
            comm_d_proofs: self.comm_d_proofs.clone(),
            comm_r_last_proof: self.comm_r_last_proof.clone(),
            replica_column_proofs: self.replica_column_proofs.clone(),
            labeling_proofs: self.labeling_proofs.clone(),
            encoding_proof: self.encoding_proof.clone(),
        }
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> Proof<Tree, G> {
    pub fn comm_r_last(&self) -> <Tree::Hasher as Hasher>::Domain {
        self.comm_r_last_proof.root()
    }

    pub fn comm_c(&self) -> <Tree::Hasher as Hasher>::Domain {
        self.replica_column_proofs.c_x.root()
    }

    /// Verify the full proof.
    pub fn verify(
        &self,
        pub_params: &PublicParams<Tree>,
        pub_inputs: &PublicInputs<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>,
        challenge: usize,
        graph: &StackedBucketGraph<Tree::Hasher>,
    ) -> bool {
        let replica_id = &pub_inputs.replica_id;

        check!(challenge < graph.size());
        check!(pub_inputs.tau.is_some());

        // Verify initial data layer
        trace!("verify initial data layer");

        check!(self.comm_d_proofs.proves_challenge(challenge));

        if let Some(ref tau) = pub_inputs.tau {
            check_eq!(&self.comm_d_proofs.root(), &tau.comm_d);
        } else {
            return false;
        }

        // Verify replica column openings
        trace!("verify replica column openings");
        let mut parents = vec![0; graph.degree()];
        graph
            .parents(challenge, &mut parents)
            .expect("graph parents failure"); // FIXME: error handling
        check!(self.replica_column_proofs.verify(challenge, &parents));

        check!(self.verify_final_replica_layer(challenge));

        check!(self.verify_labels(replica_id, pub_params.num_layers));

        trace!("verify encoding");

        check!(self.encoding_proof.verify::<G>(
            replica_id,
            &self.comm_r_last_proof.leaf(),
            &self.comm_d_proofs.leaf()
        ));

        true
    }

    /// Verify all labels.
    fn verify_labels(
        &self,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        num_layers: usize,
    ) -> bool {
        // Verify Labels Layer 1..layers
        for layer in 1..=num_layers {
            trace!("verify labeling (layer: {})", layer,);

            check!(self.labeling_proofs.get(layer - 1).is_some());
            let labeling_proof = &self
                .labeling_proofs
                .get(layer - 1)
                .expect("labeling proofs get failure");
            let labeled_node = self
                .replica_column_proofs
                .c_x
                .get_node_at_layer(layer)
                .expect("get_node_at_layer failure"); // FIXME: error handling
            check!(labeling_proof.verify(replica_id, labeled_node));
        }

        true
    }

    /// Verify final replica layer openings
    fn verify_final_replica_layer(&self, challenge: usize) -> bool {
        trace!("verify final replica layer openings");
        check!(self.comm_r_last_proof.proves_challenge(challenge));

        true
    }

    #[allow(clippy::type_complexity)]
    fn from_parts(
        proof_d: MerkleProof<G, U2>,
        col_proof: ColumnProof<
            MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
        >,
        drg_col_proofs: Vec<
            ColumnProof<
                MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >,
        >,
        exp_col_proofs: Vec<
            ColumnProof<
                MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >,
        >,
        proof_r: MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    ) -> Self {
        let challenge = col_proof.column.index as u64;
        let num_layers = col_proof.column.rows.len();
        let num_drg_parents = drg_col_proofs.len();
        let num_exp_parents = exp_col_proofs.len();

        let labeling_proofs: Vec<LabelingProof<Tree::Hasher>> = (0..num_layers)
            .map(|layer_index| {
                let layer_parents = if layer_index == 0 {
                    num_drg_parents
                } else {
                    num_drg_parents + num_exp_parents
                };
                let (layer, prev_layer) = (layer_index + 1, layer_index);

                let repeated_parent_labels = drg_col_proofs
                    .iter()
                    .zip(iter::repeat(layer))
                    .chain(exp_col_proofs.iter().zip(iter::repeat(prev_layer)))
                    .map(|(col_proof, layer)| {
                        *col_proof
                            .get_node_at_layer(layer)
                            .expect("layer index should never be invalid")
                    })
                    .take(layer_parents)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .cycle()
                    .take(TOTAL_PARENTS)
                    .collect();

                LabelingProof::new(layer as u32, challenge, repeated_parent_labels)
            })
            .collect();

        let encoding_proof = {
            let enc_key_proof = &labeling_proofs[num_layers - 1];
            EncodingProof::new(
                enc_key_proof.layer_index,
                enc_key_proof.node,
                enc_key_proof.parents.clone(),
            )
        };

        Proof {
            comm_d_proofs: proof_d,
            comm_r_last_proof: proof_r,
            replica_column_proofs: ReplicaColumnProof {
                c_x: col_proof,
                drg_parents: drg_col_proofs,
                exp_parents: exp_col_proofs,
            },
            labeling_proofs,
            encoding_proof,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaColumnProof<Proof: MerkleProofTrait> {
    #[serde(bound(
        serialize = "ColumnProof<Proof>: Serialize",
        deserialize = "ColumnProof<Proof>: Deserialize<'de>"
    ))]
    pub c_x: ColumnProof<Proof>,
    #[serde(bound(
        serialize = "ColumnProof<Proof>: Serialize",
        deserialize = "ColumnProof<Proof>: Deserialize<'de>"
    ))]
    pub drg_parents: Vec<ColumnProof<Proof>>,
    #[serde(bound(
        serialize = "ColumnProof<Proof>: Serialize",
        deserialize = "ColumnProof<Proof>: Deserialize<'de>"
    ))]
    pub exp_parents: Vec<ColumnProof<Proof>>,
}

impl<Proof: MerkleProofTrait> ReplicaColumnProof<Proof> {
    pub fn verify(&self, challenge: usize, parents: &[u32]) -> bool {
        let expected_comm_c = self.c_x.root();

        trace!("  verify c_x");
        check!(self.c_x.verify(challenge as u32, &expected_comm_c));

        trace!("  verify drg_parents");
        for (proof, parent) in self.drg_parents.iter().zip(parents.iter()) {
            check!(proof.verify(*parent, &expected_comm_c));
        }

        trace!("  verify exp_parents");
        for (proof, parent) in self
            .exp_parents
            .iter()
            .zip(parents.iter().skip(self.drg_parents.len()))
        {
            check!(proof.verify(*parent, &expected_comm_c));
        }

        true
    }
}

/// Type for serializing/deserializing synthetic proofs' file.
///
/// Note that the synthetic proofs' serialization format differs from the standard `serde`
/// serialization format for `Proof` to achieve a smaller synthetic proofs file.
///
/// The synthetic proofs serialization format is:
///
/// 1) root_d (32 bytes)
/// 2) root_c (32 bytes)
/// 3) root_r (32 bytes)
/// 4) For each synthetic challenge proof:
///     4.1) Challenge's node index (8 bytes)
///     4.2) Parents' node indices (8 bytes per parent)
///     4.3) Challenge's proof_d (32 bytes for leaf_d and 32 bytes per path_d sibling)
///     4.4) Challenge's column (32 bytes per layer)
///     4.5) Challenge's proof_c (32 bytes for leaf_c and 32 bytes per path_c sibling)
///     4.6) For each parent:
///         4.6.1) Parent's column (32 bytes per layer)
///         4.6.2) Parent's proof_c (32 bytes for leaf_c and 32 bytes per path_c sibling)
///     4.7) Challenge's proof_r (32 bytes for leaf_r and 32 bytes per path_r sibling)
pub(crate) struct SynthProofs;

impl SynthProofs {
    /// Serializes and writes synthetic proofs `proofs` into `writer`.
    pub fn write<Tree, G, W>(mut writer: W, proofs: &[Proof<Tree, G>]) -> Result<()>
    where
        Tree: MerkleTreeTrait,
        G: Hasher,
        W: Write,
    {
        // Write each Merkle root.
        let root_d = proofs[0].comm_d_proofs.root();
        let root_c = proofs[0].replica_column_proofs.c_x.inclusion_proof.root();
        let root_r = proofs[0].comm_r_last_proof.root();

        writer.write_all(root_d.as_ref())?;
        writer.write_all(root_c.as_ref())?;
        writer.write_all(root_r.as_ref())?;

        for proof in proofs {
            let proof_d = &proof.comm_d_proofs;
            let col_proof = &proof.replica_column_proofs.c_x;
            let drg_col_proofs = &proof.replica_column_proofs.drg_parents;
            let exp_col_proofs = &proof.replica_column_proofs.exp_parents;
            let proof_c = &col_proof.inclusion_proof;
            let proof_r = &proof.comm_r_last_proof;

            // Write challenge and parents.
            let challenge = proof_d.path_index() as u64;
            let parents = drg_col_proofs
                .iter()
                .chain(exp_col_proofs)
                .map(|col_proof| col_proof.inclusion_proof.path_index() as u64);

            writer.write_all(&challenge.to_le_bytes())?;
            for parent in parents {
                writer.write_all(&parent.to_le_bytes())?;
            }

            // Write challenge's `proof_d`.
            let leaf_d = proof_d.leaf();
            let path_d = proof_d.path().into_iter().map(|(sibs, _)| sibs[0]);

            writer.write_all(leaf_d.as_ref())?;
            for sib in path_d {
                writer.write_all(sib.as_ref())?;
            }

            // Write challenge's column and `proof_c`.
            let col = &col_proof.column.rows;
            let leaf_c = proof_c.leaf();
            let path_c = proof_c.path().into_iter().map(|(sibs, _)| sibs);

            for label in col {
                writer.write_all(label.as_ref())?;
            }
            writer.write_all(leaf_c.as_ref())?;
            for sibs in path_c {
                for sib in sibs {
                    writer.write_all(sib.as_ref())?;
                }
            }

            // Write each parent's column and `proof_c`.
            for col_proof in drg_col_proofs.iter().chain(exp_col_proofs) {
                let col = &col_proof.column.rows;
                let proof_c = &col_proof.inclusion_proof;
                let leaf_c = proof_c.leaf();
                let path_c = proof_c.path().into_iter().map(|(sibs, _)| sibs);

                for label in col {
                    writer.write_all(label.as_ref())?;
                }
                writer.write_all(leaf_c.as_ref())?;
                for sibs in path_c {
                    for sib in sibs {
                        writer.write_all(sib.as_ref())?;
                    }
                }
            }

            // Write challenge's `proof_r`.
            let leaf_r = proof_r.leaf();
            let path_r = proof_r.path().into_iter().map(|(sibs, _)| sibs);

            writer.write_all(leaf_r.as_ref())?;
            for sibs in path_r {
                for sib in sibs {
                    writer.write_all(sib.as_ref())?;
                }
            }
        }

        writer.flush()?;
        Ok(())
    }

    /// Reads a subset of synthetic proofs, specified by synthetic proof indexes `selected_proofs`,
    /// from `reader`.
    pub fn read<Tree, G, R>(
        mut reader: R,
        sector_nodes: usize,
        num_layers: usize,
        selected_proofs: impl Iterator<Item = usize>,
    ) -> Result<Vec<Proof<Tree, G>>>
    where
        Tree: MerkleTreeTrait,
        G: Hasher,
        R: Read + Seek,
    {
        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
        let (num_drg_parents, num_exp_parents) = (BASE_DEGREE, EXP_DEGREE);
        let num_parents = num_drg_parents + num_exp_parents;

        // Reads and deserializes a TreeD Merkle proof from reader.
        fn read_proof_d<R: Read, G: Hasher>(
            reader: &mut R,
            challenge: u64,
            root: G::Domain,
            path_len: usize,
        ) -> io::Result<MerkleProof<G, U2>> {
            let mut buf_32 = [0u8; 32];
            let leaf = reader.read_exact(&mut buf_32).map(|_| buf_32.into())?;
            let path = (0..path_len)
                .map(|i| {
                    let index = (challenge >> i) & 1;
                    let sib = reader.read_exact(&mut buf_32).map(|_| buf_32.into())?;
                    Ok((vec![sib], index as usize))
                })
                .collect::<io::Result<Vec<_>>>()?;
            Ok(MerkleProof::from_parts(leaf, root, path))
        }

        let base_arity = Tree::Arity::to_usize();
        let sub_arity = Tree::SubTreeArity::to_usize();
        let top_arity = Tree::TopTreeArity::to_usize();

        let has_sub = (sub_arity != 0) as usize;
        let has_top = (top_arity != 0) as usize;

        let base_bit_len = base_arity.trailing_zeros() as usize;
        let sub_bit_len = has_sub * sub_arity.trailing_zeros() as usize;
        let top_bit_len = has_top * top_arity.trailing_zeros() as usize;
        let base_path_r_len = (challenge_bit_len - sub_bit_len - top_bit_len) / base_bit_len;
        let path_r_len = base_path_r_len + has_sub + has_top;

        let (path_r_sibs, path_r_bit_masks): (Vec<usize>, Vec<u64>) = iter::repeat(base_arity)
            .take(base_path_r_len)
            .chain([sub_arity, top_arity])
            .take(path_r_len)
            .map(|arity| {
                let arity_minus_1 = arity - 1;
                (arity_minus_1, arity_minus_1 as u64)
            })
            .unzip();

        let path_r_bit_lens: Vec<usize> = iter::repeat(base_bit_len)
            .take(base_path_r_len)
            .chain([sub_bit_len, top_bit_len])
            .take(path_r_len)
            .collect();

        // Returns the TreeC/TreeR Merkle path indices corresponding to `challenge`.
        #[inline]
        fn path_r_indexes(
            mut challenge: u64,
            path_r_bit_masks: &[u64],
            path_r_bit_lens: &[usize],
        ) -> Vec<usize> {
            path_r_bit_masks
                .iter()
                .zip(path_r_bit_lens)
                .map(|(mask, bit_len)| {
                    let index = challenge & mask;
                    challenge >>= bit_len;
                    index as usize
                })
                .collect()
        }

        // Reads and deserializes a TreeC/TreeR Merkle proof from reader.
        fn read_proof_r<R: Read, Tree: MerkleTreeTrait>(
            reader: &mut R,
            path_indexes: &[usize],
            root: <Tree::Hasher as Hasher>::Domain,
            path_r_sibs: &[usize],
        ) -> io::Result<
            MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
        > {
            let mut buf_32 = [0u8; 32];
            let leaf = reader.read_exact(&mut buf_32).map(|_| buf_32.into())?;
            let path = path_r_sibs
                .iter()
                .zip(path_indexes)
                .map(|(&num_sibs, &index)| {
                    let sibs = (0..num_sibs)
                        .map(|_| reader.read_exact(&mut buf_32).map(|_| buf_32.into()))
                        .collect::<io::Result<Vec<_>>>()?;
                    Ok((sibs, index))
                })
                .collect::<io::Result<Vec<_>>>()?;
            Ok(MerkleProof::from_parts(leaf, root, path))
        }

        // Reads and deserializes a column proof (a column and TreeC Merkle proof) from `reader`.
        #[allow(clippy::type_complexity)]
        fn read_col_proof<R: Read, Tree: MerkleTreeTrait>(
            reader: &mut R,
            challenge: u64,
            path_indexes: &[usize],
            root: <Tree::Hasher as Hasher>::Domain,
            path_r_sibs: &[usize],
            num_layers: usize,
        ) -> io::Result<
            ColumnProof<
                MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >,
        > {
            let mut buf_32 = [0u8; 32];
            let col = (0..num_layers)
                .map(|_| reader.read_exact(&mut buf_32).map(|_| buf_32.into()))
                .collect::<io::Result<Vec<_>>>()?;
            let proof_c = read_proof_r::<R, Tree>(reader, path_indexes, root, path_r_sibs)?;
            Ok(ColumnProof::new(challenge as u32, col, proof_c))
        }

        // Read Merkle roots.
        reader.rewind()?;
        let mut buf_32 = [0u8; 32];
        let root_d = reader.read_exact(&mut buf_32).map(|_| buf_32.into())?;
        let root_c = reader.read_exact(&mut buf_32).map(|_| buf_32.into())?;
        let root_r = reader.read_exact(&mut buf_32).map(|_| buf_32.into())?;

        let roots_size = 3 * NODE_SIZE;
        let proof_size = Self::proof_size::<Tree>(sector_nodes, num_layers);

        selected_proofs
            .map(|proof_index| {
                let offset = roots_size + proof_index * proof_size;
                reader.seek(SeekFrom::Start(offset as u64))?;

                let mut buf_8 = [0u8; 8];
                let challenge = reader
                    .read_exact(&mut buf_8)
                    .map(|_| u64::from_le_bytes(buf_8))?;
                let parents = (0..num_parents)
                    .map(|_| {
                        reader
                            .read_exact(&mut buf_8)
                            .map(|_| u64::from_le_bytes(buf_8))
                    })
                    .collect::<io::Result<Vec<u64>>>()?;

                let proof_d =
                    read_proof_d::<R, G>(&mut reader, challenge, root_d, challenge_bit_len)?;

                let challenge_path_indexes =
                    path_r_indexes(challenge, &path_r_bit_masks, &path_r_bit_lens);

                let col_proof = read_col_proof::<R, Tree>(
                    &mut reader,
                    challenge,
                    &challenge_path_indexes,
                    root_c,
                    &path_r_sibs,
                    num_layers,
                )?;

                let mut parent_col_proofs = parents.into_iter().map(|parent| {
                    read_col_proof::<R, Tree>(
                        &mut reader,
                        parent,
                        &path_r_indexes(parent, &path_r_bit_masks, &path_r_bit_lens),
                        root_c,
                        &path_r_sibs,
                        num_layers,
                    )
                });
                let drg_col_proofs = (&mut parent_col_proofs)
                    .take(num_drg_parents)
                    .collect::<io::Result<_>>()?;
                let exp_col_proofs = parent_col_proofs.collect::<io::Result<_>>()?;

                let proof_r = read_proof_r::<R, Tree>(
                    &mut reader,
                    &challenge_path_indexes,
                    root_r,
                    &path_r_sibs,
                )?;

                Ok(Proof::from_parts(
                    proof_d,
                    col_proof,
                    drg_col_proofs,
                    exp_col_proofs,
                    proof_r,
                ))
            })
            .collect()
    }

    /// Returns the size of a single challenge's serialized synthetic proof.
    pub fn proof_size<Tree: MerkleTreeTrait>(sector_nodes: usize, num_layers: usize) -> usize {
        // The number of node indices associated with each challenge proof: one node index for the
        // challenge and one for each of the challenge's parents.
        let num_merkle_challenges = 1 + BASE_DEGREE + EXP_DEGREE;

        // The number of 32-byte nodes in a TreeD Merkle proof. Add one node for leaf_d to path_d's
        // length.
        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
        let proof_d_nodes = 1 + challenge_bit_len;

        // The number of 32-byte nodes in a TreeC/TreeR Merkle proof.
        let proof_r_nodes = {
            let base_arity = Tree::Arity::to_usize();
            let sub_arity = Tree::SubTreeArity::to_usize();
            let top_arity = Tree::TopTreeArity::to_usize();

            let base_arity_bit_len = base_arity.trailing_zeros() as usize;
            let sub_arity_bit_len = (sub_arity != 0) as usize * sub_arity.trailing_zeros() as usize;
            let top_arity_bit_len = (top_arity != 0) as usize * top_arity.trailing_zeros() as usize;
            let base_path_len =
                (challenge_bit_len - sub_arity_bit_len - top_arity_bit_len) / base_arity_bit_len;

            let base_path_nodes = base_path_len * (base_arity - 1);
            let sub_path_nodes = sub_arity.saturating_sub(1);
            let top_path_nodes = top_arity.saturating_sub(1);
            // Add one node for leaf_r to path_r's length.
            1 + base_path_nodes + sub_path_nodes + top_path_nodes
        };

        // A column proof is comprised of a column (of `num_layers` nodes) and a TreeC Merkle proof.
        let col_proof_nodes = num_layers + proof_r_nodes;

        let total_proof_nodes =
            proof_d_nodes + num_merkle_challenges * col_proof_nodes + proof_r_nodes;

        num_merkle_challenges * mem::size_of::<u64>() + total_proof_nodes * NODE_SIZE
    }
}

pub type TransformedLayers<Tree, G> = (
    Tau<<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain, <G as Hasher>::Domain>,
    PersistentAux<<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain>,
    TemporaryAux<Tree, G>,
);

/// Tau for a single parition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tau<D: Domain, E: Domain> {
    #[serde(bound = "")]
    pub comm_d: E,
    #[serde(bound = "")]
    pub comm_r: D,
}

/// Stored along side the sector on disk.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PersistentAux<D> {
    pub comm_c: D,
    pub comm_r_last: D,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TemporaryAux<Tree: MerkleTreeTrait, G: Hasher> {
    /// The encoded nodes for 1..layers.
    #[serde(bound(
        serialize = "StoreConfig: Serialize",
        deserialize = "StoreConfig: Deserialize<'de>"
    ))]
    pub labels: Labels<Tree>,
    pub tree_d_config: StoreConfig,
    pub tree_r_last_config: StoreConfig,
    pub tree_c_config: StoreConfig,
    pub _g: PhantomData<G>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for TemporaryAux<Tree, G> {
    fn clone(&self) -> Self {
        Self {
            labels: self.labels.clone(),
            tree_d_config: self.tree_d_config.clone(),
            tree_r_last_config: self.tree_r_last_config.clone(),
            tree_c_config: self.tree_c_config.clone(),
            _g: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> TemporaryAux<Tree, G> {
    /// Create a new instance based on default values.
    #[cfg(feature = "fixed-rows-to-discard")]
    pub fn new(sector_nodes: usize, num_layers: usize, cache_path: PathBuf) -> Self {
        use merkletree::merkle::get_merkle_tree_len;
        use storage_proofs_core::{cache_key::CacheKey, util};

        let labels = (1..=num_layers)
            .map(|layer| StoreConfig {
                path: cache_path.clone(),
                id: CacheKey::label_layer(layer),
                size: Some(sector_nodes),
                rows_to_discard: 0,
            })
            .collect();

        let tree_d_size = get_merkle_tree_len(sector_nodes, BINARY_ARITY)
            .expect("Tree must have enough leaves and have an arity of power of two");
        let tree_d_config = StoreConfig {
            path: cache_path.clone(),
            id: CacheKey::CommDTree.to_string(),
            size: Some(tree_d_size),
            rows_to_discard: 0,
        };

        let tree_count = get_base_tree_count::<Tree>();
        let tree_nodes = sector_nodes / tree_count;
        let tree_size = get_merkle_tree_len(tree_nodes, Tree::Arity::to_usize())
            .expect("Tree must have enough leaves and have an arity of power of two");

        let tree_r_last_config = StoreConfig {
            path: cache_path.clone(),
            id: CacheKey::CommRLastTree.to_string(),
            size: Some(tree_size),
            rows_to_discard: util::default_rows_to_discard(tree_nodes, Tree::Arity::to_usize()),
        };

        let tree_c_config = StoreConfig {
            path: cache_path,
            id: CacheKey::CommCTree.to_string(),
            size: Some(tree_size),
            rows_to_discard: 0,
        };

        Self {
            labels: Labels::new(labels),
            tree_d_config,
            tree_r_last_config,
            tree_c_config,
            _g: PhantomData,
        }
    }

    pub fn set_cache_path<P: AsRef<Path>>(&mut self, cache_path: P) {
        let cp = cache_path.as_ref().to_path_buf();
        for label in self.labels.labels.iter_mut() {
            label.path = cp.clone();
        }
        self.tree_d_config.path = cp.clone();
        self.tree_r_last_config.path = cp.clone();
        self.tree_c_config.path = cp;
    }

    pub fn labels_for_layer(
        &self,
        layer: usize,
    ) -> Result<DiskStore<<Tree::Hasher as Hasher>::Domain>> {
        self.labels.labels_for_layer(layer)
    }

    pub fn domain_node_at_layer(
        &self,
        layer: usize,
        node_index: u32,
    ) -> Result<<Tree::Hasher as Hasher>::Domain> {
        self.labels_for_layer(layer)?.read_at(node_index as usize)
    }

    pub fn column(&self, column_index: u32) -> Result<Column<Tree::Hasher>> {
        self.labels.column(column_index)
    }

    pub fn synth_proofs_path(&self) -> PathBuf {
        self.tree_d_config.path.clone().join(format!(
            "{}.{}",
            SYNTHETIC_POREP_VANILLA_PROOFS_KEY, SYNTHETIC_POREP_VANILLA_PROOFS_EXT
        ))
    }
}

#[derive(Debug)]
pub struct TemporaryAuxCache<Tree: MerkleTreeTrait, G: Hasher> {
    /// The encoded nodes for 1..layers.
    pub labels: LabelsCache<Tree>,
    pub tree_d: Option<BinaryMerkleTree<G>>,

    // Notably this is a LevelCacheTree instead of a full merkle.
    pub tree_r_last: LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,

    // Store the 'rows_to_discard' value from the tree_r_last
    // StoreConfig for later use (i.e. proof generation).
    pub tree_r_last_config_rows_to_discard: usize,

    pub tree_c: Option<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>,
    pub t_aux: TemporaryAux<Tree, G>,
    pub replica_path: PathBuf,
}

impl<Tree: MerkleTreeTrait, G: Hasher> TemporaryAuxCache<Tree, G> {
    pub fn new(
        t_aux: &TemporaryAux<Tree, G>,
        replica_path: PathBuf,
        skip_labels: bool,
    ) -> Result<Self> {
        let tree_count = get_base_tree_count::<Tree>();

        // Skip Labels is true in the case of SyntheticPoRep which doesn't need the labels nor TreeD/TreeC
        let (tree_d, tree_c) = if skip_labels {
            (None, None)
        } else {
            // tree_d_size stored in the config is the base tree size
            let tree_d_size = t_aux.tree_d_config.size.expect("config size failure");
            let tree_d_leafs = get_merkle_tree_leafs(tree_d_size, BINARY_ARITY)?;
            trace!(
                "Instantiating tree d with size {} and leafs {}",
                tree_d_size,
                tree_d_leafs,
            );
            let tree_d_store: DiskStore<G::Domain> =
                DiskStore::new_from_disk(tree_d_size, BINARY_ARITY, &t_aux.tree_d_config)
                    .context("tree_d_store")?;
            let tree_d = BinaryMerkleTree::<G>::from_data_store(tree_d_store, tree_d_leafs)
                .context("tree_d")?;

            let configs = split_config(t_aux.tree_c_config.clone(), tree_count)?;

            // tree_c_size stored in the config is the base tree size
            let tree_c_size = t_aux.tree_c_config.size.expect("config size failure");
            trace!(
                "Instantiating tree c [count {}] with size {} and arity {}",
                tree_count,
                tree_c_size,
                Tree::Arity::to_usize(),
            );
            let tree_c = create_disk_tree::<
                DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >(tree_c_size, &configs)?;

            (Some(tree_d), Some(tree_c))
        };

        // tree_r_last_size stored in the config is the base tree size
        let tree_r_last_size = t_aux.tree_r_last_config.size.expect("config size failure");
        let tree_r_last_config_rows_to_discard = t_aux.tree_r_last_config.rows_to_discard;
        let (configs, replica_config) = split_config_and_replica(
            t_aux.tree_r_last_config.clone(),
            replica_path.clone(),
            get_merkle_tree_leafs(tree_r_last_size, Tree::Arity::to_usize())?,
            tree_count,
        )?;

        trace!(
            "Instantiating tree r last [count {}] with size {} and arity {}, {}, {}",
            tree_count,
            tree_r_last_size,
            Tree::Arity::to_usize(),
            Tree::SubTreeArity::to_usize(),
            Tree::TopTreeArity::to_usize(),
        );
        let tree_r_last = create_lc_tree::<
            LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
        >(tree_r_last_size, &configs, &replica_config)?;

        // Skipping labels is for when SyntheticPoRep is used and the labels no longer exist.
        if skip_labels {
            trace!("Skipping label instantiation");
            Ok(TemporaryAuxCache {
                labels: LabelsCache::new(&Labels::new(Vec::new())).context("labels_cache")?,
                tree_d: None, //tree_d,
                tree_r_last,
                tree_r_last_config_rows_to_discard,
                tree_c: None, //tree_c,
                replica_path,
                t_aux: t_aux.clone(),
            })
        } else {
            Ok(TemporaryAuxCache {
                labels: LabelsCache::new(&t_aux.labels).context("labels_cache")?,
                tree_d,
                tree_r_last,
                tree_r_last_config_rows_to_discard,
                tree_c,
                replica_path,
                t_aux: t_aux.clone(),
            })
        }
    }

    pub fn labels_for_layer(&self, layer: usize) -> &DiskStore<<Tree::Hasher as Hasher>::Domain> {
        self.labels.labels_for_layer(layer)
    }

    pub fn domain_node_at_layer(
        &self,
        layer: usize,
        node_index: u32,
    ) -> Result<<Tree::Hasher as Hasher>::Domain> {
        self.labels_for_layer(layer).read_at(node_index as usize)
    }

    pub fn column(&self, column_index: u32) -> Result<Column<Tree::Hasher>> {
        self.labels.column(column_index)
    }

    pub fn synth_proofs_path(&self) -> PathBuf {
        self.t_aux.synth_proofs_path()
    }
}

type VerifyCallback = fn(&StoreConfig, usize, usize) -> Result<()>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Labels<Tree: MerkleTreeTrait> {
    #[serde(bound(
        serialize = "StoreConfig: Serialize",
        deserialize = "StoreConfig: Deserialize<'de>"
    ))]
    pub labels: Vec<StoreConfig>,
    pub _h: PhantomData<Tree>,
}

impl<Tree: MerkleTreeTrait> Clone for Labels<Tree> {
    fn clone(&self) -> Self {
        Self {
            labels: self.labels.clone(),
            _h: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait> Labels<Tree> {
    pub fn new(labels: Vec<StoreConfig>) -> Self {
        Labels {
            labels,
            _h: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn verify_stores(&self, callback: VerifyCallback, cache_dir: &Path) -> Result<()> {
        let updated_path_labels = self.labels.clone();
        let required_configs = get_base_tree_count::<Tree>();
        for mut label in updated_path_labels {
            label.path = cache_dir.to_path_buf();
            callback(&label, BINARY_ARITY, required_configs)?;
        }

        Ok(())
    }

    pub fn labels_for_layer(
        &self,
        layer: usize,
    ) -> Result<DiskStore<<Tree::Hasher as Hasher>::Domain>> {
        assert!(layer != 0, "Layer cannot be 0");
        assert!(
            layer <= self.layers(),
            "Layer {} is not available (only {} layers available)",
            layer,
            self.layers()
        );

        let row_index = layer - 1;
        let config = self.labels[row_index].clone();
        assert!(config.size.is_some());

        DiskStore::new_from_disk(
            config.size.expect("config size failure"),
            Tree::Arity::to_usize(),
            &config,
        )
    }

    /// Returns label for the last layer.
    pub fn labels_for_last_layer(&self) -> Result<DiskStore<<Tree::Hasher as Hasher>::Domain>> {
        self.labels_for_layer(self.labels.len())
    }

    /// How many layers are available.
    fn layers(&self) -> usize {
        self.labels.len()
    }

    /// Build the column for the given node.
    pub fn column(&self, node: u32) -> Result<Column<Tree::Hasher>> {
        let rows = self
            .labels
            .iter()
            .map(|label| {
                assert!(label.size.is_some());
                let store = DiskStore::new_from_disk(
                    label.size.expect("label size failure"),
                    Tree::Arity::to_usize(),
                    label,
                )?;
                store.read_at(node as usize)
            })
            .collect::<Result<_>>()?;

        Column::new(node, rows)
    }

    /// Update all configs to the new passed in root cache path.
    pub fn update_root<P: AsRef<Path>>(&mut self, root: P) {
        for config in &mut self.labels {
            config.path = root.as_ref().into();
        }
    }
}

#[derive(Debug)]
pub struct LabelsCache<Tree: MerkleTreeTrait> {
    pub labels: Vec<DiskStore<<Tree::Hasher as Hasher>::Domain>>,
}

impl<Tree: MerkleTreeTrait> LabelsCache<Tree> {
    pub fn new(labels: &Labels<Tree>) -> Result<Self> {
        let mut disk_store_labels: Vec<DiskStore<<Tree::Hasher as Hasher>::Domain>> =
            Vec::with_capacity(labels.len());
        for i in 0..labels.len() {
            trace!("Instantiating label {}", i);
            disk_store_labels.push(labels.labels_for_layer(i + 1)?);
        }

        Ok(LabelsCache {
            labels: disk_store_labels,
        })
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn labels_for_layer(&self, layer: usize) -> &DiskStore<<Tree::Hasher as Hasher>::Domain> {
        assert!(layer != 0, "Layer cannot be 0");
        assert!(
            layer <= self.layers(),
            "Layer {} is not available (only {} layers available)",
            layer,
            self.layers()
        );

        let row_index = layer - 1;
        &self.labels[row_index]
    }

    /// Returns the labels on the last layer.
    pub fn labels_for_last_layer(&self) -> Result<&DiskStore<<Tree::Hasher as Hasher>::Domain>> {
        Ok(&self.labels[self.labels.len() - 1])
    }

    /// How many layers are available.
    fn layers(&self) -> usize {
        self.labels.len()
    }

    /// Build the column for the given node.
    pub fn column(&self, node: u32) -> Result<Column<Tree::Hasher>> {
        let rows = self
            .labels
            .iter()
            .map(|labels| labels.read_at(node as usize))
            .collect::<Result<_>>()?;

        Column::new(node, rows)
    }
}

pub fn get_node<H: Hasher>(data: &[u8], index: usize) -> Result<H::Domain> {
    H::Domain::try_from_bytes(data_at_node(data, index).expect("invalid node math"))
}

/// Generate the replica id as expected for Stacked DRG.
pub fn generate_replica_id<H: Hasher, T: AsRef<[u8]>>(
    prover_id: &[u8; 32],
    sector_id: u64,
    ticket: &[u8; 32],
    comm_d: T,
    porep_seed: &[u8; 32],
) -> H::Domain {
    let hash = Sha256::new()
        .chain_update(prover_id)
        .chain_update(sector_id.to_be_bytes())
        .chain_update(ticket)
        .chain_update(&comm_d)
        .chain_update(porep_seed)
        .finalize();

    bytes_into_fr_repr_safe(hash.as_ref()).into()
}

#[cfg(test)]
mod tests {
    use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher};
    use generic_array::typenum::{U0, U2, U8};
    use storage_proofs_core::{
        api_version::ApiVersion, drgraph::BASE_DEGREE, merkle::DiskTree,
        parameter_cache::ParameterSetMetadata, proof::ProofScheme, util::NODE_SIZE,
    };

    use crate::stacked::{LayerChallenges, SetupParams, StackedDrg, EXP_DEGREE};

    // The identifier is used for the parameter file filenames. It must not change, as the
    // filenames are fixed for the official parameter files. Hence staticly assert certain
    // identifiers.
    #[test]
    fn test_public_params_identifier() {
        type OctTree32Gib = DiskTree<PoseidonHasher, U8, U8, U0>;
        let setup_params_32gib = SetupParams {
            nodes: 32 * 1024 * 1024 * 1024 / NODE_SIZE,
            degree: BASE_DEGREE,
            expansion_degree: EXP_DEGREE,
            porep_id: [1u8; 32],
            challenges: LayerChallenges::new(18),
            num_layers: 11,
            api_version: ApiVersion::V1_1_0,
            api_features: vec![],
        };
        let public_params_32gib =
            StackedDrg::<OctTree32Gib, Sha256Hasher>::setup(&setup_params_32gib)
                .expect("setup failed");
        assert_eq!(public_params_32gib.identifier(), "layered_drgporep::PublicParams{ graph: stacked_graph::StackedGraph{expansion_degree: 8 base_graph: drgraph::BucketGraph{size: 1073741824; degree: 6; hasher: poseidon_hasher} }, challenges: LayerChallenges { layers: 11, max_count: 18 }, tree: merkletree-poseidon_hasher-8-8-0 }");

        type OctTree64Gib = DiskTree<PoseidonHasher, U8, U8, U2>;
        let setup_params_64gib = SetupParams {
            nodes: 64 * 1024 * 1024 * 1024 / NODE_SIZE,
            degree: BASE_DEGREE,
            expansion_degree: EXP_DEGREE,
            porep_id: [1u8; 32],
            challenges: LayerChallenges::new(18),
            num_layers: 11,
            api_version: ApiVersion::V1_1_0,
            api_features: vec![],
        };
        let public_params_64gib =
            StackedDrg::<OctTree64Gib, Sha256Hasher>::setup(&setup_params_64gib)
                .expect("setup failed");
        assert_eq!(public_params_64gib.identifier(), "layered_drgporep::PublicParams{ graph: stacked_graph::StackedGraph{expansion_degree: 8 base_graph: drgraph::BucketGraph{size: 2147483648; degree: 6; hasher: poseidon_hasher} }, challenges: LayerChallenges { layers: 11, max_count: 18 }, tree: merkletree-poseidon_hasher-8-8-2 }");
    }
}
