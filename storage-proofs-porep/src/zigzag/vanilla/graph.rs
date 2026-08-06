use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use std::convert::TryInto;

use anyhow::ensure;
use filecoin_hashers::Hasher;
use fr32::bytes_into_fr_repr_safe;
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    api_version::ApiVersion,
    crypto::{
        derive_porep_domain_seed,
        feistel::{self, FeistelPrecomputed},
        FEISTEL_DST,
    },
    drgraph::{BucketGraph, Graph, BASE_DEGREE},
    error::Result,
    parameter_cache::ParameterSetMetadata,
    util::{data_at_node_offset, NODE_SIZE},
    PoRepID,
};

/// The expansion degree used for ZigZag Graphs.
pub const EXP_DEGREE: usize = 8;

#[allow(dead_code)]
pub(crate) const DEGREE: usize = BASE_DEGREE + EXP_DEGREE;

fn derive_feistel_keys(porep_id: PoRepID) -> [u64; 4] {
    let mut feistel_keys = [0u64; 4];
    let raw_seed = derive_porep_domain_seed(FEISTEL_DST, porep_id);
    feistel_keys[0] = u64::from_le_bytes(raw_seed[0..8].try_into().expect("from_le_bytes failure"));
    feistel_keys[1] =
        u64::from_le_bytes(raw_seed[8..16].try_into().expect("from_le_bytes failure"));
    feistel_keys[2] =
        u64::from_le_bytes(raw_seed[16..24].try_into().expect("from_le_bytes failure"));
    feistel_keys[3] =
        u64::from_le_bytes(raw_seed[24..32].try_into().expect("from_le_bytes failure"));
    feistel_keys
}

/// A ZigZag graph.
///
/// A ZigZag graph is a DRG base graph plus a reversible Feistel-based expansion component. Between
/// layers the graph is "reversed" (toggling `reversed`), which flips the direction of both the base
/// DRG edges (via `real_index`) and the expansion edges (via `invert_permute`). This is the defining
/// property that distinguishes ZigZag from Stacked DRG, which only ever layers forward.
#[derive(Clone)]
pub struct ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + 'static,
{
    expansion_degree: usize,
    base_graph: G,
    pub reversed: bool,
    feistel_keys: [feistel::Index; 4],
    feistel_precomputed: FeistelPrecomputed,
    id: String,
    _h: PhantomData<H>,
}

impl<H, G> Debug for ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZigZagGraph")
            .field("expansion_degree", &self.expansion_degree)
            .field("base_graph", &self.base_graph)
            .field("reversed", &self.reversed)
            .field("feistel_precomputed", &self.feistel_precomputed)
            .field("id", &self.id)
            .finish()
    }
}

pub type ZigZagBucketGraph<H> = ZigZagGraph<H, BucketGraph<H>>;

impl<H, G> ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    pub fn new_zigzag(
        base_graph: Option<G>,
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
        api_version: ApiVersion,
    ) -> Result<Self> {
        assert_eq!(base_degree, BASE_DEGREE);
        assert_eq!(expansion_degree, EXP_DEGREE);
        ensure!(nodes <= u32::MAX as usize, "too many nodes");

        let base_graph = match base_graph {
            Some(graph) => graph,
            None => G::new(nodes, base_degree, 0, porep_id, api_version)?,
        };

        let bg_id = base_graph.identifier();
        let feistel_keys = derive_feistel_keys(porep_id);

        Ok(ZigZagGraph {
            id: format!(
                "zigzag_graph::ZigZagGraph{{expansion_degree: {} base_graph: {} reversed: {} }}",
                expansion_degree, bg_id, false,
            ),
            base_graph,
            expansion_degree,
            reversed: false,
            feistel_keys,
            feistel_precomputed: feistel::precompute((expansion_degree * nodes) as feistel::Index),
            _h: PhantomData,
        })
    }

    /// To zigzag a graph, we just toggle its `reversed` field. All the real work happens when we
    /// calculate node parents on demand.
    pub fn zigzag(&self) -> Self {
        let mut zigzag = self.clone();
        zigzag.reversed = !zigzag.reversed;
        zigzag.id = format!(
            "zigzag_graph::ZigZagGraph{{expansion_degree: {} base_graph: {} reversed: {} }}",
            zigzag.expansion_degree,
            zigzag.base_graph.identifier(),
            zigzag.reversed,
        );
        zigzag
    }

    pub fn base_graph(&self) -> &G {
        &self.base_graph
    }

    pub fn expansion_degree(&self) -> usize {
        self.expansion_degree
    }

    pub fn reversed(&self) -> bool {
        self.reversed
    }

    #[inline]
    pub fn forward(&self) -> bool {
        !self.reversed
    }

    /// When the graph is reversed, indices are mirrored around the center of the node range.
    #[inline]
    pub fn real_index(&self, i: usize) -> usize {
        if self.reversed {
            (self.size() - 1) - i
        } else {
            i
        }
    }

    /// Assign `expansion_degree` parents to `node` using an invertible permutation. The permutation
    /// is applied in the forward direction for forward layers, and inverted for reversed layers,
    /// which is what guarantees the expansion edges are exactly reversed between layers.
    fn correspondent(&self, node: usize, i: usize) -> usize {
        let a = (node * self.expansion_degree) as feistel::Index + i as feistel::Index;
        let feistel_domain =
            self.size() as feistel::Index * self.expansion_degree as feistel::Index;

        let transformed = if self.reversed {
            feistel::invert_permute(
                feistel_domain,
                a,
                &self.feistel_keys,
                self.feistel_precomputed,
            )
        } else {
            feistel::permute(
                feistel_domain,
                a,
                &self.feistel_keys,
                self.feistel_precomputed,
            )
        };
        transformed as usize / self.expansion_degree
    }

    fn generate_expanded_parents(&self, node: usize) -> Vec<u32> {
        (0..self.expansion_degree)
            .filter_map(|i| {
                let other = self.correspondent(node, i);
                if self.reversed {
                    if other > node {
                        Some(other as u32)
                    } else {
                        None
                    }
                } else if other < node {
                    Some(other as u32)
                } else {
                    None
                }
            })
            .collect()
    }
}

impl<H, G> ParameterSetMetadata for ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    fn identifier(&self) -> String {
        self.id.clone()
    }

    fn sector_size(&self) -> u64 {
        self.base_graph.sector_size()
    }
}

impl<H, G> Graph<H> for ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    type Key = H::Domain;

    fn size(&self) -> usize {
        self.base_graph.size()
    }

    fn degree(&self) -> usize {
        self.base_graph.degree() + self.expansion_degree
    }

    #[inline]
    fn parents(&self, raw_node: usize, parents: &mut [u32]) -> Result<()> {
        let base_degree = self.base_graph.degree();

        // If the graph is reversed, use `real_index` to convert the requested (reversed) index to
        // its unreversed counterpart, calculate the base parents there, then map the parents back to
        // the reversed index space.
        self.base_graph
            .parents(self.real_index(raw_node), &mut parents[..base_degree])?;
        for parent in parents.iter_mut().take(base_degree) {
            *parent = self.real_index(*parent as usize) as u32;
        }

        let expanded_parents = self.generate_expanded_parents(raw_node);
        for (ii, value) in expanded_parents.iter().enumerate() {
            parents[base_degree + ii] = *value;
        }

        // Pad so all nodes have the correct degree.
        let current_length = base_degree + expanded_parents.len();
        let pad_value = if self.reversed {
            (self.size() - 1) as u32
        } else {
            0
        };
        for parent in parents.iter_mut().take(self.degree()).skip(current_length) {
            *parent = pad_value;
        }

        debug_assert_eq!(parents.len(), self.degree());

        if self.forward() {
            parents.sort_unstable();
        } else {
            parents.sort_unstable_by(|a, b| a.cmp(b).reverse());
        }

        Ok(())
    }

    fn seed(&self) -> [u8; 28] {
        self.base_graph.seed()
    }

    fn new(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
        api_version: ApiVersion,
    ) -> Result<Self> {
        Self::new_zigzag(
            None,
            nodes,
            base_degree,
            expansion_degree,
            porep_id,
            api_version,
        )
    }

    fn create_key(
        &self,
        id: &H::Domain,
        node: usize,
        parents: &[u32],
        base_parents_data: &[u8],
        _exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key> {
        let mut hasher = Sha256::new();
        hasher.update(AsRef::<[u8]>::as_ref(id));

        // The hash is about the parents, hence skip if a node doesn't have any parents.
        if node != parents[0] as usize {
            for parent in parents.iter() {
                let offset = data_at_node_offset(*parent as usize);
                hasher.update(&base_parents_data[offset..offset + NODE_SIZE]);
            }
        }

        let hash = hasher.finalize();
        Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
    }
}

impl<H, G> PartialEq for ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H>,
{
    fn eq(&self, other: &ZigZagGraph<H, G>) -> bool {
        self.base_graph == other.base_graph
            && self.expansion_degree == other.expansion_degree
            && self.reversed == other.reversed
    }
}

impl<H, G> Eq for ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H>,
{
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    use filecoin_hashers::poseidon::PoseidonHasher;

    // Ensure that toggling `reversed` twice returns to the original direction and parent structure.
    #[test]
    fn zigzag_reverse_involution() {
        let nodes = 256;
        let porep_id = [1u8; 32];
        let g: ZigZagBucketGraph<PoseidonHasher> =
            ZigZagGraph::new_zigzag(None, nodes, BASE_DEGREE, EXP_DEGREE, porep_id, ApiVersion::V1_2_0)
                .expect("failed to create graph");

        let reversed = g.zigzag();
        let back = reversed.zigzag();

        assert!(!g.reversed());
        assert!(reversed.reversed());
        assert!(!back.reversed());

        let mut p_forward = vec![0u32; g.degree()];
        let mut p_back = vec![0u32; g.degree()];
        for node in 0..nodes {
            g.parents(node, &mut p_forward).expect("parents failed");
            back.parents(node, &mut p_back).expect("parents failed");
            assert_eq!(p_forward, p_back, "double reverse changed parents at {}", node);
        }
    }

    // In the forward direction, every parent index must be <= the node; in the reverse direction,
    // every parent index must be >= the node. This is the core ZigZag directionality invariant.
    #[test]
    fn zigzag_parent_directionality() {
        let nodes = 256;
        let porep_id = [2u8; 32];
        let forward: ZigZagBucketGraph<PoseidonHasher> =
            ZigZagGraph::new_zigzag(None, nodes, BASE_DEGREE, EXP_DEGREE, porep_id, ApiVersion::V1_2_0)
                .expect("failed to create graph");
        let reversed = forward.zigzag();

        let mut parents = vec![0u32; forward.degree()];

        for node in 0..nodes {
            forward.parents(node, &mut parents).expect("parents failed");
            assert!(
                parents.iter().all(|p| *p as usize <= node),
                "forward parent exceeded node {}",
                node
            );

            reversed.parents(node, &mut parents).expect("parents failed");
            assert!(
                parents.iter().all(|p| *p as usize >= node),
                "reverse parent below node {}",
                node
            );
        }
    }

    #[test]
    fn zigzag_expansion_reciprocity() {
        // A forward expansion edge (node -> parent) should appear as a reverse expansion edge
        // (parent -> node) after reversal, confirming the expansion component is truly inverted.
        let nodes = 64;
        let porep_id = [3u8; 32];
        let forward: ZigZagBucketGraph<PoseidonHasher> =
            ZigZagGraph::new_zigzag(None, nodes, BASE_DEGREE, EXP_DEGREE, porep_id, ApiVersion::V1_2_0)
                .expect("failed to create graph");
        let reversed = forward.zigzag();

        // Collect forward expansion edges as (child, parent) pairs.
        let mut forward_edges = HashSet::new();
        for node in 0..nodes {
            for parent in forward.generate_expanded_parents(node) {
                forward_edges.insert((node, parent as usize));
            }
        }

        // Each reverse expansion edge (node, parent) must correspond to a forward edge (parent, node).
        for node in 0..nodes {
            for parent in reversed.generate_expanded_parents(node) {
                assert!(
                    forward_edges.contains(&(parent as usize, node)),
                    "reverse edge ({}, {}) has no forward counterpart",
                    node,
                    parent
                );
            }
        }
    }
}
