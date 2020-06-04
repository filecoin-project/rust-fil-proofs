use std::convert::TryInto;
use std::marker::PhantomData;

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use anyhow::ensure;
use log::info;
use once_cell::sync::OnceCell;
use rayon::prelude::*;
use sha2raw::Sha256;
use storage_proofs_core::{
    crypto::{
        derive_porep_domain_seed,
        feistel::{self, FeistelPrecomputed},
        FEISTEL_DST,
    },
    drgraph::BASE_DEGREE,
    drgraph::{BucketGraph, Graph},
    error::Result,
    hasher::Hasher,
    parameter_cache::ParameterSetMetadata,
    settings,
    util::NODE_SIZE,
};

/// The expansion degree used for Stacked Graphs.
pub const EXP_DEGREE: usize = 8;

const DEGREE: usize = BASE_DEGREE + EXP_DEGREE;

/// Returns a reference to the parent cache, initializing it lazily the first time this is called.
fn parent_cache<H, G>(
    cache_entries: u32,
    graph: &StackedGraph<H, G>,
) -> Result<&'static ParentCache>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Send + Sync,
{
    static INSTANCE_32_GIB: OnceCell<ParentCache> = OnceCell::new();
    static INSTANCE_64_GIB: OnceCell<ParentCache> = OnceCell::new();

    const NODE_GIB: u32 = (1024 * 1024 * 1024) / NODE_SIZE as u32;
    ensure!(
        ((cache_entries == 32 * NODE_GIB) || (cache_entries == 64 * NODE_GIB)),
        "Cache is only available for 32GiB and 64GiB sectors"
    );
    info!("using parent_cache[{}]", cache_entries);
    if cache_entries == 32 * NODE_GIB {
        Ok(INSTANCE_32_GIB.get_or_init(|| {
            ParentCache::new(cache_entries, graph).expect("failed to fill 32GiB cache")
        }))
    } else {
        Ok(INSTANCE_64_GIB.get_or_init(|| {
            ParentCache::new(cache_entries, graph).expect("failed to fill 64GiB cache")
        }))
    }
}

// StackedGraph will hold two different (but related) `ParentCache`,
#[derive(Debug, Clone)]
struct ParentCache {
    /// This is a large list of fixed (parent) sized arrays.
    /// `Vec<Vec<u32>>` was showing quite a large memory overhead, so this is layed out as a fixed boxed slice of memory.
    cache: Box<[u32]>,
}

impl ParentCache {
    pub fn new<H, G>(cache_entries: u32, graph: &StackedGraph<H, G>) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        info!("filling parents cache");
        let mut cache = vec![0u32; DEGREE * cache_entries as usize];

        let base_degree = BASE_DEGREE;
        let exp_degree = EXP_DEGREE;

        cache
            .par_chunks_mut(DEGREE)
            .enumerate()
            .try_for_each(|(node, entry)| -> Result<()> {
                graph
                    .base_graph()
                    .parents(node, &mut entry[..base_degree])?;
                graph.generate_expanded_parents(
                    node,
                    &mut entry[base_degree..base_degree + exp_degree],
                );
                Ok(())
            })?;

        info!("cache filled");

        Ok(ParentCache {
            cache: cache.into_boxed_slice(),
        })
    }

    /// Read a single cache element at position `node`.
    #[inline]
    pub fn read(&self, node: u32) -> &[u32] {
        let start = node as usize * DEGREE;
        let end = start + DEGREE;
        &self.cache[start..end]
    }
}

#[derive(Clone)]
pub struct StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + 'static,
{
    expansion_degree: usize,
    base_graph: G,
    feistel_keys: [feistel::Index; 4],
    feistel_precomputed: FeistelPrecomputed,
    id: String,
    cache: Option<&'static ParentCache>,
    _h: PhantomData<H>,
}

impl<H, G> std::fmt::Debug for StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StackedGraph")
            .field("expansion_degree", &self.expansion_degree)
            .field("base_graph", &self.base_graph)
            .field("feistel_precomputed", &self.feistel_precomputed)
            .field("id", &self.id)
            .field("cache", &self.cache)
            .finish()
    }
}

pub type StackedBucketGraph<H> = StackedGraph<H, BucketGraph<H>>;

#[inline]
fn prefetch(parents: &[u32], data: &[u8]) {
    for parent in parents {
        let start = *parent as usize * NODE_SIZE;
        let end = start + NODE_SIZE;

        unsafe {
            _mm_prefetch(data[start..end].as_ptr() as *const i8, _MM_HINT_T0);
        }
    }
}

#[inline]
fn read_node<'a>(i: usize, parents: &[u32], data: &'a [u8]) -> &'a [u8] {
    let start = parents[i] as usize * NODE_SIZE;
    let end = start + NODE_SIZE;
    &data[start..end]
}

impl<H, G> StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    pub fn new(
        base_graph: Option<G>,
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: [u8; 32],
    ) -> Result<Self> {
        assert_eq!(base_degree, BASE_DEGREE);
        assert_eq!(expansion_degree, EXP_DEGREE);
        ensure!(nodes <= std::u32::MAX as usize, "too many nodes");

        let use_cache = settings::SETTINGS.lock().unwrap().maximize_caching;

        let base_graph = match base_graph {
            Some(graph) => graph,
            None => G::new(nodes, base_degree, 0, porep_id)?,
        };
        let bg_id = base_graph.identifier();

        let mut feistel_keys = [0u64; 4];
        let raw_seed = derive_porep_domain_seed(FEISTEL_DST, porep_id);
        feistel_keys[0] = u64::from_le_bytes(raw_seed[0..8].try_into().unwrap());
        feistel_keys[1] = u64::from_le_bytes(raw_seed[8..16].try_into().unwrap());
        feistel_keys[2] = u64::from_le_bytes(raw_seed[16..24].try_into().unwrap());
        feistel_keys[3] = u64::from_le_bytes(raw_seed[24..32].try_into().unwrap());

        let mut res = StackedGraph {
            base_graph,
            id: format!(
                "stacked_graph::StackedGraph{{expansion_degree: {} base_graph: {} }}",
                expansion_degree, bg_id,
            ),
            expansion_degree,
            cache: None,
            feistel_keys,
            feistel_precomputed: feistel::precompute((expansion_degree * nodes) as feistel::Index),
            _h: PhantomData,
        };

        if use_cache {
            info!("using parents cache of unlimited size");

            let cache = parent_cache(nodes as u32, &res)?;
            res.cache = Some(cache);
        }

        Ok(res)
    }

    pub fn copy_parents_data_exp(
        &self,
        node: u32,
        base_data: &[u8],
        exp_data: &[u8],
        hasher: Sha256,
    ) -> [u8; 32] {
        if let Some(cache) = self.cache {
            let cache_parents = cache.read(node as u32);
            self.copy_parents_data_inner_exp(&cache_parents, base_data, exp_data, hasher)
        } else {
            let mut cache_parents = [0u32; DEGREE];

            self.parents(node as usize, &mut cache_parents[..]).unwrap();
            self.copy_parents_data_inner_exp(&cache_parents, base_data, exp_data, hasher)
        }
    }

    pub fn copy_parents_data(&self, node: u32, base_data: &[u8], hasher: Sha256) -> [u8; 32] {
        if let Some(cache) = self.cache {
            let cache_parents = cache.read(node as u32);
            self.copy_parents_data_inner(&cache_parents, base_data, hasher)
        } else {
            let mut cache_parents = [0u32; DEGREE];

            self.parents(node as usize, &mut cache_parents[..]).unwrap();
            self.copy_parents_data_inner(&cache_parents, base_data, hasher)
        }
    }

    fn copy_parents_data_inner_exp(
        &self,
        cache_parents: &[u32],
        base_data: &[u8],
        exp_data: &[u8],
        mut hasher: Sha256,
    ) -> [u8; 32] {
        prefetch(&cache_parents[..BASE_DEGREE], base_data);
        prefetch(&cache_parents[BASE_DEGREE..], exp_data);

        // fill buffer
        let parents = [
            read_node(0, cache_parents, base_data),
            read_node(1, cache_parents, base_data),
            read_node(2, cache_parents, base_data),
            read_node(3, cache_parents, base_data),
            read_node(4, cache_parents, base_data),
            read_node(5, cache_parents, base_data),
            read_node(6, cache_parents, exp_data),
            read_node(7, cache_parents, exp_data),
            read_node(8, cache_parents, exp_data),
            read_node(9, cache_parents, exp_data),
            read_node(10, cache_parents, exp_data),
            read_node(11, cache_parents, exp_data),
            read_node(12, cache_parents, exp_data),
            read_node(13, cache_parents, exp_data),
        ];

        // round 1 (14)
        hasher.input(&parents);

        // round 2 (14)
        hasher.input(&parents);

        // round 3 (9)
        hasher.input(&parents[..8]);
        hasher.finish_with(&parents[8])
    }

    fn copy_parents_data_inner(
        &self,
        cache_parents: &[u32],
        base_data: &[u8],
        mut hasher: Sha256,
    ) -> [u8; 32] {
        prefetch(&cache_parents[..BASE_DEGREE], base_data);

        // fill buffer
        let parents = [
            read_node(0, cache_parents, base_data),
            read_node(1, cache_parents, base_data),
            read_node(2, cache_parents, base_data),
            read_node(3, cache_parents, base_data),
            read_node(4, cache_parents, base_data),
            read_node(5, cache_parents, base_data),
        ];

        // round 1 (0..6)
        hasher.input(&parents);

        // round 2 (6..12)
        hasher.input(&parents);

        // round 3 (12..18)
        hasher.input(&parents);

        // round 4 (18..24)
        hasher.input(&parents);

        // round 5 (24..30)
        hasher.input(&parents);

        // round 6 (30..36)
        hasher.input(&parents);

        // round 7 (37)
        hasher.finish_with(parents[0])
    }
}

impl<H, G> ParameterSetMetadata for StackedGraph<H, G>
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

impl<H, G> Graph<H> for StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    type Key = Vec<u8>;

    fn size(&self) -> usize {
        self.base_graph().size()
    }

    fn degree(&self) -> usize {
        self.base_graph.degree() + self.expansion_degree
    }

    #[inline]
    fn parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
        if let Some(cache) = self.cache {
            // Read from the cache
            let cache_parents = cache.read(node as u32);
            parents.copy_from_slice(cache_parents);
        } else {
            self.base_parents(node, &mut parents[..self.base_graph().degree()])?;

            // expanded_parents takes raw_node
            self.expanded_parents(
                node,
                &mut parents[self.base_graph().degree()
                    ..self.base_graph().degree() + self.expansion_degree()],
            );
        }
        Ok(())
    }

    fn seed(&self) -> [u8; 28] {
        self.base_graph().seed()
    }

    fn new(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: [u8; 32],
    ) -> Result<Self> {
        Self::new_stacked(nodes, base_degree, expansion_degree, porep_id)
    }

    fn create_key(
        &self,
        _id: &H::Domain,
        _node: usize,
        _parents: &[u32],
        _base_parents_data: &[u8],
        _exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key> {
        unimplemented!("not used");
    }
}

impl<'a, H, G> StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    /// Assign one parent to `node` using a Chung's construction with a reversible
    /// permutation function from a Feistel cipher (controlled by `invert_permutation`).
    fn correspondent(&self, node: usize, i: usize) -> u32 {
        // We can't just generate random values between `[0, size())`, we need to
        // expand the search space (domain) to accommodate every unique parent assignment
        // generated here. This can be visualized more clearly as a matrix where the each
        // new parent of each new node is assigned a unique `index`:
        //
        //
        //          | Parent 1 | Parent 2 | Parent 3 |
        //
        // | Node 1 |     0    |     1    |     2    |
        //
        // | Node 2 |     3    |     4    |     5    |
        //
        // | Node 3 |     6    |     7    |     8    |
        //
        // | Node 4 |     9    |     A    |     B    |
        //
        // This starting `index` will be shuffled to another position to generate a
        // parent-child relationship, e.g., if generating the parents for the second node,
        // `permute` would be called with values `[3; 4; 5]` that would be mapped to other
        // indexes in the search space of `[0, B]`, say, values `[A; 0; 4]`, that would
        // correspond to nodes numbered `[4; 1, 2]` which will become the parents of the
        // second node. In a later pass invalid parents like 2, self-referencing, and parents
        // with indexes bigger than 2 (if in the `forward` direction, smaller than 2 if the
        // inverse), will be removed.
        let a = (node * self.expansion_degree) as feistel::Index + i as feistel::Index;

        let transformed = feistel::permute(
            self.size() as feistel::Index * self.expansion_degree as feistel::Index,
            a,
            &self.feistel_keys,
            self.feistel_precomputed,
        );
        transformed as u32 / self.expansion_degree as u32
        // Collapse the output in the matrix search space to the row of the corresponding
        // node (losing the column information, that will be regenerated later when calling
        // back this function in the `reversed` direction).
    }

    fn generate_expanded_parents(&self, node: usize, expanded_parents: &mut [u32]) {
        debug_assert_eq!(expanded_parents.len(), self.expansion_degree);
        for (i, el) in expanded_parents.iter_mut().enumerate() {
            *el = self.correspondent(node, i);
        }
    }

    pub fn new_stacked(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: [u8; 32],
    ) -> Result<Self> {
        Self::new(None, nodes, base_degree, expansion_degree, porep_id)
    }

    pub fn base_graph(&self) -> &G {
        &self.base_graph
    }

    pub fn expansion_degree(&self) -> usize {
        self.expansion_degree
    }

    pub fn base_parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
        if let Some(cache) = self.cache {
            // Read from the cache
            let cache_parents = cache.read(node as u32);
            parents.copy_from_slice(&cache_parents[..self.base_graph().degree()]);
            Ok(())
        } else {
            // No cache usage, generate on demand.
            self.base_graph().parents(node, parents)
        }
    }

    /// Assign `self.expansion_degree` parents to `node` using an invertible permutation
    /// that is applied one way for the forward layers and one way for the reversed
    /// ones.
    #[inline]
    pub fn expanded_parents(&self, node: usize, parents: &mut [u32]) {
        if let Some(cache) = self.cache {
            // Read from the cache
            let cache_parents = cache.read(node as u32);
            parents.copy_from_slice(&cache_parents[self.base_graph().degree()..]);
        } else {
            // No cache usage, generate on demand.
            self.generate_expanded_parents(node, parents);
        }
    }
}

impl<H, G> PartialEq for StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H>,
{
    fn eq(&self, other: &StackedGraph<H, G>) -> bool {
        self.base_graph == other.base_graph && self.expansion_degree == other.expansion_degree
    }
}

impl<H, G> Eq for StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H>,
{
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    // Test that 3 (or more) rounds of the Feistel cipher can be used
    // as a pseudorandom permutation, that is, each input will be mapped
    // to a unique output (and though not test here, since the cipher
    // is symmetric, the decryption rounds also work as the inverse
    // permutation), for more details see:
    // https://en.wikipedia.org/wiki/Feistel_cipher#Theoretical_work.
    #[test]
    fn test_shuffle() {
        let n = 2_u64.pow(10);
        let d = EXP_DEGREE as u64;
        // Use a relatively small value of `n` as Feistel is expensive (but big
        // enough that `n >> d`).

        let mut shuffled: HashSet<u64> = HashSet::with_capacity((n * d) as usize);

        let feistel_keys = &[1, 2, 3, 4];
        let feistel_precomputed = feistel::precompute((n * d) as feistel::Index);

        for i in 0..n {
            for k in 0..d {
                let permuted =
                    feistel::permute(n * d, i * d + k, feistel_keys, feistel_precomputed);

                // Since the permutation implies a one-to-one correspondence,
                // traversing the entire input space should generate the entire
                // output space (in `shuffled`) without repetitions (since a duplicate
                // output would imply there is another output that wasn't generated
                // and the permutation would be incomplete).
                assert!(shuffled.insert(permuted));
            }
        }

        // Actually implied by the previous `assert!` this is left in place as an
        // extra safety check that indeed the permutation preserved all the output
        // space (of `n * d` nodes) without repetitions (which the `HashSet` would
        // have skipped as duplicates).
        assert_eq!(shuffled.len(), (n * d) as usize);
    }
}
