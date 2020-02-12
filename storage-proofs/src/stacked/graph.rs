use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};

use anyhow::ensure;
use lazy_static::lazy_static;
use log::info;
use rayon::prelude::*;

use crate::crypto::feistel::{self, FeistelPrecomputed};
use crate::drgraph::{BucketGraph, Graph};
use crate::error::Result;
use crate::hasher::Hasher;
use crate::parameter_cache::ParameterSetMetadata;
use crate::settings;
use crate::util::{data_at_node_offset, NODE_SIZE};

/// The expansion degree used for Stacked Graphs.
pub const EXP_DEGREE: usize = 8;
const FEISTEL_KEYS: [feistel::Index; 4] = [1, 2, 3, 4];

lazy_static! {
    // This parents cache is currently used for the full parents set.
    // It is indexed by the `sector size`, to ensure that the right cache is used.
    static ref PARENT_CACHE: Arc<RwLock<HashMap<u64, ParentCache>>> = Arc::new(RwLock::new(HashMap::new()));
}

// StackedGraph will hold two different (but related) `ParentCache`,
#[derive(Debug, Clone)]
struct ParentCache {
    /// This is a large list of fixed (parent) sized arrays.
    /// `Vec<Vec<u32>>` was showing quite a large memory overhead, so this is layed out as a fixed boxed slice of memory.
    cache: Box<[u32]>,
    /// The size of a single slice in the cache.
    degree: usize,
}

impl ParentCache {
    pub fn new<H, G>(cache_entries: u32, graph: &StackedGraph<H, G>) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        info!("filling parents cache");
        let degree = graph.degree();
        let mut cache = vec![0u32; degree * cache_entries as usize];

        let base_degree = graph.base_graph().degree();
        let exp_degree = graph.expansion_degree();

        cache
            .par_chunks_mut(degree)
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
            degree,
        })
    }

    /// Read a single cache element at position `node`.
    pub fn read(&self, node: u32) -> &[u32] {
        let start = node as usize * self.degree;
        let end = start + self.degree;
        &self.cache[start..end]
    }
}

#[derive(Debug, Clone)]
pub struct StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + 'static,
{
    expansion_degree: usize,
    base_graph: G,
    feistel_precomputed: FeistelPrecomputed,
    id: String,
    use_cache: bool,
    _h: PhantomData<H>,
}

pub type StackedBucketGraph<H> = StackedGraph<H, BucketGraph<H>>;

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
        seed: [u8; 28],
    ) -> Result<Self> {
        let use_cache = settings::SETTINGS.lock().unwrap().maximize_caching;

        let base_graph = match base_graph {
            Some(graph) => graph,
            None => G::new(nodes, base_degree, 0, seed)?,
        };
        let bg_id = base_graph.identifier();

        let res = StackedGraph {
            base_graph,
            id: format!(
                "stacked_graph::StackedGraph{{expansion_degree: {} base_graph: {} }}",
                expansion_degree, bg_id,
            ),
            expansion_degree,
            use_cache,
            feistel_precomputed: feistel::precompute((expansion_degree * nodes) as feistel::Index),
            _h: PhantomData,
        };

        if use_cache {
            info!("using parents cache of unlimited size");
            ensure!(nodes <= std::u32::MAX as usize, "too many nodes");

            if !PARENT_CACHE
                .read()
                .unwrap()
                .contains_key(&res.sector_size())
            {
                PARENT_CACHE
                    .write()
                    .unwrap()
                    .insert(res.sector_size(), ParentCache::new(nodes as u32, &res)?);
            }
        }

        Ok(res)
    }

    pub fn copy_parents_data(
        &self,
        node: u32,
        base_data: &[u8],
        exp_data: Option<&Vec<u8>>,
        target: &mut [u8],
    ) {
        if self.use_cache {
            let cache_lock = PARENT_CACHE.read().unwrap();
            let cache = cache_lock
                .get(&self.sector_size())
                .expect("Invalid cache construction");
            let cache_parents = cache.read(node as u32);
            self.copy_parents_data_inner(&cache_parents, base_data, exp_data, target);
        } else {
            let mut cache_parents = vec![0u32; self.degree()];
            self.parents(node as usize, &mut cache_parents).unwrap();
            self.copy_parents_data_inner(&cache_parents, base_data, exp_data, target);
        }
    }

    fn copy_parents_data_inner(
        &self,
        cache_parents: &[u32],
        base_data: &[u8],
        exp_data: Option<&Vec<u8>>,
        target: &mut [u8],
    ) {
        let base_degree = self.base_graph().degree();

        // Base parents
        for (i, parent) in cache_parents.iter().enumerate().take(base_degree) {
            let node_off = data_at_node_offset(*parent as usize);
            let off = i * NODE_SIZE;
            target[off..off + NODE_SIZE]
                .copy_from_slice(&base_data[node_off..node_off + NODE_SIZE]);
        }

        // Expander parents
        if let Some(ref parents_data) = exp_data {
            for (i, parent) in cache_parents.iter().enumerate().skip(base_degree) {
                let node_off = data_at_node_offset(*parent as usize);
                let off = i * NODE_SIZE;
                target[off..off + NODE_SIZE]
                    .copy_from_slice(&parents_data[node_off..node_off + NODE_SIZE]);
            }
        }
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
        self.base_graph().degree() + self.expansion_degree()
    }

    #[inline]
    fn parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
        if !self.use_cache {
            self.base_parents(node, &mut parents[..self.base_graph().degree()])?;

            // expanded_parents takes raw_node
            self.expanded_parents(
                node,
                &mut parents[self.base_graph().degree()
                    ..self.base_graph().degree() + self.expansion_degree()],
            );
            return Ok(());
        }

        // Read from the cache
        let cache_lock = PARENT_CACHE.read().unwrap();
        let cache = cache_lock
            .get(&self.sector_size())
            .expect("Invalid cache construction");

        let cache_parents = cache.read(node as u32);
        parents.copy_from_slice(cache_parents);
        Ok(())
    }

    fn seed(&self) -> [u8; 28] {
        self.base_graph().seed()
    }

    fn new(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        seed: [u8; 28],
    ) -> Result<Self> {
        Self::new_stacked(nodes, base_degree, expansion_degree, seed)
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
            &FEISTEL_KEYS,
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
        seed: [u8; 28],
    ) -> Result<Self> {
        Self::new(None, nodes, base_degree, expansion_degree, seed)
    }

    pub fn base_graph(&self) -> &G {
        &self.base_graph
    }

    pub fn expansion_degree(&self) -> usize {
        self.expansion_degree
    }

    pub fn base_parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
        if !self.use_cache {
            // No cache usage, generate on demand.
            return self.base_graph().parents(node, parents);
        }

        // Read from the cache
        let cache_lock = PARENT_CACHE.read().unwrap();
        let cache = cache_lock
            .get(&self.sector_size())
            .expect("Invalid cache construction");

        let cache_parents = cache.read(node as u32);
        parents.copy_from_slice(&cache_parents[..self.base_graph().degree()]);

        Ok(())
    }

    /// Assign `self.expansion_degree` parents to `node` using an invertible permutation
    /// that is applied one way for the forward layers and one way for the reversed
    /// ones.
    #[inline]
    pub fn expanded_parents(&self, node: usize, parents: &mut [u32]) {
        if !self.use_cache {
            // No cache usage, generate on demand.
            return self.generate_expanded_parents(node, parents);
        }

        // Read from the cache
        let cache_lock = PARENT_CACHE.read().unwrap();
        let cache = cache_lock
            .get(&self.sector_size())
            .expect("Invalid cache construction");

        let cache_parents = cache.read(node as u32);
        parents.copy_from_slice(&cache_parents[self.base_graph().degree()..]);
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
