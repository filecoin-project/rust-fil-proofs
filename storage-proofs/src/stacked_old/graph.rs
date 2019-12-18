use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};

use lazy_static::lazy_static;
use log::info;

use crate::crypto::feistel::{self, FeistelPrecomputed};
use crate::drgraph::{BucketGraph, Graph, BASE_DEGREE};
use crate::error::Result;
use crate::hasher::Hasher;
use crate::parameter_cache::ParameterSetMetadata;
use crate::settings;

/// The expansion degree used for Stacked Graphs.
pub const EXP_DEGREE: usize = 8;

lazy_static! {
    // This parents cache is currently used for the *expanded parents only*, generated
    // by the expensive Feistel operations in the Stacked, it doesn't contain the
    // "base" (in the `Graph` terminology) parents, which are cheaper to compute.
    // It is indexed by the `Graph.identifier`, to ensure that the right cache is used.
    static ref PARENT_CACHE: Arc<RwLock<HashMap<String, ParentCache>>> = Arc::new(RwLock::new(HashMap::new()));
}

// StackedGraph will hold two different (but related) `ParentCache`,
#[derive(Debug, Clone)]
struct ParentCache {
    cache: Vec<Option<Vec<u32>>>,
    // Keep the size of the cache outside the lock to be easily accessible.
    cache_entries: u32,
}

impl ParentCache {
    pub fn new(cache_entries: u32) -> Self {
        ParentCache {
            cache: vec![None; cache_entries as usize],
            cache_entries,
        }
    }

    pub fn contains(&self, node: u32) -> bool {
        assert!(node < self.cache_entries);
        self.cache[node as usize].is_some()
    }

    pub fn read<F, T>(&self, node: u32, mut cb: F) -> T
    where
        F: FnMut(Option<&Vec<u32>>) -> T,
    {
        assert!(node < self.cache_entries);
        cb(self.cache[node as usize].as_ref())
    }

    pub fn write(&mut self, node: u32, parents: Vec<u32>) {
        assert!(node < self.cache_entries);

        let old_value = std::mem::replace(&mut self.cache[node as usize], Some(parents));

        debug_assert_eq!(old_value, None);
        // We shouldn't be rewriting entries (with most likely the same values),
        // this would be a clear indication of a bug.
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
    G: Graph<H> + ParameterSetMetadata,
{
    pub fn new(
        base_graph: Option<G>,
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        seed: [u8; 28],
    ) -> Result<Self> {
        if !cfg!(feature = "unchecked-degrees") {
            assert_eq!(base_degree, BASE_DEGREE, "Invalid base degree");
            assert_eq!(expansion_degree, EXP_DEGREE, "Invalid expansion degree");
        }

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
            info!("using parents cache of unlimited size",);
            assert!(nodes <= std::u32::MAX as usize);

            if !PARENT_CACHE.read().unwrap().contains_key(&res.id) {
                PARENT_CACHE
                    .write()
                    .unwrap()
                    .insert(res.id.clone(), ParentCache::new(nodes as u32));
            }
        }

        Ok(res)
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
    G: Graph<H> + ParameterSetMetadata,
{
    type Key = Vec<u8>;

    fn size(&self) -> usize {
        self.base_graph().size()
    }

    fn degree(&self) -> usize {
        self.base_graph().degree() + self.expansion_degree()
    }

    #[inline]
    fn parents(&self, raw_node: usize, parents: &mut [u32]) -> Result<()> {
        self.base_parents(raw_node, &mut parents[..self.base_graph().degree()])?;

        // expanded_parents takes raw_node
        self.expanded_parents(
            raw_node,
            &mut parents
                [self.base_graph().degree()..self.base_graph().degree() + self.expansion_degree()],
        );

        debug_assert!(parents.len() == self.degree());
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
    G: Graph<H> + ParameterSetMetadata,
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
        let feistel_keys = &[1, 2, 3, 4];

        let transformed = feistel::permute(
            self.size() as feistel::Index * self.expansion_degree as feistel::Index,
            a,
            feistel_keys,
            self.feistel_precomputed,
        );
        transformed as u32 / self.expansion_degree as u32
        // Collapse the output in the matrix search space to the row of the corresponding
        // node (losing the column information, that will be regenerated later when calling
        // back this function in the `reversed` direction).
    }

    // Read the `node` entry in the parents cache (which may not exist) for
    // the current direction set in the graph and return a copy of it (or
    // `None` to signal a cache miss).
    fn contains_parents_cache(&self, node: usize) -> bool {
        if self.use_cache {
            if let Some(ref cache) = PARENT_CACHE.read().unwrap().get(&self.id) {
                cache.contains(node as u32)
            } else {
                false
            }
        } else {
            false
        }
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

    pub fn base_graph(&self) -> G {
        self.base_graph.clone()
    }

    pub fn expansion_degree(&self) -> usize {
        self.expansion_degree
    }

    pub fn base_parents(&self, raw_node: usize, parents: &mut [u32]) -> Result<()> {
        self.base_graph().parents(raw_node, parents)
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

        // Check if we need to fill the cache.
        if !self.contains_parents_cache(node) {
            // Cache is empty so we need to generate the parents.
            let mut parents = vec![0; self.expansion_degree()];
            self.generate_expanded_parents(node, &mut parents);

            // Store the newly generated cached value.
            let mut cache_lock = PARENT_CACHE.write().unwrap();
            let cache = cache_lock
                .get_mut(&self.id)
                .expect("Invalid cache construction");
            cache.write(node as u32, parents);
        }

        // We made sure the cache is filled above, now we can return the value.
        let cache_lock = PARENT_CACHE.read().unwrap();
        let cache = cache_lock
            .get(&self.id)
            .expect("Invalid cache construction");

        cache.read(node as u32, |cache_parents| {
            parents.copy_from_slice(cache_parents.expect("Invalid cache construction"));
        });
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
