use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};

use crate::crypto::feistel::{self, FeistelPrecomputed};
use crate::drgraph::{BucketGraph, Graph, BASE_DEGREE};
use crate::hasher::Hasher;
use crate::layered_drgporep::Layerable;
use crate::parameter_cache::ParameterSetMetadata;
use crate::settings;

/// The expansion degree used for ZigZag Graphs.
pub const EXP_DEGREE: usize = 8;

lazy_static! {
    // This parents cache is currently used for the *expanded parents only*, generated
    // by the expensive Feistel operations in the ZigZag, it doesn't contain the
    // "base" (in the `Graph` terminology) parents, which are cheaper to compute.
    // It is indexed by the `Graph.identifier`, to ensure that the right cache is used.
    static ref PARENT_CACHE: Arc<RwLock<HashMap<String, ParentCache>>> = Arc::new(RwLock::new(HashMap::new()));
}

// ZigZagGraph will hold two different (but related) `ParentCache`,
// the first one for the `forward` direction and the second one for the `reversed`.
#[derive(Debug, Clone)]
pub struct ParentCache {
    forward: Vec<Option<Vec<u32>>>,
    reverse: Vec<Option<Vec<u32>>>,
    // Keep the size of the cache outside the lock to be easily accessible.
    cache_entries: u32,
}

impl ParentCache {
    pub fn new(cache_entries: u32) -> Self {
        ParentCache {
            forward: vec![None; cache_entries as usize],
            reverse: vec![None; cache_entries as usize],
            cache_entries,
        }
    }

    pub fn contains_forward(&self, node: u32) -> bool {
        assert!(node < self.cache_entries);
        self.forward[node as usize].is_some()
    }

    pub fn contains_reverse(&self, node: u32) -> bool {
        assert!(node < self.cache_entries);
        self.reverse[node as usize].is_some()
    }

    pub fn read_forward<F, T>(&self, node: u32, mut cb: F) -> T
    where
        F: FnMut(Option<&Vec<u32>>) -> T,
    {
        assert!(node < self.cache_entries);
        cb(self.forward[node as usize].as_ref())
    }

    pub fn read_reverse<F, T>(&self, node: u32, mut cb: F) -> T
    where
        F: FnMut(Option<&Vec<u32>>) -> T,
    {
        assert!(node < self.cache_entries);
        cb(self.reverse[node as usize].as_ref())
    }

    pub fn write_forward(&mut self, node: u32, parents: Vec<u32>) {
        assert!(node < self.cache_entries);

        let old_value = std::mem::replace(&mut self.forward[node as usize], Some(parents));

        debug_assert_eq!(old_value, None);
        // We shouldn't be rewriting entries (with most likely the same values),
        // this would be a clear indication of a bug.
    }

    pub fn write_reverse(&mut self, node: u32, parents: Vec<u32>) {
        assert!(node < self.cache_entries);

        let old_value = std::mem::replace(&mut self.reverse[node as usize], Some(parents));

        debug_assert_eq!(old_value, None);
        // We shouldn't be rewriting entries (with most likely the same values),
        // this would be a clear indication of a bug.
    }
}

#[derive(Debug, Clone)]
pub struct ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + 'static,
{
    expansion_degree: usize,
    base_graph: G,
    pub reversed: bool,
    feistel_precomputed: FeistelPrecomputed,
    id: String,
    use_cache: bool,
    _h: PhantomData<H>,
}

pub type ZigZagBucketGraph<H> = ZigZagGraph<H, BucketGraph<H>>;

impl<'a, H, G> Layerable<H> for ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + 'static,
{
}

impl<H, G> ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    pub fn new(
        base_graph: Option<G>,
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        seed: [u32; 7],
    ) -> Self {
        if !cfg!(feature = "unchecked-degrees") {
            assert_eq!(base_degree, BASE_DEGREE);
            assert_eq!(expansion_degree, EXP_DEGREE);
        }

        let use_cache = settings::SETTINGS.lock().unwrap().maximize_caching;

        let base_graph = match base_graph {
            Some(graph) => graph,
            None => G::new(nodes, base_degree, 0, seed),
        };
        let bg_id = base_graph.identifier();

        let res = ZigZagGraph {
            base_graph,
            id: format!(
                "zigzag_graph::ZigZagGraph{{expansion_degree: {} base_graph: {} }}",
                expansion_degree, bg_id,
            ),
            expansion_degree,
            use_cache,
            reversed: false,
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

        res
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

pub trait ZigZag: ::std::fmt::Debug + Clone + PartialEq + Eq {
    type BaseHasher: Hasher;
    type BaseGraph: Graph<Self::BaseHasher>;

    /// zigzag returns a new graph with expansion component inverted and a distinct
    /// base DRG graph -- with the direction of drg connections reversed. (i.e. from high-to-low nodes).
    /// The name is 'weird', but so is the operation -- hence the choice.
    fn zigzag(&self) -> Self;
    /// Constructs a new graph.
    fn base_graph(&self) -> Self::BaseGraph;
    fn expansion_degree(&self) -> usize;
    fn reversed(&self) -> bool;
    fn expanded_parents<F, T>(&self, node: usize, cb: F) -> T
    where
        F: FnMut(&Vec<u32>) -> T;
    fn real_index(&self, i: usize) -> usize;
    fn new_zigzag(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        seed: [u32; 7],
    ) -> Self;
}

impl<Z: ZigZag> Graph<Z::BaseHasher> for Z {
    fn size(&self) -> usize {
        self.base_graph().size()
    }

    fn degree(&self) -> usize {
        self.base_graph().degree() + self.expansion_degree()
    }

    #[inline]
    fn parents(&self, raw_node: usize, parents: &mut [usize]) {
        // If graph is reversed, use real_index to convert index to reversed index.
        // So we convert a raw reversed node to an unreversed node, calculate its parents,
        // then convert the parents to reversed.

        self.base_graph()
            .parents(self.real_index(raw_node), parents);
        for parent in parents.iter_mut().take(self.base_graph().degree()) {
            *parent = self.real_index(*parent);
        }

        // expanded_parents takes raw_node
        self.expanded_parents(raw_node, |expanded_parents| {
            for (ii, value) in expanded_parents.iter().enumerate() {
                parents[ii + self.base_graph().degree()] = *value as usize
            }

            // Pad so all nodes have correct degree.
            let current_length = self.base_graph().degree() + expanded_parents.len();
            for ii in 0..(self.degree() - current_length) {
                if self.reversed() {
                    parents[ii + current_length] = self.size() - 1
                } else {
                    parents[ii + current_length] = 0
                }
            }
        });
        assert!(parents.len() == self.degree());
        if self.forward() {
            parents.sort();
        } else {
            // Sort in reverse order.
            parents.sort_by(|a, b| a.cmp(b).reverse());
        }

        assert!(parents.iter().all(|p| if self.forward() {
            *p <= raw_node
        } else {
            *p >= raw_node
        }));
    }

    fn seed(&self) -> [u32; 7] {
        self.base_graph().seed()
    }

    fn new(nodes: usize, base_degree: usize, expansion_degree: usize, seed: [u32; 7]) -> Self {
        Z::new_zigzag(nodes, base_degree, expansion_degree, seed)
    }

    fn forward(&self) -> bool {
        !self.reversed()
    }
}

impl<'a, H, G> ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    // Assign `expansion_degree` parents to `node` using an invertible function. That
    // means we can't just generate random values between `[0, size())`, we need to
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
    //
    // Since `permute` is a bijective function which has the inverse `invert_permute`,
    // it is guaranteed that when looking for the parents in the `reversed` direction
    // the child `node` used earlier will now actually be the parent of the output
    // parents generated before (inverting the relationship). Following the example,
    // in the reverse direction, when looking for the parents of, say, node 1,
    // `invert_permute` (that maps back the output of `permute` to its input) would
    // receive the indexes `[0; 1; 2]`, where the index `0` is guaranteed to map back
    // to the index `4` that generated it earlier, corresponding to the node 2, inverting
    // in fact the child-parent relationship.
    fn correspondent(&self, node: usize, i: usize) -> usize {
        let a = (node * self.expansion_degree) as feistel::Index + i as feistel::Index;
        let feistel_keys = &[1, 2, 3, 4];

        let transformed = if self.reversed {
            feistel::invert_permute(
                self.size() as feistel::Index * self.expansion_degree as feistel::Index,
                a,
                feistel_keys,
                self.feistel_precomputed,
            )
        } else {
            feistel::permute(
                self.size() as feistel::Index * self.expansion_degree as feistel::Index,
                a,
                feistel_keys,
                self.feistel_precomputed,
            )
        };
        transformed as usize / self.expansion_degree
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
                if self.forward() {
                    cache.contains_forward(node as u32)
                } else {
                    cache.contains_reverse(node as u32)
                }
            } else {
                false
            }
        } else {
            false
        }
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

impl<'a, H, G> ZigZag for ZigZagGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    type BaseHasher = H;
    type BaseGraph = G;

    fn new_zigzag(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        seed: [u32; 7],
    ) -> Self {
        Self::new(None, nodes, base_degree, expansion_degree, seed)
    }

    /// To zigzag a graph, we just toggle its reversed field.
    /// All the real work happens when we calculate node parents on-demand.
    // We always share the two caches (forward/reversed) between
    // ZigZag graphs even if each graph will use only one of those
    // caches (depending of its direction). This allows to propagate
    // the caches across different layers, where consecutive even+odd
    // layers have inverse directions.
    fn zigzag(&self) -> Self {
        let mut zigzag = self.clone();
        zigzag.reversed = !zigzag.reversed;
        zigzag
    }

    fn base_graph(&self) -> Self::BaseGraph {
        self.base_graph.clone()
    }

    fn expansion_degree(&self) -> usize {
        self.expansion_degree
    }

    fn reversed(&self) -> bool {
        self.reversed
    }

    // TODO: Optimization: Evaluate providing an `all_parents` (and hence
    // `all_expanded_parents`) method that would return the entire cache
    // in a single lock operation, or at least (if the cache is not big enough)
    // it would allow to batch parents calculations with that single lock. Also,
    // since there is a reciprocity between forward and reversed parents,
    // we would only need to compute the parents in one direction and with
    // that fill both caches.
    #[inline]
    fn expanded_parents<F, T>(&self, node: usize, mut cb: F) -> T
    where
        F: FnMut(&Vec<u32>) -> T,
    {
        if !self.use_cache {
            // No cache usage, generate on demand.
            return cb(&self.generate_expanded_parents(node));
        }

        // Check if we need to fill the cache.
        if !self.contains_parents_cache(node) {
            // Cache is empty so we need to generate the parents.
            let parents = self.generate_expanded_parents(node);

            // Store the newly generated cached value.
            let mut cache_lock = PARENT_CACHE.write().unwrap();
            let cache = cache_lock
                .get_mut(&self.id)
                .expect("Invalid cache construction");
            if self.forward() {
                cache.write_forward(node as u32, parents);
            } else {
                cache.write_reverse(node as u32, parents);
            }
        }

        // We made sure the cache is filled above, now we can return the value.
        let cache_lock = PARENT_CACHE.read().unwrap();
        let cache = cache_lock
            .get(&self.id)
            .expect("Invalid cache construction");
        if self.forward() {
            cache.read_forward(node as u32, |parents| cb(parents.unwrap()))
        } else {
            cache.read_reverse(node as u32, |parents| cb(parents.unwrap()))
        }
    }

    #[inline]
    fn real_index(&self, i: usize) -> usize {
        if self.reversed {
            (self.size() - 1) - i
        } else {
            i
        }
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

    use std::collections::{HashMap, HashSet};

    use crate::drgraph::{new_seed, BASE_DEGREE};
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};

    fn assert_graph_ascending<H: Hasher, G: Graph<H>>(g: G) {
        for i in 0..g.size() {
            let mut parents = vec![0; g.degree()];
            g.parents(i, &mut parents);
            for p in parents {
                if i == 0 {
                    assert!(p == i);
                } else {
                    assert!(p < i);
                }
            }
        }
    }

    fn assert_graph_descending<H: Hasher, G: Graph<H>>(g: G) {
        for i in 0..g.size() {
            let mut parents = vec![0; g.degree()];
            g.parents(i, &mut parents);
            for p in parents {
                if i == g.size() - 1 {
                    assert!(p == i);
                } else {
                    assert!(p > i);
                }
            }
        }
    }

    #[test]
    fn zigzag_graph_zigzags_pedersen() {
        test_zigzag_graph_zigzags::<PedersenHasher>();
    }

    #[test]
    fn zigzag_graph_zigzags_sha256() {
        test_zigzag_graph_zigzags::<Sha256Hasher>();
    }

    #[test]
    fn zigzag_graph_zigzags_blake2s() {
        test_zigzag_graph_zigzags::<Blake2sHasher>();
    }

    fn test_zigzag_graph_zigzags<H: 'static + Hasher>() {
        let g = ZigZagBucketGraph::<H>::new_zigzag(50, BASE_DEGREE, EXP_DEGREE, new_seed());
        let gz = g.zigzag();

        assert_graph_ascending(g);
        assert_graph_descending(gz);
    }

    #[test]
    fn expansion_pedersen() {
        test_expansion::<PedersenHasher>();
    }

    #[test]
    fn expansion_sha256() {
        test_expansion::<Sha256Hasher>();
    }

    #[test]
    fn expansion_blake2s() {
        test_expansion::<Blake2sHasher>();
    }

    fn test_expansion<H: 'static + Hasher>() {
        // We need a graph.
        let g = ZigZagBucketGraph::<H>::new_zigzag(25, BASE_DEGREE, EXP_DEGREE, new_seed());

        // We're going to fully realize the expansion-graph component, in a HashMap.
        let gcache = get_all_expanded_parents(&g);

        // Here's the zigzag version of the graph.
        let gz = g.zigzag();

        // And a HashMap to hold the expanded parents.
        let gzcache = get_all_expanded_parents(&gz);

        for i in 0..gz.size() {
            let parents = gzcache.get(&i).unwrap();

            // Check to make sure all (expanded) node-parent relationships also exist in reverse,
            // in the original graph's Hashmap.
            for p in parents {
                assert!(gcache[&(*p as usize)].contains(&(i as u32)));
            }
        }

        // And then do the same check to make sure all (expanded) node-parent relationships from the original
        // are present in the zigzag, just reversed.
        for i in 0..g.size() {
            g.expanded_parents(i, |parents| {
                for p in parents.iter() {
                    assert!(gzcache[&(*p as usize)].contains(&(i as u32)));
                }
            });
        }
        // Having checked both ways, we know the graph and its zigzag counterpart have 'expanded' components
        // which are each other's inverses. It's important that this be true.
    }

    fn get_all_expanded_parents<H: 'static + Hasher>(
        zigzag_graph: &ZigZagBucketGraph<H>,
    ) -> HashMap<usize, Vec<u32>> {
        let mut parents_map: HashMap<usize, Vec<u32>> = HashMap::new();
        for i in 0..zigzag_graph.size() {
            parents_map.insert(i, zigzag_graph.expanded_parents(i, |p| p.clone()));
        }

        parents_map
    }

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
