use std::ops::Range;
use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::{bail, ensure, Context};
use byteorder::{BigEndian, ByteOrder};
use log::info;
use rayon::prelude::*;

use storage_proofs_core::{
    drgraph::Graph,
    drgraph::BASE_DEGREE,
    error::Result,
    hasher::Hasher,
    parameter_cache::{ParameterSetMetadata, VERSION},
    settings,
    util::NODE_SIZE,
};

use super::graph::{StackedGraph, DEGREE, EXP_DEGREE};

/// u32 = 4 bytes
const NODE_BYTES: usize = 4;

// StackedGraph will hold two different (but related) `ParentCache`,
#[derive(Debug)]
pub struct ParentCache {
    /// Disk path for the cache.
    path: PathBuf,
    /// The total number of cache entries.
    num_cache_entries: u32,
    cache: RwLock<CacheData>,
}

#[derive(Debug)]
struct CacheData {
    /// This is a large list of fixed (parent) sized arrays.
    data: memmap::Mmap,
    /// The range of the stored data
    range: Range<u32>,
    /// The underlyling file.
    file: std::fs::File,
}

impl CacheData {
    /// Change the cache to point to the newly passed in range.
    fn shift(&mut self, new_range: Range<u32>) -> Result<()> {
        if self.range == new_range {
            return Ok(());
        }

        self.data = unsafe {
            memmap::MmapOptions::new()
                .offset(new_range.start as u64)
                .len(new_range.end as usize - new_range.start as usize)
                .map(&self.file)
                .context("could not shift mmap}")?
        };
        self.range = new_range;

        Ok(())
    }

    /// Read the parents for the given node from cache.
    ///
    /// Panics if node is not in the cache.
    fn read(&self, node: u32) -> [u32; DEGREE] {
        let start = node as usize * DEGREE;
        let end = start + DEGREE;

        let mut res = [0u32; DEGREE];
        BigEndian::read_u32_into(&self.data[start..end], &mut res);
        res
    }

    fn open(range: Range<u32>, path: &PathBuf) -> Result<Self> {
        let min_cache_size = DEGREE * (range.end as usize - range.start as usize);

        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .with_context(|| format!("could not open path={}", path.display()))?;

        let actual_len = file.metadata()?.len();
        if actual_len < min_cache_size as u64 {
            bail!(
                "corrupted cache: {}, expected at least {}, got {} bytes",
                path.display(),
                min_cache_size,
                actual_len
            );
        }

        let data = unsafe {
            memmap::MmapOptions::new()
                .offset(range.start as u64)
                .len(range.end as usize - range.start as usize)
                .map(&file)
                .with_context(|| format!("could not mmap path={}", path.display()))?
        };

        Ok(Self { data, file, range })
    }
}

impl ParentCache {
    pub fn new<H, G>(
        range: Range<u32>,
        cache_entries: u32,
        graph: &StackedGraph<H, G>,
    ) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        let path = cache_path(cache_entries, graph);
        if path.exists() {
            Self::open(range, cache_entries, path)
        } else {
            Self::generate(range, cache_entries, graph, path)
        }
    }

    /// Opens an existing cache from disk.
    pub fn open(range: Range<u32>, cache_entries: u32, path: PathBuf) -> Result<Self> {
        info!("parent cache: opening {}", path.display());

        let cache = CacheData::open(range, &path)?;
        info!("parent cache: opened");

        Ok(ParentCache {
            cache: RwLock::new(cache),
            path,
            num_cache_entries: cache_entries,
        })
    }

    /// Generates a new cache and stores it on disk.
    pub fn generate<H, G>(
        range: Range<u32>,
        cache_entries: u32,
        graph: &StackedGraph<H, G>,
        path: PathBuf,
    ) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        info!("parent cache: generating {}", path.display());

        let cache_size = DEGREE * cache_entries as usize;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .with_context(|| format!("could not open path={}", path.display()))?;
        file.set_len((NODE_BYTES * cache_size) as u64)
            .with_context(|| format!("failed to set length: {}", cache_size))?;

        let mut data = unsafe {
            memmap::MmapOptions::new()
                .offset(range.start as u64)
                .len(range.end as usize - range.start as usize)
                .map_mut(&file)
                .with_context(|| format!("could not mmap path={}", path.display()))?
        };

        data.par_chunks_mut(DEGREE * NODE_BYTES)
            .enumerate()
            .try_for_each(|(node, entry)| -> Result<()> {
                let mut parents = [0u32; BASE_DEGREE + EXP_DEGREE];
                graph
                    .base_graph()
                    .parents(node, &mut parents[..BASE_DEGREE])?;
                graph.generate_expanded_parents(node, &mut parents[BASE_DEGREE..]);

                BigEndian::write_u32_into(&parents, entry);

                Ok(())
            })?;

        info!("parent cache: generated");
        data.flush().context("failed to flush parent cache")?;

        info!("parent cache: written to disk");

        Ok(ParentCache {
            cache: RwLock::new(CacheData {
                data: data.make_read_only()?,
                range,
                file,
            }),
            path,
            num_cache_entries: cache_entries,
        })
    }

    /// Read a single cache element at position `node`.
    #[inline]
    pub fn read(&self, node: u32) -> Result<[u32; DEGREE]> {
        let cache = self.cache.read().unwrap();
        if cache.range.contains(&node) {
            Ok(cache.read(node))
        } else {
            // not in memory, shift cache
            drop(cache);
            let cache = &mut *self.cache.write().unwrap();
            ensure!(
                node >= cache.range.end,
                "cache must be read in ascending order"
            );

            // TODO: shift by more than 1 entry to reduce changing the mapping continously.
            // Idea: move cache by the range size.
            let end = node + 1;
            let start = if end > self.num_cache_entries {
                end - self.num_cache_entries as u32
            } else {
                0
            };
            let new_range = start..node + 1;
            cache.shift(new_range)?;

            Ok(cache.read(node))
        }
    }
}

fn cache_path<H, G>(cache_entries: u32, graph: &StackedGraph<H, G>) -> PathBuf
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Send + Sync,
{
    PathBuf::from(format!(
        "v{}-sdr-parent-h{}-{}-e{}.cache",
        VERSION,
        H::name(),
        hex::encode(graph.identifier()),
        cache_entries,
    ))
}
