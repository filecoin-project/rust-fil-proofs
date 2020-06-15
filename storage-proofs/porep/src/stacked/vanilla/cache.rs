use std::ops::Range;
use std::path::PathBuf;

use anyhow::{bail, Context};
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
    /// This is a large list of fixed (parent) sized arrays.
    data: memmap::Mmap,
    /// Disk path for the cache.
    path: PathBuf,
    /// The range of the stored data
    range: Range<u32>,
    /// The total number of cache entries.
    num_cache_entries: usize,
}

impl ParentCache {
    pub fn new<H, G>(cache_entries: u32, graph: &StackedGraph<H, G>) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        let path = cache_path(cache_entries, graph);
        if path.exists() {
            Self::open(cache_entries, path)
        } else {
            Self::generate(cache_entries, graph, path)
        }
    }

    /// Opens an existing cache from disk.
    pub fn open(cache_entries: u32, path: PathBuf) -> Result<Self> {
        info!("parent cache: opening {}", path.display());
        let cache_size = DEGREE * cache_entries as usize;

        let data = {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .open(&path)
                .with_context(|| format!("could not open path={}", path.display()))?;

            let actual_len = file.metadata()?.len();
            if actual_len != cache_size as u64 {
                bail!(
                    "corrupted cache: {}, expected {}, got {} bytes",
                    path.display(),
                    cache_size,
                    actual_len
                );
            }

            unsafe {
                memmap::MmapOptions::new()
                    .map(&file)
                    .with_context(|| format!("could not mmap path={}", path.display()))?
            }
        };

        info!("parent cache: opened");

        Ok(ParentCache {
            data,
            path,
            range: 0..cache_entries, // TODO: partial cache
            num_cache_entries: cache_entries as usize,
        })
    }

    /// Generates a new cache and stores it on disk.
    pub fn generate<H, G>(
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

        let mut data = {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&path)
                .with_context(|| format!("could not open path={}", path.display()))?;
            file.set_len((NODE_BYTES * cache_size) as u64)
                .with_context(|| format!("failed to set length: {}", cache_size))?;

            unsafe {
                memmap::MmapOptions::new()
                    .map_mut(&file)
                    .with_context(|| format!("could not mmap path={}", path.display()))?
            }
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
            data: data.make_read_only()?,
            path,
            range: 0..cache_entries, // TODO: partial cache
            num_cache_entries: cache_entries as usize,
        })
    }

    /// Read a single cache element at position `node`.
    #[inline]
    pub fn read(&self, node: u32) -> [u32; DEGREE] {
        if self.range.contains(&node) {
            // in memory cache
            let start = node as usize * DEGREE;
            let end = start + DEGREE;

            let mut res = [0u32; DEGREE];
            BigEndian::read_u32_into(&self.data[start..end], &mut res);
            res
        } else {
            // not in memory, read from disk
            todo!()
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
