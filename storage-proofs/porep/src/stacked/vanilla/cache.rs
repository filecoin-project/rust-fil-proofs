use std::fs::File;
use std::io::{Read, Write, BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context};
use byteorder::{ByteOrder, LittleEndian};
use log::info;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use storage_proofs_core::{
    drgraph::Graph,
    drgraph::BASE_DEGREE,
    error::Result,
    hasher::Hasher,
    parameter_cache::{with_exclusive_lock, LockedFile, ParameterSetMetadata, VERSION},
    settings,
};

use super::graph::{StackedGraph, DEGREE};

/// u32 = 4 bytes
const NODE_BYTES: usize = 4;

// StackedGraph will hold two different (but related) `ParentCache`,
#[derive(Debug)]
pub struct ParentCache {
    /// Disk path for the cache.
    path: PathBuf,
    /// The total number of cache entries.
    num_cache_entries: u32,
    cache: CacheData,
}

#[derive(Debug)]
struct CacheData {
    /// This is a large list of fixed (parent) sized arrays.
    data: memmap::Mmap,
    /// Offset in nodes.
    offset: u32,
    /// Len in nodes.
    len: u32,
    /// The underlyling file.
    file: LockedFile,
}

impl CacheData {
    /// Change the cache to point to the newly passed in offset.
    ///
    /// The `new_offset` must be set, such that `new_offset + len` does not
    /// overflow the underlying data.
    fn shift(&mut self, new_offset: u32) -> Result<()> {
        if self.offset == new_offset {
            return Ok(());
        }

        let offset = new_offset as usize * DEGREE * NODE_BYTES;
        let len = self.len as usize * DEGREE * NODE_BYTES;

        self.data = unsafe {
            memmap::MmapOptions::new()
                .offset(offset as u64)
                .len(len)
                .map(self.file.as_ref())
                .context("could not shift mmap}")?
        };
        self.offset = new_offset;

        Ok(())
    }

    /// Returns true if this node is in the cached range.
    fn contains(&self, node: u32) -> bool {
        node >= self.offset && node < self.offset + self.len
    }

    /// Read the parents for the given node from cache.
    ///
    /// Panics if the `node` is not in the cache.
    fn read(&self, node: u32) -> [u32; DEGREE] {
        assert!(node >= self.offset, "node not in cache");
        let start = (node - self.offset) as usize * DEGREE * NODE_BYTES;
        let end = start + DEGREE * NODE_BYTES;

        let mut res = [0u32; DEGREE];
        LittleEndian::read_u32_into(&self.data[start..end], &mut res);
        res
    }

    fn reset(&mut self) -> Result<()> {
        if self.offset == 0 {
            return Ok(());
        }

        self.shift(0)
    }

    fn open(offset: u32, len: u32, path: &PathBuf) -> Result<Self> {
        let min_cache_size = (offset + len) as usize * DEGREE * NODE_BYTES;

        let file = LockedFile::open_shared_read(path)
            .with_context(|| format!("could not open path={}", path.display()))?;

        let actual_len = file.as_ref().metadata()?.len();
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
                .offset((offset as usize * DEGREE * NODE_BYTES) as u64)
                .len(len as usize * DEGREE * NODE_BYTES)
                .map(file.as_ref())
                .with_context(|| format!("could not mmap path={}", path.display()))?
        };

        Ok(Self {
            data,
            file,
            len,
            offset,
        })
    }
}

impl ParentCache {
    pub fn new<H, G>(len: u32, cache_entries: u32, graph: &StackedGraph<H, G>) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        let path = cache_path(cache_entries, graph);
        if path.exists() {
            Self::open(len, cache_entries, graph, path)
        } else {
            Self::generate(len, cache_entries, graph, path)
        }
    }

    /// Opens an existing cache from disk.  If the verify_cache option
    /// is enabled, we rehash the data and compare with the persisted
    /// hash file.  If the persisted hash file does not exist, we
    /// re-generate the cache file, which will create it.
    pub fn open<H, G>(
        len: u32,
        cache_entries: u32,
        graph: &StackedGraph<H, G>,
        path: PathBuf,
    ) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        let mut digest_path = path.clone();
        digest_path.set_extension("digest");

        let mut verify_cache = settings::SETTINGS
            .lock()
            .expect("verify_cache settings lock failure")
            .verify_cache;

        info!(
            "parent cache: opening {}, verify enabled: {}",
            path.display(),
            verify_cache
        );

        // If the digest file does not exist, generate the cache
        // file again along with the digest file.
        if !Path::new(&digest_path).exists() {
            info!(
                "[!!!] Parent cache digest is missing.  Regenerating {}",
                path.display()
            );
            ensure!(
                Self::generate(len, graph.size() as u32, graph, path.clone()).is_ok(),
                "Failed to generate parent cache"
            );

            // If we've just generated the digest file, do not
            // re-verify, even if requested.
            verify_cache = false;
        }

        if verify_cache {
            // Always check all of the data for integrity checks, even
            // if we're only opening a portion of it.
            let mut hasher = Sha256::new();
            info!("[open] parent cache: calculating consistency digest");
            let file = File::open(&path)?;
            /*
            let mut reader = BufReader::new(file);
            while reader.fill_buf()?.len() > 0 {
                hasher.update(reader.buffer());
            }*/
            let data = unsafe {
                memmap::MmapOptions::new()
                    .map(&file)
                    .with_context(|| format!("could not mmap path={}", path.display()))?
            };
            hasher.update(&data);
            drop(data);

            let hash = hasher.finalize();
            info!("[open] parent cache: calculated consistency digest");

            let mut digest = Vec::new();
            let mut digest_file = File::open(&digest_path)?;
            digest_file.read_to_end(&mut digest)?;
            if digest.as_slice() == hash.as_slice() {
                info!("[open] parent cache: cached is verified!");
            } else {
                info!(
                    "[!!!] Parent cache digest mismatch detected.  Regenerating {}",
                    path.display()
                );
                ensure!(
                    Self::generate(len, graph.size() as u32, graph, path.clone()).is_ok(),
                    "Failed to generate parent cache"
                );
            }
        }

        Ok(ParentCache {
            cache: CacheData::open(0, len, &path)?,
            path,
            num_cache_entries: cache_entries,
        })
    }

    /// Generates a new cache and stores it on disk.
    pub fn generate<H, G>(
        len: u32,
        cache_entries: u32,
        graph: &StackedGraph<H, G>,
        path: PathBuf,
    ) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        info!("parent cache: generating {}", path.display());

        with_exclusive_lock(&path, |file| {
            let cache_size = cache_entries as usize * NODE_BYTES * DEGREE;
            file.as_ref()
                .set_len(cache_size as u64)
                .with_context(|| format!("failed to set length: {}", cache_size))?;

            let mut data = unsafe {
                memmap::MmapOptions::new()
                    .map_mut(file.as_ref())
                    .with_context(|| format!("could not mmap path={}", path.display()))?
            };

            data.par_chunks_mut(DEGREE * NODE_BYTES)
                .enumerate()
                .try_for_each(|(node, entry)| -> Result<()> {
                    let mut parents = [0u32; DEGREE];
                    graph
                        .base_graph()
                        .parents(node, &mut parents[..BASE_DEGREE])?;
                    graph.generate_expanded_parents(node, &mut parents[BASE_DEGREE..]);

                    LittleEndian::write_u32_into(&parents, entry);
                    Ok(())
                })?;

            info!("parent cache: generated");
            data.flush().context("failed to flush parent cache")?;

            info!("[generate] parent cache: generating consistency digest");
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let hash = hasher.finalize();
            info!("[generate]parent cache: generated consistency digest");

            drop(data);

            // Write out the data digest to disk.
            let mut digest_path = path.clone();
            digest_path.set_extension("digest");

            // If the digest file already exists, remove it since we
            // just generated the data.
            if Path::new(&digest_path).exists() {
                std::fs::remove_file(&digest_path)?;
            }

            with_exclusive_lock(&digest_path, |file| Ok(file.as_ref().write_all(&hash)?))?;

            info!("parent cache: written to disk");
            Ok(())
        })?;

        Ok(ParentCache {
            cache: CacheData::open(0, len, &path)?,
            path,
            num_cache_entries: cache_entries,
        })
    }

    /// Read a single cache element at position `node`.
    pub fn read(&mut self, node: u32) -> Result<[u32; DEGREE]> {
        if self.cache.contains(node) {
            return Ok(self.cache.read(node));
        }

        // not in memory, shift cache
        ensure!(
            node >= self.cache.offset + self.cache.len,
            "cache must be read in ascending order {} < {} + {}",
            node,
            self.cache.offset,
            self.cache.len,
        );

        // Shift cache by its current size.
        let new_offset =
            (self.num_cache_entries - self.cache.len).min(self.cache.offset + self.cache.len);
        self.cache.shift(new_offset)?;

        Ok(self.cache.read(node))
    }

    /// Resets the partial cache to the beginning.
    pub fn reset(&mut self) -> Result<()> {
        self.cache.reset()
    }
}

fn parent_cache_dir_name() -> String {
    settings::SETTINGS
        .lock()
        .expect("parent_cache settings lock failure")
        .parent_cache
        .clone()
}

fn cache_path<H, G>(cache_entries: u32, graph: &StackedGraph<H, G>) -> PathBuf
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Send + Sync,
{
    let mut hasher = Sha256::default();

    hasher.update(H::name());
    hasher.update(graph.identifier());
    for key in &graph.feistel_keys {
        hasher.update(key.to_le_bytes());
    }
    hasher.update(cache_entries.to_le_bytes());
    let h = hasher.finalize();
    PathBuf::from(parent_cache_dir_name()).join(format!(
        "v{}-sdr-parent-{}.cache",
        VERSION,
        hex::encode(h),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::stacked::vanilla::graph::{StackedBucketGraph, EXP_DEGREE};
    use storage_proofs_core::hasher::PoseidonHasher;

    #[test]
    fn test_read_full_range() {
        let nodes = 24u32;
        let graph = StackedBucketGraph::<PoseidonHasher>::new_stacked(
            nodes as usize,
            BASE_DEGREE,
            EXP_DEGREE,
            [0u8; 32],
        )
        .expect("new_stacked failure");

        let mut cache = ParentCache::new(nodes, nodes, &graph).expect("parent cache new failure");

        for node in 0..nodes {
            let mut expected_parents = [0; DEGREE];
            graph
                .parents(node as usize, &mut expected_parents)
                .expect("graph parents failure");
            let parents = cache.read(node).expect("cache read failure");

            assert_eq!(expected_parents, parents);
        }
    }

    #[test]
    fn test_read_partial_range() {
        let nodes = 48u32;
        let graph = StackedBucketGraph::<PoseidonHasher>::new_stacked(
            nodes as usize,
            BASE_DEGREE,
            EXP_DEGREE,
            [0u8; 32],
        )
        .expect("new_stacked failure");

        let mut half_cache =
            ParentCache::new(nodes / 2, nodes, &graph).expect("parent cache new failure");
        let mut quarter_cache =
            ParentCache::new(nodes / 4, nodes, &graph).expect("parent cache new failure");

        for node in 0..nodes {
            let mut expected_parents = [0; DEGREE];
            graph
                .parents(node as usize, &mut expected_parents)
                .expect("graph parents failure");

            let parents = half_cache.read(node).expect("half cache read failure");
            assert_eq!(expected_parents, parents);

            let parents = quarter_cache
                .read(node)
                .expect("quarter cache read failure");
            assert_eq!(expected_parents, parents);

            // some internal checks to make sure the cache works as expected
            assert_eq!(
                half_cache.cache.data.len() / DEGREE / NODE_BYTES,
                nodes as usize / 2
            );
            assert_eq!(
                quarter_cache.cache.data.len() / DEGREE / NODE_BYTES,
                nodes as usize / 4
            );
        }

        half_cache.reset().expect("half cache reset failure");
        quarter_cache.reset().expect("quarter cache reset failure");

        for node in 0..nodes {
            let mut expected_parents = [0; DEGREE];
            graph
                .parents(node as usize, &mut expected_parents)
                .expect("graph parents failure");

            let parents = half_cache.read(node).expect("half cache read failure");
            assert_eq!(expected_parents, parents);

            let parents = quarter_cache
                .read(node)
                .expect("quarter cache read failure");
            assert_eq!(expected_parents, parents);
        }
    }
}
