use std::{
    collections::HashMap,
    fs::OpenOptions,
    path::Path,
    sync::{Mutex, MutexGuard},
};

use log::{trace, warn};
use memmap2::{MmapMut, MmapOptions};

use crate::stacked::vanilla::numa::NumaNodeIndex;

// memory_size -> memory
type InnerPool = HashMap<usize, Vec<Mutex<MmapMut>>>;

pub(super) struct NumaMemPool {
    /// The index of the numa_groups vec is numa_node_index
    numa_groups: Vec<InnerPool>,
}

impl NumaMemPool {
    /// Create an empty NumaMemPool
    pub const fn empty() -> Self {
        Self {
            numa_groups: Vec::new(),
        }
    }

    /// Create NumaMemPool with the given `numa_memory_files`
    ///
    /// The index of the `numa_memory_files` vec is numa_node_index,
    /// and each item of `numa_memory_files` is the memory file paths corresponding to numa_node_index
    #[allow(dead_code)]
    pub fn new(numa_memory_files: Vec<impl IntoIterator<Item = impl AsRef<Path>>>) -> Self {
        let mut numa_mem_pool = Self::empty();
        numa_mem_pool.init(numa_memory_files);
        numa_mem_pool
    }

    /// Init NumaMemPool with the given `numa_memory_files`
    ///
    /// The index of the `numa_memory_files` vec is numa_node_index,
    /// and each item of `numa_memory_files` is the memory file paths corresponding to numa_node_index
    pub fn init(&mut self, numa_memory_files: Vec<impl IntoIterator<Item = impl AsRef<Path>>>) {
        if !self.numa_groups.is_empty() {
            warn!("The numa pool has already been initialized");
            return;
        }
        let numa_groups: Vec<_> = numa_memory_files
            .into_iter()
            .map(Self::load_memory_files)
            .collect();
        trace!(
            "number of loaded memory files: {}",
            numa_groups
                .iter()
                .enumerate()
                .map(|(numa_id, mems)| {
                    format!(
                        "numa_id: {}, loaded: {}",
                        numa_id,
                        mems.values().map(Vec::len).sum::<usize>()
                    )
                })
                .collect::<Vec<_>>()
                .join("; ")
        );
        self.numa_groups = numa_groups;
    }

    fn load_memory_files(memory_files: impl IntoIterator<Item = impl AsRef<Path>>) -> InnerPool {
        let mut inner_pool: HashMap<usize, Vec<Mutex<MmapMut>>> = HashMap::new();

        for p in memory_files.into_iter() {
            let p = p.as_ref();
            let memory_file = match OpenOptions::new().read(true).write(true).open(p) {
                Ok(file) => file,
                Err(e) => {
                    warn!(
                        "open memory file: '{}', {:?}. ignore this memory file.",
                        p.display(),
                        e
                    );
                    continue;
                }
            };

            let file_size = match memory_file.metadata() {
                Ok(meta) => meta.len(),
                Err(e) => {
                    warn!(
                        "get the size of the '{}' file: {:?}. ignore this memory file.",
                        p.display(),
                        e,
                    );
                    continue;
                }
            };

            let mmap = match unsafe { MmapOptions::new().map_mut(&memory_file) } {
                Ok(mut mmap) => {
                    if let Err(err) = mmap.lock() {
                        warn!(
                            "failed to lock mmap memory file '{}': {:?}",
                            p.display(),
                            err
                        );
                    }
                    mmap
                }
                Err(err) => {
                    warn!(
                        "failed to mmap memory file '{}': {:?}. ignore this memory file.",
                        p.display(),
                        err
                    );
                    continue;
                }
            };
            trace!("loaded memory file: {}", p.display());
            let mmap = Mutex::new(mmap);
            inner_pool
                .entry(file_size as usize)
                .or_insert_with(Vec::new)
                .push(mmap);
        }
        inner_pool
    }

    /// Acquire the memory for the specified size
    ///
    /// Acquire returns the memory of the NUMA node where the caller thread is located
    /// if there is enough memory.
    /// Make sure that the caller thread and the thread that using the memory returned
    /// by this function are in the same NUMA node and make sure the thread that using
    /// the returned memory will not be dispatched to other NUMA nodes, To maintain high
    /// performance of memory access
    pub fn acquire(&self, size: usize) -> Option<MutexGuard<'_, MmapMut>> {
        let numa_group = self
            .numa_groups
            .get(current_numa_node().unwrap_or_default().raw() as usize)?;
        for l in numa_group.get(&size)? {
            match l.try_lock() {
                Ok(m) => return Some(m),
                Err(_) => {}
            }
        }
        None
    }
}

#[cfg(not(test))]
fn current_numa_node() -> Option<NumaNodeIndex> {
    use crate::stacked::vanilla::numa;
    numa::current_numa_node()
}

#[cfg(test)]
fn current_numa_node() -> Option<NumaNodeIndex> {
    *tests::CUR_NUMA_NODE.lock().unwrap()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Mutex;

    use lazy_static::lazy_static;

    use crate::stacked::vanilla::numa::NumaNodeIndex;

    use super::NumaMemPool;

    lazy_static! {
        pub(super) static ref CUR_NUMA_NODE: Mutex<Option<NumaNodeIndex>> = Mutex::new(None);
    }

    /// set current numa node for testing
    fn set_current_numa_node(curr: Option<NumaNodeIndex>) {
        *CUR_NUMA_NODE.lock().unwrap() = curr;
    }

    #[test]
    fn test_numa_mem_pool() {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let temp_dir_path = temp_dir.as_ref();

        fn size_fn(numa_node_idx: usize) -> usize {
            (numa_node_idx + 1) * 10
        }

        let numa_memory_files: Vec<_> = (0..2)
            .map(|numa_node_idx| {
                (0..2).map(move |i| {
                    let path = temp_dir_path.join(format!("numa_{}_{}", numa_node_idx, i));

                    fs::write(&path, " ".repeat(size_fn(numa_node_idx)))
                        .expect("Failed to write data");
                    path
                })
            })
            .collect();
        let numa_mem_pool = NumaMemPool::new(numa_memory_files);

        let mut mems = Vec::new();
        for numa_node_idx in 0..2 {
            let size = size_fn(numa_node_idx);
            let no_exist_size = size + 1;

            set_current_numa_node(Some(NumaNodeIndex::new(numa_node_idx as u32)));

            for _ in 0..2 {
                // Test for normal memory acquire
                let mem = numa_mem_pool.acquire(size);
                assert!(mem.is_some());
                mems.push(mem);

                // Test to acquire the memory of non-existent memory size
                assert!(
                    numa_mem_pool.acquire(no_exist_size).is_none(),
                    "acquire non-existent memory size should return None"
                );
            }
        }

        // Test when NumaMemPool is empty
        for numa_node_idx in 0..2 {
            let size = size_fn(numa_node_idx);
            set_current_numa_node(Some(NumaNodeIndex::new(numa_node_idx as u32)));

            for _ in 0..2 {
                assert!(
                    numa_mem_pool.acquire(size).is_none(),
                    "acquire memory from empty NumaMemPool should return None"
                );
            }
        }

        drop(mems);

        for numa_node_idx in 0..2 {
            let size = size_fn(numa_node_idx);
            set_current_numa_node(Some(NumaNodeIndex::new(numa_node_idx as u32)));

            for _ in 0..2 {
                // Test for normal memory acquire
                let mem = numa_mem_pool.acquire(size);
                assert!(mem.is_some());
            }
        }
    }
}
