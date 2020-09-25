use std::cell::UnsafeCell;
use std::fs::File;
use std::marker::{PhantomData, Sync};
use std::mem::size_of;
use std::path::PathBuf;

use anyhow::Result;
use byte_slice_cast::*;
use log::*;
use mapr::{Mmap, MmapMut, MmapOptions};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst};

pub struct CacheReader<T> {
    file: File,
    bufs: UnsafeCell<[Mmap; 2]>,
    size: usize,
    degree: usize,
    window_size: usize,
    cur_window: AtomicUsize,
    cur_window_safe: AtomicUsize,
    _t: PhantomData<T>,
}

unsafe impl<T> Sync for CacheReader<T> {}

impl<T: FromByteSlice> CacheReader<T> {
    pub fn new(filename: &PathBuf, window_size: Option<usize>, degree: usize) -> Result<Self> {
        info!("initializing cache");
        let file = File::open(filename)?;
        let size = File::metadata(&file)?.len() as usize;
        let window_size = match window_size {
            Some(s) => {
                if s < size {
                    assert_eq!(
                        0,
                        size % degree * size_of::<T>(),
                        "window size is not multiple of element size"
                    );
                };
                s
            }
            None => {
                let num_windows = 8;
                assert_eq!(0, size % num_windows);
                size / num_windows
            }
        };

        let buf0 = Self::map_buf(0, window_size, &file)?;
        let buf1 = Self::map_buf(window_size as u64, window_size, &file)?;
        Ok(Self {
            file,
            bufs: UnsafeCell::new([buf0, buf1]),
            size,
            degree,
            window_size,
            // The furthest window from which the cache has yet been read.
            cur_window: AtomicUsize::new(0),
            cur_window_safe: AtomicUsize::new(0),
            _t: PhantomData::<T>,
        })
    }

    #[inline]
    fn get_bufs(&self) -> &[Mmap] {
        unsafe { &std::slice::from_raw_parts((*self.bufs.get()).as_ptr(), 2) }
    }

    #[inline]
    #[allow(clippy::mut_from_ref)]
    unsafe fn get_mut_bufs(&self) -> &mut [Mmap] {
        std::slice::from_raw_parts_mut((*self.bufs.get()).as_mut_ptr(), 2)
    }

    // TODO: is this actually needed?
    #[allow(dead_code)]
    pub fn reset(&self) -> Result<()> {
        let buf0 = Self::map_buf(0, self.window_size, &self.file)?;
        // FIXME: If window_size is more than half of size, then buf1 will map past end of file.
        // This should never be accessed, but we should not map it.
        let buf1 = Self::map_buf(self.window_size as u64, self.window_size, &self.file)?;
        let bufs = unsafe { self.get_mut_bufs() };
        bufs[0] = buf0;
        bufs[1] = buf1;
        self.cur_window.store(0, SeqCst);
        self.cur_window_safe.store(0, SeqCst);
        Ok(())
    }

    pub fn start_reset(&self) -> Result<()> {
        let buf0 = Self::map_buf(0, self.window_size, &self.file)?;
        let bufs = unsafe { self.get_mut_bufs() };
        bufs[0] = buf0;
        Ok(())
    }
    pub fn finish_reset(&self) -> Result<()> {
        let buf1 = Self::map_buf(self.window_size as u64, self.window_size, &self.file)?;
        let bufs = unsafe { self.get_mut_bufs() };
        bufs[1] = buf1;
        self.cur_window.store(0, SeqCst);
        self.cur_window_safe.store(0, SeqCst);
        Ok(())
    }

    fn map_buf(offset: u64, len: usize, file: &File) -> Result<Mmap> {
        match unsafe {
            MmapOptions::new()
                .offset(offset)
                .len(len)
                .private()
                .lock()
                .map(file)
        }
        .and_then(|mut parents| {
            parents.mlock()?;
            Ok(parents)
        }) {
            Ok(parents) => Ok(parents),
            Err(err) => {
                // fallback to not locked if permissions are not available
                warn!("failed to lock map {:?}, falling back", err);
                let parents = unsafe {
                    MmapOptions::new()
                        .offset(offset)
                        .len(len)
                        .private()
                        .map(file)?
                };
                Ok(parents)
            }
        }
    }

    #[inline]
    fn window_element_count(&self) -> usize {
        self.window_size / size_of::<T>()
    }

    /// `pos` is in units of `T`.
    #[inline]
    pub fn consumer_slice_at(&self, pos: usize) -> &[T] {
        assert!(
            pos < self.size,
            "pos {} out of range for buffer of size {}",
            pos,
            self.size
        );
        let window = pos / self.window_element_count();
        let pos = pos % self.window_element_count();
        let targeted_buf = &self.get_bufs()[window % 2];

        &targeted_buf.as_slice_of::<T>().unwrap()[pos..]
    }

    /// `pos` is in units of `T`.
    #[inline]
    pub fn slice_at(&self, pos: usize, consumer: &AtomicU64) -> &[T] {
        assert!(
            pos < self.size,
            "pos {} out of range for buffer of size {}",
            pos,
            self.size
        );
        let window = pos / self.window_element_count();
        if window == 1 {
            self.cur_window.compare_and_swap(0, 1, SeqCst);
            self.cur_window_safe.compare_and_swap(0, 1, SeqCst);
        }

        let pos = pos % self.window_element_count();

        // Check using `cur_window_safe`, to ensure we wait until the window is safe to use.
        // If we were to instead check `cur_window`, it could have been incremented but the mapping not completed yet.
        let cur = self.cur_window_safe.load(SeqCst);
        if window > cur {
            // Only one producer will successfully increment `cur_window`.
            // We need this second atomic because we cannot increment `cur_window_safe` until after the window has been advanced.
            let instant_cur = self.cur_window.compare_and_swap(cur, cur + 1, SeqCst);

            if instant_cur == cur {
                // We successfully incremented `self.cur_window`, so we are responsible for advancing the window.

                {
                    // Wait until the consumer has advanced far enough that it is safe to load the unused buffer.
                    let safe_consumer = (window - 1) * (self.window_element_count() / self.degree);
                    while (consumer.load(SeqCst) as usize) < safe_consumer {}
                }

                self.advance_rear_window(window);

                // Now it is safe to use the new window.
                self.cur_window_safe.fetch_add(1, SeqCst);
            } else {
                // We failed to increment `self.cur_window`, so we must wait for the window to be advanced before continuing.
                // Wait until it is safe to use the new current window.
                while self.cur_window_safe.load(SeqCst) != cur + 1 {}
            }
        }

        let targeted_buf = &self.get_bufs()[window % 2];

        &targeted_buf.as_slice_of::<T>().unwrap()[pos..]
    }

    fn advance_rear_window(&self, new_window: usize) {
        assert!(new_window as usize * self.window_size < self.size);

        let replace_idx = (new_window % 2) as usize;

        let new_buf = Self::map_buf(
            (new_window * self.window_size) as u64,
            self.window_size as usize,
            &self.file,
        )
        .unwrap();

        unsafe {
            self.get_mut_bufs()[replace_idx] = new_buf;
        }
    }
}

fn allocate_layer(sector_size: usize) -> Result<MmapMut> {
    match MmapOptions::new()
        .len(sector_size)
        .private()
        .clone()
        .lock()
        .map_anon()
        .and_then(|mut layer| {
            layer.mlock()?;
            Ok(layer)
        }) {
        Ok(layer) => Ok(layer),
        Err(err) => {
            // fallback to not locked if permissions are not available
            warn!("failed to lock map {:?}, falling back", err);
            let layer = MmapOptions::new().len(sector_size).private().map_anon()?;
            Ok(layer)
        }
    }
}

pub fn setup_create_label_memory(
    sector_size: usize,
    degree: usize,
    window_size: Option<usize>,
    cache_path: &PathBuf,
) -> Result<(CacheReader<u32>, MmapMut, MmapMut)> {
    let parents_cache = CacheReader::new(cache_path, window_size, degree)?;
    let layer_labels = allocate_layer(sector_size)?;
    let exp_labels = allocate_layer(sector_size)?;

    Ok((parents_cache, layer_labels, exp_labels))
}
