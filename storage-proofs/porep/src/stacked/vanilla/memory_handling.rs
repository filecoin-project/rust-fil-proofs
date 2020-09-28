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
    buf0: UnsafeCell<Mmap>,
    buf1: UnsafeCell<Mmap>,
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
            buf0: UnsafeCell::new(buf0),
            buf1: UnsafeCell::new(buf1),
            size,
            degree,
            window_size,
            // The furthest window from which the cache has yet been read.
            cur_window: AtomicUsize::new(0),
            cur_window_safe: AtomicUsize::new(0),
            _t: PhantomData::<T>,
        })
    }

    /// Unsafe because the caller must ensure no `buf0` is not accessed mutably in parallel.
    #[inline]
    unsafe fn get_buf0(&self) -> &Mmap {
        &*self.buf0.get()
    }

    /// Unsafe because the caller must ensure no `buf1` is not accessed mutably in parallel.
    #[inline]
    unsafe fn get_buf1(&self) -> &Mmap {
        &*self.buf1.get()
    }

    pub fn start_reset(&mut self) -> Result<()> {
        self.buf0 = UnsafeCell::new(Self::map_buf(0, self.window_size, &self.file)?);
        Ok(())
    }

    pub fn finish_reset(&mut self) -> Result<()> {
        self.buf1 = UnsafeCell::new(Self::map_buf(self.window_size as u64, self.window_size, &self.file)?);
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
    ///
    /// Unsafe because the caller must ensure to only read a position that is currently not accessed mutably.
    #[inline]
    pub unsafe fn consumer_slice_at(&self, pos: usize) -> &[T] {
        assert!(
            pos < self.size,
            "pos {} out of range for buffer of size {}",
            pos,
            self.size
        );
        let window = pos / self.window_element_count();
        let pos = pos % self.window_element_count();

        if window % 2 == 0 {
            &self.get_buf0().as_slice_of::<T>().unwrap()[pos..]
        } else {
            &self.get_buf1().as_slice_of::<T>().unwrap()[pos..]
        }
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

                // Safety: we have waited for the consumer to advance beyond the rear window above.
                unsafe {
                    self.advance_rear_window(window);
                }

                // Now it is safe to use the new window.
                self.cur_window_safe.fetch_add(1, SeqCst);
            } else {
                // We failed to increment `self.cur_window`, so we must wait for the window to be advanced before continuing.
                // Wait until it is safe to use the new current window.
                while self.cur_window_safe.load(SeqCst) != cur + 1 {}
            }
        }

        // Safety: we wait for the current window to be at pos above.
        if window % 2 == 0 {
            unsafe {
                &self.get_buf0().as_slice_of::<T>().unwrap()[pos..]
            }
        } else {
            unsafe {
                &self.get_buf1().as_slice_of::<T>().unwrap()[pos..]
            }
        }
    }

    /// Unsafe because the caller must ensure that there is no current access the rear window.
    unsafe fn advance_rear_window(&self, new_window: usize) {
        assert!(new_window as usize * self.window_size < self.size);

        let new_buf = Self::map_buf(
            (new_window * self.window_size) as u64,
            self.window_size as usize,
            &self.file,
        )
        .unwrap();

        let buf = if new_window % 2 == 0 {
            &mut *self.buf0.get() 
        } else {
            &mut *self.buf0.get() 
        };

        *buf = new_buf;
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
