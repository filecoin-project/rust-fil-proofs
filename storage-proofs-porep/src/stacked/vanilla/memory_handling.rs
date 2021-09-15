use std::cell::UnsafeCell;
use std::fs::File;
use std::hint::spin_loop;
use std::marker::{PhantomData, Sync};
use std::mem::size_of;
use std::path::Path;
use std::slice;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use anyhow::{ensure, Result};
use byte_slice_cast::{AsSliceOf, FromByteSlice};
use log::{info, warn};
use mapr::{Mmap, MmapMut, MmapOptions};

pub struct CacheReader<T> {
    file: File,
    file_len: usize,
    bufs: UnsafeCell<[Mmap; 2]>,
    size: usize,
    degree: usize,
    window_size: usize,
    cursor: IncrementingCursor,
    consumer: AtomicU64,
    _t: PhantomData<T>,
}

unsafe impl<T> Sync for CacheReader<T> {}

struct IncrementingCursor {
    cur: AtomicUsize,
    cur_safe: AtomicUsize,
}

fn compare_and_swap(atomic: &AtomicUsize, before: usize, after: usize) -> usize {
    match atomic.compare_exchange_weak(before, after, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(x) => {
            assert_eq!(x, before);
            before
        }
        _ => after,
    }
}

/// IncrementingCursor provides an atomic variable which can be incremented such that only one thread attempting the
/// increment is selected to perform actions required to effect the transition. Unselected threads wait until the
/// transition has completed. Transition and wait condition are both specified by closures supplied by the caller.
impl IncrementingCursor {
    fn new(val: usize) -> Self {
        Self {
            cur: AtomicUsize::new(val),
            cur_safe: AtomicUsize::new(val),
        }
    }

    fn store(&self, val: usize) {
        self.cur.store(val, Ordering::SeqCst);
        self.cur_safe.store(val, Ordering::SeqCst);
    }

    fn compare_and_swap(&self, before: usize, after: usize) {
        compare_and_swap(&self.cur, before, after);
        compare_and_swap(&self.cur_safe, before, after);
    }

    /// Increments or waits for the cursor to be incremented, iff the `target` is larger than the
    /// current safe position.
    fn increment<F: Fn() -> bool, G: Fn()>(&self, target: usize, wait_fn: F, advance_fn: G) {
        // Check using `cur_safe`, to ensure we wait until the current cursor value is safe to use.
        // If we were to instead check `cur`, it could have been incremented but not yet safe.
        let cur = self.cur_safe.load(Ordering::SeqCst);
        // We only need to increment if we actually
        if target > cur {
            // Only one producer will successfully increment `cur`. We need this second atomic because we cannot
            // increment `cur_safe` until after the underlying resource has been advanced.
            let instant_cur = compare_and_swap(&self.cur, cur, cur + 1);
            if instant_cur == cur {
                // We (this thread) have been selected to increment.
                while wait_fn() {
                    spin_loop()
                }
                // We successfully incremented `self.cur`, so we are responsible for advancing the resource.
                advance_fn();

                // Now it is safe to use the new window.
                self.cur_safe.fetch_add(1, Ordering::SeqCst);
            } else {
                // We failed to increment `self.cur_window`, so we must wait for the window to be advanced before
                // continuing. Wait until it is safe to use the new current window.
                while self.cur_safe.load(Ordering::SeqCst) != cur + 1 {
                    println!(
                        "{:?} waiting for new window {} {}",
                        std::thread::current().id(),
                        cur + 1,
                        self.cur_safe.load(Ordering::SeqCst)
                    );
                    spin_loop()
                }
            }
        }
    }
}

impl<T: FromByteSlice> CacheReader<T> {
    pub fn new(filename: &Path, window_size: Option<usize>, degree: usize) -> Result<Self> {
        info!("initializing cache");
        let file = File::open(filename)?;
        let size = File::metadata(&file)?.len() as usize;
        let window_size = window_size.unwrap_or_else(|| {
            let num_windows = 8;
            assert_eq!(0, size % num_windows);
            size / num_windows
        });

        ensure!(
            window_size <= size / 2,
            "window is too large: {} > {}",
            window_size,
            size
        );

        ensure!(
            size % window_size == 0,
            "window does not divide the cache size: {} % {} != 0",
            size,
            window_size,
        );

        ensure!(
            window_size % (degree * size_of::<T>()) == 0,
            "window does not divide the cache parent size: {} % {} != 0",
            window_size,
            degree * size_of::<T>(),
        );

        eprintln!(
            "{} window size {} {} {}",
            window_size,
            size,
            degree,
            size_of::<T>()
        );

        let buf0 = Self::map_buf(0, window_size, &file, size)?;
        let buf1 = Self::map_buf(window_size as u64, window_size, &file, size)?;
        Ok(Self {
            file,
            file_len: size,
            bufs: UnsafeCell::new([buf0, buf1]),
            size,
            degree,
            window_size,
            // The furthest window from which the cache has yet been read.
            cursor: IncrementingCursor::new(0),
            consumer: AtomicU64::new(0),
            _t: PhantomData::<T>,
        })
    }

    /// Returns the size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    pub fn window_nodes(&self) -> usize {
        self.window_size / (size_of::<T>() * self.degree)
    }

    /// Safety: incrementing the consumer at the end of a window will unblock the producer waiting to remap the
    /// consumer's previous buffer. The buffer must not be accessed once this has happened.
    pub unsafe fn increment_consumer(&self) {
        self.consumer.fetch_add(1, Ordering::SeqCst);
    }

    pub fn store_consumer(&self, val: u64) {
        self.consumer.store(val, Ordering::SeqCst);
    }

    pub fn get_consumer(&self) -> u64 {
        self.consumer.load(Ordering::SeqCst)
    }

    #[inline]
    fn get_bufs(&self) -> &[Mmap] {
        unsafe { &std::slice::from_raw_parts((*self.bufs.get()).as_ptr(), 2) }
    }

    #[inline]
    #[allow(clippy::mut_from_ref)]
    unsafe fn get_mut_bufs(&self) -> &mut [Mmap] {
        slice::from_raw_parts_mut((*self.bufs.get()).as_mut_ptr(), 2)
    }

    #[allow(dead_code)]
    // This is unused, but included to document the meaning of its components.

    pub fn reset(&self) -> Result<()> {
        self.start_reset()?;
        self.finish_reset()
    }

    pub fn start_reset(&self) -> Result<()> {
        let buf0 = Self::map_buf(0, self.window_size, &self.file, self.file_len)?;
        let bufs = unsafe { self.get_mut_bufs() };
        bufs[0] = buf0;
        Ok(())
    }

    pub fn finish_reset(&self) -> Result<()> {
        let buf1 = Self::map_buf(
            self.window_size as u64,
            self.window_size,
            &self.file,
            self.file_len,
        )?;
        let bufs = unsafe { self.get_mut_bufs() };
        bufs[1] = buf1;
        self.cursor.store(0);
        Ok(())
    }

    fn map_buf(offset: u64, len: usize, file: &File, file_len: usize) -> Result<Mmap> {
        ensure!(
            offset as usize + len <= file_len,
            "mmapping too large: offset:{}, len:{}, file_len:{}",
            offset,
            len,
            file_len
        );
        unsafe {
            MmapOptions::new()
                .offset(offset)
                .len(len)
                .private()
                .map(file)
                .map_err(|e| e.into())
        }
    }

    #[inline]
    fn window_element_count(&self) -> usize {
        self.window_size / size_of::<T>()
    }

    /// `pos` is in units of `T`.
    #[inline]
    /// Safety: A returned slice must not be accessed once the buffer from which it has been derived is remapped. A
    /// buffer will never be remapped until the `consumer` atomic contained in `self` has been advanced past the end of
    /// the window. NOTE: each time `consumer` is incremented, `self.degrees` elements of the cache are invalidated.
    /// This means callers should only access slice elements sequentially. They should only call `increment_consumer`
    /// once the next `self.degree` elements of the cache will never be accessed again.
    pub unsafe fn consumer_slice_at(&self, pos: usize) -> &[T] {
        assert!(
            pos < self.size,
            "pos {} out of range for buffer of size {}",
            pos,
            self.size
        );
        let window = pos / self.window_element_count();
        let pos = pos % self.window_element_count();
        let targeted_buf = &self.get_bufs()[window % 2];

        &targeted_buf.as_slice_of::<T>().expect("as_slice_of failed")[pos..]
    }

    /// `pos` is in units of `T`.
    #[inline]
    /// Safety: This call may advance the rear buffer, making it unsafe to access slices derived from that buffer again.
    /// It is the callers responsibility to ensure such illegal access is not attempted. This can be prevented if users
    /// never access values past which the cache's `consumer` atomic has been incremented. NOTE: each time `consumer` is
    /// incremented, `self.degrees` elements of the cache are invalidated.
    pub unsafe fn slice_at(&self, pos: usize) -> &[T] {
        assert!(
            pos < self.size,
            "pos {} out of range for buffer of size {}",
            pos,
            self.size
        );
        // The window in which the `pos` is placed.
        let target_window = pos / self.window_element_count();
        if target_window == 1 {
            self.cursor.compare_and_swap(0, 1);
        }

        let pos = pos % self.window_element_count();

        let wait_fn = || {
            let safe_consumer = (target_window - 1) * (self.window_element_count() / self.degree);
            // println!(
            //     "vmx: {:?} self.consumer < safe_consumer: {} {}",
            //     std::thread::current().id(),
            //     self.consumer.load(Ordering::SeqCst),
            //     safe_consumer
            // );
            (self.consumer.load(Ordering::SeqCst) as usize) < safe_consumer
        };

        // Move or wait until the window cursor is in the target_window.
        self.cursor.increment(target_window, &wait_fn, &|| {
            self.advance_rear_window(target_window)
        });

        // Retrieve the actual window buffer.
        let targeted_buf = &self.get_bufs()[target_window % 2];
        &targeted_buf.as_slice_of::<T>().expect("as_slice_of failed")[pos..]
    }

    /// Returns true if the given position is in a window.
    pub fn is_in_window(&self, pos: usize) -> bool {
        let target_window = pos / self.window_element_count();
        let current_window = self.cursor.cur_safe.load(Ordering::SeqCst);

        println!(
            "{:?} is in window: {} - {} - {} - {} - {}",
            std::thread::current().id(),
            (target_window == current_window)
                || (current_window > 0 && target_window == current_window - 1),
            pos,
            current_window,
            target_window,
            self.cursor.cur.load(Ordering::SeqCst)
        );
        (target_window == current_window)
            || (current_window > 0 && target_window == current_window - 1)
    }

    fn advance_rear_window(&self, new_window: usize) {
        assert!(new_window as usize * self.window_size < self.size);

        let replace_idx = (new_window % 2) as usize;

        let new_buf = Self::map_buf(
            (new_window * self.window_size) as u64,
            self.window_size as usize,
            &self.file,
            self.file_len,
        )
        .expect("map_buf failed");

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
    cache_path: &Path,
) -> Result<(CacheReader<u32>, MmapMut, MmapMut)> {
    let parents_cache = CacheReader::new(cache_path, window_size, degree)?;
    let layer_labels = allocate_layer(sector_size)?;
    let exp_labels = allocate_layer(sector_size)?;

    Ok((parents_cache, layer_labels, exp_labels))
}
