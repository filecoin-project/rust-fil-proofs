#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
pub use unsupported::*;

use libc::c_int;

/// Index of a NUMA node.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct NumaNodeIndex(u32);

impl NumaNodeIndex {
    #[allow(dead_code)]
    pub fn new(idx: u32) -> Self {
        Self(idx)
    }

    /// Returns NUMA node index of c_int type
    pub fn raw(&self) -> c_int {
        self.0 as c_int
    }
}

#[cfg(target_os = "linux")]
mod linux {

    use lazy_static::lazy_static;
    use libc::{self, c_int};

    use super::NumaNodeIndex;

    #[link(name = "numa", kind = "dylib")]
    extern "C" {
        /// Check if NUMA support is enabled. Returns -1 if not enabled, in which case other functions will undefined
        fn numa_available() -> c_int;
        ///  Returns the NUMA node corresponding to a CPU core, or -1 if the CPU core is invalid
        fn numa_node_of_cpu(cpu: c_int) -> c_int;
    }

    lazy_static! {
        static ref NUMA_AVAILABLE: bool = unsafe { numa_available() >= 0 };
    }

    /// Returns the current NUMA node on which the thread is running.
    ///
    /// Since threads may migrate to another node with the scheduler,
    /// you need to bind the current worker thread to the specified core when calling this function
    #[allow(dead_code)]
    pub fn current_numa_node() -> Option<NumaNodeIndex> {
        if !*NUMA_AVAILABLE {
            return None;
        }
        let cpu = unsafe { libc::sched_getcpu() };
        // Return None if sched_getcpu call fails
        if cpu < 0 {
            return None;
        }
        let node = unsafe { numa_node_of_cpu(cpu) };
        // If libnuma cannot find the appropriate node, then return None
        if node < 0 {
            return None;
        }
        Some(NumaNodeIndex(node as u32))
    }
}

#[cfg(not(target_os = "linux"))]
mod unsupported {

    use super::NumaNodeIndex;

    #[allow(dead_code)]
    pub fn current_numa_node() -> Option<NumaNodeIndex> {
        None
    }
}
