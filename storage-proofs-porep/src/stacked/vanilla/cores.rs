use std::convert::TryInto;
use std::sync::{Mutex, MutexGuard};

use anyhow::{format_err, Result};
use hwloc::{Bitmap, ObjectType, Topology, TopologyObject, CPUBIND_THREAD};
use lazy_static::lazy_static;
use log::{debug, warn};
use storage_proofs_core::settings::SETTINGS;

type CoreUnit = Vec<CoreIndex>;
lazy_static! {
    pub static ref TOPOLOGY: Mutex<Topology> = Mutex::new(Topology::new());
    pub static ref CORE_GROUPS: Option<Vec<Mutex<CoreUnit>>> = {
        let num_producers = &SETTINGS.multicore_sdr_producers;
        let cores_per_unit = num_producers + 1;

        core_units(cores_per_unit)
    };
}

#[derive(Clone, Copy, Debug, PartialEq)]
/// `CoreIndex` is a simple wrapper type for indexes into the set of visible cores. A `CoreIndex`
/// should only ever be created with a value known to be less than the number of visible cores.
pub struct CoreIndex(usize);

pub fn checkout_core_group() -> Option<MutexGuard<'static, CoreUnit>> {
    match &*CORE_GROUPS {
        Some(units) => {
            for (i, unit) in units.iter().enumerate() {
                match unit.try_lock() {
                    Ok(guard) => {
                        debug!("checked out core group {}", i);
                        return Some(guard);
                    }
                    Err(_) => debug!("core group {} locked, could not checkout", i),
                }
            }
            None
        }
        None => None,
    }
}

#[cfg(not(target_os = "windows"))]
pub type ThreadId = libc::pthread_t;

#[cfg(target_os = "windows")]
pub type ThreadId = winapi::winnt::HANDLE;

/// Helper method to get the thread id through libc, with current rust stable (1.5.0) its not
/// possible otherwise I think.
#[cfg(not(target_os = "windows"))]
fn get_thread_id() -> ThreadId {
    unsafe { libc::pthread_self() }
}

#[cfg(target_os = "windows")]
fn get_thread_id() -> ThreadId {
    unsafe { kernel32::GetCurrentThread() }
}

pub struct Cleanup {
    tid: ThreadId,
    prior_state: Option<Bitmap>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(prior) = self.prior_state.take() {
            let child_topo = &TOPOLOGY;
            let mut locked_topo = child_topo.lock().expect("poisded lock");
            let _ = locked_topo.set_cpubind_for_thread(self.tid, prior, CPUBIND_THREAD);
        }
    }
}

pub fn bind_core(core_index: CoreIndex) -> Result<Cleanup> {
    let child_topo = &TOPOLOGY;
    let tid = get_thread_id();
    let mut locked_topo = child_topo.lock().expect("poisoned lock");
    let core = get_core_by_index(&locked_topo, core_index)
        .map_err(|err| format_err!("failed to get core at index {}: {:?}", core_index.0, err))?;

    let cpuset = core
        .allowed_cpuset()
        .ok_or_else(|| format_err!("no allowed cpuset for core at index {}", core_index.0,))?;
    debug!("allowed cpuset: {:?}", cpuset);
    let mut bind_to = cpuset;

    // Get only one logical processor (in case the core is SMT/hyper-threaded).
    bind_to.singlify();

    // Thread binding before explicit set.
    let before = locked_topo.get_cpubind_for_thread(tid, CPUBIND_THREAD);

    debug!("binding to {:?}", bind_to);
    // Set the binding.
    let result = locked_topo
        .set_cpubind_for_thread(tid, bind_to, CPUBIND_THREAD)
        .map_err(|err| format_err!("failed to bind CPU: {:?}", err));

    if result.is_err() {
        warn!("error in bind_core, {:?}", result);
    }

    Ok(Cleanup {
        tid,
        prior_state: before,
    })
}

fn get_core_by_index(topo: &Topology, index: CoreIndex) -> Result<&TopologyObject> {
    let idx = index.0;

    match topo.objects_with_type(&ObjectType::Core) {
        Ok(all_cores) if idx < all_cores.len() => Ok(all_cores[idx]),
        Ok(all_cores) => Err(format_err!(
            "idx ({}) out of range for {} cores",
            idx,
            all_cores.len()
        )),
        _e => Err(format_err!("failed to get core by index {}", idx,)),
    }
}

/// Group all available cores, that share a (L3) cache in a way, so that the multicore SDR can
/// operate most efficiently.
///
/// A single multicore SDR run needs a certain amount of cores, a so-called *unit*.
/// `cores_per_unit` defines how many cores are dedicated to a single multicore SDR instance.
///
/// On larget systems, the available cores (given by `core_count`) may be connected to separate
/// (L3) caches. All cores that belong to the same cache are called a *group*, the number of
/// groups is given by `group_count`. On smaller systems, like laptops, there usually is just a
/// single group.
///
/// A unit is always bound to a single group. Groups may be large enough to bind multiple units.
/// Though for performance reasons it is preferred that units don't share a cache, hence the units
/// are distributed across separate groups first. Only if all groups are already bound to a unit,
/// a group will be re-used.
///
/// Here's an example: you have a 48 core system, with 8 separate caches and you have units of size
/// 3. Your `core_count` is 48, the `group_count` is 8 and the `cores_per_unit` is 3. In every
/// group we have 6 cores available. This means that we can have two units bound to a single group.
/// You start scheduling multiple SDR multicore jobs. The first job is bound to the first group
/// which cointains cores 0, 1 and 2. The second job is then bound to the second group, which
/// contains cores 6, 7 and 8. It is *not* bound to the cores 3, 4 and 5, which belong to the first
/// group. They would fight for the same cache, which isn't ideal. Those cores will only be used
/// once all 8 groups have already a single unit bound.
///
/// Not necessarily all cores will be used. If you e.g. have a system as in the example above, but
/// your unit is of size 4 (instead of 3), then only a single unit fits (due to its size) into a
/// single group. This would mean that the first group would only consist of cores 0, 1, 2 and 3.
/// Cores 4, 5 would be unassigned. If you schedule more than 8 multicore SDR jobs, those jobs can
/// pick any core, whicher the operating system decides to use.
fn create_core_units(
    core_count: usize,
    group_count: usize,
    cores_per_unit: usize,
    allowed_cores: &hwloc::CpuSet,
) -> Vec<Vec<usize>> {
    assert_eq!(0, core_count % group_count);
    // The number of cores that belong to a single group.
    let group_size = core_count / group_count;

    // The number of units that can fit into single group.
    let units_per_group = group_size / cores_per_unit;

    // The total number of units that can be bound to specific cores on the system.
    let unit_count = group_count * units_per_group;

    debug!(
        "Cores: {}, Shared Caches: {}, cores per cache (group_size): {}, cores per unit: {}",
        core_count, group_count, group_size, cores_per_unit
    );

    let core_units = (0..unit_count)
        .map(|i| {
            (0..cores_per_unit)
                .filter_map(|j| {
                    // Every group gets a single unit assigned first. Only if all groups have
                    // already one unit, a second one will be assigned if possible. This would then
                    // be the second "round" of assignments.
                    let round = i / group_count;
                    // The index of the core that is bound to a unit.
                    let core_index = (j + i * group_size) % core_count + (round * cores_per_unit);
                    assert!(core_index < core_count);

                    allowed_cores
                        .is_set(core_index.try_into().ok()?)
                        .then_some(core_index)
                })
                .collect::<Vec<_>>()
        })
        .filter(|x| !x.is_empty())
        .collect::<Vec<_>>();
    debug!("Core units: {:?}", core_units);
    core_units
}

/// Returns the number of caches that are shared between cores.
///
/// The hwloc topology is traverse upwards starting at the given depth. As soon as there are less
/// objects than cores, we expect it to be a cache that is shared between those cores.
///
/// When traversing upwards from the cores, the first level you reach could e.g. be a L2 cache
/// which every core has its own. But then you might reach the L3 cache, that is shared between
/// several cores.
fn get_shared_cache_count(topo: &Topology, depth: u32, core_count: usize) -> usize {
    let mut depth = depth;
    while depth > 0 {
        let obj_count: usize = topo
            .size_at_depth(depth)
            .try_into()
            .expect("Platform must be at lest 32-bit");
        if obj_count < core_count {
            return obj_count;
        }
        depth -= 1;
    }
    1
}

fn core_units(cores_per_unit: usize) -> Option<Vec<Mutex<CoreUnit>>> {
    let topo = TOPOLOGY.lock().expect("poisoned lock");

    // At which depths the cores within one package are. If you think of the "depths" as a
    // directory tree, it's the directory where all cores are stored.
    let core_depth = match topo.depth_or_below_for_type(&ObjectType::Core) {
        Ok(depth) => depth,
        Err(_) => return None,
    };

    let all_cores = topo
        .objects_with_type(&ObjectType::Core)
        .expect("objects_with_type failed");

    let allowed_cores = topo
        .get_cpubind(hwloc::CpuBindFlags::empty())
        .unwrap_or_else(|| {
            topo.object_at_root()
                .allowed_cpuset()
                .unwrap_or_else(hwloc::CpuSet::full)
        });

    // The total number of physical cores, even across packages.
    let core_count = all_cores.len();

    // The number of separate caches the cores are grouped into. There could e.g. be a machine with
    // 48 cores. Those cores are separated into 2 packages, where each of them has 4 sepearate
    // caches, where each cache contains 6 cores. Then the `group_count` would be 8.
    let group_count = get_shared_cache_count(&topo, core_depth, core_count);

    // The list of units the multicore SDR threads can be bound to.
    let core_units = create_core_units(core_count, group_count, cores_per_unit, &allowed_cores);
    // this needs to take the all_cores vec instead of just a core count
    Some(
        core_units
            .iter()
            .map(|unit| {
                let unit_core_index = unit.iter().map(|core| CoreIndex(*core)).collect();
                Mutex::new(unit_core_index)
            })
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cores() {
        fil_logger::maybe_init();
        core_units(2);
    }

    #[test]
    #[cfg(feature = "isolated-testing")]
    // This test should not be run while other tests are running, as
    // the cores we're working with may otherwise be busy and cause a
    // failure.
    fn test_checkout_cores() {
        fil_logger::maybe_init();
        let checkout1 = checkout_core_group();
        dbg!(&checkout1);
        let checkout2 = checkout_core_group();
        dbg!(&checkout2);

        // This test might fail if run on a machine with fewer than four cores.
        match (checkout1, checkout2) {
            (Some(c1), Some(c2)) => assert!(*c1 != *c2),
            _ => panic!("failed to get two checkouts"),
        }
    }

    #[test]
    fn test_create_core_units() {
        fil_logger::maybe_init();

        let ci = create_core_units(18, 1, 4, &(0..18).collect());
        assert_eq!(
            ci,
            [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]
        );

        let dc = create_core_units(32, 2, 4, &(0..32).collect());
        assert_eq!(
            dc,
            [
                [0, 1, 2, 3],
                [16, 17, 18, 19],
                [4, 5, 6, 7],
                [20, 21, 22, 23],
                [8, 9, 10, 11],
                [24, 25, 26, 27],
                [12, 13, 14, 15],
                [28, 29, 30, 31]
            ]
        );

        let amd = create_core_units(16, 4, 4, &(0..16).collect());
        assert_eq!(
            amd,
            [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]
        );

        let amd_not_filled = create_core_units(16, 4, 3, &(0..16).collect());
        assert_eq!(
            amd_not_filled,
            [[0, 1, 2], [4, 5, 6], [8, 9, 10], [12, 13, 14]]
        );

        let amd_not_filled = create_core_units(16, 4, 3, &(0..16).collect());
        assert_eq!(
            amd_not_filled,
            [[0, 1, 2], [4, 5, 6], [8, 9, 10], [12, 13, 14]]
        );

        let intel = create_core_units(16, 2, 3, &(0..16).collect());
        assert_eq!(intel, [[0, 1, 2], [8, 9, 10], [3, 4, 5], [11, 12, 13]]);

        let sp = create_core_units(48, 8, 3, &(0..48).collect());
        assert_eq!(
            sp,
            [
                [0, 1, 2],
                [6, 7, 8],
                [12, 13, 14],
                [18, 19, 20],
                [24, 25, 26],
                [30, 31, 32],
                [36, 37, 38],
                [42, 43, 44],
                [3, 4, 5],
                [9, 10, 11],
                [15, 16, 17],
                [21, 22, 23],
                [27, 28, 29],
                [33, 34, 35],
                [39, 40, 41],
                [45, 46, 47]
            ]
        );

        let sp_not_filled = create_core_units(48, 8, 4, &(0..48).collect());
        assert_eq!(
            sp_not_filled,
            [
                [0, 1, 2, 3],
                [6, 7, 8, 9],
                [12, 13, 14, 15],
                [18, 19, 20, 21],
                [24, 25, 26, 27],
                [30, 31, 32, 33],
                [36, 37, 38, 39],
                [42, 43, 44, 45]
            ]
        );

        let laptop = create_core_units(4, 1, 2, &(0..4).collect());
        assert_eq!(laptop, [[0, 1], [2, 3]]);
        let laptop_not_filled = create_core_units(4, 1, 3, &(0..4).collect());
        assert_eq!(laptop_not_filled, [[0, 1, 2]]);

        let amd_limited_0 = create_core_units(16, 4, 4, &(0..8).collect());
        assert_eq!(amd_limited_0, [[0, 1, 2, 3], [4, 5, 6, 7]]);

        let amd_limited_1 = create_core_units(16, 4, 4, &(8..16).collect());
        assert_eq!(amd_limited_1, [[8, 9, 10, 11], [12, 13, 14, 15]]);

        let sp_limited_0 = create_core_units(48, 8, 3, &(0..24).collect());
        assert_eq!(
            sp_limited_0,
            [
                [0, 1, 2],
                [6, 7, 8],
                [12, 13, 14],
                [18, 19, 20],
                [3, 4, 5],
                [9, 10, 11],
                [15, 16, 17],
                [21, 22, 23],
            ]
        );

        let sp_limited_1 = create_core_units(48, 8, 3, &(24..48).collect());
        assert_eq!(
            sp_limited_1,
            [
                [24, 25, 26],
                [30, 31, 32],
                [36, 37, 38],
                [42, 43, 44],
                [27, 28, 29],
                [33, 34, 35],
                [39, 40, 41],
                [45, 46, 47]
            ]
        );

        let limited_group = create_core_units(
            16,
            4,
            4,
            &vec![0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14]
                .into_iter()
                .collect(),
        );
        assert_eq!(
            limited_group,
            [[0, 1, 2], [4, 5, 6], [8, 9, 10], [12, 13, 14],]
        );

        let limited_non_continuous = create_core_units(48, 8, 3, &(0..12).chain(24..36).collect());
        assert_eq!(
            limited_non_continuous,
            [
                [0, 1, 2],
                [6, 7, 8],
                [24, 25, 26],
                [30, 31, 32],
                [3, 4, 5],
                [9, 10, 11],
                [27, 28, 29],
                [33, 34, 35],
            ]
        );
    }
}
