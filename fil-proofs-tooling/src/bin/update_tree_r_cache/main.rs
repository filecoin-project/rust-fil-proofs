use std::fs::{self, create_dir_all, remove_dir_all, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bincode::deserialize;
use clap::{value_t, App, Arg, SubCommand};
use filecoin_hashers::Hasher;
use filecoin_proofs::{
    is_sector_shape_base, is_sector_shape_sub2, is_sector_shape_sub8, is_sector_shape_top2,
    with_shape, DefaultTreeDomain, PersistentAux, SectorShapeBase, SectorShapeSub2,
    SectorShapeSub8, SectorShapeTop2, OCT_ARITY,
};
use generic_array::typenum::Unsigned;
use memmap::MmapOptions;
use merkletree::{
    merkle::get_merkle_tree_len,
    store::{ExternalReader, ReplicaConfig, Store, StoreConfig},
};
use storage_proofs_core::{
    cache_key::CacheKey,
    merkle::{
        create_lc_tree, get_base_tree_count, split_config_and_replica, LCStore, LCTree,
        MerkleTreeTrait,
    },
    util::{default_rows_to_discard, NODE_SIZE},
};
use tempfile::tempdir;

fn get_tree_r_info(
    sector_size: usize,
    cache: &Path,
    replica_path: &Path,
) -> Result<(usize, usize, Vec<StoreConfig>, ReplicaConfig)> {
    let tree_count = with_shape!(sector_size as u64, get_base_tree_count);

    // Number of nodes per base tree
    let base_tree_leafs = sector_size / NODE_SIZE / tree_count;

    // If the cache dir doesn't exist, create it
    if !Path::new(&cache).exists() {
        create_dir_all(&cache)?;
    }

    // Create a StoreConfig from the provided cache path
    let tree_r_last_config = StoreConfig::new(
        &cache,
        CacheKey::CommRLastTree.to_string(),
        default_rows_to_discard(base_tree_leafs, OCT_ARITY),
    );

    // Split the config based on the number of nodes required
    let (configs, replica_config) = split_config_and_replica(
        tree_r_last_config,
        replica_path.to_path_buf(),
        base_tree_leafs,
        tree_count,
    )?;

    Ok((tree_count, base_tree_leafs, configs, replica_config))
}

fn get_tree_r_last_root(
    base_tree_leafs: usize,
    sector_size: u64,
    configs: &[StoreConfig],
    replica_config: &ReplicaConfig,
) -> Result<DefaultTreeDomain> {
    let base_tree_len = get_merkle_tree_len(base_tree_leafs, OCT_ARITY)?;
    let tree_r_last_root = if is_sector_shape_base(sector_size) {
        ensure!(configs.len() == 1, "Invalid tree-shape specified");
        let store = LCStore::<DefaultTreeDomain>::new_from_disk_with_reader(
            base_tree_len,
            OCT_ARITY,
            &configs[0],
            ExternalReader::new_from_path(&replica_config.path)?,
        )?;

        let tree_r_last = SectorShapeBase::from_data_store(store, base_tree_leafs)?;
        tree_r_last.root()
    } else if is_sector_shape_sub2(sector_size) {
        let tree_r_last = SectorShapeSub2::from_store_configs_and_replica(
            base_tree_leafs,
            &configs,
            &replica_config,
        )?;
        tree_r_last.root()
    } else if is_sector_shape_sub8(sector_size) {
        let tree_r_last = SectorShapeSub8::from_store_configs_and_replica(
            base_tree_leafs,
            &configs,
            &replica_config,
        )?;
        tree_r_last.root()
    } else if is_sector_shape_top2(sector_size) {
        let tree_r_last = SectorShapeTop2::from_sub_tree_store_configs_and_replica(
            base_tree_leafs,
            &configs,
            &replica_config,
        )?;
        tree_r_last.root()
    } else {
        panic!("Unsupported sector size");
    };

    Ok(tree_r_last_root)
}

fn get_persistent_aux(cache: &Path) -> Result<PersistentAux<DefaultTreeDomain>> {
    let p_aux: PersistentAux<DefaultTreeDomain> = {
        let p_aux_path = cache.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    Ok(p_aux)
}

fn build_tree_r_last<Tree: MerkleTreeTrait>(
    sector_size: usize,
    cache: &Path,
    replica_path: &Path,
) -> Result<(<Tree::Hasher as Hasher>::Domain, Vec<DefaultTreeDomain>)> {
    let (tree_count, base_tree_leafs, configs, replica_config) =
        get_tree_r_info(sector_size, cache, replica_path)?;

    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&replica_path)
        .with_context(|| format!("could not open replica_path={:?}", replica_path))?;
    let input_mmap = unsafe {
        MmapOptions::new()
            .map(&f_data)
            .with_context(|| format!("could not mmap replica_path={:?}", replica_path))?
    };

    let mut base_tree_roots: Vec<DefaultTreeDomain> = Vec::with_capacity(tree_count);
    for (i, config) in configs.iter().enumerate().take(tree_count) {
        let offset = replica_config.offsets[i];

        let slice = &input_mmap[offset..(offset + (sector_size / tree_count))];
        let store_path = StoreConfig::data_path(&config.path, &config.id);
        println!(
            "Building tree_r_last {}/{}, [nodes={}, rows_to_discard={}, offsets={}-{}] in {:?}",
            i + 1,
            tree_count,
            base_tree_leafs,
            config.rows_to_discard,
            offset,
            (offset + (sector_size / tree_count)),
            &store_path
        );
        let tree = SectorShapeBase::from_byte_slice_with_config(slice, config.clone())?;
        base_tree_roots.push(tree.root());
    }

    let tree_r_last = create_lc_tree::<
        LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    >(
        get_merkle_tree_len(base_tree_leafs, Tree::Arity::to_usize())?,
        &configs,
        &replica_config,
    )?;

    Ok((tree_r_last.root(), base_tree_roots))
}

fn run_rebuild(
    sector_size: usize,
    cache: &Path,
    replica_path: &Path,
) -> Result<(DefaultTreeDomain, Vec<DefaultTreeDomain>)> {
    with_shape!(
        sector_size as u64,
        build_tree_r_last,
        sector_size,
        cache,
        replica_path
    )
}

fn run_inspect(sector_size: usize, cache: &Path, replica_path: &Path) -> Result<()> {
    let (_tree_count, base_tree_leafs, configs, replica_config) =
        get_tree_r_info(sector_size, cache, replica_path)?;
    let tree_r_last_root = get_tree_r_last_root(
        base_tree_leafs,
        sector_size as u64,
        &configs,
        &replica_config,
    )?;
    let p_aux = get_persistent_aux(&cache)?;

    println!("CommRLast from p_aux: {:?}", p_aux.comm_r_last);
    println!(
        "CommRLast [cached tree_r_last root]: {:?}",
        tree_r_last_root
    );
    let status = if tree_r_last_root == p_aux.comm_r_last {
        "MATCH"
    } else {
        "MISMATCH"
    };
    println!("Cached inspection shows a {} of CommRLast", status);

    Ok(())
}

fn run_verify(sector_size: usize, cache: &Path, replica_path: &Path) -> Result<()> {
    let (tree_count, base_tree_leafs, configs, replica_config) =
        get_tree_r_info(sector_size, cache, replica_path)?;
    let base_tree_len = get_merkle_tree_len(base_tree_leafs, OCT_ARITY)?;

    let match_str = |a, b| -> &str {
        if a == b {
            "MATCH"
        } else {
            "MISMATCH"
        }
    };

    // First, read the roots from the cached trees on disk
    let mut cached_base_tree_roots: Vec<DefaultTreeDomain> = Vec::with_capacity(tree_count);
    for (i, config) in configs.iter().enumerate().take(tree_count) {
        let store = LCStore::new_from_disk_with_reader(
            base_tree_len,
            OCT_ARITY,
            &config,
            ExternalReader::new_from_config(&replica_config, i)?,
        )?;
        cached_base_tree_roots.push(store.last()?);
    }

    // Retrieve the tree_r_last root from the cached trees on disk.
    let tree_r_last_root = get_tree_r_last_root(
        base_tree_leafs,
        sector_size as u64,
        &configs,
        &replica_config,
    )?;

    // Read comm_r_last from the persistent aux in the cache dir
    let p_aux: PersistentAux<DefaultTreeDomain> = {
        let p_aux_path = cache.join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    // Rebuild each of the tree_r_last base trees (in a new temp dir so as not to interfere
    // with any existing ones on disk) and check if the roots match what's cached on disk
    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path();
    create_dir_all(&tmp_path)?;

    let (rebuilt_tree_r_last_root, rebuilt_base_tree_roots) =
        run_rebuild(sector_size, &tmp_path, &replica_path)?;

    remove_dir_all(&tmp_path)?;

    let status = match_str(tree_r_last_root, p_aux.comm_r_last);
    let rebuilt_status = match_str(rebuilt_tree_r_last_root, p_aux.comm_r_last);

    println!();
    for (i, (cached_root, rebuilt_root)) in cached_base_tree_roots
        .iter()
        .zip(rebuilt_base_tree_roots)
        .enumerate()
    {
        println!(
            "tree_r_last {}/{} inspection shows a {} of base tree root {:?}",
            i + 1,
            tree_count,
            match_str(*cached_root, rebuilt_root),
            rebuilt_root
        );
        if *cached_root != rebuilt_root {
            println!(
                "Cached root {:?}, Rebuilt root {:?}",
                cached_root, rebuilt_root
            );
        }
    }

    println!();
    println!(
        "CommRLast from p_aux                : {:?}",
        p_aux.comm_r_last
    );
    println!(
        "CommRLast [cached tree_r_last root] : {:?}",
        tree_r_last_root
    );
    println!(
        "CommRLast [rebuilt tree_r_last root]: {:?}",
        rebuilt_tree_r_last_root
    );
    println!();
    println!(
        " Cached inspection shows a {} of CommRLast {:?}",
        status, tree_r_last_root
    );
    println!(
        "Rebuilt inspection shows a {} of CommRLast {:?}",
        rebuilt_status, rebuilt_tree_r_last_root
    );

    Ok(())
}

fn main() -> Result<()> {
    fil_logger::init();

    let rebuild_cmd = SubCommand::with_name("rebuild")
        .about("Rebuild tree_r_last trees from replica")
        .arg(
            Arg::with_name("size")
                .required(true)
                .long("size")
                .default_value("34359738368")
                .help("The data size in bytes")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("replica")
                .long("replica")
                .help("The replica file")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cache")
                .long("cache")
                .help("The cache directory for the output trees")
                .required(true)
                .takes_value(true),
        );

    let inspect_cmd = SubCommand::with_name("inspect")
        .about("Inspect tree_r_last trees and match with p_aux in cache")
        .arg(
            Arg::with_name("size")
                .required(true)
                .long("size")
                .default_value("34359738368")
                .help("The data size in bytes")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("replica")
                .long("replica")
                .help("The replica file")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cache")
                .long("cache")
                .help("The cache directory for the output trees")
                .required(true)
                .takes_value(true),
        );

    let verify_cmd = SubCommand::with_name("verify")
        .about("Verify tree_r_last trees and check for cache mis-match")
        .arg(
            Arg::with_name("size")
                .required(true)
                .long("size")
                .default_value("34359738368")
                .help("The data size in bytes")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("replica")
                .long("replica")
                .help("The replica file")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cache")
                .long("cache")
                .help("The cache directory for the output trees")
                .required(true)
                .takes_value(true),
        );

    let matches = App::new("update_tree_r_cache")
        .version("0.1")
        .subcommand(rebuild_cmd)
        .subcommand(inspect_cmd)
        .subcommand(verify_cmd)
        .get_matches();

    match matches.subcommand() {
        ("rebuild", Some(m)) => {
            let cache = value_t!(m, "cache", PathBuf)?;
            let replica = value_t!(m, "replica", PathBuf)?;
            let size = value_t!(m, "size", usize)
                .expect("could not convert `size` CLI argument to `usize`");
            run_rebuild(size, cache.as_path(), replica.as_path())?;
        }
        ("inspect", Some(m)) => {
            let cache = value_t!(m, "cache", PathBuf)?;
            let replica = value_t!(m, "replica", PathBuf)?;
            let size = value_t!(m, "size", usize)
                .expect("could not convert `size` CLI argument to `usize`");
            run_inspect(size, cache.as_path(), replica.as_path())?;
        }
        ("verify", Some(m)) => {
            let cache = value_t!(m, "cache", PathBuf)?;
            let replica = value_t!(m, "replica", PathBuf)?;
            let size = value_t!(m, "size", usize)
                .expect("could not convert `size` CLI argument to `usize`");
            run_verify(size, cache.as_path(), replica.as_path())?;
        }
        _ => panic!("Unrecognized subcommand"),
    }

    Ok(())
}
