use std::fs::{create_dir_all, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{value_t, App, Arg, SubCommand};
use generic_array::typenum::{U0, U8};
use memmap::MmapOptions;
use merkletree::store::StoreConfig;

use filecoin_proofs::constants::*;
use filecoin_proofs::types::*;
use storage_proofs::cache_key::CacheKey;
use storage_proofs::merkle::LCTree;
use storage_proofs::merkle::{get_base_tree_count, split_config_and_replica};
use storage_proofs::util::{default_rows_to_discard, NODE_SIZE};

fn run_update(sector_size: usize, cache: PathBuf, replica_path: PathBuf) -> Result<()> {
    let tree_count = match sector_size as u64 {
        SECTOR_SIZE_2_KIB => get_base_tree_count::<SectorShape2KiB>(),
        SECTOR_SIZE_4_KIB => get_base_tree_count::<SectorShape4KiB>(),
        SECTOR_SIZE_16_KIB => get_base_tree_count::<SectorShape16KiB>(),
        SECTOR_SIZE_32_KIB => get_base_tree_count::<SectorShape32KiB>(),
        SECTOR_SIZE_512_MIB => get_base_tree_count::<SectorShape512MiB>(),
        SECTOR_SIZE_32_GIB => get_base_tree_count::<SectorShape32GiB>(),
        SECTOR_SIZE_64_GIB => get_base_tree_count::<SectorShape64GiB>(),
        _ => panic!("Unsupported sector size"),
    };
    // Number of nodes per base tree
    let nodes_count = sector_size / NODE_SIZE / tree_count;

    // If the cache dir doesn't exist, create it
    if !Path::new(&cache).exists() {
        create_dir_all(&cache)?;
    }

    // Create a StoreConfig from the provided cache path
    let tree_r_last_config = StoreConfig::new(
        &cache,
        CacheKey::CommRLastTree.to_string(),
        default_rows_to_discard(nodes_count, OCT_ARITY),
    );
    println!(
        "Using nodes_count {}, rows_to_discard {}",
        nodes_count,
        default_rows_to_discard(nodes_count, OCT_ARITY)
    );

    // Split the config based on the number of nodes required
    let (configs, replica_config) = split_config_and_replica(
        tree_r_last_config,
        replica_path.clone(),
        nodes_count,
        tree_count,
    )?;

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

    for i in 0..tree_count {
        let config = &configs[i];
        let offset = replica_config.offsets[i];

        let slice = &input_mmap[offset..(offset + (sector_size / tree_count))];
        let store_path = StoreConfig::data_path(&config.path, &config.id);
        println!(
            "Building tree_r_last {}/{}, {} nodes at replica offset {}-{} and storing in {:?}",
            i + 1,
            tree_count,
            nodes_count,
            offset,
            (offset + (sector_size / tree_count)),
            &store_path
        );
        LCTree::<DefaultTreeHasher, U8, U0, U0>::from_byte_slice_with_config(
            slice,
            config.clone(),
        )?;
    }

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
                .default_value("32")
                .help("The data size in GiB")
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
        .get_matches();

    match matches.subcommand() {
        ("rebuild", Some(m)) => {
            let cache = value_t!(m, "cache", PathBuf)?;
            let replica = value_t!(m, "replica", PathBuf)?;
            let size = value_t!(m, "size", usize)
                .expect("could not convert `size` CLI argument to `usize`");
            run_update(size, cache, replica)?;
        }
        _ => panic!("Unrecognized subcommand"),
    }

    Ok(())
}
