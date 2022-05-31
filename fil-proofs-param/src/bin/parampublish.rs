use std::collections::BTreeMap;
use std::env;
use std::fs::{read_dir, File};
use std::io::{stderr, Write};
use std::path::Path;
use std::process::{exit, Command};

use anyhow::{ensure, Context, Result};
use dialoguer::{theme::ColorfulTheme, MultiSelect, Select};
use filecoin_proofs::{
    param::{
        add_extension, filename_to_parameter_id, get_digest_for_file_within_cache,
        get_full_path_for_file_within_cache, has_extension, parameter_id_to_metadata_map,
    },
    SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_GIB, SECTOR_SIZE_512_MIB, SECTOR_SIZE_64_GIB,
    SECTOR_SIZE_8_MIB,
};
use humansize::{file_size_opts, FileSize};
use itertools::Itertools;
use lazy_static::lazy_static;
use log::{error, info, trace, warn};
use storage_proofs_core::parameter_cache::{
    parameter_cache_dir, parameter_cache_dir_name, ParameterData, ParameterMap,
    GROTH_PARAMETER_EXT, PARAMETER_METADATA_EXT, VERIFYING_KEY_EXT,
};
use structopt::StructOpt;

lazy_static! {
    static ref CLI_ABOUT: String = format!(
        "Publish param files found in the cache directory specified by the env-var \
        $FIL_PROOFS_PARAMETER_CACHE (or if the env-var is not set, the dir: {}) to ipfs",
        parameter_cache_dir_name(),
    );
}

// Default sector-sizes to publish.
const DEFAULT_SECTOR_SIZES: [u64; 5] = [
    SECTOR_SIZE_2_KIB,
    SECTOR_SIZE_8_MIB,
    SECTOR_SIZE_512_MIB,
    SECTOR_SIZE_32_GIB,
    SECTOR_SIZE_64_GIB,
];

#[derive(Clone, Debug, PartialEq)]
struct FileInfo {
    id: String,
    filename: String,
    sector_size: u64,
    version: String,
    ext: String,
}

#[inline]
fn human_size(sector_size: u64) -> String {
    sector_size.file_size(file_size_opts::BINARY).unwrap()
}

/// Returns `true` if a params filename starts with a version string and has a valid extension.
fn is_well_formed_filename(filename: &str) -> bool {
    let ext_is_valid = has_extension(filename, GROTH_PARAMETER_EXT)
        || has_extension(filename, VERIFYING_KEY_EXT)
        || has_extension(filename, PARAMETER_METADATA_EXT);
    if !ext_is_valid {
        warn!("file has invalid extension: {}, ignoring file", filename);
        return false;
    }
    let version = filename.split('-').next().unwrap();
    if version.len() < 2 {
        return false;
    }
    let version_is_valid =
        version.get(0..1).unwrap() == "v" && version[1..].chars().all(|c| c.is_digit(10));
    if !version_is_valid {
        warn!(
            "filename does not start with version: {}, ignoring file",
            filename
        );
        return false;
    }
    true
}

fn get_filenames_in_cache_dir() -> Vec<String> {
    let path = parameter_cache_dir();
    if !path.exists() {
        warn!("param cache dir does not exist (no files to publish), exiting");
        exit(1);
    }
    // Ignore entries that are not files or have a non-Utf8 filename.
    read_dir(path)
        .expect("failed to read param cache dir")
        .filter_map(|entry_res| {
            let path = entry_res.expect("failed to read directory entry").path();
            if !path.is_file() {
                return None;
            }
            path.file_name()
                .and_then(|os_str| os_str.to_str())
                .map(|s| s.to_string())
        })
        .collect()
}

fn publish_file(ipfs_bin: &str, filename: &str) -> Result<String> {
    let path = get_full_path_for_file_within_cache(filename);
    let output = Command::new(ipfs_bin)
        .args(&["add", "-Q", path.to_str().unwrap()])
        .output()
        .expect("failed to run ipfs subprocess");
    stderr()
        .write_all(&output.stderr)
        .with_context(|| "failed to write ipfs' stderr")?;
    ensure!(output.status.success(), "failed to publish via ipfs");
    let cid = String::from_utf8(output.stdout)
        .with_context(|| "ipfs' stdout is not valid Utf8")?
        .trim()
        .to_string();
    Ok(cid)
}

/// Write the parameters.json file (or file specified by `json_path`) containing the published
/// params' IPFS cid's.
fn write_param_map_to_disk(param_map: &ParameterMap, json_path: &str) -> Result<()> {
    let mut file = File::create(json_path).with_context(|| "failed to create json file")?;
    serde_json::to_writer_pretty(&mut file, &param_map).with_context(|| "failed to write json")?;
    Ok(())
}

#[derive(Debug, StructOpt)]
#[structopt(name = "parampublish", version = "1.0", about = CLI_ABOUT.as_str())]
struct Cli {
    #[structopt(
        long = "list-all",
        short = "a",
        help = "The user will be prompted to select the files to publish from the set of all files \
            found in the cache dir. Excluding the -a/--list-all flag will result in the user being \
            prompted for a single param version number for filtering-in files in the cache dir."
    )]
    list_all_files: bool,
    #[structopt(
        long = "ipfs-bin",
        value_name = "PATH TO IPFS BINARY",
        default_value = "ipfs",
        help = "Use a specific ipfs binary instead of searching for one in $PATH."
    )]
    ipfs_bin: String,
    #[structopt(
        long = "json",
        short = "j",
        value_name = "PATH",
        default_value = "parameters.json",
        help = "The path to write the parameters.json file."
    )]
    json_path: String,
}

pub fn main() {
    // Log all levels to stderr.
    env::set_var("RUST_LOG", "parampublish");
    fil_logger::init();

    let cli = Cli::from_args();

    let cache_dir = match env::var("FIL_PROOFS_PARAMETER_CACHE") {
        Ok(s) => s,
        _ => format!("{}", parameter_cache_dir().display()),
    };
    info!("using param cache dir: {}", cache_dir);

    if !Path::new(&cli.ipfs_bin).exists() {
        error!("ipfs binary not found: `{}`, exiting", cli.ipfs_bin);
        exit(1);
    }

    // Get the param-id's in the cache dir for which three files exist (.meta, .params, and .vk).
    let ids = {
        let filenames: Vec<String> = get_filenames_in_cache_dir()
            .into_iter()
            .filter(|filename| is_well_formed_filename(filename))
            .collect();
        trace!("found {} param files in cache dir", filenames.len());
        let mut ids: Vec<String> = filenames
            .iter()
            .map(|filename| filename_to_parameter_id(filename).unwrap())
            .unique()
            .collect_vec();
        ids.retain(|id| {
            filenames.contains(&add_extension(id, GROTH_PARAMETER_EXT))
                && filenames.contains(&add_extension(id, VERIFYING_KEY_EXT))
                && filenames.contains(&add_extension(id, PARAMETER_METADATA_EXT))
        });
        if ids.is_empty() {
            warn!("no file triples found, exiting");
            exit(0);
        }
        trace!("found {} file triples", ids.len());
        ids
    };

    // Read each param file's sector-size from its .meta file.
    let meta_map = parameter_id_to_metadata_map(&ids).unwrap_or_else(|e| {
        error!("failed to parse .meta file:\n{:?}\nexiting", e);
        exit(1);
    });

    // Store every param-id's .params and .vk file info.
    let mut infos = Vec::<FileInfo>::with_capacity(2 * ids.len());
    for id in &ids {
        let version = id.split('-').next().unwrap().to_string();
        let sector_size = meta_map[id].sector_size;
        infos.push(FileInfo {
            id: id.clone(),
            filename: add_extension(id, GROTH_PARAMETER_EXT),
            sector_size,
            version: version.clone(),
            ext: GROTH_PARAMETER_EXT.to_string(),
        });
        infos.push(FileInfo {
            id: id.clone(),
            filename: add_extension(id, VERIFYING_KEY_EXT),
            sector_size,
            version,
            ext: VERIFYING_KEY_EXT.to_string(),
        });
    }

    if cli.list_all_files {
        // Create two vectors, one containing the file infos sorted in the order with which they
        // will appear in the user prompt and a second for each param file's prompt string sorted
        // in the same way.
        let mut infos_sorted: Vec<&FileInfo> = Vec::with_capacity(infos.len());
        let mut items: Vec<String> = Vec::with_capacity(infos.len());
        infos
            .iter()
            .sorted_by(|info_1, info_2| {
                // Sort in descending order by version, then order each version's files by ascending
                // sector-size and filename, example order:
                // ("v28", 1024, "filename"), ("v28", 2056, "filename"), ("v27", 1024, "filename")
                let a = (&info_2.version, info_1.sector_size, &info_1.filename);
                let b = (&info_1.version, info_2.sector_size, &info_2.filename);
                a.cmp(&b)
            })
            .for_each(|info| {
                let item = format!("{} ({})", info.filename, human_size(info.sector_size));
                items.push(item);
                infos_sorted.push(info);
            });

        infos = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Select files to publish (press 'space' to select, 'return' to submit)")
            .items(&items[..])
            .interact()
            .expect("interaction failed")
            .into_iter()
            .map(|i| infos_sorted[i].clone())
            .collect();
    } else {
        let versions: Vec<String> = infos
            .iter()
            .map(|info| info.version.clone())
            .dedup()
            .sorted()
            .rev()
            .collect();

        let selected_version = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a version (press 'space' to select, 'q' to quit)")
            .default(0)
            .items(&versions[..])
            .interact_opt()
            .expect("interaction failed")
            .map(|i| versions[i].clone())
            .unwrap_or_else(|| {
                warn!("no versions selected, exiting");
                exit(0);
            });

        infos.retain(|info| info.version == selected_version);

        // Sort the param-ids by ascending sector-size. Associate each param-id (two files: .params and
        // .vk) with one prompt item.
        let mut ids_sorted = Vec::<String>::with_capacity(infos.len() / 2);
        let mut items = Vec::<String>::with_capacity(infos.len() / 2);
        let mut default_items: Vec<bool> = vec![];
        infos
            .iter()
            .sorted_by_key(|info| info.sector_size)
            .for_each(|info| {
                if !ids_sorted.contains(&info.id) {
                    let item = format!("{} ({})", human_size(info.sector_size), info.id);
                    items.push(item);
                    ids_sorted.push(info.id.clone());
                    default_items.push(DEFAULT_SECTOR_SIZES.contains(&info.sector_size));
                }
            });

        let selected_ids: Vec<&String> = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Select sizes to publish (press 'space' to select, 'return' to submit)")
            .items(&items[..])
            .defaults(&default_items)
            .interact()
            .expect("interaction failed")
            .into_iter()
            .map(|i| &ids_sorted[i])
            .collect();

        infos.retain(|info| selected_ids.contains(&&info.id));
    }

    let n_files_to_publish = infos.len();
    if n_files_to_publish == 0 {
        warn!("no params selected, exiting");
        exit(0);
    }
    trace!("{} files to publish", n_files_to_publish);

    // Publish files to ipfs.
    let mut param_map: ParameterMap = BTreeMap::new();

    for info in infos {
        trace!("publishing file to ipfs: {}", info.filename);
        match publish_file(&cli.ipfs_bin, &info.filename) {
            Ok(cid) => {
                info!("successfully published file to ipfs, cid={}", cid);
                let digest =
                    get_digest_for_file_within_cache(&info.filename).expect("failed to hash file");
                trace!("successfully hashed file: {}", digest);
                let param_data = ParameterData {
                    cid,
                    digest,
                    sector_size: info.sector_size,
                };
                param_map.insert(info.filename, param_data);
            }
            Err(e) => {
                error!("failed to publish file to ipfs:\n{:?}\nexiting", e);
                exit(1);
            }
        }
    }
    info!("finished publishing files");

    // Write parameters.json file containing published ipfs cid's.
    if let Err(e) = write_param_map_to_disk(&param_map, &cli.json_path) {
        error!("failed to write json file:\n{:?}\nexiting", e);
        exit(1);
    }
    info!("successfully wrote json file: {}", cli.json_path);
}
