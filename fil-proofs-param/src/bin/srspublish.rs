use std::collections::BTreeMap;
use std::env;
use std::fs::{read_dir, File};
use std::io::{stderr, Write};
use std::path::Path;
use std::process::{exit, Command};

use anyhow::{ensure, Context, Result};
use filecoin_proofs::param::{
    get_digest_for_file_within_cache, get_full_path_for_file_within_cache, has_extension,
};
use lazy_static::lazy_static;
use log::{error, info, trace, warn};
use storage_proofs_core::parameter_cache::{
    parameter_cache_dir, parameter_cache_dir_name, ParameterData, ParameterMap,
    GROTH_PARAMETER_EXT, PARAMETER_METADATA_EXT, SRS_KEY_EXT, VERIFYING_KEY_EXT,
};
use structopt::StructOpt;

lazy_static! {
    static ref CLI_ABOUT: String = format!(
        "Publish srs file(s) found in the cache directory specified by the env-var \
        $FIL_PROOFS_PARAMETER_CACHE (or if the env-var is not set, the dir: {}) to ipfs",
        parameter_cache_dir_name(),
    );
}

/// Returns `true` if a params filename starts with a version string and has a valid extension.
fn is_well_formed_filename(filename: &str) -> bool {
    let ext_is_valid = has_extension(filename, SRS_KEY_EXT);
    if !ext_is_valid {
        if !has_extension(filename, GROTH_PARAMETER_EXT)
            && !has_extension(filename, VERIFYING_KEY_EXT)
            && !has_extension(filename, PARAMETER_METADATA_EXT)
        {
            warn!("file has invalid extension: {}, ignoring file", filename);
        }
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

/// Write the srs-inner-product.json file (or file specified by `json_path`) containing the published
/// params' IPFS cid's.
fn write_param_map_to_disk(param_map: &ParameterMap, json_path: &str) -> Result<()> {
    let mut file = File::create(json_path).with_context(|| "failed to create json file")?;
    serde_json::to_writer_pretty(&mut file, &param_map).with_context(|| "failed to write json")?;
    Ok(())
}

#[derive(Debug, StructOpt)]
#[structopt(name = "srspublish", version = "1.0", about = CLI_ABOUT.as_str())]
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
        default_value = "srs-inner-product.json",
        help = "The path to write the srs-inner-product.json file."
    )]
    json_path: String,
}

pub fn main() {
    // Log all levels to stderr.
    env::set_var("RUST_LOG", "srspublish");
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

    // Get the filenames in the cache dir (.srs).
    let filenames: Vec<String> = get_filenames_in_cache_dir()
        .into_iter()
        .filter(|filename| is_well_formed_filename(filename))
        .collect();
    trace!("found {} param files in cache dir", filenames.len());

    // Publish files to ipfs.
    let mut param_map: ParameterMap = BTreeMap::new();

    for filename in filenames {
        trace!("publishing file to ipfs: {}", filename);
        match publish_file(&cli.ipfs_bin, &filename) {
            Ok(cid) => {
                info!("successfully published file to ipfs, cid={}", cid);
                let digest =
                    get_digest_for_file_within_cache(&filename).expect("failed to hash file");
                trace!("successfully hashed file: {}", digest);
                let param_data = ParameterData {
                    cid,
                    digest,
                    sector_size: 0,
                };
                param_map.insert(filename, param_data);
            }
            Err(e) => {
                error!("failed to publish file to ipfs:\n{:?}\nexiting", e);
                exit(1);
            }
        }
    }
    info!("finished publishing files");

    // Write srs-inner-product.json file containing published ipfs cid's.
    if let Err(e) = write_param_map_to_disk(&param_map, &cli.json_path) {
        error!("failed to write json file:\n{:?}\nexiting", e);
        exit(1);
    }
    info!("successfully wrote json file: {}", cli.json_path);
}
