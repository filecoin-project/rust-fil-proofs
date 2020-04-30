use std::collections::BTreeMap;
use std::fs::{read_dir, File};
use std::io;
use std::io::prelude::*;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

use anyhow::{ensure, Context, Result};
use clap::{App, Arg, ArgMatches};
use dialoguer::{theme::ColorfulTheme, Select};
use itertools::Itertools;

use filecoin_proofs::param::{
    choose_from, filename_to_parameter_id, get_digest_for_file_within_cache,
    get_full_path_for_file_within_cache, has_extension, parameter_id_to_metadata_map,
    ParameterData, ParameterMap,
};
use storage_proofs::parameter_cache::{
    parameter_cache_dir, CacheEntryMetadata, GROTH_PARAMETER_EXT, PARAMETER_CACHE_DIR,
    PARAMETER_METADATA_EXT, VERIFYING_KEY_EXT,
};

const ERROR_IPFS_COMMAND: &str = "failed to run ipfs";
const ERROR_IPFS_PUBLISH: &str = "failed to publish via ipfs";

pub fn main() {
    fil_logger::init();

    let matches = App::new("parampublish")
        .version("1.0")
        .about(
            &format!(
                "
Set $FIL_PROOFS_PARAMETER_CACHE to specify parameter directory.
Defaults to '{}'
",
                PARAMETER_CACHE_DIR
            )[..],
        )
        .arg(
            Arg::with_name("json")
                .value_name("JSON")
                .takes_value(true)
                .short("j")
                .long("json")
                .help("Use specific json file"),
        )
        .arg(
            Arg::with_name("all")
                .short("a")
                .long("all")
                .help("Publish all local Groth parameters and verifying keys"),
        )
        .arg(
            Arg::with_name("ipfs-bin")
                .takes_value(true)
                .short("i")
                .long("ipfs-bin")
                .help("Use specific ipfs binary instead of searching for one in $PATH"),
        )
        .get_matches();

    match publish(&matches) {
        Ok(_) => println!("done"),
        Err(err) => {
            println!("fatal error: {}", err);
            exit(1);
        }
    }
}

fn publish(matches: &ArgMatches) -> Result<()> {
    let ipfs_bin_path = matches.value_of("ipfs-bin").unwrap_or("ipfs");

    let filenames = get_filenames_in_cache_dir()?
        .into_iter()
        .filter(|f| {
            has_extension(f, GROTH_PARAMETER_EXT)
                || has_extension(f, VERIFYING_KEY_EXT)
                || has_extension(f, PARAMETER_METADATA_EXT)
        })
        .collect_vec();

    // build a mapping from parameter id to metadata
    let meta_map = parameter_id_to_metadata_map(&filenames)?;

    // split off parameter metadata files, which should not be published
    let (meta_filenames, mut filenames): (Vec<_>, Vec<_>) = filenames
        .into_iter()
        .partition(|f| has_extension(f, PARAMETER_METADATA_EXT));

    if !matches.is_present("all") {
        filenames = choose_from(&filenames, |filename| {
            filename_to_parameter_id(PathBuf::from(filename))
                .as_ref()
                .and_then(|p_id| meta_map.get(p_id).map(|x| x.sector_size))
        })?;
        println!();
    } else {
        // `--all` let's you select a specific version

        // Only consider files where there is also a corresponding meta file
        let versions: Vec<String> = meta_filenames
            .into_iter()
            // Split off the version of the parameters
            .map(|name| name.split('-').into_iter().next().unwrap().to_string())
            // Sort by descending order, newest parameter first
            .sorted_by(|a, b| Ord::cmp(&b, &a))
            .dedup()
            .collect();
        let selected_version = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a version (press 'q' to quit)")
            .default(0)
            .items(&versions[..])
            .interact_opt()
            .unwrap();
        let version = match selected_version {
            Some(index) => &versions[index],
            None => {
                println!("Aborted.");
                std::process::exit(1)
            }
        };
        filenames = filenames
            .into_iter()
            .filter(|name| name.starts_with(version))
            .collect_vec();
    }

    let json = PathBuf::from(matches.value_of("json").unwrap_or("./parameters.json"));
    let mut parameter_map: ParameterMap = BTreeMap::new();

    if !filenames.is_empty() {
        println!("publishing {} files...", filenames.len());
        println!();

        for filename in filenames {
            let id = filename_to_parameter_id(&filename)
                .with_context(|| format!("failed to parse id from file name {}", filename))?;

            let meta: &CacheEntryMetadata = meta_map
                .get(&id)
                .with_context(|| format!("no metadata found for parameter id {}", id))?;

            println!("publishing: {}", filename);
            print!("publishing to ipfs... ");
            io::stdout().flush().unwrap();

            match publish_parameter_file(&ipfs_bin_path, &filename) {
                Ok(cid) => {
                    println!("ok");
                    print!("generating digest... ");
                    io::stdout().flush().unwrap();

                    let digest = get_digest_for_file_within_cache(&filename)?;
                    let data = ParameterData {
                        cid,
                        digest,
                        sector_size: meta.sector_size,
                    };

                    parameter_map.insert(filename, data);

                    println!("ok");
                }
                Err(err) => println!("error: {}", err),
            }

            println!();
        }

        write_parameter_map_to_disk(&parameter_map, &json)?;
    } else {
        println!("no files to publish");
    }

    Ok(())
}

fn get_filenames_in_cache_dir() -> Result<Vec<String>> {
    let path = parameter_cache_dir();

    if path.exists() {
        Ok(read_dir(path)?
            .map(|f| f.unwrap().path())
            .filter(|p| p.is_file())
            .map(|p| {
                p.as_path()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect())
    } else {
        println!(
            "parameter directory '{}' does not exist",
            path.as_path().to_str().unwrap()
        );

        Ok(Vec::new())
    }
}

fn publish_parameter_file(ipfs_bin_path: &str, filename: &str) -> Result<String> {
    let path = get_full_path_for_file_within_cache(filename);

    let output = Command::new(ipfs_bin_path)
        .arg("add")
        .arg("-Q")
        .arg(&path)
        .output()
        .expect(ERROR_IPFS_COMMAND);

    ensure!(output.status.success(), ERROR_IPFS_PUBLISH);

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn write_parameter_map_to_disk<P: AsRef<Path>>(
    parameter_map: &ParameterMap,
    dest_path: P,
) -> Result<()> {
    let p: &Path = dest_path.as_ref();
    let file = File::create(p)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &parameter_map)?;

    Ok(())
}
