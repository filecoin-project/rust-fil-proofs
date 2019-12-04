use std::collections::BTreeMap;
use std::fs::{read_dir, File};
use std::io;
use std::io::prelude::*;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

use anyhow::{ensure, Context, Result};
use clap::{App, Arg, ArgMatches};
use itertools::Itertools;

use filecoin_proofs::param::*;
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

    let mut filenames = get_filenames_in_cache_dir()?
        .into_iter()
        .filter(|f| {
            has_extension(f, GROTH_PARAMETER_EXT)
                || has_extension(f, VERIFYING_KEY_EXT)
                || has_extension(f, PARAMETER_METADATA_EXT)
        })
        .collect_vec();

    // build a mapping from parameter id to metadata
    let meta_map = parameter_id_to_metadata_map(&filenames)?;

    // exclude parameter metadata files, which should not be published
    filenames = filenames
        .into_iter()
        .filter(|f| !has_extension(f, PARAMETER_METADATA_EXT))
        .collect_vec();

    if !matches.is_present("all") {
        filenames = choose_from(&filenames, |filename| {
            filename_to_parameter_id(PathBuf::from(filename))
                .as_ref()
                .and_then(|p_id| meta_map.get(p_id).map(|x| x.sector_size))
        })?;
        println!();
    };

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
