use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{read_dir, File};
use std::io;
use std::io::prelude::*;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

use clap::{App, Arg, ArgMatches};
use failure::err_msg;
use itertools::Itertools;
use regex::Regex;

use filecoin_proofs::param::*;
use storage_proofs::error::Error::Unclassified;
use storage_proofs::parameter_cache::{
    parameter_cache_dir, CacheEntryMetadata, GROTH_PARAMETER_EXT, PARAMETER_CACHE_DIR,
    PARAMETER_METADATA_EXT, VERIFYING_KEY_EXT,
};

const ERROR_IPFS_COMMAND: &str = "failed to run ipfs";
const ERROR_IPFS_OUTPUT: &str = "failed to capture ipfs output";
const ERROR_IPFS_PARSE: &str = "failed to parse ipfs output";
const ERROR_IPFS_PUBLISH: &str = "failed to publish via ipfs";

pub fn main() {
    let matches = App::new("parampublish")
        .version("1.0")
        .about(
            &format!(
                "
Set $FILECOIN_PARAMETER_CACHE to specify parameter directory.
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
                .help("Publish all local parameters"),
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
    let mut filenames = get_filenames_in_cache_dir()?
        .into_iter()
        .filter(|f| {
            has_extension(f, GROTH_PARAMETER_EXT)
                || has_extension(f, VERIFYING_KEY_EXT)
                || has_extension(f, PARAMETER_METADATA_EXT)
        })
        .collect_vec();

    // build a mapping from parameter id to metadata filename
    let parameter_id_to_metadata_filename: BTreeMap<String, String> = filenames
        .clone()
        .iter()
        .flat_map(|filename| {
            PathBuf::from(filename)
                .extension()
                .and_then(OsStr::to_str)
                .and_then(|s| match s {
                    PARAMETER_METADATA_EXT => filename_to_parameter_id(filename)
                        .map(|id| (id.to_string(), filename.clone())),
                    _ => None,
                })
                .into_iter()
        })
        .collect();

    // exclude parameter metadata files, which should not be published
    filenames = filenames
        .into_iter()
        .filter(|f| !has_extension(f, PARAMETER_METADATA_EXT))
        .collect_vec();

    if !matches.is_present("all") {
        filenames = choose_from(filenames)?;
        println!();
    };

    let json = PathBuf::from(matches.value_of("json").unwrap_or("./parameters.json"));
    let mut parameter_map: ParameterMap = BTreeMap::new();

    if !filenames.is_empty() {
        println!("publishing {} parameters...", filenames.len());
        println!();

        for filename in filenames {
            let id = filename_to_parameter_id(&filename).ok_or_else(|| {
                Unclassified(format!("failed to parse id from file name {}", filename))
            })?;

            let name = parameter_id_to_metadata_filename.get(&id).ok_or_else(|| {
                Unclassified(format!("no metadata file found for parameter id {}", id))
            })?;

            let parameter_metadata_file = File::open(get_full_path_for_file_within_cache(name))?;

            let parameter_metadata: CacheEntryMetadata =
                serde_json::from_reader(parameter_metadata_file)?;

            println!("publishing: {}", filename);
            print!("publishing to ipfs... ");
            io::stdout().flush().unwrap();

            match publish_parameter_file(&filename) {
                Ok(cid) => {
                    println!("ok");
                    print!("generating digest... ");
                    io::stdout().flush().unwrap();

                    let digest = get_digest_for_file_within_cache(&filename)?;
                    let data = ParameterData {
                        cid,
                        digest,
                        sector_size: parameter_metadata.sector_size,
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
        println!("no parameters to publish");
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

fn filename_to_parameter_id<'a, P: AsRef<Path> + 'a>(filename: P) -> Option<String> {
    filename
        .as_ref()
        .file_stem()
        .and_then(OsStr::to_str)
        .map(ToString::to_string)
}

fn publish_parameter_file(filename: &str) -> Result<String> {
    let path = get_full_path_for_file_within_cache(filename);

    let output = Command::new("ipfs")
        .arg("add")
        .arg(&path)
        .output()
        .expect(ERROR_IPFS_COMMAND);

    if !output.status.success() {
        Err(err_msg(ERROR_IPFS_PUBLISH))
    } else {
        let pattern = Regex::new("added ([^ ]+) ")?;
        let string = String::from_utf8(output.stdout)?;
        let captures = pattern.captures(string.as_str()).expect(ERROR_IPFS_OUTPUT);
        let cid = captures.get(1).expect(ERROR_IPFS_PARSE);

        Ok(cid.as_str().to_string())
    }
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
