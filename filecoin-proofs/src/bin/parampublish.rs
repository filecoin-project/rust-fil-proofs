use clap::{App, Arg, ArgMatches};
use filecoin_proofs::param::*;
use itertools::Itertools;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::exit;
use storage_proofs::error::Error::Unclassified;
use storage_proofs::parameter_cache::{CacheEntryMetadata, PARAMETER_CACHE_DIR};

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

fn filename_to_parameter_id<'a, P: AsRef<Path> + 'a>(filename: P) -> Option<String> {
    filename
        .as_ref()
        .file_stem()
        .and_then(|os_str| os_str.to_str())
        .map(|s| s.to_string())
}

fn has_extension<S: AsRef<str>, P: AsRef<Path>>(filename: P, ext: S) -> bool {
    filename
        .as_ref()
        .extension()
        .and_then(|os_str| os_str.to_str())
        .map(|s| s == ext.as_ref())
        .unwrap_or(false)
}

fn publish(matches: &ArgMatches) -> Result<()> {
    let mut filenames = get_filenames_in_cache_dir()?;

    // build an mapping from parameter id to metadata filename
    let parameter_id_to_metadata_filename: BTreeMap<String, String> = filenames
        .clone()
        .iter()
        .flat_map(|filename| {
            PathBuf::from(filename)
                .extension()
                .and_then(OsStr::to_str)
                .and_then(|s| match s {
                    "meta" => filename_to_parameter_id(filename)
                        .map(|id| (id.to_string(), filename.clone())),
                    _ => None,
                })
                .into_iter()
        })
        .collect();

    // exclude parameter metadata files, which should not be published
    filenames = filenames
        .into_iter()
        .filter(|f| !has_extension(f, "meta"))
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

            let parameter_metadata_file = File::open(get_parameter_file_path(name))?;

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

                    let digest = get_parameter_digest(&filename)?;
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

        save_parameter_map(&parameter_map, &json)?;
    } else {
        println!("no parameters to publish");
    }

    Ok(())
}
