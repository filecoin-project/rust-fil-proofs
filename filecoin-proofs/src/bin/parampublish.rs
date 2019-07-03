use clap::{App, Arg, ArgMatches};
use failure::err_msg;
use filecoin_proofs::param::*;
use regex::Regex;
use std::collections::btree_map::BTreeMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;
use std::process::{exit, Command};
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

fn publish(matches: &ArgMatches) -> Result<()> {
    let files = get_files_from_cache()?;
    let file_metadata = to_cached_file_metadata(&files);

    let parameter_id_to_parameter_metadata: BTreeMap<&str, &CachedFileMetadata> = file_metadata
        .iter()
        .flat_map(|entry| {
            match entry {
                CachedFileMetadata::ParameterMetadata { parameter_id, .. } => {
                    Some((parameter_id.as_str(), entry))
                }
                _ => None,
            }
            .into_iter()
        })
        .collect();

    let mut publishable_file_metadata = file_metadata
        .iter()
        .flat_map(|entry| CachedFileMetadata::try_publishable(entry.clone()).into_iter())
        .collect::<Vec<PublishableCachedFileMetadata>>();

    if !matches.is_present("all") {
        publishable_file_metadata = publishable_file_metadata
            .into_iter()
            .filter(|entry| choose(&entry.filename()))
            .collect();

        println!();
    };

    if !publishable_file_metadata.is_empty() {
        let mut manifest: Manifest = BTreeMap::new();

        println!(
            "publishing {} parameters...",
            publishable_file_metadata.len()
        );
        println!();

        for publishable in publishable_file_metadata {
            println!("publishing: {}", publishable.filename());
            print!("publishing to IPFS... ");
            io::stdout().flush().unwrap();

            if let Some(file_metadata) =
                parameter_id_to_parameter_metadata.get(publishable.parameter_id())
            {
                let parameter_metadata_file = File::open(file_metadata.path())?;

                let parameter_metadata: CacheEntryMetadata =
                    serde_json::from_reader(parameter_metadata_file)?;

                match publish_cached_file_to_ipfs(&publishable) {
                    Ok(cid) => {
                        println!("ok");
                        print!("generating digest... ");
                        io::stdout().flush().unwrap();

                        let key = publishable.filename().to_string();

                        let value = ManifestEntry {
                            sector_size: parameter_metadata.sector_size,
                            cid,
                            digest: get_cached_file_digest(publishable.filename())?,
                        };

                        manifest.insert(key, value);

                        println!("ok");
                    }
                    Err(err) => eprintln!("error: {}", err),
                }
            } else {
                eprintln!(
                    "no metadata file found for entry with filename {}",
                    publishable.filename()
                );
            }

            println!();
        }

        let manifest_path = PathBuf::from(matches.value_of("json").unwrap_or("./parameters.json"));

        write_manifest_json(&manifest, &manifest_path)?;
    } else {
        eprintln!("no parameters to publish");
    }

    Ok(())
}

fn publish_cached_file_to_ipfs(file_meta: &PublishableCachedFileMetadata) -> Result<String> {
    let path = get_cached_file_path(file_meta.filename());

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
