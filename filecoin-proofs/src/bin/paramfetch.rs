use std::collections::HashSet;
use std::fs::{create_dir_all, rename, File};
use std::io;
use std::io::copy;
use std::io::prelude::*;
use std::io::Stdout;
use std::path::PathBuf;
use std::process::exit;

use clap::{values_t, App, Arg, ArgMatches};
use failure::err_msg;
use itertools::Itertools;
use pbr::{ProgressBar, Units};
use reqwest::{header, Client, Url};

use filecoin_proofs::param::*;
use storage_proofs::parameter_cache::{
    parameter_cache_dir, GROTH_PARAMETER_EXT, PARAMETER_CACHE_DIR, PARAMETER_CACHE_ENV_VAR,
};

const ERROR_PARAMETER_FILE: &str = "failed to find file in cache";
const ERROR_PARAMETER_ID: &str = "failed to find key in manifest";

struct FetchProgress<R> {
    inner: R,
    progress_bar: ProgressBar<Stdout>,
}

impl<R: Read> Read for FetchProgress<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).map(|n| {
            self.progress_bar.add(n as u64);
            n
        })
    }
}

pub fn main() {
    let matches = App::new("paramfetch")
        .version("1.1")
        .about(
            &format!(
                "
Set {} to specify Groth parameter and verifying key-cache directory.
Defaults to '{}'

Use -g,--gateway to specify ipfs gateway.
Defaults to 'https://ipfs.io'
", 
                PARAMETER_CACHE_ENV_VAR,
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
            Arg::with_name("gateway")
                .value_name("URL")
                .takes_value(true)
                .short("g")
                .long("gateway")
                .help("Use specific ipfs gateway"),
        )
        .arg(
            Arg::with_name("retry")
                .short("r")
                .long("retry")
                .help("Prompt to retry on failure"),
        )
        .arg(
            Arg::with_name("all")
                .short("a")
                .long("all")
                .conflicts_with("params-for-sector-sizes")
                .help("Download all available parameters and verifying keys"),
        )
        .arg(
            Arg::with_name("params-for-sector-sizes")
                .short("z")
                .long("params-for-sector-sizes")
                .conflicts_with("all")
                .require_delimiter(true)
                .value_delimiter(",")
                .multiple(true)
                .help("A comma-separated list of sector sizes, in bytes, for which Groth parameters will be downloaded"),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Print diagnostic information to stdout"),
        )
        .get_matches();

    match fetch(&matches) {
        Ok(_) => println!("done"),
        Err(err) => {
            println!("fatal error: {}", err);
            exit(1);
        }
    }
}

fn fetch(matches: &ArgMatches) -> Result<()> {
    let json_path = PathBuf::from(matches.value_of("json").unwrap_or("./parameters.json"));
    let retry = matches.is_present("retry");
    let gateway = matches.value_of("gateway").unwrap_or("https://ipfs.io");

    if !json_path.exists() {
        return Err(err_msg(format!(
            "json file '{}' does not exist",
            &json_path.to_str().unwrap_or("")
        )));
    }

    let manifest = read_parameter_map_from_disk(&json_path)?;
    let mut filenames = get_filenames_from_parameter_map(&manifest)?;

    println!("{} files in manifest...", filenames.len());
    println!();

    // if user has specified sector sizes for which they wish to download Groth
    // parameters, trim non-matching Groth parameter filenames from the list
    if matches.is_present("params-for-sector-sizes") {
        let whitelisted_sector_sizes: HashSet<u64> =
            values_t!(matches.values_of("params-for-sector-sizes"), u64)?
                .into_iter()
                .collect();

        // always download all verifying keys - but conditionally skip Groth
        // parameters for sector sizes the user doesn't care about
        filenames = filenames
            .into_iter()
            .filter(|id| {
                !has_extension(id, GROTH_PARAMETER_EXT) || {
                    manifest
                        .get(id)
                        .map(|p| p.sector_size)
                        .map(|n| whitelisted_sector_sizes.contains(&n))
                        .unwrap_or(false)
                }
            })
            .collect_vec();
    }

    println!("{} files to check for (re)download...", filenames.len());
    println!();

    // ensure filename corresponds to asset on disk and that its checksum
    // matches that which is specified in the manifest
    filenames = get_filenames_requiring_download(&manifest, filenames)?;

    // don't prompt the user to download files if they've used certain flags
    if !matches.is_present("params-for-sector-sizes")
        && !matches.is_present("all")
        && !filenames.is_empty()
    {
        filenames = choose_from(&filenames, |filename| {
            manifest.get(filename).map(|x| x.sector_size)
        })?;
        println!();
    }

    loop {
        println!("{} files to fetch...", filenames.len());
        println!();

        for filename in &filenames {
            println!("fetching: {}", filename);
            print!("downloading file... ");
            io::stdout().flush().unwrap();

            match fetch_parameter_file(
                matches.is_present("verbose"),
                &manifest,
                &filename,
                &gateway,
            ) {
                Ok(_) => println!("ok\n"),
                Err(err) => println!("error: {}\n", err),
            }
        }

        // if we haven't downloaded a valid copy of each asset specified in the
        // manifest, ask the user if they wish to try again
        filenames = get_filenames_requiring_download(&manifest, filenames)?;

        if filenames.is_empty() {
            break;
        } else {
            println!("{} files failed to be fetched:", filenames.len());

            for parameter_id in &filenames {
                println!("{}", parameter_id);
            }

            println!();

            if !retry || !choose("try again?") {
                return Err(err_msg("some files failed to be fetched. try again, or run paramcache to generate locally"));
            }
        }
    }

    Ok(())
}

fn fetch_parameter_file(
    is_verbose: bool,
    parameter_map: &ParameterMap,
    filename: &str,
    gateway: &str,
) -> Result<()> {
    let parameter_data = parameter_map_lookup(parameter_map, filename)?;
    let path = get_full_path_for_file_within_cache(filename);

    create_dir_all(parameter_cache_dir())?;

    let mut paramfile = match File::create(&path).map_err(failure::Error::from) {
        Err(why) => return Err(why),
        Ok(file) => file,
    };

    let client = Client::new();
    let url = Url::parse(&format!("{}/ipfs/{}", gateway, parameter_data.cid))?;
    let total_size = {
        let res = client.head(url.as_str()).send()?;
        if res.status().is_success() {
            res.headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|ct_len| ct_len.to_str().ok())
                .and_then(|ct_len| ct_len.parse().ok())
                .unwrap_or(0)
        } else {
            return Err(failure::err_msg("failed to download file"));
        }
    };

    let req = client.get(url.as_str());
    if is_verbose {
        let mut pb = ProgressBar::new(total_size);
        pb.set_units(Units::Bytes);

        let mut source = FetchProgress {
            inner: req.send()?,
            progress_bar: pb,
        };

        let _ = copy(&mut source, &mut paramfile)?;
    } else {
        let mut source = req.send()?;
        let _ = copy(&mut source, &mut paramfile)?;
    }

    Ok(())
}

fn get_filenames_requiring_download(
    parameter_map: &ParameterMap,
    parameter_ids: Vec<String>,
) -> Result<Vec<String>> {
    Ok(parameter_ids
        .into_iter()
        .filter(|parameter_id| {
            println!("checking: {}", parameter_id);
            print!("does file exist... ");

            if get_full_path_for_file_within_cache(parameter_id).exists() {
                println!("yes");
                print!("is file valid... ");
                io::stdout().flush().unwrap();

                match validate_parameter_file(&parameter_map, &parameter_id) {
                    Ok(true) => {
                        println!("yes\n");
                        false
                    }
                    Ok(false) => {
                        println!("no\n");
                        invalidate_parameter_file(&parameter_id).unwrap();
                        true
                    }
                    Err(err) => {
                        println!("error: {}\n", err);
                        true
                    }
                }
            } else {
                println!("no\n");
                true
            }
        })
        .collect())
}

fn get_filenames_from_parameter_map(parameter_map: &ParameterMap) -> Result<Vec<String>> {
    Ok(parameter_map.iter().map(|(k, _)| k.clone()).collect())
}

fn validate_parameter_file(parameter_map: &ParameterMap, filename: &str) -> Result<bool> {
    let parameter_data = parameter_map_lookup(parameter_map, filename)?;
    let digest = get_digest_for_file_within_cache(filename)?;

    if parameter_data.digest != digest {
        Ok(false)
    } else {
        Ok(true)
    }
}

fn invalidate_parameter_file(filename: &str) -> Result<()> {
    let parameter_file_path = get_full_path_for_file_within_cache(filename);
    let target_parameter_file_path =
        parameter_file_path.with_file_name(format!("{}-invalid-digest", filename));

    if parameter_file_path.exists() {
        rename(parameter_file_path, target_parameter_file_path)?;
        Ok(())
    } else {
        Err(err_msg(ERROR_PARAMETER_FILE))
    }
}

fn parameter_map_lookup<'a>(
    parameter_map: &'a ParameterMap,
    filename: &str,
) -> Result<&'a ParameterData> {
    if parameter_map.contains_key(filename) {
        Ok(parameter_map.get(filename).unwrap())
    } else {
        Err(err_msg(ERROR_PARAMETER_ID))
    }
}
