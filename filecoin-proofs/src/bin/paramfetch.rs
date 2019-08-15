use std::collections::HashSet;
use std::fs::{create_dir_all, rename, File};
use std::io::copy;
use std::io::prelude::*;
use std::io::{BufReader, Stdout};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::process::Command;
use std::{fs, io};

use clap::{values_t, App, Arg, ArgMatches};
use env_proxy;
use failure::err_msg;
use flate2::read::GzDecoder;
use itertools::Itertools;
use pbr::{ProgressBar, Units};
use reqwest::{header, Client, Proxy, Url};
use tar::Archive;

use filecoin_proofs::param::*;
use storage_proofs::parameter_cache::{
    parameter_cache_dir, GROTH_PARAMETER_EXT, PARAMETER_CACHE_DIR, PARAMETER_CACHE_ENV_VAR,
};

const ERROR_PARAMETER_FILE: &str = "failed to find file in cache";
const ERROR_PARAMETER_ID: &str = "failed to find key in manifest";

const IPGET_PATH: &str = "/var/tmp/ipget";
const IPGET_BIN: &str = "/var/tmp/ipget/ipget";
const DEFAULT_PARAMETERS: &str = include_str!("../../../parameters.json");

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
    pretty_env_logger::init_timed();

    let matches = App::new("paramfetch")
        .version("1.1")
        .about(
            &format!(
                "
Set {} to specify Groth parameter and verifying key-cache directory.
Defaults to '{}'

Use -g,--gateway to specify ipfs gateway.
Defaults to 'https://ipfs.io'

Set http_proxy/https_proxy environment variables to specify proxy for ipfs gateway.
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
                .help("Use specific JSON file"),
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
    let manifest = if matches.is_present("json") {
        let json_path = PathBuf::from(matches.value_of("json").unwrap());
        println!("using JSON file: {:?}", json_path);

        if !json_path.exists() {
            return Err(err_msg(format!(
                "JSON file '{}' does not exist",
                &json_path.to_str().unwrap_or("")
            )));
        }

        let file = File::open(&json_path)?;
        let reader = BufReader::new(file);

        serde_json::from_reader(reader).map_err(|err| {
            failure::format_err!(
                "JSON file '{}' did not parse correctly: {}",
                &json_path.to_str().unwrap_or(""),
                err,
            )
        })?
    } else {
        println!("using built-in manifest");
        serde_json::from_str(&DEFAULT_PARAMETERS)?
    };

    let retry = matches.is_present("retry");
    let gateway = matches.value_of("gateway").unwrap_or("https://ipfs.io");

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

    let is_verbose = matches.is_present("verbose");
    // Make sure we have ipget available
    ensure_ipget(is_verbose)?;

    loop {
        println!("{} files to fetch...", filenames.len());
        println!();

        for filename in &filenames {
            println!("fetching: {}", filename);
            print!("downloading file... ");
            io::stdout().flush().unwrap();

            match fetch_parameter_file(is_verbose, &manifest, &filename, &gateway) {
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

/// Check if ipget is available, dowwnload it otherwise.
fn ensure_ipget(is_verbose: bool) -> Result<()> {
    if Path::new(IPGET_BIN).exists() {
        Ok(())
    } else {
        download_ipget(is_verbose)
    }
    .map(|_| {
        if is_verbose {
            println!("ipget installed: {}", IPGET_BIN);
        }
    })
}

/// Download a version of ipget.
fn download_ipget(is_verbose: bool) -> Result<()> {
    let version = "v0.3.1";

    let (os, extension) = if cfg!(target_os = "macos") {
        ("darwin", "tar.gz")
    } else if cfg!(target_os = "windows") {
        ("windows", "zip")
    } else {
        ("linux", "tar.gz")
    };

    let url = Url::parse(&format!(
        "https://dist.ipfs.io/ipget/{}/ipget_{}_{}-amd64.{}",
        version, version, os, extension
    ))?;

    if is_verbose {
        println!("downloading ipget@{}-{}...", version, os);
    }

    // download file
    let p = format!("{}.{}", IPGET_PATH, extension);
    download_file(url, &p, is_verbose)?;

    // extract file
    if extension == "tar.gz" {
        let tar_gz = fs::File::open(p)?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        archive.unpack("/var/tmp/")?;
    } else {
        // TODO: handle zip archives on windows
        unimplemented!("failed to install ipget: unzip is not yet supported");
    }

    Ok(())
}

/// Download the given file.
fn download_file(url: Url, target: impl AsRef<Path>, is_verbose: bool) -> Result<()> {
    let mut file = File::create(target)?;

    let client = Client::builder()
        .proxy(Proxy::custom(move |url| env_proxy::for_url(&url).to_url()))
        .build()?;
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

        let _ = copy(&mut source, &mut file)?;
    } else {
        let mut source = req.send()?;
        let _ = copy(&mut source, &mut file)?;
    }

    Ok(())
}

fn fetch_parameter_file(
    is_verbose: bool,
    parameter_map: &ParameterMap,
    filename: &str,
    _gateway: &str,
) -> Result<()> {
    let parameter_data = parameter_map_lookup(parameter_map, filename)?;
    let path = get_full_path_for_file_within_cache(filename);

    create_dir_all(parameter_cache_dir())?;
    download_file_with_ipget(&parameter_data.cid, path, is_verbose)
}

fn download_file_with_ipget(
    cid: impl AsRef<str>,
    target: impl AsRef<Path>,
    is_verbose: bool,
) -> Result<()> {
    let output = Command::new(IPGET_BIN)
        .arg("-o")
        .arg(target.as_ref().to_str().unwrap())
        .arg(cid.as_ref())
        .output()?;

    if is_verbose {
        io::stdout().write_all(&output.stdout)?;
        io::stderr().write_all(&output.stderr)?;
    }

    failure::ensure!(
        output.status.success(),
        "failed to download {}",
        target.as_ref().display()
    );

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
