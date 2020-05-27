use std::collections::HashSet;
use std::fs::{create_dir_all, rename, File};
use std::io::copy;
use std::io::prelude::*;
use std::io::{BufReader, Stdout};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::process::Command;
use std::{fs, io};

use anyhow::{bail, ensure, Context, Result};
use clap::{values_t, App, Arg, ArgMatches};
use flate2::read::GzDecoder;
use itertools::Itertools;
use pbr::{ProgressBar, Units};
use reqwest::{blocking::Client, header, Proxy, Url};
use tar::Archive;

use filecoin_proofs::param::*;
use storage_proofs::parameter_cache::{
    parameter_cache_dir, parameter_cache_dir_name, GROTH_PARAMETER_EXT,
};

const ERROR_PARAMETER_FILE: &str = "failed to find file in cache";
const ERROR_PARAMETER_ID: &str = "failed to find key in manifest";

const IPGET_PATH: &str = "/var/tmp/ipget";
const DEFAULT_PARAMETERS: &str = include_str!("../../parameters.json");
const IPGET_VERSION: &str = "v0.4.0";

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
    fil_logger::init();

    let matches = App::new("paramfetch")
        .version("1.1")
        .about(
            &format!(
                "
Set {} to specify Groth parameter and verifying key-cache directory.
Defaults to '{}'
",
                "FIL_PROOFS_PARAMETER_CACHE", // related to var name in core/src/settings.rs
                parameter_cache_dir_name(),
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
        .arg(
            Arg::with_name("ipget-bin")
                .conflicts_with("ipget-version")
                .takes_value(true)
                .short("i")
                .long("ipget-bin")
                .help("Use specific ipget binary instead of looking for (or installing) one in /var/tmp/ipget/ipget"),
        )
        .arg(
            Arg::with_name("ipget-args")
                .takes_value(true)
                .long("ipget-args")
                .help("Specify additional arguments for ipget")
        )
        .arg(
            Arg::with_name("ipget-version")
                .conflicts_with("ipget-bin")
                .long("ipget-version")
                .takes_value(true)
                .help("Set the version of ipget to use")
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
        let json_path = PathBuf::from(
            matches
                .value_of("json")
                .expect("failed to convert to path buf"),
        );
        println!("using JSON file: {:?}", json_path);

        if !json_path.exists() {
            bail!(
                "JSON file '{}' does not exist",
                &json_path.to_str().unwrap_or("")
            );
        }

        let file = File::open(&json_path)?;
        let reader = BufReader::new(file);

        serde_json::from_reader(reader).with_context(|| {
            format!(
                "JSON file '{}' did not parse correctly",
                &json_path.to_str().unwrap_or(""),
            )
        })?
    } else {
        println!("using built-in manifest");
        serde_json::from_str(&DEFAULT_PARAMETERS)?
    };

    let retry = matches.is_present("retry");

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
    let ipget_bin_path = matches.value_of("ipget-bin");
    let ipget_version = matches.value_of("ipget-version").unwrap_or(IPGET_VERSION);
    let ipget_args = matches.value_of("ipget-args");

    // Make sure we have ipget available
    if ipget_bin_path.is_none() {
        ensure_ipget(is_verbose, ipget_version)?;
    }

    let ipget_path = if let Some(p) = ipget_bin_path {
        PathBuf::from(p)
    } else {
        PathBuf::from(&get_ipget_bin(ipget_version))
    };

    loop {
        println!("{} files to fetch...", filenames.len());
        println!();

        for filename in &filenames {
            println!("fetching: {}", filename);
            print!("downloading file... ");
            io::stdout().flush().expect("failed to flush stdout");

            match fetch_parameter_file(is_verbose, &manifest, &filename, &ipget_path, ipget_args) {
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
                bail!("some files failed to be fetched. try again, or run paramcache to generate locally");
            }
        }
    }

    Ok(())
}

fn get_ipget_bin(version: &str) -> String {
    format!("{}-{}/ipget/ipget", IPGET_PATH, version)
}

/// Check if ipget is available, dowwnload it otherwise.
fn ensure_ipget(is_verbose: bool, version: &str) -> Result<()> {
    let ipget_bin = get_ipget_bin(version);
    if Path::new(&ipget_bin).exists() {
        Ok(())
    } else {
        download_ipget(is_verbose, version)
    }
    .map(|_| {
        if is_verbose {
            println!("ipget installed: {}", ipget_bin);
        }
    })
}

/// Download a version of ipget.
fn download_ipget(is_verbose: bool, version: &str) -> Result<()> {
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
    let p = format!("{}-{}.{}", IPGET_PATH, version, extension);
    download_file(url, &p, is_verbose)?;

    // extract file
    if extension == "tar.gz" {
        let tar_gz = fs::File::open(p)?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        archive.unpack(format!("/var/tmp/ipget-{}", version))?;
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
            bail!("failed to download file: {}", url);
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
    ipget_bin_path: impl AsRef<Path>,
    ipget_args: Option<impl AsRef<str>>,
) -> Result<()> {
    let parameter_data = parameter_map_lookup(parameter_map, filename)?;
    let path = get_full_path_for_file_within_cache(filename);

    create_dir_all(parameter_cache_dir())?;
    download_file_with_ipget(
        &parameter_data.cid,
        path,
        is_verbose,
        ipget_bin_path,
        ipget_args,
    )
}

fn download_file_with_ipget(
    cid: impl AsRef<str>,
    target: impl AsRef<Path>,
    is_verbose: bool,
    ipget_bin_path: impl AsRef<Path>,
    ipget_args: Option<impl AsRef<str>>,
) -> Result<()> {
    let mut cmd = Command::new(ipget_bin_path.as_ref().as_os_str());
    cmd.arg("-o")
        .arg(target.as_ref().to_str().expect("failed to convert -o arg"))
        .arg(cid.as_ref());

    if let Some(args) = ipget_args {
        cmd.args(args.as_ref().split(' '));
    }

    let output = cmd.output()?;

    if is_verbose {
        io::stdout().write_all(&output.stdout)?;
        io::stderr().write_all(&output.stderr)?;
    }

    ensure!(
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
                io::stdout().flush().expect("failed to flush stdout");

                match validate_parameter_file(&parameter_map, &parameter_id) {
                    Ok(true) => {
                        println!("yes\n");
                        false
                    }
                    Ok(false) => {
                        println!("no\n");
                        invalidate_parameter_file(&parameter_id)
                            .expect("invalidate failed to rename file");
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

    ensure!(parameter_file_path.exists(), ERROR_PARAMETER_FILE);
    rename(parameter_file_path, target_parameter_file_path)?;

    Ok(())
}

fn parameter_map_lookup<'a>(
    parameter_map: &'a ParameterMap,
    filename: &str,
) -> Result<&'a ParameterData> {
    ensure!(parameter_map.contains_key(filename), ERROR_PARAMETER_ID);

    Ok(parameter_map
        .get(filename)
        .expect("unreachable: contains_key()"))
}
