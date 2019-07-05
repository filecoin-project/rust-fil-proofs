use blake2b_simd::State as Blake2b;
use failure::{err_msg, Error};
use regex::Regex;
use reqwest::{header, Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{create_dir_all, read_dir, rename, File};
use std::io::{stdin, stdout, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use pbr::{ProgressBar, Units};
use std::ffi::OsStr;
use std::io::Stdout;
use std::io::{self, copy, Read};
use storage_proofs::parameter_cache::parameter_cache_dir;

const ERROR_IPFS_COMMAND: &str = "failed to run ipfs";
const ERROR_IPFS_OUTPUT: &str = "failed to capture ipfs output";
const ERROR_IPFS_PARSE: &str = "failed to parse ipfs output";
const ERROR_IPFS_PUBLISH: &str = "failed to publish via ipfs";
const ERROR_PARAMETER_FILE: &str = "failed to find parameter file";
const ERROR_PARAMETER_ID: &str = "failed to find parameter in map";
const ERROR_STRING: &str = "invalid string";

pub type Result<T> = ::std::result::Result<T, Error>;
pub type ParameterMap = BTreeMap<String, ParameterData>;

#[derive(Deserialize, Serialize)]
pub struct ParameterData {
    pub cid: String,
    pub digest: String,
    pub sector_size: Option<u64>,
}

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

pub fn get_filenames_in_cache_dir() -> Result<Vec<String>> {
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

pub fn get_filenames_from_parameter_map(parameter_map: &ParameterMap) -> Result<Vec<String>> {
    Ok(parameter_map.iter().map(|(k, _)| k.clone()).collect())
}

pub fn read_parameter_map_from_disk<P: AsRef<Path>>(source_path: P) -> Result<ParameterMap> {
    let file = File::open(source_path)?;
    let reader = BufReader::new(file);
    let parameter_map = serde_json::from_reader(reader)?;

    Ok(parameter_map)
}

pub fn parameter_map_lookup<'a>(
    parameter_map: &'a ParameterMap,
    filename: &str,
) -> Result<&'a ParameterData> {
    if parameter_map.contains_key(filename) {
        Ok(parameter_map.get(filename).unwrap())
    } else {
        Err(err_msg(ERROR_PARAMETER_ID))
    }
}

pub fn write_parameter_map_to_disk<P: AsRef<Path>>(
    parameter_map: &ParameterMap,
    dest_path: P,
) -> Result<()> {
    let file = File::create(dest_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &parameter_map)?;

    Ok(())
}

pub fn get_full_path_for_file_within_cache(filename: &str) -> PathBuf {
    let mut path = parameter_cache_dir();
    path.push(filename);
    path
}

pub fn get_digest_for_file_within_cache(filename: &str) -> Result<String> {
    let path = get_full_path_for_file_within_cache(filename);
    let mut file = File::open(path)?;
    let mut hasher = Blake2b::new();

    std::io::copy(&mut file, &mut hasher)?;

    Ok(hasher.finalize().to_hex()[..32].into())
}

pub fn publish_parameter_file(filename: &str) -> Result<String> {
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

pub fn fetch_parameter_file(
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
            return Err(failure::err_msg("failed to download parameter file"));
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

pub fn validate_parameter_file(parameter_map: &ParameterMap, filename: &str) -> Result<bool> {
    let parameter_data = parameter_map_lookup(parameter_map, filename)?;
    let digest = get_digest_for_file_within_cache(filename)?;

    if parameter_data.digest != digest {
        Ok(false)
    } else {
        Ok(true)
    }
}

pub fn invalidate_parameter_file(filename: &str) -> Result<()> {
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

pub fn choose(message: &str) -> bool {
    loop {
        print!("[y/n] {}: ", message);

        let _ = stdout().flush();
        let mut s = String::new();
        stdin().read_line(&mut s).expect(ERROR_STRING);

        match s.trim().to_uppercase().as_str() {
            "Y" => return true,
            "N" => return false,
            _ => {}
        }
    }
}

pub fn choose_from(vector: Vec<String>) -> Result<Vec<String>> {
    Ok(vector.into_iter().filter(|i| choose(i)).collect())
}

pub fn filename_to_parameter_id<'a, P: AsRef<Path> + 'a>(filename: P) -> Option<String> {
    filename
        .as_ref()
        .file_stem()
        .and_then(OsStr::to_str)
        .map(ToString::to_string)
}

pub fn has_extension<S: AsRef<str>, P: AsRef<Path>>(filename: P, ext: S) -> bool {
    filename
        .as_ref()
        .extension()
        .and_then(OsStr::to_str)
        .map(|s| s == ext.as_ref())
        .unwrap_or(false)
}
