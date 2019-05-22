use blake2b_simd::State as Blake2b;
use failure::{err_msg, Error};
use regex::Regex;
use reqwest::{header, Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{create_dir_all, read_dir, rename, File};
use std::io::{stdin, stdout, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::Command;

use pbr::{ProgressBar, Units};
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

pub fn get_local_parameter_ids() -> Result<Vec<String>> {
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

pub fn get_mapped_parameter_ids(parameter_map: &ParameterMap) -> Result<Vec<String>> {
    Ok(parameter_map.iter().map(|(k, _)| k.clone()).collect())
}

pub fn get_parameter_map(path: &PathBuf) -> Result<ParameterMap> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let parameter_map = serde_json::from_reader(reader)?;

    Ok(parameter_map)
}

pub fn get_parameter_data<'a>(
    parameter_map: &'a ParameterMap,
    parameter_id: &str,
) -> Result<&'a ParameterData> {
    if parameter_map.contains_key(parameter_id) {
        Ok(parameter_map.get(parameter_id).unwrap())
    } else {
        Err(err_msg(ERROR_PARAMETER_ID))
    }
}

pub fn save_parameter_map(parameter_map: &ParameterMap, file_path: &PathBuf) -> Result<()> {
    let file = File::create(file_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &parameter_map)?;

    Ok(())
}

pub fn get_parameter_file_path(parameter_id: &str) -> PathBuf {
    let mut path = parameter_cache_dir();
    path.push(parameter_id);
    path
}

pub fn get_parameter_digest(parameter_id: &str) -> Result<String> {
    let path = get_parameter_file_path(parameter_id);
    let mut file = File::open(path)?;
    let mut hasher = Blake2b::new();

    std::io::copy(&mut file, &mut hasher)?;

    Ok(hasher.finalize().to_hex()[..32].into())
}

pub fn publish_parameter_file(parameter_id: &str) -> Result<String> {
    let path = get_parameter_file_path(parameter_id);

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

pub fn spawn_fetch_parameter_file(
    is_verbose: bool,
    parameter_map: &ParameterMap,
    parameter_id: &str,
) -> Result<()> {
    let parameter_data = get_parameter_data(parameter_map, parameter_id)?;
    let path = get_parameter_file_path(parameter_id);

    create_dir_all(parameter_cache_dir())?;

    let mut paramfile = match File::create(&path).map_err(failure::Error::from) {
        Err(why) => return Err(why),
        Ok(file) => file,
    };

    let client = Client::new();
    let url = Url::parse(&format!("https://ipfs.io/ipfs/{}", parameter_data.cid))?;
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

pub fn validate_parameter_file(parameter_map: &ParameterMap, parameter_id: &str) -> Result<bool> {
    let parameter_data = get_parameter_data(parameter_map, parameter_id)?;
    let digest = get_parameter_digest(parameter_id)?;

    if parameter_data.digest != digest {
        Ok(false)
    } else {
        Ok(true)
    }
}

pub fn invalidate_parameter_file(parameter_id: &str) -> Result<()> {
    let parameter_file_path = get_parameter_file_path(parameter_id);
    let target_parameter_file_path =
        parameter_file_path.with_file_name(format!("{}-invalid-digest", parameter_id));

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
