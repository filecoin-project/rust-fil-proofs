use blake2::{Blake2b, Digest};
use failure::{err_msg, Error};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{create_dir_all, read_dir, rename, File};
use std::io::{stdin, stdout, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use storage_proofs::parameter_cache::parameter_cache_dir;

const ERROR_IPFS_COMMAND: &str = "failed to run ipfs";
const ERROR_IPFS_OUTPUT: &str = "failed to capture ipfs output";
const ERROR_IPFS_PARSE: &str = "failed to parse ipfs output";
const ERROR_IPFS_PUBLISH: &str = "failed to publish via ipfs";
const ERROR_PARAMETER_FILE: &str = "failed to find parameter file";
const ERROR_PARAMETER_ID: &str = "failed to find parameter in map";
const ERROR_STRING: &str = "invalid string";

pub type Result<T> = ::std::result::Result<T, Error>;
pub type ParameterMap = HashMap<String, ParameterData>;

#[derive(Deserialize, Serialize)]
pub struct ParameterData {
    pub cid: String,
    pub digest: String,
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

    Ok(format!("{:.32x}", &hasher.result()))
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
) -> Result<std::process::Child> {
    let parameter_data = get_parameter_data(parameter_map, parameter_id)?;
    let path = get_parameter_file_path(parameter_id);

    create_dir_all(parameter_cache_dir())?;

    let output_styling = if is_verbose {
        &["--verbose", "--progress-bar"]
    } else {
        &["--silent", "--show-error"]
    };

    let connect_timeout = &["--connect-timeout", "30"];

    // time out if speed stays at below 1000 bytes/second for >= 15 seconds
    let speed_timeout = &["--speed-time", "15", "--speed-limit", "1000"];

    Command::new("curl")
        .args(output_styling)
        .args(connect_timeout)
        .args(speed_timeout)
        .arg("--output")
        .arg(&path)
        .arg(format!("https://ipfs.io/ipfs/{}", parameter_data.cid))
        .stdout(Stdio::inherit())
        .spawn()
        .map_err(failure::Error::from)
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
