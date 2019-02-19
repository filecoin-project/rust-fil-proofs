use blake2::{Blake2b, Digest};
use failure::{err_msg, Error};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{read_dir, rename, File};
use std::io::{stdin, stdout, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::Command;
use storage_proofs::parameter_cache::parameter_cache_dir;

pub const ERROR_CURL_COMMAND: &str = "failed to run curl";
pub const ERROR_CURL_FETCH: &str = "failed to fetch via curl";
pub const ERROR_IPFS_COMMAND: &str = "failed to run ipfs";
pub const ERROR_IPFS_OUTPUT: &str = "failed to capture ipfs output";
pub const ERROR_IPFS_PARSE: &str = "failed to parse ipfs output";
pub const ERROR_IPFS_PUBLISH: &str = "failed to publish via ipfs";
pub const ERROR_PARAMETERS_LOCAL: &str = "failed to load local parameters";
pub const ERROR_PARAMETERS_MAPPED: &str = "failed to load mapped parameters";
pub const ERROR_PARAMETER_FILE: &str = "failed to find parameter file";
pub const ERROR_PARAMETER_ID: &str = "failed to find parameter in map";
pub const ERROR_PARAMETER_MAP_LOAD: &str = "failed to load parameter map";
pub const ERROR_PARAMETER_MAP_SAVE: &str = "failed to save parameter map";
pub const ERROR_PARAMETER_INVALID: &str = "invalid parameter file";
pub const ERROR_DIGEST: &str = "failed to generate digest";
pub const ERROR_STRING: &str = "invalid string";

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
    if path.exists() {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let parameter_map = serde_json::from_reader(reader)?;

        Ok(parameter_map)
    } else {
        println!(
            "parameter manifest '{}' does not exist",
            path.as_path().to_str().unwrap()
        );

        Ok(HashMap::new())
    }
}

pub fn get_parameter_data(
    parameter_map: &ParameterMap,
    parameter_id: String,
) -> Result<&ParameterData> {
    if parameter_map.contains_key(&parameter_id) {
        Ok(parameter_map.get(&parameter_id).unwrap())
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

pub fn get_parameter_file_path(parameter_id: String) -> PathBuf {
    let mut path = parameter_cache_dir();
    path.push(parameter_id);
    path
}

pub fn get_parameter_digest(parameter_id: String) -> Result<String> {
    let path = get_parameter_file_path(parameter_id);
    let mut file = File::open(path)?;
    let mut hasher = Blake2b::new();

    std::io::copy(&mut file, &mut hasher)?;

    Ok(format!("{:.32x}", &hasher.result()))
}

pub fn publish_parameter_file(parameter_id: String) -> Result<String> {
    let path = get_parameter_file_path(parameter_id);

    let output = Command::new("ipfs")
        .arg("add")
        .arg(path.as_path().to_str().unwrap().to_string())
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

pub fn fetch_parameter_file(parameter_map: &ParameterMap, parameter_id: String) -> Result<()> {
    let parameter_data = get_parameter_data(parameter_map, parameter_id.to_string())?;
    let path = get_parameter_file_path(parameter_id.to_string());

    if path.exists() {
        println!(
            "parameter file '{}' already exists",
            path.as_path().to_str().unwrap()
        );

        Ok(())
    } else {
        let output = Command::new("curl")
            .arg("-o")
            .arg(path.as_path().to_str().unwrap().to_string())
            .arg(format!("https://ipfs.io/ipfs/{}", parameter_data.cid))
            .output();

        match output {
            Err(_) => Err(err_msg(ERROR_CURL_COMMAND)),
            Ok(output) => {
                if !output.status.success() {
                    Err(err_msg(ERROR_CURL_FETCH))
                } else {
                    let is_valid =
                        validate_parameter_file(&parameter_map, parameter_id.to_string())?;

                    if !is_valid {
                        invalidate_parameter_file(parameter_id.to_string())?;
                        Err(err_msg(ERROR_PARAMETER_INVALID))
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }
}

pub fn validate_parameter_file(parameter_map: &ParameterMap, parameter_id: String) -> Result<bool> {
    let parameter_data = get_parameter_data(parameter_map, parameter_id.to_string())?;
    let digest = get_parameter_digest(parameter_id.to_string())?;

    if parameter_data.digest != digest {
        Ok(false)
    } else {
        Ok(true)
    }
}

pub fn invalidate_parameter_file(parameter_id: String) -> Result<()> {
    let parameter_file_path = get_parameter_file_path(parameter_id.to_string());
    let target_parameter_file_path =
        parameter_file_path.with_file_name(format!("{}-invalid-digest", parameter_id.to_string()));

    if parameter_file_path.exists() {
        rename(parameter_file_path, target_parameter_file_path)?;
        Ok(())
    } else {
        Err(err_msg(ERROR_PARAMETER_FILE))
    }
}

pub fn choose(message: String) -> bool {
    loop {
        print!("{} [y/n]: ", message);

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
    Ok(vector
        .into_iter()
        .filter(|i| choose(i.to_string()))
        .collect())
}

pub fn choose_local_parameter_ids() -> Result<Vec<String>> {
    choose_from(get_local_parameter_ids()?)
}

pub fn choose_mapped_parameter_ids(map: &ParameterMap) -> Result<Vec<String>> {
    choose_from(get_mapped_parameter_ids(&map)?)
}
