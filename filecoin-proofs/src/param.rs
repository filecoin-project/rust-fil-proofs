use failure::{err_msg, Error};
use regex::Regex;
use std::collections::HashMap;
use std::fs::{read_dir, File};
use std::io::{stdin, stdout, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::Command;

const PARAMETER_PATH: &str = "/tmp/filecoin-proof-parameters";
const PARAMETER_JSON_PATH: &str = "./parameters.json";

pub const ERROR_PARAMETER_ID: &str = "failed to find parameter in map";
pub const ERROR_PARAMETER_MAP_LOAD: &str = "failed to load parameter map";
pub const ERROR_PARAMETER_MAP_SAVE: &str = "failed to load parameter map";
pub const ERROR_PARAMETERS_MAPPED: &str = "failed to load mapped parameters";
pub const ERROR_PARAMETERS_LOCAL: &str = "failed to load local parameters";
pub const ERROR_IPFS_COMMAND: &str = "failed to run ipfs";
pub const ERROR_IPFS_OUTPUT: &str = "failed to capture ipfs output";
pub const ERROR_IPFS_PARSE: &str = "failed to parse ipfs output";
pub const ERROR_IPFS_PUBLISH: &str = "failed to publish via ipfs";
pub const ERROR_IPFS_FETCH: &str = "failed to fetch via ipfs";
pub const ERROR_STRING: &str = "invalid string";

pub type Result<T> = ::std::result::Result<T, Error>;

pub type ParameterMap = HashMap<String, String>;

pub fn get_local_parameters() -> Result<Vec<String>> {
    Ok(read_dir(PARAMETER_PATH)?
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
}

pub fn get_mapped_parameters() -> Result<Vec<String>> {
    Ok(load_parameter_map()?.into_iter().map(|(k, _)| k).collect())
}

pub fn load_parameter_map() -> Result<ParameterMap> {
    let path = PathBuf::from(PARAMETER_JSON_PATH);

    if path.exists() {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let map = serde_json::from_reader(reader)?;

        Ok(map)
    } else {
        Ok(HashMap::new())
    }
}

pub fn save_parameter_map(map: ParameterMap) -> Result<()> {
    let file = File::create(PARAMETER_JSON_PATH)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &map)?;

    Ok(())
}

pub fn publish_parameter_file(parameter: String) -> Result<String> {
    let mut path = PathBuf::from(PARAMETER_PATH);
    path.push(parameter);

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

pub fn fetch_parameter_file(parameter: String) -> Result<()> {
    let map = load_parameter_map()?;
    let cid = map.get(&parameter).expect(ERROR_PARAMETER_ID);

    let mut path = PathBuf::from(PARAMETER_PATH);
    path.push(parameter);

    let output = Command::new("ipfs")
        .arg("get")
        .arg("-o")
        .arg(path.as_path().to_str().unwrap().to_string())
        .arg(cid.to_string())
        .output()
        .expect(ERROR_IPFS_COMMAND);

    if !output.status.success() {
        Err(err_msg(ERROR_IPFS_FETCH))
    } else {
        Ok(())
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

pub fn choose_local_parameters() -> Result<Vec<String>> {
    choose_from(get_local_parameters()?)
}

pub fn choose_mapped_parameters() -> Result<Vec<String>> {
    choose_from(get_mapped_parameters()?)
}
