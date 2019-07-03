use blake2b_simd::State as Blake2b;
use failure::{err_msg, Error};
use pbr::{ProgressBar, Units};
use reqwest::{header, Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::btree_map::BTreeMap;
use std::ffi::OsStr;
use std::fs::{create_dir_all, read_dir, rename, File};
use std::io::Stdout;
use std::io::{self, copy, Read};
use std::io::{stdin, stdout, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use storage_proofs::parameter_cache::parameter_cache_dir;

pub const ERROR_IPFS_COMMAND: &str = "failed to run ipfs";
pub const ERROR_IPFS_OUTPUT: &str = "failed to capture ipfs output";
pub const ERROR_IPFS_PARSE: &str = "failed to parse ipfs output";
pub const ERROR_IPFS_PUBLISH: &str = "failed to publish via ipfs";
pub const ERROR_PARAMETER_FILE: &str = "failed to find parameter file";
pub const ERROR_PARAMETER_ID: &str = "failed to find parameter in map";
pub const ERROR_STRING: &str = "invalid string";

pub type Result<T> = ::std::result::Result<T, Error>;
pub type Manifest = BTreeMap<String, ManifestEntry>;

#[derive(Deserialize, Serialize)]
pub struct ManifestEntry {
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

pub fn get_files_from_cache() -> Result<Vec<PathBuf>> {
    let path = parameter_cache_dir();

    if path.exists() {
        Ok(read_dir(path)?
            .map(|f| f.unwrap().path())
            .filter(|p| p.is_file())
            .collect())
    } else {
        println!(
            "parameter directory '{}' does not exist",
            path.as_path().to_str().unwrap()
        );

        Ok(Vec::new())
    }
}

pub fn get_mapped_parameter_ids(parameter_map: &Manifest) -> Result<Vec<String>> {
    Ok(parameter_map.iter().map(|(k, _)| k.clone()).collect())
}

pub fn get_parameter_map(path: &PathBuf) -> Result<Manifest> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let parameter_map = serde_json::from_reader(reader)?;

    Ok(parameter_map)
}

pub fn get_parameter_data<'a>(
    parameter_map: &'a Manifest,
    parameter_id: &str,
) -> Result<&'a ManifestEntry> {
    if parameter_map.contains_key(parameter_id) {
        Ok(parameter_map.get(parameter_id).unwrap())
    } else {
        Err(err_msg(ERROR_PARAMETER_ID))
    }
}

pub fn write_manifest_json(parameter_map: &Manifest, file_path: &PathBuf) -> Result<()> {
    let file = File::create(file_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &parameter_map)?;

    Ok(())
}

pub fn get_cached_file_path(filename: &str) -> PathBuf {
    let mut path = parameter_cache_dir();
    path.push(filename);
    path
}

pub fn get_cached_file_digest(filename: &str) -> Result<String> {
    let path = get_cached_file_path(filename);
    let mut file = File::open(path)?;
    let mut hasher = Blake2b::new();

    std::io::copy(&mut file, &mut hasher)?;

    Ok(hasher.finalize().to_hex()[..32].into())
}

pub fn spawn_fetch_parameter_file(
    is_verbose: bool,
    parameter_map: &Manifest,
    parameter_id: &str,
    gateway: &str,
) -> Result<()> {
    let parameter_data = get_parameter_data(parameter_map, parameter_id)?;
    let path = get_cached_file_path(parameter_id);

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

pub fn validate_parameter_file(parameter_map: &Manifest, parameter_id: &str) -> Result<bool> {
    let parameter_data = get_parameter_data(parameter_map, parameter_id)?;
    let digest = get_cached_file_digest(parameter_id)?;

    if parameter_data.digest != digest {
        Ok(false)
    } else {
        Ok(true)
    }
}

pub fn invalidate_parameter_file(parameter_id: &str) -> Result<()> {
    let parameter_file_path = get_cached_file_path(parameter_id);
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

pub fn choose_from(vector: Vec<String>) -> Vec<String> {
    vector.into_iter().filter(|i| choose(i)).collect()
}

#[derive(Clone)]
pub enum CachedFileMetadata {
    ParameterMetadata {
        parameter_id: String,
        filename: String,
        path: String,
    },
    VerifyingKey {
        parameter_id: String,
        filename: String,
        path: String,
    },
    GrothParameters {
        parameter_id: String,
        filename: String,
        path: String,
    },
}

pub struct PublishableCachedFileMetadata(CachedFileMetadata);

impl PublishableCachedFileMetadata {
    pub fn filename(&self) -> &str {
        self.0.filename()
    }

    pub fn parameter_id(&self) -> &str {
        self.0.parameter_id()
    }

    pub fn path(&self) -> &str {
        self.0.path()
    }
}

impl CachedFileMetadata {
    pub fn filename(&self) -> &str {
        match &self {
            CachedFileMetadata::ParameterMetadata { filename, .. } => filename,
            CachedFileMetadata::VerifyingKey { filename, .. } => filename,
            CachedFileMetadata::GrothParameters { filename, .. } => filename,
        }
    }

    pub fn path(&self) -> &str {
        match &self {
            CachedFileMetadata::ParameterMetadata { path, .. } => path,
            CachedFileMetadata::VerifyingKey { path, .. } => path,
            CachedFileMetadata::GrothParameters { path, .. } => path,
        }
    }

    pub fn parameter_id(&self) -> &str {
        match &self {
            CachedFileMetadata::ParameterMetadata { parameter_id, .. } => parameter_id,
            CachedFileMetadata::VerifyingKey { parameter_id, .. } => parameter_id,
            CachedFileMetadata::GrothParameters { parameter_id, .. } => parameter_id,
        }
    }

    pub fn try_publishable(entry: CachedFileMetadata) -> Option<PublishableCachedFileMetadata> {
        match entry {
            CachedFileMetadata::ParameterMetadata { .. } => None,
            entry => Some(PublishableCachedFileMetadata(entry)),
        }
    }
}

pub fn to_cached_file_metadata<P: AsRef<Path>>(paths: &[P]) -> Vec<CachedFileMetadata> {
    paths
        .iter()
        .flat_map(|p| {
            match (
                extension_to_owned_string(p),
                filename_to_owned_string(p),
                file_stem_to_owned_string(p),
                path_to_owned_string(p),
            ) {
                (Some(ext), Some(filename), Some(parameter_id), Some(path)) => match ext.as_ref() {
                    "meta" => Some(CachedFileMetadata::ParameterMetadata {
                        parameter_id,
                        filename,
                        path,
                    }),
                    "vk" => Some(CachedFileMetadata::VerifyingKey {
                        parameter_id,
                        filename,
                        path,
                    }),
                    "params" => Some(CachedFileMetadata::GrothParameters {
                        parameter_id,
                        filename,
                        path,
                    }),
                    _ => None,
                },
                _ => None,
            }
            .into_iter()
        })
        .collect()
}

fn extension_to_owned_string<P: AsRef<Path>>(path: P) -> Option<String> {
    path.as_ref()
        .extension()
        .and_then(OsStr::to_str)
        .map(&str::to_string)
}

fn filename_to_owned_string<P: AsRef<Path>>(path: P) -> Option<String> {
    path.as_ref()
        .file_name()
        .and_then(OsStr::to_str)
        .map(&str::to_string)
}

fn file_stem_to_owned_string<P: AsRef<Path>>(path: P) -> Option<String> {
    path.as_ref()
        .file_stem()
        .and_then(OsStr::to_str)
        .map(&str::to_string)
}

fn path_to_owned_string<P: AsRef<Path>>(path: P) -> Option<String> {
    path.as_ref().to_str().map(&str::to_string)
}
