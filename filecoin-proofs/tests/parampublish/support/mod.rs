use std::fs::File;
use std::path::PathBuf;

pub mod session;

/// Create a parameters.json manifest file in a temp directory and return its
/// path.
pub fn create_tmp_manifest_file() -> Result<PathBuf, failure::Error> {
    let manifest_dir = tempfile::tempdir()?;
    let mut pbuf = manifest_dir.into_path();
    pbuf.push("parameters.json");

    File::create(&pbuf)?;

    Ok(pbuf)
}
