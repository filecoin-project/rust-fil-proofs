use std::collections::btree_map::BTreeMap;
use std::fs::File;
use std::path::Path;

use failure::Error as FailureError;

use storage_proofs::parameter_cache::{CacheEntryMetadata, ParameterData};

use crate::parampublish::support::session::ParamPublishSessionBuilder;
use crate::support::{tmp_manifest, FakeIpfsBin};

#[test]
fn writes_json_manifest() -> Result<(), FailureError> {
    let filenames = vec!["v10-aaa.vk", "v10-aaa.params"];

    let manifest_path = tmp_manifest(None)?;

    let ipfs = FakeIpfsBin::new();

    let (mut session, files_in_cache) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .with_files(&filenames)
        .with_metadata("v10-aaa.meta", &CacheEntryMetadata { sector_size: 1234 })
        .write_manifest_to(manifest_path.clone())
        .with_ipfs_bin(&ipfs)
        .with_prompt_disabled()
        .build();

    // compute checksums from files added to cache to compare with
    // manifest entries after publishing completes
    let cache_checksums = filename_to_checksum(&ipfs, files_in_cache.as_ref());

    session.exp_string("Select a version")?;
    // There is only one version of parameters, accept that one
    session.send_line("")?;
    //session.exp_regex(".*Select the sizes to publish.*")?;
    session.exp_string("Select the sizes to publish")?;
    // There is only one size, accept that one
    session.send_line("")?;

    // wait for confirmation...
    session.exp_string("publishing 2 files")?;
    session.exp_string("done")?;

    // read the manifest file from disk and verify that it is well
    // formed and contains the expected keys
    let manifest_file = File::open(&manifest_path)?;
    let manifest_map: BTreeMap<String, ParameterData> = serde_json::from_reader(manifest_file)?;

    // ensure that each filename exists in the manifest and that its
    // cid matches that which was produced from the `ipfs add` command
    for filename in filenames.iter().cloned() {
        if let (Some(m_entry), Some(expected)) =
            (manifest_map.get(filename), cache_checksums.get(filename))
        {
            assert_eq!(
                &m_entry.cid, expected,
                "manifest does not include digest produced by ipfs add for {}",
                filename
            );
        } else {
            panic!("{} must be present in both manifest and cache", filename);
        }
    }

    Ok(())
}

/// Produce a map of filename (not path) to the checksum produced by the ipfs
/// binary.
fn filename_to_checksum<P: AsRef<Path>>(
    ipfs_bin: &FakeIpfsBin,
    paths: &[P],
) -> BTreeMap<String, String> {
    paths.iter().fold(BTreeMap::new(), |mut acc, item| {
        acc.insert(
            item.as_ref()
                .file_name()
                .and_then(|os_str| os_str.to_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "".to_string()),
            ipfs_bin
                .compute_checksum(item)
                .expect("failed to compute checksum"),
        );
        acc
    })
}
