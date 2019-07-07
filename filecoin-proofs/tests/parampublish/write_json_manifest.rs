use std::collections::btree_map::BTreeMap;
use std::fs::File;
use std::path::Path;

use failure::Error as FailureError;

use filecoin_proofs::param::ParameterData;
use storage_proofs::parameter_cache::CacheEntryMetadata;

use crate::parampublish::support::session::ParamPublishSessionBuilder;
use crate::support::{tmp_manifest, FakeIpfsBin};

#[test]
fn writes_json_manifest() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            let filenames = vec!["aaa.vk", "aaa.params"];

            let manifest_path = tmp_manifest(None)?;

            let ipfs = FakeIpfsBin::new();

            let (mut session, files_in_cache) = ParamPublishSessionBuilder::new()
                .with_session_timeout_ms(1000)
                .with_files(&filenames)
                .with_metadata("aaa.meta", &CacheEntryMetadata { sector_size: 1234 })
                .write_manifest_to(manifest_path.clone())
                .with_ipfs_bin(&ipfs)
                .with_prompt_disabled()
                .build();

            // compute checksums from files added to cache to compare with
            // manifest entries after publishing completes
            let cache_checksums = filename_to_checksum(&ipfs, files_in_cache.as_ref());

            // wait for confirmation...
            session.exp_string("publishing 2 parameters")?;
            session.exp_string("done")?;

            // read the manifest file from disk and verify that it is well
            // formed and contains the expected keys
            let manifest_file = File::open(&manifest_path)?;
            let manifest_map: BTreeMap<String, ParameterData> =
                serde_json::from_reader(manifest_file)?;

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
        })
        .expect("parampublish test failed");
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
                .unwrap_or("".to_string()),
            ipfs_bin
                .compute_checksum(item)
                .expect("failed to compute checksum"),
        );
        acc
    })
}
