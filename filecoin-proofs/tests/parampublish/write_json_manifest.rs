use crate::parampublish::support::create_tmp_manifest_file;
use crate::parampublish::support::session::ParamPublishSessionBuilder;
use failure::Error as FailureError;
use filecoin_proofs::param::ParameterData;
use std::collections::btree_map::BTreeMap;
use std::fs::File;
use storage_proofs::parameter_cache::CacheEntryMetadata;

#[test]
fn writes_json_manifest() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            let filenames = vec!["aaa.vk", "aaa.params"];

            let manifest_path = create_tmp_manifest_file()?;

            let mut session = ParamPublishSessionBuilder::new()
                .with_session_timeout_ms(1000)
                .with_files(&filenames)
                .with_metadata(
                    "aaa.meta",
                    &CacheEntryMetadata {
                        sector_size: Some(1234),
                    },
                )
                .write_manifest_to(manifest_path.clone())
                .build();

            // agree to publish both params
            for _ in 0..2 {
                session.exp_string(": ")?;
                session.send_line("y")?;
            }

            // wait for confirmation...
            session.exp_string("publishing 2 parameters")?;
            session.exp_string("done")?;

            // read the manifest file from disk and verify that it is well
            // formed and contains the expected keys
            let manifest_file = File::open(&manifest_path)?;
            let manifest_map: BTreeMap<String, ParameterData> =
                serde_json::from_reader(manifest_file)?;

            for filename in filenames.iter().cloned() {
                assert!(
                    manifest_map.contains_key(filename),
                    "manifest does not contain {}",
                    filename
                );
            }

            Ok(())
        })
        .expect("parampublish test failed");
}
