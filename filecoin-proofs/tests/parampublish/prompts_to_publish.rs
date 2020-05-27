use std::collections::HashSet;
use std::iter::FromIterator;

use failure::Error as FailureError;

use storage_proofs::parameter_cache::CacheEntryMetadata;

use crate::parampublish::support::session::ParamPublishSessionBuilder;
use std::collections::btree_map::BTreeMap;

#[test]
fn ignores_files_unrecognized_extensions() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            // create files with these names in the parameter cache
            let to_create = vec!["aaa.vk", "aaa.params", "bbb.txt", "ddd"];

            // parampublish should prompt user to publish these files
            let to_prompt: HashSet<&str> =
                HashSet::from_iter(vec!["aaa.vk", "aaa.params"].iter().cloned());

            let (mut session, _) = ParamPublishSessionBuilder::new()
                .with_session_timeout_ms(1000)
                .with_files(&to_create)
                .with_metadata("aaa.meta", &CacheEntryMetadata { sector_size: 1234 })
                .build();

            for _ in 0..to_prompt.len() {
                session.exp_string("[y/n] (sector size: 1234B) ")?;
                let prompt_filename = session.exp_string(": ")?;
                let key: &str = &prompt_filename;
                assert_eq!(true, to_prompt.contains(key), "missing {}", key);
                session.send_line("n")?;
            }

            session.exp_string("no files to publish")?;
            session.exp_string("done")?;

            Ok(())
        })
        .expect("parampublish test failed");
}

#[test]
fn displays_sector_size_in_prompt() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            let to_create = vec!["aaa.vk", "aaa.params", "xxx.vk", "xxx.params"];

            let (mut session, _) = ParamPublishSessionBuilder::new()
                .with_session_timeout_ms(1000)
                .with_files(&to_create)
                .with_metadata("aaa.meta", &CacheEntryMetadata { sector_size: 1234 })
                .with_metadata("xxx.meta", &CacheEntryMetadata { sector_size: 4444 })
                .build();

            let mut map: BTreeMap<&str, String> = BTreeMap::new();
            map.insert("aaa.vk", "1234".to_string());
            map.insert("aaa.params", "1234".to_string());
            map.insert("xxx.vk", "4444".to_string());
            map.insert("xxx.params", "4444".to_string());

            for _ in 0..to_create.len() {
                session.exp_string("[y/n] (sector size: ")?;
                let prompt_sector_size: &str = &session.exp_string("B) ")?;
                let prompt_filename: &str = &session.exp_string(": ")?;
                assert_eq!(
                    map.get(prompt_filename).expect("missing prompt filename"),
                    prompt_sector_size
                );
                session.send_line("n")?;
            }

            Ok(())
        })
        .expect("parampublish test failed");
}

#[test]
fn no_assets_no_prompt() -> Result<(), FailureError> {
    let (mut session, _) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .build();

    session.exp_string("No valid parameters in directory")?;

    Ok(())
}
