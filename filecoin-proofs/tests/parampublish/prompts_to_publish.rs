extern crate rexpect;

use std::collections::HashSet;
use std::iter::FromIterator;

use failure::Error as FailureError;

use storage_proofs::parameter_cache::CacheEntryMetadata;

use crate::parampublish::support::session::ParamPublishSessionBuilder;

#[test]
fn prompts_to_publish_assets_in_cache_dir() {
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
                session.exp_string("[y/n] (1234B) ")?;
                let prompt_filename = session.exp_string(": ")?;
                let key: &str = &prompt_filename;
                assert_eq!(true, to_prompt.contains(key), "missing {}", key);
                session.send_line("n")?;
            }

            session.exp_string("no parameters to publish")?;
            session.exp_string("done")?;

            Ok(())
        })
        .expect("parampublish test failed");
}

#[test]
fn all_flag_disables_prompt() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            let filenames = vec!["aaa.vk", "aaa.params"];

            let (mut session, _) = ParamPublishSessionBuilder::new()
                .with_session_timeout_ms(1000)
                .with_prompt_disabled()
                .with_files(&filenames)
                .with_metadata("aaa.meta", &CacheEntryMetadata { sector_size: 1234 })
                .build();

            session.exp_string("publishing 2 parameters")?;
            session.exp_string("done")?;

            Ok(())
        })
        .expect("parampublish test failed");
}

#[test]
fn no_assets_no_prompt() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            let (mut session, _) = ParamPublishSessionBuilder::new()
                .with_session_timeout_ms(1000)
                .build();

            session.exp_string("no parameters to publish")?;
            session.exp_string("done")?;

            Ok(())
        })
        .expect("parampublish test failed");
}
