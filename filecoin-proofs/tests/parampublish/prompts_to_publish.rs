extern crate rexpect;

use std::collections::HashSet;
use std::iter::FromIterator;

use failure::Error as FailureError;

use crate::parampublish::support::session::ParamPublishSessionBuilder;

#[test]
fn prompts_to_publish_assets_in_cache_dir() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            // create files with these names in the parameter cache
            let to_create = vec!["aaa.vk", "aaa.meta", "aaa.params", "bbb.txt", "ddd"];

            // parampublish should prompt user to publish these files
            let to_prompt: HashSet<&str> =
                HashSet::from_iter(vec!["aaa.vk", "aaa.params"].iter().cloned());

            let mut session = ParamPublishSessionBuilder::new()
                .with_session_timeout_ms(1000)
                .with_files(&to_create)
                .build();

            for _ in 0..to_prompt.len() {
                session.exp_string("[y/n] ")?;
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
fn displays_sector_size_from_metadata_files_in_prompt() {
    unimplemented!();
}

#[test]
fn all_flag_disables_prompt() {
    unimplemented!();
}

#[test]
fn no_assets_no_prompt() {
    unimplemented!();
}
