use failure::Error as FailureError;
use storage_proofs_core::parameter_cache::CacheEntryMetadata;

use crate::parampublish::support::session::ParamPublishSessionBuilder;

#[test]
fn ignores_files_unrecognized_extensions() -> Result<(), FailureError> {
    let to_create = vec!["v1-aaa.vk", "v1-aaa.params", "v1-bbb.txt", "ddd"];

    let (mut session, _) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .with_files(&to_create)
        .with_metadata("v1-aaa.meta", &CacheEntryMetadata { sector_size: 1024 })
        .list_all_files()
        .build();

    session.exp_string("found 3 param files in cache dir")?;
    session.exp_string("found 1 file triples")?;
    session.exp_string("Select files to publish")?;
    session.exp_string("v1-aaa.params (1 KiB)")?;
    session.exp_string("v1-aaa.vk (1 KiB)")?;
    session.send_line("")?;
    session.exp_string("no params selected, exiting")?;

    Ok(())
}

#[test]
fn displays_sector_size_in_prompt() -> Result<(), FailureError> {
    let to_create = vec!["v1-aaa.vk", "v1-aaa.params", "v1-xxx.vk", "v1-xxx.params"];

    let (mut session, _) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .with_files(&to_create)
        .with_metadata("v1-aaa.meta", &CacheEntryMetadata { sector_size: 2048 })
        .with_metadata("v1-xxx.meta", &CacheEntryMetadata { sector_size: 1024 })
        .list_all_files()
        .build();

    session.exp_string("found 6 param files in cache dir")?;
    session.exp_string("found 2 file triples")?;
    session.exp_string("Select files to publish")?;
    session.exp_string("v1-xxx.params (1 KiB)")?;
    session.exp_string("v1-xxx.vk (1 KiB)")?;
    session.exp_string("v1-aaa.params (2 KiB)")?;
    session.exp_string("v1-aaa.vk (2 KiB)")?;
    session.send_line("")?;
    session.exp_string("no params selected, exiting")?;

    Ok(())
}

#[test]
fn no_assets_no_prompt() -> Result<(), FailureError> {
    let (mut session, _) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .build();

    session.exp_string("found 0 param files in cache dir")?;
    session.exp_string("no file triples found, exiting")?;

    Ok(())
}
