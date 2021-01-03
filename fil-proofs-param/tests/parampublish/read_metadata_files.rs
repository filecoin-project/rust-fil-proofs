use failure::Error as FailureError;

use crate::parampublish::support::session::ParamPublishSessionBuilder;

#[test]
fn fails_if_missing_metadata_file() -> Result<(), FailureError> {
    // missing the corresponding .meta file
    let filenames = vec!["v12-aaa.vk", "v12-aaa.params"];

    let (mut session, _) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .with_files(&filenames)
        .build();

    session.exp_string("found 2 param files in cache dir")?;
    session.exp_string("no file triples found, exiting")?;

    Ok(())
}

#[test]
fn fails_if_malformed_metadata_file() -> Result<(), FailureError> {
    // A malformed v11-aaa.meta file.
    let mut malformed: &[u8] = &[42];

    let (mut session, _) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .with_files(&["v11-aaa.vk", "v11-aaa.params"])
        .with_file_and_bytes("v11-aaa.meta", &mut malformed)
        .build();

    session.exp_string("found 3 param files in cache dir")?;
    session.exp_string("found 1 file triples")?;
    session.exp_string("failed to parse .meta file")?;
    session.exp_string("exiting")?;

    Ok(())
}
