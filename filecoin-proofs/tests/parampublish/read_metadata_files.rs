use failure::Error as FailureError;

use crate::parampublish::support::session::ParamPublishSessionBuilder;

#[test]
fn fails_if_missing_metadata_file() -> Result<(), FailureError> {
    // missing the corresponding .meta file
    let filenames = vec!["aaa.vk", "aaa.params"];

    let (mut session, _) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .with_files(&filenames)
        .with_prompt_disabled()
        .build();

    // error!
    session.exp_string("no metadata found for parameter id aaa")?;

    Ok(())
}

#[test]
fn fails_if_malformed_metadata_file() -> Result<(), FailureError> {
    let mut malformed: &[u8] = &vec![42];

    let (mut session, _) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .with_files(&vec!["aaa.vk", "aaa.params"])
        .with_file_and_bytes("aaa.meta", &mut malformed)
        .with_prompt_disabled()
        .build();

    // error!
    session.exp_string("fatal error")?;

    Ok(())
}
