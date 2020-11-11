use failure::Error as FailureError;

use crate::parampublish::support::session::ParamPublishSessionBuilder;

#[test]
fn fails_if_missing_metadata_file() -> Result<(), FailureError> {
    // missing the corresponding .meta file
    let filenames = vec!["v12-aaa.vk", "v12-aaa.params"];

    let (mut session, _) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .with_files(&filenames)
        .with_prompt_disabled()
        .build();

    // error!
    session.exp_string("No valid parameters in directory")?;

    Ok(())
}

#[test]
fn fails_if_malformed_metadata_file() -> Result<(), FailureError> {
    let mut malformed: &[u8] = &[42];

    let (mut session, _) = ParamPublishSessionBuilder::new()
        .with_session_timeout_ms(1000)
        .with_files(&["v11-aaa.vk", "v11-aaa.params"])
        .with_file_and_bytes("v11-aaa.meta", &mut malformed)
        .with_prompt_disabled()
        .build();

    // error!
    session.exp_string("fatal error")?;

    Ok(())
}
