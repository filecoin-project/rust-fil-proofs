use crate::parampublish::support::session::ParamPublishSessionBuilder;
use failure::Error as FailureError;

#[test]
fn fails_if_missing_metadata_file() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            // missing the corresponding .meta file
            let filenames = vec!["aaa.vk", "aaa.params"];

            let mut session = ParamPublishSessionBuilder::new()
                .with_session_timeout_ms(1000)
                .with_files(&filenames)
                .build();

            for _ in 0..2 {
                session.exp_string(": ")?;
                session.send_line("y")?;
            }

            // error!
            session.exp_string("no metadata file found for parameter id aaa")?;

            Ok(())
        })
        .expect("parampublish test failed");
}

#[test]
fn fails_if_malformed_metadata_file() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            let mut malformed: &[u8] = &vec![42];

            let builder = ParamPublishSessionBuilder::new()
                .with_session_timeout_ms(1000)
                .with_files(&vec!["aaa.vk", "aaa.params"])
                .with_file_and_bytes("aaa.meta", &mut malformed);

            let mut session = builder.build();

            for _ in 0..2 {
                session.exp_string(": ")?;
                session.send_line("y")?;
            }

            // error!
            session.exp_string("fatal error")?;

            Ok(())
        })
        .expect("parampublish test failed");
}
