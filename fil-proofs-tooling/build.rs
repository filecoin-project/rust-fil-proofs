use std::error::Error;
use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn Error>> {
    // Emits the `VERGEN_GIT_SHA` and `VERGEN_GIT_COMMIT_TIMESTAMP` environment variables.
    EmitBuilder::builder().all_git().emit()?;
    Ok(())
}
