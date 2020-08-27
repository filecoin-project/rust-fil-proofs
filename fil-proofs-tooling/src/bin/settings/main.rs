use anyhow::Result;

use storage_proofs::settings::{Settings, SETTINGS};

fn main() -> Result<()> {
    println!("{:#?}", *SETTINGS.lock().unwrap());
    Ok(())
}
