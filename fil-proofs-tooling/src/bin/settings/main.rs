use anyhow::Result;

use storage_proofs_core::settings::SETTINGS;

fn main() -> Result<()> {
    println!("{:#?}", *SETTINGS);
    Ok(())
}
