use anyhow::Result;

use storage_proofs::settings::SETTINGS;

fn main() -> Result<()> {
    println!("{:#?}", *SETTINGS);
    Ok(())
}
