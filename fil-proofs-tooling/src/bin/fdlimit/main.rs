use anyhow::Result;

fn main() -> Result<()> {
    fil_logger::init();

    let res = fdlimit::raise_fd_limit().expect("failed to raise fd limit");
    println!("File descriptor limit was raised to {}", res);

    Ok(())
}
