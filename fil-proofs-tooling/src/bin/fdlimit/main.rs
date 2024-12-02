fn main() {
    fil_logger::init();

    match fdlimit::raise_fd_limit() {
        Ok(fdlimit::Outcome::LimitRaised { from, to }) => {
            println!("File descriptor limit was raised from {from} to {to}");
        }
        Ok(fdlimit::Outcome::Unsupported) => {
            panic!("failed to raise fd limit: unsupported")
        }
        Err(e) => {
            panic!("failed to raise fd limit: {}", e)
        }
    }
}
