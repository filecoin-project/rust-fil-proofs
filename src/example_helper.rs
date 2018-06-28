use clap::{App, Arg};

pub trait Example {
    fn do_the_work(data_size: usize, challenge_count: usize);
    fn main(name: &str) {
        let matches = App::new(name)
            .version("1.0")
            .arg(
                Arg::with_name("size")
                    .required(true)
                    .long("size")
                    .help("The data size in MB")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("challenges")
                    .long("challenges")
                    .help("How many challenges to execute, defaults to 1")
                    .takes_value(true),
            )
            .get_matches();

        let data_size = value_t!(matches, "size", usize).unwrap() * 1024 * 1024;
        let challenge_count = value_t!(matches, "challenges", usize).unwrap_or_else(|_| 1);

        Self::do_the_work(data_size, challenge_count);
    }
}
