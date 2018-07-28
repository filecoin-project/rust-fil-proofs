extern crate bellman;
extern crate pairing;
extern crate proofs;
extern crate rand;
extern crate sapling_crypto;
#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;
extern crate env_logger;

use clap::{App, Arg};
use pairing::bls12_381::{Bls12, Fr};
use pairing::PrimeField;
use std::time::{Duration, Instant};

use proofs::crypto::sloth;
use proofs::example_helper::{init_logger, prettyb};

fn do_the_work(rounds: usize) {
    info!(target: "config", "rounds: {}", prettyb(rounds));

    // timers
    let mut sloth_encode_duration = Duration::new(0, 0);
    let mut sloth_decode_duration = Duration::new(0, 0);

    // sample data to encrypt and sample key
    let key = Fr::from_str("11111111").unwrap();
    let plaintext = Fr::from_str("123456789").unwrap();

    // benchmark encode
    let start_encode = Instant::now();
    let ciphertext = sloth::encode::<Bls12>(&key, &plaintext, rounds);
    sloth_encode_duration += start_encode.elapsed();

    // benchmark decode
    let start_decode = Instant::now();
    let _decrypted = sloth::decode::<Bls12>(&key, &ciphertext, rounds);
    sloth_decode_duration += start_decode.elapsed();

    // printing stats
    info!(target: "stats", "Sloth encode time: {:?}", sloth_encode_duration);
    info!(target: "stats", "Sloth decode time: {:?}", sloth_decode_duration);
}

fn main() {
    init_logger();

    let matches = App::new(stringify!("Sloth Vanilla Bench"))
        .version("1.0")
        .arg(
            Arg::with_name("rounds")
                .required(true)
                .long("rounds")
                .help("Number of sloth rounds")
                .takes_value(true),
        )
        .get_matches();

    let rounds = value_t!(matches, "rounds", usize).unwrap();
    do_the_work(rounds);
}
