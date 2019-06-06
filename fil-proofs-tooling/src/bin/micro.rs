#[macro_use]
extern crate commandspec;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate prometheus;

use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use regex::Regex;

#[derive(Debug, Default, Clone, PartialEq)]
struct Interval {
    start: f64,
    end: f64,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct CriterionResult {
    name: String,
    samples: u32,
    time_med_us: f64,
    time_us: Interval,
    slope_us: Interval,
    mean_us: Interval,
    median_us: Interval,
    r_2: Interval,
    std_dev_us: Interval,
    med_abs_dev: Interval,
}

fn make_detail_re(name: &str) -> Regex {
    Regex::new(&format!(r"{}\s+\[(\d+\.\d+ \w+) (\d+\.\d+ \w+)\]", name)).expect("invalid regex")
}

/// Parses the output of `cargo bench -p storage-proofs --bench <benchmark> -- --verbose --colors never`.
fn parse_criterion_out(s: impl AsRef<str>) -> Result<Vec<CriterionResult>, failure::Error> {
    let mut res = Vec::new();

    let start_re = Regex::new(r"^Benchmarking ([^:]+)$").expect("invalid regex");
    let sample_re = Regex::new(r"Collecting (\d+) samples").expect("invalid regex");
    let time_re = Regex::new(r"time:\s+\[(\d+\.\d+ \w+) (\d+\.\d+ \w+) (\d+\.\d+ \w+)\]")
        .expect("invalid regex");

    let slope_re = make_detail_re("slope");
    let r_2_re = Regex::new(r"R\^2\s+\[(\d+\.\d+) (\d+\.\d+)\]").expect("invalid regex");
    let mean_re = make_detail_re("mean");
    let std_dev_re = make_detail_re(r"std\. dev\.");
    let median_re = make_detail_re("median");
    let med_abs_dev_re = make_detail_re(r"med\. abs\. dev\.");

    let mut current: Option<(
        String,
        Option<u32>,
        Option<f64>,
        Option<Interval>,
        Option<Interval>,
        Option<Interval>,
        Option<Interval>,
        Option<Interval>,
        Option<Interval>,
        Option<Interval>,
    )> = None;

    for line in s.as_ref().lines() {
        if let Some(caps) = start_re.captures(line) {
            if current.is_some() {
                let r = current.take().unwrap();
                res.push(CriterionResult {
                    name: r.0,
                    samples: r.1.unwrap_or_default(),
                    time_med_us: r.2.unwrap_or_default(),
                    time_us: r.3.unwrap_or_default(),
                    slope_us: r.4.unwrap_or_default(),
                    mean_us: r.5.unwrap_or_default(),
                    median_us: r.6.unwrap_or_default(),
                    r_2: r.7.unwrap_or_default(),
                    std_dev_us: r.8.unwrap_or_default(),
                    med_abs_dev: r.9.unwrap_or_default(),
                });
            }
            current = Some((
                caps[1].to_string(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ));
        }

        if let Some(ref mut current) = current {
            // Samples
            if let Some(caps) = sample_re.captures(line) {
                current.1 = Some(caps[1].parse().unwrap_or_default());
            }

            // Time
            if let Some(caps) = time_re.captures(line) {
                current.2 = Some(time_to_us(&caps[2]));
                current.3 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[3]),
                });
            }

            // Slope
            if let Some(caps) = slope_re.captures(line) {
                current.4 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                });
            }
            // R^2
            if let Some(caps) = r_2_re.captures(line) {
                current.7 = Some(Interval {
                    start: caps[1].parse().unwrap(),
                    end: caps[2].parse().unwrap(),
                });
            }

            // Mean
            if let Some(caps) = mean_re.captures(line) {
                current.5 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                });
            }

            // std.dev
            if let Some(caps) = std_dev_re.captures(line) {
                current.8 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                });
            }

            // median
            if let Some(caps) = median_re.captures(line) {
                current.6 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                });
            }

            // med.abs.dev
            if let Some(caps) = med_abs_dev_re.captures(line) {
                current.9 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                });
            }
        }
    }

    if current.is_some() {
        let r = current.take().unwrap();
        res.push(CriterionResult {
            name: r.0,
            samples: r.1.unwrap_or_default(),
            time_med_us: r.2.unwrap_or_default(),
            time_us: r.3.unwrap_or_default(),
            slope_us: r.4.unwrap_or_default(),
            mean_us: r.5.unwrap_or_default(),
            median_us: r.6.unwrap_or_default(),
            r_2: r.7.unwrap_or_default(),
            std_dev_us: r.8.unwrap_or_default(),
            med_abs_dev: r.9.unwrap_or_default(),
        });
    }
    Ok(res)
}

/// parses a string of the form "123.12 us".
fn time_to_us(s: &str) -> f64 {
    let parts = s.trim().split_whitespace().collect::<Vec<_>>();
    assert_eq!(parts.len(), 2, "invalid val: {:?}", parts);
    let ts: f64 = parts[0].parse().expect("invalid number");
    match parts[1] {
        "ns" => ts / 1000.,
        "us" => ts,
        "ms" => ts * 1000.,
        "s" => ts * 1000. * 1000.,
        _ => panic!("unknown unit: {}", parts[1]),
    }
}

fn run_benches(args: Vec<String>, push_prometheus: bool) -> Result<(), failure::Error> {
    let mut cmd = command!(
        r"
        cargo bench -p storage-proofs {args} -- --verbose --color never
    ",
        args = args
    )?;

    println!("{:?}", cmd);
    let result = cmd.output()?;

    if !result.status.success() {
        bail!(
            "Exit: {} - {}",
            result.status,
            std::str::from_utf8(&result.stderr)?
        );
    }

    let stdout = std::str::from_utf8(&result.stdout)?;
    let parsed_results = parse_criterion_out(stdout)?;
    process_results(parsed_results, push_prometheus);

    Ok(())
}

fn process_results(results: Vec<CriterionResult>, push: bool) {
    // Create a prometheus registry
    let r = Registry::new();

    // Create a Counter.
    let time_gauge_vec =
        GaugeVec::new(Opts::new("time_gauge_us", "time gauge help"), &["name"]).unwrap();

    r.register(Box::new(time_gauge_vec.clone())).unwrap();

    for res in &results {
        time_gauge_vec
            .with_label_values(&[&res.name])
            .set(res.time_med_us);
    }

    // Gather the metrics.
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = r.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    // Output to the standard output.
    println!("{}", String::from_utf8(buffer).unwrap());

    if push {
        let address = "127.0.0.1:9091";
        println!("pushing results to gateway {}", address);

        let metric_families = prometheus::gather();
        prometheus::push_metrics(
            "micros-fil-proofs",
            labels! { "why".to_owned() => "are you here?".to_owned(), },
            &address,
            metric_families,
            None,
        )
        .expect("failed to push")
    }
}

fn main() {
    let pass_through = std::env::args()
        .skip(1)
        .filter(|arg| arg != "--push-prometheus")
        .collect();
    let push_prometheus = std::env::args()
        .find(|arg| arg == "--push-prometheus")
        .is_some();
    match run_benches(pass_through, push_prometheus) {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_to_us() {
        assert_eq!(time_to_us("123.12 us"), 123.12);
        assert_eq!(time_to_us("1.0 s"), 1_000_000.);
    }

    #[test]
    fn test_parse_criterion() {
        let stdout = "Benchmarking merkletree/blake2s/128
Benchmarking merkletree/blake2s/128: Warming up for 3.0000 s
Benchmarking merkletree/blake2s/128: Collecting 20 samples in estimated 5.0192 s (39060 iterations)
Benchmarking merkletree/blake2s/128: Analyzing
merkletree/blake2s/128  time:   [141.11 us 151.42 us 159.66 us]
                        change: [-25.163% -21.490% -17.475%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 20 measurements (20.00%)
  1 (5.00%) high mild
  3 (15.00%) high severe
slope  [141.11 us 159.66 us] R^2            [0.8124914 0.8320154]
mean   [140.55 us 150.62 us] std. dev.      [5.6028 us 15.213 us]
median [138.33 us 143.23 us] med. abs. dev. [1.7507 us 8.4109 us]";

        let parsed = parse_criterion_out(stdout).unwrap();
        assert_eq!(
            parsed,
            vec![CriterionResult {
                name: "merkletree/blake2s/128".into(),
                samples: 20,
                time_med_us: 151.42,
                time_us: Interval {
                    start: 141.11,
                    end: 159.66
                },
                slope_us: Interval {
                    start: 141.11,
                    end: 159.66
                },
                mean_us: Interval {
                    start: 140.55,
                    end: 150.62
                },
                median_us: Interval {
                    start: 138.33,
                    end: 143.23
                },
                r_2: Interval {
                    start: 0.8124914,
                    end: 0.8320154
                },
                std_dev_us: Interval {
                    start: 5.6028,
                    end: 15.213
                },
                med_abs_dev: Interval {
                    start: 1.7507,
                    end: 8.4109
                },
            }]
        );
    }
}
