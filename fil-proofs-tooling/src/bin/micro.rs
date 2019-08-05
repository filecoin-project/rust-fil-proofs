#[macro_use]
extern crate commandspec;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde;

use regex::Regex;
use std::io;

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
struct Interval {
    start: f64,
    end: f64,
    unit: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
struct CriterionResult {
    name: String,
    samples: u32,
    time_med: f64,
    time: Interval,
    throughput: Interval,
    slope: Interval,
    mean: Interval,
    median: Interval,
    r_2: Interval,
    std_dev: Interval,
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
    let time_re = Regex::new(r"time:\s+\[(\d+\.\d+ \w+) (\d+\.\d+ \w+) (\d+\.\d+ \w+)]")
        .expect("invalid regex");

    let throughput_re =
        Regex::new(r"thrpt:\s+\[(\d+\.\d+ \w+/s) (\d+\.\d+ \w+/s) (\d+\.\d+ \w+/s)]")
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
        Option<Interval>,
    )> = None;

    for line in s.as_ref().lines() {
        if let Some(caps) = start_re.captures(line) {
            if current.is_some() {
                let r = current.take().unwrap();
                res.push(CriterionResult {
                    name: r.0,
                    samples: r.1.unwrap_or_default(),
                    time_med: r.2.unwrap_or_default(),
                    time: r.3.unwrap_or_default(),
                    throughput: r.4.unwrap_or_default(),
                    slope: r.5.unwrap_or_default(),
                    mean: r.6.unwrap_or_default(),
                    median: r.7.unwrap_or_default(),
                    r_2: r.8.unwrap_or_default(),
                    std_dev: r.9.unwrap_or_default(),
                    med_abs_dev: r.10.unwrap_or_default(),
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
                    unit: Some("us".to_string()),
                });
            }

            // Throughput
            if let Some(caps) = throughput_re.captures(line) {
                current.4 = Some(Interval {
                    start: throughput_val(&caps[1]),
                    end: throughput_val(&caps[3]),
                    unit: Some(throughput_to_uom(&caps[1])),
                });
            }

            // Slope
            if let Some(caps) = slope_re.captures(line) {
                current.5 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
            }

            // Mean
            if let Some(caps) = mean_re.captures(line) {
                current.6 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
            }

            // median
            if let Some(caps) = median_re.captures(line) {
                current.7 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
            }

            // R^2
            if let Some(caps) = r_2_re.captures(line) {
                current.8 = Some(Interval {
                    start: caps[1].parse().unwrap(),
                    end: caps[2].parse().unwrap(),
                    unit: None,
                });
            }

            // std.dev
            if let Some(caps) = std_dev_re.captures(line) {
                current.9 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
            }

            // med.abs.dev
            if let Some(caps) = med_abs_dev_re.captures(line) {
                current.10 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
            }
        }
    }

    if current.is_some() {
        let r = current.take().unwrap();
        res.push(CriterionResult {
            name: r.0,
            samples: r.1.unwrap_or_default(),
            time_med: r.2.unwrap_or_default(),
            time: r.3.unwrap_or_default(),
            throughput: r.4.unwrap_or_default(),
            slope: r.5.unwrap_or_default(),
            mean: r.6.unwrap_or_default(),
            median: r.7.unwrap_or_default(),
            r_2: r.8.unwrap_or_default(),
            std_dev: r.9.unwrap_or_default(),
            med_abs_dev: r.10.unwrap_or_default(),
        });
    }
    Ok(res)
}

/// parses a string of the form "521.80 KiB/s".
fn throughput_to_uom(s: &str) -> String {
    let parts = s.trim().split_whitespace().collect::<Vec<_>>();
    assert_eq!(parts.len(), 2, "invalid val: {:?}", parts);
    let _: f64 = parts[0].parse().expect("invalid number");
    parts[1].to_string()
}

/// parses a string of the form "521.80 KiB/s".
fn throughput_val(s: &str) -> f64 {
    let parts = s.trim().split_whitespace().collect::<Vec<_>>();
    assert_eq!(parts.len(), 2, "invalid val: {:?}", parts);
    let ts: f64 = parts[0].parse().expect("invalid number");
    ts
}

/// parses a string of the form "123.12 us".
fn time_to_us(s: &str) -> f64 {
    let parts = s.trim().split_whitespace().collect::<Vec<_>>();
    assert_eq!(parts.len(), 2, "invalid val: {:?}", parts);
    let ts: f64 = parts[0].parse().expect("invalid number");
    let normalized = match parts[1] {
        "ns" => ts / 1000.,
        "us" => ts,
        "ms" => ts * 1000.,
        "s" => ts * 1000. * 1000.,
        _ => panic!("unknown unit: {}", parts[1]),
    };

    (normalized * 10000.0).round() / 10000.0
}

fn run_benches(args: Vec<String>, _push_prometheus: bool) -> Result<(), failure::Error> {
    let mut cmd = command!(
        r"
        cargo bench --all --verbose --color never {args} --
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
    serde_json::to_writer(io::stdout(), &parsed_results)
        .expect("cannot write report-JSON to stdout");

    Ok(())
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
    fn test_parse_criterion_no_throughput() {
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
median [138.33 us 143.23 us] med. abs. dev. [1.7507 ms 8.4109 ms]";

        let parsed = parse_criterion_out(stdout).unwrap();
        assert_eq!(
            parsed,
            vec![CriterionResult {
                name: "merkletree/blake2s/128".into(),
                samples: 20,
                time_med: 151.42,
                time: Interval {
                    start: 141.11,
                    end: 159.66,
                    unit: Some("us".to_string())
                },
                throughput: Interval {
                    start: 0.0,
                    end: 0.0,
                    unit: None
                },
                slope: Interval {
                    start: 141.11,
                    end: 159.66,
                    unit: Some("us".to_string())
                },
                mean: Interval {
                    start: 140.55,
                    end: 150.62,
                    unit: Some("us".to_string())
                },
                median: Interval {
                    start: 138.33,
                    end: 143.23,
                    unit: Some("us".to_string())
                },
                r_2: Interval {
                    start: 0.8124914,
                    end: 0.8320154,
                    unit: None
                },
                std_dev: Interval {
                    start: 5.6028,
                    end: 15.213,
                    unit: Some("us".to_string())
                },
                med_abs_dev: Interval {
                    start: 1750.7,
                    end: 8410.9,
                    unit: Some("us".to_string())
                },
            }]
        );
    }

    #[test]
    fn test_parse_criterion_with_throughput() {
        let with_throughput = "Benchmarking merkletree/blake2s/128
Benchmarking merkletree/blake2s/128: Warming up for 3.0000 s
Benchmarking merkletree/blake2s/128: Collecting 20 samples in estimated 5.0192 s (39060 iterations)
Benchmarking merkletree/blake2s/128: Analyzing
merkletree/blake2s/128  
                    time:   [141.11 us 151.42 us 159.66 us]
                    thrpt:  [68.055 MiB/s 68.172 MiB/s 68.644 MiB/s]
             change: 
                    time:   [-25.163% -21.490% -17.475%] (p = 0.00 < 0.05)
                    thrpt:  [-25.163% -21.490% -17.475%] (p = 0.00 < 0.05)
                    Performance has improved.
Found 4 outliers among 20 measurements (20.00%)
1 (5.00%) high mild
3 (15.00%) high severe
slope  [141.11 us 159.66 us] R^2            [0.8124914 0.8320154]
mean   [140.55 us 150.62 us] std. dev.      [5.6028 us 15.213 us]
median [138.33 us 143.23 us] med. abs. dev. [1.7507 ms 8.4109 ms]";

        let parsed = parse_criterion_out(with_throughput).unwrap();
        assert_eq!(
            parsed,
            vec![CriterionResult {
                name: "merkletree/blake2s/128".into(),
                samples: 20,
                time_med: 151.42,
                time: Interval {
                    start: 141.11,
                    end: 159.66,
                    unit: Some("us".to_string())
                },
                throughput: Interval {
                    start: 68.055,
                    end: 68.644,
                    unit: Some("MiB/s".to_string())
                },
                slope: Interval {
                    start: 141.11,
                    end: 159.66,
                    unit: Some("us".to_string())
                },
                mean: Interval {
                    start: 140.55,
                    end: 150.62,
                    unit: Some("us".to_string())
                },
                median: Interval {
                    start: 138.33,
                    end: 143.23,
                    unit: Some("us".to_string())
                },
                r_2: Interval {
                    start: 0.8124914,
                    end: 0.8320154,
                    unit: None
                },
                std_dev: Interval {
                    start: 5.6028,
                    end: 15.213,
                    unit: Some("us".to_string())
                },
                med_abs_dev: Interval {
                    start: 1750.7,
                    end: 8410.9,
                    unit: Some("us".to_string())
                },
            }]
        );
    }
}
