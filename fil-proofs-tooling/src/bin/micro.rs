use std::io::{self, BufRead};

use anyhow::{anyhow, Context, Result};
use commandspec::command;
use fil_proofs_tooling::metadata::Metadata;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Interval {
    start: f64,
    end: f64,
    unit: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Point {
    value: f64,
    unit: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct CriterionResult {
    name: String,
    samples: u32,
    time_med: Point,
    time: Interval,
    throughput: Option<Interval>,
    throughput_med: Option<Point>,
    slope: Option<Interval>,
    mean: Option<Interval>,
    median: Option<Interval>,
    r_2: Option<Interval>,
    std_dev: Option<Interval>,
    med_abs_dev: Option<Interval>,
}

fn make_detail_re(name: &str) -> Regex {
    Regex::new(&format!(r"{}\s+\[(\d+\.\d+ \w+) (\d+\.\d+ \w+)\]", name)).expect("invalid regex")
}

/// Parses the output of `cargo bench -p storage-proofs --bench <benchmark> -- --verbose --colors never`.
fn parse_criterion_out(s: impl AsRef<str>) -> Result<Vec<CriterionResult>> {
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

    #[allow(clippy::type_complexity)]
    let mut current: Option<(
        String,
        Option<u32>,
        Option<Point>,
        Option<Interval>,
        Option<Interval>,
        Option<Point>,
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
                let r = current.take().expect("unreachable: is_some()");
                res.push(CriterionResult {
                    name: r.0,
                    samples: r.1.unwrap_or_default(),
                    time_med: r.2.unwrap_or_default(),
                    time: r.3.unwrap_or_default(),
                    throughput: r.4,
                    throughput_med: r.5,
                    slope: r.6,
                    mean: r.7,
                    median: r.8,
                    r_2: r.9,
                    std_dev: r.10,
                    med_abs_dev: r.11,
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
                current.2 = Some(Point {
                    value: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
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
                current.5 = Some(Point {
                    value: throughput_val(&caps[2]),
                    unit: Some(throughput_to_uom(&caps[2])),
                });
            }

            // Slope
            if let Some(caps) = slope_re.captures(line) {
                current.6 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
            }

            // Mean
            if let Some(caps) = mean_re.captures(line) {
                current.7 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
            }

            // median
            if let Some(caps) = median_re.captures(line) {
                current.8 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
            }

            // R^2
            if let Some(caps) = r_2_re.captures(line) {
                current.9 = Some(Interval {
                    start: caps[1].parse().expect("failed to parse caps[1] string"),
                    end: caps[2].parse().expect("failed to parse caps[2] string"),
                    unit: None,
                });
            }

            // std.dev
            if let Some(caps) = std_dev_re.captures(line) {
                current.10 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
            }

            // med.abs.dev
            if let Some(caps) = med_abs_dev_re.captures(line) {
                current.11 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                    unit: Some("us".to_string()),
                });
            }
        }
    }

    if current.is_some() {
        let r = current.take().expect("unreachable: is_some()");
        res.push(CriterionResult {
            name: r.0,
            samples: r.1.unwrap_or_default(),
            time_med: r.2.unwrap_or_default(),
            time: r.3.unwrap_or_default(),
            throughput: r.4,
            throughput_med: r.5,
            slope: r.6,
            mean: r.7,
            median: r.8,
            r_2: r.9,
            std_dev: r.10,
            med_abs_dev: r.11,
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
        "ps" => ts / 1_000_000.,
        "ns" => ts / 1000.,
        "us" => ts,
        "ms" => ts * 1000.,
        "s" => ts * 1000. * 1000.,
        _ => panic!("unknown unit: {}", parts[1]),
    };

    (normalized * 10000.0).round() / 10000.0
}

fn run_benches(mut args: Vec<String>) -> Result<()> {
    let is_verbose = if let Some(index) = args.iter().position(|a| a.as_str() == "--verbose") {
        args.remove(index);
        true
    } else {
        false
    };

    let mut cmd = command!(
        r"
        cargo bench -p storage-proofs {args} -- --verbose --color never
    ",
        args = args
    )
    .map_err(|err| anyhow!("{:?}", err))?;

    let process = cmd.stdout(std::process::Stdio::piped()).spawn()?;

    let stdout = process.stdout.context("Failed to capture stdout")?;

    let reader = std::io::BufReader::new(stdout);
    let mut stdout = String::new();
    reader.lines().for_each(|line| {
        let line = line.expect("io (stdout) read error");
        if is_verbose {
            println!("{}", &line);
        }
        stdout += &line;
        stdout += "\n";
    });

    let parsed_results = parse_criterion_out(stdout)?;

    let wrapped = Metadata::wrap(parsed_results)?;

    serde_json::to_writer(io::stdout(), &wrapped).context("cannot write report-JSON to stdout")?;

    Ok(())
}

fn main() {
    let pass_through = std::env::args().skip(1).collect();

    match run_benches(pass_through) {
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
    #[allow(clippy::float_cmp)]
    fn test_time_to_us() {
        assert_eq!(time_to_us("123.12 us"), 123.12); // No math done on 'us' so strict float cmp is ok.
        assert_eq!(time_to_us("1.0 s"), 1_000_000.); // Multiplication, so strict float cmp is ok.
    }

    #[test]
    fn test_throughput_uom() {
        assert_eq!(throughput_to_uom("521.80 KiB/s"), "KiB/s");
        assert_eq!(throughput_to_uom("521.80 MiB/hr"), "MiB/hr");
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

        let parsed = parse_criterion_out(stdout).expect("failed to parse criterion output");
        assert_eq!(
            parsed,
            vec![CriterionResult {
                name: "merkletree/blake2s/128".into(),
                samples: 20,
                time_med: Point {
                    unit: Some("us".to_string()),
                    value: 151.42,
                },
                time: Interval {
                    start: 141.11,
                    end: 159.66,
                    unit: Some("us".to_string())
                },
                throughput: None,
                throughput_med: None,
                slope: Some(Interval {
                    start: 141.11,
                    end: 159.66,
                    unit: Some("us".to_string())
                }),
                mean: Some(Interval {
                    start: 140.55,
                    end: 150.62,
                    unit: Some("us".to_string())
                }),
                median: Some(Interval {
                    start: 138.33,
                    end: 143.23,
                    unit: Some("us".to_string())
                }),
                r_2: Some(Interval {
                    start: 0.812_491_4,
                    end: 0.832_015_4,
                    unit: None
                }),
                std_dev: Some(Interval {
                    start: 5.6028,
                    end: 15.213,
                    unit: Some("us".to_string())
                }),
                med_abs_dev: Some(Interval {
                    start: 1750.7,
                    end: 8410.9,
                    unit: Some("us".to_string())
                }),
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

        let parsed =
            parse_criterion_out(with_throughput).expect("failed to parse criterion output");
        assert_eq!(
            parsed,
            vec![CriterionResult {
                name: "merkletree/blake2s/128".into(),
                samples: 20,
                time_med: Point {
                    unit: Some("us".to_string()),
                    value: 151.42,
                },
                time: Interval {
                    start: 141.11,
                    end: 159.66,
                    unit: Some("us".to_string())
                },
                throughput: Some(Interval {
                    start: 68.055,
                    end: 68.644,
                    unit: Some("MiB/s".to_string())
                }),
                throughput_med: Some(Point {
                    value: 68.172,
                    unit: Some("MiB/s".to_string())
                }),
                slope: Some(Interval {
                    start: 141.11,
                    end: 159.66,
                    unit: Some("us".to_string())
                }),
                mean: Some(Interval {
                    start: 140.55,
                    end: 150.62,
                    unit: Some("us".to_string())
                }),
                median: Some(Interval {
                    start: 138.33,
                    end: 143.23,
                    unit: Some("us".to_string())
                }),
                r_2: Some(Interval {
                    start: 0.812_491_4,
                    end: 0.832_015_4,
                    unit: None
                }),
                std_dev: Some(Interval {
                    start: 5.6028,
                    end: 15.213,
                    unit: Some("us".to_string())
                }),
                med_abs_dev: Some(Interval {
                    start: 1750.7,
                    end: 8410.9,
                    unit: Some("us".to_string())
                }),
            }]
        );
    }
}
