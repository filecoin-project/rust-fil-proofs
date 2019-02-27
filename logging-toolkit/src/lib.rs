#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_json;
extern crate slog_term;

use slog::Drain;
use slog::FnValue;
use slog::Level;
use slog::LevelFilter;
use slog::Logger;
use std::env;

pub fn make_logger(
    root_name: &'static str,
    use_json_env_name: &str,
    min_log_level_env_name: &str,
) -> Logger {
    let drain = match env::var(use_json_env_name).as_ref().map(String::as_str) {
        Ok("true") => {
            let json_drain = slog_json::Json::new(std::io::stdout())
                .add_default_keys()
                .build()
                .fuse();

            slog_async::Async::new(json_drain).build().fuse()
        }
        _ => {
            let term_decorator = slog_term::TermDecorator::new().build();
            let term_drain = slog_term::FullFormat::new(term_decorator).build().fuse();

            slog_async::Async::new(term_drain).build().fuse()
        }
    };

    let min_log_level = match env::var(min_log_level_env_name) {
        Ok(val) => match val.parse::<u64>() {
            Ok(parsed) => match Level::from_usize(parsed as usize) {
                Some(level) => level,
                None => Level::Info,
            },
            _ => Level::Info,
        },
        _ => Level::Info,
    };

    let with_filter = LevelFilter::new(drain, min_log_level).map(slog::Fuse);

    Logger::root(
        with_filter,
        o!("root" => root_name, "place" => FnValue(move |info| {
            format!("{}:{} {}",
                    info.file(),
                    info.line(),
                    info.module(),
                    )
        })),
    )
}
