use crate::FCP_LOG;
use failure::{Backtrace, Error};
use slog::*;

pub type Result<T> = ::std::result::Result<T, Error>;

pub trait ErrorLogResult<T> {
    fn expect_with_logging(self, msg: &str) -> T;
}

impl<T, E: std::fmt::Debug> ErrorLogResult<T> for ::std::result::Result<T, E> {
    fn expect_with_logging(self, msg: &str) -> T {
        if let Err(ref err) = self {
            let err = format!("{:?}", err);
            let backtrace = format!("{:?}", Backtrace::new());
            error!(FCP_LOG, "expected Result to be Ok"; "error" => err, "backtrace" => backtrace);
        }
        self.expect(msg)
    }
}

impl<T> ErrorLogResult<T> for Option<T> {
    fn expect_with_logging(self, msg: &str) -> T {
        if self.is_none() {
            let backtrace = format!("{:?}", Backtrace::new());
            error!(FCP_LOG, "expected Option to be Some"; "backtrace" => backtrace);
        }
        self.expect(msg)
    }
}
