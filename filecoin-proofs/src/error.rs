use failure::{Backtrace, Error};

pub type Result<T> = std::result::Result<T, Error>;

pub trait ExpectWithBacktrace<T> {
    fn expects(self, msg: &str) -> T;
}

impl<T, E: std::fmt::Debug> ExpectWithBacktrace<T> for ::std::result::Result<T, E> {
    fn expects(self, msg: &str) -> T {
        if let Err(ref err) = self {
            let err = format!("{:?}", err);
            let backtrace = format!("{:?}", Backtrace::new());
            error!("expected Result to be Ok: {} - {}", err, backtrace);
        }
        self.expect(msg)
    }
}

impl<T> ExpectWithBacktrace<T> for Option<T> {
    fn expects(self, msg: &str) -> T {
        if self.is_none() {
            let backtrace = format!("{:?}", Backtrace::new());
            error!("expected Option to be Some: {}", backtrace);
        }
        self.expect(msg)
    }
}
