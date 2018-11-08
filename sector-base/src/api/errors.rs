#[derive(Debug, Fail)]
pub enum SectorManagerErr {
    #[fail(display = "unclassified error: {}", _0)]
    UnclassifiedError(String),

    #[fail(display = "caller error: {}", _0)]
    CallerError(String),

    #[fail(display = "receiver error: {}", _0)]
    ReceiverError(String),
}
