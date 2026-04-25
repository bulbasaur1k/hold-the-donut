use thiserror::Error;

#[derive(Debug, Error)]
pub enum QuicError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid certificate: {0}")]
    Cert(String),

    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("quinn endpoint: {0}")]
    Endpoint(String),

    #[error("quinn connect: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("quinn connection: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("h3 connection: {0}")]
    H3Conn(String),

    #[error("h3 stream: {0}")]
    H3Stream(String),

    #[error("session id missing or malformed")]
    BadSessionId,

    #[error("upstream returned http status {0}")]
    BadStatus(http::StatusCode),
}
