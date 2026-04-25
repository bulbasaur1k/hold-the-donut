use thiserror::Error;

#[derive(Debug, Error)]
pub enum CarrierError {
    #[error("invalid session id on the wire")]
    InvalidSessionId,

    #[error("missing session id binding (placement={0:?})")]
    MissingSessionId(crate::Placement),

    #[error("invalid sequence number")]
    InvalidSequence,

    #[error("missing sequence number binding")]
    MissingSequence,

    #[error("upload chunk exceeds sc_max_each_post_bytes")]
    UploadChunkTooLarge,

    #[error("buffered uplink window is full (sc_max_buffered_posts)")]
    UploadWindowFull,

    #[error("path does not match configured prefix")]
    BadPath,

    #[error("hyper: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("http: {0}")]
    Http(#[from] http::Error),

    #[error("address parse: {0}")]
    Uri(#[from] http::uri::InvalidUri),
}
