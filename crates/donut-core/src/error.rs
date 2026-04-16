use thiserror::Error;

use crate::address::AddressParseError;
use crate::id::ShortIdParseError;

/// Top-level error shared across the workspace.
///
/// Crate-local errors convert into this via `#[from]`.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("address: {0}")]
    Address(#[from] AddressParseError),

    #[error("short id: {0}")]
    ShortId(#[from] ShortIdParseError),

    #[error("protocol: {0}")]
    Protocol(&'static str),

    #[error("config: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

pub type CoreResult<T> = Result<T, CoreError>;
