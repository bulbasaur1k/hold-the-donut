use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("unexpected version byte {0:#04x}, expected 0x00")]
    BadVersion(u8),

    #[error("truncated frame: wanted {want} bytes, had {have}")]
    Truncated { want: usize, have: usize },

    #[error("unknown command byte {0:#04x}")]
    UnknownCommand(u8),

    #[error("unknown address type {0:#04x}")]
    UnknownAddressType(u8),

    #[error("domain name has zero length")]
    ZeroDomain,

    #[error("domain name is not valid UTF-8")]
    InvalidDomainUtf8,

    #[error("addon length {addon_len} exceeds u8::MAX")]
    AddonTooLarge { addon_len: usize },

    #[error("unknown flow identifier")]
    UnknownFlow,

    #[error("malformed protobuf in addons segment")]
    BadAddonsProto,

    #[error("varint exceeds 10 bytes")]
    VarintOverflow,
}
