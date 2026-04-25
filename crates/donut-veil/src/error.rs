use thiserror::Error;

#[derive(Debug, Error)]
pub enum VeilError {
    #[error("private key must be 32 bytes")]
    BadPrivateKey,

    #[error("public key must be 32 bytes")]
    BadPublicKey,

    #[error("at least one short id is required on the server")]
    EmptyShortIds,

    #[error("ClientHello shorter than the legacy SessionID at offset 39")]
    ShortClientHello,

    #[error("session id length on the wire is not 32 bytes")]
    BadSessionIdLength,

    #[error("client hello has no key_share extension")]
    MissingKeyShare,

    #[error("no X25519 share in key_share extension")]
    NoX25519Share,

    #[error("AEAD authentication failed: not a veiled client")]
    AuthFailed,

    #[error("decoded short id is not in the configured set")]
    UnknownShortId,
}
