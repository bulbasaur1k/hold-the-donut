use std::sync::Arc;
use std::time::Duration;

use ahash::AHashSet;
use donut_core::ShortId;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::VeilError;
use crate::fingerprint::Fingerprint;

/// Default anti-replay clock-skew tolerance. A ClientHello whose stamped
/// timestamp differs from the server clock by more than this is treated as
/// a replay/forgery and forwarded to the decoy. Wide enough to absorb
/// real client clock drift, narrow enough to bound a capture-replay window.
pub const DEFAULT_MAX_TIME_SKEW: Duration = Duration::from_secs(120);

/// Server-side static configuration for the veiled-TLS handshake.
#[derive(Clone)]
pub struct VeilServerConfig {
    pub(crate) private: Arc<Zeroizing<StaticSecret>>,
    pub(crate) public: PublicKey,
    pub(crate) short_ids: Arc<AHashSet<ShortId>>,
    /// Anti-replay clock-skew window. `Some(d)` rejects (forwards) any
    /// ClientHello whose sealed unix timestamp is more than `d` away from
    /// the server clock; `None` disables the check entirely.
    pub(crate) max_time_skew: Option<Duration>,
}

impl VeilServerConfig {
    /// Build a server config from a 32-byte X25519 private key and at
    /// least one configured short id. Anti-replay defaults to
    /// [`DEFAULT_MAX_TIME_SKEW`]; override with [`with_max_time_skew`].
    ///
    /// [`with_max_time_skew`]: Self::with_max_time_skew
    pub fn new(
        private_key: [u8; 32],
        short_ids: impl IntoIterator<Item = ShortId>,
    ) -> Result<Self, VeilError> {
        let private = StaticSecret::from(private_key);
        let public = PublicKey::from(&private);
        let short_ids: AHashSet<ShortId> = short_ids.into_iter().collect();
        if short_ids.is_empty() {
            return Err(VeilError::EmptyShortIds);
        }
        Ok(Self {
            private: Arc::new(Zeroizing::new(private)),
            public,
            short_ids: Arc::new(short_ids),
            max_time_skew: Some(DEFAULT_MAX_TIME_SKEW),
        })
    }

    /// Set the anti-replay clock-skew tolerance. `None` disables the
    /// timestamp check (e.g. for replaying a fixed test vector).
    pub fn with_max_time_skew(mut self, skew: Option<Duration>) -> Self {
        self.max_time_skew = skew;
        self
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}

/// Client-side static configuration for the veiled-TLS handshake.
#[derive(Clone)]
pub struct VeilClientConfig {
    pub(crate) server_pub: PublicKey,
    pub(crate) short_id: ShortId,
    pub(crate) version: [u8; 3],
    pub(crate) fingerprint: Fingerprint,
}

impl VeilClientConfig {
    /// Build a client config. `version` is a 3-byte tag the client
    /// stamps into the sealed plaintext; we mirror upstream's
    /// `version_x.version_y.version_z` for wire compatibility.
    ///
    /// The ClientHello fingerprint defaults to [`Fingerprint::Native`];
    /// use [`with_fingerprint`](Self::with_fingerprint) to enable
    /// uTLS-style randomization.
    pub fn new(server_public_key: [u8; 32], short_id: ShortId, version: [u8; 3]) -> Self {
        Self {
            server_pub: PublicKey::from(server_public_key),
            short_id,
            version,
            fingerprint: Fingerprint::default(),
        }
    }

    /// Select the TLS ClientHello fingerprint the client mimics
    /// (e.g. [`Fingerprint::Randomized`]). See [`crate::Fingerprint`].
    pub fn with_fingerprint(mut self, fingerprint: Fingerprint) -> Self {
        self.fingerprint = fingerprint;
        self
    }
}
