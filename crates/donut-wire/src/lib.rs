//! donut-wire — inner-frame codec (byte-exact).
//!
//! Encode/decode of the minimal request/response header carried inside
//! the outer tunnel. See `docs/PROTOCOLS.md` § 1 for the frozen byte
//! spec.
//!
//! # Example
//!
//! ```
//! use bytes::BytesMut;
//! use donut_core::{Address, Command, Endpoint, FlowKind, UserId};
//! use donut_wire::Request;
//!
//! let req = Request {
//!     user: UserId::new_v4(),
//!     flow: FlowKind::None,
//!     command: Command::Tcp,
//!     target: Some(Endpoint::new(
//!         Address::ipv4("1.2.3.4".parse().unwrap()),
//!         443,
//!     )),
//!     seed: Vec::new(),
//! };
//!
//! let mut buf = BytesMut::with_capacity(req.encoded_len());
//! req.encode(&mut buf);
//! let mut frozen = buf.freeze();
//! let parsed = Request::decode(&mut frozen).unwrap();
//! assert_eq!(parsed, req);
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]

mod addons;
mod error;
mod request;
mod vision;

pub use addons::Addons;
pub use error::WireError;
pub use request::{Request, Response};
pub use vision::{
    VisionPadder, VisionUnpadder, CMD_PADDING_CONTINUE, CMD_PADDING_DIRECT, CMD_PADDING_END,
    MAX_CONTENT,
};
