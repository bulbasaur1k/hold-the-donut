//! donut-core — shared domain vocabulary.
//!
//! Pure types + error enum. No runtime, no frameworks. Consumed by every
//! other crate in the workspace.

#![forbid(unsafe_op_in_unsafe_fn)]

mod address;
mod error;
mod id;
mod kinds;

pub use address::{Address, AddressParseError, Endpoint};
pub use error::{CoreError, CoreResult};
pub use id::{ShortId, ShortIdParseError, UserAuth, UserId};
pub use kinds::{Command, FlowKind, TlsKind, TransportKind};
