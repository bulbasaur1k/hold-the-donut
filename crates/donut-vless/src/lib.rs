//! donut-vless — VLESS header encode / decode (byte-exact).
//!
//! Wire format (client → server request header):
//!
//! ```text
//! offset  size   field
//! 0       1      version (constant 0x00)
//! 1       16     UUID (binary)
//! 17      1      addon length L (u8)
//! 18      L      addons: protobuf Addons { flow: string, seed: bytes }
//! 18+L    1      command (1=TCP, 2=UDP, 3=Mux)
//! 19+L    2      port (BE u16)              # omitted for Mux
//! 21+L    1      addr type (1=IPv4, 2=Domain-len-prefixed, 3=IPv6)
//! 22+L    N      addr bytes (4 / 1+len / 16)
//! ...            payload
//! ```
//!
//! Flow constants accepted (xray-core v26.4.15):
//! * `""` / `"none"` — no flow.
//! * `"xtls-rprx-vision"` — Vision. Only valid with raw TCP+REALITY;
//!   rejected when transport is XHTTP (issue XTLS/Xray-core#5576).
//!
//! Status: **M0 stub.** Implementation in M1.

#![forbid(unsafe_op_in_unsafe_fn)]
