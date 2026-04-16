//! donut-geo — v2fly/xray `.dat` parser + lookup.
//!
//! Reference format: `common/geodata/geodat.proto` in xray-core.
//! Messages: `GeoIPList { GeoIP { country_code, cidr[] } }`,
//! `GeoSiteList { GeoSite { country_code, domain[] } }`.
//!
//! Status: **M0 stub.** Implementation in M6.

#![forbid(unsafe_op_in_unsafe_fn)]
