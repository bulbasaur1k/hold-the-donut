//! donut-geo — `.dat` parser + lookup for the v2fly-compatible
//! geodata format (both geoip.dat and geosite.dat).
//!
//! Reference schema: `common/geodata/geodat.proto` from the upstream
//! project. Messages: `GeoIPList { GeoIP { country_code, cidr[] } }`,
//! `GeoSiteList { GeoSite { country_code, domain[] } }`.
//!
//! Status: **M0 stub.** Implementation in M6.

#![forbid(unsafe_op_in_unsafe_fn)]
