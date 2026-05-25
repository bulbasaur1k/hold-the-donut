//! Pull a [`SessionId`] (and, for `packet-up`, a sequence number) out
//! of a hyper request according to the configured [`Placement`].

use hyper::Request;

use crate::config::ServerConfig;
use crate::error::CarrierError;
use crate::placement::Placement;
use crate::session::SessionId;

/// Returns the session id for `req` and the relative path-tail (the
/// portion after the configured prefix and after the path-encoded
/// session id, if any).
pub(super) fn session_id<B>(
    req: &Request<B>,
    config: &ServerConfig,
) -> Result<(SessionId, String), CarrierError> {
    let path = req.uri().path();
    if !path.starts_with(&config.path_prefix) {
        return Err(CarrierError::BadPath);
    }
    let after_prefix = &path[config.path_prefix.len()..];

    match config.session_placement {
        Placement::Path => {
            // Tolerate a leading slash between the prefix and the session
            // id: clients append "/<hex>" to the prefix, so whether the
            // configured prefix ends with a slash or not, the hex segment
            // is the same. (Without this, a prefix like "/store/sync"
            // leaves "/<hex>" and the first segment parses as empty.)
            let rest = after_prefix.strip_prefix('/').unwrap_or(after_prefix);
            // First path segment after the prefix is the hex session id.
            let (segment, tail) = match rest.find('/') {
                Some(slash) => (&rest[..slash], &rest[slash..]),
                None => (rest, ""),
            };
            let sid: SessionId = segment.parse()?;
            Ok((sid, tail.to_string()))
        }
        Placement::Query => {
            let q = req.uri().query().unwrap_or_default();
            let val = query_value(q, &config.session_key)
                .ok_or(CarrierError::MissingSessionId(Placement::Query))?;
            let sid: SessionId = val.parse()?;
            Ok((sid, after_prefix.to_string()))
        }
        Placement::Header => {
            let val = req
                .headers()
                .get(&config.session_header)
                .and_then(|v| v.to_str().ok())
                .ok_or(CarrierError::MissingSessionId(Placement::Header))?;
            let sid: SessionId = val.parse()?;
            Ok((sid, after_prefix.to_string()))
        }
        Placement::Cookie => {
            let cookies = req
                .headers()
                .get_all(http::header::COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok());
            let val = cookies
                .flat_map(|s| s.split(';').map(str::trim))
                .find_map(|kv| {
                    let (k, v) = kv.split_once('=')?;
                    (k == config.session_key).then_some(v)
                })
                .ok_or(CarrierError::MissingSessionId(Placement::Cookie))?;
            let sid: SessionId = val.parse()?;
            Ok((sid, after_prefix.to_string()))
        }
    }
}

pub(super) fn sequence<B>(req: &Request<B>, config: &ServerConfig) -> Result<u64, CarrierError> {
    match config.seq_placement {
        Placement::Header => {
            let s = req
                .headers()
                .get(&config.seq_header)
                .and_then(|v| v.to_str().ok())
                .ok_or(CarrierError::MissingSequence)?;
            s.parse::<u64>().map_err(|_| CarrierError::InvalidSequence)
        }
        Placement::Query => {
            let q = req.uri().query().unwrap_or_default();
            let val = query_value(q, "x_seq").ok_or(CarrierError::MissingSequence)?;
            val.parse::<u64>()
                .map_err(|_| CarrierError::InvalidSequence)
        }
        Placement::Path => {
            // Last path segment.
            let path = req.uri().path();
            let last = path
                .rsplit('/')
                .find(|s| !s.is_empty())
                .ok_or(CarrierError::MissingSequence)?;
            last.parse::<u64>()
                .map_err(|_| CarrierError::InvalidSequence)
        }
        Placement::Cookie => {
            let cookies = req
                .headers()
                .get_all(http::header::COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok());
            let val = cookies
                .flat_map(|s| s.split(';').map(str::trim))
                .find_map(|kv| {
                    let (k, v) = kv.split_once('=')?;
                    (k == "x_seq").then_some(v)
                })
                .ok_or(CarrierError::MissingSequence)?;
            val.parse::<u64>()
                .map_err(|_| CarrierError::InvalidSequence)
        }
    }
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}
