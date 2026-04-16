#![no_main]

use bytes::{Bytes, BytesMut};
use donut_wire::Request;
use libfuzzer_sys::fuzz_target;

// Differential fuzz: any request that decodes successfully must
// re-encode to a byte sequence that decodes back to an equal value.
fuzz_target!(|data: &[u8]| {
    let mut cursor = Bytes::copy_from_slice(data);
    let Ok(req) = Request::decode(&mut cursor) else {
        return;
    };

    let mut out = BytesMut::with_capacity(req.encoded_len());
    req.encode(&mut out);
    assert_eq!(
        out.len(),
        req.encoded_len(),
        "encoded_len must match actual encoded size",
    );

    let mut back = out.freeze();
    let round = Request::decode(&mut back).expect("self-encoded must decode");
    assert_eq!(req, round);
    assert_eq!(back.len(), 0, "decoder must consume exactly the header");
});
