#![no_main]

use bytes::Bytes;
use donut_wire::Request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = Bytes::copy_from_slice(data);
    // Must never panic on arbitrary input; only return errors.
    let _ = Request::decode(&mut buf);
});
