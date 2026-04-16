#![no_main]

use bytes::Bytes;
use donut_wire::Response;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = Bytes::copy_from_slice(data);
    let _ = Response::decode(&mut buf);
});
