#![no_main]

use std::{convert::Infallible, sync::OnceLock};

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{header::CONTENT_TYPE, Request},
};
use futures_util::stream;
use libfuzzer_sys::fuzz_target;
use vaultlink::multipart_guard::{guard_multipart_request_with_limits, MultipartGuardLimits};

const BOUNDARY: &str = "vaultlink-fuzz-boundary";
const MAX_FUZZ_BODY_BYTES: usize = 256 * 1024;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("fuzz runtime")
    })
}

fuzz_target!(|input: &[u8]| {
    let control = |index: usize, default: u8| input.get(index).copied().unwrap_or(default);

    let payload = input.get(5..).unwrap_or_default();
    let payload = &payload[..payload.len().min(MAX_FUZZ_BODY_BYTES)];
    let mut raw = Vec::with_capacity(payload.len().saturating_add(192));
    match control(0, 1) % 4 {
        // Fully arbitrary input exercises missing/opening boundaries and malformed EOF.
        0 => raw.extend_from_slice(payload),
        // Arbitrary file data inside a valid multipart envelope reaches body scanning.
        1 => {
            raw.extend_from_slice(format!("--{BOUNDARY}\r\nX-Fuzz: value\r\n\r\n").as_bytes());
            raw.extend_from_slice(payload);
            raw.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
        }
        // Arbitrary header bytes exercise exact and over-limit header termination.
        2 => {
            raw.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
            raw.extend_from_slice(payload);
            raw.extend_from_slice(format!("\r\n\r\nbody\r\n--{BOUNDARY}--\r\n").as_bytes());
        }
        // Arbitrary preamble bytes exercise the opening-boundary search and limit.
        _ => {
            raw.extend_from_slice(payload);
            raw.extend_from_slice(
                format!("--{BOUNDARY}\r\nX: y\r\n\r\nbody\r\n--{BOUNDARY}--\r\n").as_bytes(),
            );
        }
    }

    // Odd values simulate transport EOF at an arbitrary byte; even values drain
    // the complete request. This reaches every scanner finish-state.
    if control(3, 0) & 1 == 1 && !raw.is_empty() {
        raw.truncate(usize::from(control(4, 0)) % (raw.len() + 1));
    }

    // Preserve transport chunking rather than coalescing the generated body.
    // Mutating the control bytes yields one-byte chunks as well as boundary and
    // header splits at many offsets.
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    let mut chunk_control = 0usize;
    while offset < raw.len() {
        let chunk_len = 1 + usize::from(input.get(chunk_control % 5).copied().unwrap_or(0)) % 31;
        let end = offset.saturating_add(chunk_len).min(raw.len());
        chunks.push(Ok::<_, Infallible>(Bytes::copy_from_slice(
            &raw[offset..end],
        )));
        offset = end;
        chunk_control += 1;
    }

    let request = Request::builder()
        .header(
            CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from_stream(stream::iter(chunks)))
        .expect("static request is valid");
    let guarded = guard_multipart_request_with_limits(
        request,
        MultipartGuardLimits {
            max_preamble_bytes: usize::from(control(1, 64)),
            max_header_bytes: usize::from(control(2, 64)),
        },
    )
    .expect("static multipart Content-Type is valid");

    let body_limit = raw.len().saturating_add(1);
    let _ = runtime().block_on(to_bytes(guarded.into_body(), body_limit));
});
