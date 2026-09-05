#![no_main]

use std::{convert::Infallible, sync::OnceLock};

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{FromRequest, Multipart},
    http::{header::CONTENT_TYPE, HeaderValue, Request},
};
use futures_util::stream;
use libfuzzer_sys::fuzz_target;
use vaultlink::multipart_guard::{guard_multipart_request_with_limits, MultipartGuardLimits};

const MAX_FUZZ_BODY_BYTES: usize = 256 * 1024;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    })
}

fn request(raw: &[u8], content_type: &HeaderValue, chunk_size: usize) -> Request<Body> {
    let chunks: Vec<_> = raw
        .chunks(chunk_size)
        .map(|chunk| Ok::<_, Infallible>(Bytes::copy_from_slice(chunk)))
        .collect();
    Request::builder()
        .header(CONTENT_TYPE, content_type)
        .body(Body::from_stream(stream::iter(chunks)))
        .unwrap()
}

type ExtractedField = (String, Option<String>, Vec<u8>);

async fn extract(request: Request<Body>) -> Result<Vec<ExtractedField>, ()> {
    let mut multipart = Multipart::from_request(request, &())
        .await
        .map_err(|_| ())?;
    let mut fields = Vec::new();
    while let Some(mut field) = multipart.next_field().await.map_err(|_| ())? {
        let name = field.name().unwrap_or_default().to_owned();
        let filename = field.file_name().map(str::to_owned);
        let mut bytes = Vec::new();
        while let Some(chunk) = field.chunk().await.map_err(|_| ())? {
            bytes.extend_from_slice(&chunk);
        }
        fields.push((name, filename, bytes));
    }
    Ok(fields)
}

fuzz_target!(|input: &[u8]| {
    // Wire format for reproducible seeds: mode/flags, LE u16 preamble/header
    // limits, LE u32 EOF offset, chunk-size byte, boundary-length byte,
    // boundary bytes, then payload. Flag 0x80 truncates; 0x10 quotes boundaries.
    let control = |index: usize| input.get(index).copied().unwrap_or(0);
    let mode = control(0) & 7;
    let limits = MultipartGuardLimits {
        max_preamble_bytes: usize::from(u16::from_le_bytes([control(1), control(2)])),
        max_header_bytes: usize::from(u16::from_le_bytes([control(3), control(4)])),
    };
    let boundary_len = (1 + usize::from(control(10)) % 70).min(input.len().saturating_sub(11));
    let boundary_bytes = input.get(11..11 + boundary_len).unwrap_or_default();
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut boundary: String = boundary_bytes
        .iter()
        .map(|byte| char::from(alphabet[usize::from(*byte) % alphabet.len()]))
        .collect();
    if boundary.is_empty() {
        boundary.push('x');
    }
    let payload = input.get(11 + boundary_len..).unwrap_or_default();
    let payload = &payload[..payload.len().min(MAX_FUZZ_BODY_BYTES)];
    let content_type = if mode == 7 {
        // Exercise the actual Content-Type parser, including duplicate/quoted
        // parameters, invalid lengths, and escaped boundary values.
        let Ok(value) = HeaderValue::from_bytes(payload) else {
            return;
        };
        value
    } else if control(0) & 0x10 != 0 {
        HeaderValue::from_str(&format!(
            "multipart/form-data; boundary=\"{boundary}\"; charset=utf-8"
        ))
        .unwrap()
    } else {
        HeaderValue::from_str(&format!("multipart/form-data; boundary={boundary}")).unwrap()
    };

    let header = b"Content-Disposition: form-data; name=\"file\"; filename=\"fuzz.bin\"";
    let mut raw = Vec::new();
    let mut expected_fields = Vec::new();
    let mut expected_success = None;
    let mut closing_end = 0usize;
    match mode {
        0 => raw.extend_from_slice(payload),
        2 => {
            raw.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            raw.extend_from_slice(payload);
            raw.extend_from_slice(format!("\r\n\r\nbody\r\n--{boundary}--\r\n").as_bytes());
        }
        3 => {
            raw.extend_from_slice(payload);
            raw.extend_from_slice(
                format!("\r\n--{boundary}\r\nX: y\r\n\r\nbody\r\n--{boundary}--\r\n").as_bytes(),
            );
        }
        7 => raw.extend_from_slice(b"--x--\r\n"),
        _ => {
            // Structured cases cannot contain an accidental body boundary, so
            // acceptance and extracted bytes have an independent exact oracle.
            let data: Vec<_> = payload
                .iter()
                .map(|byte| if *byte == b'\r' { b'~' } else { *byte })
                .collect();
            let preamble_len = if mode == 5 {
                limits
                    .max_preamble_bytes
                    .saturating_add(usize::from(control(0) & 8 != 0))
            } else {
                0
            };
            if preamble_len != 0 {
                raw.resize(preamble_len, b'p');
                raw.extend_from_slice(b"\r\n");
            }
            raw.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            if mode == 6 {
                let path_header = b"Content-Disposition: form-data; name=\"path\"";
                raw.extend_from_slice(path_header);
                raw.extend_from_slice(format!("\r\n\r\ndocs\r\n--{boundary}\r\n").as_bytes());
                expected_fields.push(("path".into(), None, b"docs".to_vec()));
            }
            raw.extend_from_slice(header);
            let mut header_len = header.len();
            if mode == 4 {
                raw.extend_from_slice(b"\r\nX-Pad: ");
                header_len += 9;
                let desired = limits
                    .max_header_bytes
                    .saturating_add(usize::from(control(0) & 8 != 0));
                let padding = desired.saturating_sub(header_len);
                raw.resize(raw.len() + padding, b'h');
                header_len += padding;
            }
            raw.extend_from_slice(b"\r\n\r\n");
            raw.extend_from_slice(&data);
            raw.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
            closing_end = raw.len();
            raw.extend_from_slice(b"\r\n");
            expected_fields.push(("file".into(), Some("fuzz.bin".into()), data));
            expected_success = Some(
                preamble_len <= limits.max_preamble_bytes && header_len <= limits.max_header_bytes,
            );
        }
    }
    if control(0) & 0x80 != 0 {
        let eof = u32::from_le_bytes([control(5), control(6), control(7), control(8)]) as usize;
        raw.truncate(eof % (raw.len() + 1));
        expected_success = expected_success.map(|valid| valid && raw.len() >= closing_end);
    }

    runtime().block_on(async {
        // Compare coalesced input with transport chunking. Error results are
        // intentionally compared as classifications, not chunk-dependent text.
        let mut previous = None;
        for chunk_size in [raw.len().max(1), 1 + usize::from(control(9))] {
            let guarded = guard_multipart_request_with_limits(
                request(&raw, &content_type, chunk_size),
                limits,
            );
            let guarded = match guarded {
                Ok(request) => request,
                Err(_) => {
                    assert_eq!(mode, 7, "generated Content-Type is valid");
                    return;
                }
            };
            let drained = to_bytes(guarded.into_body(), raw.len() + 1).await;
            if let Some(expected) = expected_success {
                assert_eq!(drained.is_ok(), expected);
            }
            if let Ok(bytes) = &drained {
                assert_eq!(bytes.as_ref(), raw);
            }
            let parsed = extract(
                guard_multipart_request_with_limits(
                    request(&raw, &content_type, chunk_size),
                    limits,
                )
                .unwrap(),
            )
            .await;
            if expected_success == Some(true) {
                assert_eq!(parsed.as_ref(), Ok(&expected_fields));
            }
            let outcome = (drained.is_ok(), parsed);
            if let Some(previous) = &previous {
                assert_eq!(
                    &outcome, previous,
                    "chunking must preserve guard and extractor semantics"
                );
            }
            previous = Some(outcome);
        }
    });
});
