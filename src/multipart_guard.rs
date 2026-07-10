//! Streaming limits for the parts of a multipart request that `multer` buffers.
//!
//! File contents are inspected in-place and are never retained by this guard. The
//! scanner only keeps KMP offsets and counters, so its memory use is bounded by the
//! multipart boundary length regardless of the upload size.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use axum::body::{Body, BodyDataStream, Bytes};
use futures_util::Stream;
use http::{header::CONTENT_TYPE, Request, StatusCode};
use thiserror::Error;

pub const DEFAULT_MAX_PREAMBLE_BYTES: usize = 8 * 1024;
pub const DEFAULT_MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BOUNDARY_BYTES: usize = 70;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultipartGuardLimits {
    pub max_preamble_bytes: usize,
    pub max_header_bytes: usize,
}

impl Default for MultipartGuardLimits {
    fn default() -> Self {
        Self {
            max_preamble_bytes: DEFAULT_MAX_PREAMBLE_BYTES,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MultipartGuardError {
    #[error("missing Content-Type header")]
    MissingContentType,
    #[error("Content-Type must be multipart/form-data")]
    UnsupportedContentType,
    #[error("multipart Content-Type is missing its boundary parameter")]
    MissingBoundary,
    #[error("invalid multipart Content-Type")]
    InvalidContentType,
    #[error("invalid multipart boundary")]
    InvalidBoundary,
}

impl MultipartGuardError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingContentType | Self::UnsupportedContentType => {
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            }
            Self::MissingBoundary | Self::InvalidContentType | Self::InvalidBoundary => {
                StatusCode::BAD_REQUEST
            }
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MultipartGuardBodyError {
    #[error("multipart preamble exceeds the configured limit")]
    PreambleTooLarge,
    #[error("multipart header block exceeds the configured limit")]
    HeaderTooLarge,
    #[error("multipart body is missing its opening boundary")]
    MissingOpeningBoundary,
    #[error("multipart body ended inside a header block")]
    IncompleteHeaderBlock,
    #[error("multipart boundary line is invalid")]
    InvalidBoundaryLine,
    #[error("multipart body ended inside a boundary line")]
    IncompleteBoundaryLine,
    #[error("multipart boundary padding exceeds the configured limit")]
    BoundaryPaddingTooLarge,
    #[error("multipart body is missing its closing boundary")]
    MissingClosingBoundary,
}

/// Validates the multipart `Content-Type` and wraps the request body in a
/// constant-memory scanner using the default limits.
///
/// This function is synchronous and can be called directly from Axum
/// middleware before `Multipart` extraction. Initial header errors are returned
/// here; streaming violations surface as body errors to the extractor.
pub fn guard_multipart_request(
    request: Request<Body>,
) -> Result<Request<Body>, MultipartGuardError> {
    guard_multipart_request_with_limits(request, MultipartGuardLimits::default())
}

/// Like [`guard_multipart_request`], with caller-supplied limits.
pub fn guard_multipart_request_with_limits(
    request: Request<Body>,
    limits: MultipartGuardLimits,
) -> Result<Request<Body>, MultipartGuardError> {
    let boundary = boundary_from_headers(&request)?;
    let (parts, body) = request.into_parts();
    let guarded = GuardedMultipartStream {
        inner: Box::pin(body.into_data_stream()),
        scanner: MultipartScanner::new(&boundary, limits),
        terminal: false,
    };
    Ok(Request::from_parts(parts, Body::from_stream(guarded)))
}

fn boundary_from_headers(request: &Request<Body>) -> Result<Vec<u8>, MultipartGuardError> {
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .ok_or(MultipartGuardError::MissingContentType)?
        .to_str()
        .map_err(|_| MultipartGuardError::InvalidContentType)?;
    parse_boundary(content_type)
}

fn parse_boundary(content_type: &str) -> Result<Vec<u8>, MultipartGuardError> {
    if !content_type.is_ascii() {
        return Err(MultipartGuardError::InvalidContentType);
    }

    let parameters = split_content_type(content_type)?;
    let Some((media_type, rest)) = parameters.split_first() else {
        return Err(MultipartGuardError::InvalidContentType);
    };
    if !media_type
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return Err(MultipartGuardError::UnsupportedContentType);
    }

    let mut boundary = None;
    for parameter in rest {
        let (name, raw_value) = parameter
            .split_once('=')
            .ok_or(MultipartGuardError::InvalidContentType)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(MultipartGuardError::InvalidContentType);
        }
        if name.eq_ignore_ascii_case("boundary") {
            if boundary.is_some() {
                return Err(MultipartGuardError::InvalidContentType);
            }
            boundary = Some(parse_parameter_value(raw_value.trim())?);
        }
    }

    let (boundary, quoted) = boundary.ok_or(MultipartGuardError::MissingBoundary)?;
    validate_boundary(&boundary, quoted)?;
    Ok(boundary)
}

fn split_content_type(value: &str) -> Result<Vec<&str>, MultipartGuardError> {
    let mut sections = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;

    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b';' if !quoted => {
                sections.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || escaped {
        return Err(MultipartGuardError::InvalidContentType);
    }
    sections.push(&value[start..]);
    if sections.iter().any(|section| section.trim().is_empty()) {
        return Err(MultipartGuardError::InvalidContentType);
    }
    Ok(sections)
}

fn parse_parameter_value(value: &str) -> Result<(Vec<u8>, bool), MultipartGuardError> {
    if let Some(quoted) = value.strip_prefix('"') {
        let quoted = quoted
            .strip_suffix('"')
            .ok_or(MultipartGuardError::InvalidContentType)?;
        let mut decoded = Vec::with_capacity(quoted.len());
        let mut escaped = false;
        for byte in quoted.bytes() {
            if escaped {
                decoded.push(byte);
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return Err(MultipartGuardError::InvalidContentType);
            } else {
                decoded.push(byte);
            }
        }
        if escaped {
            return Err(MultipartGuardError::InvalidContentType);
        }
        Ok((decoded, true))
    } else {
        if value.contains('"') || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(MultipartGuardError::InvalidContentType);
        }
        Ok((value.as_bytes().to_vec(), false))
    }
}

fn validate_boundary(boundary: &[u8], quoted: bool) -> Result<(), MultipartGuardError> {
    if boundary.is_empty() || boundary.len() > MAX_BOUNDARY_BYTES {
        return Err(MultipartGuardError::InvalidBoundary);
    }
    if boundary.last() == Some(&b' ') {
        return Err(MultipartGuardError::InvalidBoundary);
    }
    if boundary.iter().any(|byte| {
        !(matches!(
            byte,
            b'0'..=b'9'
                | b'A'..=b'Z'
                | b'a'..=b'z'
                | b'\''
                | b'('
                | b')'
                | b'+'
                | b'_'
                | b','
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b'?'
        ) || quoted && *byte == b' ')
    }) {
        return Err(MultipartGuardError::InvalidBoundary);
    }
    Ok(())
}

#[derive(Debug)]
struct GuardedMultipartStream {
    inner: Pin<Box<BodyDataStream>>,
    scanner: MultipartScanner,
    terminal: bool,
}

impl Stream for GuardedMultipartStream {
    type Item = Result<Bytes, GuardedBodyError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.terminal {
            return Poll::Ready(None);
        }
        match self.inner.as_mut().poll_next(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(bytes))) => match self.scanner.scan(&bytes) {
                Ok(()) => Poll::Ready(Some(Ok(bytes))),
                Err(error) => {
                    self.terminal = true;
                    Poll::Ready(Some(Err(GuardedBodyError::Violation(error))))
                }
            },
            Poll::Ready(Some(Err(error))) => {
                self.terminal = true;
                Poll::Ready(Some(Err(GuardedBodyError::Source(error))))
            }
            Poll::Ready(None) => match self.scanner.finish() {
                Ok(()) => {
                    self.terminal = true;
                    Poll::Ready(None)
                }
                Err(error) => {
                    self.terminal = true;
                    Poll::Ready(Some(Err(GuardedBodyError::Violation(error))))
                }
            },
        }
    }
}

#[derive(Debug, Error)]
enum GuardedBodyError {
    #[error("request body error: {0}")]
    Source(#[source] axum::Error),
    #[error(transparent)]
    Violation(#[from] MultipartGuardBodyError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScannerPhase {
    Preamble,
    BoundarySuffix,
    Headers,
    Body,
    Epilogue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundarySuffixPhase {
    First,
    ClosingHyphen,
    Padding,
    LineFeed,
}

#[derive(Debug)]
struct MultipartScanner {
    phase: ScannerPhase,
    limits: MultipartGuardLimits,
    preamble_seen: usize,
    header_seen: usize,
    boundary_padding_seen: usize,
    boundary_suffix_phase: BoundarySuffixPhase,
    initial_boundary: ByteMatcher,
    body_boundary: ByteMatcher,
    header_end: ByteMatcher,
}

impl MultipartScanner {
    fn new(boundary: &[u8], limits: MultipartGuardLimits) -> Self {
        let initial = [b"--".as_slice(), boundary].concat();
        let body = [b"\r\n--".as_slice(), boundary].concat();
        Self {
            phase: ScannerPhase::Preamble,
            limits,
            preamble_seen: 0,
            header_seen: 0,
            boundary_padding_seen: 0,
            boundary_suffix_phase: BoundarySuffixPhase::First,
            initial_boundary: ByteMatcher::new(initial),
            body_boundary: ByteMatcher::new(body),
            header_end: ByteMatcher::new(b"\r\n\r\n".to_vec()),
        }
    }

    fn scan(&mut self, bytes: &[u8]) -> Result<(), MultipartGuardBodyError> {
        for &byte in bytes {
            match self.phase {
                ScannerPhase::Preamble => self.scan_preamble(byte)?,
                ScannerPhase::BoundarySuffix => self.scan_boundary_suffix(byte)?,
                ScannerPhase::Headers => self.scan_header(byte)?,
                ScannerPhase::Body => self.scan_body(byte),
                ScannerPhase::Epilogue => {}
            }
        }
        Ok(())
    }

    fn scan_preamble(&mut self, byte: u8) -> Result<(), MultipartGuardBodyError> {
        self.preamble_seen = self.preamble_seen.saturating_add(1);
        if self.initial_boundary.feed(byte) {
            let preamble_len = self
                .preamble_seen
                .saturating_sub(self.initial_boundary.pattern_len());
            if preamble_len > self.limits.max_preamble_bytes {
                return Err(MultipartGuardBodyError::PreambleTooLarge);
            }
            self.start_boundary_suffix();
        } else {
            if self.preamble_seen
                > self
                    .limits
                    .max_preamble_bytes
                    .saturating_add(self.initial_boundary.pattern_len())
            {
                return Err(MultipartGuardBodyError::PreambleTooLarge);
            }
        }
        Ok(())
    }

    fn scan_boundary_suffix(&mut self, byte: u8) -> Result<(), MultipartGuardBodyError> {
        match self.boundary_suffix_phase {
            BoundarySuffixPhase::First => match byte {
                b'-' => self.boundary_suffix_phase = BoundarySuffixPhase::ClosingHyphen,
                b' ' | b'\t' => {
                    self.boundary_padding_seen = 1;
                    if self.boundary_padding_seen > self.limits.max_header_bytes {
                        return Err(MultipartGuardBodyError::BoundaryPaddingTooLarge);
                    }
                    self.boundary_suffix_phase = BoundarySuffixPhase::Padding;
                }
                b'\r' => self.boundary_suffix_phase = BoundarySuffixPhase::LineFeed,
                _ => return Err(MultipartGuardBodyError::InvalidBoundaryLine),
            },
            BoundarySuffixPhase::ClosingHyphen => {
                if byte != b'-' {
                    return Err(MultipartGuardBodyError::InvalidBoundaryLine);
                }
                self.phase = ScannerPhase::Epilogue;
            }
            BoundarySuffixPhase::Padding => match byte {
                b' ' | b'\t' => {
                    self.boundary_padding_seen = self.boundary_padding_seen.saturating_add(1);
                    if self.boundary_padding_seen > self.limits.max_header_bytes {
                        return Err(MultipartGuardBodyError::BoundaryPaddingTooLarge);
                    }
                }
                b'\r' => self.boundary_suffix_phase = BoundarySuffixPhase::LineFeed,
                _ => return Err(MultipartGuardBodyError::InvalidBoundaryLine),
            },
            BoundarySuffixPhase::LineFeed => {
                if byte != b'\n' {
                    return Err(MultipartGuardBodyError::InvalidBoundaryLine);
                }
                self.start_headers();
            }
        }
        Ok(())
    }

    fn scan_header(&mut self, byte: u8) -> Result<(), MultipartGuardBodyError> {
        self.header_seen = self.header_seen.saturating_add(1);
        if self.header_end.feed(byte) {
            let header_len = self
                .header_seen
                .saturating_sub(self.header_end.pattern_len());
            if header_len > self.limits.max_header_bytes {
                return Err(MultipartGuardBodyError::HeaderTooLarge);
            }
            self.phase = ScannerPhase::Body;
            self.body_boundary.reset();
        } else if self.header_seen
            > self
                .limits
                .max_header_bytes
                .saturating_add(self.header_end.pattern_len())
        {
            return Err(MultipartGuardBodyError::HeaderTooLarge);
        }
        Ok(())
    }

    fn scan_body(&mut self, byte: u8) {
        if self.body_boundary.feed(byte) {
            self.start_boundary_suffix();
        }
    }

    fn start_boundary_suffix(&mut self) {
        self.phase = ScannerPhase::BoundarySuffix;
        self.boundary_padding_seen = 0;
        self.boundary_suffix_phase = BoundarySuffixPhase::First;
    }

    fn start_headers(&mut self) {
        self.phase = ScannerPhase::Headers;
        self.header_seen = 0;
        self.header_end.reset();
    }

    fn finish(&self) -> Result<(), MultipartGuardBodyError> {
        match self.phase {
            ScannerPhase::Preamble => Err(MultipartGuardBodyError::MissingOpeningBoundary),
            ScannerPhase::BoundarySuffix => Err(MultipartGuardBodyError::IncompleteBoundaryLine),
            ScannerPhase::Headers => Err(MultipartGuardBodyError::IncompleteHeaderBlock),
            ScannerPhase::Body => Err(MultipartGuardBodyError::MissingClosingBoundary),
            ScannerPhase::Epilogue => Ok(()),
        }
    }
}

#[derive(Debug)]
struct ByteMatcher {
    pattern: Box<[u8]>,
    prefix: Box<[usize]>,
    matched: usize,
}

impl ByteMatcher {
    fn new(pattern: Vec<u8>) -> Self {
        debug_assert!(!pattern.is_empty());
        let mut prefix = vec![0; pattern.len()];
        let mut matched = 0;
        for index in 1..pattern.len() {
            while matched > 0 && pattern[index] != pattern[matched] {
                matched = prefix[matched - 1];
            }
            if pattern[index] == pattern[matched] {
                matched += 1;
                prefix[index] = matched;
            }
        }
        Self {
            pattern: pattern.into_boxed_slice(),
            prefix: prefix.into_boxed_slice(),
            matched: 0,
        }
    }

    fn feed(&mut self, byte: u8) -> bool {
        while self.matched > 0 && byte != self.pattern[self.matched] {
            self.matched = self.prefix[self.matched - 1];
        }
        if byte == self.pattern[self.matched] {
            self.matched += 1;
        }
        if self.matched == self.pattern.len() {
            self.matched = self.prefix[self.matched - 1];
            true
        } else {
            false
        }
    }

    fn pattern_len(&self) -> usize {
        self.pattern.len()
    }

    fn reset(&mut self) {
        self.matched = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum::body::to_bytes;
    use futures_util::{stream, StreamExt};
    use http::header::CONTENT_TYPE;

    use super::*;

    fn request(body: Body, content_type: &str) -> Request<Body> {
        Request::builder()
            .header(CONTENT_TYPE, content_type)
            .body(body)
            .unwrap()
    }

    async fn drain(request: Request<Body>) -> Result<Bytes, axum::Error> {
        to_bytes(request.into_body(), usize::MAX).await
    }

    #[test]
    fn validates_content_type_and_boundary() {
        let missing = request(Body::empty(), "multipart/form-data");
        assert_eq!(
            guard_multipart_request(missing).unwrap_err(),
            MultipartGuardError::MissingBoundary
        );

        let too_long = "x".repeat(MAX_BOUNDARY_BYTES + 1);
        let invalid = request(
            Body::empty(),
            &format!("multipart/form-data; boundary={too_long}"),
        );
        assert_eq!(
            guard_multipart_request(invalid).unwrap_err(),
            MultipartGuardError::InvalidBoundary
        );

        let quoted = request(
            Body::empty(),
            "multipart/form-data; charset=utf-8; boundary=\"valid boundary\"",
        );
        assert!(guard_multipart_request(quoted).is_ok());
    }

    #[tokio::test]
    async fn rejects_an_overlong_preamble() {
        let body = Body::from("123456789--x\r\nA: b\r\n\r\nv\r\n--x--\r\n");
        let guarded = guard_multipart_request_with_limits(
            request(body, "multipart/form-data; boundary=x"),
            MultipartGuardLimits {
                max_preamble_bytes: 8,
                max_header_bytes: 32,
            },
        )
        .unwrap();
        let error = drain(guarded).await.unwrap_err();
        assert!(error.to_string().contains("preamble"));
    }

    #[tokio::test]
    async fn rejects_an_overlong_first_header_block() {
        let body = Body::from("--x\r\n123456789\r\n\r\nv\r\n--x--\r\n");
        let guarded = guard_multipart_request_with_limits(
            request(body, "multipart/form-data; boundary=x"),
            MultipartGuardLimits {
                max_preamble_bytes: 8,
                max_header_bytes: 8,
            },
        )
        .unwrap();
        let error = drain(guarded).await.unwrap_err();
        assert!(error.to_string().contains("header block"));
    }

    #[tokio::test]
    async fn rejects_an_overlong_later_header_block() {
        let body =
            Body::from("--x\r\nA: b\r\n\r\nfirst\r\n--x\r\n123456789\r\n\r\nsecond\r\n--x--\r\n");
        let guarded = guard_multipart_request_with_limits(
            request(body, "multipart/form-data; boundary=x"),
            MultipartGuardLimits {
                max_preamble_bytes: 8,
                max_header_bytes: 8,
            },
        )
        .unwrap();
        let error = drain(guarded).await.unwrap_err();
        assert!(error.to_string().contains("header block"));
    }

    #[tokio::test]
    async fn recognizes_transport_padding_before_every_header_block() {
        let raw = b"--padded \t \r\nA: b\r\n\r\nfirst\r\n--padded    \r\nB: c\r\n\r\nsecond\r\n--padded--\t\r\n";
        let chunks = raw
            .iter()
            .map(|byte| Ok::<_, Infallible>(Bytes::copy_from_slice(&[*byte])));
        let guarded = guard_multipart_request(request(
            Body::from_stream(stream::iter(chunks)),
            "multipart/form-data; boundary=padded",
        ))
        .unwrap();
        assert_eq!(drain(guarded).await.unwrap().as_ref(), raw);

        let overlong = Body::from("--padded     \r\nA: b\r\n\r\nx\r\n--padded--\r\n");
        let guarded = guard_multipart_request_with_limits(
            request(overlong, "multipart/form-data; boundary=padded"),
            MultipartGuardLimits {
                max_preamble_bytes: 8,
                max_header_bytes: 4,
            },
        )
        .unwrap();
        assert!(drain(guarded)
            .await
            .unwrap_err()
            .to_string()
            .contains("boundary padding"));
    }

    #[tokio::test]
    async fn recognizes_boundaries_across_every_chunk_split() {
        let raw = b"--split-boundary\r\nA: b\r\n\r\nvalue\r\n--split-boundary--\r\n";
        for split_at in 1..raw.len() {
            let chunks = vec![
                Ok::<_, Infallible>(Bytes::copy_from_slice(&raw[..split_at])),
                Ok(Bytes::copy_from_slice(&raw[split_at..])),
            ];
            let guarded = guard_multipart_request(request(
                Body::from_stream(stream::iter(chunks)),
                "multipart/form-data; boundary=split-boundary",
            ))
            .unwrap();
            let collected = drain(guarded).await.unwrap();
            assert_eq!(collected.as_ref(), raw, "split at byte {split_at}");
        }
    }

    #[tokio::test]
    async fn streams_a_large_file_body_without_coalescing_chunks() {
        const FILE_CHUNKS: usize = 256;
        const CHUNK_SIZE: usize = 64 * 1024;
        let source = stream::unfold(0usize, |index| async move {
            let item = match index {
                0 => Bytes::from_static(b"--big\r\nA: b\r\n\r\n"),
                1..=FILE_CHUNKS => Bytes::from(vec![b'x'; CHUNK_SIZE]),
                value if value == FILE_CHUNKS + 1 => Bytes::from_static(b"\r\n--big--\r\n"),
                _ => return None,
            };
            Some((Ok::<_, Infallible>(item), index + 1))
        });
        let guarded = guard_multipart_request(request(
            Body::from_stream(source),
            "multipart/form-data; boundary=big",
        ))
        .unwrap();

        let mut stream = guarded.into_body().into_data_stream();
        let mut total = 0usize;
        let mut chunks = 0usize;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.unwrap();
            total += chunk.len();
            chunks += 1;
        }
        assert!(total > 16 * 1024 * 1024);
        assert_eq!(chunks, FILE_CHUNKS + 2);
    }
}
