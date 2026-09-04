pub(crate) const HARD_MULTIPART_LIMIT: u64 = crate::config::MAX_MULTIPART_BODY_SIZE;
pub(crate) const ERROR_CODE_HEADER: &str = "x-vaultlink-error-code";
pub(crate) const DEFAULT_REQUEST_BODY_LIMIT: usize = 1024 * 1024;
pub(crate) const MAX_UPLOAD_PATH_FIELD_BYTES: usize = 4 * 1024;
pub(crate) const MAX_UPLOAD_OPTION_FIELD_BYTES: usize = 16;
pub(crate) const MAX_SEARCH_QUERY_BYTES: usize = 256;
pub(crate) const STREAM_BUFFER_BYTES: usize = 64 * 1024;

/// Axum wraps body deadline failures in several transport-specific error
/// layers. Keep their classification transport-neutral so every upload
/// adapter preserves the same 408 contract.
pub(crate) fn request_body_timed_out(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(cause) = current {
        if cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        {
            return true;
        }
        let message = cause.to_string().to_ascii_lowercase();
        if message.contains("deadline exceeded")
            || message.contains("minimum request body progress")
            || message.contains("timed out")
            || message.contains("timeout")
        {
            return true;
        }
        current = cause.source();
    }
    false
}
