#[cfg(test)]
mod webauthn_response_tests {
    use super::*;

    #[test]
    fn capacity_exhaustion_returns_retryable_service_unavailable() {
        let response = webauthn_start_response::<serde_json::Value>(Err(
            WebAuthnServiceError::CapacityExceeded,
        ))
        .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("60"))
        );
    }

    #[test]
    fn ceremony_errors_keep_the_existing_bad_request_contract() {
        let error = webauthn_start_response::<serde_json::Value>(Err(
            WebAuthnServiceError::Ceremony("invalid challenge".into()),
        ))
        .unwrap_err();

        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(!error.1.is_empty());
    }
}
