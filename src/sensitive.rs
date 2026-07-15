use std::fmt;

use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

/// An owned UTF-8 secret whose allocation is zeroed when it is dropped.
///
/// `SecretString` intentionally implements neither `Clone`, `Display`, nor
/// `Serialize`: callers must opt into the narrow operation that needs access
/// to the plaintext, and unavoidable copies must be named at their call site.
/// This limits the lifetime and number of application-owned copies. It cannot
/// erase copies made internally by the HTTP framework, Serde input buffers,
/// SQLite, formatting, or response buffers.
pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrows the plaintext for a narrowly scoped cryptographic or persistence
    /// operation. Callers must not retain the returned reference.
    pub(crate) fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    /// Uses an ordinary comparison for two fields from the same submitted
    /// password form. Authentication tokens must use `auth::constant_time_eq`
    /// instead.
    pub(crate) fn matches_confirmation(&self, confirmation: &Self) -> bool {
        self.expose_secret() == confirmation.expose_secret()
    }

    /// Creates the one unavoidable second password allocation used when setup
    /// must both hash a submitted password and verify an interrupted prior run.
    pub(crate) fn duplicate_for_verification(&self) -> Self {
        Self::new(self.expose_secret().to_owned())
    }

    /// Creates the one-time response copy retained after a generated TOTP
    /// secret has been persisted. The response framework may copy it again.
    pub(crate) fn duplicate_for_one_time_response(&self) -> Self {
        Self::new(self.expose_secret().to_owned())
    }

    /// Crosses the unavoidable HTTP response boundary after a caller has made
    /// the explicitly named one-time-response copy above. The returned String
    /// is owned by Serde/framework buffers and can no longer be guaranteed to
    /// be zeroized by VaultLink.
    pub(crate) fn into_one_time_response(mut self) -> String {
        std::mem::take(&mut *self.0)
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_exposes_the_plaintext() {
        let secret = SecretString::from("correct horse battery staple");
        let debug = format!("{secret:?}");
        assert_eq!(debug, "SecretString([REDACTED])");
        assert!(!debug.contains("horse"));
    }

    #[test]
    fn serde_deserializes_without_a_clone_capable_wrapper() {
        let secret: SecretString = serde_json::from_str(r#""sensitive value""#).unwrap();
        assert_eq!(secret.expose_secret(), "sensitive value");
    }

    #[test]
    fn explicitly_named_duplicates_have_independent_allocations() {
        let secret = SecretString::from("sensitive value");
        let duplicate = secret.duplicate_for_verification();
        assert_eq!(secret.expose_secret(), duplicate.expose_secret());
        assert_ne!(
            secret.expose_secret().as_ptr(),
            duplicate.expose_secret().as_ptr()
        );
    }

    #[test]
    fn one_time_response_conversion_moves_the_named_copy() {
        let secret = SecretString::from("sensitive value");
        let response = secret
            .duplicate_for_one_time_response()
            .into_one_time_response();
        assert_eq!(response, "sensitive value");
        assert_eq!(secret.expose_secret(), "sensitive value");
    }
}
