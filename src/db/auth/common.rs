impl Database {
    fn encrypt_admin_totp(
        &self,
        username: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<(u64, Vec<u8>)> {
        self.encrypt_secret(
            totp_secret.as_bytes(),
            format!("admins.totp:{}", username.to_lowercase()).as_bytes(),
        )
    }

    fn decrypt_admin_totp(
        &self,
        username: &str,
        key_id: u64,
        ciphertext: &[u8],
    ) -> rusqlite::Result<SecretString> {
        let plaintext = self.decrypt_secret(
            key_id,
            ciphertext,
            format!("admins.totp:{}", username.to_lowercase()).as_bytes(),
        )?;
        String::from_utf8(plaintext)
            .map(SecretString::from)
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })
    }

    fn encrypt_enrollment_totp(
        &self,
        enrollment_token_hash: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<(u64, Vec<u8>)> {
        self.encrypt_secret(
            totp_secret.as_bytes(),
            format!("admin_mfa_enrollments.totp:{enrollment_token_hash}").as_bytes(),
        )
    }

    fn decrypt_enrollment_totp(
        &self,
        enrollment_token_hash: &str,
        key_id: u64,
        ciphertext: &[u8],
    ) -> rusqlite::Result<SecretString> {
        let plaintext = self.decrypt_secret(
            key_id,
            ciphertext,
            format!("admin_mfa_enrollments.totp:{enrollment_token_hash}").as_bytes(),
        )?;
        String::from_utf8(plaintext)
            .map(SecretString::from)
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })
    }
}
