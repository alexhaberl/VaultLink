use super::*;

fn public_multipart_read_rejection(
    token: &str,
    upload_subdir: &str,
    error: &(dyn std::error::Error + 'static),
    fallback_message: &'static str,
) -> PublicUploadPhaseError {
    if request_body_timed_out(error) {
        public_upload_rejection(
            token,
            upload_subdir,
            StatusCode::REQUEST_TIMEOUT,
            "Upload timed out",
        )
    } else {
        public_upload_rejection(
            token,
            upload_subdir,
            StatusCode::BAD_REQUEST,
            fallback_message,
        )
    }
}

async fn limited_public_multipart_text(
    mut field: axum::extract::multipart::Field<'_>,
    maximum: usize,
) -> std::result::Result<String, Option<axum::extract::multipart::MultipartError>> {
    let mut value = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(Some)? {
        if value
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum)
        {
            return Err(None);
        }
        value.extend_from_slice(&chunk);
    }
    String::from_utf8(value).map_err(|_| None)
}

pub(super) struct PublicUploadFormPhase<'a> {
    pub(super) state: &'a AppState,
    pub(super) token: &'a str,
    pub(super) share: &'a Share,
    pub(super) share_scope: SecureDirectory,
    pub(super) settings: &'a RuntimeSettings,
    pub(super) maximum: u64,
    pub(super) required_csrf: Option<&'a str>,
    pub(super) csrf_header_valid: bool,
    pub(super) authorized_upload: AuthorizedUpload,
}

impl PublicUploadFormPhase<'_> {
    pub(super) async fn run(self, multipart: Multipart) -> PublicUploadPhaseResult<PreparedUpload> {
        PublicUploadParser::new(self).run(multipart).await
    }
}

struct PublicUploadParser<'a> {
    state: &'a AppState,
    token: &'a str,
    share: &'a Share,
    share_scope: SecureDirectory,
    settings: &'a RuntimeSettings,
    maximum: u64,
    required_csrf: Option<&'a str>,
    upload_subdir: String,
    folder_path: Option<String>,
    overwrite_requested: bool,
    form_state: UploadFormState,
    csrf_validated: bool,
    authorized_upload: Option<AuthorizedUpload>,
    staged_upload: Option<StagedUpload>,
}

impl<'a> PublicUploadParser<'a> {
    fn new(phase: PublicUploadFormPhase<'a>) -> Self {
        Self {
            state: phase.state,
            token: phase.token,
            share: phase.share,
            share_scope: phase.share_scope,
            settings: phase.settings,
            maximum: phase.maximum,
            required_csrf: phase.required_csrf,
            upload_subdir: String::new(),
            folder_path: None,
            overwrite_requested: false,
            form_state: UploadFormState::default(),
            csrf_validated: phase.required_csrf.is_none() || phase.csrf_header_valid,
            authorized_upload: Some(phase.authorized_upload),
            staged_upload: None,
        }
    }

    async fn run(mut self, mut multipart: Multipart) -> PublicUploadPhaseResult<PreparedUpload> {
        while let Some(field) = multipart.next_field().await.map_err(|error| {
            public_multipart_read_rejection(
                self.token,
                &self.upload_subdir,
                &error,
                "Invalid upload",
            )
        })? {
            let field_kind = self.observe_field(field.name().unwrap_or(""))?;
            self.handle_field(field_kind, field).await?;
        }
        self.finish()
    }

    fn observe_field(&mut self, name: &str) -> PublicUploadPhaseResult<UploadFormField> {
        let field = match name {
            "path" => UploadFormField::Path,
            "folder_path" => UploadFormField::FolderPath,
            "overwrite_existing" => UploadFormField::Overwrite,
            "csrf" => UploadFormField::Csrf,
            "file" => UploadFormField::File,
            _ => UploadFormField::Unknown,
        };
        self.form_state
            .observe(field, MAX_UPLOAD_MULTIPART_FIELDS)
            .map_err(|error| {
                self.rejection(StatusCode::BAD_REQUEST, form_state_error_message(error))
            })?;
        Ok(field)
    }

    async fn handle_field(
        &mut self,
        field_kind: UploadFormField,
        field: axum::extract::multipart::Field<'_>,
    ) -> PublicUploadPhaseResult<()> {
        match field_kind {
            UploadFormField::Path => self.handle_path(field).await,
            UploadFormField::FolderPath => self.handle_folder_path(field).await,
            UploadFormField::Overwrite => self.handle_overwrite(field).await,
            UploadFormField::Csrf => self.handle_csrf(field).await,
            UploadFormField::File => self.handle_file(field).await,
            UploadFormField::Unknown => {
                Err(self.rejection(StatusCode::BAD_REQUEST, "Unknown multipart field"))
            }
        }
    }

    async fn read_text(
        &self,
        field: axum::extract::multipart::Field<'_>,
        maximum: usize,
        invalid_status: StatusCode,
        invalid_message: &'static str,
    ) -> PublicUploadPhaseResult<String> {
        limited_public_multipart_text(field, maximum)
            .await
            .map_err(|error| {
                error.map_or_else(
                    || self.rejection(invalid_status, invalid_message),
                    |error| {
                        public_multipart_read_rejection(
                            self.token,
                            &self.upload_subdir,
                            &error,
                            invalid_message,
                        )
                    },
                )
            })
    }

    async fn handle_path(
        &mut self,
        field: axum::extract::multipart::Field<'_>,
    ) -> PublicUploadPhaseResult<()> {
        let value = self
            .read_text(
                field,
                MAX_UPLOAD_PATH_FIELD_BYTES,
                StatusCode::BAD_REQUEST,
                "Invalid upload path",
            )
            .await?;
        self.upload_subdir = policy::normalize_public_upload_subdir(self.share.permission, &value)
            .map_err(|_| self.rejection(StatusCode::BAD_REQUEST, "Invalid upload path"))?;
        Ok(())
    }

    async fn handle_folder_path(
        &mut self,
        field: axum::extract::multipart::Field<'_>,
    ) -> PublicUploadPhaseResult<()> {
        let value = self
            .read_text(
                field,
                MAX_UPLOAD_PATH_FIELD_BYTES,
                StatusCode::BAD_REQUEST,
                "Invalid folder path",
            )
            .await?;
        self.folder_path = Some(
            crate::path_security::validate_relative(&value)
                .map_err(|_| self.rejection(StatusCode::BAD_REQUEST, "Invalid folder path"))?
                .to_string_lossy()
                .replace('\\', "/"),
        );
        Ok(())
    }

    async fn handle_overwrite(
        &mut self,
        field: axum::extract::multipart::Field<'_>,
    ) -> PublicUploadPhaseResult<()> {
        let value = self
            .read_text(
                field,
                MAX_UPLOAD_OPTION_FIELD_BYTES,
                StatusCode::BAD_REQUEST,
                "Invalid upload",
            )
            .await?;
        self.overwrite_requested = value == "1";
        if self.overwrite_requested && !self.state.config().storage.replacements_allowed() {
            return Err(self.rejection(
                StatusCode::BAD_REQUEST,
                "Overwriting is disabled with external storage writers",
            ));
        }
        Ok(())
    }

    async fn handle_csrf(
        &mut self,
        field: axum::extract::multipart::Field<'_>,
    ) -> PublicUploadPhaseResult<()> {
        let value = self
            .read_text(field, 256, StatusCode::FORBIDDEN, "Invalid CSRF token")
            .await?;
        self.csrf_validated = self
            .required_csrf
            .is_none_or(|expected| auth::constant_time_eq(expected, &value));
        if !self.csrf_validated {
            return Err(self.rejection(StatusCode::FORBIDDEN, "Invalid CSRF token"));
        }
        Ok(())
    }

    async fn handle_file(
        &mut self,
        field: axum::extract::multipart::Field<'_>,
    ) -> PublicUploadPhaseResult<()> {
        if !self.csrf_validated {
            return Err(self.rejection(StatusCode::FORBIDDEN, "CSRF token missing"));
        }
        let file_name = field
            .file_name()
            .ok_or_else(|| self.rejection(StatusCode::BAD_REQUEST, "File name missing"))?;
        let name = match policy::validate_public_upload_filename(
            file_name,
            &self.settings.blocked_extensions,
        ) {
            Ok(name) => name.to_string(),
            Err(PublicUploadPolicyError::BlockedExtension) => {
                return Err(self.rejection(StatusCode::UNSUPPORTED_MEDIA_TYPE, "File type blocked"));
            }
            Err(_) => {
                return Err(self.rejection(StatusCode::BAD_REQUEST, "Invalid file name"));
            }
        };
        let (authorized_upload, target) = self.bind_target(name).await?;
        let mut staging = authorized_upload
            .begin_staging(self.state, self.token, target)
            .await?;
        self.upload_subdir = staging.target.upload_subdir.clone();
        #[cfg(test)]
        upload_phase_test_checkpoint(self.token, PublicUploadTestPhase::Staging)
            .await
            .map_err(|error| PublicUploadPhaseError::App(upload_io_error(error)))?;
        let stream = field;
        tokio::pin!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                public_multipart_read_rejection(
                    self.token,
                    &self.upload_subdir,
                    &error,
                    "Upload aborted",
                )
            })?;
            staging
                .write_chunk(self.state, self.token, self.maximum, chunk)
                .await?;
        }
        staging.finish_staging(self.token).await?;
        self.staged_upload = Some(staging);
        Ok(())
    }

    async fn bind_target(
        &mut self,
        file_name: String,
    ) -> PublicUploadPhaseResult<(AuthorizedUpload, PublicUploadTarget)> {
        let upload_base = self.upload_subdir.clone();
        let folder_path = self.folder_path.clone().unwrap_or_default();
        let upload_subdir = join_display(&upload_base, &folder_path);
        let authorized_upload = self
            .authorized_upload
            .take()
            .expect("one authorized owner exists until the only file field");
        let binding = PublicUploadTargetBinding {
            authorized_upload,
            share_scope: self.share_scope.clone(),
            share_id: self.share.id,
            upload_policy_epoch: self.share.upload_policy_epoch,
            upload_base,
            folder_path,
            upload_subdir,
            file_name,
            #[cfg(test)]
            token: self.token.to_string(),
        };
        // Public/share admission bounds these blocking opens to 28 globally and
        // two per share. The task owns admission so cancelling the HTTP future
        // cannot release a slot while descriptor binding is still running.
        let (authorized_upload, target) = tokio::task::spawn_blocking(move || binding.run())
            .await
            .map_err(|error| {
                PublicUploadPhaseError::App(AppError::from(report_internal(
                    InternalOperation::WebPublicUploadBindDestination,
                    error,
                )))
            })?;
        let target = target.map_err(|error| match error {
            PublicUploadTargetBindError::UploadBaseUnavailable => {
                self.rejection(StatusCode::NOT_FOUND, "Target folder unavailable")
            }
            PublicUploadTargetBindError::UploadTargetUnavailable => {
                self.rejection(StatusCode::CONFLICT, "Upload target unavailable")
            }
        })?;
        Ok((authorized_upload, target))
    }

    fn finish(self) -> PublicUploadPhaseResult<PreparedUpload> {
        let missing_file = self.rejection(StatusCode::BAD_REQUEST, "File is missing");
        let staged_upload = self.staged_upload.ok_or(missing_file)?;
        Ok(staged_upload.prepare(PublicUploadIntent {
            overwrite_requested: self.overwrite_requested,
        }))
    }

    fn rejection(&self, status: StatusCode, message: &'static str) -> PublicUploadPhaseError {
        public_upload_rejection(self.token, &self.upload_subdir, status, message)
    }
}

enum PublicUploadTargetBindError {
    UploadBaseUnavailable,
    UploadTargetUnavailable,
}

/// The detached blocking task owns the only authorized upload capability.
/// Consequently permits survive request cancellation until both descriptor
/// opens have either completed or unwound.
struct PublicUploadTargetBinding {
    authorized_upload: AuthorizedUpload,
    share_scope: SecureDirectory,
    share_id: i64,
    upload_policy_epoch: i64,
    upload_base: String,
    folder_path: String,
    upload_subdir: String,
    file_name: String,
    #[cfg(test)]
    token: String,
}

impl PublicUploadTargetBinding {
    fn run(
        self,
    ) -> (
        AuthorizedUpload,
        std::result::Result<PublicUploadTarget, PublicUploadTargetBindError>,
    ) {
        let Self {
            authorized_upload,
            share_scope,
            share_id,
            upload_policy_epoch,
            upload_base,
            folder_path,
            upload_subdir,
            file_name,
            #[cfg(test)]
            token,
        } = self;
        #[cfg(test)]
        if upload_blocking_phase_test_checkpoint(&token, PublicUploadTestPhase::TargetBinding)
            .is_err()
        {
            return (
                authorized_upload,
                Err(PublicUploadTargetBindError::UploadBaseUnavailable),
            );
        }
        let target = (|| {
            let upload_base_scope = share_scope
                .bind_directory(&upload_base)
                .map_err(|_| PublicUploadTargetBindError::UploadBaseUnavailable)?;
            let expected_destination = if folder_path.is_empty() {
                Some(upload_base_scope.clone())
            } else {
                match upload_base_scope.bind_directory(&folder_path) {
                    Ok(directory) => Some(directory),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(_) => {
                        return Err(PublicUploadTargetBindError::UploadTargetUnavailable);
                    }
                }
            };
            Ok(PublicUploadTarget {
                share_id,
                upload_policy_epoch,
                upload_base_scope,
                expected_destination,
                upload_base,
                folder_path,
                upload_subdir,
                file_name,
            })
        })();
        (authorized_upload, target)
    }
}

fn form_state_error_message(error: UploadFormStateError) -> &'static str {
    match error {
        UploadFormStateError::TooManyFields => "Too many multipart fields",
        UploadFormStateError::DuplicateOrLatePath => {
            "Upload path was submitted more than once or too late"
        }
        UploadFormStateError::DuplicateOrLateFolderPath => {
            "Folder path was submitted more than once or too late"
        }
        UploadFormStateError::DuplicateOverwrite => "Upload option was submitted more than once",
        UploadFormStateError::DuplicateOrLateCsrf => {
            "CSRF token was submitted more than once or too late"
        }
        UploadFormStateError::MultipleFiles => "Exactly one file is allowed per request",
        UploadFormStateError::UnknownField => "Unknown multipart field",
    }
}
