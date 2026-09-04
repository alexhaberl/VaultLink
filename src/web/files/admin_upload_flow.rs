struct AdminUploadParser {
    directory: Option<String>,
    csrf_seen: bool,
    overwrite_existing: bool,
    saw_overwrite: bool,
    folder_path: Option<String>,
    directory_durability_uncertain: bool,
    staged: Option<StagedAdminUpload>,
    fields_seen: usize,
    authorization: Option<AuthorizedAdminUpload>,
}

#[must_use = "an authorized admin upload owns admission permits and its MFA proof"]
struct AuthorizedAdminUpload {
    permits: AdminUploadPermits,
}

#[must_use = "a staged admin upload owns its temporary file until it is prepared or dropped"]
struct StagedAdminUpload {
    pending: PendingUpload,
    name: String,
    total: u64,
    directory: String,
    overwrite_existing: bool,
    directory_durability_uncertain: bool,
    permits: AdminUploadPermits,
}

#[must_use = "a prepared admin upload must be handed to the non-cancellable finalizer"]
struct PreparedAdminUpload {
    pending: PendingUpload,
    name: String,
    total: u64,
    directory: String,
    overwrite_existing: bool,
    directory_durability_uncertain: bool,
    permits: AdminUploadPermits,
}

#[must_use = "a committed admin upload owns the namespace fence until publication finishes"]
struct CommittedAdminUpload {
    upload: PreparedAdminUpload,
    storage_guard: crate::storage_authority::StorageMutationGuard,
    existed: bool,
}

#[must_use = "a published admin upload must be converted into its transport outcome"]
struct PublishedAdminUpload {
    name: String,
    directory: String,
    replaced: bool,
    durability_uncertain: bool,
    audit_uncertain: bool,
    directory_durability_uncertain: bool,
}

fn admin_multipart_read_error(
    error: &(dyn std::error::Error + 'static),
    fallback_message: &'static str,
) -> AppError {
    if request_body_timed_out(error) {
        AppError(StatusCode::REQUEST_TIMEOUT, "Upload timed out")
    } else {
        AppError(StatusCode::BAD_REQUEST, fallback_message)
    }
}

fn admin_multipart_text_error(
    error: Option<&axum::extract::multipart::MultipartError>,
    fallback_message: &'static str,
) -> AppError {
    error.map_or(
        AppError(StatusCode::BAD_REQUEST, fallback_message),
        |error| admin_multipart_read_error(error, fallback_message),
    )
}

impl AdminUploadParser {
    fn new(authorization: AuthorizedAdminUpload) -> Self {
        Self {
            directory: None,
            csrf_seen: false,
            overwrite_existing: false,
            saw_overwrite: false,
            folder_path: None,
            directory_durability_uncertain: false,
            staged: None,
            fields_seen: 0,
            authorization: Some(authorization),
        }
    }

    fn record_field(&mut self) -> Result<()> {
        self.fields_seen += 1;
        if self.fields_seen > 5 {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Too many multipart fields",
            ));
        }
        Ok(())
    }

    async fn path_field(&mut self, field: axum::extract::multipart::Field<'_>) -> Result<()> {
        if self.directory.is_some() || self.staged.is_some() {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Upload path was submitted more than once or too late",
            ));
        }
        self.directory = Some(normalized_multipart_path(field, "Invalid upload path").await?);
        Ok(())
    }

    async fn csrf_field(
        &mut self,
        admin: &crate::db::Session,
        field: axum::extract::multipart::Field<'_>,
    ) -> Result<()> {
        if self.csrf_seen || self.staged.is_some() {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "CSRF proof was submitted more than once or too late",
            ));
        }
        let value = limited_multipart_text(field, 512)
            .await
            .map_err(|error| admin_multipart_text_error(error.as_ref(), "Invalid CSRF proof"))?;
        csrf(admin, &value)?;
        self.csrf_seen = true;
        Ok(())
    }

    async fn overwrite_field(
        &mut self,
        state: &FileRouteState,
        field: axum::extract::multipart::Field<'_>,
    ) -> Result<()> {
        if std::mem::replace(&mut self.saw_overwrite, true) || self.staged.is_some() {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Upload option was submitted more than once or too late",
            ));
        }
        let value = limited_multipart_text(field, MAX_UPLOAD_OPTION_FIELD_BYTES)
            .await
            .map_err(|error| admin_multipart_text_error(error.as_ref(), "Invalid upload option"))?;
        self.overwrite_existing = value == "1";
        if self.overwrite_existing && !state.config().storage.replacements_allowed() {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Overwriting is disabled with external storage writers",
            ));
        }
        Ok(())
    }

    async fn folder_path_field(
        &mut self,
        field: axum::extract::multipart::Field<'_>,
    ) -> Result<()> {
        if self.folder_path.is_some() || self.staged.is_some() {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Folder path was submitted more than once or too late",
            ));
        }
        self.folder_path = Some(normalized_multipart_path(field, "Invalid folder path").await?);
        Ok(())
    }

    async fn file_field(
        &mut self,
        state: &FileRouteState,
        admin: &crate::db::Session,
        field: axum::extract::multipart::Field<'_>,
        settings: &crate::runtime::RuntimeSettings,
    ) -> Result<()> {
        if self.staged.is_some() {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Exactly one file is allowed per request",
            ));
        }
        let base = self.directory.clone().ok_or(AppError(
            StatusCode::BAD_REQUEST,
            "Upload path must be submitted before the file",
        ))?;
        if !self.csrf_seen {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "CSRF proof must be submitted before the file",
            ));
        }
        let mut authorization = self
            .authorization
            .take()
            .expect("parser owns authorization until the file field is staged");
        let target = if let Some(folder_path) = self.folder_path.clone() {
            let (next, target, uncertain) = authorization
                .ensure_directory(state, &base, &folder_path, &admin.username)
                .await?;
            authorization = next;
            self.directory_durability_uncertain |= uncertain;
            target
        } else {
            base
        };
        self.staged = Some(
            authorization
                .stage(
                    state,
                    target,
                    field,
                    settings.max_upload_size,
                    &settings.blocked_extensions,
                    self.overwrite_existing,
                    self.directory_durability_uncertain,
                )
                .await?,
        );
        Ok(())
    }

    fn finish(self) -> Result<PreparedAdminUpload> {
        self.directory
            .ok_or(AppError(StatusCode::BAD_REQUEST, "Upload path missing"))?;
        if !self.csrf_seen {
            return Err(AppError(StatusCode::FORBIDDEN, "CSRF proof missing"));
        }
        let staged = self.staged.ok_or(AppError(
            StatusCode::BAD_REQUEST,
            "Exactly one file is required per request",
        ))?;
        Ok(staged.prepare())
    }
}

impl AuthorizedAdminUpload {
    async fn ensure_directory(
        self,
        state: &FileRouteState,
        base: &str,
        relative: &str,
        actor: &str,
    ) -> Result<(Self, String, bool)> {
        let AdminUploadPermits {
            global,
            peer,
            proof,
        } = self.permits;
        let (target, durability_uncertain, permits) =
            ensure_admin_upload_directory(state, proof, base, relative, actor, global, peer)
                .await?;
        Ok((Self { permits }, target, durability_uncertain))
    }

    #[allow(clippy::too_many_arguments)]
    async fn stage(
        self,
        state: &FileRouteState,
        directory: String,
        field: axum::extract::multipart::Field<'_>,
        maximum: u64,
        blocked_extensions: &[String],
        overwrite_existing: bool,
        directory_durability_uncertain: bool,
    ) -> Result<StagedAdminUpload> {
        let (pending, name, total) =
            stage_admin_upload(state, &directory, field, maximum, blocked_extensions).await?;
        Ok(StagedAdminUpload {
            pending,
            name,
            total,
            directory,
            overwrite_existing,
            directory_durability_uncertain,
            permits: self.permits,
        })
    }
}

impl StagedAdminUpload {
    fn prepare(self) -> PreparedAdminUpload {
        let Self {
            pending,
            name,
            total,
            directory,
            overwrite_existing,
            directory_durability_uncertain,
            permits,
        } = self;
        PreparedAdminUpload {
            pending,
            name,
            total,
            directory,
            overwrite_existing,
            directory_durability_uncertain,
            permits,
        }
    }
}

impl PreparedAdminUpload {
    fn commit(
        self,
        storage_guard: crate::storage_authority::StorageMutationGuard,
        existed: bool,
    ) -> CommittedAdminUpload {
        CommittedAdminUpload {
            upload: self,
            storage_guard,
            existed,
        }
    }
}

async fn normalized_multipart_path(
    field: axum::extract::multipart::Field<'_>,
    message: &'static str,
) -> Result<String> {
    let value = limited_multipart_text(field, MAX_UPLOAD_PATH_FIELD_BYTES)
        .await
        .map_err(|error| admin_multipart_text_error(error.as_ref(), message))?;
    Ok(path_security::validate_relative(&value)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, message))?
        .to_string_lossy()
        .replace('\\', "/"))
}

async fn acquire_admin_upload_permits(
    state: &FileRouteState,
    headers: &HeaderMap,
    proof: MfaSessionProof,
) -> Result<AdminUploadPermits> {
    let upload_permit = state.try_acquire_upload().map_err(|_| {
        AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent uploads",
        )
    })?;
    let peer_permit = state
        .try_acquire_upload_peer(current_client_limit_key())
        .ok_or(AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent uploads from this client",
        ))?;
    verify_admin_upload_capacity(state, headers).await?;
    Ok(AdminUploadPermits {
        global: upload_permit,
        peer: peer_permit,
        proof,
    })
}

async fn verify_admin_upload_capacity(state: &FileRouteState, headers: &HeaderMap) -> Result<()> {
    let Some(length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return Ok(());
    };
    match storage_has_room(state, length).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(AppError(
            StatusCode::INSUFFICIENT_STORAGE,
            "Not enough free storage",
        )),
        Err(_) => Err(AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Storage capacity could not be determined",
        )),
    }
}

async fn parse_admin_upload(
    state: &FileRouteState,
    admin: &crate::db::Session,
    mut multipart: Multipart,
    authorization: AuthorizedAdminUpload,
) -> Result<PreparedAdminUpload> {
    let settings = runtime_settings(state);
    let mut parser = AdminUploadParser::new(authorization);
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| admin_multipart_read_error(&error, "Invalid upload"))?
    {
        parser.record_field()?;
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "path" => parser.path_field(field).await?,
            "csrf" => parser.csrf_field(admin, field).await?,
            "overwrite_existing" => parser.overwrite_field(state, field).await?,
            "folder_path" => parser.folder_path_field(field).await?,
            "file" => parser.file_field(state, admin, field, &settings).await?,
            _ => return Err(AppError(StatusCode::BAD_REQUEST, "Unknown multipart field")),
        }
    }
    parser.finish()
}

pub(super) async fn process_admin_upload(
    state: &FileRouteState,
    headers: &HeaderMap,
    multipart: Multipart,
) -> Result<AdminUploadSuccess> {
    let authorization = mfa_session(state, headers, MissingSession::RedirectToLogin).await?;
    let (admin, proof) = authorization.into_parts();
    let authorization = AuthorizedAdminUpload {
        permits: acquire_admin_upload_permits(state, headers, proof).await?,
    };
    let mut upload = parse_admin_upload(state, &admin, multipart, authorization).await?;
    apply_admin_upload_test_fault(state, &mut upload);
    let audit_client_ip = current_audit_client_ip();
    let audit_context = AuditContext::new(admin.username, enabled_audit_client_ip(state));
    let task_state = state.clone();
    let finalizer = tokio::spawn(
        with_audit_client_ip(audit_client_ip, async move {
            finalize_admin_upload(&task_state, upload, audit_context).await
        })
        .instrument(tracing::Span::current()),
    );
    finalizer.await.map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebAdminUploadFinalizerJoin,
            error,
        ))
    })?
}

#[cfg(test)]
fn apply_admin_upload_test_fault(state: &FileRouteState, upload: &mut PreparedAdminUpload) {
    if let Some(kind) = state.take_upload_directory_sync_failure_for_test() {
        upload.pending.fail_next_directory_sync(kind);
    }
}

#[cfg(not(test))]
fn apply_admin_upload_test_fault(_state: &FileRouteState, _upload: &mut PreparedAdminUpload) {}

async fn finalize_admin_upload(
    state: &FileRouteState,
    upload: PreparedAdminUpload,
    audit_context: AuditContext,
) -> Result<AdminUploadSuccess> {
    let committed = commit_admin_upload(state, upload).await?;
    let publication = publish_admin_upload(state, committed, audit_context).await?;
    finish_admin_upload(publication)
}

async fn commit_admin_upload(
    state: &FileRouteState,
    upload: PreparedAdminUpload,
) -> Result<CommittedAdminUpload> {
    let storage_guard = file_ops::acquire_storage_mutation(state)
        .await
        .map_err(storage_recovery_app_error)?;
    let root = state.secure_root().clone();
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _entered = span.enter();
        let existed = inspect_admin_upload_target(&root, &upload)?;
        Ok(upload.commit(storage_guard, existed))
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebAdminUploadStageTaskJoin,
            error,
        ))
    })?
}

fn inspect_admin_upload_target(
    root: &crate::secure_fs::SecureRoot,
    upload: &PreparedAdminUpload,
) -> Result<bool> {
    let current_destination = root.bind_directory(&upload.directory).map_err(|_| {
        AppError(
            StatusCode::CONFLICT,
            "Upload target changed in the meantime",
        )
    })?;
    if !upload
        .pending
        .destination_matches(&current_destination)
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebAdminUploadDestinationMatch,
                error,
            ))
        })?
    {
        return Err(AppError(
            StatusCode::CONFLICT,
            "Upload target changed in the meantime",
        ));
    }
    let destination = join_display(&upload.directory, &upload.name);
    match root.metadata(&destination) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AppError::from(report_internal(
            InternalOperation::WebAdminUploadDestinationMetadata,
            error,
        ))),
    }
}

async fn publish_admin_upload(
    state: &FileRouteState,
    committed: CommittedAdminUpload,
    audit_context: AuditContext,
) -> Result<PublishedAdminUpload> {
    let database = state.db().clone();
    let database_permit = file_ops::acquire_database_permit(&database)
        .await
        .map_err(file_operation_app_error)?;
    let result = tokio::task::spawn_blocking(move || {
        publish_admin_upload_blocking(&database, database_permit, committed, &audit_context)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebAdminUploadPublishTaskJoin,
            error,
        ))
    })?;
    match result.map_err(admin_upload_publish_error)? {
        SessionBound::Authorized(outcome) => Ok(outcome),
        SessionBound::SessionUnavailable => Err(AppError(
            StatusCode::UNAUTHORIZED,
            ADMIN_UPLOAD_SESSION_REVOKED,
        )),
    }
}

fn publish_admin_upload_blocking(
    database: &crate::db::Database,
    database_permit: tokio::sync::OwnedSemaphorePermit,
    committed: CommittedAdminUpload,
    audit_context: &AuditContext,
) -> std::result::Result<SessionBound<PublishedAdminUpload>, file_ops::FileOperationError> {
    let _database_permit = database_permit;
    let CommittedAdminUpload {
        upload,
        storage_guard,
        existed,
    } = committed;
    let PreparedAdminUpload {
        mut pending,
        name,
        total,
        directory,
        overwrite_existing,
        directory_durability_uncertain,
        permits,
    } = upload;
    let AdminUploadPermits {
        global: _global_permit,
        peer: _peer_permit,
        proof,
    } = permits;
    let replaced = overwrite_existing && existed;
    let destination = join_display(&directory, &name);
    let detail = format!("file={name};bytes={total};path={destination}");
    let action = if replaced {
        AuditAction::AdminUploadReplaced
    } else {
        AuditAction::AdminUpload
    };
    let mut published_snapshot = None;
    let result = database.run_required_session_audit(|database| {
        database.required_transaction_for_mfa_session_audited(
            &proof,
            audit_context,
            |_transaction| {
                publish_admin_file(
                    &mut pending,
                    &name,
                    overwrite_existing,
                    action,
                    &destination,
                    &detail,
                    &mut published_snapshot,
                )
            },
        )
    });
    let result =
        recover_admin_upload_audit_uncertainty(result, published_snapshot, action, &destination);
    if result.is_ok() {
        storage_guard.finish_clean();
    }
    Ok(match result? {
        SessionBound::Authorized((durability_uncertain, audit_uncertain)) => {
            SessionBound::Authorized(PublishedAdminUpload {
                name,
                directory,
                replaced,
                durability_uncertain,
                audit_uncertain,
                directory_durability_uncertain,
            })
        }
        SessionBound::SessionUnavailable => SessionBound::SessionUnavailable,
    })
}

fn publish_admin_file(
    pending: &mut PendingUpload,
    name: &str,
    overwrite_existing: bool,
    action: AuditAction,
    destination: &str,
    detail: &str,
    published_snapshot: &mut Option<bool>,
) -> std::result::Result<(bool, Vec<RequiredAuditEvent>), file_ops::FileOperationError> {
    let outcome = if overwrite_existing {
        pending.publish_replace(name)
    } else {
        pending.publish(name)
    }
    .map_err(file_ops::FileOperationError::Io)?;
    let durability_uncertain = !outcome.is_durable();
    *published_snapshot = Some(durability_uncertain);
    let mut events = vec![RequiredAuditEvent::new(
        action,
        Some(destination.to_string()),
        Some(detail.to_string()),
    )];
    if let Some(error) = outcome.uncertainty_error() {
        tracing::warn!(
            file = %EscapedLogPath::new(name),
            error = %EscapedLogValue::new(error),
            "admin upload publication or directory durability is uncertain"
        );
        events.push(RequiredAuditEvent::new(
            AuditAction::AdminUploadDurabilityUncertain,
            Some(destination.to_string()),
            Some(detail.to_string()),
        ));
    }
    Ok((durability_uncertain, events))
}

fn recover_admin_upload_audit_uncertainty(
    result: std::result::Result<SessionBound<bool>, file_ops::FileOperationError>,
    published_snapshot: Option<bool>,
    action: AuditAction,
    destination: &str,
) -> std::result::Result<SessionBound<(bool, bool)>, file_ops::FileOperationError> {
    match result {
        Ok(SessionBound::Authorized(durability_uncertain)) => {
            Ok(SessionBound::Authorized((durability_uncertain, false)))
        }
        Ok(SessionBound::SessionUnavailable) => Ok(SessionBound::SessionUnavailable),
        Err(file_ops::FileOperationError::Database(error)) if published_snapshot.is_some() => {
            let durability_uncertain =
                published_snapshot.expect("published upload snapshot recorded");
            tracing::error!(
                error = %EscapedLogValue::new(&error),
                action = action.as_str(),
                path = %EscapedLogPath::new(destination),
                "admin upload is visible but required audit durability is uncertain"
            );
            Ok(SessionBound::Authorized((durability_uncertain, true)))
        }
        Err(error) => Err(error),
    }
}

fn admin_upload_publish_error(error: file_ops::FileOperationError) -> AppError {
    match error {
        file_ops::FileOperationError::Io(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            AppError(
                StatusCode::CONFLICT,
                "File already exists; replacement must be confirmed for this file",
            )
        }
        file_ops::FileOperationError::Io(error) => upload_io_error(error),
        other => file_operation_app_error(other),
    }
}

fn finish_admin_upload(publication: PublishedAdminUpload) -> Result<AdminUploadSuccess> {
    let disposition = match (publication.replaced, publication.durability_uncertain) {
        (true, true) => UploadDisposition::ReplacedUncertain,
        (false, true) => UploadDisposition::CreatedUncertain,
        (true, false) => UploadDisposition::Replaced,
        (false, false) => UploadDisposition::Created,
    };
    Ok(AdminUploadSuccess {
        file: publication.name,
        disposition,
        directory: publication.directory,
        audit_durability_uncertain: publication.directory_durability_uncertain
            || publication.durability_uncertain
            || publication.audit_uncertain,
    })
}
