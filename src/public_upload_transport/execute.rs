pub(crate) async fn execute_public_upload(
    state: AppState,
    headers: &HeaderMap,
    token: String,
    mut multipart: Multipart,
    prechecked_upload_id: Option<crate::upload_operation::UploadIdSelection>,
) -> Result<PublicUploadOutcome> {
    let share = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, headers, &share).await? {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError::new(StatusCode::FORBIDDEN, "Upload not allowed"));
    }
    let required_csrf = share_unlock_csrf(&state, headers, &share).await?;
    if share.password_hash.is_some() && required_csrf.is_none() {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "Share is locked"));
    }

    let selection = match prechecked_upload_id {
        Some(selection) => selection,
        None => crate::upload_operation::take_upload_id(&mut multipart, headers)
            .await
            .map_err(|message| AppError::new(StatusCode::BAD_REQUEST, message))?,
    };
    let upload_id = selection.id;
    let prefix = selection.prefix;
    let share_id = share.id;
    let claim_id = upload_id.clone();
    let claim = database(state.db().clone(), move |db| {
        db.claim_upload_operation(UploadOperationScope::Share(share_id), &claim_id)
    })
    .await?;
    match claim {
        UploadOperationClaim::Started => {}
        UploadOperationClaim::Unavailable => {
            return Err(AppError::new(
                StatusCode::GONE,
                "Upload operation unavailable",
            ));
        }
        UploadOperationClaim::Existing(view) => {
            if view.state == "completed" {
                return replay_public_upload(
                    view,
                    multipart,
                    &upload_id,
                    prefix,
                    headers,
                    &share,
                    required_csrf.as_deref(),
                )
                .await;
            }
            if view.state == "outcome_unknown" {
                return Err(AppError::new(
                    StatusCode::CONFLICT,
                    "Upload outcome is unknown; check its status",
                ));
            }
            if view.state == "rejected" {
                return Err(AppError::new(
                    StatusCode::CONFLICT,
                    "Upload operation was rejected; create a new operation",
                ));
            }
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "Upload operation already started; check its status",
            ));
        }
    }
    execute_claimed_public_upload(state, headers, token, multipart, share, prefix, upload_id).await
}

async fn execute_claimed_public_upload(
    state: AppState,
    headers: &HeaderMap,
    token: String,
    multipart: Multipart,
    share: Share,
    prefix: Vec<crate::upload_operation::UploadPrefixField>,
    upload_id: String,
) -> Result<PublicUploadOutcome> {
    let claim_guard =
        crate::upload_operation::UploadClaimGuard::new(state.db().clone(), &upload_id);

    let (share, share_scope, required_csrf, csrf_header_valid, authorized_upload) =
        reauthorize_claimed_public_upload(&state, headers, &token, share.id).await?;

    let settings = runtime_settings(&state);
    let maximum = share
        .max_upload_size
        .unwrap_or(settings.max_upload_size)
        .min(crate::config::MAX_UPLOAD_SIZE);
    if let Some(length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        match storage_has_room(&state, length).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(rejected(
                    "",
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Not enough free storage",
                ))
            }
            Err(_) => {
                return Ok(rejected(
                    "",
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Storage capacity could not be determined",
                ))
            }
        }
    }

    let form_phase = PublicUploadFormPhase {
        state: &state,
        token: &token,
        share: &share,
        share_scope,
        settings: &settings,
        maximum,
        required_csrf: required_csrf.as_deref(),
        csrf_header_valid,
        authorized_upload,
        upload_id: &upload_id,
        prefix,
    };
    let mut upload = match form_phase.run(multipart).await {
        Ok(upload) => upload,
        Err(PublicUploadPhaseError::Rejection(rejection)) => {
            let operation_hash = claim_guard.id_hash().to_owned();
            let receipt = serde_json::json!({
                "status": rejection.status().as_u16(),
                "reason": rejection.reason_code(),
                "upload_subdir": rejection.upload_subdir(),
            });
            database(state.db().clone(), move |db| {
                db.finish_upload_operation(&operation_hash, "rejected", Some(&receipt))
            })
            .await?;
            return Ok(PublicUploadOutcome::Rejected(rejection));
        }
        Err(PublicUploadPhaseError::App(error)) => return Err(error),
    };

    let fingerprint = upload.fingerprint();
    let fragment_name = upload.pending.fragment_name().to_owned();
    let bound_fragment_name = fragment_name.clone();
    let operation_hash = claim_guard.id_hash().to_owned();
    let bind_hash = operation_hash.clone();
    let bound = database(state.db().clone(), move |db| {
        db.bind_upload_fingerprint(&bind_hash, &fingerprint, &bound_fragment_name)
    })
    .await?;
    if !bound {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "Upload operation content differs",
        ));
    }
    let committing_hash = operation_hash.clone();
    let committing = database(state.db().clone(), move |db| {
        db.mark_upload_committing(&committing_hash)
    })
    .await?;
    if !committing {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "Upload operation changed",
        ));
    }
    upload.pending.retain_for_upload_operation();

    let audit_client_ip = current_audit_client_ip();
    let locale = i18n::current_locale();
    let return_to = i18n::current_return_to();
    let audit_context = AuditContext::new("public", enabled_audit_client_ip(&state));
    let finalizer = PublicUploadFinalizer {
        state,
        token,
        upload,
        audit_context,
        operation_hash: operation_hash.clone(),
    };
    run_public_upload_finalizer(
        finalizer,
        claim_guard,
        audit_client_ip,
        locale,
        return_to,
        operation_hash,
        fragment_name,
    )
    .await
}

async fn reauthorize_claimed_public_upload(
    state: &AppState,
    headers: &HeaderMap,
    token: &str,
    expected_id: i64,
) -> Result<(
    Share,
    SecureDirectory,
    Option<String>,
    bool,
    AuthorizedUpload,
)> {
    let (share, storage_guard) = get_storage_share(state, token, expected_id).await?;
    if !share_is_unlocked(&state, headers, &share).await? {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !share.is_directory || !share.permission.can_upload() {
        return Err(AppError::new(StatusCode::FORBIDDEN, "Upload not allowed"));
    }
    let required_csrf = share_unlock_csrf(&state, headers, &share).await?;
    if share.password_hash.is_some() && required_csrf.is_none() {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    let csrf_header_valid = required_csrf.as_ref().is_some_and(|expected| {
        headers
            .get("x-vaultlink-upload-csrf")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| auth::constant_time_eq(expected, value))
    });

    let public_upload_permit = state.try_acquire_public_upload().map_err(|_| {
        AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent public uploads",
        )
    })?;
    let upload_permit = state.try_acquire_upload().map_err(|_| {
        AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent uploads",
        )
    })?;
    let upload_peer_permit = state
        .try_acquire_upload_peer(current_client_limit_key())
        .ok_or(AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent uploads from this client",
        ))?;
    let upload_share_permit = state
        .try_acquire_upload_share(share.id)
        .ok_or(AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent uploads for this share",
        ))?;
    let authorized_upload = AuthorizedUpload::new(PublicUploadAdmission {
        _public: public_upload_permit,
        _upload: upload_permit,
        _peer: upload_peer_permit,
        _share: upload_share_permit,
    });
    let secure_root = state.secure_root().clone();
    let share_path = share.relative_path.clone();
    let share_scope = tokio::task::spawn_blocking(move || {
        // The capability open can block on remote storage. Retain namespace
        // authority in the detached blocking task if the HTTP request is
        // cancelled, then release it as soon as the descriptor is bound.
        let _storage_guard = storage_guard;
        secure_root.bind_directory(&share_path)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebPublicUploadBindDestination,
            error,
        ))
    })?
    .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "Target folder unavailable"))?;
    // The descriptor remains bound to the revalidated directory, so a long
    // request body cannot block admin namespace operations.

    Ok((
        share,
        share_scope,
        required_csrf,
        csrf_header_valid,
        authorized_upload,
    ))
}

async fn replay_public_upload(
    view: UploadOperationView,
    multipart: Multipart,
    upload_id: &str,
    prefix: Vec<crate::upload_operation::UploadPrefixField>,
    headers: &HeaderMap,
    share: &Share,
    required_csrf: Option<&str>,
) -> Result<PublicUploadOutcome> {
    let csrf_header_valid = required_csrf.is_some_and(|expected| {
        headers
            .get("x-vaultlink-upload-csrf")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| auth::constant_time_eq(expected, value))
    });
    let fingerprint = crate::upload_operation::replay_fingerprint(
        multipart,
        upload_id,
        prefix,
        crate::upload_operation::ReplayKind::Public {
            permission: share.permission,
            csrf: required_csrf,
            csrf_header_valid,
        },
    )
    .await
    .map_err(|message| match message {
        "Upload IDs disagree" => AppError::new(StatusCode::BAD_REQUEST, message),
        "Invalid CSRF proof" | "CSRF proof missing" => {
            AppError::new(StatusCode::FORBIDDEN, message)
        }
        _ => AppError::new(StatusCode::CONFLICT, "Upload ID conflicts with request"),
    })?;
    if view.fingerprint.as_deref() != Some(&fingerprint) {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "Upload ID conflicts with request",
        ));
    }
    let success = view
        .result
        .as_ref()
        .and_then(PublicUploadSuccess::from_receipt)
        .ok_or(AppError::new(
            StatusCode::CONFLICT,
            "Upload outcome unavailable",
        ))?;
    Ok(PublicUploadOutcome::Success(success))
}
