pub(super) async fn process_admin_upload(
    state: &FileRouteState,
    headers: &HeaderMap,
    mut multipart: Multipart,
    prechecked_upload_id: Option<crate::upload_operation::UploadIdSelection>,
) -> Result<AdminUploadSuccess> {
    let authorization = mfa_session(state, headers, MissingSession::RedirectToLogin).await?;
    let (admin, proof) = authorization.into_parts();
    let selection = match prechecked_upload_id {
        Some(selection) => selection,
        None => crate::upload_operation::take_upload_id(&mut multipart, headers)
            .await
            .map_err(|message| AppError(StatusCode::BAD_REQUEST, message))?,
    };
    let upload_id = selection.id;
    let prefix = selection.prefix;
    let admin_id = admin.admin_id;
    let claim_id = upload_id.clone();
    let claim = crate::http_auth::database(state.db().clone(), move |db| {
        db.claim_upload_operation(crate::db::UploadOperationScope::Admin(admin_id), &claim_id)
    })
    .await?;
    match claim {
        crate::db::UploadOperationClaim::Started => {}
        crate::db::UploadOperationClaim::Unavailable => {
            return Err(AppError(StatusCode::GONE, "Upload operation unavailable"));
        }
        crate::db::UploadOperationClaim::Existing(view) => {
            if view.state == "completed" {
                return replay_admin_upload(view, multipart, &upload_id, prefix, &admin).await;
            }
            if view.state == "outcome_unknown" {
                return Err(AppError(
                    StatusCode::CONFLICT,
                    "Upload outcome is unknown; check its status",
                ));
            }
            if view.state == "rejected" {
                return Err(AppError(
                    StatusCode::CONFLICT,
                    "Upload operation was rejected; create a new operation",
                ));
            }
            return Err(AppError(
                StatusCode::CONFLICT,
                "Upload operation already started; check its status",
            ));
        }
    }
    let claim_guard =
        crate::upload_operation::UploadClaimGuard::new(state.db().clone(), &upload_id);
    let authorization = AuthorizedAdminUpload {
        permits: acquire_admin_upload_permits(state, headers, proof).await?,
    };
    let operation_hash = claim_guard.id_hash().to_owned();
    let mut upload =
        parse_admin_upload(state, &admin, multipart, authorization, upload_id, prefix).await?;
    let fingerprint = upload.fingerprint();
    let fragment_name = upload.pending.fragment_name().to_owned();
    let bound_fragment_name = fragment_name.clone();
    let bound_hash = operation_hash.clone();
    if !crate::http_auth::database(state.db().clone(), move |db| {
        db.bind_upload_fingerprint(&bound_hash, &fingerprint, &bound_fragment_name)
    })
    .await?
    {
        return Err(AppError(
            StatusCode::CONFLICT,
            "Upload operation content differs",
        ));
    }
    let committing_hash = operation_hash.clone();
    if !crate::http_auth::database(state.db().clone(), move |db| {
        db.mark_upload_committing(&committing_hash)
    })
    .await?
    {
        return Err(AppError(StatusCode::CONFLICT, "Upload operation changed"));
    }
    upload.pending.retain_for_upload_operation();
    apply_admin_upload_test_fault(state, &mut upload);
    let audit_client_ip = current_audit_client_ip();
    let audit_context = AuditContext::new(admin.username, enabled_audit_client_ip(state));
    let task_state = state.clone();
    let operation_database = state.db().clone();
    let fragment_root = state.secure_root().clone();
    let finalizer = tokio::spawn(
        with_audit_client_ip(audit_client_ip, async move {
            let _claim_guard = claim_guard;
            let operation_guard = crate::upload_operation::UploadStorageGuard::default();
            let (result, safe_to_retry) =
                finalize_admin_upload(&task_state, upload, audit_context, &operation_guard).await;
            let (state_name, receipt) = match &result {
                Ok(success) => {
                    let mut receipt = serde_json::json!({
                        "file": success.file,
                        "directory": success.directory,
                        "outcome": success.disposition.outcome(),
                    });
                    if success.warnings.any() {
                        receipt["warning"] = serde_json::json!(success.warnings.legacy_code());
                        receipt["warnings"] = serde_json::json!(success.warnings.codes());
                    }
                    ("completed", Some(receipt))
                }
                Err(_) if safe_to_retry => ("retryable", None),
                Err(_) => ("outcome_unknown", None),
            };
            let saved = crate::http_auth::database(operation_database, move |db| {
                db.finish_upload_operation(&operation_hash, state_name, receipt.as_ref())
            })
            .await?;
            if !saved {
                return Err(AppError(StatusCode::CONFLICT, "Upload operation changed"));
            }
            if matches!(&result, Ok(success) if success.disposition != UploadDisposition::DirectoryUncertain) {
                operation_guard.finish_clean();
            }
            if state_name != "outcome_unknown" {
                let removed = tokio::task::spawn_blocking(move || {
                    fragment_root.remove_finished_upload_fragment(&fragment_name)
                })
                .await;
                if !matches!(removed, Ok(Ok(()))) {
                    task_state.request_storage_cleanup();
                }
            }
            task_state.request_storage_cleanup();
            result
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

async fn replay_admin_upload(
    view: crate::db::UploadOperationView,
    multipart: Multipart,
    upload_id: &str,
    prefix: Vec<crate::upload_operation::UploadPrefixField>,
    admin: &crate::db::Session,
) -> Result<AdminUploadSuccess> {
    let fingerprint = crate::upload_operation::replay_fingerprint(
        multipart,
        upload_id,
        prefix,
        crate::upload_operation::ReplayKind::Admin {
            csrf: &admin.csrf_token,
        },
    )
    .await
    .map_err(|_| AppError(StatusCode::CONFLICT, "Upload ID conflicts with request"))?;
    if view.fingerprint.as_deref() != Some(&fingerprint) {
        return Err(AppError(
            StatusCode::CONFLICT,
            "Upload ID conflicts with request",
        ));
    }
    let receipt = view
        .result
        .as_ref()
        .ok_or(AppError(StatusCode::CONFLICT, "Upload outcome unavailable"))?;
    let disposition = UploadDisposition::from_outcome(
        receipt
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .ok_or(AppError(StatusCode::CONFLICT, "Upload outcome unavailable"))?,
    )
    .ok_or(AppError(StatusCode::CONFLICT, "Upload outcome unavailable"))?;
    let warnings = receipt
        .get("warnings")
        .and_then(serde_json::Value::as_array);
    let audit = warnings
        .into_iter()
        .flatten()
        .any(|value| value.as_str() == Some("audit_durability_uncertain"));
    Ok(AdminUploadSuccess {
        file: receipt
            .get("file")
            .and_then(serde_json::Value::as_str)
            .ok_or(AppError(StatusCode::CONFLICT, "Upload outcome unavailable"))?
            .to_owned(),
        disposition,
        directory: receipt
            .get("directory")
            .and_then(serde_json::Value::as_str)
            .ok_or(AppError(StatusCode::CONFLICT, "Upload outcome unavailable"))?
            .to_owned(),
        audit_durability_uncertain: audit,
        warnings: crate::services::upload::UploadWarnings {
            storage: warnings
                .into_iter()
                .flatten()
                .any(|value| value.as_str() == Some("storage_durability_uncertain")),
            audit,
        },
    })
}
