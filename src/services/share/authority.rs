/// Serializes every administrator-controlled share-authority change with the
/// public-upload policy checkpoint.  The guard is moved into the blocking DB
/// task on commit, so cancelling the HTTP adapter cannot release the storage
/// lock before the database mutation has reached a terminal result.
pub(crate) struct ShareAuthorityMutation {
    database: Database,
    storage_guard: StorageMutationGuard,
    proof: MfaSessionProof,
}

impl ShareAuthorityMutation {
    pub(crate) async fn acquire(
        state: &(impl Borrow<AppState> + ?Sized),
        authorization: MfaMutationContext,
    ) -> Result<Self, ShareServiceError> {
        Ok(Self::from_guard(
            state,
            crate::file_ops::acquire_storage_mutation(state)
                .await
                .map_err(map_storage_authority_error)?,
            authorization,
        ))
    }

    pub(crate) fn from_guard(
        state: &(impl Borrow<AppState> + ?Sized),
        storage_guard: StorageMutationGuard,
        authorization: MfaMutationContext,
    ) -> Self {
        let state = state.borrow();
        let (_, proof) = authorization.into_parts();
        Self {
            database: state.db().clone(),
            storage_guard,
            proof,
        }
    }

    pub(crate) async fn commit<T, E, F>(
        self,
        operation: F,
    ) -> Result<SessionBound<Audited<T>>, ShareServiceError>
    where
        T: Send + 'static,
        E: IntoServiceError<ShareValidationError> + Send + 'static,
        F: FnOnce(Database, MfaSessionProof) -> Result<SessionBound<Audited<T>>, E>
            + Send
            + 'static,
    {
        let Self {
            database,
            storage_guard,
            proof,
        } = self;
        crate::db::execute_database_operation(database, "required_audit", move |database| {
            let result = operation(database, proof);
            storage_guard.finish_clean();
            result
        })
        .await
        .map_err(map_database_execution_error)
    }

    pub(crate) async fn commit_decision<T, R, E, F>(
        self,
        operation: F,
    ) -> Result<SessionBound<crate::db::RequiredAuditDecision<T, R>>, ShareServiceError>
    where
        T: Send + 'static,
        R: Send + 'static,
        E: IntoServiceError<ShareValidationError> + Send + 'static,
        F: FnOnce(
                Database,
                MfaSessionProof,
            ) -> Result<SessionBound<crate::db::RequiredAuditDecision<T, R>>, E>
            + Send
            + 'static,
    {
        let Self {
            database,
            storage_guard,
            proof,
        } = self;
        crate::db::execute_database_operation(database, "required_audit", move |database| {
            let result = operation(database, proof);
            storage_guard.finish_clean();
            result
        })
        .await
        .map_err(map_database_execution_error)
    }
}

fn map_database_execution_error<E>(error: DatabaseExecutionError<E>) -> ShareServiceError
where
    E: IntoServiceError<ShareValidationError>,
{
    match error {
        DatabaseExecutionError::Admission(error) => {
            ShareServiceError::Capacity(ServiceFailure::database_executor_admission(error))
        }
        DatabaseExecutionError::Join(error) => ShareServiceError::Internal(
            ServiceFailure::database_executor_join("required_audit", error),
        ),
        DatabaseExecutionError::Operation(error) => error.into_service_error(),
    }
}
