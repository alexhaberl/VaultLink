macro_rules! monitoring_share_query {
    ($predicate:literal) => {
        concat!(
            "SELECT shares.id,\n",
            "       CASE\n",
            "           WHEN shares.active=0 THEN 'inactive'\n",
            "           WHEN shares.expires_at IS NOT NULL AND shares.expires_at<=?1\n",
            "               THEN 'expired'\n",
            "           WHEN shares.max_downloads IS NOT NULL\n",
            "                AND shares.download_count>=shares.max_downloads\n",
            "               THEN 'download_limit_reached'\n",
            "           ELSE 'available'\n",
            "       END AS status,\n",
            "       shares.permission, shares.is_directory,\n",
            "       shares.password_hash IS NOT NULL AS password_protected,\n",
            "       shares.created_at, shares.expires_at, shares.download_count,\n",
            "       shares.max_downloads, shares.max_upload_size,\n",
            "       COALESCE(usage.uploaded_bytes,0) AS uploaded_bytes,\n",
            "       shares.max_upload_total_size,\n",
            "       COALESCE(usage.uploaded_files,0) AS uploaded_files,\n",
            "       shares.max_upload_files\n",
            "FROM shares\n",
            "LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id\n",
            "WHERE ",
            $predicate,
            "\n  AND (?2 IS NULL OR shares.id<?2)\n",
            "ORDER BY shares.id DESC\n",
            "LIMIT ?3"
        )
    };
}

const MONITORING_SHARES_ALL: &str = monitoring_share_query!("1=1");
const MONITORING_SHARES_INACTIVE: &str = monitoring_share_query!("shares.active=0");
const MONITORING_SHARES_EXPIRED: &str = monitoring_share_query!(
    "shares.active=1 AND shares.expires_at IS NOT NULL AND shares.expires_at<=?1"
);
const MONITORING_SHARES_DOWNLOAD_LIMIT: &str = monitoring_share_query!(
    "shares.active=1 AND (shares.expires_at IS NULL OR shares.expires_at>?1)\n\
     AND shares.max_downloads IS NOT NULL AND shares.download_count>=shares.max_downloads"
);
const MONITORING_SHARES_AVAILABLE: &str = monitoring_share_query!(
    "shares.active=1 AND (shares.expires_at IS NULL OR shares.expires_at>?1)\n\
     AND (shares.max_downloads IS NULL OR shares.download_count<shares.max_downloads)"
);

fn monitoring_share_query_for(status: MonitoringShareListStatus) -> &'static str {
    match status {
        MonitoringShareListStatus::All => MONITORING_SHARES_ALL,
        MonitoringShareListStatus::Available => MONITORING_SHARES_AVAILABLE,
        MonitoringShareListStatus::Inactive => MONITORING_SHARES_INACTIVE,
        MonitoringShareListStatus::Expired => MONITORING_SHARES_EXPIRED,
        MonitoringShareListStatus::DownloadLimitReached => MONITORING_SHARES_DOWNLOAD_LIMIT,
    }
}

impl Database {
    pub fn monitoring_summary(&self, now: DateTime<Utc>) -> rusqlite::Result<MonitoringSummary> {
        let month = now.format("%Y-%m").to_string();
        let now_string = now.to_rfc3339();
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction()?;
        let (total, inactive, expired, download_limit_reached, available, protected) = transaction
            .query_row(
                "SELECT
                     COUNT(*),
                     COALESCE(SUM(CASE WHEN active=0 THEN 1 ELSE 0 END),0),
                     COALESCE(SUM(CASE WHEN active=1 AND expires_at IS NOT NULL
                         AND expires_at<=?1 THEN 1 ELSE 0 END),0),
                     COALESCE(SUM(CASE WHEN active=1
                         AND (expires_at IS NULL OR expires_at>?1)
                         AND max_downloads IS NOT NULL
                         AND download_count>=max_downloads THEN 1 ELSE 0 END),0),
                     COALESCE(SUM(CASE WHEN active=1
                         AND (expires_at IS NULL OR expires_at>?1)
                         AND (max_downloads IS NULL OR download_count<max_downloads)
                         THEN 1 ELSE 0 END),0),
                     COALESCE(SUM(CASE WHEN password_hash IS NOT NULL THEN 1 ELSE 0 END),0)
                 FROM shares",
                [&now_string],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                    ))
                },
            )?;
        let statistics_started_at = transaction.query_row(
            "SELECT started_at FROM transfer_statistics WHERE singleton=1",
            [],
            |row| row.get::<_, String>(0),
        )?;
        let (download, zip_download, preview) = transaction.query_row(
            "SELECT
                 COALESCE(SUM(CASE WHEN action='download' THEN count ELSE 0 END),0),
                 COALESCE(SUM(CASE WHEN action='zip_download' THEN count ELSE 0 END),0),
                 COALESCE(SUM(CASE WHEN action='preview' THEN count ELSE 0 END),0)
             FROM transfer_monthly_counts WHERE month=?1",
            [&month],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            },
        )?;
        transaction.commit()?;
        Ok(MonitoringSummary {
            total,
            available,
            inactive,
            expired,
            download_limit_reached,
            protected,
            transfers: TransferMonthlyCounts {
                month,
                download,
                zip_download,
                preview,
            },
            statistics_started_at,
        })
    }

    pub fn list_monitoring_share_page(
        &self,
        options: &MonitoringShareListOptions,
    ) -> rusqlite::Result<MonitoringSharePage> {
        let limit = options.limit.clamp(1, 200);
        let connection = self.try_conn()?;
        let mut statement =
            connection.prepare_cached(monitoring_share_query_for(options.status))?;
        let mut shares = statement
            .query_map(
                params![
                    options.now.to_rfc3339(),
                    options.cursor,
                    limit.saturating_add(1) as i64,
                ],
                |row| {
                    let status = parse_monitoring_status(&row.get::<_, String>(1)?)?;
                    let permission = Permission::parse(&row.get::<_, String>(2)?)
                        .ok_or(rusqlite::Error::InvalidQuery)?;
                    let expires_at = parse_optional_timestamp(row.get::<_, Option<String>>(6)?, 6)?;
                    Ok(MonitoringShare {
                        id: row.get(0)?,
                        status,
                        permission,
                        is_directory: row.get::<_, i64>(3)? != 0,
                        password_protected: row.get::<_, i64>(4)? != 0,
                        created_at: row.get(5)?,
                        expires_at,
                        download_count: row.get(7)?,
                        max_downloads: row.get(8)?,
                        max_upload_size_bytes: row.get(9)?,
                        uploaded_bytes: row.get(10)?,
                        max_upload_total_size_bytes: row.get(11)?,
                        uploaded_files: row.get(12)?,
                        max_upload_files: row.get(13)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let next_cursor = if shares.len() > limit {
            shares.pop();
            shares.last().map(|share| share.id)
        } else {
            None
        };
        Ok(MonitoringSharePage {
            shares,
            next_cursor,
        })
    }
}
