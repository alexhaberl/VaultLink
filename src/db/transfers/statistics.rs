impl Database {
    pub fn transfer_statistics_started_at(&self) -> rusqlite::Result<String> {
        self.try_conn()?.query_row(
            "SELECT started_at FROM transfer_statistics WHERE singleton=1",
            [],
            |row| row.get(0),
        )
    }
    pub fn transfer_monthly_counts(&self, month: &str) -> rusqlite::Result<TransferMonthlyCounts> {
        if !valid_utc_month(month) {
            return Err(rusqlite::Error::InvalidParameterName(
                "month must use UTC YYYY-MM".into(),
            ));
        }
        let connection = self.try_conn()?;
        let mut statement = connection.prepare(
            "SELECT action,count FROM transfer_monthly_counts WHERE month=?1 ORDER BY action",
        )?;
        let mut counts = TransferMonthlyCounts {
            month: month.to_string(),
            download: 0,
            zip_download: 0,
            preview: 0,
        };
        for row in statement.query_map([month], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })? {
            let (action, count) = row?;
            match action.as_str() {
                "download" => counts.download = count,
                "zip_download" => counts.zip_download = count,
                "preview" => counts.preview = count,
                _ => return Err(rusqlite::Error::InvalidQuery),
            }
        }
        Ok(counts)
    }
    pub fn current_transfer_monthly_counts(&self) -> rusqlite::Result<TransferMonthlyCounts> {
        self.transfer_monthly_counts(&current_utc_month())
    }
}
