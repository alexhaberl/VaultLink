use super::Database;
use chrono::Utc;
use rusqlite::{params, TransactionBehavior};

impl Database {
    pub fn runtime_settings(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let c = self.conn();
        let mut statement = c.prepare("SELECT key,value FROM runtime_settings ORDER BY key")?;
        let settings = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect();
        settings
    }
    pub fn replace_runtime_settings(
        &self,
        settings: &[(&str, String)],
        admin: i64,
    ) -> rusqlite::Result<()> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM runtime_settings", [])?;
        let updated_at = Utc::now().to_rfc3339();
        {
            let mut statement = transaction.prepare(
                "INSERT INTO runtime_settings(key,value,updated_by,updated_at)
                 VALUES(?1,?2,?3,?4)",
            )?;
            for (key, value) in settings {
                statement.execute(params![*key, value.as_str(), admin, updated_at])?;
            }
        }
        transaction.commit()
    }
}
