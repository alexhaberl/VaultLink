type LegacySchemaFixture = fn() -> (tempfile::TempDir, PathBuf);

#[test]
fn missing_or_empty_migration_records_block_legacy_upgrades_without_changing_version() {
    let fixtures: [(i64, LegacySchemaFixture); 6] = [
        (2, schema_two_fixture),
        (3, schema_three_fixture),
        (4, schema_four_fixture),
        (5, schema_five_fixture),
        (6, schema_six_fixture),
        (7, schema_seven_fixture),
    ];
    for (version, fixture) in fixtures {
        for empty_record in [false, true] {
            let (_directory, path) = fixture();
            let connection = Connection::open(&path).unwrap();
            let sql = if empty_record {
                "UPDATE vaultlink_schema_migrations SET applied_at='' WHERE target_version=?1"
            } else {
                "DELETE FROM vaultlink_schema_migrations WHERE target_version=?1"
            };
            assert_eq!(connection.execute(sql, [version]).unwrap(), 1);
            drop(connection);
            let Err(error) = Database::open(&path) else {
                panic!("schema {version} with corrupt migration evidence was upgraded");
            };
            assert!(
                error
                    .to_string()
                    .contains("migration record is missing or invalid"),
                "{error}"
            );
            let connection = Connection::open(&path).unwrap();
            let after: i64 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap();
            assert_eq!(
                after, version,
                "rejected upgrades must preserve the original schema version"
            );
        }
    }
}
