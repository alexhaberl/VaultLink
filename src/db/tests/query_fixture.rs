pub(crate) fn large_share_fixture(count: i64) -> Database {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    database
        .create_share(
            "seed",
            None,
            "file.bin",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    database
        .conn()
        .execute(
            "WITH RECURSIVE ids(id) AS (SELECT 2 UNION ALL SELECT id+1 FROM ids WHERE id<?1)
         INSERT INTO shares(id,token_hash,token_key_id,token_ciphertext,relative_path,
             path_search_key,is_directory,permission,created_by,created_at)
         SELECT ids.id,CAST(ids.id AS TEXT),seed.token_key_id,seed.token_ciphertext,
             seed.relative_path,seed.path_search_key,0,'download_only',1,seed.created_at
         FROM ids CROSS JOIN shares seed WHERE seed.id=1",
            [count],
        )
        .unwrap();
    database
}
