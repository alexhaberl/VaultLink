impl Database {
    pub(crate) fn populate_encrypted_share_fixture(&self, count: i64) {
        let mut connection = self.conn();
        let transaction = connection.transaction().unwrap();
        {
            let mut insert = transaction
                .prepare(
                    "INSERT INTO shares(id,token_hash,token_key_id,token_ciphertext,
                relative_path,path_search_key,is_directory,permission,created_by,created_at)
                VALUES(?1,?2,?3,?4,'file.txt','file.txt',0,'download_only',1,?5)",
                )
                .unwrap();
            let now = Utc::now().to_rfc3339();
            for id in 1..=count {
                let token = format!("benchmark-share-{id}");
                let digest = token_hash(&token);
                let (key, ciphertext) = self
                    .encrypt_secret(
                        token.as_bytes(),
                        format!("shares.token:{digest}").as_bytes(),
                    )
                    .unwrap();
                insert
                    .execute(params![id, digest, key, ciphertext, now])
                    .unwrap();
            }
        }
        transaction.commit().unwrap();
    }
}

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
