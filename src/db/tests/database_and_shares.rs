#[test]
fn persistent_database_is_regular_private_and_not_linked() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("data.sqlite");
    std::fs::write(&path, []).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

    let database = Database::open(&path).unwrap();
    drop(database);
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.mode() & 0o7777, 0o600);

    let hard_link = directory.path().join("data-hard-link.sqlite");
    std::fs::hard_link(&path, &hard_link).unwrap();
    assert!(Database::open(&path).is_err());

    let symlink = directory.path().join("data-symlink.sqlite");
    std::os::unix::fs::symlink(&path, &symlink).unwrap();
    assert!(Database::open(&symlink).is_err());
    assert!(Database::open(directory.path()).is_err());
}

#[test]
fn database_open_stays_bound_to_the_validated_directory_capability() {
    let parent = tempfile::tempdir().unwrap();
    let configured = parent.path().join("data");
    let displaced = parent.path().join("data-validated");
    std::fs::create_dir(&configured).unwrap();
    std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700)).unwrap();
    let capability = File::open(&configured).unwrap();

    std::fs::rename(&configured, &displaced).unwrap();
    std::fs::create_dir(&configured).unwrap();

    let database = Database::open_in_directory(capability).unwrap();
    assert_eq!(database.admin_count().unwrap(), 0);
    drop(database);

    assert!(displaced.join("data.sqlite").is_file());
    assert!(!configured.join("data.sqlite").exists());
}

#[test]
fn file_mutations_update_only_exact_share_subtrees() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let mut ids = Vec::new();
    for (index, path) in ["foo", "foo/child.txt", "foobar", "other"]
        .into_iter()
        .enumerate()
    {
        ids.push(
            database
                .create_share(
                    &format!("token-{index}"),
                    None,
                    path,
                    path == "foo",
                    &Permission::DownloadOnly,
                    None,
                    None,
                    None,
                    1,
                    None,
                    &UploadConflictStrategy::Reject,
                )
                .unwrap(),
        );
    }
    database.set_share_active(ids[1], false).unwrap();
    assert_eq!(
        database.rename_share_paths("foo", "renamed", true).unwrap(),
        2
    );
    let shares = database.list_shares().unwrap();
    assert!(shares.iter().any(|share| share.relative_path == "renamed"));
    assert!(shares
        .iter()
        .any(|share| share.relative_path == "renamed/child.txt" && !share.active));
    assert!(shares.iter().any(|share| share.relative_path == "foobar"));
    assert_eq!(
        database
            .count_active_shares_for_path("renamed", true)
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .deactivate_shares_for_path("renamed", true)
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .count_active_shares_for_path("renamed", true)
            .unwrap(),
        0
    );
}

#[test]
fn share_cursor_pages_are_gapless_sorted_and_unicode_searchable() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let aliases = ["alpha", "Grüße", "gamma", "delta", "omega"];
    let mut ids = Vec::new();
    for (index, alias) in aliases.iter().enumerate() {
        ids.push(
            database
                .create_share(
                    &format!("cursor-token-{index}"),
                    Some(alias),
                    &format!("folder/{index}.txt"),
                    false,
                    &Permission::DownloadOnly,
                    None,
                    None,
                    None,
                    1,
                    None,
                    &UploadConflictStrategy::Reject,
                )
                .unwrap(),
        );
    }
    database.set_share_active(ids[3], false).unwrap();
    let now = Utc::now();
    let mut cursor = None;
    let mut newest_ids = Vec::new();
    loop {
        let page = database
            .list_share_page(&ShareListOptions {
                query: None,
                status: ShareListStatus::All,
                sort: ShareListSort::Newest,
                cursor,
                limit: 2,
                now,
            })
            .unwrap();
        newest_ids.extend(page.shares.iter().map(|share| share.id));
        let Some(next) = page.next_cursor else { break };
        cursor = Some(next);
    }
    assert_eq!(newest_ids.len(), aliases.len());
    assert!(newest_ids.windows(2).all(|ids| ids[0] > ids[1]));

    let unicode = database
        .list_share_page(&ShareListOptions {
            query: Some("GRÜS".into()),
            status: ShareListStatus::All,
            sort: ShareListSort::Oldest,
            cursor: None,
            limit: 50,
            now,
        })
        .unwrap();
    assert_eq!(unicode.shares.len(), 1);
    assert_eq!(unicode.shares[0].alias.as_deref(), Some("Grüße"));

    let inactive = database
        .list_share_page(&ShareListOptions {
            query: None,
            status: ShareListStatus::Inactive,
            sort: ShareListSort::Newest,
            cursor: None,
            limit: 50,
            now,
        })
        .unwrap();
    assert_eq!(inactive.shares.len(), 1);
    assert_eq!(inactive.shares[0].id, ids[3]);
    let summary = database.share_summary(now).unwrap();
    assert_eq!(summary.available, 4);
}

#[test]
fn share_search_index_tracks_path_renames_and_deletes_atomically() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let id = database
        .create_share(
            "search-index-token",
            None,
            "Alt/Grüße.txt",
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
        .rename_share_paths("Alt/Grüße.txt", "Neu/Ablage.txt", false)
        .unwrap();
    let search = |query: &str| {
        database
            .list_share_page(&ShareListOptions {
                query: Some(query.to_owned()),
                status: ShareListStatus::All,
                sort: ShareListSort::Newest,
                cursor: None,
                limit: 100,
                now: Utc::now(),
            })
            .unwrap()
            .shares
    };
    assert!(search("GRÜS").is_empty());
    assert_eq!(search("ablage")[0].relative_path, "Neu/Ablage.txt");
    database.delete_share(id).unwrap();
    assert!(search("ablage").is_empty());
}

#[test]
fn share_search_filters_and_limits_before_decrypting_tokens() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let mut ids = Vec::new();
    for index in 0..3 {
        ids.push(
            database
                .create_share(
                    &format!("search-limit-token-{index}"),
                    None,
                    &format!("matching/path-{index}.txt"),
                    false,
                    &Permission::DownloadOnly,
                    None,
                    None,
                    None,
                    1,
                    None,
                    &UploadConflictStrategy::Reject,
                )
                .unwrap(),
        );
    }
    let nonmatching = database
        .create_share(
            "nonmatching-corrupt-token",
            None,
            "unrelated/file.txt",
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
            "UPDATE shares SET token_ciphertext=x'00' WHERE id IN (?1,?2)",
            params![ids[0], nonmatching],
        )
        .unwrap();
    super::shares::reset_share_map_count();
    let page = database
        .list_share_page(&ShareListOptions {
            query: Some("matching".to_owned()),
            status: ShareListStatus::All,
            sort: ShareListSort::Newest,
            cursor: None,
            limit: 1,
            now: Utc::now(),
        })
        .unwrap();
    assert_eq!(page.shares.len(), 1);
    assert!(page.next_cursor.is_some());
    assert_eq!(
        super::shares::share_map_count(),
        2,
        "FTS search must map/decrypt at most limit + 1 rows"
    );
    super::shares::reset_share_map_count();
    let short_query_page = database
        .list_share_page(&ShareListOptions {
            query: Some("ma".to_owned()),
            status: ShareListStatus::All,
            sort: ShareListSort::Newest,
            cursor: None,
            limit: 1,
            now: Utc::now(),
        })
        .unwrap();
    assert_eq!(short_query_page.shares.len(), 1);
    assert!(short_query_page.next_cursor.is_some());
    assert_eq!(
        super::shares::share_map_count(),
        2,
        "short-query fallback must map/decrypt at most limit + 1 rows"
    );
}

#[test]
fn download_limit_is_atomic() {
    let d = Database::open(":memory:").unwrap();
    d.create_admin("a", "h", "s").unwrap();
    let id = d
        .create_share(
            "token",
            None,
            "x",
            false,
            &Permission::DownloadOnly,
            None,
            Some(1),
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    assert!(d.count_download(id).unwrap());
    assert!(!d.count_download(id).unwrap());
}
#[test]
fn alias_unique() {
    let d = Database::open(":memory:").unwrap();
    d.create_admin("a", "h", "s").unwrap();
    d.create_share(
        "a",
        Some("alias"),
        "x",
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
    assert!(d
        .create_share(
            "b",
            Some("alias"),
            "y",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .is_err());
}

#[test]
fn disabled_and_deleted_links_change_state() {
    let d = Database::open(":memory:").unwrap();
    d.create_admin("admin", "hash", "secret").unwrap();
    let id = d
        .create_share(
            "token",
            None,
            "file",
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
    assert!(d.set_share_active(id, false).unwrap());
    assert!(!d.set_share_active(id + 1, false).unwrap());
    assert!(!d.share_by_token("token").unwrap().unwrap().active);
    assert!(d.delete_share(id).unwrap());
    assert!(!d.delete_share(id).unwrap());
    assert!(d.share_by_token("token").unwrap().is_none());
}

#[test]
fn malformed_share_expiry_fails_individual_and_list_queries() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    for (token, path) in [("valid", "valid.txt"), ("corrupt", "corrupt.txt")] {
        database
            .create_share(
                token,
                None,
                path,
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
    }
    database
        .conn()
        .execute(
            "UPDATE shares SET expires_at='not-a-timestamp' WHERE token_hash=?1",
            [token_hash("corrupt")],
        )
        .unwrap();

    assert!(database.share_by_token("corrupt").is_err());
    assert!(database.list_shares().is_err());
}
