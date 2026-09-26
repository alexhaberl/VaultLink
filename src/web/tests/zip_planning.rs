#[tokio::test]
async fn zip_temp_and_direct_paths_reject_changed_source_lengths() {
    for (original, replacement) in [
        (b"old".as_slice(), b"new-complete-content".as_slice()),
        (b"original-content".as_slice(), b"new".as_slice()),
        (b"".as_slice(), b"new".as_slice()),
    ] {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("docs")).unwrap();
        let file_path = root.path().join("docs/file.txt");
        std::fs::write(&file_path, original).unwrap();
        let state = test_state(root.path(), data.path());
        let scope = state.secure_root().bind_directory("docs").unwrap();
        let plan = plan_zip(&scope, "", &runtime_settings(&state)).unwrap();
        std::fs::write(root.path().join("replacement"), replacement).unwrap();
        std::fs::rename(root.path().join("replacement"), &file_path).unwrap();
        assert!(matches!(
            build_zip_temp(&scope, &plan),
            Err(ZipBuildError::Source(_))
        ));
        let mut stream = Box::pin(direct_zip_stream(scope, plan));
        let mut failed = false;
        while let Some(chunk) = stream.next().await {
            if chunk.is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed, "changed source must fail the direct archive");
    }
}

#[test]
fn zero_disables_zip_size_and_file_count_limits() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/one.txt"), b"one").unwrap();
    std::fs::write(root.path().join("docs/two.txt"), b"two").unwrap();
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root().bind_directory("docs").unwrap();
    let mut settings = runtime_settings(&state);
    settings.max_zip_size = 0;
    settings.max_zip_files = 0;

    let plan = plan_zip(&scope, "", &settings).unwrap();
    assert_eq!(plan.files.len(), 2);
    assert_eq!(plan.max_data_size, 0);
    write_zip_archive(&scope, &plan, Vec::new()).unwrap();
}

#[test]
fn zip_planning_bounds_empty_directory_scans() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::create_dir(root.path().join("docs/one")).unwrap();
    std::fs::create_dir(root.path().join("docs/two")).unwrap();
    std::fs::create_dir(root.path().join("single")).unwrap();
    std::fs::write(root.path().join("single/only.txt"), b"one").unwrap();
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root().bind_directory("docs").unwrap();
    let mut settings = runtime_settings(&state);
    settings.max_search_entries = 1;
    assert!(matches!(
        plan_zip(&scope, "", &settings),
        Err(ZipBuildError::Limit("zip scan entry limit exceeded"))
    ));
    let single = state.secure_root().bind_directory("single").unwrap();
    assert_eq!(plan_zip(&single, "", &settings).unwrap().files.len(), 1);
}

#[test]
fn zip_planning_rejects_unsafe_external_writer_filenames() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let unsafe_name = "C:escape.txt";
    std::fs::write(root.path().join("docs").join(unsafe_name), b"malicious").unwrap();
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root().bind_directory("docs").unwrap();
    let settings = runtime_settings(&state);

    let visible_entries = scope.list("", 0, 10).unwrap();
    assert_eq!(visible_entries.len(), 1);
    assert_eq!(visible_entries[0].name, unsafe_name);
    assert!(matches!(
        plan_zip(&scope, "", &settings),
        Err(ZipBuildError::Source(error)) if error.kind() == io::ErrorKind::InvalidData
    ));
}

#[test]
fn filtered_directory_items_consume_listing_search_and_zip_budgets() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    for _ in 0..2 {
        std::fs::write(
            root.path()
                .join("docs")
                .join(crate::secure_fs::upload_fragment_name()),
            b"partial",
        )
        .unwrap();
    }
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root().bind_directory("docs").unwrap();
    let mut settings = runtime_settings(&state);
    settings.max_search_entries = 1;

    let (entries, truncated) = list_directory_page(&scope, "", 0, 1).unwrap();
    assert!(entries.is_empty());
    assert!(truncated);
    let cursor_page = list_directory_cursor_page(
        &scope,
        "",
        None,
        None,
        1,
        FileSortColumn::Name,
        FileSortDirection::Ascending,
    )
    .unwrap();
    assert!(cursor_page.entries.is_empty());
    assert!(cursor_page.truncated);
    assert_eq!(cursor_page.scanned, 1);
    assert!(cursor_page.peak_retained <= 101);
    assert!(search_tree(&scope, "", "missing", &settings)
        .unwrap()
        .is_empty());
    assert!(matches!(
        plan_zip(&scope, "", &settings),
        Err(ZipBuildError::Limit("zip scan entry limit exceeded"))
    ));
}
