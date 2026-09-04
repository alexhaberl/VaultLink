#[tokio::test]
async fn zip_temp_and_direct_paths_cap_files_at_the_scanned_size() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    let file_path = root.path().join("docs/file.txt");
    std::fs::write(&file_path, b"small").unwrap();
    let state = test_state(root.path(), data.path());
    let scope = state.secure_root().bind_directory("docs").unwrap();
    let settings = runtime_settings(&state);
    let plan = plan_zip(&scope, "", &settings).unwrap();
    let estimated_archive_size = plan.estimated_archive_size;

    const GROWN_MARKER: &[u8] = b"-must-not-enter-the-archive";
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&file_path)
        .unwrap()
        .write_all(GROWN_MARKER)
        .unwrap();

    let mut temp_file = build_zip_temp(&scope, &plan).unwrap();
    let mut temp_bytes = Vec::new();
    temp_file.read_to_end(&mut temp_bytes).unwrap();

    let mut direct_bytes = Vec::new();
    let mut stream = Box::pin(direct_zip_stream(scope, plan));
    while let Some(chunk) = stream.next().await {
        direct_bytes.extend_from_slice(&chunk.unwrap());
    }

    assert_eq!(direct_bytes, temp_bytes);
    assert_eq!(temp_bytes.len() as u64, estimated_archive_size);
    assert!(temp_bytes.starts_with(b"PK\x03\x04"));
    let eocd = temp_bytes.len() - ZIP_EOCD_SIZE as usize;
    assert_eq!(zip_u32(&temp_bytes, eocd), 0x0605_4b50);
    assert_eq!(zip_u16(&temp_bytes, eocd + 8), u16::MAX);
    assert_eq!(zip_u16(&temp_bytes, eocd + 10), u16::MAX);
    assert_eq!(zip_u32(&temp_bytes, eocd + 12), u32::MAX);
    assert_eq!(zip_u32(&temp_bytes, eocd + 16), u32::MAX);
    assert!(!temp_bytes
        .windows(GROWN_MARKER.len())
        .any(|window| window == GROWN_MARKER));
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
